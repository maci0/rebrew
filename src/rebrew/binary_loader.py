"""Unified binary format loader for rebrew.

Provides a format-agnostic interface for reading PE, ELF, and Mach-O binaries.
Backed by LIEF for all format parsing.  This module replaces direct ``pefile``
usage throughout the codebase.

Usage::

    from rebrew.binary_loader import load_binary, extract_bytes_at_va

    info = load_binary("path/to/binary")
    print(info.format, info.image_base, info.text_va)

    code = extract_bytes_at_va(info, va=0x10001000, size=64)
"""

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, overload

import lief

log = logging.getLogger(__name__)

_MAX_BINARY_SIZE = 512 * 1024 * 1024  # 512 MB safety limit

# Guards the lazy ``BinaryInfo.data`` fill.  One global lock rather than a
# per-instance one: the instance cache holds at most _LOAD_BINARY_CACHE_MAX
# entries and in practice a run touches one target binary, so contention is
# a non-issue.  Make it per-instance if that ever stops being true.
_data_load_lock = threading.Lock()

# x86 padding opcodes inserted by MSVC linker for alignment (INT3 and NOP).
# Shared across catalog, matcher, and binary loader for consistent trimming.
PADDING_BYTES: tuple[int, ...] = (0xCC, 0x90)


def _decode_lief_name(raw: str | bytes) -> str:
    """Decode a LIEF name, which may be returned as ``bytes`` or ``str``."""
    return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class SectionInfo:
    """Metadata for a single section in a binary."""

    name: str
    va: int  # virtual address (absolute)
    size: int  # virtual size (mapped)
    file_offset: int  # offset in the file on disk
    raw_size: int  # size on disk (may differ from virtual size)


@dataclass
class BinaryInfo:
    """Format-agnostic representation of a parsed binary."""

    path: Path
    format: str  # "pe", "elf", "macho"

    # Base address
    image_base: int = 0

    # .text section shortcuts (most-used for rebrew)
    text_va: int = 0
    text_size: int = 0
    text_raw_offset: int = 0

    # All sections
    sections: dict[str, SectionInfo] = field(default_factory=dict)

    # Raw file bytes (lazy-loaded)
    _data: bytes | None = field(default=None, repr=False)

    @property
    def data(self) -> bytes:
        """Raw file bytes, loaded lazily.

        Uses a single ``read_bytes()`` call so that the size check is
        performed on the bytes we actually read, not a separate ``stat()``
        that could race with a file replacement between the two syscalls.

        ``BinaryInfo`` instances are shared across worker threads via
        ``_load_binary_cache``, so the lazy fill is guarded: without the
        lock every worker of ``rebrew verify -j N`` that touches a cold
        instance reads the whole target binary itself, spiking peak memory
        to N copies of the file for no benefit.
        """
        if self._data is None:
            with _data_load_lock:
                # Re-check: another thread may have filled it while we waited.
                if self._data is None:
                    raw = self.path.read_bytes()
                    if len(raw) > _MAX_BINARY_SIZE:
                        raise ValueError(
                            f"Binary file too large ({len(raw) / 1024 / 1024:.0f} MB): {self.path}"
                        )
                    self._data = raw
        return self._data


# ---------------------------------------------------------------------------
# Format-specific loaders
# ---------------------------------------------------------------------------


def _load_pe(binary: lief.PE.Binary, path: Path) -> BinaryInfo:
    """Extract layout information from a PE binary."""
    image_base = binary.optional_header.imagebase

    sections: dict[str, SectionInfo] = {}
    text_va = image_base
    text_size = 0
    text_raw_offset = 0

    for section in binary.sections:
        name = _decode_lief_name(section.name).rstrip("\x00")
        va = image_base + section.virtual_address
        vsize = section.virtual_size
        raw_offset = section.pointerto_raw_data
        raw_size = section.sizeof_raw_data

        sections[name] = SectionInfo(
            name=name,
            va=va,
            size=vsize,
            file_offset=raw_offset,
            raw_size=raw_size,
        )

        if name == ".text":
            text_va = va
            text_size = vsize
            text_raw_offset = raw_offset

    return BinaryInfo(
        path=path,
        format="pe",
        image_base=image_base,
        text_va=text_va,
        text_size=text_size,
        text_raw_offset=text_raw_offset,
        sections=sections,
    )


def _load_elf(binary: lief.ELF.Binary, path: Path) -> BinaryInfo:
    """Extract layout information from an ELF binary."""
    # Image base: lowest PT_LOAD segment virtual address
    load_segments = [seg for seg in binary.segments if seg.type == lief.ELF.Segment.TYPE.LOAD]
    image_base = min((seg.virtual_address for seg in load_segments), default=0)

    sections: dict[str, SectionInfo] = {}
    text_va = image_base
    text_size = 0
    text_raw_offset = 0

    for section in binary.sections:
        raw_name = section.name
        if not raw_name:
            continue
        name = _decode_lief_name(raw_name)
        va = section.virtual_address
        vsize = section.size
        raw_offset = section.offset
        raw_size = section.original_size if hasattr(section, "original_size") else vsize

        sections[name] = SectionInfo(
            name=name,
            va=va,
            size=vsize,
            file_offset=raw_offset,
            raw_size=raw_size,
        )

        if name == ".text":
            text_va = va
            text_size = vsize
            text_raw_offset = raw_offset

    return BinaryInfo(
        path=path,
        format="elf",
        image_base=image_base,
        text_va=text_va,
        text_size=text_size,
        text_raw_offset=text_raw_offset,
        sections=sections,
    )


def _load_macho(fat_or_binary: lief.MachO.FatBinary | lief.MachO.Binary, path: Path) -> BinaryInfo:
    """Extract layout information from a Mach-O binary.

    LIEF's ``lief.MachO.parse()`` returns a ``FatBinary`` even for thin
    binaries.  We always take the first slice (architecture selection for
    fat binaries is not supported).
    """
    if isinstance(fat_or_binary, lief.MachO.FatBinary):
        # Always use first slice -- architecture selection for fat binaries
        # is not supported.
        binary = fat_or_binary.at(0)
    else:
        binary = fat_or_binary

    # Image base: virtual address of __TEXT segment
    image_base = 0
    for seg in binary.segments:
        if seg.name == "__TEXT":
            image_base = seg.virtual_address
            break

    sections: dict[str, SectionInfo] = {}
    text_va = image_base
    text_size = 0
    text_raw_offset = 0

    for section in binary.sections:
        raw_seg_name = section.segment_name if hasattr(section, "segment_name") else ""
        raw_sec_name = section.name

        seg_name = _decode_lief_name(raw_seg_name)
        sec_name = _decode_lief_name(raw_sec_name)

        name = f"{seg_name}.{sec_name}" if seg_name else sec_name
        va = section.virtual_address
        vsize = section.size
        raw_offset = section.offset
        raw_size = vsize  # Mach-O section size == file size for non-zerofill

        sections[name] = SectionInfo(
            name=name,
            va=va,
            size=vsize,
            file_offset=raw_offset,
            raw_size=raw_size,
        )

        # __text is the Mach-O equivalent of .text
        if section.name == "__text":
            text_va = va
            text_size = vsize
            text_raw_offset = raw_offset

    return BinaryInfo(
        path=path,
        format="macho",
        image_base=image_base,
        text_va=text_va,
        text_size=text_size,
        text_raw_offset=text_raw_offset,
        sections=sections,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_load_binary_cache: dict[tuple[str, str], BinaryInfo] = {}
_LOAD_BINARY_CACHE_MAX = 16
_load_binary_lock = threading.Lock()

# Bounded memo for :func:`iat_slot_vas` (IAT slot VAs).  Keyed on the
# resolved path — the same binary is scanned once per run, not once per
# function comparison.  Same lock/bounded-dict discipline as
# ``_load_binary_cache`` so tests can clear it when they rewrite a fixture.
_iat_slot_cache: dict[str, set[int]] = {}
_IAT_SLOT_CACHE_MAX = 32
_iat_slot_lock = threading.Lock()


def is_ne(path: str | Path) -> bool:
    """True when *path* is a 16-bit Windows NE executable (MZ stub + "NE"
    header at the MZ ``e_lfanew`` offset).  Windows 3.x binaries use this
    format.  The NE header offset is read from ``e_lfanew`` rather than
    assumed to sit within the MZ stub: Borland linkers emit it close to the
    start (e.g. 0x40) but MSVC 16-bit linkers place it far past the stub
    (e.g. 0x400), which a fixed-length header read would miss."""
    try:
        with open(path, "rb") as f:
            head = f.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return False
            e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
            if e_lfanew == 0:
                return False
            f.seek(e_lfanew)
            sig = f.read(2)
    except OSError:
        return False
    return sig == b"NE"


def load_binary(path: Path, fmt: str = "auto") -> BinaryInfo:
    """Parse a binary file and return a ``BinaryInfo``.

    Args:
        path: Path to the binary file.
        fmt: Format hint -- ``"pe"``, ``"elf"``, ``"macho"``, or ``"auto"``
             (LIEF auto-detects from file headers).

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the format cannot be determined or parsing fails.

    """
    path = Path(path)

    # The documented contract (and round_trip's error handling) expects a
    # missing binary to raise FileNotFoundError; lief.parse only logs to
    # stderr and returns None for missing files.
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    # Bounded cache keyed on resolved path + format to avoid re-parsing.
    # Lock protects concurrent reads/writes from multiple workers.  This
    # covers NE binaries too — without it every extract_raw_bytes call
    # re-parsed the 16-bit target (0.18s each → minutes for a 1783-function
    # similar scan).
    cache_key = (str(path.resolve()), fmt)
    with _load_binary_lock:
        cached = _load_binary_cache.get(cache_key)
        if cached is not None:
            # LRU refresh: pop and re-insert so this entry moves to the end.
            # Python 3.7+ dicts are insertion-ordered; next(iter(...)) always
            # yields the oldest entry.  Re-inserting makes this the newest.
            _load_binary_cache[cache_key] = _load_binary_cache.pop(cache_key)
            return cached

    # 16-bit Windows NE executables are parsed natively (Borland Delphi /
    # Turbo Pascal Windows targets) — segments become sections with synthetic
    # flat VAs of (segment_index << 16).
    if is_ne(path):
        from rebrew.ne_loader import load_ne_binary

        result = load_ne_binary(path)
    elif is_mz(path):
        # Plain DOS MZ executables: one pseudo code section spanning the
        # code region, VAs as linear segment*16+offset addresses starting
        # at the CS segment base (the entry's segment).
        result = _load_mz(path)
    else:
        result = _parse_regular(path, fmt)

    # Store in cache under the lock (double-checked; another thread may have
    # populated it while we parsed).
    with _load_binary_lock:
        if cache_key not in _load_binary_cache:
            # Evict oldest entry when cache is full.
            if len(_load_binary_cache) >= _LOAD_BINARY_CACHE_MAX:
                oldest_key = next(iter(_load_binary_cache))
                del _load_binary_cache[oldest_key]
            _load_binary_cache[cache_key] = result
    return result


def _parse_regular(path: Path, fmt: str) -> BinaryInfo:
    """Parse a PE/ELF/Mach-O binary via LIEF (used by load_binary)."""
    import lief

    spath = str(path)
    result: BinaryInfo
    # lief.parse returns a polymorphic Binary union; the isinstance dispatch
    # below handles runtime narrowing, so Any is the pragmatic annotation.
    binary: Any = None
    try:
        if fmt == "auto":
            binary = lief.parse(spath)
            if binary is None:
                raise ValueError(f"Failed to parse binary (unknown format): {path}")
            if isinstance(binary, lief.PE.Binary):
                result = _load_pe(binary, path)
            elif isinstance(binary, lief.ELF.Binary):
                result = _load_elf(binary, path)
            elif isinstance(binary, (lief.MachO.FatBinary, lief.MachO.Binary)):
                result = _load_macho(binary, path)
            else:
                raise ValueError(f"Unsupported binary format: {path}")
        elif fmt == "pe":
            binary = lief.PE.parse(spath)
            if binary is None:
                raise ValueError(f"Failed to parse PE: {path}")
            result = _load_pe(binary, path)
        elif fmt == "elf":
            binary = lief.ELF.parse(spath)
            if binary is None:
                raise ValueError(f"Failed to parse ELF: {path}")
            result = _load_elf(binary, path)
        elif fmt == "macho":
            binary = lief.MachO.parse(spath)
            if binary is None:
                raise ValueError(f"Failed to parse Mach-O: {path}")
            result = _load_macho(binary, path)
        elif fmt == "ne":
            # A real NE file is routed to the native loader by is_ne() before
            # this branch; reaching here means the file is not NE.
            raise ValueError(f"Not a 16-bit Windows NE executable: {path}")
        else:
            raise ValueError(f"Unknown binary format: {fmt!r}")
    except OSError as exc:
        raise FileNotFoundError(f"Binary not found: {path}") from exc
    return result


def section_dict(info: BinaryInfo) -> dict[str, dict[str, int]]:
    """Map section name → {va, size, file_offset, raw_size} for *info*.

    Shared by depgraph and data --dispatch, which previously duplicated this
    dict comprehension.
    """
    return {
        name: {
            "va": si.va,
            "size": si.size,
            "file_offset": si.file_offset,
            "raw_size": si.raw_size,
        }
        for name, si in info.sections.items()
    }


def extract_bytes_at_va(
    info: BinaryInfo,
    va: int,
    size: int,
    padding_bytes: tuple[int, ...] | list[int] = PADDING_BYTES,
    *,
    trim_padding: bool = True,
) -> bytes | None:
    """Extract raw bytes from a binary at a given virtual address.

    Locates the section containing *va*, reads *size* bytes from the
    underlying file, and optionally trims trailing linker padding.

    Args:
        info: Parsed ``BinaryInfo``.
        va: Virtual address to read from.
        size: Number of bytes to read.
        padding_bytes: Bytes to consider padding (default: x86 INT3/NOP).
        trim_padding: Whether to strip trailing padding bytes.  Set to
            ``False`` when exact byte fidelity is required (e.g. scoring).

    Returns:
        Extracted bytes, or ``None`` if the VA is not in any section.

    Note:
        Trimming is appropriate when the caller wants only the semantic
        function body (linker-inserted INT3/NOP alignment padding removed).
        When the exact ``size`` bytes are needed for byte-level comparison
        or scoring, pass ``trim_padding=False``.

    """
    for section in info.sections.values():
        if section.va <= va < section.va + section.raw_size:
            offset = va - section.va
            file_pos = section.file_offset + offset
            max_read = min(size, section.raw_size - offset)
            data = info.data[file_pos : file_pos + max_read]
            if trim_padding:
                # Trim trailing linker padding (single slice instead of per-byte)
                end = len(data)
                while end > 0 and data[end - 1] in padding_bytes:
                    end -= 1
                return data[:end]
            return data
    return None


def va_to_file_offset(info: BinaryInfo, va: int) -> int:
    """Convert a virtual address to a raw file offset.

    Falls back to the .text section shortcut if no section contains the VA.
    """
    for section in info.sections.values():
        if section.va <= va < section.va + section.raw_size:
            return section.file_offset + (va - section.va)
    # Fallback: use .text section constants
    return va - info.text_va + info.text_raw_offset


def extract_raw_bytes(binary_path: Path, va: int, size: int) -> bytes:
    """Read raw bytes from a target binary at a given VA.

    Supports VAs in any section by using section-aware extraction.
    Falls back to a simple file-offset calculation if the VA is not in
    any known section. The fallback path does not trim trailing padding.
    """
    info = load_binary(binary_path)
    data = extract_bytes_at_va(info, va, size)
    if data is not None:
        return data
    # Fallback to simple file-offset calculation.  A VA below the .text base
    # yields a NEGATIVE offset (seek would raise and abort whole batches) —
    # clamp to empty instead.
    offset = va_to_file_offset(info, va)
    if offset < 0:
        return b""
    with binary_path.open("rb") as f:
        f.seek(offset)
        return f.read(size)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


@overload
def function_extent_from_disasm(
    binary_path: Path | str, va: int, max_size: int = 512
) -> int | None: ...
@overload
def function_extent_from_disasm(
    binary_path: Path | str, va: int, max_size: int = 512, *, with_kind: Literal[True]
) -> tuple[int, str] | None: ...


def function_extent_from_disasm(
    binary_path: Path | str,
    va: int,
    max_size: int = 512,
    *,
    with_kind: bool = False,
) -> int | tuple[int, str] | None:
    """Disassembly-derived function extent (size in bytes), or ``None``.

    Walks instructions from *va* until a terminator — ``ret``/``ret N``/
    ``iret``, an unconditional ``jmp`` (tail call / thunk end), or ``int3``
    padding — and returns the byte offset just past it.  This is the
    *authoritative* function end, independent of any discovery-derived
    annotation size (which often merges the next function or includes
    padding).

    With ``with_kind=True``, returns ``(extent, kind)`` where ``kind`` is
    ``"ret"`` or ``"jmp"`` — callers that need to distinguish a real
    epilogue from a branch-merge jmp (e.g. padding past a mid-function
    jmp to reach the true epilogue) can branch on it.

    Conservative by design: the walk stops at the first terminator, so a
    ``jmp`` that is really a loop branch yields a *smaller* extent — callers
    must treat ``extent != compiled size`` as "cannot confirm", not as a
    contradiction.  Returns ``None`` when the region cannot be cleanly
    decoded (malformed opcode, hits the section end).
    """
    path = Path(binary_path)
    if not path.exists():
        return None
    try:
        info = load_binary(path)
        data = extract_bytes_at_va(info, va, max_size, trim_padding=False)
        if not data:
            return None
    except Exception:
        log.debug("failed to load bytes at 0x%x from %s", va, path, exc_info=True)
        return None

    import capstone

    # 16-bit DOS/NE code must disassemble in 16-bit mode — parsing it as
    # 32-bit mis-decodes instructions and hits a bogus early `ret` (the
    # extent then truncates every DOS function at ~20 bytes).
    mode = (
        capstone.CS_MODE_16 if getattr(info, "format", "") in ("mz", "ne") else capstone.CS_MODE_32
    )
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.skipdata = False
    offset = 0
    for insn in md.disasm(data, va):
        mnem = insn.mnemonic
        if mnem in ("ret", "retf", "iret", "iretd", "int3"):
            extent = offset + insn.size
            return (extent, "ret") if with_kind else extent
        if mnem == "jmp":
            # Unconditional jump: tail call / thunk terminator (a backward
            # loop jmp underestimates the extent — callers refuse, which is
            # the safe direction).
            extent = offset + insn.size
            return (extent, "jmp") if with_kind else extent
        if mnem.startswith("j"):
            # Conditional jumps continue the walk.
            offset += insn.size
            continue
        if mnem in ("ud2", "hlt"):
            extent = offset + insn.size
            return (extent, "ud2") if with_kind else extent
        offset += insn.size
    return None


def iat_slot_vas(binary_path: Path | str) -> set[int]:
    """Absolute VAs of the PE import-address-table slots, or ``set()``.

    MSVC PEs place the IAT at the START of ``.text`` (before the code), so
    linear-sweep discovery walks it as code and emits a fake function per
    slot (``sym.imp.`` entries from rizin, or generic ``fcn.`` names from
    other sweeps).  The registry must not treat those data slots as
    functions, and reloc masking must know their addresses.  Returns
    ``set()`` on any failure (non-PE, unparsable, absent file).

    Shared by ``rebrew.core.build_iat_region`` (reloc masking) and the
    catalog registry (function filtering) — one LIEF scan, two consumers.

    Memoized per resolved path (bounded dict + lock, mirroring
    ``_load_binary_cache``): ``compile_and_compare`` calls this once per
    function (via :func:`build_iat_region`) even on compile-cache hits, so
    a full verify/test batch re-parsed the *same immutable PE* N times
    (0.05-0.3s each).  The target binary never changes mid-run, so the
    cache cannot go stale.
    """
    path = Path(binary_path)
    if not path.exists():
        return set()
    cache_key = str(path.resolve())
    with _iat_slot_lock:
        cached = _iat_slot_cache.get(cache_key)
        if cached is not None:
            _iat_slot_cache[cache_key] = _iat_slot_cache.pop(cache_key)
            return set(cached)
    try:
        import lief

        if not lief.is_pe(str(path)):
            return set()
        pe = lief.PE.parse(str(path))
        if pe is None:
            return set()
        image_base = int(getattr(pe, "imagebase", 0) or 0)
        out: set[int] = set()
        for entry in pe.imports:
            for imp in entry.entries:
                va = int(getattr(imp, "iat_address", 0) or 0)
                if va:
                    # LIEF reports the IAT slot as an RVA; canonicalize.
                    out.add((va + image_base) & 0xFFFFFFFF)
        with _iat_slot_lock:
            if cache_key not in _iat_slot_cache:
                if len(_iat_slot_cache) >= _IAT_SLOT_CACHE_MAX:
                    oldest_key = next(iter(_iat_slot_cache))
                    del _iat_slot_cache[oldest_key]
                _iat_slot_cache[cache_key] = set(out)
        return out
    except Exception as exc:
        # A silent empty result here would silently disable IAT reloc
        # masking (DIR32 slots into the IAT then fail validation and
        # demote true RELOC matches) — surface the failure once.
        log.warning(
            "iat_slot_vas: IAT scan failed for %s (reloc masking degraded): %s",
            path,
            exc,
        )
        return set()


def detect_source_language(binary_path: Path) -> tuple[str, str]:
    """Detect likely source language from binary symbol names and sections.

    Examines exported/imported symbol mangling schemes and well-known section
    names to infer the original source language.

    Args:
        binary_path: Path to the binary file.

    Returns:
        ``(language_name, file_extension)`` -- e.g. ``("C++", ".cpp")``.
        Falls back to ``("C", ".c")`` when no strong signal is found.

    """
    _THRESHOLD = 3  # minimum matching symbols to avoid false positives

    binary_path = Path(binary_path)
    if not binary_path.exists():
        return ("C", ".c")

    try:
        parsed = lief.parse(str(binary_path))
    except (OSError, ValueError, RuntimeError):
        return ("C", ".c")

    if parsed is None:
        return ("C", ".c")

    # Collect section names
    section_names: list[str] = []
    try:
        for sec in parsed.sections:
            if not hasattr(sec, "name"):
                continue
            name = _decode_lief_name(sec.name).rstrip("\x00")
            if name:
                section_names.append(name)
    except (AttributeError, TypeError):
        pass

    # Check sections for language-specific markers
    for name in section_names:
        if name == ".gopclntab" or name == ".gosymtab":
            return ("Go", ".go")
        if name in ("__objc_methnames", "__objc_classlist", "__objc_selrefs"):
            return ("Objective-C", ".m")

    # Collect symbol names
    symbols: list[str] = []
    try:
        if hasattr(parsed, "symbols"):
            for sym in parsed.symbols:
                if sym.name:
                    symbols.append(_decode_lief_name(sym.name))
    except (AttributeError, TypeError):
        pass
    try:
        if hasattr(parsed, "exported_functions"):
            for func in parsed.exported_functions:
                if hasattr(func, "name") and func.name:
                    symbols.append(_decode_lief_name(func.name))
    except (AttributeError, TypeError):
        pass

    # Count mangling scheme hits
    go_count = 0
    rust_count = 0
    d_count = 0
    cpp_msvc_count = 0
    cpp_itanium_count = 0

    for sym_name in symbols:
        if sym_name.startswith(("go.", "go:")):
            go_count += 1
        if sym_name.startswith("_R") and len(sym_name) > 2 and sym_name[2:3].isalpha():
            rust_count += 1
        if sym_name.startswith("_D") and len(sym_name) > 2 and sym_name[2:3].isdigit():
            d_count += 1
        if sym_name.startswith("?"):
            cpp_msvc_count += 1
        if sym_name.startswith("_Z"):
            cpp_itanium_count += 1

    # Return first language exceeding threshold (most specific first)
    if go_count >= _THRESHOLD:
        return ("Go", ".go")
    if rust_count >= _THRESHOLD:
        return ("Rust", ".rs")
    if d_count >= _THRESHOLD:
        return ("D", ".d")
    if cpp_msvc_count >= _THRESHOLD or cpp_itanium_count >= _THRESHOLD:
        return ("C++", ".cpp")

    return ("C", ".c")


_PE_MACHINE_TO_ARCH: dict[lief.PE.Header.MACHINE_TYPES, str] = {
    lief.PE.Header.MACHINE_TYPES.I386: "x86_32",
    lief.PE.Header.MACHINE_TYPES.AMD64: "x86_64",
    lief.PE.Header.MACHINE_TYPES.ARM: "arm32",
    lief.PE.Header.MACHINE_TYPES.ARM64: "arm64",
}

_ELF_MACHINE_TO_ARCH: dict[lief.ELF.ARCH, str] = {
    lief.ELF.ARCH.I386: "x86_32",
    lief.ELF.ARCH.X86_64: "x86_64",
    lief.ELF.ARCH.ARM: "arm32",
    lief.ELF.ARCH.AARCH64: "arm64",
}

_MACHO_CPU_TO_ARCH: dict[lief.MachO.Header.CPU_TYPE, str] = {
    lief.MachO.Header.CPU_TYPE.X86: "x86_32",
    lief.MachO.Header.CPU_TYPE.X86_64: "x86_64",
    lief.MachO.Header.CPU_TYPE.ARM: "arm32",
    lief.MachO.Header.CPU_TYPE.ARM64: "arm64",
}


def detect_format_and_arch(path: Path) -> tuple[str, str | None]:
    """Detect binary format and architecture using LIEF.

    Raises ``FileNotFoundError`` if *path* does not exist, or ``ValueError``
    if the format cannot be identified.
    """
    if not path.exists():
        raise FileNotFoundError(path)
    spath = str(path)
    binary: Any = None  # format-specific lief.parse results (polymorphic union)
    if lief.is_pe(spath):
        binary = lief.PE.parse(spath)
        arch = _PE_MACHINE_TO_ARCH.get(binary.header.machine) if binary else None
        return "pe", arch
    if lief.is_elf(spath):
        binary = lief.ELF.parse(spath)
        arch = _ELF_MACHINE_TO_ARCH.get(binary.header.machine_type) if binary else None
        return "elf", arch
    if lief.is_macho(spath):
        fat = lief.MachO.parse(spath)
        if fat is not None:
            b = fat.at(0) if isinstance(fat, lief.MachO.FatBinary) else fat
            return "macho", _MACHO_CPU_TO_ARCH.get(b.header.cpu_type)
        return "macho", None
    raise ValueError(f"Cannot detect binary format: {path}")


def is_mz(path: str | Path) -> bool:
    """True when *path* is a plain DOS MZ executable (not an NE/PE wrapper)."""
    try:
        with open(path, "rb") as f:
            head = f.read(0x40)
    except OSError:
        return False
    if len(head) < 2 or head[:2] != b"MZ":
        return False
    if len(head) >= 0x40:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if e_lfanew + 4 <= 0x10000:
            with open(path, "rb") as f:
                f.seek(e_lfanew)
                sig = f.read(4)
            if sig[:2] in (b"NE", b"PE", b"LE", b"LX"):
                return False
    return True


def parse_mz_header(path: str | Path) -> dict[str, int]:
    """Parse a DOS MZ header, returning the code-region geometry.

    Returns ``code_offset`` (file offset where the code starts — after the
    header and relocation table), ``code_size`` (remaining file bytes),
    ``entry_va`` (the CS:IP entry expressed as a linear ``segment*16+offset``
    address, the classic DOS convention used for function VAs), and
    ``va_base`` (linear address of ``code_offset`` — the first code byte's
    segment is unknown for a bare MZ, so 0 is assumed, matching how
    ``extract_raw_bytes`` would address it).

    Segment semantics: the MZ header's CS/SS fields are *relative to the
    image start* (the loader maps the image content — file ``code_offset``
    onward — to a contiguous block, and ``e_cs``/``e_ss`` count paragraphs
    into it).  Consequently the file itself IS the load image minus the
    header, and ``VA(file F) = F - code_offset`` — code segment ``e_cs``
    lands at linear ``e_cs*16`` and the entry at ``e_cs*16 + e_ip``, both
    matching what a DOS disassembler would show.  (``e_cs`` lives at offset
    0x16; ``e_ss`` at 0x0E is the stack segment, a common mix-up that
    silently shifts every VA when the two differ — as in any program with
    separate code and data segments.)"""
    with open(path, "rb") as f:
        head = f.read(0x40)
    if len(head) < 0x40 or head[:2] != b"MZ":
        raise ValueError(f"not an MZ executable: {path}")
    cparhdr = int.from_bytes(head[0x08:0x0A], "little")
    crlc = int.from_bytes(head[0x06:0x08], "little")
    lfarlc = int.from_bytes(head[0x18:0x1A], "little")
    cs = int.from_bytes(head[0x16:0x18], "little")  # e_cs — NOT e_ss (0x0E)!
    ip = int.from_bytes(head[0x14:0x16], "little")
    cblp = int.from_bytes(head[0x02:0x04], "little")
    cp = int.from_bytes(head[0x04:0x06], "little")

    # Degenerate header (no header paragraphs, no pages) — not a real MZ.
    if cparhdr == 0 and cp == 0:
        raise ValueError(f"invalid MZ header (no header/pages): {path}")
    # Per the MZ spec, cblp == 0 means the last page is exactly 512 bytes
    # (a full page), so the true size is cp * 512 — the (cp-1)*512 + cblp
    # formula would undercount by 512 and yield an empty code region for
    # files whose size is an exact multiple of 512.
    file_size = ((cp - 1) * 512 + cblp) if cp > 0 and cblp > 0 else (cp * 512 if cp > 0 else 0)
    if file_size == 0:
        import os

        file_size = os.path.getsize(path)
    header_size = cparhdr * 16
    # The code region starts at the end of the header paragraphs — the MZ
    # loader maps the file from cparhdr*16 onward as the load image.  The
    # relocation table (at lfarlc, crlc entries) usually lives INSIDE the
    # header area; only when it extends past the header does the code
    # effectively start after it.  (The old `header_size + crlc*4` skipped
    # the first crlc*4 bytes even when the table fit in the header —
    # shifting every function VA by that amount.)
    code_offset = max(header_size, lfarlc + crlc * 4)
    if lfarlc == 0:
        # No relocation table — code starts right after the header.
        code_offset = header_size
    code_size = max(0, file_size - code_offset)
    entry_va = cs * 16 + ip
    return {
        "code_offset": code_offset,
        "code_size": code_size,
        "entry_va": entry_va,
        "va_base": 0,  # VA of the first code byte (seg-relative space, see docstring)
    }


def _load_mz(path: Path) -> BinaryInfo:
    """Build a BinaryInfo for a plain DOS MZ executable.

    The code region (after the header + relocation table) becomes a single
    pseudo ``.text`` section in segment-relative linear space: ``VA(F) =
    F - code_offset``, so the header's code segment ``e_cs`` lands at
    linear ``e_cs*16`` and the entry at ``e_cs*16 + e_ip`` — matching the
    addresses a DOS disassembler shows.  ``va_to_file_offset`` and
    ``extract_raw_bytes`` therefore work for DOS targets.
    """
    h = parse_mz_header(path)
    code_size = h["code_size"]
    info = BinaryInfo(path=path, format="mz", image_base=0)
    info.text_va = 0
    info.text_size = code_size
    info.text_raw_offset = h["code_offset"]
    info.sections = {
        ".text": SectionInfo(
            name=".text",
            va=0,
            size=code_size,
            file_offset=h["code_offset"],
            raw_size=code_size,
        )
    }
    return info
