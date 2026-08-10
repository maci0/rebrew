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

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief

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


def is_ne(path: str | Path) -> bool:
    """True when *path* is a 16-bit Windows NE executable (MZ stub + "NE"
    header at the MZ ``e_lfanew`` offset).  Windows 3.x binaries use this
    format; rebrew targets 32-bit PE/ELF/Mach-O, so they are detected and
    reported explicitly rather than failing as "unknown format"."""
    try:
        with open(path, "rb") as f:
            head = f.read(0x104)
    except OSError:
        return False
    if len(head) < 0x104 or head[:2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
    if e_lfanew + 2 > len(head):
        return False
    return head[e_lfanew : e_lfanew + 2] == b"NE"


_NE_UNSUPPORTED_MSG = (
    "16-bit NE Windows executable (Windows 3.x) detected — rebrew targets "
    "32-bit PE/ELF/Mach-O and cannot parse NE yet. The 16-bit path (NE "
    "parser, capstone x86-16 disassembly, a genuine 16-bit compiler profile "
    "such as Borland Turbo C — the vendored MSVC420 is 32-bit) is documented "
    "in docs/TOOLCHAIN.md."
)


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

    # 16-bit Windows NE executables are detected explicitly — lief.parse
    # returns None for them and the generic "unknown format" error would
    # mislead.  The specific message names the format and the path forward.
    if is_ne(path):
        raise ValueError(_NE_UNSUPPORTED_MSG)

    # Bounded cache keyed on resolved path + format to avoid re-parsing.
    # Lock protects concurrent reads/writes from multiple workers.
    cache_key = (str(path.resolve()), fmt)
    with _load_binary_lock:
        cached = _load_binary_cache.get(cache_key)
        if cached is not None:
            # LRU refresh: pop and re-insert so this entry moves to the end.
            # Python 3.7+ dicts are insertion-ordered; next(iter(...)) always
            # yields the oldest entry.  Re-inserting makes this the newest.
            _load_binary_cache[cache_key] = _load_binary_cache.pop(cache_key)
            return cached

    # Parsing happens outside the lock (expensive I/O, no shared state)
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
        else:
            raise ValueError(f"Unknown binary format: {fmt!r}")
    except OSError as exc:
        raise FileNotFoundError(f"Binary not found: {path}") from exc

    with _load_binary_lock:
        # Double-check: another thread may have parsed the same binary
        if cache_key in _load_binary_cache:
            return _load_binary_cache[cache_key]
        # Evict oldest entry when cache is full
        if len(_load_binary_cache) >= _LOAD_BINARY_CACHE_MAX:
            oldest_key = next(iter(_load_binary_cache))
            del _load_binary_cache[oldest_key]
        _load_binary_cache[cache_key] = result
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
