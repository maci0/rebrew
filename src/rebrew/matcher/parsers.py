"""Object file and binary parsers for rebrew.

Provides functions to extract symbol bytes and relocation offsets from
object files (COFF ``.obj``, ELF ``.o``, Mach-O ``.o``) and to extract
function bytes from linked binaries (PE, ELF, Mach-O).

All format parsing is backed by LIEF.
"""

import bisect
import struct
import warnings
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from rebrew.binary_loader import PADDING_BYTES as _PADDING_BYTES
from rebrew.core.matching import CoffRelocRecord

_PADDING_STRIP = bytes(_PADDING_BYTES)


# ---------------------------------------------------------------------------
# Shared helpers for format-specific parsers
# ---------------------------------------------------------------------------


def _next_symbol_end(sec_offsets: list[int], func_start: int, fallback: int) -> int:
    """End offset of the function at *func_start*: the next symbol's offset
    in *sec_offsets* (sorted ascending), or *fallback* (section end) when
    there is no later symbol.  Shared by the COFF/ELF/Mach-O extractors."""
    idx = bisect.bisect_right(sec_offsets, func_start)
    if idx < len(sec_offsets):
        return sec_offsets[idx]
    return fallback


def _extract_reloc_name(reloc: Any) -> str:
    """Extract target symbol name from a relocation entry."""
    if hasattr(reloc, "symbol") and reloc.symbol is not None:
        name = getattr(reloc.symbol, "name", "")
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        return name
    return ""


def _collect_reloc_offsets(
    relocations: Iterable[Any],
    func_start: int,
    func_end: int,
) -> dict[int, str]:
    """Collect relocation offsets within a function's byte range."""
    offsets: dict[int, str] = {}
    for reloc in relocations:
        rva = reloc.address
        if func_start <= rva < func_end:
            offsets[rva - func_start] = _extract_reloc_name(reloc) or ""
    return offsets


# ---------------------------------------------------------------------------
# Type-aware COFF relocation extraction
# ---------------------------------------------------------------------------


def parse_obj_relocs_full(obj_path: str | Path, symbol: str) -> list[CoffRelocRecord]:
    """Extract type-aware relocation records for ``symbol`` from a COFF .obj.

    Unlike ``parse_obj_symbol_bytes``, this preserves the IMAGE_REL_I386_*
    type so callers can apply (not just mask) relocations.
    """
    _, _, records = parse_obj_symbol_and_relocs(obj_path, symbol)
    return records


def parse_obj_symbol_and_relocs(
    obj_path: str | Path, symbol: str
) -> tuple[bytes | None, dict[int, str] | None, list[CoffRelocRecord]]:
    """Parse a COFF .obj ONCE, returning (code_bytes, reloc_offsets, typed_records).

    ``compile_and_compare``/``_test_multi`` previously called
    ``parse_obj_symbol_bytes`` then ``parse_obj_relocs_full`` — two
    ``lief.COFF.parse`` calls on the same file.  This single-parse variant
    returns everything both helpers produce so hot compile paths parse once.
    """

    # OMF objects (Open Watcom / MSVC 1.52) are converted to COFF via the
    # vendored objconv first — LIEF cannot parse OMF.
    data = Path(obj_path).read_bytes()
    if _detect_obj_format_data(data[:4]) == "omf":
        from rebrew.matcher.omf16 import is_omf16, parse_obj_omf16

        if is_omf16(data):
            code, reloc_dict = parse_obj_omf16(obj_path, symbol)
            if code is not None:
                return code, reloc_dict, []
            # 16-bit MSVC dialect the minimal parser cannot decode (the
            # /O1 and far-code COMDAT models) — fall through to the
            # objconv path below, which converts COMDAT records to COFF
            # sections (requires the fixed objconv; the stock build errors
            # and the parse yields None, surfacing as a failed match).
        # Convert via objconv into a TemporaryDirectory so the .coff is
        # cleaned up (the old NamedTemporaryFile(delete=False) leaked one
        # /tmp file per OMF compile — every flag-sweep iteration).
        import tempfile

        with tempfile.TemporaryDirectory(prefix="omfcoff-") as td:
            coff_path = Path(td) / "conv.coff"
            _omf_to_coff(obj_path, coff_path)
            return _parse_coff(obj_path, coff_path, symbol)

    return _parse_coff(obj_path, None, symbol)


def _parse_coff(
    obj_path: str | Path,
    coff_path: Path | None,
    symbol: str,
) -> tuple[bytes | None, dict[int, str] | None, list[CoffRelocRecord]]:
    """Parse a COFF object and extract *symbol*'s code + relocations.

    *coff_path* is the objconv-converted file (inside a TemporaryDirectory
    owned by the caller) when the source was OMF; ``None`` for a native
    COFF object (parsed in place).
    """
    import lief

    parse_path = coff_path if coff_path is not None else obj_path
    coff = lief.COFF.parse(str(parse_path))
    if coff is None:
        return None, None, []

    # Match the symbol across compiler naming conventions: MSVC prefixes
    # (_name), Watcom/Borland suffix (name_), or bare (name).  wcc386 emits
    # trailing underscores (callg_); the rebrew annotation layer derives
    # MSVC-style leading-underscore symbols.
    sym_names = [symbol]
    if symbol.startswith("_"):
        sym_names.append(symbol[1:])
        sym_names.append(symbol[1:] + "_")
    else:
        sym_names.append("_" + symbol)
        sym_names.append(symbol + "_")
    # Materialize the symbols once: lazily-iterated coff.symbols generators
    # hold nanobind iterator refs that LIEF's refleak detector flags at
    # interpreter shutdown (every parse leaked → non-zero exit).
    symbols = list(coff.symbols)
    target_sym = next(
        (s for s in symbols if s.name in sym_names and s.section is not None),
        None,
    )
    if target_sym is None:
        return None, None, []

    section = target_sym.section
    content = bytes(section.content)
    func_start = target_sym.value
    # Match symbols by SECTION OFFSET, not name: naked functions land in
    # separate .text COMDATs (multiple sections all named ".text"), so a
    # name match collects offsets from unrelated sections and the
    # next-symbol distance (function size) comes out wrong (e.g. a 3328-byte
    # naked function reported as 57 bytes).  LIEF COFF has no
    # section_number on symbols and returns a fresh Section object per
    # access, so compare the stable section file offset instead.
    target_off = getattr(section, "offset", None)
    sec_offsets = sorted(
        s.value
        for s in symbols
        if s.section is not None
        and not str(s.name).startswith("$")
        and (getattr(s.section, "offset", None) == target_off if target_off is not None else True)
    )
    func_end = _next_symbol_end(sec_offsets, func_start, len(content))

    code = content[func_start:func_end].rstrip(_PADDING_STRIP)
    reloc_offsets = _collect_reloc_offsets(section.relocations, func_start, func_end)

    records: list[CoffRelocRecord] = []
    for r in section.relocations:
        rva = r.address
        if func_start <= rva < func_end:
            raw_type = int(r.type) & 0xFFFF
            records.append(
                CoffRelocRecord(
                    offset=rva - func_start,
                    type=raw_type,
                    symbol=_extract_reloc_name(r),
                )
            )
    return code, reloc_offsets, records


# ---------------------------------------------------------------------------
# Object file format detection
# ---------------------------------------------------------------------------


def _detect_obj_format(obj_path: str) -> str:
    """Detect object file format from magic bytes."""
    with open(obj_path, "rb") as f:
        magic = f.read(4)
    return _detect_obj_format_data(magic)


def _detect_obj_format_data(magic: bytes) -> str:
    """Detect object file format from a 4-byte magic prefix.

    Data-based sibling of :func:`_detect_obj_format` so hot paths that
    already hold the file bytes (e.g. the OMF branch of
    ``parse_obj_symbol_and_relocs``) do not re-open the file to re-detect
    (perf-review: one open + read per compiled candidate is pure overhead).
    """
    if magic == b"\x7fELF":
        return "elf"
    if magic in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ):
        return "macho"
    # COFF: validate machine type in first 2 bytes (multiple architectures)
    if len(magic) >= 2:
        (machine,) = struct.unpack_from("<H", magic, 0)
        if machine in (0x14C, 0x8664, 0x1C0, 0xAA64):
            return "coff"
    # OMF: first record type in 0x80..0xA0 with a plausible length field.
    if len(magic) >= 3 and 0x80 <= magic[0] <= 0xA0:
        ln = magic[1] | (magic[2] << 8)
        if 1 <= (ln & 0x7FFF) <= 0x4000:
            return "omf"
    return "unknown"


def _omf_to_coff(obj_path: str | Path, out_path: str | Path) -> None:
    """Convert an OMF object to COFF via the vendored objconv.

    Open Watcom / MSVC 1.52 emit OMF ("8086 relocatable"), which LIEF
    cannot parse — objconv converts it to a real i386 COFF that the
    existing LIEF path consumes unchanged (verified: reloc offsets land on
    the expected call/disp slots)."""
    import shutil
    import subprocess

    # Prefer the vendored (pinned) objconv over a PATH binary — the vendored
    # copy is the byte-reproducible one and carries the 16-bit OMF fix; a
    # system objconv may be an arbitrary version.  parents[3] is the repo
    # root for the editable install (parsers.py → matcher → rebrew → src).
    vendored_objconv = Path(__file__).resolve().parents[3] / "tools" / "objconv" / "objconv"
    path_objconv = shutil.which("objconv")
    objconv: Path | None = (
        vendored_objconv
        if vendored_objconv.exists()
        else (Path(path_objconv) if path_objconv else None)
    )
    if objconv is None or not objconv.exists():
        raise FileNotFoundError(
            "objconv not found (needed to parse OMF objects) — vendored at tools/objconv"
        )
    r = subprocess.run(
        [str(objconv), "-fcoff", str(obj_path), "-o", str(out_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # The caller pre-creates the output tempfile, so mere existence is not
    # proof of conversion: a failed objconv run (error aborts before Write)
    # leaves an empty file that LIEF would silently parse as None.  Require
    # a non-empty output AND a clean exit — a real COFF object is always at
    # least the 20-byte file header.
    out = Path(out_path)
    if r.returncode != 0 or not out.exists() or out.stat().st_size == 0:
        raise ValueError(f"objconv failed to convert OMF {obj_path}: {r.stderr[-300:]}")


# ---------------------------------------------------------------------------
# COFF .obj parsing via LIEF
# ---------------------------------------------------------------------------


def _parse_coff_symbol_bytes(
    obj_path: str, symbol: str
) -> tuple[bytes | None, dict[int, str] | None]:
    """Extract code bytes + relocation offsets for a symbol from COFF .obj using LIEF."""
    code, reloc_offsets, _ = parse_obj_symbol_and_relocs(obj_path, symbol)
    return code, reloc_offsets


def _list_coff_symbols(obj_path: str) -> list[str]:
    """List all public symbols in a COFF .obj file using LIEF."""
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return []

    symbols = [
        str(sym.name)
        for sym in coff.symbols
        if sym.section is not None
        and not str(sym.name).startswith("$")
        and sym.storage_class == lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL
    ]
    return symbols


# ---------------------------------------------------------------------------
# ELF .o parsing via LIEF
# ---------------------------------------------------------------------------


def _parse_elf_symbol_bytes(
    obj_path: str, symbol: str
) -> tuple[bytes | None, dict[int, str] | None]:
    """Extract code bytes + relocation offsets for a symbol from ELF .o using LIEF."""
    import lief

    elf = lief.ELF.parse(str(obj_path))
    if elf is None:
        return None, None

    # Find the target symbol
    target_sym = None
    for sym in elf.symbols:
        if sym.name == symbol and getattr(sym, "section", None) is not None:
            target_sym = sym
            break

    if target_sym is None:
        return None, None

    # Get the section containing this symbol
    # In ELF .o files, sym.shndx gives the section index
    section = None
    if hasattr(target_sym, "section") and target_sym.section is not None:
        section = target_sym.section

    if section is None:
        return None, None

    content = bytes(section.content)
    func_start = target_sym.value

    # Determine function size from symbol's size attribute or next symbol
    if target_sym.size > 0:
        func_end = func_start + target_sym.size
    else:
        # Build sorted offsets for this section to find func_end in O(log n)
        sec_offsets = sorted(
            sym.value
            for sym in elf.symbols
            if hasattr(sym, "section")
            and sym.section is not None
            and sym.section.name == section.name
        )
        func_end = _next_symbol_end(sec_offsets, func_start, len(content))

    code = content[func_start:func_end].rstrip(_PADDING_STRIP)

    # Filter to section-local relocations (ELF exposes all relocations globally)
    section_relocs = (
        r
        for r in elf.relocations
        if hasattr(r, "section") and r.section is not None and r.section.name == section.name
    )
    reloc_offsets = _collect_reloc_offsets(section_relocs, func_start, func_end)
    return code, reloc_offsets


def _list_elf_symbols(obj_path: str) -> list[str]:
    """List all public symbols in an ELF .o file using LIEF."""
    import lief

    elf = lief.ELF.parse(str(obj_path))
    if elf is None:
        return []

    symbols = [
        str(sym.name)
        for sym in elf.symbols
        if sym.name
        and sym.value is not None
        and sym.binding == lief.ELF.Symbol.BINDING.GLOBAL
        and sym.type == lief.ELF.Symbol.TYPE.FUNC
    ]
    return symbols


# ---------------------------------------------------------------------------
# Mach-O .o parsing via LIEF
# ---------------------------------------------------------------------------


def _parse_macho_symbol_bytes(
    obj_path: str, symbol: str
) -> tuple[bytes | None, dict[int, str] | None]:
    """Extract code bytes + relocation offsets for a symbol from Mach-O .o using LIEF."""
    import lief

    fat = lief.MachO.parse(str(obj_path))
    if fat is None:
        return None, None
    binary = fat.at(0)
    if binary is None:
        return None, None

    # Find the target symbol (Mach-O may prefix with '_')
    target_sym = None
    for sym in binary.symbols:
        if sym.name in (symbol, f"_{symbol}"):
            target_sym = sym
            break

    if target_sym is None:
        return None, None

    # Find the section
    section = None
    if hasattr(target_sym, "section") and target_sym.section is not None:
        section = target_sym.section

    if section is None:
        # Try __text section
        for sec in binary.sections:
            if sec.name == "__text":
                section = sec
                break

    if section is None:
        return None, None

    content = bytes(section.content)
    func_start = target_sym.value - section.virtual_address

    if func_start < 0 or func_start >= len(content):
        return None, None

    # Build sorted offsets for this section to find func_end in O(log n)
    sec_name = getattr(section, "name", None)
    sec_offsets = sorted(
        sym.value - section.virtual_address
        for sym in binary.symbols
        if hasattr(sym, "section")
        and sym.section is not None
        and getattr(sym.section, "name", None) == sec_name
    )
    func_end = _next_symbol_end(sec_offsets, func_start, len(content))

    code = content[func_start:func_end].rstrip(_PADDING_STRIP)
    reloc_offsets = _collect_reloc_offsets(section.relocations, func_start, func_end)
    return code, reloc_offsets


def _list_macho_symbols(obj_path: str) -> list[str]:
    """List all public symbols in a Mach-O .o file using LIEF."""
    import lief

    fat = lief.MachO.parse(str(obj_path))
    if fat is None:
        return []
    binary = fat.at(0)
    if binary is None:
        return []

    symbols = []
    for sym in binary.symbols:
        if sym.name and getattr(sym, "type", 0) > 0:
            # Strip leading underscore (Mach-O convention) — exactly one
            name = sym.name[1:] if str(sym.name).startswith("_") else sym.name
            symbols.append(str(name))
    return symbols


# ---------------------------------------------------------------------------
# Public API: unified dispatchers
# ---------------------------------------------------------------------------


def parse_obj_symbol_bytes(
    obj_path: str | Path, symbol: str
) -> tuple[bytes | None, dict[int, str] | None]:
    """Extract code bytes + relocation offsets for a symbol from an object file.

    Supports COFF ``.obj``, ELF ``.o``, Mach-O ``.o``, and OMF (Watcom /
    MSVC 1.52 — via objconv or the built-in 16-bit parser).
    """
    path_str = str(obj_path)
    fmt = _detect_obj_format(path_str)

    if fmt == "coff":
        return _parse_coff_symbol_bytes(path_str, symbol)
    if fmt == "elf":
        return _parse_elf_symbol_bytes(path_str, symbol)
    if fmt == "macho":
        return _parse_macho_symbol_bytes(path_str, symbol)
    if fmt == "omf":
        code, relocs, _ = parse_obj_symbol_and_relocs(obj_path, symbol)
        return code, relocs
    return None, None


def list_obj_symbols(obj_path: str | Path) -> list[str]:
    """List all public symbols in an object file.

    Supports COFF ``.obj``, ELF ``.o``, and Mach-O ``.o`` files.
    """
    path_str = str(obj_path)
    fmt = _detect_obj_format(path_str)

    if fmt == "coff":
        return _list_coff_symbols(path_str)
    if fmt == "elf":
        return _list_elf_symbols(path_str)
    if fmt == "macho":
        return _list_macho_symbols(path_str)
    return []


# ---------------------------------------------------------------------------
# Binary extraction (linked executables)
# ---------------------------------------------------------------------------


def extract_function_from_binary(bin_path: Path, va: int, size: int) -> bytes | None:
    """Extract raw bytes from a binary file at a given VA.

    Supports PE, ELF, and Mach-O via ``binary_loader``.
    """
    try:
        from rebrew.binary_loader import extract_bytes_at_va, load_binary

        info = load_binary(bin_path)
        return extract_bytes_at_va(info, va, size, padding_bytes=tuple(_PADDING_BYTES))
    except (ImportError, OSError, KeyError, ValueError) as e:
        warnings.warn(f"Error extracting from binary: {e}", stacklevel=2)
    return None
