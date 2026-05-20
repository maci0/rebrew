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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rebrew.binary_loader import PADDING_BYTES as _PADDING_BYTES

_PADDING_STRIP = bytes(_PADDING_BYTES)


# ---------------------------------------------------------------------------
# Shared helpers for format-specific parsers
# ---------------------------------------------------------------------------


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


@dataclass(frozen=True)
class CoffRelocRecord:
    """One COFF relocation entry with its IMAGE_REL_I386_* type preserved."""

    offset: int  # byte offset inside the function's .text slice
    type: int  # IMAGE_REL_I386_* (0x06=DIR32, 0x14=REL32, ...)
    symbol: str  # target symbol name (with leading underscore on MSVC)


def parse_obj_relocs_full(obj_path: str | Path, symbol: str) -> list[CoffRelocRecord]:
    """Extract type-aware relocation records for ``symbol`` from a COFF .obj.

    Unlike ``parse_obj_symbol_bytes``, this preserves the IMAGE_REL_I386_*
    type so callers can apply (not just mask) relocations.
    """
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return []

    target_sym = next(
        (s for s in coff.symbols if s.name == symbol and s.section is not None),
        None,
    )
    if target_sym is None:
        return []

    section = target_sym.section
    func_start = target_sym.value
    sec_offsets = sorted(
        s.value
        for s in coff.symbols
        if s.section is not None
        and s.section.name == section.name
        and not str(s.name).startswith("$")
    )
    func_end = len(bytes(section.content))
    idx = bisect.bisect_right(sec_offsets, func_start)
    if idx < len(sec_offsets):
        func_end = sec_offsets[idx]

    records: list[CoffRelocRecord] = []
    for r in section.relocations:
        rva = r.address
        if func_start <= rva < func_end:
            # LIEF encodes the type as (machine_type << 16) | raw_IMAGE_REL_type.
            # Mask to 16 bits to recover the raw IMAGE_REL_I386_* value.
            raw_type = int(r.type) & 0xFFFF
            records.append(
                CoffRelocRecord(
                    offset=rva - func_start,
                    type=raw_type,
                    symbol=_extract_reloc_name(r),
                )
            )
    return records


# ---------------------------------------------------------------------------
# Object file format detection
# ---------------------------------------------------------------------------


def _detect_obj_format(obj_path: str) -> str:
    """Detect object file format from magic bytes."""
    with open(obj_path, "rb") as f:
        magic = f.read(4)
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
    return "unknown"


# ---------------------------------------------------------------------------
# COFF .obj parsing via LIEF
# ---------------------------------------------------------------------------


def _parse_coff_symbol_bytes(
    obj_path: str, symbol: str
) -> tuple[bytes | None, dict[int, str] | None]:
    """Extract code bytes + relocation offsets for a symbol from COFF .obj using LIEF."""
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return None, None

    # Find the target symbol
    target_sym = None
    for sym in coff.symbols:
        if sym.name == symbol and sym.section is not None:
            target_sym = sym
            break

    if target_sym is None:
        return None, None

    section = target_sym.section
    content = bytes(section.content)
    func_start = target_sym.value

    # Build sorted offsets for this section to find func_end in O(log n)
    sec_offsets = sorted(
        sym.value
        for sym in coff.symbols
        if sym.section is not None
        and sym.section.name == section.name
        and not str(sym.name).startswith("$")
    )
    func_end = len(content)
    idx = bisect.bisect_right(sec_offsets, func_start)
    if idx < len(sec_offsets):
        func_end = sec_offsets[idx]

    code = content[func_start:func_end].rstrip(_PADDING_STRIP)
    reloc_offsets = _collect_reloc_offsets(section.relocations, func_start, func_end)
    return code, reloc_offsets


def _list_coff_symbols(obj_path: str) -> list[str]:
    """List all public symbols in a COFF .obj file using LIEF."""
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return []

    symbols = [
        sym.name
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
        func_end = len(content)
        idx = bisect.bisect_right(sec_offsets, func_start)
        if idx < len(sec_offsets):
            func_end = sec_offsets[idx]

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
        sym.name
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
    func_end = len(content)
    idx = bisect.bisect_right(sec_offsets, func_start)
    if idx < len(sec_offsets):
        func_end = sec_offsets[idx]

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
            symbols.append(name)
    return symbols


# ---------------------------------------------------------------------------
# Public API: unified dispatchers
# ---------------------------------------------------------------------------


def parse_obj_symbol_bytes(
    obj_path: str | Path, symbol: str
) -> tuple[bytes | None, dict[int, str] | None]:
    """Extract code bytes + relocation offsets for a symbol from an object file.

    Supports COFF ``.obj``, ELF ``.o``, and Mach-O ``.o`` files.
    """
    path_str = str(obj_path)
    fmt = _detect_obj_format(path_str)

    if fmt == "coff":
        return _parse_coff_symbol_bytes(path_str, symbol)
    if fmt == "elf":
        return _parse_elf_symbol_bytes(path_str, symbol)
    if fmt == "macho":
        return _parse_macho_symbol_bytes(path_str, symbol)
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
