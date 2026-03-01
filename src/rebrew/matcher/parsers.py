"""Object file and binary parsers for rebrew.

Provides functions to extract symbol bytes and relocation offsets from
object files (COFF ``.obj``, ELF ``.o``, Mach-O ``.o``) and to extract
function bytes from linked binaries (PE, ELF, Mach-O).

All format parsing is backed by LIEF.
"""

import struct
import warnings
from collections.abc import Iterable
from pathlib import Path
from typing import Any

# x86 padding bytes used to trim trailing filler from compiled functions.
# 0xCC = int3 (breakpoint), 0x90 = nop
_PADDING_BYTES = (0xCC, 0x90)
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
# Object file format detection
# ---------------------------------------------------------------------------


def _detect_obj_format(obj_path: str) -> str:
    """Detect object file format from magic bytes."""
    with open(obj_path, "rb") as f:
        magic = f.read(4)
    if magic[:4] == b"\x7fELF":
        return "elf"
    if magic[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ):
        return "macho"
    # COFF: check for valid machine type in first 2 bytes
    # i386=0x14c, AMD64=0x8664, ARM=0x1c0, ARM64=0xaa64
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

    # Find the end of this function: next symbol in same section with higher offset
    func_end = len(content)
    for sym in coff.symbols:
        if (
            sym.section is not None
            and sym.section.name == section.name
            and sym.value > func_start
            and sym.value < func_end
            and not str(sym.name).startswith("$")
        ):
            func_end = sym.value

    code = content[func_start:func_end].rstrip(_PADDING_STRIP)
    reloc_offsets = _collect_reloc_offsets(section.relocations, func_start, func_end)
    return code, reloc_offsets


def _list_coff_symbols(obj_path: str) -> list[str]:
    """List all public symbols in a COFF .obj file using LIEF."""
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return []

    symbols = []
    for sym in coff.symbols:
        if (
            sym.section is not None
            and not str(sym.name).startswith("$")
            and sym.storage_class == lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL
        ):
            symbols.append(sym.name)
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
        func_end = len(content)
        for sym in elf.symbols:
            if (
                hasattr(sym, "section")
                and sym.section is not None
                and sym.section.name == section.name
                and sym.value > func_start
                and sym.value < func_end
            ):
                func_end = sym.value

    code = content[func_start:func_end].rstrip(_PADDING_STRIP)

    # ELF relocations are global — filter to our section before collecting
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

    symbols = []
    for sym in elf.symbols:
        if (
            sym.name
            and sym.value is not None
            and sym.binding == lief.ELF.Symbol.BINDING.GLOBAL
            and sym.type == lief.ELF.Symbol.TYPE.FUNC
        ):
            symbols.append(sym.name)
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

    # Determine function end by finding the next symbol after func_start
    func_end = len(content)
    for sym in binary.symbols:
        if (
            hasattr(sym, "section")
            and sym.section is not None
            and getattr(sym.section, "name", None) == getattr(section, "name", None)
        ):
            sym_off = sym.value - section.virtual_address
            if sym_off > func_start and sym_off < func_end:
                func_end = sym_off

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
    obj_path: str, symbol: str
) -> tuple[bytes | None, dict[int, str] | None]:
    """Extract code bytes + relocation offsets for a symbol from an object file.

    Supports COFF ``.obj``, ELF ``.o``, and Mach-O ``.o`` files.
    """
    obj_path = str(obj_path)
    fmt = _detect_obj_format(obj_path)

    if fmt == "coff":
        return _parse_coff_symbol_bytes(obj_path, symbol)
    elif fmt == "elf":
        return _parse_elf_symbol_bytes(obj_path, symbol)
    elif fmt == "macho":
        return _parse_macho_symbol_bytes(obj_path, symbol)
    else:
        return None, None


def list_obj_symbols(obj_path: str) -> list[str]:
    """List all public symbols in an object file.

    Supports COFF ``.obj``, ELF ``.o``, and Mach-O ``.o`` files.
    """
    obj_path = str(obj_path)
    fmt = _detect_obj_format(obj_path)

    if fmt == "coff":
        return _list_coff_symbols(obj_path)
    elif fmt == "elf":
        return _list_elf_symbols(obj_path)
    elif fmt == "macho":
        return _list_macho_symbols(obj_path)
    else:
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
