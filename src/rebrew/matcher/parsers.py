"""Object file and binary parsers for rebrew.

Provides functions to extract symbol bytes and relocation offsets from
object files (COFF ``.obj``, ELF ``.o``, Mach-O ``.o``) and to extract
function bytes from linked binaries (PE, ELF, Mach-O).

All format parsing is backed by LIEF.
"""

import os
import subprocess
from pathlib import Path

# Padding bytes from config (fallback to x86 CC/90)
try:
    from rebrew.config import cfg as _cfg
    _PADDING_BYTES = tuple(_cfg.padding_bytes)
except Exception:
    _PADDING_BYTES = (0xCC, 0x90)


# ---------------------------------------------------------------------------
# Object file format detection
# ---------------------------------------------------------------------------

def _detect_obj_format(obj_path: str) -> str:
    """Detect object file format from magic bytes."""
    with open(obj_path, "rb") as f:
        magic = f.read(4)
    if magic[:4] == b"\x7fELF":
        return "elf"
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                      b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    # COFF: check for valid machine type in first 2 bytes
    # i386=0x14c, AMD64=0x8664, ARM=0x1c0, ARM64=0xaa64
    if len(magic) >= 2:
        import struct
        (machine,) = struct.unpack_from("<H", magic, 0)
        if machine in (0x14C, 0x8664, 0x1C0, 0xAA64, 0):
            return "coff"
    return "coff"  # default fallback


# ---------------------------------------------------------------------------
# COFF .obj parsing via LIEF
# ---------------------------------------------------------------------------

def _parse_coff_symbol_bytes(
    obj_path: str, symbol: str
) -> tuple[bytes | None, list[int] | None]:
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
        if (sym.section is not None and sym.section.name == section.name
                and sym.value > func_start and sym.value < func_end
                and not sym.name.startswith("$")):
            func_end = sym.value

    code = content[func_start:func_end]

    # Trim trailing padding
    while code and code[-1] in _PADDING_BYTES:
        code = code[:-1]

    # Collect relocation offsets within this function
    reloc_offsets = []
    for reloc in section.relocations:
        rva = reloc.address
        if func_start <= rva < func_end:
            reloc_offsets.append(rva - func_start)

    return code, reloc_offsets


def _list_coff_symbols(obj_path: str) -> list[str]:
    """List all public symbols in a COFF .obj file using LIEF."""
    import lief
    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return []

    symbols = []
    for sym in coff.symbols:
        if (sym.section is not None
                and not sym.name.startswith("$")
                and sym.storage_class == lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL):
            symbols.append(sym.name)
    return symbols


# ---------------------------------------------------------------------------
# ELF .o parsing via LIEF
# ---------------------------------------------------------------------------

def _parse_elf_symbol_bytes(
    obj_path: str, symbol: str
) -> tuple[bytes | None, list[int] | None]:
    """Extract code bytes + relocation offsets for a symbol from ELF .o using LIEF."""
    import lief
    elf = lief.ELF.parse(str(obj_path))
    if elf is None:
        return None, None

    # Find the target symbol
    target_sym = None
    for sym in elf.symbols:
        if sym.name == symbol and sym.value is not None:
            target_sym = sym
            break

    if target_sym is None:
        return None, None

    # Get the section containing this symbol
    # In ELF .o files, sym.shndx gives the section index
    section = None
    if hasattr(target_sym, 'section') and target_sym.section is not None:
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
            if (hasattr(sym, 'section') and sym.section is not None
                    and sym.section.name == section.name
                    and sym.value > func_start and sym.value < func_end):
                func_end = sym.value

    code = content[func_start:func_end]

    # Trim trailing padding
    while code and code[-1] in _PADDING_BYTES:
        code = code[:-1]

    # Collect relocation offsets
    reloc_offsets = []
    for reloc in elf.relocations:
        if (hasattr(reloc, 'section') and reloc.section is not None
                and reloc.section.name == section.name):
            rva = reloc.address
            if func_start <= rva < func_end:
                reloc_offsets.append(rva - func_start)

    return code, reloc_offsets


def _list_elf_symbols(obj_path: str) -> list[str]:
    """List all public symbols in an ELF .o file using LIEF."""
    import lief
    elf = lief.ELF.parse(str(obj_path))
    if elf is None:
        return []

    symbols = []
    for sym in elf.symbols:
        if (sym.name and sym.value is not None
                and sym.binding == lief.ELF.Symbol.BINDING.GLOBAL
                and sym.type == lief.ELF.Symbol.TYPE.FUNC):
            symbols.append(sym.name)
    return symbols


# ---------------------------------------------------------------------------
# Mach-O .o parsing via LIEF
# ---------------------------------------------------------------------------

def _parse_macho_symbol_bytes(
    obj_path: str, symbol: str
) -> tuple[bytes | None, list[int] | None]:
    """Extract code bytes + relocation offsets for a symbol from Mach-O .o using LIEF."""
    import lief
    fat = lief.MachO.parse(str(obj_path))
    if fat is None:
        return None, None
    binary = fat.at(0)

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
    if hasattr(target_sym, 'section') and target_sym.section is not None:
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

    # Determine function end
    func_end = len(content)
    for sym in binary.symbols:
        if (hasattr(sym, 'section') and sym.section is not None
                and sym.section.name == section.name):
            sym_off = sym.value - section.virtual_address
            if sym_off > func_start and sym_off < func_end:
                func_end = sym_off

    if func_start < 0 or func_start >= len(content):
        return None, None

    code = content[func_start:func_end]

    # Trim trailing padding
    while code and code[-1] in _PADDING_BYTES:
        code = code[:-1]

    # Collect relocation offsets
    reloc_offsets = []
    for reloc in section.relocations:
        rva = reloc.address
        if func_start <= rva < func_end:
            reloc_offsets.append(rva - func_start)

    return code, reloc_offsets


def _list_macho_symbols(obj_path: str) -> list[str]:
    """List all public symbols in a Mach-O .o file using LIEF."""
    import lief
    fat = lief.MachO.parse(str(obj_path))
    if fat is None:
        return []
    binary = fat.at(0)

    symbols = []
    for sym in binary.symbols:
        if sym.name and sym.type > 0:
            # Strip leading underscore (Mach-O convention)
            name = sym.name.lstrip("_") if sym.name.startswith("_") else sym.name
            symbols.append(sym.name)
    return symbols


# ---------------------------------------------------------------------------
# Public API: unified dispatchers
# ---------------------------------------------------------------------------

def parse_obj_symbol_bytes(
    obj_path: str, symbol: str
) -> tuple[bytes | None, list[int] | None]:
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


# Backward-compatible aliases
parse_coff_obj_symbol_bytes = parse_obj_symbol_bytes
parse_coff_symbol_bytes = parse_obj_symbol_bytes
list_coff_obj_symbols = list_obj_symbols


# ---------------------------------------------------------------------------
# Binary extraction (linked executables)
# ---------------------------------------------------------------------------

def extract_function_from_binary(
    bin_path: Path, va: int, size: int, map_path: Path | None = None
) -> bytes | None:
    """Extract raw bytes from a binary file at a given VA.

    Supports PE, ELF, and Mach-O via ``binary_loader``.
    """
    try:
        from rebrew.binary_loader import extract_bytes_at_va, load_binary
        info = load_binary(bin_path)
        return extract_bytes_at_va(info, va, size, padding_bytes=tuple(_PADDING_BYTES))
    except Exception as e:
        print(f"Error extracting from binary: {e}")
    return None


# Backward-compatible alias
extract_function_from_pe = extract_function_from_binary


def extract_function_from_lib(
    lib_path: Path, obj_name: str, lib_exe: str, symbol: str
) -> bytes | None:
    """Extract an object from a .LIB and parse its symbol bytes."""
    import shutil
    import tempfile

    workdir = tempfile.mkdtemp(prefix="lib_extract_")
    try:
        cmd = lib_exe.split() + [f"/EXTRACT:{obj_name}", f"/OUT:{obj_name}", str(lib_path)]
        env = {**os.environ, "WINEDEBUG": "-all"}
        r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env)
        if r.returncode != 0:
            print(f"LIB.EXE error: {r.stderr.decode()}")
            return None

        obj_path = os.path.join(workdir, obj_name)
        if not os.path.exists(obj_path):
            return None

        code, _ = parse_obj_symbol_bytes(obj_path, symbol)
        return code
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
