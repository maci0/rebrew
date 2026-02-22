import struct
import subprocess
import os
from typing import Optional, Tuple, List
from pathlib import Path

# Padding bytes from config (fallback to x86 CC/90)
try:
    from rebrew.config import cfg as _cfg
    _PADDING_BYTES = tuple(_cfg.padding_bytes)
except Exception:
    _PADDING_BYTES = (0xCC, 0x90)

# Canonical COFF parser
def parse_coff_obj_symbol_bytes(
    obj_path: str, symbol: str
) -> Tuple[Optional[bytes], Optional[List[int]]]:
    """Extract code bytes + relocation offsets for a symbol from COFF .obj."""
    with open(obj_path, "rb") as f:
        data = f.read()

    (num_sections,) = struct.unpack_from("<H", data, 2)
    (sym_offset,) = struct.unpack_from("<I", data, 8)
    (num_symbols,) = struct.unpack_from("<I", data, 12)

    str_tab_off = sym_offset + num_symbols * 18

    def get_sym_name(entry):
        if entry[:4] == b"\x00\x00\x00\x00":
            (offset,) = struct.unpack_from("<I", entry, 4)
            end = data.index(b"\x00", str_tab_off + offset)
            return data[str_tab_off + offset : end].decode()
        return entry[:8].rstrip(b"\x00").decode()

    sections = []
    off = 20
    for _ in range(num_sections):
        sec = data[off : off + 40]
        (raw_size,) = struct.unpack_from("<I", sec, 16)
        (raw_ptr,) = struct.unpack_from("<I", sec, 20)
        (reloc_ptr,) = struct.unpack_from("<I", sec, 24)
        (num_relocs,) = struct.unpack_from("<H", sec, 32)
        sections.append((raw_ptr, raw_size, reloc_ptr, num_relocs))
        off += 40

    i = 0
    while i < num_symbols:
        entry = data[sym_offset + i * 18 : sym_offset + i * 18 + 18]
        name = get_sym_name(entry)
        (value,) = struct.unpack_from("<I", entry, 8)
        (sec_num,) = struct.unpack_from("<h", entry, 12)
        num_aux = entry[17]

        if name == symbol and sec_num > 0:
            sec_idx = sec_num - 1
            raw_ptr, raw_size, reloc_ptr, num_relocs = sections[sec_idx]
            func_start = value
            func_end = raw_size

            j = 0
            while j < num_symbols:
                e2 = data[sym_offset + j * 18 : sym_offset + j * 18 + 18]
                (v2,) = struct.unpack_from("<I", e2, 8)
                (s2,) = struct.unpack_from("<h", e2, 12)
                n2 = get_sym_name(e2)
                if s2 == sec_num and v2 > func_start and v2 < func_end:
                    if not n2.startswith("$"):
                        func_end = v2
                j += 1 + e2[17]

            code = data[raw_ptr + func_start : raw_ptr + func_end]
            while code and code[-1] in _PADDING_BYTES:
                code = code[:-1]

            reloc_offsets = []
            for ri in range(num_relocs):
                roff = reloc_ptr + ri * 10
                (rva,) = struct.unpack_from("<I", data, roff)
                if func_start <= rva < func_end:
                    reloc_offsets.append(rva - func_start)

            return code, reloc_offsets

        i += 1 + num_aux
    return None, None

# Backward-compatible alias
parse_coff_symbol_bytes = parse_coff_obj_symbol_bytes

def list_coff_obj_symbols(obj_path: str) -> List[str]:
    """List all symbols in a COFF .obj file."""
    with open(obj_path, "rb") as f:
        data = f.read()

    (sym_offset,) = struct.unpack_from("<I", data, 8)
    (num_symbols,) = struct.unpack_from("<I", data, 12)
    str_tab_off = sym_offset + num_symbols * 18

    def get_sym_name(entry):
        if entry[:4] == b"\x00\x00\x00\x00":
            (offset,) = struct.unpack_from("<I", entry, 4)
            end = data.index(b"\x00", str_tab_off + offset)
            return data[str_tab_off + offset : end].decode()
        return entry[:8].rstrip(b"\x00").decode()

    symbols = []
    i = 0
    while i < num_symbols:
        entry = data[sym_offset + i * 18 : sym_offset + i * 18 + 18]
        name = get_sym_name(entry)
        (sec_num,) = struct.unpack_from("<h", entry, 12)
        num_aux = entry[17]
        if sec_num > 0 and not name.startswith("$"):
            symbols.append(name)
        i += 1 + num_aux
    return symbols

def extract_function_from_pe(
    pe_path: Path, va: int, size: int, map_path: Optional[Path] = None
) -> Optional[bytes]:
    """Extract raw bytes from a PE file at a given VA."""
    import pefile

    try:
        pe = pefile.PE(str(pe_path))
        rva = va - pe.OPTIONAL_HEADER.ImageBase
        for section in pe.sections:
            if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
                offset = rva - section.VirtualAddress
                data = section.get_data()[offset : offset + size]
                while data and data[-1] in _PADDING_BYTES:
                    data = data[:-1]
                return data
    except Exception as e:
        print(f"Error extracting from PE: {e}")
    return None

def extract_function_from_lib(
    lib_path: Path, obj_name: str, lib_exe: str, symbol: str
) -> Optional[bytes]:
    """Extract an object from a .LIB and parse its symbol bytes."""
    import tempfile
    import shutil

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

        code, _ = parse_coff_obj_symbol_bytes(obj_path, symbol)
        return code
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
