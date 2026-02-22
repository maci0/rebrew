#!/usr/bin/env python3
"""Dump assembly bytes for a function in the target binary.
Usage: python3 dump_asm.py <VA> [size]
"""

import sys
from typing import Optional

import pefile
import typer
from capstone import *

from rebrew.cli import TargetOption, get_config

app = typer.Typer(help="Dump assembly from target binary.")

# Config-driven defaults
try:
    from rebrew.config import cfg as _cfg
    _DEFAULT_EXE = str(_cfg.target_binary)
    _CS_ARCH = _cfg.capstone_arch
    _CS_MODE = _cfg.capstone_mode
except Exception:
    _DEFAULT_EXE = "original/Server/server.dll"
    _CS_ARCH = CS_ARCH_X86
    _CS_MODE = CS_MODE_32


def dump_asm(exe_path, va, size, cs_arch=None, cs_mode=None):
    pe = pefile.PE(exe_path)
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    try:
        offset = pe.get_offset_from_rva(rva)
    except pefile.PEFormatError:
        print(f"ERROR: VA {hex(va)} not found in PE sections.")
        sys.exit(1)

    with open(exe_path, "rb") as f:
        f.seek(offset)
        code = f.read(size)

    arch = cs_arch or _CS_ARCH
    mode = cs_mode or _CS_MODE
    md = Cs(arch, mode)
    md.detail = True
    print(f"; Disassembly for {hex(va)} (size: {size})")
    for i in md.disasm(code, va):
        print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")


@app.command()
def main(
    va: str = typer.Argument(help="Virtual Address in hex (e.g., 0x100011f0)"),
    size: int = typer.Argument(256, help="Number of bytes to disassemble"),
    exe: Optional[str] = typer.Option(None, help="Target PE file path (default: from config)"),
    target: Optional[str] = TargetOption,
):
    """Dump disassembly from the target binary at a given VA."""
    cfg = get_config(target)
    exe_path = exe or str(cfg.target_binary)
    dump_asm(exe_path, int(va, 16), size, cfg.capstone_arch, cfg.capstone_mode)


if __name__ == "__main__":
    app()

