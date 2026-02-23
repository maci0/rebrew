#!/usr/bin/env python3
"""Dump assembly bytes for a function from the target binary.

Usage:
    rebrew-asm 0x10003ca0 --size 77
    rebrew-asm --va 0x10003ca0 --size 77
"""

import json
import os
from pathlib import Path

import typer

from rebrew.annotation import parse_c_file
from rebrew.cli import TargetOption, get_config
from rebrew.verify import load_ghidra_functions

app = typer.Typer(
    help="Dump hex/asm for a function from the target binary.",
)


def build_function_lookup(cfg) -> dict[int, tuple[str, str]]:
    """Build a VA -> (name, status) lookup from Ghidra JSON and existing .c files.
    
    Returns dict mapping VA int -> (display_name, status_string).
    Status is one of: EXACT, RELOC, MATCHING, STUB, or '' for Ghidra-only.
    """
    lookup: dict[int, tuple[str, str]] = {}

    # Load Ghidra function names
    ghidra_json = cfg.reversed_dir / "ghidra_functions.json"
    ghidra_funcs = load_ghidra_functions(ghidra_json)
    for func in ghidra_funcs:
        va = func.get("va")
        name = func.get("ghidra_name", "")
        if va and name:
            lookup[va] = (name, "")

    # Override with names from existing .c files (more accurate)
    src_dir = Path(cfg.reversed_dir)
    if src_dir.is_dir():
        for cfile in src_dir.glob("*.c"):
            try:
                entry = parse_c_file(cfile)
                if not entry:
                    continue
                
                va = entry.va
                status = entry.status
                symbol = entry.symbol.lstrip("_")
                
                display = symbol or cfile.stem
                lookup[va] = (display, status)
            except Exception:
                continue

    return lookup


@app.command()
def main(
    va_hex: str | None = typer.Argument(None, help="Function VA in hex"),
    va: str | None = typer.Option(None, "--va", help="Function VA in hex"),
    size: int = typer.Option(32, help="Function size in bytes"),
    annotate: bool = typer.Option(True, "--annotate/--no-annotate", help="Annotate calls with known function names"),
    target: str | None = TargetOption,
):
    """Dump hex/asm for a function from the target binary."""
    va_str = va or va_hex
    if not va_str:
        print("Error: Specify VA as a positional argument or via --va")
        raise typer.Exit(code=1)

    cfg = get_config(target=target)
    bin_path = cfg.target_binary

    if not bin_path.exists():
        print(f"Error: Binary not found at {bin_path}")
        raise typer.Exit(code=1)

    va_int = int(va_str, 16)

    # Build function name lookup for call annotation
    func_lookup: dict[int, tuple[str, str]] = {}
    if annotate:
        func_lookup = build_function_lookup(cfg)

    # Read the bytes from the binary using config's PE-aware offset calculation
    try:
        data = cfg.extract_dll_bytes(va_int, size)

        print(f"Dumping 0x{va_int:08x} ({len(data)} bytes) from {bin_path.name}:")
        print()

        # Try capstone disassembly
        try:
            from capstone import CS_ARCH_X86, CS_MODE_32, Cs
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.detail = False
            for insn in md.disasm(data, va_int):
                hex_bytes = insn.bytes.hex()
                line = f"  0x{insn.address:08x}:  {hex_bytes:<20s}  {insn.mnemonic:<8s} {insn.op_str}"

                # Annotate call/jmp targets with known function names
                if annotate and insn.mnemonic in ("call", "jmp") and insn.op_str.startswith("0x"):
                    try:
                        target_va = int(insn.op_str, 16)
                        if target_va in func_lookup:
                            name, status = func_lookup[target_va]
                            tag = f" ({status})" if status else ""
                            line += f"  ; {name}{tag}"
                    except ValueError:
                        pass

                print(line)
        except ImportError:
            # Fallback to hex dump if capstone not available
            print("(capstone not installed, showing hex dump)")
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"  0x{va_int + i:08x}:  {hex_str:<48s}  {ascii_str}")
    except Exception as e:
        print(f"Error: {e}")
        raise typer.Exit(code=1)



def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
