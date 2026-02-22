#!/usr/bin/env python3
"""Batch extract and disassemble functions from server.dll.

Reads r2_functions.txt (or .json), auto-detects already-reversed VAs from
src/server_dll/*.c annotations, and lets you list/extract/batch the remaining
candidates.

Usage:
    python3 batch_extract.py list                # List un-reversed candidates
    python3 batch_extract.py extract 0x10001860  # Extract + disasm one VA
    python3 batch_extract.py batch 20            # Extract first 20 smallest
    python3 batch_extract.py batch 20 --start 10 # Offset into sorted list
"""

import typer
from typing import Optional
import json
import os
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# SCRIPT_DIR removed — use load_config()
# PROJECT_ROOT removed — use cfg.root

from verify import parse_c_file, parse_r2_functions


# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------


def load_pe(dll_path: Path):
    """Load PE and return (pe, dll_data)."""
    pe = pefile.PE(str(dll_path))
    with open(dll_path, "rb") as f:
        data = f.read()
    return pe, data


def va_to_file_offset(pe, va: int) -> int:
    """Convert VA to raw file offset using PE section headers."""
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        sec_start = section.VirtualAddress
        sec_end = sec_start + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return section.PointerToRawData + (rva - sec_start)
    # Fallback for .text section
    return rva


def extract_bytes(dll_data: bytes, pe, va: int, size: int) -> bytes:
    """Extract raw bytes from DLL at given VA."""
    off = va_to_file_offset(pe, va)
    data = dll_data[off : off + size]
    # Trim trailing padding
    while data and data[-1] in (0xCC, 0x90):
        data = data[:-1]
    return data


# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------

_md = Cs(CS_ARCH_X86, CS_MODE_32)


def disasm(code_bytes: bytes, va: int) -> str:
    """Disassemble using capstone and return formatted string."""
    lines = []
    for insn in _md.disasm(code_bytes, va):
        hex_bytes = insn.bytes.hex()
        lines.append(f"  {insn.address:08X}  {hex_bytes:20s}  {insn.mnemonic:6s} {insn.op_str}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Auto-detect reversed VAs
# ---------------------------------------------------------------------------


def detect_reversed_vas(src_dir: Path) -> set:
    """Scan src/server_dll/*.c for annotation headers and return set of VAs."""
    reversed_vas = set()
    if not src_dir.exists():
        return reversed_vas
    for cfile in sorted(src_dir.glob("*.c")):
        entry = parse_c_file(cfile)
        if entry is not None:
            reversed_vas.add(entry["va"])
    return reversed_vas


# ---------------------------------------------------------------------------
# Load function list
# ---------------------------------------------------------------------------


def load_functions(root: Path):
    """Load function list from r2_functions.txt (preferred) or .json."""
    txt_path = root / "src" / "server_dll" / "r2_functions.txt"
    json_path = root / "src" / "server_dll" / "r2_functions.json"

    if txt_path.exists():
        return parse_r2_functions(txt_path)

    if json_path.exists():
        with open(json_path) as f:
            raw = json.load(f)
        return [
            {"va": fn["offset"], "size": fn.get("realsz", fn.get("size", 0)), "r2_name": fn["name"]}
            for fn in raw
        ]

    print(f"ERROR: No function list found at {txt_path} or {json_path}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_list(candidates):
    """List candidate functions."""
    print(f"Candidates: {len(candidates)} (sorted by size)")
    for i, (va, size, name) in enumerate(candidates):
        print(f"  {i:3d}  0x{va:08X}  {size:5d}B  {name}")


def cmd_extract(dll_data, pe, candidates, target_va, bin_dir):
    """Extract and disassemble a single function."""
    for va, size, name in candidates:
        if va == target_va:
            code = extract_bytes(dll_data, pe, va, size)
            print(f"=== {name} @ 0x{va:08X}, {len(code)} bytes ===")
            print(f"Hex: {code.hex()}")
            print()
            print(disasm(code, va))
            # Save .bin
            os.makedirs(bin_dir, exist_ok=True)
            bin_path = os.path.join(bin_dir, f"func_0x{va:08X}.bin")
            with open(bin_path, "wb") as f:
                f.write(code)
            print(f"\nSaved to {bin_path}")
            return
    print(f"VA 0x{target_va:08X} not found in candidate list")


def cmd_batch(dll_data, pe, candidates, count, start, bin_dir):
    """Extract and disassemble a batch of functions."""
    os.makedirs(bin_dir, exist_ok=True)
    batch = candidates[start : start + count]
    for va, size, name in batch:
        code = extract_bytes(dll_data, pe, va, size)
        print(f"\n{'=' * 60}")
        print(f"=== {name} @ 0x{va:08X}, {len(code)} bytes ===")
        print(f"{'=' * 60}")
        print(f"Hex: {code.hex()}")
        print()
        print(disasm(code, va))
        bin_path = os.path.join(bin_dir, f"func_0x{va:08X}.bin")
        with open(bin_path, "wb") as f:
            f.write(code)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


app = typer.Typer(help="Batch extract and disassemble functions from server.dll.")


@app.command()
def main(
    command: str = typer.Argument(help="Command: list, extract, or batch"),
    batch_target: Optional[str] = typer.Argument(None, help="VA (hex) for extract, or count for batch"),
    exe: Optional[Path] = typer.Option(None, help="Path to DLL/EXE (default: from config)"),
    root: Path = typer.Option(PROJECT_ROOT, help="Project root directory"),
    start: int = typer.Option(0, help="Start offset for batch mode"),
    min_size: int = typer.Option(8, help="Minimum function size"),
    max_size: int = typer.Option(50000, help="Maximum function size"),
    config_target: Optional[str] = typer.Option(None, "--target", "-t", help="Target from rebrew.toml"),
):
    """Batch extract and disassemble functions from server.dll."""
    args = type("Args", (), {
        "command": command, "target": batch_target,
        "exe": exe or (PROJECT_ROOT / "original" / "Server" / "server.dll"),
        "root": root, "start": start, "min_size": min_size, "max_size": max_size,
    })()

    root = args.root
    src_dir = root / "src" / "server_dll"
    bin_dir = str(root / "bin" / "server_dll")

    # Load functions
    funcs = load_functions(root)

    # Auto-detect already-reversed VAs
    reversed_vas = detect_reversed_vas(src_dir)
    print(f"Found {len(reversed_vas)} already-reversed functions", file=sys.stderr)

    # Filter candidates
    candidates = []
    for fn in funcs:
        va = fn["va"]
        size = fn["size"]
        name = fn["r2_name"]

        if va in reversed_vas:
            continue
        if size < args.min_size or size > args.max_size:
            continue

        candidates.append((va, size, name))

    candidates.sort(key=lambda x: x[1])  # Sort by size

    if args.command == "list":
        cmd_list(candidates)
    elif args.command == "extract":
        if not args.target:
            print("ERROR: extract requires a VA argument (e.g. 0x10001860)")
            sys.exit(1)
        pe, dll_data = load_pe(args.exe)
        target_va = int(args.target, 16)
        cmd_extract(dll_data, pe, candidates, target_va, bin_dir)
    elif args.command == "batch":
        count = int(args.target) if args.target else 20
        pe, dll_data = load_pe(args.exe)
        cmd_batch(dll_data, pe, candidates, count, args.start, bin_dir)


if __name__ == "__main__":
    app()
