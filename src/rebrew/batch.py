#!/usr/bin/env python3
"""Batch extract and disassemble functions from the target binary.

Reads a function list (r2_functions.txt or .json), auto-detects already-reversed VAs from
the projects src directory, and lets you list/extract/batch the remaining
candidates.

Usage:
    rebrew extract list                # List un-reversed candidates
    rebrew extract extract 0x10001860  # Extract + disasm one VA
    rebrew extract batch 20            # Extract first 20 smallest
    rebrew extract batch 20 --start 10 # Offset into sorted list
"""

import json
import sys
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import parse_c_file_multi
from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
from rebrew.catalog import parse_r2_functions
from rebrew.cli import get_config

# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------


def load_target_binary(bin_path: Path) -> BinaryInfo:
    """Load binary and return BinaryInfo."""
    return load_binary(bin_path)


def extract_bytes(binary_info: BinaryInfo, va: int, size: int) -> bytes:
    """Extract raw bytes from binary at given VA."""
    data = extract_bytes_at_va(binary_info, va, size)
    return data if data is not None else b""


# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------


def disasm(code_bytes: bytes, va: int, cfg: Any = None) -> str:
    """Disassemble using capstone and return formatted string."""
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    arch = getattr(cfg, "capstone_arch", CS_ARCH_X86) if cfg else CS_ARCH_X86
    mode = getattr(cfg, "capstone_mode", CS_MODE_32) if cfg else CS_MODE_32
    md = Cs(arch, mode)
    lines = []
    for insn in md.disasm(code_bytes, va):
        hex_bytes = insn.bytes.hex()
        lines.append(f"  {insn.address:08X}  {hex_bytes:20s}  {insn.mnemonic:6s} {insn.op_str}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Auto-detect reversed VAs
# ---------------------------------------------------------------------------


def detect_reversed_vas(src_dir: Path, cfg: Any = None) -> set[int]:
    """Scan the reversed source directory for annotation headers and return set of VAs."""
    from rebrew.cli import source_glob

    reversed_vas: set[int] = set()
    if not src_dir.exists():
        return reversed_vas
    for cfile in sorted(src_dir.glob(source_glob(cfg))):
        for entry in parse_c_file_multi(cfile):
            if entry.marker_type not in ("GLOBAL", "DATA"):
                reversed_vas.add(entry.va)
    return reversed_vas


# ---------------------------------------------------------------------------
# Load function list
# ---------------------------------------------------------------------------


def load_functions(cfg: Any) -> list[dict[str, int | str]]:
    """Load function list from r2_functions.txt (preferred) or .json."""
    txt_path = cfg.function_list
    json_path = txt_path.with_suffix(".json")

    if txt_path.exists():
        return parse_r2_functions(txt_path)

    if json_path.exists():
        with open(json_path, encoding="utf-8") as f:
            raw = json.load(f)
        return [
            {"va": fn["offset"], "size": fn.get("realsz", fn.get("size", 0)), "r2_name": fn["name"]}
            for fn in raw
        ]

    print(f"ERROR: No function list found at {txt_path} or {json_path}", file=sys.stderr)
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_list(candidates: list[tuple[int, int, str]]) -> None:
    """List candidate functions."""
    print(f"Candidates: {len(candidates)} (sorted by size)")
    for i, (va, size, name) in enumerate(candidates):
        print(f"  {i:3d}  0x{va:08X}  {size:5d}B  {name}")


def cmd_extract(
    binary_info: BinaryInfo,
    candidates: list[tuple[int, int, str]],
    target_va: int,
    bin_dir: Path,
    cfg: Any = None,
) -> None:
    """Extract and disassemble a single function."""
    for va, size, name in candidates:
        if va == target_va:
            code = extract_bytes(binary_info, va, size)
            print(f"=== {name} @ 0x{va:08X}, {len(code)} bytes ===")
            print(f"Hex: {code.hex()}")
            print()
            print(disasm(code, va, cfg=cfg))
            # Save .bin
            bin_dir.mkdir(parents=True, exist_ok=True)
            bin_path = bin_dir / f"func_0x{va:08X}.bin"
            bin_path.write_bytes(code)
            print(f"\nSaved to {bin_path}")
            return
    print(f"VA 0x{target_va:08X} not found in candidate list")


def cmd_batch(
    binary_info: BinaryInfo,
    candidates: list[tuple[int, int, str]],
    count: int,
    start: int,
    bin_dir: Path,
    cfg: Any = None,
) -> None:
    """Extract and disassemble a batch of functions."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    batch = candidates[start : start + count]
    for va, size, name in batch:
        code = extract_bytes(binary_info, va, size)
        print(f"\n{'=' * 60}")
        print(f"=== {name} @ 0x{va:08X}, {len(code)} bytes ===")
        print(f"{'=' * 60}")
        print(f"Hex: {code.hex()}")
        print()
        print(disasm(code, va, cfg=cfg))
        bin_path = bin_dir / f"func_0x{va:08X}.bin"
        bin_path.write_bytes(code)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Batch extract and disassemble functions from the target binary.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]
  rebrew-batch                            Extract all annotated functions
  rebrew-batch --extract                  Extract .bin files for each function
  rebrew-batch --disasm                   Disassemble all extracted functions
  rebrew-batch --origin GAME              Filter by origin
  rebrew-batch --status STUB              Only STUB functions
  rebrew-batch -j 8                       Parallel extraction with 8 jobs

[dim]Reads function list from reversed .c file annotations.
Outputs .bin and .asm files to the configured bin_dir.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    command: str = typer.Argument(help="Command: list, extract, or batch"),
    batch_target: str | None = typer.Argument(
        None, help="VA (hex) for extract, or count for batch"
    ),
    exe: Path | None = typer.Option(None, help="Path to DLL/EXE (default: from config)"),
    root: Path = typer.Option(
        Path.cwd(), help="Project root directory (auto-detected via rebrew.toml)"
    ),
    start: int = typer.Option(0, help="Start offset for batch mode"),
    min_size: int = typer.Option(8, help="Minimum function size"),
    max_size: int = typer.Option(50000, help="Maximum function size"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    config_target: str | None = typer.Option(
        None, "--target", "-t", help="Target from rebrew.toml"
    ),
) -> None:
    """Batch extract and disassemble functions from the target binary."""
    cfg = get_config(target=config_target)

    exe_path = exe or cfg.target_binary
    src_dir = cfg.reversed_dir
    bin_dir = cfg.bin_dir

    # Load functions
    funcs = load_functions(cfg)

    # Auto-detect already-reversed VAs
    reversed_vas = detect_reversed_vas(src_dir, cfg=cfg)
    print(f"Found {len(reversed_vas)} already-reversed functions", file=sys.stderr)

    # Filter candidates — cast dict values to expected types for type safety
    candidates: list[tuple[int, int, str]] = []
    for fn in funcs:
        va = int(fn["va"])
        size = int(fn["size"])
        name = str(fn["r2_name"])

        if va in reversed_vas:
            continue
        if size < min_size or size > max_size:
            continue

        candidates.append((va, size, name))

    candidates.sort(key=lambda x: x[1])  # Sort by size

    if command == "list":
        if json_output:
            items = [{"va": f"0x{va:08x}", "size": sz, "name": nm} for va, sz, nm in candidates]
            print(json.dumps({"count": len(candidates), "candidates": items}, indent=2))
            return
        cmd_list(candidates)
    elif command == "extract":
        if not batch_target:
            print("ERROR: extract requires a VA argument (e.g. 0x10001860)", file=sys.stderr)
            raise typer.Exit(code=1)
        binary_info = load_target_binary(exe_path)
        try:
            target_va = int(batch_target, 16)
        except ValueError:
            print(f"ERROR: Invalid hex address '{batch_target}'", file=sys.stderr)
            raise typer.Exit(code=1)
        cmd_extract(binary_info, candidates, target_va, bin_dir, cfg=cfg)
    elif command == "batch":
        try:
            count = int(batch_target) if batch_target else 20
        except ValueError:
            print(f"ERROR: Invalid count '{batch_target}'", file=sys.stderr)
            raise typer.Exit(code=1)
        binary_info = load_target_binary(exe_path)
        cmd_batch(binary_info, candidates, count, start, bin_dir, cfg=cfg)
    else:
        print(f"ERROR: Unknown command '{command}'. Use list, extract, or batch.", file=sys.stderr)
        raise typer.Exit(code=1)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
