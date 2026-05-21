"""extract.py - Extract and disassemble functions from the target binary.

Reads a function list (functions.txt or .json), auto-detects already-reversed VAs from
the project's src directory, and lets you list/extract/batch the remaining
candidates.

Usage:
    rebrew extract list                # List un-reversed candidates
    rebrew extract show 0x10001860     # Extract + disasm one VA
    rebrew extract batch 20            # Extract first 20 smallest
    rebrew extract batch 20 --start 10 # Offset into sorted list
"""

import json
from pathlib import Path
from typing import Any, cast

import typer
from rich.console import Console
from rich.table import Table

from rebrew.asm import disasm_bytes
from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
from rebrew.catalog import parse_function_list, scan_reversed_dir
from rebrew.cli import TargetOption, error_exit, json_print, parse_va, require_config
from rebrew.config import ProjectConfig

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------


def extract_bytes(binary_info: BinaryInfo, va: int, size: int) -> bytes:
    """Extract raw bytes from binary at given VA, returning empty bytes on failure."""
    return extract_bytes_at_va(binary_info, va, size) or b""


# ---------------------------------------------------------------------------
# Auto-detect reversed VAs
# ---------------------------------------------------------------------------


def detect_reversed_vas(src_dir: Path, cfg: ProjectConfig | None = None) -> set[int]:
    """Scan the reversed source directory for annotation headers and return set of VAs."""
    if not src_dir.exists():
        return set()
    return {
        entry.va
        for entry in scan_reversed_dir(src_dir, cfg=cfg)
        if entry.marker_type not in ("GLOBAL", "DATA")
    }


# ---------------------------------------------------------------------------
# Load function list
# ---------------------------------------------------------------------------


def load_functions(cfg: ProjectConfig) -> list[dict[str, int | str]]:
    """Load function list from functions.txt (preferred) or .json."""
    txt_path = cfg.function_list
    json_path = txt_path.with_suffix(".json")

    if txt_path.exists():
        raw_funcs = parse_function_list(txt_path)
        return [
            {"va": int(fn["va"]), "size": int(fn["size"]), "name": str(fn["name"])}
            for fn in raw_funcs
        ]

    if json_path.exists():
        with json_path.open(encoding="utf-8") as f:
            raw = cast(list[dict[str, Any]], json.load(f))
        return [
            {
                "va": int(fn["offset"]),
                "size": int(fn.get("realsz", fn.get("size", 0))),
                "name": str(fn["name"]),
            }
            for fn in raw
        ]

    raise FileNotFoundError(f"No function list found at {txt_path} or {json_path}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_list(candidates: list[tuple[int, int, str]]) -> None:
    """List candidate functions."""
    table = Table(title=f"Candidates ({len(candidates)}, sorted by size)")
    table.add_column("#", justify="right", style="bold")
    table.add_column("VA", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Name", style="magenta")
    for i, (va, size, name) in enumerate(candidates):
        table.add_row(str(i), f"0x{va:08X}", f"{size}B", name)
    console.print(table)


def cmd_extract(
    binary_info: BinaryInfo,
    candidates: list[tuple[int, int, str]],
    target_va: int,
    bin_dir: Path,
    cfg: ProjectConfig | None = None,
    *,
    json_output: bool = False,
) -> None:
    """Extract and disassemble a single function."""
    for va, size, name in candidates:
        if va == target_va:
            code = extract_bytes_at_va(binary_info, va, size) or b""
            if code == b"":
                msg = f"Failed to extract bytes at VA 0x{va:08X}"
                if json_output:
                    json_print({"status": "ERROR", "error": msg})
                else:
                    console.print(f"[red bold]error:[/red bold] {msg}")
                return
            try:
                asm_text = disasm_bytes(code, va, cfg=cfg)
            except RuntimeError as e:
                if json_output:
                    json_print({"status": "ERROR", "error": str(e)})
                else:
                    console.print(f"[red bold]error:[/red bold] {e}")
                return

            # Save .bin
            bin_dir.mkdir(parents=True, exist_ok=True)
            bin_path = bin_dir / f"func_0x{va:08X}.bin"
            bin_path.write_bytes(code)

            if json_output:
                json_print(
                    {
                        "status": "OK",
                        "name": name,
                        "va": f"0x{va:08x}",
                        "size": len(code),
                        "hex": code.hex(),
                        "asm": asm_text,
                        "bin_path": str(bin_path),
                    }
                )
                return

            console.print(f"\n[bold]=== {name} @ 0x{va:08X}, {len(code)} bytes ===[/]")
            print(f"Hex: {code.hex()}")
            print()
            print(asm_text)
            console.print(f"Saved to {bin_path}")
            return
    if json_output:
        json_print(
            {"status": "ERROR", "error": f"VA 0x{target_va:08X} not found in candidate list"}
        )
        return
    console.print(f"[red bold]error:[/red bold] VA 0x{target_va:08X} not found in candidate list")


def cmd_batch(
    binary_info: BinaryInfo,
    candidates: list[tuple[int, int, str]],
    count: int,
    start: int,
    bin_dir: Path,
    cfg: ProjectConfig | None = None,
    *,
    json_output: bool = False,
) -> None:
    """Extract and disassemble a batch of functions."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    batch = candidates[start : start + count]
    items: list[dict[str, str | int]] = []
    for va, size, name in batch:
        code = extract_bytes_at_va(binary_info, va, size) or b""
        if code == b"":
            if json_output:
                items.append(
                    {
                        "status": "ERROR",
                        "name": name,
                        "va": f"0x{va:08x}",
                        "size": size,
                        "error": "Failed to extract bytes",
                    }
                )
                continue
            console.print(f"[red bold]error:[/red bold] Failed to extract bytes at VA 0x{va:08X}")
            continue

        try:
            asm_text = disasm_bytes(code, va, cfg=cfg)
        except RuntimeError as e:
            if json_output:
                items.append(
                    {
                        "status": "ERROR",
                        "name": name,
                        "va": f"0x{va:08x}",
                        "size": size,
                        "error": str(e),
                    }
                )
                continue
            console.print(f"[red bold]error:[/red bold] {e}")
            return

        bin_path = bin_dir / f"func_0x{va:08X}.bin"
        bin_path.write_bytes(code)

        if json_output:
            items.append(
                {
                    "status": "OK",
                    "name": name,
                    "va": f"0x{va:08x}",
                    "size": len(code),
                    "hex": code.hex(),
                    "asm": asm_text,
                    "bin_path": str(bin_path),
                }
            )
            continue

        console.print(f"\n[bold]{'=' * 60}[/]")
        console.print(f"[bold]=== {name} @ 0x{va:08X}, {len(code)} bytes ===[/]")
        console.print(f"[bold]{'=' * 60}[/]")
        print(f"Hex: {code.hex()}")
        print()
        print(asm_text)

    if json_output:
        json_print(
            {
                "count": len(items),
                "start": start,
                "requested": count,
                "results": items,
            }
        )


# ---------------------------------------------------------------------------
# Main Setup
# ---------------------------------------------------------------------------


def _setup_candidates(
    target: str | None,
    json_output: bool,
    exe: Path | None,
    min_size: int,
    max_size: int,
) -> tuple[ProjectConfig, list[tuple[int, int, str]], Path]:
    cfg = require_config(target=target, json_mode=json_output)

    exe_path = exe or cfg.target_binary
    src_dir = cfg.reversed_dir

    try:
        funcs = load_functions(cfg)
    except FileNotFoundError as exc:
        error_exit(str(exc), json_mode=json_output)

    reversed_vas = detect_reversed_vas(src_dir, cfg=cfg)
    if not json_output:
        console.print(f"Found {len(reversed_vas)} already-reversed functions")

    candidates: list[tuple[int, int, str]] = []
    for fn in funcs:
        va = int(fn["va"])
        size = int(fn["size"])
        name = str(fn["name"])

        if va in reversed_vas:
            continue
        if size < min_size or size > max_size:
            continue

        candidates.append((va, size, name))

    candidates.sort(key=lambda x: x[1])  # Sort by size
    return cfg, candidates, exe_path


# ---------------------------------------------------------------------------
# CLI Application
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Extract and disassemble functions from the target binary.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew extract list · · · · · · · · List un-reversed candidates\n\n"
        "  rebrew extract show 0x10001860 · · · Extract + disassemble one VA\n\n"
        "  rebrew extract batch 20 · · · · · · Extract first 20 smallest\n\n"
        "  rebrew extract batch 20 --start 10 · Offset into sorted list\n\n"
        "[dim]Reads function list from functions.txt or .json and auto-detects "
        "already-reversed VAs. Outputs .bin files to the configured bin_dir.[/dim]"
    ),
)


@app.callback()
def main() -> None:
    """Extract and disassemble functions from the target binary."""


@app.command("list")
def list_candidates(
    exe: Path | None = typer.Option(None, "--exe", help="Path to DLL/EXE (default: from config)"),
    min_size: int = typer.Option(8, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(50000, "--max-size", help="Maximum function size"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """List un-reversed candidates."""
    cfg, candidates, exe_path = _setup_candidates(target, json_output, exe, min_size, max_size)
    if json_output:
        items = [{"va": f"0x{va:08x}", "size": sz, "name": nm} for va, sz, nm in candidates]
        json_print({"count": len(candidates), "candidates": items})
        return
    cmd_list(candidates)


@app.command("show")
def show_candidate(
    va: str = typer.Argument(..., help="VA (hex) to extract and disassemble"),
    size: int | None = typer.Option(
        None, "--size", help="Override catalog-recorded size for this extraction"
    ),
    exe: Path | None = typer.Option(None, "--exe", help="Path to DLL/EXE (default: from config)"),
    min_size: int = typer.Option(8, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(50000, "--max-size", help="Maximum function size"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Extract and disassemble a single VA."""
    cfg, candidates, exe_path = _setup_candidates(target, json_output, exe, min_size, max_size)
    binary_info = load_binary(exe_path)
    target_va = parse_va(va, json_mode=json_output)
    # --size override: inject a synthetic candidate entry so the VA is found
    # even when it is absent from the candidate list (e.g. already-reversed) or
    # when the catalog size is wrong.
    if size is not None:
        # Replace or prepend an entry with the overridden size.
        candidates = [(target_va, size, f"0x{target_va:08X}")] + [
            c for c in candidates if c[0] != target_va
        ]
    cmd_extract(binary_info, candidates, target_va, cfg.bin_dir, cfg=cfg, json_output=json_output)


@app.command("batch")
def batch_candidates(
    count: int = typer.Argument(20, help="Number of functions to extract"),
    start: int = typer.Option(0, "--start", help="Start offset for batch mode"),
    exe: Path | None = typer.Option(None, "--exe", help="Path to DLL/EXE (default: from config)"),
    min_size: int = typer.Option(8, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(50000, "--max-size", help="Maximum function size"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Extract and disassemble a batch of functions."""
    cfg, candidates, exe_path = _setup_candidates(target, json_output, exe, min_size, max_size)
    binary_info = load_binary(exe_path)
    cmd_batch(binary_info, candidates, count, start, cfg.bin_dir, cfg=cfg, json_output=json_output)


# Add extract as an alias to show
app.command("extract", hidden=True)(show_candidate)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
