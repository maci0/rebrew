"""extract.py - Extract and disassemble functions from the target binary.

Reads the discovery inventory (function_structure.json), auto-detects
already-reversed VAs from the project's src directory, and lets you
list/extract/batch the remaining candidates.

Usage:
    rebrew extract list                # List un-reversed candidates
    rebrew extract show 0x10001860     # Extract + disasm one VA
    rebrew extract batch 20            # Extract first 20 smallest
    rebrew extract batch 20 --start 10 # Offset into sorted list
"""

import logging
from pathlib import Path

import typer
from rich.table import Table

from rebrew.asm import disasm_bytes
from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
from rebrew.catalog import cached_function_list, scan_reversed_dir
from rebrew.cli import (
    EXIT_ERROR,
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.config import ProjectConfig, inventory_path_for

log = logging.getLogger(__name__)


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
        # GLOBAL/DATA mark data symbols, not functions.  A bare `// STUB:`
        # marker is a pre-skeleton placeholder (no body, no SIZE) — the
        # function is not actually reversed and stays an extract candidate.
        if entry.is_function and entry.marker_type != "STUB"
    }


# ---------------------------------------------------------------------------
# Load function list
# ---------------------------------------------------------------------------


def load_functions(cfg: ProjectConfig) -> list[dict[str, int | str]]:
    """Load the discovery inventory (function_structure.json)."""

    inv = inventory_path_for(cfg.reversed_dir, cfg)
    if not inv.exists():
        raise FileNotFoundError(
            f"No function inventory at {inv} — run `rebrew intake` or "
            "`rebrew discover-functions` first"
        )
    return [
        {"va": int(fn["va"]), "size": int(fn["size"]), "name": str(fn["name"])}
        for fn in cached_function_list(cfg)
    ]


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
                error_exit(
                    f"Failed to extract bytes at VA 0x{va:08X}",
                    json_mode=json_output,
                    code=EXIT_ERROR,
                )
            try:
                asm_text = disasm_bytes(code, va, cfg=cfg)
            except RuntimeError as e:
                error_exit(str(e), json_mode=json_output, code=EXIT_ERROR)

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
    error_exit(
        f"VA 0x{target_va:08X} not found in candidate list",
        json_mode=json_output,
        code=EXIT_ERROR,
    )


def cmd_batch(
    binary_info: BinaryInfo,
    candidates: list[tuple[int, int, str]],
    count: int,
    start: int,
    bin_dir: Path,
    cfg: ProjectConfig | None = None,
    *,
    json_output: bool = False,
    dry_run: bool = False,
) -> None:
    """Extract and disassemble a batch of functions."""
    if not dry_run:
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
            # A per-function failure must not abort the whole batch — the
            # remaining functions would be silently unprocessed.
            console.print(f"[red bold]error:[/red bold] {e}")
            continue

        bin_path = bin_dir / f"func_0x{va:08X}.bin"
        if not dry_run:
            bin_path.write_bytes(code)
        elif json_output:
            items.append(
                {
                    "status": "DRY_RUN",
                    "name": name,
                    "va": f"0x{va:08x}",
                    "size": len(code),
                    "bin_path": str(bin_path),
                }
            )
            continue
        else:
            console.print(
                f"[cyan]dry-run:[/cyan] would write {bin_path.name} ({len(code)} bytes, {name})"
            )
            continue

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
                "failed": sum(1 for i in items if i.get("status") == "ERROR"),
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
    binary: Path | None,
    min_size: int,
    max_size: int,
) -> tuple[ProjectConfig, list[tuple[int, int, str]], Path]:
    cfg = require_config(target=target, json_mode=json_output)

    exe_path = binary or cfg.target_binary
    src_dir = cfg.reversed_dir

    try:
        funcs = load_functions(cfg)
    except (OSError, ValueError) as exc:
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
        "[dim]Reads the discovery inventory (function_structure.json) and auto-detects "
        "already-reversed VAs. Outputs .bin files to the configured bin_dir.[/dim]"
    ),
)


@app.callback()
def main() -> None:
    """Extract and disassemble functions from the target binary."""


@app.command("list")
def list_candidates(
    binary: Path | None = typer.Option(
        None, "--binary", help="Path to DLL/EXE (default: from config)"
    ),
    min_size: int = typer.Option(8, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(50000, "--max-size", help="Maximum function size"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """List un-reversed candidates."""
    cfg, candidates, exe_path = _setup_candidates(target, json_output, binary, min_size, max_size)
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
    binary: Path | None = typer.Option(
        None, "--binary", help="Path to DLL/EXE (default: from config)"
    ),
    min_size: int = typer.Option(8, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(50000, "--max-size", help="Maximum function size"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Extract and disassemble a single VA."""
    cfg, candidates, exe_path = _setup_candidates(target, json_output, binary, min_size, max_size)
    binary_info = load_binary(exe_path)
    target_va = parse_va(va, json_mode=json_output)
    # --size override: inject a synthetic candidate entry so the VA is found
    # even when it is absent from the candidate list (e.g. already-reversed) or
    # when the catalog size is wrong.
    if size is not None:
        candidates = [(target_va, size, f"0x{target_va:08X}")] + [
            c for c in candidates if c[0] != target_va
        ]
    cmd_extract(binary_info, candidates, target_va, cfg.bin_dir, cfg=cfg, json_output=json_output)


@app.command("batch")
def batch_candidates(
    count: int = typer.Argument(20, help="Number of functions to extract"),
    start: int = typer.Option(0, "--start", help="Start offset for batch mode"),
    binary: Path | None = typer.Option(
        None, "--binary", help="Path to DLL/EXE (default: from config)"
    ),
    min_size: int = typer.Option(8, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(50000, "--max-size", help="Maximum function size"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Extract and disassemble a batch of functions."""
    cfg, candidates, exe_path = _setup_candidates(target, json_output, binary, min_size, max_size)
    binary_info = load_binary(exe_path)
    cmd_batch(
        binary_info,
        candidates,
        count,
        start,
        cfg.bin_dir,
        cfg=cfg,
        json_output=json_output,
        dry_run=dry_run,
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
