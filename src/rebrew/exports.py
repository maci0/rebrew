"""exports.py — Export-table comparison (original target vs recompiled build).

reccmp ``verexp`` equivalent: verifies that the recompiled binary exports the
same API surface as the original.  Compares export *names* only — addresses
are ignored because the recompiled binary's layout legitimately differs —
so a missing or renamed export fails the check (exit ``EXIT_MISMATCH``).

Usage:
    rebrew verify-exports path/to/recomp.dll
    rebrew verify-exports path/to/recomp.dll --json
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import EXIT_MISMATCH, TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)


def parse_exports(binary_path: Path) -> list[str]:
    """Return the sorted export names of a PE binary.

    Empty list when the binary is not a PE, has no export table, or cannot
    be parsed (mirrors :func:`rebrew.imports.parse_imports`'s tolerance).
    """
    import lief

    try:
        pe = lief.PE.parse(str(binary_path))
    except Exception:  # parse failures degrade to "no exports"
        return []
    if pe is None:
        return []
    exports: list[str] = []
    for func in getattr(pe, "exported_functions", []):
        name = getattr(func, "name", "")
        if name:
            exports.append(name)
    return sorted(set(exports))


def compare_exports(original: Path, recomp: Path) -> dict[str, Any]:
    """Compare the export sets of *original* and *recomp*.

    Returns a dict with ``missing`` (present in the original, absent from
    the recompiled build), ``added`` (recomp-only), and ``match`` — the
    reccmp verexp semantics, addresses intentionally ignored.
    """
    orig_exports = parse_exports(original)
    recomp_exports = parse_exports(recomp)
    orig_set, recomp_set = set(orig_exports), set(recomp_exports)
    missing = sorted(orig_set - recomp_set)
    added = sorted(recomp_set - orig_set)
    return {
        "original": str(original),
        "recompiled": str(recomp),
        "original_count": len(orig_set),
        "recompiled_count": len(recomp_set),
        "missing": missing,
        "added": added,
        "match": not missing and not added,
    }


app = typer.Typer(
    help="Verify the recompiled binary's export table matches the original target.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    recomp_binary: Path = typer.Argument(
        ..., help="Path to the recompiled DLL/EXE (built from your sources)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compare export names between the project target and RECOMP_BINARY."""
    cfg = require_config(target=target, json_mode=json_output)
    if not recomp_binary.exists():
        error_exit(f"recompiled binary not found: {recomp_binary}", json_mode=json_output)
    if not cfg.target_binary.exists():
        error_exit(f"target binary missing: {cfg.target_binary}", json_mode=json_output)

    result = compare_exports(cfg.target_binary, recomp_binary)
    if json_output:
        json_print(result)
    else:
        console.print(
            f"[bold]Original:[/bold] {result['original']} ({result['original_count']} exports)"
        )
        console.print(
            f"[bold]Recomp:[/bold]   {result['recompiled']} ({result['recompiled_count']} exports)"
        )
        for name in result["missing"]:
            console.print(f"  [red]missing:[/red] {name}")
        for name in result["added"]:
            console.print(f"  [yellow]added:[/yellow] {name}")
        if result["match"]:
            console.print("[green]Export tables match.[/green]")
        else:
            console.print("[red]Export tables differ.[/red]")
    if not result["match"]:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
