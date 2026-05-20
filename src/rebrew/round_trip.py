"""``rebrew round-trip`` — splice matched function bytes back into the target PE.

Pipeline: enumerate every EXACT/RELOC function from rebrew-function.toml,
compile each via the existing compile_and_compare path, apply COFF relocations
against the active target's function + data catalogs, splice the patched
bytes into a byte copy of the original PE at each function's file offset,
SHA-256 the result, write ``<binary>.reasm`` next to the original, exit
non-zero on any unexpected byte mismatch.

PROVEN functions are deliberately skipped — their bytes differ from the
original by design (semantic equivalence, not byte equivalence) — and are
reported as ``skipped_proven`` without altering the spliced PE.
"""

from __future__ import annotations

import hashlib  # noqa: F401
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import (
    EXIT_ERROR,  # noqa: F401
    EXIT_MISMATCH,  # noqa: F401
    EXIT_OK,
    TargetOption,
    error_exit,  # noqa: F401
    json_print,  # noqa: F401
    require_config,
)

console = Console(stderr=True)

app = typer.Typer(
    help="Splice every matched function back into the target PE and verify byte equality.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    out: Path | None = typer.Option(
        None, "--out", help="Override output PE path (default: <binary>.reasm next to target)"
    ),
    no_write: bool = typer.Option(
        False, "--no-write", help="Skip writing the reassembled PE; still emit the report"
    ),
    symbol_filter: str | None = typer.Option(
        None, "--filter", help="Only round-trip functions whose symbol contains this substring"
    ),
    target: str | None = TargetOption,
) -> None:
    cfg = require_config(target=target)
    raise typer.Exit(
        _run_round_trip(
            cfg, out=out, no_write=no_write, symbol_filter=symbol_filter, json_output=json_output
        )
    )


def _run_round_trip(
    cfg, *, out: Path | None, no_write: bool, symbol_filter: str | None, json_output: bool
) -> int:
    """Top-level orchestration. Returns the process exit code.

    Stub until Task 5 wires the splice pipeline. Returns EXIT_OK silently so
    the help / arg-surface tests in this task can assert flag presence without
    depending on a real project tree.
    """
    return EXIT_OK


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
