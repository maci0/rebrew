"""order-sources — order source files by their first function's original VA.

Thin CLI over :mod:`rebrew.link_order` (which owns ``order_sources``,
``file_va``, and the VA-order enforcement used by the CMake drift gate).
Kept as its own command so ``rebrew order-sources`` prints an ordering
without requiring a CMakeLists.txt.
"""

from __future__ import annotations

from pathlib import Path

import typer

from rebrew.cli import console, error_exit, json_print
from rebrew.link_order import order_sources

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew order-sources src/*.c · · · · · Print the VA-ordered source list\n\n"
    "  rebrew order-sources src/*.c --first-va 0x10001000 · · Ignore files below this VA\n\n"
    "  rebrew order-sources src/*.c --exclude tests/ --json · Machine-readable order\n"
)


app = typer.Typer(
    help="Order source files by their first function's original VA (position-aligned .text).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)

__all__ = ["app", "main", "main_entry"]


@app.callback(invoke_without_command=True)
def main(
    files: list[Path] = typer.Argument(..., help="Source files to order"),
    first_va: list[str] = typer.Option(
        [],
        "--first-va",
        help="File basename=0xVA for files without code markers (repeatable)",
    ),
    exclude: list[str] = typer.Option(
        [], "--exclude", help="File basenames absent from the original (repeatable)"
    ),
    marker: str = typer.Option(
        "",
        "--marker",
        help="Code marker module to order by (e.g. SERVER) when files carry several targets",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Print *files* ordered by their first function's original VA."""
    table: dict[str, int] = {}
    for entry in first_va:
        name, sep, va = entry.partition("=")
        if not sep or not name or not va:
            # "file=0xVA" without a '=' (or an empty side) would feed "" to
            # int("", 0) → a raw ValueError.
            error_exit(
                f"--first-va {entry!r}: expected FILE=0xVA (e.g. zlib/adler32.c=0x10001000)",
                json_mode=json_output,
            )
        try:
            table[name] = int(va, 0)
        except ValueError:
            error_exit(
                f"--first-va {entry!r}: cannot parse VA {va!r} as an integer",
                json_mode=json_output,
            )
    ordered, excluded = order_sources(files, table, set(exclude), marker=marker or None)
    if json_output:
        json_print({"ordered": [str(f) for f in ordered], "excluded": excluded})
    else:
        for f in ordered:
            print(f)
        if excluded:
            console.print(f"[yellow]# excluded (absent from original): {sorted(excluded)}[/yellow]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
