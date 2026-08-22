"""order-sources — order source files by their first function's original VA.

MSVC6 LINK places objects in command-line order and (without /Gy) does not
reorder functions, so a recompiled binary's .text/.data layout equals its
object link order.  Sorting the sources by each file's lowest original
function VA reproduces the original layout — functions land at their
original addresses (fixes reccmp "0 aligned") and the byte diff shrinks to
real content differences.

VAs come from the ``// FUNCTION: <module> 0x<VA>`` headers inside the
files, plus an explicit ``--first-va`` table for library files without
markers (e.g. zlib).  Files with no discoverable VA sort last (path order);
``--exclude`` drops files absent from the original binary.

Usage:
    rebrew order-sources <src.c>... [--first-va zlib/adler32.c=0x10001000]
                                    [--exclude gzio.c] [--json]
"""

from __future__ import annotations

import re
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import json_print

console = Console(stderr=True)

app = typer.Typer(
    help="Order source files by their first function's original VA (position-aligned .text).",
    rich_markup_mode="rich",
)

_FUNC_RE = re.compile(r"^//\s*FUNCTION:\s+\S+\s+0x([0-9A-Fa-f]+)", re.M)


def file_va(path: Path) -> int | None:
    """Lowest ``// FUNCTION:`` VA in *path* (None when the file has none)."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    vas = [int(m.group(1), 16) for m in _FUNC_RE.finditer(text)]
    return min(vas) if vas else None


def order_sources(
    files: list[Path],
    first_va: dict[str, int] | None = None,
    exclude: set[str] | None = None,
) -> tuple[list[Path], list[str]]:
    """Order *files* by first-function VA.

    Returns ``(ordered, excluded_names)``: known-VA files sorted by VA, then
    unknown-VA files in path order; *excluded* files (absent from the
    original) are dropped.
    """
    first_va = first_va or {}
    exclude = exclude or set()
    known: list[tuple[int, Path]] = []
    unknown: list[Path] = []
    excluded: list[str] = []
    for f in files:
        if f.name in exclude:
            excluded.append(f.name)
            continue
        va = first_va.get(f.name) or file_va(f)
        if va is None:
            unknown.append(f)
        else:
            known.append((va, f))
    known.sort(key=lambda t: t[0])
    unknown.sort(key=lambda p: str(p))
    return [f for _, f in known] + unknown, excluded


@app.callback(invoke_without_command=True)
def main(
    files: list[Path] = typer.Argument(..., help="Source files to order"),
    first_va: list[str] = typer.Option(
        [],
        "--first-va",
        help="File basename=0xVA for files without FUNCTION markers (repeatable)",
    ),
    exclude: list[str] = typer.Option(
        [], "--exclude", help="File basenames absent from the original (repeatable)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Print *files* ordered by their first function's original VA."""
    table: dict[str, int] = {}
    for entry in first_va:
        name, _, va = entry.partition("=")
        table[name] = int(va, 0)
    ordered, excluded = order_sources(files, table, set(exclude))
    if json_output:
        json_print({"ordered": [str(f) for f in ordered], "excluded": excluded})
    else:
        for f in ordered:
            print(f)
        if excluded:
            console.print(f"[yellow]# excluded (absent from original): {sorted(excluded)}[/yellow]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
