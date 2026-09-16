"""order-sources — order source files by their first function's original VA.

Thin CLI over :mod:`rebrew.link_order` (which owns ``order_sources``,
``file_va``, and the VA-order enforcement used by the CMake drift gate).
Kept as its own command so ``rebrew order-sources`` prints an ordering
without requiring a CMakeLists.txt.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.link_order import _base_key, file_va, order_sources

console = Console(stderr=True)

app = typer.Typer(
    help="Order source files by their first function's original VA (position-aligned .text).",
    rich_markup_mode="rich",
)

__all__ = ["_base_key", "app", "file_va", "order_sources"]


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
        name, sep, va = entry.partition("=")
        if not sep or not name or not va:
            # "file=0xVA" without a '=' (or an empty side) would feed "" to
            # int("", 0) → a raw ValueError (link-review F8).
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
    ordered, excluded = order_sources(files, table, set(exclude))
    if json_output:
        json_print({"ordered": [str(f) for f in ordered], "excluded": excluded})
    else:
        for f in ordered:
            print(f)
        if excluded:
            console.print(f"[yellow]# excluded (absent from original): {sorted(excluded)}[/yellow]")


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
