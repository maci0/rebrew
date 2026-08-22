"""lzexe_cli.py — Unpack LZEXE 0.90/0.91 compressed DOS executables.

Many DOS games shipped LZEXE-packed (the header's CS:IP points at a
decompressor stub appended to the file).  ``rebrew unpack-lzexe`` restores
the original MZ executable: rebuilt header, standard relocation table, and
the decompressed image — the first step for any static analysis of a packed
DOS binary.

Usage:
    rebrew unpack-lzexe packed.exe [--output original.exe] [--json]
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.lzexe import NotLzexeError, unpack_lzexe

console = Console(stderr=True)

app = typer.Typer(
    help="Unpack an LZEXE 0.90/0.91 compressed DOS executable.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew unpack-lzexe packed.exe · · · · · · · · Unpack in place (packed.exe.unpacked.exe)\n\n"
        "  rebrew unpack-lzexe packed.exe -o original.exe · Write to a specific path\n\n"
        "  rebrew unpack-lzexe packed.exe --json · · · · · Machine-readable result\n\n"
        "[dim]LZEXE (Fabrice Bellard, 1989-91) compressed many DOS games; the "
        "format is documented only by its own decompressor stub.  Detection "
        "matches the stub byte-for-byte, so merely patching the 'LZ91' magic "
        "does not fool it.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    binary: Path = typer.Argument(..., help="Path to the LZEXE-packed executable."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output path for the unpacked file."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Unpack an LZEXE-compressed DOS executable into a loadable MZ file."""
    if not binary.exists():
        msg = f"binary not found: {binary}"
        error_exit(msg, json_mode=json_output)

    try:
        # unpack_lzexe runs detection internally — derive the version from
        # its result instead of probing the file twice.
        unpacked = unpack_lzexe(binary)
        version = unpacked.version
        out = output if output is not None else Path(str(binary) + ".unpacked.exe")
        out.write_bytes(unpacked.to_bytes())
    except NotLzexeError as exc:
        error_exit(str(exc), json_mode=json_output)
    except (OSError, ValueError, struct.error, IndexError) as exc:
        error_exit(f"unpack failed for {binary}: {exc}", json_mode=json_output)

    result: dict[str, Any] = {
        "packed": str(binary),
        "version": f"0.{version}",
        "output": str(out),
        "size": out.stat().st_size,
    }
    if json_output:
        json_print(result)
    else:
        console.print(
            f"[green]unpacked[/green] LZEXE 0.{version}: [bold]{out}[/bold] "
            f"({result['size']} bytes)"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
