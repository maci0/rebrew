"""order-sources — order source files by their first function's original VA.

Thin CLI over :mod:`rebrew.link_order` (which owns ``order_sources``,
``file_va``, and the VA-order enforcement used by the CMake drift gate).
Kept as its own command so ``rebrew build order-sources`` prints an ordering
without requiring a CMakeLists.txt.
"""

from __future__ import annotations

lazy from pathlib import Path

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print
lazy from rebrew.config import ConfigError, ConfigNotFoundError, load_config, target_module
lazy from rebrew.link_order import order_sources

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew build order-sources src/*.c  # Print the VA-ordered source list\n\n"
    "  # Supply a missing first address\n"
    "  rebrew build order-sources src/*.c --first-va helpers.c=0x10001000\n\n"
    "  # Machine-readable order\n"
    "  rebrew build order-sources src/*.c --exclude test_helpers.c --json\n"
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
        help="File basename=0xVA for files without bound functions (repeatable)",
    ),
    first_va_file: Path | None = typer.Option(
        None,
        "--first-va-file",
        help=(
            "Read FILE=0xVA lines (one per line, # comments allowed) for files without "
            "bound functions"
        ),
    ),
    exclude: list[str] = typer.Option(
        [], "--exclude", help="File basenames absent from the original (repeatable)"
    ),
    target_module_name: str = typer.Option(
        "",
        "--module",
        help="Metadata module to order by (e.g. SERVER) for multi-target sources",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Print files ordered by their first function's original VA."""
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
    if first_va_file is not None:
        try:
            lines = first_va_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            error_exit(f"--first-va-file: {exc}", json_mode=json_output)
        for lineno, line in enumerate(lines, start=1):
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            name, sep, va = text.partition("=")
            name, va = name.strip(), va.strip()
            if not sep or not name or not va:
                error_exit(
                    f"--first-va-file {first_va_file}:{lineno}: expected FILE=0xVA",
                    json_mode=json_output,
                )
            try:
                value = int(va, 0)
            except ValueError:
                error_exit(
                    f"--first-va-file {first_va_file}:{lineno}: cannot parse VA {va!r}",
                    json_mode=json_output,
                )
            if name in table and table[name] != value:
                error_exit(
                    f"--first-va-file {first_va_file}:{lineno}: {name} already has "
                    f"0x{table[name]:X}",
                    json_mode=json_output,
                )
            table[name] = value
    try:
        cfg = load_config(target=target)
    except ConfigNotFoundError as exc:
        if target is not None:
            error_exit(str(exc), json_mode=json_output)
        cfg = None
    except ConfigError as exc:
        error_exit(str(exc), json_mode=json_output)
    ordered, excluded = order_sources(
        files,
        table,
        set(exclude),
        target_module_name=target_module_name or (target_module(cfg) if cfg is not None else None),
        metadata_dir=cfg.metadata_dir if cfg is not None else None,
    )
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
