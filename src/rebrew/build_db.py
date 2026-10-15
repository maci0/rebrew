"""The ``rebrew coverage export`` command.

A thin Typer front over :func:`rebrew.coverage_db.write_coverage`, which does the work.
The normalizers, catalog loaders and verify-cache import the writer needs live in
``coverage_db`` so ``coverage_toml`` can import them without depending on a
console script.
"""

from __future__ import annotations

from pathlib import Path

import typer

from rebrew.cli import RootOption, TargetOption, require_root
from rebrew.coverage_db import write_coverage

app = typer.Typer(
    help="Export portable coverage snapshots for offline viewing.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  # Scan the project and write portable coverage snapshots\n"
        "  rebrew coverage export --output snapshots/\n\n"
        "  # Specify project root explicitly\n"
        "  rebrew coverage export --root /path/to/project --output snapshots/\n\n"
        "[bold]What it creates:[/bold]\n\n"
        "  <output>/coverage-<target>.toml · · One clear-text document per target, holding\n"
        "                              functions, globals, sections, cells, verify results\n"
        "                              and status history\n\n"
        "[dim]Local dashboards read project metadata directly. Export only when you need portable snapshots for offline viewing.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    output: Path = typer.Option(
        ..., "--output", "-o", help="Directory for portable coverage snapshots"
    ),
    root: Path | None = RootOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Scan the current project tree and write coverage documents for each target."""
    root_dir = require_root(root, json_mode=json_output)
    from rebrew.cli import error_exit
    from rebrew.errors import RebrewError

    try:
        write_coverage(root_dir, output, target=target, json_output=json_output)
    except (OSError, ValueError, KeyError, TypeError, RebrewError) as exc:
        error_exit(str(exc), json_mode=json_output)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
