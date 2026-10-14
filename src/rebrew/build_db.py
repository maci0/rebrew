"""The ``rebrew coverage build`` command.

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
    help="Build clear-text coverage documents from the project tree.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  # Scan the project and write db/coverage-<target>.toml\n"
        "  rebrew coverage build\n\n"
        "  # Specify project root explicitly\n"
        "  rebrew coverage build --root /path/to/project\n\n"
        "[bold]What it creates:[/bold]\n\n"
        "  db/coverage-<target>.toml · · One clear-text document per target, holding\n"
        "                              functions, globals, sections, cells, verify results\n"
        "                              and status history\n\n"
        "[dim]The documents are served by the coverage dashboards and can be read, diffed and edited by hand. Each run scans the current project tree and replaces the documents while preserving status history.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    root: Path | None = RootOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Scan the current project tree and write coverage documents for each target."""
    root_dir = require_root(root, json_mode=json_output)
    write_coverage(root_dir, target=target, json_output=json_output)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
