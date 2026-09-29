"""build_db.py – the ``build-db`` command.

A thin Typer front over :func:`rebrew.coverage_db.build_db`, which does the work.
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
        "  rebrew build-db · · · · · · · · · · · Scan the project and write "
        "db/coverage-<target>.toml\n\n"
        "  rebrew build-db --root /path/to/project  Specify project root explicitly\n\n"
        "[bold]What it creates:[/bold]\n\n"
        "  db/coverage-<target>.toml · · One clear-text document per target, holding\n"
        "                              functions, globals, sections, cells, verify results\n"
        "                              and status history\n\n"
        "[dim]The documents are served by the coverage dashboards and can be read, "
        "diffed and edited by hand. Each is replaced whole on every run, so --force "
        "does nothing here: there is no schema to migrate and no partial state to "
        "recover.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    root: Path | None = RootOption,
    force: bool = typer.Option(
        False,
        "--force",
        help="Accepted for symmetry with the SQLite-era command and has no effect: "
        "each coverage document is rewritten whole, so there is nothing to force past.",
    ),
    regen: bool = typer.Option(
        False,
        "--regen",
        help="Accepted for compatibility and has no effect: the catalog analysis "
        "always runs in this process, so there is no snapshot mode to select.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Build clear-text coverage documents from the project tree.

    Scans the tree in-process; ``--regen`` is accepted and does nothing,
    because there is no other mode left to select.
    """
    root_dir = require_root(root, json_mode=json_output)
    write_coverage(root_dir, target=target, force=force, json_output=json_output, regen=regen)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
