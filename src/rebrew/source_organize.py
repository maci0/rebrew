"""Review all-target source organization and compare raw rebuild artifacts."""

lazy from pathlib import Path

import typer

lazy from rebrew.cli import console, error_exit, json_print, require_config, run_cli
lazy from rebrew.source_organization import (
    check_reorganization,
    organization_configs,
    review_organization,
)

app = typer.Typer(
    help="Review target providers, TU contexts and native orders before reorganizing source.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source organize review src/a.c src/b.c --json\n\n"
        "  rebrew source organize check old-raw.dll build/raw.dll --json\n\n"
        "Reviews are read-only. Rebuild every affected target and compare raw links."
    ),
)


@app.command(
    "review",
    epilog="[bold]Examples:[/bold]\n\n  rebrew source organize review a.c b.c --destination merged.c --json",
)
def review_cmd(
    files: list[Path] = typer.Argument(
        ..., help="Existing project sources to review across every target"
    ),
    destination: Path | None = typer.Option(
        None,
        "--destination",
        help="Proposed merged TU; checks foreign-definition and compiler-setting changes",
    ),
    shared: bool = typer.Option(
        False, "--shared", help="Model same-named identical definitions as shared merge candidates"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Preview providers, original compilation contexts and conflicting native orders."""
    cfg = require_config(json_mode=json_output)
    try:
        report = review_organization(
            organization_configs(cfg),
            [path.resolve() for path in files],
            destination=destination.resolve() if destination is not None else None,
            shared=shared,
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)
    if report["problems"] or report["unknown"]:
        raise typer.Exit(1)


@app.command(
    "check",
    epilog="[bold]Examples:[/bold]\n\n  rebrew source organize check old-raw.dll build/raw.dll --json",
)
def check_cmd(
    before: Path = typer.Argument(..., help="Preserved raw link before the source reorganization"),
    after: Path = typer.Argument(..., help="Fresh raw rebuild after the source reorganization"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Compare complete PE raw links, code/data bytes and section placement."""
    try:
        report = check_reorganization(before, after)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)
    if not report["match"]:
        raise typer.Exit(1)


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_cli(app)


if __name__ == "__main__":
    main_entry()
