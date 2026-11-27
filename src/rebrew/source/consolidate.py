"""Fold source evidence into the format-3 function metadata store."""

import typer

from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    TargetOption,
    error_exit,
    json_print,
    require_config,
    run_standalone,
)
lazy from rebrew.metadata.source_provenance import consolidate_source_metadata
lazy from rebrew.utils import console

app = typer.Typer(
    help=__doc__,
    rich_markup_mode="rich",
    epilog="[bold]Examples:[/bold]\n\n  rebrew source consolidate --dry-run --json\n\n  rebrew source consolidate --expected-digest SHA256 --json",
)


@app.callback(invoke_without_command=True)
def main(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target_name: str | None = TargetOption,
) -> None:
    """Migrate the selected metadata root without changing function verdicts."""
    cfg = require_config(target=target_name, json_mode=json_output)
    try:
        report = consolidate_source_metadata(
            cfg.metadata_dir, dry_run=dry_run, expected_digest=expected_digest
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(
            f"{'Would consolidate' if dry_run else 'Consolidated'} {report['definitions']} assembly records and {report['files']} support purposes into rebrew-functions.toml"
        )
        if dry_run:
            console.print(f"Input digest: {report['input_digest']}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_standalone(main)
