"""Record target-scoped original assembly evidence for a named C definition."""

from pathlib import Path

import typer

from rebrew.cli import TargetOption, error_exit, json_print, require_config, run_standalone
from rebrew.config import module_marker
from rebrew.metadata.source_provenance import document_assembly
from rebrew.utils import console, untrusted_ident

app = typer.Typer(
    help=__doc__,
    rich_markup_mode="rich",
    epilog="Examples:\n\n  rebrew source document-assembly src/game.c --symbol fill0 --evidence 'Original macro at 0x401123' --target client\n\n  rebrew source document-assembly src/game.c --symbol fill0 --clear --target client\n",
)


@app.callback(invoke_without_command=True)
def main(
    file: Path = typer.Argument(..., help="Source file containing the definition."),
    symbol: str = typer.Option(
        ..., "--symbol", help="C identifier of the definition, including inline helpers."
    ),
    evidence: str | None = typer.Option(
        None,
        "--evidence",
        help="Positive evidence of original assembly; a byte match alone is insufficient.",
    ),
    clear: bool = typer.Option(
        False, "--clear", help="Remove this definition's evidence for the selected target."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target_name: str | None = TargetOption,
) -> None:
    """Record evidence without inventing a function VA or changing byte STATUS."""
    cfg = require_config(target=target_name, json_mode=json_output)
    if clear == (evidence is not None):
        error_exit("supply either --evidence or --clear", json_mode=json_output)
    source = file if file.is_absolute() else cfg.root / file
    try:
        report = document_assembly(
            cfg.metadata_dir, source, symbol, module_marker(cfg), evidence, dry_run=dry_run
        )
    except (OSError, ValueError, ImportError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        action = "clear" if clear else "record"
        verb = f"Would {action}" if dry_run else ("Cleared" if clear else "Recorded")
        console.print(
            f"{verb} source assembly provenance for {untrusted_ident(symbol)} ({untrusted_ident(module_marker(cfg))})"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_standalone(main)
