"""Import portable coverage history into canonical function metadata."""

from __future__ import annotations

import logging
lazy import unicodedata
lazy from pathlib import Path

import typer

from rebrew.cli import RootOption, error_exit, json_print, require_root
lazy from rebrew.config import load_config, target_module
lazy from rebrew.coverage_toml import CoverageSnapshot, CoverageTomlError, load_coverage_from
lazy from rebrew.metadata.functions import import_status_history
lazy from rebrew.utils import console

logger = logging.getLogger(__name__)

app = typer.Typer(
    help="Import status history from portable snapshots without changing verdicts.",
    rich_markup_mode="rich",
    epilog="[bold]Examples:[/bold]\n\n  rebrew coverage import-history --snapshots db/ --dry-run\n\n"
    "  rebrew coverage import-history --snapshots db/",
)


@app.callback(invoke_without_command=True)
def main(
    snapshots: Path = typer.Option(
        ..., "--snapshots", help="Directory containing portable coverage snapshots"
    ),
    root: Path | None = RootOption,
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Target name from rebrew-project.toml (default: every snapshot); a final --target lists targets.",
    ),
) -> None:
    """Preserve historical progress without changing verdicts. Imports every snapshot unless --target selects one."""
    project = require_root(root, json_mode=json_output)
    try:
        if not snapshots.is_dir():
            raise ValueError(f"{snapshots}: not a snapshot directory")
        documents: dict[str, CoverageSnapshot] = {}
        unreadable: list[str] = []
        for path in sorted(snapshots.glob("coverage-*.toml")):
            name = unicodedata.normalize("NFC", path.stem.removeprefix("coverage-"))
            if target is not None and name != target:
                continue
            try:
                documents[name] = load_coverage_from(snapshots, name)
            except (OSError, ValueError, CoverageTomlError) as exc:
                # One damaged snapshot used to raise out of the dict
                # comprehension and refuse every other target in the same
                # directory, with the message "no readable coverage snapshots".
                unreadable.append(f"{path.name}: {exc}")
        if not documents:
            detail = "; ".join(unreadable)
            raise ValueError(
                f"{snapshots}: no readable coverage snapshots" + (f" ({detail})" if detail else "")
            )
        if target is not None and target not in documents:
            raise ValueError(f"{target}: no readable coverage snapshot")
        for problem in unreadable:
            # A skipped snapshot is a lost history row for that target, so it
            # stays on the warning stream whether or not the caller asked for
            # JSON (the JSON document itself stays the successful imports).
            logger.warning("coverage import-history: skipping %s", problem)
        prepared = []
        for name, snapshot in documents.items():
            if target is not None and name != target:
                continue
            cfg = load_config(project, target=name)
            rows = [dict(row) for row in snapshot.history]
            # Validate every target before the first write.
            count = import_status_history(cfg, target_module(cfg), rows, dry_run=True)
            prepared.append((cfg, rows, count))
        for cfg, rows, _count in prepared:
            if not dry_run:
                import_status_history(cfg, target_module(cfg), rows)
    except (OSError, ValueError, KeyError, TypeError, CoverageTomlError) as exc:
        error_exit(str(exc), json_mode=json_output)
    results = [
        {"target": cfg.target_name, "functions_changed": count} for cfg, _rows, count in prepared
    ]
    if json_output:
        json_print({"dry_run": dry_run, "results": results})
    else:
        for row in results:
            console.print(
                f"{row['target']}: {row['functions_changed']} function histories {'would change' if dry_run else 'imported'}"
            )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
