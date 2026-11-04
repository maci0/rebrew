"""CLI for reviewed managed-metadata storage transfers and database backup/restore."""

from pathlib import Path

import typer

from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
    run_cli,
)
lazy from rebrew.metadata_transfer import migrate_metadata

app = typer.Typer(
    help="Manage metadata storage and preview backend transfers.",
    rich_markup_mode="rich",
    epilog="[bold]Examples:[/bold]\n\n  rebrew metadata migrate sqlite --dry-run\n\n  rebrew metadata migrate sqlite\n\n  rebrew metadata migrate toml\n\n  rebrew metadata backup --dir /off-tree/backups\n\n  rebrew metadata restore --file backups/db.sqlite3",
)


@app.callback()
def main() -> None:
    """Manage metadata storage and reviewed backend transfers."""


@app.command(
    "migrate",
    epilog="[bold]Examples:[/bold]\n\n  rebrew metadata migrate sqlite --dry-run\n\n  rebrew metadata migrate toml --json",
)
def migrate_cmd(
    backend: str = typer.Argument(..., help="Destination backend: toml or experimental sqlite"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Copy all managed stores and select the backend after verification."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        report = migrate_metadata(cfg, backend, dry_run=dry_run, expected_digest=expected_digest)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        action = (
            "Would transfer" if dry_run else "Transferred" if report["changed"] else "Already using"
        )
        console.print(
            f"{action} metadata: {report['source']} → {backend} ({len(report['stores'])} stores)"
        )


@app.command(
    "backup",
    epilog="[bold]Examples:[/bold]\n\n  rebrew metadata backup --dir /off-tree/backups\n\n  rebrew metadata backup --dir /off-tree/backups --json",
)
def backup_cmd(
    dest_dir: Path = typer.Option(
        ...,
        "--dir",
        help="Directory to copy the active metadata backend's stores (with GA log and BinSync baselines) into",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Copy the active metadata backend's stores, GA log and BinSync baselines to an off-tree directory."""
    from rebrew.metadata.sqlite import backup_metadata_database, backup_metadata_toml

    cfg = require_config(target=target, json_mode=json_output)
    try:
        if getattr(cfg, "metadata_backend", "toml") == "sqlite":
            dest = backup_metadata_database(Path(cfg.root), dest_dir)
        else:
            dest = backup_metadata_toml(Path(cfg.root), dest_dir)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print({"ok": True, "file": str(dest), "action": "backup"})
    else:
        console.print(f"[green]backed up metadata to {dest}[/green]")


@app.command(
    "restore",
    epilog="[bold]Examples:[/bold]\n\n  rebrew metadata restore --file backups/db.sqlite3\n\n  rebrew metadata restore --file backups/rebrew-metadata.backup.toml --json",
)
def restore_cmd(
    file: Path = typer.Option(..., "--file", help="Backup made with 'rebrew metadata backup'"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Install a metadata backup; current stores preserved as .before-restore."""
    from rebrew.metadata.sqlite import restore_metadata_database, restore_metadata_toml

    cfg = require_config(target=target, json_mode=json_output)
    try:
        if file.is_dir():
            dests = restore_metadata_toml(file, Path(cfg.root))
            dest: str = str(dests[0]) if len(dests) == 1 else f"{len(dests)} stores"
        else:
            dest = str(restore_metadata_database(file, Path(cfg.root)))
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print({"ok": True, "file": dest, "action": "restore"})
    else:
        console.print(f"[green]restored metadata to {dest}[/green]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_cli(app)
