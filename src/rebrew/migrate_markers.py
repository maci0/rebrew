"""migrate_markers.py — move inline markers into the metadata stores.

ADR 023 (markers: TOML single source): after migration a ``.c`` file is
pure C.  The ``// FUNCTION:`` marker line and its key-value comment lines
(``// SIZE:``, ``// CFLAGS:``, ``// STATUS:`` legacy blocks, …) are gone,
and so are ``// GLOBAL:`` / ``// DATA:`` / ``// VTABLE:`` / ``// STRING:``.
Function identity (file, symbol, name, marker type, VA, module) lives in
``rebrew-functions.toml``.  Data identity (file, marker type, and the
declaration's name, type, size, and section when the row lacks them) lives
in ``rebrew-data.toml``.

The reader side needs no flag: :func:`rebrew.annotation.parse_c_file_multi`
falls back to metadata-synthesized Annotations for any file that carries no
inline markers, including data rows from ``rebrew-data.toml``.  A file that
still has any inline marker is read from those markers.  Synthesized entries
are not merged in, so migration is all-or-nothing for the file.

Idempotent by construction: a second run finds no markers to strip and
returns before it would recount synthesized rows.

The active target only decides whether the file is in scope.  The strip
removes every marker line, so every function marker and every data marker
in the file is recorded, not only the active target's.  Headers are not
walked; a ``// GLOBAL:`` in a header stays inline.

Usage:
    rebrew source migrate-markers                     # migrate every source file
    rebrew source migrate-markers --dry-run           # preview, write nothing
    rebrew source migrate-markers --json
"""

from __future__ import annotations

from typing import Any

import typer

from rebrew import marker_migration
from rebrew.cli import TargetOption, console, error_exit, json_print, require_config
from rebrew.utils import untrusted_ident

app = typer.Typer(
    help=(
        "Move inline function and data markers into the metadata stores (ADR 023: pure-C sources)."
    ),
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source migrate-markers · · · · · · · · Migrate the whole tree\n\n"
        "  rebrew source migrate-markers --dry-run · · · Preview, write nothing\n\n"
        "[dim]Idempotent. Function markers move into rebrew-functions.toml. "
        "GLOBAL/DATA/VTABLE/STRING markers move into rebrew-data.toml. "
        "A file migrates every marker it carries.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Move inline function and data markers into the metadata stores; strip them from .c."""
    from rebrew.sources import iter_sources, target_marker

    cfg = require_config(target=target, json_mode=json_output)
    tm = target_marker(cfg)
    results: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    skip_why = {
        "unrecorded-markers": "a marker would be removed without being recorded, file not migrated",
    }
    for src in iter_sources(cfg.reversed_dir, cfg):
        try:
            row = marker_migration.migrate_source_file(cfg, src, tm, dry_run)
        except (OSError, ValueError) as exc:
            if json_output:
                error_exit(f"{src}: {exc}", json_mode=True)
            console.print(f"[yellow]skip {untrusted_ident(src)}: {untrusted_ident(exc)}[/yellow]")
            continue
        if not row:
            continue
        if row.get("skipped"):
            skipped.append(row)
            if not json_output:
                why = skip_why.get(str(row["skipped"]), str(row["skipped"]))
                console.print(f"[yellow]skip {untrusted_ident(src)}: {why}[/yellow]")
            continue
        results.append(row)
        if not json_output:
            verb = "would migrate" if dry_run else "migrated"
            parts: list[str] = []
            if row["functions"]:
                parts.append(f"{row['functions']} function(s)")
            if row.get("data"):
                parts.append(f"{row['data']} data marker(s)")
            detail = ", ".join(parts) if parts else "0"
            console.print(f"  {verb} [bold]{untrusted_ident(src)}[/bold] ({detail})")
            if row.get("backup"):
                console.print(
                    f"    [dim]pre-migration copy: {untrusted_ident(str(row['backup']))}[/dim]"
                )
    if json_output:
        json_print(
            {
                "migrated": len(results),
                "dry_run": dry_run,
                "files": results,
                "skipped": skipped,
            }
        )
        return
    console.print(
        f"\n[bold]{'would migrate' if dry_run else 'Migrated'} {len(results)} file(s)[/bold]"
    )
    if skipped:
        console.print(f"[yellow]{len(skipped)} file(s) left inline[/yellow]")
    if not dry_run and results:
        console.print(
            "[dim]Sources are now pure C. Identity lives in "
            "rebrew-functions.toml and rebrew-data.toml.[/dim]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)
