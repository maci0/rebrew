"""migrate_markers.py — move inline markers into ``rebrew-functions.toml``.

ADR 023 (markers: TOML single source): after migration a ``.c`` file is
pure C — the ``// FUNCTION:`` marker line and its key-value comment lines
(``// SIZE:``, ``// CFLAGS:``, ``// STATUS:`` legacy blocks, …) are gone.
Each function's identity (file, symbol, name, marker type, VA, module)
and volatile state live in the TOML entry only.

The reader side needs no flag: :func:`rebrew.annotation.parse_c_file_multi`
falls back to metadata-synthesized Annotations for any file that carries no
inline markers, so a project can migrate file-by-file (or not at all) and
every consumer keeps working.  A file that still has any inline marker is
read only from those markers — synthesized entries are not merged in — so
migration is all-or-nothing for the file.

Idempotent by construction: a second run finds no markers to strip and the
TOML fields are rewritten to the same values.

Data markers (``GLOBAL`` / ``DATA`` / ``VTABLE`` / ``STRING``) stay inline.
Their facts live in ``rebrew-data.toml``, and several readers still scan the
source text for the marker line.  A file that carries one is left untouched.
The same rule covers stacked per-target function markers (ADR 010): the
strip removes every marker line, so every function marker in the file is
recorded, not only the active target's.

Usage:
    rebrew migrate-markers                     # migrate every source file
    rebrew migrate-markers --dry-run           # preview, write nothing
    rebrew migrate-markers --json
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import (
    DATA_MARKERS,
    FUNC_NAME_HINT_RE,
    FUNCTION_MARKERS,
    NEW_FUNC_RE,
    NEW_KV_RE,
)
from rebrew.cli import TargetOption, console, error_exit, json_print, require_config
from rebrew.utils import atomic_write_text, read_source_text

app = typer.Typer(
    help="Move inline markers into rebrew-functions.toml (ADR 023: pure-C sources).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew migrate-markers · · · · · · · · Migrate the whole tree\n\n"
        "  rebrew migrate-markers --dry-run · · · Preview, write nothing\n\n"
        "[dim]Idempotent. A file migrates every function marker it carries; "
        "GLOBAL/DATA/VTABLE/STRING stay inline.[/dim]"
    ),
)


def _strip_marker_blocks(lines: list[str]) -> Iterator[str]:
    """Yield *lines* minus marker lines and their attached KV/hint comments.

    Mirrors the parser's block state machine: after a marker line, comment
    lines (KV ``// KEY: value`` and bare ``// FuncName`` hints) belong to
    the annotation block and are dropped; the first non-comment code line
    ends the block.
    """
    in_block = False
    for line in lines:
        stripped = line.strip()
        if NEW_FUNC_RE.search(stripped):
            in_block = True
            continue
        if in_block:
            if not stripped:
                yield line  # blank lines end nothing but are kept
                continue
            is_comment = stripped.startswith(("//", "/*"))
            if is_comment and (NEW_KV_RE.search(stripped) or FUNC_NAME_HINT_RE.match(stripped)):
                continue
            in_block = False
        yield line


def _skip(filepath: Path, reason: str) -> dict[str, Any]:
    """Result row for a file left inline. ``skipped`` is the reason code."""
    return {"file": str(filepath), "functions": 0, "skipped": reason}


def _migrate_file(
    cfg: Any, filepath: Path, target_name: str | None, dry_run: bool
) -> dict[str, Any] | None:
    """Migrate one source file; returns a result row or None when untouched.

    The active target only decides whether the file is in scope.  Stripping
    deletes every marker line and a file with any marker left is not
    synthesized from TOML, so either every function marker in the file is
    recorded or the file is not modified.  A data marker keeps the file
    inline: those lines are still the identity source for data readers.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.metadata import record_migrated_markers

    scoped = parse_c_file_multi(filepath, target_name=target_name, metadata_dir=cfg.metadata_dir)
    if not any(ann.marker_type in FUNCTION_MARKERS for ann in scoped):
        return None

    everyone = (
        parse_c_file_multi(filepath, target_name=None, metadata_dir=cfg.metadata_dir)
        if target_name
        else scoped
    )
    if any(ann.marker_type in DATA_MARKERS for ann in everyone):
        return _skip(filepath, "data-markers")

    text, _ = read_source_text(filepath)
    lines = text.splitlines(keepends=True)
    kept = list(_strip_marker_blocks(lines))
    if kept == lines:
        return None  # already pure C; identities already live in the TOML

    recorded = [ann for ann in everyone if ann.marker_type in FUNCTION_MARKERS]
    marker_lines = [line for line in lines if NEW_FUNC_RE.search(line.strip())]
    # The stripper drops every matching line, including ones the parser did
    # not turn into an annotation (trailing comment, commented-out marker).
    # Refuse rather than delete a line that was not recorded.
    if len(marker_lines) != len(recorded):
        return _skip(filepath, "unrecorded-markers")

    file_rel = filepath.resolve().relative_to(Path(cfg.metadata_dir).resolve()).as_posix()
    if not dry_run:
        rows: list[dict[str, Any]] = []
        for ann in recorded:
            # Compile-contract fields read inline before migration: the .c
            # copy is about to be stripped, so the TOML entry must carry them.
            fields = {
                key: value
                for key, value in (
                    ("size", ann.size),
                    ("cflags", ann.cflags),
                    ("toolchain", ann.toolchain),
                )
                if value
            }
            rows.append(
                {
                    "module": ann.module,
                    "va": ann.va,
                    "identity": {
                        "file": file_rel,
                        "symbol": ann.symbol,
                        "marker_type": ann.marker_type or "FUNCTION",
                        "name": ann.name,
                    },
                    "fields": fields,
                }
            )
        record_migrated_markers(cfg.metadata_dir, rows)
        # Strip only once the TOML holds the values: a failed metadata write
        # must leave the inline markers in place.
        atomic_write_text(filepath, "".join(kept))
    return {"file": str(filepath), "functions": len(recorded)}


@app.callback(invoke_without_command=True)
def main(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Move inline markers into rebrew-functions.toml; strip them from .c."""
    from rebrew.sources import iter_sources, target_marker

    cfg = require_config(target=target, json_mode=json_output)
    tm = target_marker(cfg)
    results: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    skip_why = {
        "data-markers": "data markers stay inline, file not migrated",
        "unrecorded-markers": "a marker would be removed without being recorded, file not migrated",
    }
    for src in iter_sources(cfg.reversed_dir, cfg):
        try:
            row = _migrate_file(cfg, src, tm, dry_run)
        except (OSError, ValueError) as exc:
            if json_output:
                error_exit(f"{src}: {exc}", json_mode=True)
            console.print(f"[yellow]skip {src}: {exc}[/yellow]")
            continue
        if not row:
            continue
        if row.get("skipped"):
            skipped.append(row)
            if not json_output:
                why = skip_why.get(str(row["skipped"]), str(row["skipped"]))
                console.print(f"[yellow]skip {src}: {why}[/yellow]")
            continue
        results.append(row)
        if not json_output:
            verb = "would migrate" if dry_run else "migrated"
            console.print(f"  {verb} [bold]{src}[/bold] ({row['functions']} function(s))")
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
            "[dim]Sources are now pure C — identity lives in rebrew-functions.toml.[/dim]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)
