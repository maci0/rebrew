"""Shared source-marker migration into locked function and data metadata stores."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from rebrew.annotation import (
    DATA_MARKERS,
    FUNC_NAME_HINT_RE,
    FUNCTION_MARKERS,
    NEW_FUNC_RE,
    NEW_KV_RE,
)
from rebrew.utils import SOURCE_BACKUP_DIRNAME, atomic_write_text, read_source_text, source_backup


def strip_marker_blocks(lines: list[str]) -> Iterator[str]:
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


def _declaration_after(variables: list[Any], marker_line: int, next_marker_line: int) -> Any | None:
    """The declaration that belongs to the marker at *marker_line*.

    *marker_line* and *next_marker_line* are 1-based.  The declaration's
    extent must start after the marker and before the next marker, matching
    the rule :func:`rebrew.data_scan.scan_globals` uses for an inline marker.
    """
    following = next((var for var in variables if var.end_line > marker_line), None)
    if following is not None and following.line < next_marker_line:
        return following
    return None


def migrate_source_file(
    cfg: Any, filepath: Path, target_name: str | None, dry_run: bool
) -> dict[str, Any] | None:
    """Migrate one source file; returns a result row or None when untouched.

    The active target only decides whether the file is in scope.  Stripping
    deletes every marker line, and a file with any marker left is not
    synthesized from TOML, so every function marker and every data marker
    in the file is recorded or the file is not modified.

    The ``kept == lines`` check runs before the unrecorded-marker count.
    A second run on a marker-less file synthesizes annotations from TOML;
    those are not marker lines, and returning here keeps the run a no-op
    instead of refusing them as unrecorded.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.data_metadata import record_migrated_data_markers
    from rebrew.metadata import record_migrated_markers

    scoped = parse_c_file_multi(filepath, target_name=target_name, metadata_dir=cfg.metadata_dir)
    in_scope = any(
        ann.marker_type in FUNCTION_MARKERS or ann.marker_type in DATA_MARKERS for ann in scoped
    )
    if not in_scope:
        return None

    everyone = (
        parse_c_file_multi(filepath, target_name=None, metadata_dir=cfg.metadata_dir)
        if target_name
        else scoped
    )

    # The stripped text is written back below; re-encoding a legacy source as
    # UTF-8 here would rewrite every cp1252 / Shift-JIS byte in the file that
    # the marker lines happen to sit next to.
    text, encoding = read_source_text(filepath)
    lines = text.splitlines(keepends=True)
    kept = list(strip_marker_blocks(lines))
    if kept == lines:
        return None  # already pure C; identities already live in the TOML

    recorded = [ann for ann in everyone if ann.marker_type in FUNCTION_MARKERS]
    recorded_data = [ann for ann in everyone if ann.marker_type in DATA_MARKERS]
    marker_lines = [line for line in lines if NEW_FUNC_RE.search(line.strip())]
    # The stripper drops every matching line, including ones the parser did
    # not turn into an annotation (trailing comment, commented-out marker).
    # Refuse rather than delete a line that was not recorded.
    if len(marker_lines) != len(recorded) + len(recorded_data):
        return _skip(filepath, "unrecorded-markers")

    file_rel = filepath.resolve().relative_to(Path(cfg.metadata_dir).resolve()).as_posix()
    data_names = _data_names(text, everyone)
    backup_path: Path | None = None
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
                    ("source", ann.source),
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
        record_migrated_data_markers(
            cfg.metadata_dir, _data_rows(recorded_data, data_names, file_rel)
        )
        # Strip only once the TOML holds the values: a failed metadata write
        # must leave the inline markers in place.
        #
        # The strip is one-shot over the whole tree and no code path puts a
        # removed marker line back, so the pre-migration bytes are kept on
        # disk.  A strip that turns out to have dropped a line the operator
        # wrote is otherwise unrecoverable once the working tree is committed.
        with source_backup(
            filepath,
            text,
            encoding,
            Path(cfg.root) / ".rebrew" / SOURCE_BACKUP_DIRNAME,
            label="pre-migration",
            keep=True,
        ) as backup_path:
            atomic_write_text(filepath, "".join(kept), encoding=encoding)
    return {
        "file": str(filepath),
        "functions": len(recorded),
        "data": len(recorded_data),
        "backup": str(backup_path) if backup_path else None,
    }


def _data_names(text: str, annotations: list[Any]) -> dict[tuple[str, int], tuple[str, str]]:
    """``(module, va) -> (name, type)`` from the declaration under each data marker.

    The annotation parser leaves ``name`` empty on ``extern ...;`` lines.
    The same tree-sitter walk :func:`rebrew.data_scan.scan_globals` uses
    supplies the identifier and the type.  The next marker of any kind ends
    the declaration, so a following function is not adopted as the global.
    """
    recorded_data = [ann for ann in annotations if ann.marker_type in DATA_MARKERS]
    if not recorded_data:
        return {}
    from rebrew.c_parser import find_extern_variables

    variables = find_extern_variables(text, include_definitions=True)
    marker_lines = sorted(ann.line for ann in annotations)
    names: dict[tuple[str, int], tuple[str, str]] = {}
    for ann in recorded_data:
        next_line = next((line for line in marker_lines if line > ann.line), 10**9)
        declaration = _declaration_after(variables, ann.line, next_line)
        if declaration is None:
            continue
        names[(ann.module, ann.va)] = (declaration.name, declaration.type_str)
    return names


def _data_rows(
    recorded_data: list[Any],
    data_names: dict[tuple[str, int], tuple[str, str]],
    file_rel: str,
) -> list[dict[str, Any]]:
    """Rows for :func:`rebrew.data_metadata.record_migrated_data_markers`."""
    rows: list[dict[str, Any]] = []
    for ann in recorded_data:
        declared_name, declared_type = data_names.get((ann.module, ann.va), ("", ""))
        name = ann.name or declared_name
        fill = {
            key: value
            for key, value in (
                ("type", declared_type),
                ("size", ann.size),
                ("section", ann.section),
            )
            if value
        }
        rows.append(
            {
                "module": ann.module,
                "va": ann.va,
                "identity": {
                    "file": file_rel,
                    "marker_type": ann.marker_type or "DATA",
                    "name": name,
                },
                "fill": fill,
            }
        )
    return rows
