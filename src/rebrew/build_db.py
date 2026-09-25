"""build_db.py – Build SQLite coverage database from function catalog.

Aggregates annotation data, verification results, and coverage statistics
into a single SQLite database for querying and reporting.
"""

import contextlib
import json
import logging
import math
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import typer

from rebrew.annotation import FUNCTION_MARKERS, VALID_MARKERS
from rebrew.cli import (
    EXIT_ERROR,
    TargetOption,
    console,
    error_exit,
    json_print,
)
from rebrew.config import load_config
from rebrew.data_metadata import (
    DATA_STATUS_DRIFT,
    DATA_STATUS_UNCHECKED,
    DATA_STATUS_VERIFIED,
)
from rebrew.metadata import canonical_status
from rebrew.utils import clip_span
from rebrew.workspace import (
    SCHEMA_TARGET,
    SECTION_CELLS_AGG_SQL,
    SECTION_CELLS_COLUMN,
    SECTION_CELLS_TABLE,
    coverage_db_lock,
    db_dir,
    encode_section_cells,
    open_sqlite_ro,
)
from rebrew.workspace.status import KNOWN_STATUSES, MATCHED_STATUSES

_CURRENT_DB_VERSION = "10"

#: ``functions.markerType`` vocabulary, from the annotation parser's set so the
#: CHECK and the insert-time sanitizer cannot drift from what sources may carry.
_MARKER_CHECK_SQL: str = ", ".join(repr(m) for m in sorted(VALID_MARKERS))

#: WHERE term selecting code rows of ``functions`` (``FUNCTION_MARKERS``);
#: every other marker (GLOBAL/DATA/VTABLE/STRING) is data.  Shared verbatim by
#: ``idx_functions_list``'s predicate and every list/stats query: SQLite uses a
#: partial index only when the query repeats its WHERE term.
FUNCTION_ROWS_SQL: str = f"markerType IN ({', '.join(repr(m) for m in sorted(FUNCTION_MARKERS))})"

#: Statuses allowed in ``functions.status``.  ``KNOWN_STATUSES`` plus
#: ``UNKNOWN`` (the DEFAULT when a catalog row omits STATUS).  Kept in one
#: place so the CREATE TABLE CHECK and the insert-time sanitizer cannot drift.
_FUNCTION_DB_STATUSES: frozenset[str] = frozenset({*KNOWN_STATUSES, "UNKNOWN"})
_FUNCTION_STATUS_CHECK_SQL: str = ", ".join(repr(s) for s in sorted(_FUNCTION_DB_STATUSES))

#: Column DDL for the persistent tables (never dropped on rebuild).  Shared by
#: CREATE IF NOT EXISTS and the in-place migration so the two cannot drift.
_HISTORY_COLUMNS_SQL = f"""
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    va INTEGER NOT NULL CHECK (va >= 0),
    old_status TEXT
        CHECK (old_status IS NULL OR old_status IN ({_FUNCTION_STATUS_CHECK_SQL})),
    new_status TEXT
        CHECK (new_status IS NULL OR new_status IN ({_FUNCTION_STATUS_CHECK_SQL})),
    changed_at TEXT NOT NULL CHECK (changed_at != ''),
    updated_by TEXT NOT NULL DEFAULT ''
"""
_VERIFY_RESULTS_COLUMNS_SQL = """
    target TEXT NOT NULL,
    va INTEGER NOT NULL CHECK (va >= 0),
    verified_at TEXT NOT NULL CHECK (verified_at != ''),
    byte_delta INTEGER CHECK (byte_delta IS NULL OR byte_delta >= 0),
    diff_lines INTEGER CHECK (diff_lines IS NULL OR diff_lines >= 0),
    similarity REAL CHECK (similarity IS NULL OR (similarity >= 0.0 AND similarity <= 1.0)),
    reg_delta INTEGER CHECK (reg_delta IS NULL OR reg_delta >= 0),
    effective_match INTEGER CHECK (effective_match IS NULL OR effective_match IN (0, 1)),
    PRIMARY KEY (target, va)
"""

#: Statuses allowed in ``globals.status``.  Empty string (no verdict yet)
#: plus the three data-metadata verdicts — derived from the same constants
#: ``data_metadata`` / the grid emit so the CHECK and the insert sanitizer
#: cannot drift from the annotation vocabulary.
_GLOBAL_DB_STATUSES: frozenset[str] = frozenset(
    {
        "",
        DATA_STATUS_VERIFIED,
        DATA_STATUS_DRIFT,
        DATA_STATUS_UNCHECKED,
    }
)
_GLOBAL_STATUS_CHECK_SQL: str = ", ".join(repr(s) for s in sorted(_GLOBAL_DB_STATUSES))

# Per-section coverage buckets, as ONE select used both to declare the
# ``section_cell_stats`` table and to refill it — the bucket definitions
# (including the catch-all that keeps total_cells reconcilable) exist in
# exactly one place.
#
# This is a build-time TABLE, not a view.  As a view, every
# reader re-aggregated the whole cells table: 13 SUM(CASE state = '<text>')
# over 64k rows measured 17.3 ms per request — 92% of the remaining cold
# /data build once the cell JSON was materialized.  A covering index did not
# help (10% for +3.1 MB): the cost is the string comparisons, not the table
# lookups.  Every consumer queries it as
# ``SELECT ... FROM section_cell_stats WHERE target = ?``, which is
# indifferent to table-vs-view, so no reader changed — and a database still
# carrying the old view keeps working until its next build replaces it.
#
# Safe as a table because ``build_db`` is the only writer of ``cells``.
_SECTION_CELL_STATS_SELECT = """
    SELECT
        target,
        section_name,
        COUNT(*) as total_cells,
        SUM(CASE WHEN state IN ('exact', 'verified') THEN 1 ELSE 0 END) as exact_count,
        SUM(CASE WHEN state = 'reloc' THEN 1 ELSE 0 END) as reloc_count,
        SUM(CASE WHEN state IN ('near_match', 'near_matching') THEN 1 ELSE 0 END) as near_match_count,
        SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) as stub_count,
        SUM(CASE WHEN state = 'padding' THEN 1 ELSE 0 END) as padding_count,
        SUM(CASE WHEN state = 'data' THEN 1 ELSE 0 END) as data_count,
        SUM(CASE WHEN state = 'thunk' THEN 1 ELSE 0 END) as thunk_count,
        SUM(CASE WHEN state = 'none' THEN 1 ELSE 0 END) as none_count,
        SUM(CASE WHEN state = 'proven' THEN 1 ELSE 0 END) as proven_count,
        SUM(CASE WHEN state = 'size_mismatch' THEN 1 ELSE 0 END) as size_mismatch_count,
        -- Catch-all for every other state (compile_error,
        -- extract_error, invalid_va, missing_file, missing_size,
        -- skip, unknown, plus the data drift/unchecked verdicts):
        -- without it total_cells never equals the sum of the counted
        -- columns and per-section stats silently undercount
        --.  `verified` is excluded here because it is
        -- counted as exact_count above.
        SUM(CASE WHEN state NOT IN (
            'exact', 'verified', 'reloc', 'near_match', 'near_matching',
            'stub', 'padding', 'data', 'thunk', 'none', 'proven',
            'size_mismatch'
        ) THEN 1 ELSE 0 END) as other_count
    FROM cells
    GROUP BY target, section_name
"""

#: Name of the derived per-section stats table (was a view before it was
#: materialized; see _SECTION_CELL_STATS_SELECT).
SECTION_CELL_STATS_TABLE = "section_cell_stats"

#: Per-target retention cap for the history table: only the newest N status-
#: change rows per target are kept after each rebuild.  The dashboard pages
#: the newest 100 (max 5000) — keeping 10k per target preserves 2+ full
#: pages of history while bounding unbounded growth.
_HISTORY_RETENTION = 10_000

# Reserved metadata target holding the schema-level db_version stamp, so the
# version is read deterministically regardless of which targets exist (a
# scoped --target rebuild must not leave the DB reporting a stale version).
#: `SCHEMA_TARGET` comes from rebrew.workspace (the shared reader uses it too).
_SQLITE_TIMEOUT_SECONDS = 30.0


def _parse_int(value: Any, default: int = 0) -> int:
    """Parse an integer from JSON-ish input, returning *default* on invalid values."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return default
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return default
        try:
            return int(s, 0)
        except ValueError:
            return default
    return default


def _clamp_nonneg_int(value: Any) -> int | None:
    """Return a non-negative int, or ``None`` when *value* is absent/unusable.

    Non-finite floats (``NaN``, ``±inf``) are rejected: ``int(inf)`` raises,
    and on Python 3.13+ ``max``/``min`` with ``NaN`` can silently pick a
    bound (``max(0, min(1, nan))`` → ``1``), which would invent a delta.
    Non-integral floats (``12.9``, ``-1.5``) are also rejected: ``int()``
    truncates toward zero and would store a wrong byte_delta (``12`` for
    ``12.9``, or ``0`` after clamping a truncated ``-1``).
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        return max(0, int(value))
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return max(0, int(s, 0))
        except ValueError:
            return None
    return None


def _clamp_unit_interval(value: Any) -> float | None:
    """Return a float in ``[0.0, 1.0]``, or ``None`` when *value* is absent/unusable.

    Non-finite inputs are rejected.  ``max(0.0, min(1.0, nan))`` returns
    ``1.0`` on Python 3.13+ (unordered comparison keeps the finite bound),
    which would store a perfect similarity for a corrupt/NaN score.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            parsed = float(s)
        except ValueError:
            return None
        if not math.isfinite(parsed):
            return None
        return max(0.0, min(1.0, parsed))
    return None


def _clamp_verify_similarity(value: Any) -> float | None:
    """Normalize verify-cache similarity into the DB's ``[0.0, 1.0]`` column.

    ``rebrew verify`` stores ``code_similarity`` on a 0–100 percent scale
    (``Sim %`` in the summary table).  The coverage DB CHECK and
    ``docs/DB_FORMAT.md`` use the unit interval.  Always divide by 100:
    a pass-through for ``[0, 1]`` treated ``1.0`` (1% Sim) as a perfect
    match and ``0.5`` (0.5%) as 50%.  This helper is only used for the
    verify-cache import path, which is always percent-scale.  Non-finite
    and ``> 100`` inputs are rejected; negatives clamp to ``0.0``.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        parsed = float(value)
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            parsed = float(s)
        except ValueError:
            return None
        if not math.isfinite(parsed):
            return None
    else:
        return None
    if parsed > 100.0:
        return None
    return max(0.0, min(1.0, parsed / 100.0))


def _clamp_effective_match(value: Any) -> int | None:
    """Return ``0``, ``1``, or ``None`` for the effective-match flag column."""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value if value in (0, 1) else None
    if isinstance(value, float) and value in (0.0, 1.0):
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if s in ("0", "1"):
            return int(s)
    return None


#: Known cell states emitted by catalog/grid.py.  Function cells set
#: ``state = item["status"].lower()``, so every ``KNOWN_STATUSES`` value can
#: appear lowercased (including ``extract_error`` / ``invalid_va``).  Deriving
#: those from ``KNOWN_STATUSES`` keeps the CHECK and the sanitizer in lockstep
#: with the annotation vocabulary.  Gap/label states and
#: data-metadata verdicts are not function STATUSes, so they are unioned in
#: explicitly.  ``near_match`` is the accepted alias for ``near_matching``.
_GAP_AND_DATA_CELL_STATES: frozenset[str] = frozenset(
    {
        "near_match",
        "unknown",
        "none",
        "padding",
        "data",
        "thunk",
        DATA_STATUS_VERIFIED.lower(),
        DATA_STATUS_DRIFT.lower(),
        DATA_STATUS_UNCHECKED.lower(),
    }
)
_KNOWN_CELL_STATES: frozenset[str] = (
    frozenset(s.lower() for s in KNOWN_STATUSES) | _GAP_AND_DATA_CELL_STATES
)
_CELL_STATE_CHECK_SQL: str = ", ".join(repr(s) for s in sorted(_KNOWN_CELL_STATES))


#: One normalized ``cells`` insert row:
#: ``(target, section_name, start, end, span, state, functions_json, label, parent)``.
_CellRow = tuple[str, str, int, int, int, str, str, str | None, str | None]


def _normalize_cell_row(target_name: str, sec_name: str, cell: dict[str, Any]) -> _CellRow:
    """Return a DB-safe cell row from generated coverage JSON."""
    start = max(0, _parse_int(cell.get("start"), 0))
    end = max(start, _parse_int(cell.get("end"), start))
    span = max(1, _parse_int(cell.get("span"), 1))
    state = str(cell.get("state") or "none")
    if state not in _KNOWN_CELL_STATES:
        logging.warning(
            "build_db: cell state %r not in known set — coercing to "
            "'unknown' (check the generator or hand-edited JSON); known: %s",
            state,
            ", ".join(sorted(_KNOWN_CELL_STATES)),
        )
        state = "unknown"
    functions = cell.get("functions", [])
    if not isinstance(functions, list):
        functions = []
    label = cell.get("label")
    parent_function = cell.get("parent_function")
    return (
        target_name,
        sec_name,
        start,
        end,
        span,
        state,
        json.dumps(functions),
        str(label) if label is not None else None,
        str(parent_function) if parent_function is not None else None,
    )


def _dedupe_cell_rows(
    rows: list[_CellRow],
    *,
    target_name: str,
    sec_name: str,
) -> list[_CellRow]:
    """Collapse rows that share ``start`` after normalization.

    ``cells`` has ``UNIQUE (target, section_name, start)``.  Hand-edited JSON
    (or a negative ``start`` clamped to 0 next to a real ``start: 0`` cell)
    would otherwise abort the whole rebuild.  Last row wins so a later real
    cell overrides a clamped collision; results are sorted by ``start`` for
    stable inserts.
    """
    if len(rows) < 2:
        return rows
    by_start: dict[int, _CellRow] = {}
    for row in rows:
        by_start[row[2]] = row
    dropped = len(rows) - len(by_start)
    if dropped:
        logging.warning(
            "build_db: %s %s: dropped %d duplicate cell row(s) sharing the "
            "same start after normalization (UNIQUE target/section/start); "
            "last wins",
            target_name,
            sec_name,
            dropped,
        )
    return sorted(by_start.values(), key=lambda r: r[2])


def _dedupe_by_va(
    rows: list[tuple[Any, ...]], *, target_name: str, table: str
) -> list[tuple[Any, ...]]:
    """Collapse rows sharing ``va`` (index 1) so the ``(target, va)`` PK holds.

    Two JSON keys can spell one VA (``"0x401000"`` and ``"4198400"``, or a bad
    key recovered from ``vaStart``); inserting both would abort the whole
    rebuild.  Last row wins, matching :func:`_dedupe_cell_rows`.
    """
    by_va = {row[1]: row for row in rows}
    dropped = len(rows) - len(by_va)
    if dropped:
        logging.warning(
            "build_db: %s: dropped %d duplicate %s row(s) sharing a VA "
            "(PRIMARY KEY target/va); last wins",
            target_name,
            dropped,
            table,
        )
    return list(by_va.values())


def _function_stats(
    c: sqlite3.Cursor, target_name: str
) -> tuple[int, dict[str, int], dict[str, list[Any]], int, int]:
    """Return (total, by_status, by_module, covered_bytes, matched_bytes).

    ``covered_bytes`` = sum of EVERY function's size regardless of status
    ("identified bytes" — a STUB placeholder counts fully).  ``matched_bytes``
    = sum of byte-matched EXACT/RELOC sizes only (the dashboard
    headline used covered_bytes, so an all-STUB binary reported ~100%
    "coverage").  The headline metric is matched bytes; identified bytes is
    the separate "fully documented" figure.
    """
    c.execute(
        "SELECT va, name, size, status, module, symbol, markerType, files "
        f"FROM functions WHERE target = ? AND {FUNCTION_ROWS_SQL} ORDER BY va",
        (target_name,),
    )
    total: int = 0
    by_status: dict[str, int] = {}
    by_module: dict[str, list[Any]] = {}
    covered_bytes: int = 0
    matched_bytes: int = 0
    rows = c.fetchall()
    # Cut each span at the next function start: a discoverer that missed a
    # start reports the previous entry running through it (as rebrew status).
    starts = [fn[0] for fn in rows]
    for fn in rows:
        total += 1
        st = fn[3] or "UNKNOWN"
        by_status[st] = by_status.get(st, 0) + 1
        mod = fn[4] or "GAME"
        by_module.setdefault(mod, []).append(fn)
        size = None if fn[2] is None else clip_span(starts, fn[0], fn[2])
        # Function statuses are EXACT/RELOC/STUB/... — never "none" (a cell
        # state); the old `st != "none"` guard was always true and misleading.
        covered_bytes += size if size is not None else 0
        if st in MATCHED_STATUSES:
            matched_bytes += size if size is not None else 0
    return total, by_status, by_module, covered_bytes, matched_bytes


def _snapshot_inputs(root_dir: Path) -> list[Path]:
    """Files a data_*.json snapshot does not reflect until it is regenerated."""
    inputs = [root_dir / ".rebrew" / "verify_cache.json"]
    if (root_dir / "rebrew-project.toml").exists():
        inputs.append(load_config(root_dir).metadata_dir / "rebrew-functions.toml")
    return [p for p in inputs if p.is_file()]


def resolve_db_dir(root_dir: Path, *, json_output: bool = False) -> Path:
    """Return the configured database directory, falling back when no config exists.

    The path comes from the shared ``rebrew.workspace.db_dir`` resolver, so a
    dashboard and this builder never disagree on where coverage.db lives.  A
    config that is present but broken still fails loud here rather than
    silently falling back to ``db/``.
    """
    if not (root_dir / "rebrew-project.toml").exists():
        return root_dir / "db"
    try:
        load_config(root_dir)
    except (FileNotFoundError, KeyError, ValueError, TypeError) as exc:
        error_exit(f"Config error: {exc}", json_mode=json_output)
    return db_dir(root_dir)


#: SQLite side files that belong to one database file.  A -wal left behind
#: by a killed build is replayed into whatever database next opens that path.
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


def _unlink_db(db_path: Path) -> None:
    """Delete *db_path* and its SQLite side files."""
    db_path.unlink()
    for suffix in _SQLITE_SIDECAR_SUFFIXES:
        db_path.with_name(db_path.name + suffix).unlink(missing_ok=True)


def _check_db_version(db_path: Path, *, force: bool = False, json_output: bool = False) -> None:
    """Raise SystemExit (via error_exit) if DB exists with an incompatible schema version.

    On mismatch without ``--force``: emit a clear error.
    With ``--force``: delete the DB file so it is recreated from scratch.
    """
    if not db_path.exists():
        return
    try:
        with contextlib.closing(open_sqlite_ro(db_path)) as conn:
            c = conn.cursor()
            objects = c.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            empty_schema = not objects
            row = None
            if ("metadata",) in objects:
                c.execute(
                    "SELECT value FROM metadata WHERE target = ? AND key = 'db_version' LIMIT 1",
                    (SCHEMA_TARGET,),
                )
                row = c.fetchone()
                if row is None:
                    c.execute("SELECT value FROM metadata WHERE key = 'db_version' LIMIT 1")
                    row = c.fetchone()
        if row is None:
            stored_version = "<unknown>"
        else:
            try:
                stored_version = json.loads(row[0])
            except (json.JSONDecodeError, TypeError):
                stored_version = str(row[0])
    except sqlite3.Error as exc:
        if "locked" in str(exc).lower():
            # A live DB under contention (concurrent build-db, recoverage
            # regen) must NEVER be deleted — that is silent data loss.
            error_exit(
                f"Database at '{db_path}' is locked by another process: {exc}. "
                "Wait for it to finish and retry.",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        error_exit(
            f"Cannot inspect database at '{db_path}': {exc}. "
            "The existing database has been preserved.",
            json_mode=json_output,
            code=EXIT_ERROR,
        )

    if empty_schema:
        console.print(
            "[yellow]warning:[/yellow] existing database has no schema (likely a "
            "failed build); deleting and rebuilding."
        )
        _unlink_db(db_path)
        return

    if stored_version == _CURRENT_DB_VERSION:
        # The version string alone is not proof of shape: a DB stamped "4" can
        # be missing required objects (history table, section_cell_stats)
        # and pass the gate, then 500 at query time.  Verify the objects the
        # version promises exist.
        try:
            missing = _missing_required_objects(db_path)
        except sqlite3.Error as exc:
            error_exit(
                f"Cannot inspect database at '{db_path}': {exc}. "
                "The existing database has been preserved.",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        if missing:
            stored_version = f"{stored_version!r} (missing: {', '.join(sorted(missing))})"

    if stored_version != _CURRENT_DB_VERSION:
        if not force:
            error_exit(
                f"Database at '{db_path}' has schema version {stored_version!r} "
                f"but this tool requires version {_CURRENT_DB_VERSION!r}.\n"
                "The existing DB is incompatible. Pass --force to delete it and rebuild.",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        console.print(
            f"[yellow]warning:[/yellow] schema mismatch (stored={stored_version!r}, "
            f"required={_CURRENT_DB_VERSION!r}); deleting '{db_path}' and rebuilding (--force)."
        )
        _unlink_db(db_path)


def _missing_required_objects(db_path: Path) -> set[str]:
    """Return the names of schema objects a current-version DB must have but
    *db_path* lacks (empty when the schema is complete).  The version stamp
    alone is not proof of shape — a hand-made or half-written DB can carry
    the right stamp and still miss tables/views.

    Checks object names AND the query-critical columns: a DB stamped "4"
    whose ``functions`` table lacks ``textOffset``/``similarity`` (or whose
    ``section_cell_stats`` is missing a counted bucket) passes a name-only gate
    and then 500s at query time.  Missing columns are reported as
    ``table.column``.
    """
    required = {
        "metadata",
        "sections",
        "cells",
        "functions",
        "globals",
        "verify_results",
        "history",
        "section_cell_stats",
        SECTION_CELLS_TABLE,
    }
    # Columns the recoverage queries depend on; a DB missing any of these
    # fails at runtime despite a correct version stamp.
    required_columns: dict[str, set[str]] = {
        "metadata": {"target", "key", "value"},
        "sections": {"target", "name", "va", "size", "fileOffset", "unitBytes", "columns"},
        "cells": {
            "target",
            "section_name",
            "start",
            "end",
            "span",
            "state",
            "functions",
            "label",
            "parent_function",
        },
        "functions": {
            "target",
            "va",
            "name",
            "vaStart",
            "size",
            "fileOffset",
            "status",
            "module",
            "cflags",
            "symbol",
            "markerType",
            "ghidra_name",
            "list_name",
            "is_thunk",
            "is_export",
            "sha256",
            "files",
            "detected_by",
            "size_by_tool",
            "textOffset",
            "blocker",
            "blockerDelta",
            "size_reason",
            "similarity",
            "updated_by",
            "updated_at",
        },
        "globals": {"target", "va", "name", "decl", "files", "module", "size", "status"},
        "verify_results": {
            "target",
            "va",
            "verified_at",
            "byte_delta",
            "diff_lines",
            "similarity",
            "reg_delta",
            "effective_match",
        },
        "history": {"id", "target", "va", "old_status", "new_status", "changed_at", "updated_by"},
        "section_cell_stats": {
            "target",
            "section_name",
            "total_cells",
            "exact_count",
            "reloc_count",
            "near_match_count",
            "stub_count",
            "padding_count",
            "data_count",
            "thunk_count",
            "none_count",
            "proven_count",
            "size_mismatch_count",
            # Dashboard ``/api/sections`` selects this catch-all; a v3-era
            # stats object without it passes a name-only gate then 500s.
            "other_count",
        },
        SECTION_CELLS_TABLE: {"target", "section_name", SECTION_CELLS_COLUMN},
    }
    with contextlib.closing(open_sqlite_ro(db_path)) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT type, name FROM sqlite_master"
            " WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
        )
        present = {row[1] for row in c.fetchall()}
        missing = required - present
        if missing:
            return missing
        for obj, cols in required_columns.items():
            c.execute(f"PRAGMA table_info({obj})")
            actual = {row[1] for row in c.fetchall()}
            for col in cols - actual:
                missing.add(f"{obj}.{col}")
        return missing


def build_db(
    project_root: Path | None = None,
    target: str | None = None,
    json_output: bool = False,
    force: bool = False,
    regen: bool = False,
) -> None:
    """Aggregate coverage data into the configured coverage database.

    By default reads ``db/data_*.json`` files (written by ``rebrew catalog
    --data-json``).  With *regen*, the coverage dicts are generated
    in-process per target instead — no intermediate files.
    """
    root_dir = Path(project_root).resolve() if project_root else Path.cwd().resolve()
    db_dir = resolve_db_dir(root_dir, json_output=json_output)
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "coverage.db"

    # Exclusive across the version check, unlink, and rebuild.  Two build-db
    # processes (or a dashboard reader) must not observe the file disappear
    # out from under an open connection.
    with coverage_db_lock(db_path):
        _build_coverage_db(
            root_dir,
            db_path,
            target=target,
            json_output=json_output,
            force=force,
            regen=regen,
        )


def _build_coverage_db(
    root_dir: Path,
    db_path: Path,
    *,
    target: str | None,
    json_output: bool,
    force: bool,
    regen: bool,
) -> None:
    """Body of :func:`build_db`.  Caller holds :func:`coverage_db_lock`."""
    _check_db_version(db_path, force=force, json_output=json_output)

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(db_path, timeout=_SQLITE_TIMEOUT_SECONDS)
        c: sqlite3.Cursor = conn.cursor()
        # WAL + relaxed sync trade durability for throughput on a rebuildable
        # cache DB; foreign_keys=ON enforces cells/section_cells_json/section_cell_stats
        # → sections cascades on scoped target deletes.
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA cache_size=-64000")
        c.execute("PRAGMA temp_store=MEMORY")

        # Start an exclusive transaction BEFORE the status snapshot so the
        # snapshot and the rebuild below are in the same transaction (a
        # concurrent rebuild between the two would record wrong old_statuses
        # in history).
        c.execute("BEGIN IMMEDIATE")

        # Snapshot existing function statuses for history tracking
        old_statuses: dict[tuple[str, int], str] = {}
        with contextlib.suppress(sqlite3.OperationalError):
            c.execute("SELECT target, va, status FROM functions")
            for row in c.fetchall():
                old_statuses[(row[0], row[1])] = row[2]

        # The stats table is derived from cells — recreate it every run
        # (scoped rebuilds keep the tables but must refresh the stats too).
        # It was a VIEW before it was materialized, and SQLite refuses
        # DROP VIEW on a table (and DROP TABLE on a view), so drop by the type
        # actually present: that type check IS the migration path for
        # databases built before the change.
        existing_stats = c.execute(
            "SELECT type FROM sqlite_master WHERE name = ?", (SECTION_CELL_STATS_TABLE,)
        ).fetchone()
        if existing_stats is not None:
            stats_kind = "VIEW" if existing_stats[0] == "view" else "TABLE"
            c.execute(f"DROP {stats_kind} {SECTION_CELL_STATS_TABLE}")
        # Derived cache: drop before sections so a sections FK cannot block
        # DROP TABLE sections on full rebuild.  Recreated with CREATE below.
        c.execute(f"DROP TABLE IF EXISTS {SECTION_CELLS_TABLE}")
        # Full rebuild (no --target): recreate the whole schema.
        # Scoped rebuild (--target): keep the schema and other targets'
        # rows; only this target's rows are deleted below.
        if not target:
            c.execute("DROP TABLE IF EXISTS cells")
            c.execute("DROP TABLE IF EXISTS functions")
            c.execute("DROP TABLE IF EXISTS globals")
            c.execute("DROP TABLE IF EXISTS sections")
            c.execute("DROP TABLE IF EXISTS metadata")
            # verify_results is NOT dropped here: it is a persistent history
            # table (DB_FORMAT.md documents "never dropped on rebuild"), and
            # dropping it wiped every target's verification rows except the
            # last-verified target's (re-imported below from
            # verify_results.json).  The per-target INSERT OR REPLACE + prune
            # below keeps it current without the drop.
            # v3-era index superseded by idx_history_target_id — history is
            # never dropped (accumulates by design), so remove the dead index
            # explicitly or it survives every rebuild.
            c.execute("DROP INDEX IF EXISTS idx_history_target_va")

        c.execute(f"""
            CREATE TABLE IF NOT EXISTS functions (
                target TEXT NOT NULL,
                va INTEGER NOT NULL CHECK (va >= 0),
                name TEXT NOT NULL DEFAULT '',
                vaStart TEXT NOT NULL DEFAULT '',
                size INTEGER CHECK (size IS NULL OR size >= 0),
                fileOffset INTEGER CHECK (fileOffset IS NULL OR fileOffset >= 0),
                status TEXT NOT NULL DEFAULT 'UNKNOWN'
                    CHECK (status IN ({_FUNCTION_STATUS_CHECK_SQL})),
                module TEXT NOT NULL DEFAULT '',
                cflags TEXT,
                symbol TEXT,
                markerType TEXT NOT NULL DEFAULT 'FUNCTION'
                    CHECK (markerType IN ({_MARKER_CHECK_SQL})),
                ghidra_name TEXT,
                list_name TEXT,
                is_thunk INTEGER NOT NULL DEFAULT 0 CHECK (is_thunk IN (0, 1)),
                is_export INTEGER NOT NULL DEFAULT 0 CHECK (is_export IN (0, 1)),
                sha256 TEXT,
                files TEXT NOT NULL DEFAULT '[]',
                detected_by TEXT NOT NULL DEFAULT '[]',
                size_by_tool TEXT NOT NULL DEFAULT '{{}}',
                textOffset INTEGER CHECK (textOffset IS NULL OR textOffset >= 0),
                blocker TEXT,
                blockerDelta INTEGER CHECK (blockerDelta IS NULL OR blockerDelta >= 0),
                size_reason TEXT,
                similarity REAL CHECK (similarity IS NULL OR (similarity >= 0.0 AND similarity <= 1.0)),
                updated_by TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (target, va)
            )
        """)

        c.execute(f"""
            CREATE TABLE IF NOT EXISTS globals (
                target TEXT NOT NULL,
                va INTEGER NOT NULL CHECK (va >= 0),
                name TEXT NOT NULL DEFAULT '',
                decl TEXT NOT NULL DEFAULT '',
                files TEXT NOT NULL DEFAULT '[]',
                module TEXT NOT NULL DEFAULT '',
                size INTEGER NOT NULL DEFAULT 4 CHECK (size >= 0),
                status TEXT NOT NULL DEFAULT ''
                    CHECK (status IN ({_GLOBAL_STATUS_CHECK_SQL})),
                PRIMARY KEY (target, va)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS sections (
                target TEXT NOT NULL,
                name TEXT NOT NULL,
                va INTEGER CHECK (va IS NULL OR va >= 0),
                size INTEGER CHECK (size IS NULL OR size >= 0),
                fileOffset INTEGER CHECK (fileOffset IS NULL OR fileOffset >= 0),
                unitBytes INTEGER CHECK (unitBytes IS NULL OR unitBytes > 0),
                columns INTEGER CHECK (columns IS NULL OR columns > 0),
                PRIMARY KEY (target, name)
            )
        """)

        c.execute(f"""
            CREATE TABLE IF NOT EXISTS cells (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                section_name TEXT NOT NULL,
                start INTEGER NOT NULL CHECK (start >= 0),
                end INTEGER NOT NULL CHECK (end >= start),
                span INTEGER NOT NULL DEFAULT 1 CHECK (span > 0),
                state TEXT NOT NULL
                    CHECK (state IN ({_CELL_STATE_CHECK_SQL})),
                functions TEXT NOT NULL DEFAULT '[]',
                label TEXT,
                parent_function TEXT,
                UNIQUE (target, section_name, start),
                FOREIGN KEY (target, section_name)
                    REFERENCES sections(target, name)
                    ON DELETE CASCADE
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                target TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY (target, key)
            )
        """)
        # PK is (target, key); dashboards and version probes also filter by
        # key alone (``WHERE key = 'function_stats'`` / ``key = 'db_version'``),
        # which cannot use that leftmost-target index.
        c.execute("CREATE INDEX IF NOT EXISTS idx_metadata_key ON metadata(key, target)")

        # Per-section cell JSON, pre-aggregated and zstd-compressed.  Serving a
        # dashboard grid otherwise re-runs json_group_array over every cell on
        # each cold request: measured 10.7 ms of SQLite per 39k-cell section
        # versus 0.3 ms to read this row, for 188 KB stored across the whole
        # table.  WITHOUT ROWID because it is accessed only by its primary key,
        # so the implicit rowid (and its index) would be dead weight.
        #
        # It is a derived cache: `cells` remains the source of truth and is the
        # only thing other queries read, so a reader without this table still
        # works (see rebrew.workspace.SECTION_CELLS_AGG_SQL).  DROP ran above
        # (before sections) so a prior FK cannot block full-rebuild drops;
        # CREATE here (not IF NOT EXISTS) so the sections FK always applies.
        c.execute(f"""
            CREATE TABLE {SECTION_CELLS_TABLE} (
                target TEXT NOT NULL,
                section_name TEXT NOT NULL,
                {SECTION_CELLS_COLUMN} BLOB NOT NULL,
                PRIMARY KEY (target, section_name),
                FOREIGN KEY (target, section_name)
                    REFERENCES sections(target, name)
                    ON DELETE CASCADE
            ) WITHOUT ROWID
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(target, name)")
        # The dashboard filters by status or module and pages ORDER BY va; the
        # trailing va lets the index serve the sort, so the planner seeks the
        # filter instead of walking idx_functions_list over the whole target.
        # Scoped rebuilds keep the table: drop the (target, status|module)
        # copies older builds created.
        c.execute("DROP INDEX IF EXISTS idx_functions_status")
        c.execute("DROP INDEX IF EXISTS idx_functions_module")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_functions_status_va ON functions(target, status, va)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_functions_module_va ON functions(target, module, va)"
        )
        # Dashboard + _function_stats list only FUNCTION_ROWS_SQL rows and
        # ORDER BY va: a partial (target, va) index matches that filter+sort
        # without scanning data rows that the UI never lists.  It also serves
        # the COUNT(*), so a (target, markerType) index would only cost writes:
        # drop the copy older builds created (scoped rebuilds keep the table).
        # idx_functions_list is dropped and recreated every run so a scoped
        # rebuild cannot keep an older build's predicate, which no current
        # query matches.
        c.execute("DROP INDEX IF EXISTS idx_functions_marker")
        c.execute("DROP INDEX IF EXISTS idx_functions_list")
        c.execute(
            f"CREATE INDEX idx_functions_list ON functions(target, va) WHERE {FUNCTION_ROWS_SQL}"
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_globals_name ON globals(target, name)")
        # The dashboard filters globals by module and pages ORDER BY va; the
        # trailing va lets the index serve the sort, so the planner seeks the
        # filter instead of scanning all globals for the target.
        c.execute("DROP INDEX IF EXISTS idx_globals_module")
        c.execute("CREATE INDEX IF NOT EXISTS idx_globals_module_va ON globals(target, module, va)")
        # idx_cells_section is deliberately NOT created: the
        # UNIQUE (target, section_name, start) constraint already serves the
        # same leftmost prefix (target, section_name) for the view's
        # GROUP BY and any WHERE target=? AND section_name=? query — a second
        # index would be paid for on every cell insert and never be the only
        # usable one.  Drop any pre-existing copy from older
        # builds explicitly or it survives every rebuild.
        c.execute("DROP INDEX IF EXISTS idx_cells_section")

        c.execute(f"CREATE TABLE IF NOT EXISTS history ({_HISTORY_COLUMNS_SQL})")
        # history is never dropped on rebuild, so CREATE IF NOT EXISTS leaves a
        # pre-CHECK table alone.  Recreate in place (preserving rows, clamping
        # outliers) when the stored DDL lacks the range/status guards.
        hist_sql_row = c.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'history'"
        ).fetchone()
        hist_sql = hist_sql_row[0] if hist_sql_row else ""
        if hist_sql and "old_status IS NULL OR old_status IN" not in hist_sql:
            c.execute("ALTER TABLE history RENAME TO _history_migrate")
            c.execute(f"CREATE TABLE history ({_HISTORY_COLUMNS_SQL})")
            # Preserve id so ORDER BY id DESC / retention stay stable across
            # the recreate.  Statuses outside the functions vocabulary become
            # UNKNOWN (same coercion the functions insert path uses).
            c.execute(
                f"""
                INSERT INTO history (
                    id, target, va, old_status, new_status, changed_at, updated_by
                )
                SELECT
                    id,
                    target,
                    CASE
                        WHEN typeof(va) = 'integer' AND va >= 0 THEN va
                        ELSE 0
                    END,
                    CASE
                        WHEN old_status IS NULL THEN NULL
                        WHEN old_status IN ({_FUNCTION_STATUS_CHECK_SQL}) THEN old_status
                        ELSE 'UNKNOWN'
                    END,
                    CASE
                        WHEN new_status IS NULL THEN NULL
                        WHEN new_status IN ({_FUNCTION_STATUS_CHECK_SQL}) THEN new_status
                        ELSE 'UNKNOWN'
                    END,
                    CASE
                        WHEN changed_at IS NULL OR changed_at = ''
                            THEN '1970-01-01T00:00:00+00:00'
                        ELSE changed_at
                    END,
                    COALESCE(updated_by, '')
                FROM _history_migrate
                """
            )
            c.execute("DROP TABLE _history_migrate")
        # history rows are appended on every rebuild; the dashboard pages them
        # with WHERE target = ? ORDER BY id DESC LIMIT ?, so (target, id) is
        # the serving index (a plain (target, va) index would not serve the
        # ORDER BY id).  Growth is bounded by a per-target retention cap —
        # only the newest _HISTORY_RETENTION rows per target are kept, so a
        # long-lived project that regenerates often does not accumulate rows
        # forever.
        c.execute("CREATE INDEX IF NOT EXISTS idx_history_target_id ON history(target, id)")

        c.execute(f"CREATE TABLE IF NOT EXISTS verify_results ({_VERIFY_RESULTS_COLUMNS_SQL})")
        # verify_results is never dropped on rebuild, so CREATE IF NOT EXISTS
        # leaves a pre-CHECK table alone.  Recreate in place (preserving rows,
        # clamping outliers) when the stored DDL lacks the range guards.
        vr_sql_row = c.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'verify_results'"
        ).fetchone()
        vr_sql = vr_sql_row[0] if vr_sql_row else ""
        if vr_sql and (
            "effective_match IN (0, 1)" not in vr_sql or "verified_at != ''" not in vr_sql
        ):
            c.execute("ALTER TABLE verify_results RENAME TO _verify_results_migrate")
            c.execute(f"CREATE TABLE verify_results ({_VERIFY_RESULTS_COLUMNS_SQL})")
            c.execute(
                """
                INSERT INTO verify_results (
                    target, va, verified_at, byte_delta, diff_lines,
                    similarity, reg_delta, effective_match
                )
                SELECT
                    target,
                    CASE WHEN va < 0 THEN 0 ELSE va END,
                    CASE
                        WHEN verified_at IS NULL OR verified_at = ''
                            THEN '1970-01-01T00:00:00+00:00'
                        ELSE verified_at
                    END,
                    CASE
                        WHEN byte_delta IS NOT NULL AND typeof(byte_delta) = 'integer'
                             AND byte_delta < 0 THEN 0
                        WHEN typeof(byte_delta) IN ('integer', 'real', 'null')
                            THEN byte_delta
                        ELSE NULL
                    END,
                    CASE
                        WHEN diff_lines IS NOT NULL AND typeof(diff_lines) = 'integer'
                             AND diff_lines < 0 THEN 0
                        WHEN typeof(diff_lines) IN ('integer', 'real', 'null')
                            THEN diff_lines
                        ELSE NULL
                    END,
                    CASE
                        WHEN similarity IS NULL THEN NULL
                        WHEN typeof(similarity) NOT IN ('integer', 'real') THEN NULL
                        -- Keep finite in-range unit-interval values.  ``x = x``
                        -- rejects NaN; percents from verify (``(1, 100]``) are
                        -- scaled down — a plain ``> 1 → 1.0`` clamp used to
                        -- store every real Sim% as a perfect match.
                        WHEN similarity = similarity
                             AND similarity >= 0.0 AND similarity <= 1.0
                            THEN similarity
                        WHEN similarity = similarity
                             AND similarity > 1.0 AND similarity <= 100.0
                            THEN similarity / 100.0
                        WHEN similarity = similarity
                             AND similarity < 0.0 AND abs(similarity) < 1e300
                            THEN 0.0
                        ELSE NULL
                    END,
                    CASE
                        WHEN reg_delta IS NOT NULL AND typeof(reg_delta) = 'integer'
                             AND reg_delta < 0 THEN 0
                        WHEN typeof(reg_delta) IN ('integer', 'real', 'null')
                            THEN reg_delta
                        ELSE NULL
                    END,
                    CASE
                        WHEN effective_match IS NULL THEN NULL
                        WHEN typeof(effective_match) != 'integer' THEN NULL
                        WHEN effective_match IN (0, 1) THEN effective_match
                        ELSE NULL
                    END
                FROM _verify_results_migrate
                """
            )
            c.execute("DROP TABLE _verify_results_migrate")

        # Per-section aggregate stats (used by both UIs).  Explicit CREATE with
        # PRIMARY KEY (target, section_name) — CREATE TABLE AS SELECT left the
        # table without a key, so duplicate rows were possible and
        # ``WHERE target = ?`` had no index.  Declared empty here and filled
        # from _SECTION_CELL_STATS_SELECT after the cells are inserted.
        c.execute(f"""
            CREATE TABLE {SECTION_CELL_STATS_TABLE} (
                target TEXT NOT NULL,
                section_name TEXT NOT NULL,
                total_cells INTEGER NOT NULL DEFAULT 0 CHECK (total_cells >= 0),
                exact_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_count >= 0),
                reloc_count INTEGER NOT NULL DEFAULT 0 CHECK (reloc_count >= 0),
                near_match_count INTEGER NOT NULL DEFAULT 0 CHECK (near_match_count >= 0),
                stub_count INTEGER NOT NULL DEFAULT 0 CHECK (stub_count >= 0),
                padding_count INTEGER NOT NULL DEFAULT 0 CHECK (padding_count >= 0),
                data_count INTEGER NOT NULL DEFAULT 0 CHECK (data_count >= 0),
                thunk_count INTEGER NOT NULL DEFAULT 0 CHECK (thunk_count >= 0),
                none_count INTEGER NOT NULL DEFAULT 0 CHECK (none_count >= 0),
                proven_count INTEGER NOT NULL DEFAULT 0 CHECK (proven_count >= 0),
                size_mismatch_count INTEGER NOT NULL DEFAULT 0 CHECK (size_mismatch_count >= 0),
                other_count INTEGER NOT NULL DEFAULT 0 CHECK (other_count >= 0),
                PRIMARY KEY (target, section_name),
                FOREIGN KEY (target, section_name)
                    REFERENCES sections(target, name)
                    ON DELETE CASCADE
            )
        """)

        # Scoped rebuild: delete only this target's rows (sections first so
        # the cells FK CASCADE clears cell rows too).  Runs after all tables
        # exist (a fresh DB may lack verify_results until created above).
        #
        # verify_results is NOT deleted here: it is a persistent history table
        # (DB_FORMAT.md: "never dropped on rebuild"), and the import below only
        # repopulates a target when the shared db/verify_results.json names it.
        # Deleting here wiped the target's history whenever another target had
        # verified last — the same reason the full-rebuild path does not drop it.
        if target:
            for table in ("sections", "functions", "globals", "metadata"):
                c.execute(f"DELETE FROM {table} WHERE target = ?", (target,))

        # Process data_*.json files, optionally filtered by target.
        # With --regen the dicts come straight from the catalog pipeline
        # (no intermediate files); otherwise they are read from disk.
        datasets: list[tuple[str, dict[str, Any]]] = []
        if regen:
            from rebrew.catalog.pipeline import build_catalog_data

            base_cfg = load_config(root_dir)
            regen_targets = [target] if target else (base_cfg.all_targets or [base_cfg.target_name])
            for tgt in regen_targets:
                try:
                    tgt_cfg = load_config(root_dir, target=tgt)
                except (FileNotFoundError, KeyError, ValueError, TypeError) as exc:
                    error_exit(f"Config error for target {tgt!r}: {exc}", json_mode=json_output)
                console.print(f"Processing {tgt}...")
                datasets.append((tgt, build_catalog_data(tgt_cfg)["data"]))
        else:
            json_files = list(db_path.parent.glob("data_*.json"))
            if target:
                json_files = [f for f in json_files if f.stem.removeprefix("data_") == target]
            if not json_files:
                error_exit(
                    f"No data_*.json files found in {db_path.parent}. "
                    "Run 'rebrew catalog --data-json' first.",
                    json_mode=json_output,
                    code=EXIT_ERROR,
                )
            inputs = _snapshot_inputs(root_dir)
            for json_path in json_files:
                target_name = json_path.stem.removeprefix("data_")
                console.print(f"Processing {target_name}...")
                newer = [p.name for p in inputs if p.stat().st_mtime > json_path.stat().st_mtime]
                if newer:
                    console.print(
                        f"[yellow]warning:[/yellow] {json_path.name} is older than "
                        f"{', '.join(newer)}; its statuses may be stale.  Rebuild with "
                        "--regen or rerun 'rebrew catalog --data-json'."
                    )

                with json_path.open(encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError as exc:
                        error_exit(
                            f"{json_path.name} is not valid JSON: {exc}. Regenerate it "
                            "with 'rebrew catalog --data-json'.",
                            json_mode=json_output,
                            code=EXIT_ERROR,
                        )
                    if not isinstance(data, dict):
                        error_exit(
                            f"{json_path.name} has unexpected shape (expected a JSON "
                            f"object, got {type(data).__name__}). Regenerate it with "
                            "'rebrew catalog --data-json'.",
                            json_mode=json_output,
                            code=EXIT_ERROR,
                        )
                datasets.append((target_name, data))

        for target_name, data in datasets:
            fn_rows = []
            bad_va = 0
            for va, fn in data.get("functions", {}).items():
                if not isinstance(fn, dict):
                    bad_va += 1
                    continue
                va_int = _parse_int(va)
                if va_int <= 0:
                    va_int = _parse_int(fn.get("vaStart"))
                if va_int <= 0:
                    bad_va += 1
                    continue

                va_start_text = str(fn.get("vaStart") or f"0x{va_int:08x}")
                # build_db CHECK constraints reject negative fileOffset/
                # textOffset/blockerDelta — a stray negative would abort the
                # entire rebuild, so clamp defensively.  size (CHECK >= 0),
                # similarity (CHECK 0..1), markerType (CHECK IN …) and status
                # (CHECK IN known + UNKNOWN) are clamped the same way.
                file_off = fn.get("fileOffset")
                text_off = fn.get("textOffset")
                blocker_delta = fn.get("blockerDelta")
                fn_size = fn.get("size")
                # bool is an int subclass; True would land as size=1 under the
                # CHECK (>= 0) path — treat bool like a non-int (NULL).
                if isinstance(fn_size, bool) or (
                    fn_size is not None and not isinstance(fn_size, int)
                ):
                    fn_size = None
                elif isinstance(fn_size, int) and fn_size < 0:
                    fn_size = 0
                if isinstance(file_off, bool) or (
                    file_off is not None and not isinstance(file_off, int)
                ):
                    file_off = None
                elif isinstance(file_off, int) and file_off < 0:
                    file_off = 0
                if isinstance(text_off, bool) or (
                    text_off is not None and not isinstance(text_off, int)
                ):
                    text_off = None
                elif isinstance(text_off, int) and text_off < 0:
                    text_off = 0
                if isinstance(blocker_delta, bool) or (
                    blocker_delta is not None and not isinstance(blocker_delta, int)
                ):
                    blocker_delta = None
                elif isinstance(blocker_delta, int) and blocker_delta < 0:
                    blocker_delta = 0
                fn_similarity = fn.get("similarity")
                fn_marker = str(fn.get("markerType") or "FUNCTION")
                if fn_marker not in VALID_MARKERS:
                    fn_marker = "FUNCTION"
                fn_status = canonical_status(str(fn.get("status") or "UNKNOWN"))
                if fn_status not in _FUNCTION_DB_STATUSES:
                    fn_status = "UNKNOWN"
                fn_similarity = _clamp_unit_interval(fn_similarity)
                fn_rows.append(
                    (
                        target_name,
                        va_int,
                        str(fn.get("name") or ""),
                        va_start_text,
                        fn_size,
                        file_off,
                        fn_status,
                        str(fn.get("module") or fn.get("origin") or ""),
                        fn.get("cflags"),
                        fn.get("symbol"),
                        fn_marker,
                        fn.get("ghidra_name"),
                        fn.get("list_name"),
                        int(bool(fn.get("is_thunk", False))),
                        int(bool(fn.get("is_export", False))),
                        fn.get("sha256"),
                        json.dumps(fn.get("files", [])),
                        json.dumps(fn.get("detected_by", [])),
                        json.dumps(fn.get("size_by_tool", {})),
                        text_off,
                        fn.get("blocker", ""),
                        blocker_delta,
                        fn.get("size_reason", ""),
                        fn_similarity,
                        str(fn.get("updated_by") or ""),
                        str(fn.get("updated_at") or ""),
                    )
                )

            if bad_va:
                console.print(
                    f"[yellow]warning:[/yellow] {target_name}: skipped {bad_va} "
                    "function row(s) with unparseable VA (no valid key or vaStart)"
                )

            c.executemany(
                "INSERT INTO functions "
                "(target, va, name, vaStart, size, fileOffset, status, module, cflags, "
                "symbol, markerType, ghidra_name, list_name, is_thunk, is_export, sha256, "
                "files, detected_by, size_by_tool, textOffset, blocker, blockerDelta, "
                "size_reason, similarity, updated_by, updated_at) "
                "VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                _dedupe_by_va(fn_rows, target_name=target_name, table="function"),
            )

            g_rows = []
            bad_global_va = 0
            globals_data: dict[str, Any] = data.get("globals", {})
            for va, g in globals_data.items():
                if not isinstance(g, dict):
                    bad_global_va += 1
                    continue
                # An unresolvable VA is SKIPPED: a va=0 row is a poison entry
                # the readers mis-group.
                va_int = _parse_int(va)
                if va_int <= 0:
                    va_int = _parse_int(g.get("va"))
                if va_int <= 0:
                    bad_global_va += 1
                    continue
                g_size = g.get("size")
                if isinstance(g_size, bool) or not isinstance(g_size, int):
                    # Non-int / bool sizes would abort on CHECK (size >= 0)
                    # or land as 1/0 via bool-as-int; fall back to pointer size.
                    g_size = 4
                elif g_size < 0:
                    g_size = 0
                g_status = str(g.get("status") or "").strip().upper()
                if g_status not in _GLOBAL_DB_STATUSES:
                    g_status = ""
                g_rows.append(
                    (
                        target_name,
                        va_int,
                        str(g.get("name") or ""),
                        str(g.get("decl") or ""),
                        json.dumps(g.get("files", [])),
                        str(g.get("module") or g.get("origin") or ""),
                        g_size,
                        g_status,
                    )
                )

            if bad_global_va:
                console.print(
                    f"[yellow]warning:[/yellow] {target_name}: skipped "
                    f"{bad_global_va} global row(s) with unparseable VA "
                    "(no valid key or va field)"
                )

            c.executemany(
                """
                INSERT INTO globals (target, va, name, decl, files, module, size, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                _dedupe_by_va(g_rows, target_name=target_name, table="global"),
            )

            # Pre-calculate stats for all sections
            summary_data = data.get("summary", {})

            for sec_name, sec in data.get("sections", {}).items():
                # Calculate stats for data sections
                if sec_name != ".text":
                    exact_count: int = 0
                    reloc_count: int = 0
                    near_match_count: int = 0
                    stub_count: int = 0
                    padding_count: int = 0
                    exact_bytes: int = 0
                    reloc_bytes: int = 0
                    near_match_bytes: int = 0
                    stub_bytes: int = 0
                    padding_bytes: int = 0
                    covered_bytes: int = 0
                    total_items: int = 0

                    for cell in sec.get("cells", []):
                        state = cell.get("state")
                        if state != "none":
                            start = max(0, _parse_int(cell.get("start"), 0))
                            end = max(start, _parse_int(cell.get("end"), start))
                            size = end - start
                            covered_bytes += size
                            funcs = cell.get("functions", [])
                            total_items += len(funcs) if funcs else 0

                            if state in ("exact", "verified"):
                                exact_count += 1
                                exact_bytes += size
                            elif state == "reloc":
                                reloc_count += 1
                                reloc_bytes += size
                            elif state in ("near_match", "near_matching"):
                                near_match_count += 1
                                near_match_bytes += size
                            elif state == "stub":
                                stub_count += 1
                                stub_bytes += size
                            elif state == "padding":
                                padding_count += 1
                                padding_bytes += size

                    summary_data[sec_name] = {
                        "exactMatches": exact_count,
                        "relocMatches": reloc_count,
                        "nearMatchCount": near_match_count,
                        "stubCount": stub_count,
                        "paddingCount": padding_count,
                        "exactBytes": exact_bytes,
                        "relocBytes": reloc_bytes,
                        "nearMatchBytes": near_match_bytes,
                        "stubBytes": stub_bytes,
                        "paddingBytes": padding_bytes,
                        "coveredBytes": covered_bytes,
                        "totalFunctions": total_items,
                        "size": sec.get("size", 0),
                    }

                # Clamp unitBytes/columns to sane positive defaults: the schema
                # CHECK (> 0) would abort the whole rebuild on a stray 0 from
                # hand-edited JSON (same pattern as the negative-offset clamps).
                ub_raw = sec.get("unitBytes", 64)
                col_raw = sec.get("columns", 64)
                unit_bytes = ub_raw if isinstance(ub_raw, int) and ub_raw > 0 else 64
                columns = col_raw if isinstance(col_raw, int) and col_raw > 0 else 64
                # va/size/fileOffset are CHECK (>= 0 OR NULL): clamp like the
                # function-row path so a stray negative does not abort rebuild.
                sec_va = _clamp_nonneg_int(sec.get("va"))
                sec_size = _clamp_nonneg_int(sec.get("size"))
                sec_file_off = _clamp_nonneg_int(sec.get("fileOffset"))

                c.execute(
                    """
                    INSERT INTO sections (target, name, va, size, fileOffset, unitBytes, columns)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        target_name,
                        sec_name,
                        sec_va,
                        sec_size,
                        sec_file_off,
                        unit_bytes,
                        columns,
                    ),
                )

                # Insert cells (dedupe by start so clamp/hand-edit collisions
                # cannot abort the rebuild on the UNIQUE constraint).
                cell_rows = _dedupe_cell_rows(
                    [
                        _normalize_cell_row(target_name, sec_name, cell)
                        for cell in sec.get("cells", [])
                        if isinstance(cell, dict)
                    ],
                    target_name=target_name,
                    sec_name=sec_name,
                )

                c.executemany(
                    """
                    INSERT INTO cells (target, section_name, start, end, span, state, functions, label, parent_function)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    cell_rows,
                )

            total, by_status, by_module, covered_bytes_func, matched_bytes = _function_stats(
                c, target_name
            )

            text_section_data = data.get("sections", {}).get(".text", {})
            total_bytes: int = text_section_data.get("size", 0)

            c.execute(
                """
                INSERT INTO metadata VALUES (?, 'function_stats', ?)
            """.strip(),
                (
                    target_name,
                    json.dumps(
                        {
                            "total": total,
                            # "covered_bytes" = identified bytes (every
                            # function, incl. STUB placeholders).
                            "covered_bytes": covered_bytes_func,
                            # "matched_bytes" = EXACT/RELOC only — the
                            # dashboard's headline coverage metric.
                            "matched_bytes": matched_bytes,
                            "total_bytes": total_bytes,
                            "by_status": by_status,
                            "by_module_counts": {
                                mod: len(f_list) for mod, f_list in by_module.items()
                            },
                        }
                    ),
                ),
            )

            c.execute(
                "INSERT INTO metadata VALUES (?, ?, ?)",
                (target_name, "summary", json.dumps(summary_data)),
            )

            # Store paths (from JSON data produced by grid.py)
            paths_data = data.get("paths", {})
            c.execute(
                "INSERT INTO metadata VALUES (?, ?, ?)",
                (target_name, "paths", json.dumps(paths_data)),
            )

            # Populate history: record any status changes since last build
            now_iso = datetime.now(UTC).isoformat()
            c.execute(
                "SELECT va, status, updated_by FROM functions WHERE target = ?",
                (target_name,),
            )
            history_rows = []
            for row in c.fetchall():
                new_va, new_status, updated_by = row
                key = (target_name, new_va)
                old_status = old_statuses.get(key)
                if old_status is not None and old_status != new_status:
                    # Clamp/coerce so a pre-CHECK snapshot or negative VA
                    # cannot abort the rebuild on the history CHECKs.
                    old_s = canonical_status(str(old_status or "UNKNOWN"))
                    if old_s not in _FUNCTION_DB_STATUSES:
                        old_s = "UNKNOWN"
                    new_s = canonical_status(str(new_status or "UNKNOWN"))
                    if new_s not in _FUNCTION_DB_STATUSES:
                        new_s = "UNKNOWN"
                    history_rows.append(
                        (
                            target_name,
                            max(0, _parse_int(new_va, 0)),
                            old_s,
                            new_s,
                            now_iso,
                            updated_by or "",
                        )
                    )
            if history_rows:
                c.executemany(
                    "INSERT INTO history (target, va, old_status, new_status, changed_at, updated_by) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    history_rows,
                )
            # Retention: keep only the newest _HISTORY_RETENTION rows of this
            # target (only this target gained rows).  Both scans are served
            # by idx_history_target_id.
            c.execute(
                "DELETE FROM history WHERE target = ? AND id NOT IN ("
                "  SELECT id FROM history WHERE target = ? ORDER BY id DESC LIMIT ?"
                ")",
                (target_name, target_name, _HISTORY_RETENTION),
            )

            # Import the verify cache's per-function rows so the
            # verify_results table carries real per-function data instead of
            # staying empty.  The cache rows ARE the report rows (same shape),
            # and they carry identity guards the old db/verify_results.json
            # snapshot lacked.  Best-effort: a missing cache is fine.
            from rebrew.verify_cache import load_verify_cache_raw

            vr_rows = []
            vr_time = now_iso
            raw_cache = load_verify_cache_raw(SimpleNamespace(root=root_dir))
            cache_entries: dict[str, Any] | None = None
            ours = isinstance(raw_cache, dict) and raw_cache.get("target") == target_name
            if ours and isinstance(raw_cache, dict):
                maybe_entries = raw_cache.get("entries")
                if isinstance(maybe_entries, dict):
                    cache_entries = maybe_entries
            if cache_entries:
                with contextlib.suppress(OSError):
                    vr_time = str(
                        datetime.fromtimestamp(
                            (root_dir / ".rebrew" / "verify_cache.json").stat().st_mtime,
                            tz=UTC,
                        ).isoformat()
                    )
                for va_key, item in cache_entries.items():
                    if not isinstance(item, dict):
                        continue
                    try:
                        va_int = int(str(item.get("va", va_key)), 0)
                    except (ValueError, TypeError):
                        continue
                    vr_rows.append(
                        (
                            target_name,
                            max(0, va_int),
                            vr_time,
                            _clamp_nonneg_int(item.get("delta")),
                            _clamp_nonneg_int(item.get("diff_lines")),
                            _clamp_verify_similarity(item.get("similarity")),
                            _clamp_nonneg_int(item.get("reg_delta")),
                            _clamp_effective_match(item.get("effective_match")),
                        )
                    )
            if vr_rows:
                c.executemany(
                    "INSERT OR REPLACE INTO verify_results "
                    "(target, va, verified_at, byte_delta, diff_lines, "
                    "similarity, reg_delta, effective_match) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    vr_rows,
                )
                # Prune rows for functions absent from the latest cache
                # (it is best-effort and can legitimately shrink).
                # Guard on the PARSED vr_rows, not the raw entries:
                # zero parseable VAs prunes nothing; only rows with
                # parseable VAs prune their stale siblings.
                # VAs travel as one JSON parameter: a placeholder per VA
                # overflows SQLITE_MAX_VARIABLE_NUMBER on large targets.
                c.execute(
                    "DELETE FROM verify_results WHERE target = ? AND va NOT IN ("
                    "SELECT value FROM json_each(?))",
                    (target_name, json.dumps([r[1] for r in vr_rows])),
                )
            elif cache_entries == {}:
                # The cache names this target but holds no rows — the target
                # was fully unverified, so its stale rows go.  (A missing or
                # other-target cache leaves rows alone — the table is never
                # dropped on rebuild.)
                c.execute("DELETE FROM verify_results WHERE target = ?", (target_name,))
            # Otherwise (no cache, or another target's): leave rows alone —
            # the table is never dropped on rebuild.

            # Schema version stamp: written under a reserved __schema__ row so
            # readers never depend on an arbitrary target's stamp (a scoped
            # --target rebuild leaves other targets at their older version).
            c.execute(
                "INSERT OR REPLACE INTO metadata VALUES (?, ?, ?)",
                (SCHEMA_TARGET, "db_version", json.dumps(_CURRENT_DB_VERSION)),
            )
            # Keep the legacy per-target stamp for older dashboard versions.
            c.execute(
                "INSERT OR REPLACE INTO metadata VALUES (?, ?, ?)",
                (target_name, "db_version", json.dumps(_CURRENT_DB_VERSION)),
            )

        # Materialize the per-section cell JSON every dashboard grid serves.
        # Rebuilt WHOLE (not per rebuilt target) from `cells` on every run, so
        # the table is complete for every target after any build — including a
        # scoped --target rebuild of an older DB that lacked the table, which
        # would otherwise leave sibling targets with no cached row and force
        # readers into a per-target "is it materialized?" guess.
        c.executemany(
            f"INSERT INTO {SECTION_CELLS_TABLE} (target, section_name, {SECTION_CELLS_COLUMN}) "
            "VALUES (?, ?, ?)",
            [
                (tgt, sec, encode_section_cells(cells_json))
                for tgt, sec, cells_json in c.execute(
                    f"SELECT target, section_name, {SECTION_CELLS_AGG_SQL} "
                    "FROM cells GROUP BY target, section_name"
                ).fetchall()
            ],
        )

        # Per-section bucket counts, from the single definition above.  Filled
        # whole (like the cell JSON) so a scoped --target rebuild also leaves
        # sibling targets with correct rows.
        c.execute(f"INSERT INTO {SECTION_CELL_STATS_TABLE} {_SECTION_CELL_STATS_SELECT}")

        c.execute("COMMIT")

        if json_output:
            json_print(
                {
                    "db_path": str(db_path),
                    "targets_processed": [name for name, _ in datasets],
                }
            )
        else:
            console.print(f"[green]Database built successfully at {db_path}[/green]")
    except BaseException:
        if conn is not None:
            with contextlib.suppress(sqlite3.Error):
                conn.rollback()
        raise
    finally:
        if conn is not None:
            conn.close()


app = typer.Typer(
    help="Build SQLite coverage database from catalog JSON.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew build-db · · · · · · · · · · · Build db/coverage.db (reads db/data_*.json)\n\n"
        "  rebrew build-db --regen · · · · · · · Generate coverage in-process, no JSON files\n\n"
        "  rebrew build-db --root /path/to/project  Specify project root explicitly\n\n"
        "[bold]Prerequisites:[/bold]\n\n"
        "  Run 'rebrew catalog --data-json' first to generate db/data_*.json files.\n\n"
        "[bold]What it creates:[/bold]\n\n"
        "  db/coverage.db · · · · · · SQLite database with functions, globals, sections, cells\n\n"
        "[dim]The database is used by recoverage (coverage dashboard) and can be queried "
        "directly for reports. Schema version is stamped in the metadata table.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Project root directory",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Delete and recreate the database if its schema version is incompatible.",
    ),
    regen: bool = typer.Option(
        False,
        "--regen",
        help="Generate coverage data in-process per target instead of reading "
        "db/data_*.json files (no intermediate files)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """CLI entry point for rebrew build-db."""
    build_db(root, target=target, json_output=json_output, force=force, regen=regen)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
