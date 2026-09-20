"""build_db.py – Build SQLite coverage database from function catalog.

Aggregates annotation data, verification results, and coverage statistics
into a single SQLite database for querying and reporting.
"""

import contextlib
import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import (
    EXIT_ERROR,
    TargetOption,
    error_exit,
    json_print,
)
from rebrew.config import load_config
from rebrew.data_metadata import (
    DATA_STATUS_DRIFT,
    DATA_STATUS_UNCHECKED,
    DATA_STATUS_VERIFIED,
)
from rebrew.metadata import KNOWN_STATUSES, MATCHED_STATUSES, canonical_status
from rebrew.workspace import (
    CELLS_JSON_OBJECT_SQL,
    SCHEMA_TARGET,
    SECTION_CELLS_COLUMN,
    SECTION_CELLS_TABLE,
    db_dir,
    encode_section_cells,
    sqlite_ro_uri,
)

console = Console(stderr=True)


_CURRENT_DB_VERSION = "10"

#: Statuses allowed in ``functions.status``.  ``KNOWN_STATUSES`` plus
#: ``UNKNOWN`` (the DEFAULT when a catalog row omits STATUS).  Kept in one
#: place so the CREATE TABLE CHECK and the insert-time sanitizer cannot drift.
_FUNCTION_DB_STATUSES: frozenset[str] = frozenset({*KNOWN_STATUSES, "UNKNOWN"})
_FUNCTION_STATUS_CHECK_SQL: str = ", ".join(repr(s) for s in sorted(_FUNCTION_DB_STATUSES))

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
# This is a build-time TABLE, not the view it used to be.  As a view, every
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
        -- (db-review F4).  `verified` is excluded here because it is
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
#: pages of history while bounding unbounded growth (db-review F7).
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
    """Return a non-negative int, or ``None`` when *value* is absent/unusable."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        if value != value:  # NaN
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
    """Return a float in ``[0.0, 1.0]``, or ``None`` when *value* is absent/unusable."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        if isinstance(value, float) and value != value:  # NaN
            return None
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return max(0.0, min(1.0, float(s)))
        except ValueError:
            return None
    return None


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
#: with the annotation vocabulary — a hand-maintained subset previously
#: dropped EXTRACT_ERROR/INVALID_VA into ``unknown``.  Gap/label states and
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


def _normalize_cell_row(
    target_name: str, sec_name: str, cell: dict[str, Any]
) -> tuple[str, str, int, int, int, str, str, str | None, str | None]:
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


def _function_stats(
    c: sqlite3.Cursor, target_name: str
) -> tuple[int, dict[str, int], dict[str, list[Any]], int, int]:
    """Return (total, by_status, by_module, covered_bytes, matched_bytes).

    ``covered_bytes`` = sum of EVERY function's size regardless of status
    ("identified bytes" — a STUB placeholder counts fully).  ``matched_bytes``
    = sum of EXACT/RELOC/PROVEN sizes only (db-review F1: the dashboard
    headline used covered_bytes, so an all-STUB binary reported ~100%
    "coverage").  The headline metric is matched bytes; identified bytes is
    the separate "fully documented" figure.
    """
    c.execute(
        "SELECT va, name, size, status, module, symbol, markerType, files "
        "FROM functions WHERE target = ? AND markerType NOT IN ('GLOBAL', 'DATA') ORDER BY va",
        (target_name,),
    )
    total: int = 0
    by_status: dict[str, int] = {}
    by_module: dict[str, list[Any]] = {}
    covered_bytes: int = 0
    matched_bytes: int = 0
    for fn in c.fetchall():
        total += 1
        st = fn[3] or "UNKNOWN"
        by_status[st] = by_status.get(st, 0) + 1
        mod = fn[4] or "GAME"
        by_module.setdefault(mod, []).append(fn)
        size = fn[2]
        # Function statuses are EXACT/RELOC/STUB/... — never "none" (a cell
        # state); the old `st != "none"` guard was always true and misleading.
        covered_bytes += size if size is not None else 0
        if st in MATCHED_STATUSES:
            matched_bytes += size if size is not None else 0
    return total, by_status, by_module, covered_bytes, matched_bytes


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


def _check_db_version(db_path: Path, *, force: bool = False, json_output: bool = False) -> None:
    """Raise SystemExit (via error_exit) if DB exists with an incompatible schema version.

    On mismatch without ``--force``: emit a clear error.
    With ``--force``: delete the DB file so it is recreated from scratch.
    """
    if not db_path.exists():
        return
    try:
        with contextlib.closing(
            sqlite3.connect(sqlite_ro_uri(db_path), uri=True, timeout=_SQLITE_TIMEOUT_SECONDS)
        ) as conn:
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
        db_path.unlink()
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
        db_path.unlink()


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
    with contextlib.closing(
        sqlite3.connect(sqlite_ro_uri(db_path), uri=True, timeout=_SQLITE_TIMEOUT_SECONDS)
    ) as conn:
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

    _check_db_version(db_path, force=force, json_output=json_output)

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(db_path, timeout=_SQLITE_TIMEOUT_SECONDS)
        c: sqlite3.Cursor = conn.cursor()
        # WAL + relaxed sync trade durability for throughput on a rebuildable
        # cache DB; foreign_keys=ON enforces the cells→sections cascade.
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
        # Full rebuild (no --target): recreate the whole schema.
        # Scoped rebuild (--target): keep the schema and other targets'
        # rows; only this target's rows are deleted below.
        if not target:
            c.execute("DROP TABLE IF EXISTS cells")
            c.execute("DROP TABLE IF EXISTS functions")
            c.execute("DROP TABLE IF EXISTS globals")
            c.execute("DROP TABLE IF EXISTS sections")
            c.execute("DROP TABLE IF EXISTS metadata")
            # Derived from cells; repopulated whole at the end of this function.
            c.execute(f"DROP TABLE IF EXISTS {SECTION_CELLS_TABLE}")
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
                    CHECK (markerType IN ('FUNCTION', 'LIBRARY', 'STUB', 'GLOBAL', 'DATA')),
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

        # Per-section cell JSON, pre-aggregated and zlib-compressed.  Serving a
        # dashboard grid otherwise re-runs json_group_array over every cell on
        # each cold request: measured 10.7 ms of SQLite per 39k-cell section
        # versus 0.3 ms to read this row, for 188 KB stored across the whole
        # table.  WITHOUT ROWID because it is accessed only by its primary key,
        # so the implicit rowid (and its index) would be dead weight.
        #
        # It is a derived cache: `cells` remains the source of truth and is the
        # only thing other queries read, so a reader without this table still
        # works (see rebrew.workspace.CELLS_JSON_OBJECT_SQL).
        c.execute(f"""
            CREATE TABLE IF NOT EXISTS {SECTION_CELLS_TABLE} (
                target TEXT NOT NULL,
                section_name TEXT NOT NULL,
                {SECTION_CELLS_COLUMN} BLOB NOT NULL,
                PRIMARY KEY (target, section_name)
            ) WITHOUT ROWID
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(target, name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_status ON functions(target, status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_module ON functions(target, module)")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_functions_marker ON functions(target, markerType)"
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_globals_name ON globals(target, name)")
        # idx_cells_section is deliberately NOT created: the
        # UNIQUE (target, section_name, start) constraint already serves the
        # same leftmost prefix (target, section_name) for the view's
        # GROUP BY and any WHERE target=? AND section_name=? query — a second
        # index would be paid for on every cell insert and never be the only
        # usable one (db-review F6).  Drop any pre-existing copy from older
        # builds explicitly or it survives every rebuild.
        c.execute("DROP INDEX IF EXISTS idx_cells_section")

        c.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                va INTEGER NOT NULL,
                old_status TEXT,
                new_status TEXT,
                changed_at TEXT NOT NULL,
                updated_by TEXT NOT NULL DEFAULT ''
            )
        """)
        # history rows are appended on every rebuild; the dashboard pages them
        # with WHERE target = ? ORDER BY id DESC LIMIT ?, so (target, id) is
        # the serving index (a plain (target, va) index would not serve the
        # ORDER BY id).  Growth is bounded by a per-target retention cap —
        # only the newest _HISTORY_RETENTION rows per target are kept, so a
        # long-lived project that regenerates often does not accumulate rows
        # forever (db-review F7).
        c.execute("CREATE INDEX IF NOT EXISTS idx_history_target_id ON history(target, id)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS verify_results (
                target TEXT NOT NULL,
                va INTEGER NOT NULL CHECK (va >= 0),
                verified_at TEXT NOT NULL,
                byte_delta INTEGER CHECK (byte_delta IS NULL OR byte_delta >= 0),
                diff_lines INTEGER CHECK (diff_lines IS NULL OR diff_lines >= 0),
                similarity REAL CHECK (similarity IS NULL OR (similarity >= 0.0 AND similarity <= 1.0)),
                reg_delta INTEGER CHECK (reg_delta IS NULL OR reg_delta >= 0),
                effective_match INTEGER CHECK (effective_match IS NULL OR effective_match IN (0, 1)),
                PRIMARY KEY (target, va)
            )
        """)
        # verify_results is never dropped on rebuild, so CREATE IF NOT EXISTS
        # leaves a pre-CHECK table alone.  Recreate in place (preserving rows,
        # clamping outliers) when the stored DDL lacks the range guards.
        vr_sql_row = c.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'verify_results'"
        ).fetchone()
        vr_sql = vr_sql_row[0] if vr_sql_row else ""
        if vr_sql and "effective_match IN (0, 1)" not in vr_sql:
            c.execute("ALTER TABLE verify_results RENAME TO _verify_results_migrate")
            c.execute("""
                CREATE TABLE verify_results (
                    target TEXT NOT NULL,
                    va INTEGER NOT NULL CHECK (va >= 0),
                    verified_at TEXT NOT NULL,
                    byte_delta INTEGER CHECK (byte_delta IS NULL OR byte_delta >= 0),
                    diff_lines INTEGER CHECK (diff_lines IS NULL OR diff_lines >= 0),
                    similarity REAL CHECK (
                        similarity IS NULL OR (similarity >= 0.0 AND similarity <= 1.0)
                    ),
                    reg_delta INTEGER CHECK (reg_delta IS NULL OR reg_delta >= 0),
                    effective_match INTEGER CHECK (
                        effective_match IS NULL OR effective_match IN (0, 1)
                    ),
                    PRIMARY KEY (target, va)
                )
            """)
            c.execute(
                """
                INSERT INTO verify_results (
                    target, va, verified_at, byte_delta, diff_lines,
                    similarity, reg_delta, effective_match
                )
                SELECT
                    target,
                    CASE WHEN va < 0 THEN 0 ELSE va END,
                    verified_at,
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
                        WHEN similarity < 0.0 THEN 0.0
                        WHEN similarity > 1.0 THEN 1.0
                        ELSE similarity
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
                total_cells INTEGER NOT NULL DEFAULT 0,
                exact_count INTEGER,
                reloc_count INTEGER,
                near_match_count INTEGER,
                stub_count INTEGER,
                padding_count INTEGER,
                data_count INTEGER,
                thunk_count INTEGER,
                none_count INTEGER,
                proven_count INTEGER,
                size_mismatch_count INTEGER,
                other_count INTEGER,
                PRIMARY KEY (target, section_name)
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
            from rebrew.catalog.cli import build_catalog_data

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
            json_files = list(db_dir.glob("data_*.json"))
            if target:
                json_files = [f for f in json_files if f.stem.removeprefix("data_") == target]
            if not json_files:
                error_exit(
                    f"No data_*.json files found in {db_dir}. Run 'rebrew catalog --json' first.",
                    json_mode=json_output,
                    code=EXIT_ERROR,
                )
            for json_path in json_files:
                target_name = json_path.stem.removeprefix("data_")
                console.print(f"Processing {target_name}...")

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
                va_int = 0
                if isinstance(va, str):
                    try:
                        va_int = int(va, 0)
                    except ValueError:
                        va_int = 0
                elif isinstance(va, int) and not isinstance(va, bool):
                    va_int = va

                if va_int == 0:
                    va_start = fn.get("vaStart") if isinstance(fn, dict) else None
                    if isinstance(va_start, str):
                        try:
                            va_int = int(va_start, 0)
                        except ValueError:
                            va_int = 0
                    elif isinstance(va_start, int) and not isinstance(va_start, bool):
                        va_int = va_start

                if va_int <= 0 or not isinstance(fn, dict):
                    bad_va += 1
                    continue

                va_start_text = str(fn.get("vaStart") or (f"0x{va_int:08x}" if va_int else ""))
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
                if fn_marker not in ("FUNCTION", "LIBRARY", "STUB", "GLOBAL", "DATA"):
                    fn_marker = "FUNCTION"
                fn_status = canonical_status(str(fn.get("status") or "UNKNOWN"))
                if fn_status not in _FUNCTION_DB_STATUSES:
                    fn_status = "UNKNOWN"
                if isinstance(fn_similarity, (int, float)) and not isinstance(fn_similarity, bool):
                    fn_similarity = max(0.0, min(1.0, float(fn_similarity)))
                else:
                    fn_similarity = None
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
                fn_rows,
            )

            g_rows = []
            bad_global_va = 0
            globals_data: dict[str, Any] = data.get("globals", {})
            for va, g in globals_data.items():
                if not isinstance(g, dict):
                    bad_global_va += 1
                    continue
                # ``int(va, 16)`` treated an int key/``va`` field as a base-16
                # string (TypeError) and a decimal string as hex.  Base 0 parses
                # both int and "0x…"/decimal string, and an unresolvable VA is
                # SKIPPED (a va=0 row is a poison entry the readers mis-group),
                # mirroring the functions path.
                va_int = 0
                if isinstance(va, int) and not isinstance(va, bool):
                    va_int = va
                elif isinstance(va, str):
                    try:
                        va_int = int(va, 0)
                    except ValueError:
                        va_int = 0
                if va_int <= 0:
                    raw_va = g.get("va")
                    if isinstance(raw_va, int) and not isinstance(raw_va, bool):
                        va_int = raw_va
                    elif isinstance(raw_va, str):
                        try:
                            va_int = int(raw_va, 0)
                        except ValueError:
                            va_int = 0
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
                g_rows,
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

                # Insert cells
                cell_rows = [
                    _normalize_cell_row(target_name, sec_name, cell)
                    for cell in sec.get("cells", [])
                    if isinstance(cell, dict)
                ]

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
                            # "matched_bytes" = EXACT/RELOC/PROVEN only — the
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
                    history_rows.append(
                        (target_name, new_va, old_status, new_status, now_iso, updated_by or "")
                    )
            if history_rows:
                c.executemany(
                    "INSERT INTO history (target, va, old_status, new_status, changed_at, updated_by) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    history_rows,
                )
            # Retention: keep only the newest _HISTORY_RETENTION rows per
            # target.  ROW_NUMBER over (target, id DESC) keeps the newest N;
            # older rows are deleted so the table does not grow unboundedly
            # across rebuilds (db-review F7).
            c.execute(
                "DELETE FROM history WHERE id NOT IN ("
                "  SELECT id FROM ("
                "    SELECT id, ROW_NUMBER() OVER ("
                "      PARTITION BY target ORDER BY id DESC"
                "    ) AS rn FROM history"
                "  ) WHERE rn <= ?"
                ")",
                (_HISTORY_RETENTION,),
            )

            # Import the verify cache's per-function rows so the
            # verify_results table carries real per-function data instead of
            # staying empty.  The cache rows ARE the report rows (same shape),
            # and they carry identity guards the old db/verify_results.json
            # snapshot lacked.  Best-effort: a missing cache is fine.
            from rebrew.cli import load_verify_cache_raw

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
                            _clamp_unit_interval(item.get("similarity")),
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
                c.execute(
                    "DELETE FROM verify_results WHERE target = ? AND va NOT IN ("
                    + ",".join("?" * len(vr_rows))
                    + ")",
                    (target_name, *(r[1] for r in vr_rows)),
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
            # --target rebuild previously left older targets at an older
            # version while the unfiltered reader picked an arbitrary row).
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
        #
        # The DELETE prunes sections/targets that no longer exist; without it a
        # removed section would keep serving its stale cells.
        c.execute(f"DELETE FROM {SECTION_CELLS_TABLE}")
        c.executemany(
            f"INSERT INTO {SECTION_CELLS_TABLE} (target, section_name, {SECTION_CELLS_COLUMN}) "
            "VALUES (?, ?, ?)",
            [
                (tgt, sec, encode_section_cells(cells_json))
                for tgt, sec, cells_json in c.execute(
                    f"SELECT target, section_name, json_group_array({CELLS_JSON_OBJECT_SQL}) "
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
        "  Run 'rebrew catalog --json' first to generate db/data_*.json files.\n\n"
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
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    regen: bool = typer.Option(
        False,
        "--regen",
        help="Generate coverage data in-process per target instead of reading "
        "db/data_*.json files (no intermediate files)",
    ),
) -> None:
    """CLI entry point for rebrew build-db."""
    build_db(root, target=target, json_output=json_output, force=force, regen=regen)


def main_entry() -> None:
    """Run the Typer CLI application (standalone single-command form)."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
