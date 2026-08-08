"""build_db.py – Build SQLite coverage database from function catalog.

Aggregates annotation data, verification results, and coverage statistics
into a single SQLite database for querying and reporting.
"""

import contextlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print
from rebrew.config import load_config

console = Console(stderr=True)


_CURRENT_DB_VERSION = "4"
_SQLITE_TIMEOUT_SECONDS = 30.0


def _parse_int(value: Any, default: int = 0) -> int:
    """Parse an integer from JSON-ish input, returning *default* on invalid values."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


def _normalize_cell_row(
    target_name: str, sec_name: str, cell: dict[str, Any]
) -> tuple[str, str, int, int, int, str, str, str | None, str | None]:
    """Return a DB-safe cell row from generated coverage JSON."""
    start = max(0, _parse_int(cell.get("start"), 0))
    end = max(start, _parse_int(cell.get("end"), start))
    span = max(1, _parse_int(cell.get("span"), 1))
    state = str(cell.get("state") or "none")
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
) -> tuple[int, dict[str, int], dict[str, list[Any]], int]:
    """Return (total, by_status, by_module, covered_bytes) for a target's functions."""
    c.execute(
        "SELECT va, name, size, status, module, symbol, markerType, files "
        "FROM functions WHERE target = ? AND markerType NOT IN ('GLOBAL', 'DATA') ORDER BY va",
        (target_name,),
    )
    total: int = 0
    by_status: dict[str, int] = {}
    by_module: dict[str, list[Any]] = {}
    covered_bytes: int = 0
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
    return total, by_status, by_module, covered_bytes


def _resolve_db_dir(root_dir: Path, *, json_output: bool = False) -> Path:
    """Return the configured database directory, falling back when no config exists."""
    if not (root_dir / "rebrew-project.toml").exists():
        return root_dir / "db"
    try:
        return load_config(root_dir).db_dir
    except (FileNotFoundError, KeyError, ValueError, TypeError) as exc:
        error_exit(f"Config error: {exc}", json_mode=json_output)


def _check_db_version(db_path: Path, *, force: bool = False, json_output: bool = False) -> None:
    """Raise SystemExit (via error_exit) if DB exists with an incompatible schema version.

    On mismatch without ``--force``: emit a clear error.
    With ``--force``: delete the DB file so it is recreated from scratch.
    """
    if not db_path.exists():
        return
    try:
        with contextlib.closing(sqlite3.connect(db_path, timeout=_SQLITE_TIMEOUT_SECONDS)) as conn:
            c = conn.cursor()
            c.execute("SELECT value FROM metadata WHERE key = 'db_version' LIMIT 1")
            row = c.fetchone()
        if row is None:
            stored_version = "<unknown>"
        else:
            try:
                stored_version = json.loads(row[0])
            except (json.JSONDecodeError, TypeError):
                stored_version = str(row[0])
    except sqlite3.OperationalError:
        # Metadata table missing — treat as incompatible
        stored_version = "<missing>"

    if stored_version == _CURRENT_DB_VERSION:
        # The version string alone is not proof of shape: a DB stamped "4" can
        # be missing required objects (history table, section_cell_stats view)
        # and pass the gate, then 500 at query time.  Verify the objects the
        # version promises exist.
        missing = _missing_required_objects(db_path)
        if missing:
            stored_version = f"{stored_version!r} (missing: {', '.join(sorted(missing))})"

    if stored_version != _CURRENT_DB_VERSION:
        if not force:
            error_exit(
                f"Database at '{db_path}' has schema version {stored_version!r} "
                f"but this tool requires version {_CURRENT_DB_VERSION!r}.\n"
                "The existing DB is incompatible. Pass --force to delete it and rebuild.",
                json_mode=json_output,
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
    the right stamp and still miss tables/views."""
    required = {
        "metadata",
        "sections",
        "cells",
        "functions",
        "globals",
        "verify_results",
        "history",
        "section_cell_stats",  # view
    }
    try:
        with contextlib.closing(sqlite3.connect(db_path, timeout=_SQLITE_TIMEOUT_SECONDS)) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT type, name FROM sqlite_master"
                " WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
            )
            present = {row[1] for row in c.fetchall()}
    except sqlite3.Error:
        return set(required)
    return required - present


def build_db(
    project_root: Path | None = None,
    target: str | None = None,
    json_output: bool = False,
    force: bool = False,
) -> None:
    """Aggregate ``data_*.json`` files into the configured coverage database."""
    root_dir = Path(project_root).resolve() if project_root else Path.cwd().resolve()
    db_dir = _resolve_db_dir(root_dir, json_output=json_output)
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

        # Snapshot existing function statuses for history tracking
        old_statuses: dict[tuple[str, int], str] = {}
        with contextlib.suppress(sqlite3.OperationalError):
            c.execute("SELECT target, va, status FROM functions")
            for row in c.fetchall():
                old_statuses[(row[0], row[1])] = row[2]

        # Warn when --target rebuilds a DB that currently contains other
        # targets: the DROP below removes them and this run only inserts the
        # filtered target's data, silently losing the rest until a full rebuild.
        if target:
            with contextlib.suppress(sqlite3.OperationalError):
                c.execute("SELECT DISTINCT target FROM functions")
                existing_targets = {row[0] for row in c.fetchall()} - {target}
                if existing_targets:
                    console.print(
                        "[yellow]warning:[/yellow] rebuilding with --target will remove "
                        f"{len(existing_targets)} other target(s) from the DB: "
                        f"{', '.join(sorted(existing_targets))}"
                    )

        # Start an exclusive transaction
        c.execute("BEGIN IMMEDIATE")

        c.execute("DROP VIEW IF EXISTS section_cell_stats")
        c.execute("DROP TABLE IF EXISTS cells")
        c.execute("DROP TABLE IF EXISTS functions")
        c.execute("""
            CREATE TABLE functions (
                target TEXT NOT NULL,
                va INTEGER NOT NULL CHECK (va >= 0),
                name TEXT NOT NULL DEFAULT '',
                vaStart TEXT NOT NULL DEFAULT '',
                size INTEGER CHECK (size IS NULL OR size >= 0),
                fileOffset INTEGER CHECK (fileOffset IS NULL OR fileOffset >= 0),
                status TEXT NOT NULL DEFAULT 'UNKNOWN',
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
                size_by_tool TEXT NOT NULL DEFAULT '{}',
                textOffset INTEGER CHECK (textOffset IS NULL OR textOffset >= 0),
                blocker TEXT,
                blockerDelta INTEGER CHECK (blockerDelta IS NULL OR blockerDelta >= 0),
                size_reason TEXT,
                similarity REAL CHECK (similarity IS NULL OR (similarity >= 0.0 AND similarity <= 1.0)),
                PRIMARY KEY (target, va)
            )
        """)

        c.execute("DROP TABLE IF EXISTS globals")
        c.execute("""
            CREATE TABLE globals (
                target TEXT NOT NULL,
                va INTEGER NOT NULL CHECK (va >= 0),
                name TEXT NOT NULL DEFAULT '',
                decl TEXT NOT NULL DEFAULT '',
                files TEXT NOT NULL DEFAULT '[]',
                module TEXT NOT NULL DEFAULT '',
                size INTEGER NOT NULL DEFAULT 4 CHECK (size >= 0),
                PRIMARY KEY (target, va)
            )
        """)

        c.execute("DROP TABLE IF EXISTS sections")
        c.execute("""
            CREATE TABLE sections (
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

        c.execute("""
            CREATE TABLE cells (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                section_name TEXT NOT NULL,
                start INTEGER NOT NULL CHECK (start >= 0),
                end INTEGER NOT NULL CHECK (end >= start),
                span INTEGER NOT NULL DEFAULT 1 CHECK (span > 0),
                state TEXT NOT NULL,
                functions TEXT NOT NULL DEFAULT '[]',
                label TEXT,
                parent_function TEXT,
                FOREIGN KEY (target, section_name)
                    REFERENCES sections(target, name)
                    ON DELETE CASCADE
            )
        """)

        c.execute("DROP TABLE IF EXISTS metadata")
        c.execute("""
            CREATE TABLE metadata (
                target TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY (target, key)
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(target, name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_status ON functions(target, status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_module ON functions(target, module)")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_functions_marker ON functions(target, markerType)"
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_globals_name ON globals(target, name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cells_section ON cells(target, section_name)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                va INTEGER NOT NULL,
                old_status TEXT,
                new_status TEXT,
                changed_at TEXT NOT NULL
            )
        """)
        # history rows are appended on every rebuild and never pruned; the
        # dashboard pages them with WHERE target = ? ORDER BY id DESC LIMIT ?,
        # so (target, id) is the serving index (a plain (target, va) index
        # would not serve the ORDER BY id).
        c.execute("CREATE INDEX IF NOT EXISTS idx_history_target_id ON history(target, id)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS verify_results (
                target TEXT NOT NULL,
                va INTEGER NOT NULL,
                verified_at TEXT NOT NULL,
                byte_delta INTEGER,
                diff_lines INTEGER,
                PRIMARY KEY (target, va)
            )
        """)

        # Create views for pre-computed aggregate stats (used by both UIs)
        c.execute("""
            CREATE VIEW section_cell_stats AS
            SELECT
                target,
                section_name,
                COUNT(*) as total_cells,
                SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,
                SUM(CASE WHEN state = 'reloc' THEN 1 ELSE 0 END) as reloc_count,
                SUM(CASE WHEN state IN ('near_match', 'near_matching') THEN 1 ELSE 0 END) as near_match_count,
                SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) as stub_count,
                SUM(CASE WHEN state = 'padding' THEN 1 ELSE 0 END) as padding_count,
                SUM(CASE WHEN state = 'data' THEN 1 ELSE 0 END) as data_count,
                SUM(CASE WHEN state = 'thunk' THEN 1 ELSE 0 END) as thunk_count,
                SUM(CASE WHEN state = 'none' THEN 1 ELSE 0 END) as none_count
            FROM cells
            GROUP BY target, section_name
        """)

        # Process data_*.json files, optionally filtered by target
        json_files = list(db_dir.glob("data_*.json"))
        if target:
            json_files = [f for f in json_files if f.stem.removeprefix("data_") == target]
        if not json_files:
            error_exit(
                f"No data_*.json files found in {db_dir}. Run 'rebrew catalog --json' first.",
                json_mode=json_output,
            )

        for json_path in json_files:
            target_name = json_path.stem.removeprefix("data_")
            console.print(f"Processing {target_name}...")

            with json_path.open(encoding="utf-8") as f:
                data = json.load(f)

            fn_rows = []
            for va, fn in data.get("functions", {}).items():
                va_int = 0
                if isinstance(va, str):
                    try:
                        va_int = int(va, 0)
                    except ValueError:
                        va_int = 0
                elif isinstance(va, int):
                    va_int = va

                if va_int == 0:
                    va_start = fn.get("vaStart")
                    if isinstance(va_start, str):
                        try:
                            va_int = int(va_start, 0)
                        except ValueError:
                            va_int = 0

                va_start_text = str(fn.get("vaStart") or (f"0x{va_int:08x}" if va_int else ""))
                # build_db CHECK constraints reject negative fileOffset/
                # textOffset/blockerDelta — a stray negative would abort the
                # entire rebuild, so clamp defensively.
                file_off = fn.get("fileOffset")
                text_off = fn.get("textOffset")
                blocker_delta = fn.get("blockerDelta")
                fn_rows.append(
                    (
                        target_name,
                        va_int,
                        str(fn.get("name") or ""),
                        va_start_text,
                        fn.get("size"),
                        file_off if not isinstance(file_off, int) or file_off >= 0 else 0,
                        str(fn.get("status") or "UNKNOWN"),
                        str(fn.get("module") or fn.get("origin") or ""),
                        fn.get("cflags"),
                        fn.get("symbol"),
                        str(fn.get("markerType") or "FUNCTION"),
                        fn.get("ghidra_name"),
                        fn.get("list_name"),
                        int(bool(fn.get("is_thunk", False))),
                        int(bool(fn.get("is_export", False))),
                        fn.get("sha256"),
                        json.dumps(fn.get("files", [])),
                        json.dumps(fn.get("detected_by", [])),
                        json.dumps(fn.get("size_by_tool", {})),
                        text_off if not isinstance(text_off, int) or text_off >= 0 else 0,
                        fn.get("blocker", ""),
                        blocker_delta
                        if not isinstance(blocker_delta, int) or blocker_delta >= 0
                        else 0,
                        fn.get("size_reason", ""),
                        fn.get("similarity"),
                    )
                )

            c.executemany(
                "INSERT INTO functions "
                "(target, va, name, vaStart, size, fileOffset, status, module, cflags, "
                "symbol, markerType, ghidra_name, list_name, is_thunk, is_export, sha256, "
                "files, detected_by, size_by_tool, textOffset, blocker, blockerDelta, "
                "size_reason, similarity) "
                "VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                fn_rows,
            )

            g_rows = []
            globals_data: dict[str, Any] = data.get("globals", {})
            for va, g in globals_data.items():
                try:
                    va_int = int(va, 16) if isinstance(va, str) and va.startswith("0x") else int(va)
                except (ValueError, TypeError):
                    va_int = int(g.get("va", "0"), 16) if g.get("va") else 0
                g_rows.append(
                    (
                        target_name,
                        va_int,
                        str(g.get("name") or ""),
                        str(g.get("decl") or ""),
                        json.dumps(g.get("files", [])),
                        str(g.get("module") or g.get("origin") or ""),
                        g.get("size") if g.get("size") is not None else 4,
                    )
                )

            c.executemany(
                """
                INSERT INTO globals (target, va, name, decl, files, module, size)
                VALUES (?, ?, ?, ?, ?, ?, ?)
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

                            if state == "exact":
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

                c.execute(
                    """
                    INSERT INTO sections (target, name, va, size, fileOffset, unitBytes, columns)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        target_name,
                        sec_name,
                        sec.get("va"),
                        sec.get("size"),
                        sec.get("fileOffset"),
                        sec.get("unitBytes", 64),
                        sec.get("columns", 64),
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

            total, by_status, by_module, covered_bytes_func = _function_stats(c, target_name)

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
                            "covered_bytes": covered_bytes_func,
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
                "SELECT va, status FROM functions WHERE target = ?",
                (target_name,),
            )
            history_rows = []
            for row in c.fetchall():
                new_va, new_status = row
                key = (target_name, new_va)
                old_status = old_statuses.get(key)
                if old_status is not None and old_status != new_status:
                    history_rows.append((target_name, new_va, old_status, new_status, now_iso))
            if history_rows:
                c.executemany(
                    "INSERT INTO history (target, va, old_status, new_status, changed_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    history_rows,
                )

            # Import the last `rebrew verify -o` report (db/verify_results.json)
            # so the verify_results table carries real per-function data instead
            # of staying empty.  Best-effort: a missing/stale report is fine.
            vr_path = db_dir / "verify_results.json"
            if vr_path.exists():
                try:
                    vr_data = json.loads(vr_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError, TypeError):
                    vr_data = {}
                if vr_data.get("target") == target_name:
                    vr_time = str(vr_data.get("timestamp") or now_iso)
                    vr_rows = []
                    for item in vr_data.get("results", []):
                        try:
                            va_int = int(item.get("va", "0"), 0)
                        except (ValueError, TypeError):
                            continue
                        vr_rows.append(
                            (
                                target_name,
                                va_int,
                                vr_time,
                                item.get("delta"),
                                item.get("diff_lines"),
                            )
                        )
                    if vr_rows:
                        c.executemany(
                            "INSERT OR REPLACE INTO verify_results "
                            "(target, va, verified_at, byte_delta, diff_lines) "
                            "VALUES (?, ?, ?, ?, ?)",
                            vr_rows,
                        )

            # Schema version stamp
            c.execute(
                "INSERT OR REPLACE INTO metadata VALUES (?, ?, ?)",
                (target_name, "db_version", json.dumps(_CURRENT_DB_VERSION)),
            )

        c.execute("COMMIT")

        if json_output:
            json_print(
                {
                    "db_path": str(db_path),
                    "targets_processed": [f.stem.removeprefix("data_") for f in json_files],
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
        "  rebrew build-db · · · · · · · · · · · Build db/coverage.db from db/data_*.json\n\n"
        "  rebrew build-db --root /path/to/project  Specify project root explicitly\n\n"
        "[bold]Prerequisites:[/bold]\n\n"
        "  Run 'rebrew catalog --json' first to generate db/data_*.json files.\n\n"
        "[bold]What it creates:[/bold]\n\n"
        "  db/coverage.db · · · · · · SQLite database with functions, globals, sections, cells\n\n"
        "  src/<target>/CATALOG.md · · Markdown catalog (regenerate with 'rebrew catalog --catalog')\n\n"
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
) -> None:
    """CLI entry point for rebrew build-db."""
    build_db(root, target=target, json_output=json_output, force=force)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
