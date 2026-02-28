"""build_db.py – Build SQLite coverage database from function catalog.

Aggregates annotation data, verification results, and coverage statistics
into a single SQLite database for querying and reporting.
"""

import contextlib
import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

import typer

from rebrew.cli import TargetOption, error_exit


def build_db(project_root: Path | None = None, target: str | None = None) -> None:
    """Aggregate ``data_*.json`` files into ``db/coverage.db``."""
    root_dir = Path(project_root).resolve() if project_root else Path.cwd().resolve()
    db_dir = root_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "coverage.db"

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        # Enable WAL mode for better concurrency during regen
        c.execute("PRAGMA journal_mode=WAL")

        # Snapshot existing function statuses for history tracking
        old_statuses: dict[tuple[str, int], str] = {}
        with contextlib.suppress(sqlite3.OperationalError):
            c.execute("SELECT target, va, status FROM functions")
            for row in c.fetchall():
                old_statuses[(row[0], row[1])] = row[2]

        # Start an exclusive transaction
        c.execute("BEGIN IMMEDIATE")

        c.execute("DROP TABLE IF EXISTS functions")
        c.execute("""
            CREATE TABLE functions (
                target TEXT,
                va INTEGER,
                name TEXT,
                vaStart TEXT,
                size INTEGER,
                fileOffset INTEGER,
                status TEXT,
                origin TEXT,
                cflags TEXT,
                symbol TEXT,
                markerType TEXT,
                ghidra_name TEXT,
                list_name TEXT,
                is_thunk BOOLEAN,
                is_export BOOLEAN,
                sha256 TEXT,
                files TEXT,
                detected_by TEXT,
                size_by_tool TEXT,
                textOffset INTEGER,
                blocker TEXT,
                blockerDelta INTEGER,
                size_reason TEXT,
                similarity REAL,
                PRIMARY KEY (target, va)
            )
        """)

        c.execute("DROP TABLE IF EXISTS globals")
        c.execute("""
            CREATE TABLE globals (
                target TEXT,
                va INTEGER,
                name TEXT,
                decl TEXT,
                files TEXT,
                origin TEXT,
                size INTEGER,
                PRIMARY KEY (target, va)
            )
        """)

        c.execute("DROP TABLE IF EXISTS sections")
        c.execute("""
            CREATE TABLE sections (
                target TEXT,
                name TEXT,
                va INTEGER,
                size INTEGER,
                fileOffset INTEGER,
                unitBytes INTEGER,
                columns INTEGER,
                PRIMARY KEY (target, name)
            )
        """)

        c.execute("DROP TABLE IF EXISTS cells")
        c.execute("""
            CREATE TABLE cells (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                section_name TEXT,
                start INTEGER,
                end INTEGER,
                span INTEGER,
                state TEXT,
                functions TEXT,
                label TEXT,
                parent_function TEXT
            )
        """)

        c.execute("DROP TABLE IF EXISTS metadata")
        c.execute("""
            CREATE TABLE metadata (
                target TEXT,
                key TEXT,
                value TEXT,
                PRIMARY KEY (target, key)
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(target, name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_status ON functions(target, status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_functions_origin ON functions(target, origin)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_globals_name ON globals(target, name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cells_section ON cells(target, section_name)")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_cells_state ON cells(target, section_name, state)"
        )

        c.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                va INTEGER,
                old_status TEXT,
                new_status TEXT,
                changed_at TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_history_target_va ON history(target, va)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS verify_results (
                target TEXT,
                va INTEGER,
                verified_at TEXT,
                byte_delta INTEGER,
                diff_lines INTEGER,
                PRIMARY KEY (target, va)
            )
        """)

        # Create views for pre-computed aggregate stats (used by both UIs)
        c.execute("DROP VIEW IF EXISTS section_cell_stats")
        c.execute("""
            CREATE VIEW section_cell_stats AS
            SELECT
                target,
                section_name,
                COUNT(*) as total_cells,
                SUM(CASE WHEN state = 'exact' THEN 1 ELSE 0 END) as exact_count,
                SUM(CASE WHEN state = 'reloc' THEN 1 ELSE 0 END) as reloc_count,
                SUM(CASE WHEN state IN ('matching', 'matching_reloc') THEN 1 ELSE 0 END) as matching_count,
                SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) as stub_count,
                SUM(CASE WHEN state = 'padding' THEN 1 ELSE 0 END) as padding_count,
                SUM(CASE WHEN state = 'data' THEN 1 ELSE 0 END) as data_count,
                SUM(CASE WHEN state = 'thunk' THEN 1 ELSE 0 END) as thunk_count,
                SUM(CASE WHEN state = 'none' THEN 1 ELSE 0 END) as none_count
            FROM cells
            GROUP BY target, section_name
        """)

        # Process data_*.json files, optionally filtered by target
        json_files = list((root_dir / "db").glob("data_*.json"))
        if target:
            json_files = [f for f in json_files if f.stem.removeprefix("data_") == target]
        if not json_files:
            error_exit("No data_*.json files found in db/. Run 'rebrew catalog --json' first.")

        for json_path in json_files:
            target_name = json_path.stem.removeprefix("data_")
            print(f"Processing {target_name}...", file=sys.stderr)

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

                fn_rows.append(
                    (
                        target_name,
                        va_int,
                        fn.get("name"),
                        fn.get("vaStart"),
                        fn.get("size"),
                        fn.get("fileOffset"),
                        fn.get("status"),
                        fn.get("origin"),
                        fn.get("cflags"),
                        fn.get("symbol"),
                        fn.get("markerType"),
                        fn.get("ghidra_name"),
                        fn.get("list_name"),
                        fn.get("is_thunk", False),
                        fn.get("is_export", False),
                        fn.get("sha256"),
                        json.dumps(fn.get("files", [])),
                        json.dumps(fn.get("detected_by", [])),
                        json.dumps(fn.get("size_by_tool", {})),
                        fn.get("textOffset"),
                        fn.get("blocker", ""),
                        fn.get("blockerDelta"),
                        fn.get("size_reason", ""),
                        fn.get("similarity"),
                    )
                )

            c.executemany(
                "INSERT INTO functions VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                fn_rows,
            )

            g_rows = []
            for va, g in data.get("globals", {}).items():
                try:
                    va_int = int(va, 16) if isinstance(va, str) and va.startswith("0x") else int(va)
                except (ValueError, TypeError):
                    va_int = int(g.get("va", "0"), 16) if g.get("va") else 0
                g_rows.append(
                    (
                        target_name,
                        va_int,
                        g.get("name"),
                        g.get("decl"),
                        json.dumps(g.get("files", [])),
                        g.get("origin"),
                        g.get("size", 4),
                    )
                )

            c.executemany(
                """
                INSERT INTO globals VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                g_rows,
            )

            # Pre-calculate stats for all sections
            summary_data = data.get("summary", {})

            for sec_name, sec in data.get("sections", {}).items():
                # Calculate stats for data sections
                if sec_name != ".text":
                    exact_count = reloc_count = matching_count = stub_count = 0
                    padding_count = 0
                    exact_bytes = reloc_bytes = matching_bytes = stub_bytes = 0
                    padding_bytes = 0
                    covered_bytes = 0
                    total_items = 0

                    for cell in sec.get("cells", []):
                        state = cell.get("state")
                        if state != "none":
                            start = int(cell.get("start", 0) or 0)
                            end = int(cell.get("end", 0) or 0)
                            size = max(0, end - start)
                            covered_bytes += size
                            funcs = cell.get("functions", [])
                            total_items += len(funcs) if funcs else 0

                            if state == "exact":
                                exact_count += 1
                                exact_bytes += size
                            elif state == "reloc":
                                reloc_count += 1
                                reloc_bytes += size
                            elif state in ("matching", "matching_reloc"):
                                matching_count += 1
                                matching_bytes += size
                            elif state == "stub":
                                stub_count += 1
                                stub_bytes += size
                            elif state == "padding":
                                padding_count += 1
                                padding_bytes += size

                    summary_data[sec_name] = {
                        "exactMatches": exact_count,
                        "relocMatches": reloc_count,
                        "matchingMatches": matching_count,
                        "stubCount": stub_count,
                        "paddingCount": padding_count,
                        "exactBytes": exact_bytes,
                        "relocBytes": reloc_bytes,
                        "matchingBytes": matching_bytes,
                        "stubBytes": stub_bytes,
                        "paddingBytes": padding_bytes,
                        "coveredBytes": covered_bytes,
                        "totalFunctions": total_items,
                        "size": sec.get("size", 0),
                    }

                c.execute(
                    """
                    INSERT INTO sections VALUES (?, ?, ?, ?, ?, ?, ?)
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
                    (
                        target_name,
                        sec_name,
                        cell.get("start"),
                        cell.get("end"),
                        cell.get("span"),
                        cell.get("state"),
                        json.dumps(cell.get("functions", [])),
                        cell.get("label"),
                        cell.get("parent_function"),
                    )
                    for cell in sec.get("cells", [])
                ]

                c.executemany(
                    """
                    INSERT INTO cells (target, section_name, start, end, span, state, functions, label, parent_function)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    cell_rows,
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

            # Schema version stamp
            c.execute(
                "INSERT OR REPLACE INTO metadata VALUES (?, ?, ?)",
                (target_name, "db_version", json.dumps("3")),
            )

        c.execute("COMMIT")
        print(f"Database built successfully at {db_path}")

        # Generate CATALOG.md from DB for each target
        _generate_catalogs(conn, root_dir)
    except BaseException:
        if conn is not None:
            with contextlib.suppress(sqlite3.Error):
                conn.rollback()
        raise
    finally:
        if conn is not None:
            conn.close()


def _generate_catalogs(conn: sqlite3.Connection, root_dir: Path) -> None:
    """Generate CATALOG.md files from DB data (DB is single source of truth)."""
    c = conn.cursor()
    c.execute("SELECT DISTINCT target FROM functions")
    targets = [row[0] for row in c.fetchall()]

    # Try to read reversed_dir from rebrew-project.toml
    toml_path = root_dir / "rebrew-project.toml"
    target_dirs: dict[str, Path] = {}
    if toml_path.exists():
        try:
            import tomllib

            with toml_path.open("rb") as f:
                raw = tomllib.load(f)
            for tname, tdata in raw.get("targets", {}).items():
                rdir = tdata.get("reversed_dir")
                if rdir:
                    target_dirs[tname] = root_dir / rdir
        except (OSError, KeyError, ValueError):
            pass

    for target_name in targets:
        # Get summary stats
        c.execute(
            "SELECT value FROM metadata WHERE target = ? AND key = 'summary'",
            (target_name,),
        )
        row = c.fetchone()
        try:
            summary = json.loads(row[0]) if row else {}
        except (json.JSONDecodeError, TypeError):
            summary = {}

        # Get all functions
        c.execute(
            "SELECT va, name, size, status, origin, symbol, markerType, files "
            "FROM functions WHERE target = ? AND markerType NOT IN ('GLOBAL', 'DATA') ORDER BY va",
            (target_name,),
        )
        functions = c.fetchall()

        # Compute stats
        total = len(functions)
        by_status: dict[str, int] = {}
        by_origin: dict[str, list[object]] = {}
        covered_bytes = 0
        for fn in functions:
            st = fn[3] or "UNKNOWN"
            by_status[st] = by_status.get(st, 0) + 1
            orig = fn[4] or "UNKNOWN"
            by_origin.setdefault(orig, []).append(fn)
            covered_bytes += fn[2] or 0

        text_summary = summary.get(".text", {})
        text_size = text_summary.get("size", 0)
        coverage_pct = (covered_bytes / text_size * 100.0) if text_size else 0.0

        # Build markdown
        lines = []
        lines.append(
            "<!-- AUTO-GENERATED FILE — DO NOT EDIT. Regenerate with: rebrew build-db -->\n"
        )
        lines.append("# Reversed Functions Catalog\n")
        lines.append(
            f"Total: {total} functions matched "
            f"({by_status.get('EXACT', 0)} exact, "
            f"{by_status.get('RELOC', 0)} reloc, "
            f"{by_status.get('STUB', 0)} stubs)  "
        )
        lines.append(
            f"Coverage: {coverage_pct:.1f}% of .text section ({covered_bytes}/{text_size} bytes)\n"
        )

        # Table by origin
        for origin in sorted(by_origin):
            fns = by_origin[origin]
            lines.append(f"\n## {origin} ({len(fns)} functions)\n")
            lines.append("| VA | Symbol | Size | Status | Files |")
            lines.append("|---:|--------|-----:|--------|-------|")
            for fn in fns:
                va_hex = f"0x{fn[0]:08x}" if fn[0] else "???"
                sym = fn[5] or fn[1] or "???"
                size = fn[2] or 0
                status = fn[3] or "?"
                try:
                    file_list = json.loads(fn[7]) if fn[7] else []
                except (json.JSONDecodeError, TypeError):
                    file_list = []
                files_str = ", ".join(file_list) if file_list else ""
                lines.append(f"| {va_hex} | {sym} | {size} | {status} | {files_str} |")

        catalog_text = "\n".join(lines) + "\n"

        # Write to reversed_dir if known, otherwise db/
        out_dir = target_dirs.get(target_name, root_dir / "db")
        out_dir.mkdir(parents=True, exist_ok=True)
        catalog_path = out_dir / "CATALOG.md"
        catalog_path.write_text(catalog_text, encoding="utf-8")
        print(f"Generated {catalog_path}")


app = typer.Typer(
    help="Build SQLite coverage database from catalog JSON.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew build-db                          Build db/coverage.db from db/data_*.json

rebrew build-db --root /path/to/project  Specify project root explicitly

[bold]Prerequisites:[/bold]

Run 'rebrew catalog --json' first to generate db/data_*.json files.

[bold]What it creates:[/bold]

db/coverage.db          SQLite database with functions, globals, sections, cells

src/<target>/CATALOG.md  Markdown catalog of all reversed functions

[dim]The database is used by recoverage (coverage dashboard) and can be queried
directly for reports. Schema version is stamped in the metadata table.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Project root directory",
    ),
    target: str | None = TargetOption,
) -> None:
    """CLI entry point for rebrew build-db."""
    build_db(root, target=target)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
