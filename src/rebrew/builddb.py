import json
import sqlite3
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


def build_db(project_root: Path | None = None):
    root_dir = Path(project_root).resolve() if project_root else Path.cwd().resolve()
    db_dir = root_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "coverage.db"

    # Load project config (optional, requires PyYAML)
    project_config = {}
    yml_path = root_dir / "reccmp-project.yml"
    if yaml and yml_path.exists():
        with open(yml_path) as f:
            project_config = yaml.safe_load(f)
    targets_info = project_config.get("targets", {})

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    try:
        # Enable WAL mode for better concurrency during regen
        c.execute("PRAGMA journal_mode=WAL")

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
                r2_name TEXT,
                is_thunk BOOLEAN,
                is_export BOOLEAN,
                sha256 TEXT,
                files TEXT,
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
                functions TEXT
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

        # Create indexes for fast lookups
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(target, name)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_globals_name ON globals(target, name)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_cells_section ON cells(target, section_name)"
        )

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
                SUM(CASE WHEN state = 'stub' THEN 1 ELSE 0 END) as stub_count
            FROM cells
            GROUP BY target, section_name
        """)

        # Process all data_*.json files
        json_files = list((root_dir / "db").glob("data_*.json"))
        if not json_files:
            print("Error: No data_*.json files found in db/. Run 'rebrew-catalog --json' first.")
            sys.exit(1)

        for json_path in json_files:
            target_name = json_path.stem.replace("data_", "")
            print(f"Processing {target_name}...")

            with open(json_path) as f:
                data = json.load(f)

            fn_rows = []
            for va, fn in data.get("functions", {}).items():
                # Ensure va is an integer
                va_int = (
                    int(va, 16)
                    if isinstance(va, str) and va.startswith("0x")
                    else int(va) if str(va).isdigit() else None
                )
                if va_int is None:
                    # Fallback if va is a name (like adler32)
                    va_int = int(fn.get("vaStart", "0"), 16) if fn.get("vaStart") else 0

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
                        fn.get("r2_name"),
                        fn.get("is_thunk", False),
                        fn.get("is_export", False),
                        fn.get("sha256"),
                        json.dumps(fn.get("files", [])),
                    )
                )

            c.executemany(
                """
                INSERT INTO functions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                fn_rows,
            )

            g_rows = [
                (
                    target_name,
                    (
                        int(va, 16)
                        if isinstance(va, str) and va.startswith("0x")
                        else int(va)
                    ),
                    g.get("name"),
                    g.get("decl"),
                    json.dumps(g.get("files", [])),
                )
                for va, g in data.get("globals", {}).items()
            ]

            c.executemany(
                """
                INSERT INTO globals VALUES (?, ?, ?, ?, ?)
            """,
                g_rows,
            )

            # Pre-calculate stats for all sections
            summary_data = data.get("summary", {})

            for sec_name, sec in data.get("sections", {}).items():
                if sec_name not in [".text", ".rdata", ".data", ".bss"]:
                    continue

                # Calculate stats for data sections
                if sec_name != ".text":
                    exact_count = reloc_count = matching_count = stub_count = 0
                    exact_bytes = reloc_bytes = matching_bytes = stub_bytes = 0
                    covered_bytes = 0
                    total_items = 0

                    for cell in sec.get("cells", []):
                        state = cell.get("state")
                        if state != "none":
                            size = cell.get("end", 0) - cell.get("start", 0)
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

                    summary_data[sec_name] = {
                        "exactMatches": exact_count,
                        "relocMatches": reloc_count,
                        "matchingMatches": matching_count,
                        "stubCount": stub_count,
                        "exactBytes": exact_bytes,
                        "relocBytes": reloc_bytes,
                        "matchingBytes": matching_bytes,
                        "stubBytes": stub_bytes,
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
                    )
                    for cell in sec.get("cells", [])
                ]

                c.executemany(
                    """
                    INSERT INTO cells (target, section_name, start, end, span, state, functions)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    cell_rows,
                )

            c.execute(
                "INSERT INTO metadata VALUES (?, ?, ?)",
                (target_name, "summary", json.dumps(summary_data)),
            )

            # Store paths
            paths_data = data.get("paths", {})
            if target_name in targets_info:
                target_info = targets_info[target_name]
                if "filename" in target_info:
                    paths_data["originalDll"] = "/" + target_info["filename"]
                if "source-root" in target_info:
                    paths_data["sourceRoot"] = "/" + target_info["source-root"]

            c.execute(
                "INSERT INTO metadata VALUES (?, ?, ?)",
                (target_name, "paths", json.dumps(paths_data)),
            )

        c.execute("COMMIT")
        print(f"Database built successfully at {db_path}")

        # Generate CATALOG.md from DB for each target
        _generate_catalogs(conn, root_dir)
    finally:
        conn.close()


def _generate_catalogs(conn: sqlite3.Connection, root_dir: Path):
    """Generate CATALOG.md files from DB data (DB is single source of truth)."""
    c = conn.cursor()
    c.execute("SELECT DISTINCT target FROM functions")
    targets = [row[0] for row in c.fetchall()]

    # Try to read reversed_dir from rebrew.toml
    toml_path = root_dir / "rebrew.toml"
    target_dirs = {}
    if toml_path.exists():
        try:
            if sys.version_info >= (3, 11):
                import tomllib
            else:
                import tomli as tomllib  # type: ignore
            with open(toml_path, "rb") as f:
                raw = tomllib.load(f)
            for tname, tdata in raw.get("targets", {}).items():
                rdir = tdata.get("reversed_dir")
                if rdir:
                    target_dirs[tname] = root_dir / rdir
        except Exception:
            pass

    for target_name in targets:
        # Get summary stats
        c.execute(
            "SELECT value FROM metadata WHERE target = ? AND key = 'summary'",
            (target_name,),
        )
        row = c.fetchone()
        summary = json.loads(row[0]) if row else {}

        # Get all functions
        c.execute(
            "SELECT va, name, size, status, origin, symbol, markerType, files "
            "FROM functions WHERE target = ? ORDER BY va",
            (target_name,),
        )
        functions = c.fetchall()

        # Compute stats
        total = len(functions)
        by_status = {}
        by_origin = {}
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
        lines.append("<!-- AUTO-GENERATED FILE — DO NOT EDIT. Regenerate with: rebrew-build-db -->\n")
        lines.append("# Reversed Functions Catalog\n")
        lines.append(
            f"Total: {total} functions matched "
            f"({by_status.get('EXACT', 0)} exact, "
            f"{by_status.get('RELOC', 0)} reloc, "
            f"{by_status.get('STUB', 0)} stubs)  "
        )
        lines.append(
            f"Coverage: {coverage_pct:.1f}% of .text section "
            f"({covered_bytes}/{text_size} bytes)\n"
        )

        # Table by origin
        for origin in sorted(by_origin.keys()):
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


import typer

from rebrew.cli import TargetOption

app = typer.Typer(help="Build SQLite coverage database.")

@app.callback(invoke_without_command=True)
def main(
    root: Path = typer.Option(
        None,
        "--root",
        help="Project root directory",
    ),
    target: str = TargetOption,
):
    """CLI entry point for rebrew-build-db."""
    build_db(root)

def main_entry():
    app()

if __name__ == "__main__":
    main_entry()

