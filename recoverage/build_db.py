import json
import sqlite3
import sys
from pathlib import Path
import yaml


def build_db():
    script_dir = Path(__file__).resolve().parent
    root_dir = script_dir.parent
    db_path = script_dir / "coverage.db"

    # Load project config
    project_config = {}
    yml_path = root_dir / "reccmp-project.yml"
    if yml_path.exists():
        with open(yml_path, "r") as f:
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
        json_files = list((root_dir / "recoverage").glob("data_*.json"))
        if not json_files:
            print("Error: No data_*.json files found. Run catalog.py first.")
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
    finally:
        conn.close()


if __name__ == "__main__":
    build_db()
