"""Tests for rebrew.builddb — round-trip JSON → SQLite → query.

Uses a synthetic data_*.json to verify that build_db() creates the expected
schema and populates all columns (including the new detected_by, size_by_tool,
textOffset, globals origin/size, and the section_cell_stats view).
"""

import json
import sqlite3
from pathlib import Path

import pytest

from rebrew.build_db import build_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_DATA = {
    "sections": {
        ".text": {
            "va": 0x10001000,
            "size": 4096,
            "fileOffset": 0x1000,
            "unitBytes": 64,
            "columns": 64,
            "cells": [
                {"start": 0, "end": 64, "span": 1, "state": "exact", "functions": ["func_a"]},
                {"start": 64, "end": 128, "span": 1, "state": "none", "functions": []},
                {"start": 128, "end": 192, "span": 1, "state": "stub", "functions": ["func_b"]},
                {"start": 192, "end": 256, "span": 1, "state": "reloc", "functions": ["func_c"]},
                {"start": 256, "end": 320, "span": 1, "state": "matching", "functions": ["func_d"]},
                {
                    "start": 320,
                    "end": 384,
                    "span": 1,
                    "state": "matching_reloc",
                    "functions": ["func_e"],
                },
            ],
        },
    },
    "globals": {
        "0x10030000": {
            "va": 0x10030000,
            "name": "g_counter",
            "decl": "int g_counter;",
            "files": ["globals.c"],
            "origin": "GAME",
            "size": 4,
        },
        "0x10030100": {
            "va": 0x10030100,
            "name": "g_buffer",
            "decl": "char g_buffer[256];",
            "files": ["globals.c"],
            "origin": "GAME",
            "size": 256,
        },
    },
    "summary": {
        "totalFunctions": 5,
        "matchedFunctions": 4,
        "exactMatches": 1,
        "relocMatches": 1,
        "matchingMatches": 2,
        "stubCount": 1,
        "coveredBytes": 256,
        "coveragePercent": 50.0,
        "textSize": 4096,
        ".text": {
            "size": 4096,
        },
    },
    "functions": {
        "func_a": {
            "name": "func_a",
            "vaStart": "0x10001000",
            "size": 64,
            "fileOffset": 0x1000,
            "status": "EXACT",
            "origin": "GAME",
            "cflags": "/O2",
            "symbol": "_func_a",
            "markerType": "FUNCTION",
            "ghidra_name": "FUN_10001000",
            "r2_name": "fcn.10001000",
            "is_thunk": False,
            "is_export": True,
            "sha256": "abcd1234",
            "files": ["func_a.c"],
            "detected_by": ["ghidra", "r2"],
            "size_by_tool": {"ghidra": 64, "r2": 64},
            "textOffset": 0,
        },
        "func_b": {
            "name": "func_b",
            "vaStart": "0x10001080",
            "size": 128,
            "fileOffset": 0x1080,
            "status": "STUB",
            "origin": "GAME",
            "cflags": "",
            "symbol": "_func_b",
            "markerType": "STUB",
            "ghidra_name": "",
            "r2_name": "fcn.10001080",
            "is_thunk": False,
            "is_export": False,
            "sha256": "",
            "files": ["func_b.c"],
            "detected_by": ["r2"],
            "size_by_tool": {"r2": 128},
            "textOffset": 0x80,
        },
    },
    "paths": {"originalDll": "/original/Server/server.dll"},
}


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    """Create a minimal project layout with data_testbin.json."""
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    json_path = db_dir / "data_testbin.json"
    json_path.write_text(json.dumps(SAMPLE_DATA), encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBuildDbRoundTrip:
    """Verify build_db creates tables with all columns and correct data."""

    def test_db_created(self, project_root: Path) -> None:
        build_db(project_root)
        db_path = project_root / "db" / "coverage.db"
        assert db_path.exists()

    def test_functions_columns(self, project_root: Path) -> None:
        """All function columns including new detected_by, size_by_tool, textOffset."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("SELECT * FROM functions WHERE target = 'testbin' AND name = 'func_a'")
        row = c.fetchone()
        assert row is not None

        assert row["name"] == "func_a"
        assert row["vaStart"] == "0x10001000"
        assert row["size"] == 64
        assert row["status"] == "EXACT"
        assert row["origin"] == "GAME"
        assert row["is_export"] == 1
        assert row["sha256"] == "abcd1234"

        # New columns
        detected = json.loads(row["detected_by"])
        assert "ghidra" in detected
        assert "r2" in detected

        sizes = json.loads(row["size_by_tool"])
        assert sizes["ghidra"] == 64
        assert sizes["r2"] == 64

        assert row["textOffset"] == 0
        conn.close()

    def test_functions_stub(self, project_root: Path) -> None:
        """Stub function has correct textOffset."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("SELECT * FROM functions WHERE target = 'testbin' AND name = 'func_b'")
        row = c.fetchone()
        assert row is not None
        assert row["status"] == "STUB"
        assert row["textOffset"] == 0x80

        detected = json.loads(row["detected_by"])
        assert detected == ["r2"]
        conn.close()

    def test_globals_columns(self, project_root: Path) -> None:
        """Globals have origin and size columns."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("SELECT * FROM globals WHERE target = 'testbin' ORDER BY va")
        rows = c.fetchall()
        assert len(rows) == 2

        counter_row = rows[0]
        assert counter_row["name"] == "g_counter"
        assert counter_row["origin"] == "GAME"
        assert counter_row["size"] == 4

        buffer_row = rows[1]
        assert buffer_row["name"] == "g_buffer"
        assert buffer_row["origin"] == "GAME"
        assert buffer_row["size"] == 256
        conn.close()

    def test_sections(self, project_root: Path) -> None:
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("SELECT * FROM sections WHERE target = 'testbin' AND name = '.text'")
        row = c.fetchone()
        assert row is not None
        assert row["name"] == ".text"
        assert row["va"] == 0x10001000
        assert row["size"] == 4096
        assert row["unitBytes"] == 64
        assert row["fileOffset"] == 0x1000
        assert row["columns"] == 64
        conn.close()

    def test_cells(self, project_root: Path) -> None:
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM cells WHERE target = 'testbin'")
        count = c.fetchone()[0]
        assert count == 6
        conn.close()

    def test_section_cell_stats_view(self, project_root: Path) -> None:
        """The view should return correct counts including none_count."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute(
            "SELECT * FROM section_cell_stats WHERE target = 'testbin' AND section_name = '.text'"
        )
        row = c.fetchone()
        assert row is not None
        assert row["total_cells"] == 6
        assert row["exact_count"] == 1
        assert row["reloc_count"] == 1
        assert row["matching_count"] == 2  # matching + matching_reloc
        assert row["stub_count"] == 1
        assert row["none_count"] == 1
        conn.close()

    def test_db_version_metadata(self, project_root: Path) -> None:
        """db_version key should be present in metadata."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT value FROM metadata WHERE target = 'testbin' AND key = 'db_version'")
        row = c.fetchone()
        assert row is not None
        version = json.loads(row[0])
        assert version == "2"
        conn.close()

    def test_summary_metadata(self, project_root: Path) -> None:
        """Summary metadata should be stored."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT value FROM metadata WHERE target = 'testbin' AND key = 'summary'")
        row = c.fetchone()
        assert row is not None
        summary = json.loads(row[0])
        assert summary["totalFunctions"] == 5
        assert summary["matchedFunctions"] == 4
        assert summary["exactMatches"] == 1
        assert summary["relocMatches"] == 1
        assert summary["stubCount"] == 1
        assert summary["coveragePercent"] == 50.0
        conn.close()

    def test_paths_metadata(self, project_root: Path) -> None:
        """Paths metadata should be stored."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT value FROM metadata WHERE target = 'testbin' AND key = 'paths'")
        row = c.fetchone()
        assert row is not None
        paths = json.loads(row[0])
        assert "originalDll" in paths
        assert paths["originalDll"] == "/original/Server/server.dll"
        conn.close()

    def test_idempotent(self, project_root: Path) -> None:
        """Running build_db twice should not error (DROP TABLE IF EXISTS)."""
        build_db(project_root)
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM functions WHERE target = 'testbin'")
        assert c.fetchone()[0] == 2
        conn.close()


class TestBuildDbTargetFiltering:
    """Verify that build_db(target=...) only processes matching JSON files."""

    def test_filters_to_specified_target(self, tmp_path: Path) -> None:
        """When target='alpha', only data_alpha.json should be ingested."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()

        # Create two different target JSON files with minimal valid data
        for name in ("alpha", "beta"):
            data = {
                "sections": {},
                "globals": {},
                "summary": {"totalFunctions": 1},
                "functions": {
                    f"func_{name}": {
                        "name": f"func_{name}",
                        "vaStart": "0x10001000",
                        "size": 64,
                        "status": "EXACT",
                    }
                },
                "paths": {},
            }
            (db_dir / f"data_{name}.json").write_text(json.dumps(data), encoding="utf-8")

        # Build with target="alpha" — only data_alpha.json should be processed
        build_db(tmp_path, target="alpha")

        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM functions")
        targets = [row[0] for row in c.fetchall()]
        conn.close()

        assert targets == ["alpha"], f"Expected only 'alpha', got {targets}"

    def test_no_filter_processes_all(self, tmp_path: Path) -> None:
        """When target is None, all data_*.json files are processed."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()

        for name in ("alpha", "beta"):
            data = {
                "sections": {},
                "globals": {},
                "summary": {},
                "functions": {
                    f"func_{name}": {
                        "name": f"func_{name}",
                        "vaStart": "0x10001000",
                        "size": 64,
                        "status": "EXACT",
                    }
                },
                "paths": {},
            }
            (db_dir / f"data_{name}.json").write_text(json.dumps(data), encoding="utf-8")

        build_db(tmp_path, target=None)

        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM functions ORDER BY target")
        targets = [row[0] for row in c.fetchall()]
        conn.close()

        assert targets == ["alpha", "beta"]

    def test_nonexistent_target_raises(self, tmp_path: Path) -> None:
        """Filtering by a non-existent target should raise Exit (no JSON found)."""
        from click.exceptions import Exit as ClickExit

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data_testbin.json").write_text(json.dumps(SAMPLE_DATA), encoding="utf-8")

        with pytest.raises(ClickExit):
            build_db(tmp_path, target="nonexistent")
