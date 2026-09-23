"""Tests for rebrew.builddb — round-trip JSON → SQLite → query.

Uses a synthetic data_*.json to verify that build_db() creates the expected
schema and populates all columns (including the new detected_by, size_by_tool,
textOffset, globals origin/size, and the section_cell_stats view).
"""

import json
import sqlite3
from pathlib import Path
from typing import Any

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
                {
                    "start": 256,
                    "end": 320,
                    "span": 1,
                    "state": "near_match",
                    "functions": ["func_d"],
                },
                {
                    "start": 320,
                    "end": 384,
                    "span": 1,
                    "state": "near_match",
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
        # exact(1) + reloc(1); NEAR_MATCHING(2) and STUB(1) are not matched.
        "matchedFunctions": 2,
        "exactMatches": 1,
        "relocMatches": 1,
        "nearMatchCount": 2,
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
            "list_name": "fcn.10001000",
            "is_thunk": False,
            "is_export": True,
            "sha256": "abcd1234",
            "files": ["func_a.c"],
            "detected_by": ["ghidra", "list"],
            "size_by_tool": {"ghidra": 64, "list": 64},
            "textOffset": 0,
            "blocker": "",
            "blockerDelta": None,
            "size_reason": "ghidra",
            "similarity": 1.0,
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
            "list_name": "fcn.10001080",
            "is_thunk": False,
            "is_export": False,
            "sha256": "",
            "files": ["func_b.c"],
            "detected_by": ["list"],
            "size_by_tool": {"list": 128},
            "textOffset": 0x80,
            "blocker": "needs vtable",
            "blockerDelta": 12,
            "size_reason": "list",
            "similarity": 0.85,
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


def _write_cache(project_root: Path, target: str, entries: dict) -> None:
    """Seed .rebrew/verify_cache.json (the verify_results import source)."""
    cache_dir = project_root / ".rebrew"
    cache_dir.mkdir(exist_ok=True)
    (cache_dir / "verify_cache.json").write_text(
        json.dumps({"version": 2, "target": target, "entries": entries}),
        encoding="utf-8",
    )


def _open_db(project_root: Path) -> tuple[sqlite3.Connection, sqlite3.Cursor]:
    """Build the coverage DB and return a (connection, cursor) pair."""
    build_db(project_root)
    conn = sqlite3.connect(project_root / "db" / "coverage.db")
    conn.row_factory = sqlite3.Row
    return conn, conn.cursor()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBuildDbRoundTrip:
    """Verify build_db creates tables with all columns and correct data."""

    def test_db_created(self, project_root: Path) -> None:
        build_db(project_root)
        db_path = project_root / "db" / "coverage.db"
        assert db_path.exists()

    def test_configured_db_dir_is_used(self, tmp_path: Path) -> None:
        configured_db = tmp_path / "coverage"
        configured_db.mkdir()
        (configured_db / "data_testbin.json").write_text(json.dumps(SAMPLE_DATA), encoding="utf-8")
        (tmp_path / "rebrew-project.toml").write_text(
            """\
[project]
default_target = "main"
db_dir = "coverage"

[targets.main]
binary = "test.exe"
""",
            encoding="utf-8",
        )

        build_db(tmp_path)

        assert (configured_db / "coverage.db").exists()
        assert not (tmp_path / "db" / "coverage.db").exists()

    @pytest.mark.parametrize("target", [None, "beta"])
    def test_regen_json_output(
        self,
        project_root: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        target: str | None,
    ) -> None:
        from copy import deepcopy
        from types import SimpleNamespace

        monkeypatch.setattr(
            "rebrew.build_db.load_config",
            lambda *args, **kwargs: SimpleNamespace(
                all_targets=["alpha", "beta"], target_name="alpha"
            ),
        )
        monkeypatch.setattr(
            "rebrew.catalog.pipeline.build_catalog_data",
            lambda cfg: {"data": deepcopy(SAMPLE_DATA)},
        )

        build_db(project_root, target=target, regen=True, json_output=True)

        result = json.loads(capsys.readouterr().out)
        expected = [target] if target else ["alpha", "beta"]
        assert result["targets_processed"] == expected
        conn = sqlite3.connect(result["db_path"])
        try:
            rows = conn.execute("SELECT DISTINCT target FROM functions ORDER BY target").fetchall()
            assert [row[0] for row in rows] == expected
        finally:
            conn.close()

    def test_functions_columns(self, project_root: Path) -> None:
        """All function columns including new detected_by, size_by_tool, textOffset."""
        conn, c = _open_db(project_root)

        c.execute("SELECT * FROM functions WHERE target = 'testbin' AND name = 'func_a'")
        row = c.fetchone()
        assert row is not None

        assert row["name"] == "func_a"
        assert row["vaStart"] == "0x10001000"
        assert row["size"] == 64
        assert row["status"] == "EXACT"
        assert row["is_export"] == 1
        assert row["sha256"] == "abcd1234"

        # New columns
        detected = json.loads(row["detected_by"])
        assert "ghidra" in detected
        assert "list" in detected

        sizes = json.loads(row["size_by_tool"])
        assert sizes["ghidra"] == 64
        assert sizes["list"] == 64

        assert row["textOffset"] == 0
        conn.close()

    def test_functions_stub(self, project_root: Path) -> None:
        """Stub function has correct textOffset."""
        conn, c = _open_db(project_root)

        c.execute("SELECT * FROM functions WHERE target = 'testbin' AND name = 'func_b'")
        row = c.fetchone()
        assert row is not None
        assert row["status"] == "STUB"
        assert row["textOffset"] == 0x80

        detected = json.loads(row["detected_by"])
        assert detected == ["list"]
        conn.close()

    def test_globals_columns(self, project_root: Path) -> None:
        """Globals have size columns."""
        conn, c = _open_db(project_root)

        c.execute("SELECT * FROM globals WHERE target = 'testbin' ORDER BY va")
        rows = c.fetchall()
        assert len(rows) == 2

        counter_row = rows[0]
        assert counter_row["name"] == "g_counter"
        assert counter_row["module"] == "GAME"
        assert counter_row["size"] == 4

        buffer_row = rows[1]
        assert buffer_row["name"] == "g_buffer"
        assert buffer_row["size"] == 256
        conn.close()

    def test_sections(self, project_root: Path) -> None:
        conn, c = _open_db(project_root)

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
        conn, c = _open_db(project_root)

        c.execute(
            "SELECT * FROM section_cell_stats WHERE target = 'testbin' AND section_name = '.text'"
        )
        row = c.fetchone()
        assert row is not None
        assert row["total_cells"] == 6
        assert row["exact_count"] == 1
        assert row["reloc_count"] == 1
        assert row["near_match_count"] == 2
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
        from rebrew.build_db import _CURRENT_DB_VERSION

        version = json.loads(row[0])
        assert version == _CURRENT_DB_VERSION
        conn.close()

    def test_new_columns(self, project_root: Path) -> None:
        conn, c = _open_db(project_root)

        c.execute(
            "SELECT size_reason, similarity, blocker, blockerDelta "
            "FROM functions WHERE target = 'testbin' AND name = 'func_a'"
        )
        func_a = c.fetchone()
        assert func_a is not None
        assert func_a["size_reason"] == "ghidra"
        assert func_a["similarity"] == 1.0
        assert func_a["blocker"] == ""
        assert func_a["blockerDelta"] is None

        c.execute(
            "SELECT size_reason, similarity, blocker, blockerDelta "
            "FROM functions WHERE target = 'testbin' AND name = 'func_b'"
        )
        func_b = c.fetchone()
        assert func_b is not None
        assert func_b["size_reason"] == "list"
        assert func_b["similarity"] == 0.85
        assert func_b["blocker"] == "needs vtable"
        assert func_b["blockerDelta"] == 12
        conn.close()

    def test_history_table_exists(self, project_root: Path) -> None:
        conn, c = _open_db(project_root)

        c.execute("PRAGMA table_info(history)")
        columns = [row["name"] for row in c.fetchall()]
        assert columns == [
            "id",
            "target",
            "va",
            "old_status",
            "new_status",
            "changed_at",
            "updated_by",
        ]
        conn.close()

    def test_history_tracks_changes(self, project_root: Path) -> None:
        db_dir = project_root / "db"
        json_path = db_dir / "data_testbin.json"

        build_db(project_root)

        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["functions"]["func_a"]["status"] = "RELOC"
        json_path.write_text(json.dumps(data), encoding="utf-8")

        build_db(project_root)

        conn, c = _open_db(project_root)
        c.execute(
            "SELECT old_status, new_status FROM history "
            "WHERE target = 'testbin' AND va = ? ORDER BY id DESC LIMIT 1",
            (0x10001000,),
        )
        row = c.fetchone()
        assert row is not None
        assert row["old_status"] == "EXACT"
        assert row["new_status"] == "RELOC"
        conn.close()

    def test_verify_results_table_exists(self, project_root: Path) -> None:
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='verify_results'")
        row = c.fetchone()
        assert row is not None
        assert row[0] == "verify_results"
        conn.close()

    def test_verify_results_persist_across_rebuild(self, project_root: Path) -> None:
        """verify_results is a persistent history table (DB_FORMAT.md: "never
        dropped on rebuild") — a full rebuild must NOT wipe it (the
        old DROP TABLE wiped every target's rows, keeping only the
        last-verified target's re-import)."""

        # First build: import a cache row.
        _write_cache(
            project_root,
            "testbin",
            {"0x00001000": {"va": "0x00001000", "status": "EXACT", "delta": 3}},
        )
        build_db(project_root)
        # Full rebuild WITHOUT the cache (simulates a later run where the
        # cache was regenerated for a different target or is absent).
        (project_root / ".rebrew" / "verify_cache.json").unlink()
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM verify_results WHERE target = 'testbin'")
        assert c.fetchone()[0] == 1  # row survived the rebuild
        conn.close()

    def test_verify_results_scales_percent_similarity(self, project_root: Path) -> None:
        """Verify cache stores code_similarity on 0–100; DB column is 0–1.

        A unit-interval clamp would store 85.5 as 1.0 (perfect match).
        """
        _write_cache(
            project_root,
            "testbin",
            {
                "0x00001000": {
                    "va": "0x00001000",
                    "status": "NEAR_MATCHING",
                    "delta": 12,
                    "similarity": 85.5,
                }
            },
        )
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT similarity FROM verify_results WHERE target = 'testbin' AND va = 4096")
        row = c.fetchone()
        conn.close()
        assert row is not None
        assert row[0] == pytest.approx(0.855)

    def test_verify_results_scales_one_percent_similarity(self, project_root: Path) -> None:
        """1.0 on the verify-cache percent scale is 1%, not a perfect match."""
        _write_cache(
            project_root,
            "testbin",
            {
                "0x00001000": {
                    "va": "0x00001000",
                    "status": "STUB",
                    "delta": 40,
                    "similarity": 1.0,
                }
            },
        )
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT similarity FROM verify_results WHERE target = 'testbin' AND va = 4096")
        row = c.fetchone()
        conn.close()
        assert row is not None
        assert row[0] == pytest.approx(0.01)

    def test_verify_results_unparseable_va_does_not_wipe(self, project_root: Path) -> None:
        """A cache whose every `va` fails to parse must NOT delete the
        target's history — the old prune built `va NOT IN ()`, which SQLite
        treats as vacuously TRUE and wiped ALL rows."""
        # Seed a row with a VALID cache entry first.
        _write_cache(
            project_root,
            "testbin",
            {"0x00001000": {"va": "0x00001000", "status": "EXACT", "delta": 3}},
        )
        build_db(project_root)
        # Rebuild with a cache whose VAs do not parse — the prune must not
        # wipe the previously-imported row.
        _write_cache(project_root, "testbin", {"0x00001000": {"va": None, "delta": 3}})
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM verify_results WHERE target = 'testbin'")
        assert c.fetchone()[0] == 1  # row survived despite the unparseable report
        conn.close()

    def test_verify_results_prune_past_sqlite_variable_limit(self, project_root: Path) -> None:
        """A cache with more VAs than SQLITE_MAX_VARIABLE_NUMBER must still
        import and prune stale rows (one bound parameter per VA overflowed)."""
        _write_cache(project_root, "testbin", {"0x1": {"va": "0x1", "delta": 1}})
        build_db(project_root)
        limit = sqlite3.connect(":memory:").getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER)
        entries = {hex(va): {"va": hex(va), "delta": 0} for va in range(0x10, 0x10 + limit + 1)}
        _write_cache(project_root, "testbin", entries)
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        try:
            count, stale = conn.execute(
                "SELECT COUNT(*), SUM(va = 1) FROM verify_results WHERE target = 'testbin'"
            ).fetchone()
        finally:
            conn.close()
        assert (count, stale) == (limit + 1, 0)

    @pytest.mark.parametrize("scoped", [False, True])
    @pytest.mark.parametrize("entries", [None, [], "invalid", 7, {}, "missing"])
    def test_verify_results_require_valid_empty_cache_to_clear(
        self, project_root: Path, scoped: bool, entries: Any
    ) -> None:
        _write_cache(project_root, "testbin", {"0x1000": {"va": "0x1000", "delta": 3}})
        build_db(project_root)
        _write_cache(project_root, "sibling", {"0x2000": {"va": "0x2000", "delta": 4}})
        (project_root / "db" / "data_sibling.json").write_text(
            json.dumps(SAMPLE_DATA), encoding="utf-8"
        )
        build_db(project_root)

        cache: dict[str, Any] = {"version": 2, "target": "testbin"}
        if entries != "missing":
            cache["entries"] = entries
        (project_root / ".rebrew" / "verify_cache.json").write_text(
            json.dumps(cache), encoding="utf-8"
        )
        build_db(project_root, target="testbin" if scoped else None)

        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        try:
            rows = conn.execute(
                "SELECT target, va, byte_delta FROM verify_results ORDER BY target"
            ).fetchall()
            expected = [("sibling", 0x2000, 4)]
            if entries != {}:
                expected.append(("testbin", 0x1000, 3))
            assert rows == expected
        finally:
            conn.close()

    def test_redundant_cells_section_index_absent(self, project_root: Path) -> None:
        """The UNIQUE (target, section_name, start) constraint already serves
        the (target, section_name) prefix — the old idx_cells_section was a
        redundant second index paid for on every cell insert."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_cells_section'")
        assert c.fetchone() is None  # not created, and any stale copy dropped
        conn.close()

    def test_stale_marker_index_dropped_on_scoped_rebuild(self, project_root: Path) -> None:
        """idx_functions_list serves every markerType filter; a scoped rebuild
        keeps the functions table, so an older DB's marker index must be dropped."""
        build_db(project_root)
        db_path = project_root / "db" / "coverage.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE INDEX idx_functions_marker ON functions(target, markerType)")
        conn.commit()
        conn.close()
        build_db(project_root, target="testbin")
        conn = sqlite3.connect(db_path)
        try:
            names = {
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
            }
            assert "idx_functions_marker" not in names
            assert "idx_functions_list" in names
            plan = conn.execute(
                "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM functions "
                "WHERE target = 'testbin' AND markerType NOT IN ('GLOBAL', 'DATA')"
            ).fetchall()
            assert any("idx_functions_list" in row[3] for row in plan)
        finally:
            conn.close()

    def test_section_cell_stats_has_primary_key(self, project_root: Path) -> None:
        """section_cell_stats must be keyed on (target, section_name) — CREATE
        TABLE AS SELECT left it without a PK so WHERE target=? was unindexed
        and duplicate section rows could accumulate."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("PRAGMA table_info(section_cell_stats)")
        pk_cols = [row[1] for row in c.fetchall() if row[5] > 0]
        assert pk_cols == ["target", "section_name"]
        c.execute("SELECT sql FROM sqlite_master WHERE name = 'section_cell_stats'")
        ddl = c.fetchone()[0]
        assert "PRIMARY KEY" in ddl
        assert "CREATE TABLE section_cell_stats" in ddl
        conn.close()

    def test_functions_status_has_check(self, project_root: Path) -> None:
        """functions.status must reject values outside KNOWN_STATUSES ∪ UNKNOWN."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='functions'")
        ddl = c.fetchone()[0]
        assert "CHECK (status IN (" in ddl
        assert "'UNKNOWN'" in ddl
        assert "'EXACT'" in ddl
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO functions (target, va, name, status) "
                "VALUES ('testbin', 99, 'bogus', 'NOT_A_STATUS')"
            )
        conn.close()

    def test_cells_state_has_check(self, project_root: Path) -> None:
        """cells.state must reject values outside the known cell-state set."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='cells'")
        ddl = c.fetchone()[0]
        assert "CHECK (state IN (" in ddl
        assert "'exact'" in ddl
        assert "'unknown'" in ddl
        # Need a parent section for the FK; reuse one from the fixture build.
        c.execute("SELECT target, name FROM sections LIMIT 1")
        sec = c.fetchone()
        assert sec is not None
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO cells (target, section_name, start, end, span, state) "
                "VALUES (?, ?, 99999, 100000, 1, 'not_a_state')",
                sec,
            )
        conn.close()

    def test_metadata_key_index_exists(self, project_root: Path) -> None:
        """key-first metadata lookups (targets list, legacy db_version) need
        idx_metadata_key — PK is (target, key) and cannot serve WHERE key=?."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_metadata_key'")
        assert c.fetchone() is not None
        conn.close()

    def test_verify_results_has_range_checks(self, project_root: Path) -> None:
        """verify_results columns that carry deltas/scores must reject out-of-
        range values at the schema level (and migrate pre-CHECK tables)."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='verify_results'")
        ddl = c.fetchone()[0]
        assert "effective_match IN (0, 1)" in ddl
        assert "similarity >= 0.0" in ddl
        assert "verified_at != ''" in ddl
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO verify_results "
                "(target, va, verified_at, byte_delta, similarity, effective_match) "
                "VALUES ('testbin', 1, 't', -1, 0.5, 1)"
            )
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO verify_results "
                "(target, va, verified_at, similarity) "
                "VALUES ('testbin', 2, 't', 1.5)"
            )
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO verify_results "
                "(target, va, verified_at, effective_match) "
                "VALUES ('testbin', 3, 't', 2)"
            )
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO verify_results (target, va, verified_at) VALUES ('testbin', 4, '')"
            )
        conn.close()

    def test_verify_results_migrates_pre_check_ddl(self, project_root: Path) -> None:
        """A persistent verify_results table built without CHECKs is recreated
        in place on the next rebuild (rows preserved, outliers clamped)."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        # Simulate a pre-CHECK table with a percent-scale similarity (85.5)
        # and negative deltas — migration must scale Sim% into [0,1] and
        # clamp the deltas rather than promoting 85.5 → 1.0.
        c.execute("DROP TABLE verify_results")
        c.execute(
            """
            CREATE TABLE verify_results (
                target TEXT NOT NULL,
                va INTEGER NOT NULL,
                verified_at TEXT NOT NULL,
                byte_delta INTEGER,
                diff_lines INTEGER,
                similarity REAL,
                reg_delta INTEGER,
                effective_match INTEGER,
                PRIMARY KEY (target, va)
            )
            """
        )
        c.execute("INSERT INTO verify_results VALUES ('testbin', 4096, 't', -3, NULL, 85.5, -1, 7)")
        conn.commit()
        conn.close()

        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='verify_results'")
        ddl = c.fetchone()[0]
        assert "effective_match IN (0, 1)" in ddl
        assert "verified_at != ''" in ddl
        # No verify cache in the fixture → the scaled legacy row is kept.
        c.execute(
            "SELECT byte_delta, similarity, reg_delta, effective_match "
            "FROM verify_results WHERE target = 'testbin' AND va = 4096"
        )
        row = c.fetchone()
        assert row == (0, pytest.approx(0.855), 0, None)
        conn.close()

    def test_functions_list_partial_index_exists(self, project_root: Path) -> None:
        """Dashboard / _function_stats exclude GLOBAL/DATA and ORDER BY va —
        idx_functions_list is the partial index that serves that path."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_functions_list'")
        row = c.fetchone()
        assert row is not None
        assert "markerType NOT IN ('GLOBAL', 'DATA')" in row[0]
        conn.close()

    def test_section_cells_agg_orders_by_start(self, project_root: Path) -> None:
        """SECTION_CELLS_AGG_SQL must emit cells in spatial order, not rowid."""
        from rebrew.workspace import SECTION_CELLS_AGG_SQL

        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("DELETE FROM cells WHERE target = 'testbin' AND section_name = '.text'")
        for start in (300, 100, 200):
            c.execute(
                "INSERT INTO cells "
                "(target, section_name, start, end, span, state, functions) "
                "VALUES ('testbin', '.text', ?, ?, 1, 'none', '[]')",
                (start, start + 10),
            )
        ordered = c.execute(
            f"SELECT {SECTION_CELLS_AGG_SQL} FROM cells "
            "WHERE target = 'testbin' AND section_name = '.text'"
        ).fetchone()[0]
        starts = [cell["start"] for cell in json.loads(ordered)]
        assert starts == [100, 200, 300]
        conn.close()

    def test_history_has_range_and_status_checks(self, project_root: Path) -> None:
        """history.va / status columns must reject out-of-range values."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='history'")
        ddl = c.fetchone()[0]
        assert "old_status IS NULL OR old_status IN" in ddl
        assert "CHECK (va >= 0)" in ddl
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO history (target, va, old_status, new_status, changed_at) "
                "VALUES ('testbin', -1, 'EXACT', 'RELOC', 't')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO history (target, va, old_status, new_status, changed_at) "
                "VALUES ('testbin', 1, 'NOT_A_STATUS', 'EXACT', 't')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO history (target, va, old_status, new_status, changed_at) "
                "VALUES ('testbin', 2, 'EXACT', 'RELOC', '')"
            )
        conn.close()

    def test_history_migrates_pre_check_ddl(self, project_root: Path) -> None:
        """A persistent history table built without CHECKs is recreated in
        place on the next rebuild (rows preserved, outliers clamped)."""
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("DROP TABLE history")
        c.execute(
            """
            CREATE TABLE history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                va INTEGER NOT NULL,
                old_status TEXT,
                new_status TEXT,
                changed_at TEXT NOT NULL,
                updated_by TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute(
            "INSERT INTO history (id, target, va, old_status, new_status, changed_at) "
            "VALUES (42, 'testbin', -7, 'BOGUS', 'EXACT', '')"
        )
        conn.commit()
        conn.close()

        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='history'")
        assert "old_status IS NULL OR old_status IN" in c.fetchone()[0]
        c.execute(
            "SELECT id, va, old_status, new_status, changed_at FROM history "
            "WHERE target = 'testbin' AND id = 42"
        )
        row = c.fetchone()
        assert row == (42, 0, "UNKNOWN", "EXACT", "1970-01-01T00:00:00+00:00")
        conn.close()

    def test_history_persists_across_rebuilds(self, project_root: Path) -> None:
        build_db(project_root)
        build_db(project_root)

        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='history'")
        row = c.fetchone()
        assert row is not None
        assert row[0] == "history"

        c.execute("SELECT COUNT(*) FROM history WHERE target = 'testbin'")
        assert c.fetchone()[0] == 0
        conn.close()

    def test_history_retention_caps_per_target(self, project_root: Path, monkeypatch) -> None:
        """history must not grow unboundedly across rebuilds — only the
        newest _HISTORY_RETENTION rows per target survive."""
        import rebrew.build_db as bdb

        # Tiny cap so the test inserts more than the limit without a huge
        # fixture; the prune SQL uses the module constant at run time.
        monkeypatch.setattr(bdb, "_HISTORY_RETENTION", 3)
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        now = "2026-01-01T00:00:00+00:00"
        rows = [("testbin", 0x1000 + i, "STUB", "EXACT", now) for i in range(8)]
        c.executemany(
            "INSERT INTO history (target, va, old_status, new_status, changed_at) "
            "VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        conn.close()
        # The rebuild applies the retention prune.
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM history WHERE target = 'testbin'")
        assert c.fetchone()[0] == 3  # newest 3 of 8 kept
        # The newest rows survive (highest id).
        c.execute("SELECT va FROM history WHERE target = 'testbin' ORDER BY id")
        vas = [r[0] for r in c.fetchall()]
        assert vas == [0x1005, 0x1006, 0x1007]
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
        assert summary["matchedFunctions"] == 2  # exact + reloc only
        assert summary["exactMatches"] == 1
        assert summary["nearMatchCount"] == 2
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

    def test_function_key_name_uses_va_start_decimal(self, tmp_path: Path) -> None:
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {},
            "globals": {},
            "summary": {},
            "functions": {
                "adler32": {
                    "name": "adler32",
                    "vaStart": "268439552",
                    "size": 64,
                    "status": "EXACT",
                }
            },
            "paths": {},
        }
        (db_dir / "data_alpha.json").write_text(json.dumps(data), encoding="utf-8")

        build_db(tmp_path)

        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT va FROM functions WHERE target = 'alpha' AND name = 'adler32'")
        row = c.fetchone()
        conn.close()
        assert row is not None
        assert row[0] == 268439552

    def test_data_section_negative_cell_size_is_clamped(self, tmp_path: Path) -> None:
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {
                ".data": {
                    "va": 0x10030000,
                    "size": 256,
                    "fileOffset": 0x3000,
                    "unitBytes": 64,
                    "columns": 64,
                    "cells": [
                        {
                            "start": 64,
                            "end": 32,
                            "span": 1,
                            "state": "exact",
                            "functions": ["g_bad"],
                        }
                    ],
                }
            },
            "globals": {},
            "summary": {},
            "functions": {
                "0x10001000": {
                    "name": "f",
                    "vaStart": "0x10001000",
                    "size": 16,
                    "status": "EXACT",
                }
            },
            "paths": {},
        }
        (db_dir / "data_alpha.json").write_text(json.dumps(data), encoding="utf-8")

        build_db(tmp_path)

        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT value FROM metadata WHERE target = 'alpha' AND key = 'summary'")
        row = c.fetchone()
        assert row is not None
        summary = json.loads(row[0])
        assert summary[".data"]["coveredBytes"] == 0

        c.execute("SELECT start, end FROM cells WHERE target = 'alpha' AND section_name = '.data'")
        cell = c.fetchone()
        conn.close()
        assert cell == (64, 64)

    def test_section_negative_extents_are_clamped(self, tmp_path: Path) -> None:
        """sections.va/size/fileOffset CHECK (>= 0) must not abort rebuild on
        a stray negative from hand-edited JSON — clamp like function rows."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {
                ".text": {
                    "va": -1,
                    "size": -64,
                    "fileOffset": -8,
                    "unitBytes": 64,
                    "columns": 64,
                    "cells": [],
                }
            },
            "globals": {},
            "summary": {},
            "functions": {
                "0x10001000": {
                    "name": "f",
                    "vaStart": "0x10001000",
                    "size": 16,
                    "status": "EXACT",
                }
            },
            "paths": {},
        }
        (db_dir / "data_alpha.json").write_text(json.dumps(data), encoding="utf-8")

        build_db(tmp_path)

        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute(
            "SELECT va, size, fileOffset FROM sections WHERE target = 'alpha' AND name = '.text'"
        )
        row = c.fetchone()
        conn.close()
        assert row == (0, 0, 0)

    def test_zero_unit_bytes_clamped(self, tmp_path: Path) -> None:
        """A stray unitBytes/columns of 0 in hand-edited JSON must not abort
        the whole rebuild — clamped to the default instead."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {
                ".text": {
                    "va": 0x10001000,
                    "size": 256,
                    "fileOffset": 0x1000,
                    "unitBytes": 0,
                    "columns": 0,
                    "cells": [],
                }
            },
            "globals": {},
            "summary": {},
            "functions": {},
            "paths": {},
        }
        (db_dir / "data_alpha.json").write_text(json.dumps(data), encoding="utf-8")

        build_db(tmp_path)  # must not raise IntegrityError

        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT unitBytes, columns FROM sections WHERE target = 'alpha'")
        row = c.fetchone()
        conn.close()
        assert row == (64, 64)

    def test_near_matching_cells_count_as_near_matches(self, tmp_path: Path) -> None:
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {
                ".text": {
                    "va": 0x10001000,
                    "size": 128,
                    "fileOffset": 0x1000,
                    "unitBytes": 64,
                    "columns": 64,
                    "cells": [
                        {
                            "start": 0,
                            "end": 64,
                            "span": 1,
                            "state": "near_matching",
                            "functions": ["f"],
                        }
                    ],
                }
            },
            "globals": {},
            "summary": {},
            "functions": {
                "0x10001000": {
                    "name": "f",
                    "vaStart": "0x10001000",
                    "size": 64,
                    "status": "NEAR_MATCHING",
                }
            },
            "paths": {},
        }
        (db_dir / "data_alpha.json").write_text(json.dumps(data), encoding="utf-8")

        build_db(tmp_path)

        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute(
            "SELECT near_match_count FROM section_cell_stats "
            "WHERE target = 'alpha' AND section_name = '.text'"
        )
        row = c.fetchone()
        conn.close()
        assert row == (1,)

    def test_data_verdict_cells_are_known_and_counted(self, tmp_path: Path, caplog: Any) -> None:
        """A grid cell carrying the lowercased rebrew-data.toml verdict
        (`verified`) must be a known state (no warning) and count as an exact
        data match, not fall into other_count."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {
                ".data": {
                    "va": 0x10030000,
                    "size": 128,
                    "fileOffset": 0x3000,
                    "unitBytes": 64,
                    "columns": 64,
                    "cells": [
                        {
                            "start": 0,
                            "end": 4,
                            "span": 1,
                            "state": "verified",
                            "functions": ["g_x"],
                        }
                    ],
                }
            },
            "globals": {
                "0x10030000": {"va": 0x10030000, "name": "g_x", "size": 4, "origin": "GAME"}
            },
            "summary": {},
            "functions": {},
            "paths": {},
        }
        (db_dir / "data_alpha.json").write_text(json.dumps(data), encoding="utf-8")

        with caplog.at_level("WARNING"):
            build_db(tmp_path)

        assert "not in known set" not in caplog.text
        conn = sqlite3.connect(db_dir / "coverage.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT * FROM section_cell_stats WHERE target = 'alpha' AND section_name = '.data'"
        )
        row = c.fetchone()
        c.execute("SELECT value FROM metadata WHERE target = 'alpha' AND key = 'summary'")
        summary = json.loads(c.fetchone()[0])
        conn.close()
        assert row["exact_count"] == 1
        assert row["other_count"] == 0
        counted = (
            row["exact_count"]
            + row["reloc_count"]
            + row["near_match_count"]
            + row["stub_count"]
            + row["padding_count"]
            + row["data_count"]
            + row["thunk_count"]
            + row["none_count"]
            + row["proven_count"]
            + row["size_mismatch_count"]
            + row["other_count"]
        )
        assert counted == row["total_cells"]
        assert summary[".data"]["exactMatches"] == 1

    def test_cells_reference_existing_sections(self, project_root: Path) -> None:
        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("PRAGMA foreign_key_list(cells)")
        rows = c.fetchall()
        conn.close()
        assert any(row[2] == "sections" for row in rows)

    def test_section_cells_json_references_sections(self, project_root: Path) -> None:
        """Derived cell-JSON cache must CASCADE with sections like cells do."""
        from rebrew.workspace import SECTION_CELLS_TABLE

        build_db(project_root)
        conn = sqlite3.connect(project_root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute(f"PRAGMA foreign_key_list({SECTION_CELLS_TABLE})")
        rows = c.fetchall()
        conn.close()
        assert any(row[2] == "sections" for row in rows)

    def test_duplicate_cell_starts_after_clamp_do_not_abort(
        self, tmp_path: Path, caplog: Any
    ) -> None:
        """A negative start clamped onto a real start=0 cell must not raise
        UNIQUE constraint failed — last row wins, rebuild completes."""
        import logging

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {
                ".text": {
                    "va": 0x10000000,
                    "size": 256,
                    "fileOffset": 0,
                    "unitBytes": 64,
                    "columns": 64,
                    "cells": [
                        {
                            "start": -1,
                            "end": 10,
                            "span": 1,
                            "state": "none",
                            "functions": [],
                        },
                        {
                            "start": 0,
                            "end": 10,
                            "span": 1,
                            "state": "exact",
                            "functions": ["f"],
                        },
                    ],
                }
            },
            "globals": {},
            "summary": {},
            "functions": {
                "0x10001000": {
                    "name": "f",
                    "vaStart": "0x10001000",
                    "size": 16,
                    "status": "EXACT",
                }
            },
            "paths": {},
        }
        (db_dir / "data_t.json").write_text(json.dumps(data), encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        try:
            rows = conn.execute(
                "SELECT start, state, functions FROM cells WHERE target = 't' ORDER BY start"
            ).fetchall()
            assert rows == [(0, "exact", '["f"]')]
        finally:
            conn.close()
        assert any("duplicate cell" in r.message for r in caplog.records)

    def test_duplicate_function_and_global_vas_do_not_abort(
        self, tmp_path: Path, caplog: Any
    ) -> None:
        """Keys spelling the same VA (hex and decimal) collide on the
        (target, va) primary key; last row wins, rebuild completes."""
        import logging

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {},
            "globals": {
                "0x10003000": {"name": "g_old", "size": 4},
                str(0x10003000): {"name": "g_new", "size": 4},
            },
            "summary": {},
            "functions": {
                "0x10001000": {"name": "f_old", "size": 16, "status": "STUB"},
                str(0x10001000): {"name": "f_new", "size": 16, "status": "EXACT"},
            },
            "paths": {},
        }
        (db_dir / "data_t.json").write_text(json.dumps(data), encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        try:
            fns = conn.execute("SELECT va, name, status FROM functions").fetchall()
            gls = conn.execute("SELECT va, name FROM globals").fetchall()
        finally:
            conn.close()
        assert fns == [(0x10001000, "f_new", "EXACT")]
        assert gls == [(0x10003000, "g_new")]
        assert sum("duplicate" in r.message for r in caplog.records) == 2


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

    def test_scoped_rebuild_keeps_verify_history(self, tmp_path: Path) -> None:
        """A scoped --target rebuild must not wipe that target's verify_results:
        the shared cache may name another target, in which case nothing is
        re-imported — and the full-rebuild path never drops the table
        (DB_FORMAT.md: 'never dropped on rebuild')."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()
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
        build_db(tmp_path)

        conn = sqlite3.connect(db_dir / "coverage.db")
        conn.execute(
            "INSERT OR REPLACE INTO verify_results "
            "(target, va, verified_at, byte_delta, diff_lines, similarity, "
            "reg_delta, effective_match) VALUES ('alpha', 4096, 't1', 0, 0, 1.0, 0, 1)"
        )
        conn.commit()
        conn.close()

        # The shared cache belongs to ANOTHER target → no re-import for alpha.
        _write_cache(tmp_path, "beta", {})
        build_db(tmp_path, target="alpha")

        conn = sqlite3.connect(db_dir / "coverage.db")
        rows = conn.execute("SELECT target, va FROM verify_results").fetchall()
        conn.close()
        assert ("alpha", 0x1000) in rows

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
        from typer import Exit as TyperExit

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data_testbin.json").write_text(json.dumps(SAMPLE_DATA), encoding="utf-8")

        with pytest.raises(TyperExit):
            build_db(tmp_path, target="nonexistent")

    def test_scoped_rebuild_preserves_other_targets(self, tmp_path: Path) -> None:
        """A --target rebuild must NOT drop other targets from an existing DB.

        Regression: the DROP TABLE statements were unconditional, so
        ``build-db --target X`` silently wiped every other target (only a
        warning was printed).  The scoped path must delete only X's rows.
        """
        db_dir = tmp_path / "db"
        db_dir.mkdir()

        def _data(name: str) -> dict[str, Any]:
            return {
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

        for name in ("alpha", "beta"):
            (db_dir / f"data_{name}.json").write_text(json.dumps(_data(name)), encoding="utf-8")

        # Full build first: both targets present.
        build_db(tmp_path, target=None)
        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM functions ORDER BY target")
        assert [r[0] for r in c.fetchall()] == ["alpha", "beta"]
        conn.close()

        # Scoped rebuild of alpha: beta must survive.
        build_db(tmp_path, target="alpha")
        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT DISTINCT target FROM functions ORDER BY target")
        targets = [r[0] for r in c.fetchall()]
        conn.close()
        assert targets == ["alpha", "beta"], f"--target rebuild dropped other targets: {targets}"


# ---------------------------------------------------------------------------
# E6: --force recreates on schema-version mismatch
# ---------------------------------------------------------------------------


def _write_stale_db(db_path: "Path", stale_version: str = "0") -> None:
    """Write a minimal DB with an outdated db_version stamp."""
    import sqlite3 as _sqlite3

    conn = _sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            target TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY (target, key)
        )
    """)
    c.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?, ?)",
        ("_schema", "db_version", json.dumps(stale_version)),
    )
    conn.commit()
    conn.close()


class TestBuildDbForceFlag:
    """Verify --force behaviour on schema-version mismatch."""

    def test_mismatch_without_force_raises(self, tmp_path: Path) -> None:
        """A stale DB without --force must raise Exit (error message)."""
        from typer import Exit as TyperExit

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data_testbin.json").write_text(json.dumps(SAMPLE_DATA), encoding="utf-8")

        db_path = db_dir / "coverage.db"
        _write_stale_db(db_path, stale_version="0")

        with pytest.raises(TyperExit):
            build_db(tmp_path, force=False)

    def test_mismatch_with_force_recreates(self, tmp_path: Path) -> None:
        """With --force the stale DB is deleted and rebuilt from scratch."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data_testbin.json").write_text(json.dumps(SAMPLE_DATA), encoding="utf-8")

        db_path = db_dir / "coverage.db"
        _write_stale_db(db_path, stale_version="0")

        build_db(tmp_path, force=True)

        # DB must exist and have the current version
        assert db_path.exists()
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT value FROM metadata WHERE key = 'db_version' LIMIT 1")
        row = c.fetchone()
        conn.close()
        assert row is not None
        from rebrew.build_db import _CURRENT_DB_VERSION

        assert json.loads(row[0]) == _CURRENT_DB_VERSION

    def test_no_mismatch_force_not_needed(self, project_root: Path) -> None:
        """When schema matches, build proceeds without --force (no error)."""
        build_db(project_root)  # Creates with current version
        # Second run: schema matches — should not error even without --force
        build_db(project_root, force=False)
        assert (project_root / "db" / "coverage.db").exists()


class TestBuildDbCorruptInput:
    """Corrupt or mis-shaped data_*.json must fail cleanly with file context."""

    def test_corrupt_json_errors_with_file_context(self, tmp_path: Path) -> None:
        from typer import Exit as TyperExit

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data_bad.json").write_text('{"functions": {"0x1000": {', encoding="utf-8")

        with pytest.raises(TyperExit):
            build_db(tmp_path)

    def test_non_object_json_errors_with_file_context(self, tmp_path: Path) -> None:
        """A valid-JSON-but-not-object file (e.g. a JSON array) must name the file."""
        from typer import Exit as TyperExit

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data_bad.json").write_text("[1, 2, 3]", encoding="utf-8")

        with pytest.raises(TyperExit):
            build_db(tmp_path)

    def test_unparseable_va_rows_skipped_with_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Rows with no parseable VA are skipped (no (target, 0) poison row),
        and the rebuild completes."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data_bad.json").write_text(
            json.dumps(
                {
                    "functions": {
                        "not-a-va": {"name": "bad", "size": 8, "status": "STUB"},
                        "also-bad": {"name": "bad2", "size": 8, "status": "STUB"},
                        "0x1000": {"name": "good", "size": 8, "status": "STUB"},
                    },
                    "globals": {},
                    "sections": {},
                    "summary": {},
                    "paths": {},
                }
            ),
            encoding="utf-8",
        )
        build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT va, name FROM functions WHERE target = 'bad'")
        rows = c.fetchall()
        conn.close()
        assert [(r[0], r[1]) for r in rows] == [(0x1000, "good")]
        assert "skipped 2" in capsys.readouterr().err

    def test_unparseable_key_falls_back_to_va_field(self, tmp_path: Path) -> None:
        """A bad key falls back to ``vaStart`` (functions) / ``va`` (globals)."""
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data_fb.json").write_text(
            json.dumps(
                {
                    "functions": {
                        "bad-key": {"name": "f", "vaStart": "0x2000", "size": 8, "status": "STUB"},
                    },
                    "globals": {
                        "bad-key": {"name": "g", "va": "4096", "size": 4},
                    },
                    "sections": {},
                    "summary": {},
                    "paths": {},
                }
            ),
            encoding="utf-8",
        )
        build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT va, name FROM functions WHERE target = 'fb'")
        functions = c.fetchall()
        c.execute("SELECT va, name FROM globals WHERE target = 'fb'")
        globals_ = c.fetchall()
        conn.close()
        assert functions == [(0x2000, "f")]
        assert globals_ == [(4096, "g")]
