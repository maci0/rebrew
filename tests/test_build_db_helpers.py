"""Tests for build_db.py pure helpers."""

import json
import sqlite3
from pathlib import Path

import pytest
import typer

from rebrew.build_db import (
    _function_stats,
    _normalize_cell_row,
    _parse_int,
    _resolve_db_dir,
)


class TestParseInt:
    def test_int_passthrough(self) -> None:
        assert _parse_int(42) == 42

    def test_hex_and_decimal_strings(self) -> None:
        assert _parse_int("0x10") == 16
        assert _parse_int("10") == 10

    def test_invalid_uses_default(self) -> None:
        assert _parse_int("zzz", default=7) == 7
        assert _parse_int(None, default=3) == 3


class TestNormalizeCellRow:
    def test_basic(self) -> None:
        row = _normalize_cell_row(
            "T", ".text", {"start": 0, "end": 64, "span": 64, "state": "exact"}
        )
        assert row[2] == 0
        assert row[3] == 64
        assert row[5] == "exact"

    def test_clamping(self) -> None:
        row = _normalize_cell_row("T", ".text", {"start": -5, "end": -1})
        assert row[2] == 0  # start clamped
        assert row[3] == 0  # end clamped to >= start
        assert row[4] == 1  # span floored

    def test_non_list_functions(self) -> None:
        row = _normalize_cell_row("T", ".text", {"functions": "not-a-list"})
        assert row[6] == "[]"

    def test_label_and_parent(self) -> None:
        row = _normalize_cell_row("T", ".text", {"label": "x", "parent_function": "f"})
        assert row[7] == "x"
        assert row[8] == "f"


class TestFunctionStats:
    def test_counts_and_coverage(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE functions (target TEXT, va INT, name TEXT, size INT, status TEXT, "
            "module TEXT, symbol TEXT, markerType TEXT, files TEXT)"
        )
        rows = [
            ("T", 0x1000, "a", 64, "EXACT", "GAME", "_a", "FUNCTION", "a.c"),
            ("T", 0x2000, "b", 32, "STUB", "GAME", "_b", "FUNCTION", "b.c"),
            ("T", 0x3000, "g", 16, "none", "GAME", "_g", "GLOBAL", "g.c"),
        ]
        conn.executemany("INSERT INTO functions VALUES (?,?,?,?,?,?,?,?,?)", rows)
        total, by_status, by_module, covered = _function_stats(conn.cursor(), "T")
        # GLOBAL/DATA rows are excluded by the query's markerType filter.
        assert total == 2
        assert by_status["EXACT"] == 1
        assert by_status["STUB"] == 1
        assert len(by_module["GAME"]) == 2
        assert covered == 64 + 32  # from the two FUNCTION rows
        conn.close()


class TestResolveDbDir:
    def test_no_config_falls_back_to_db(self, tmp_path: Path) -> None:
        assert _resolve_db_dir(tmp_path) == tmp_path / "db"

    def test_config_db_dir(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            "\n".join(
                [
                    "[project]",
                    'default_target = "main"',
                    'db_dir = "custom_db"',
                    "",
                    "[targets.main]",
                    'binary = "x.exe"',
                    'reversed_dir = "src"',
                ]
            ),
            encoding="utf-8",
        )
        assert _resolve_db_dir(tmp_path) == tmp_path / "custom_db"


class TestCheckDbVersion:
    def _db(self, tmp_path: Path, version: str | None) -> Path:
        import sqlite3

        db = tmp_path / "db" / "coverage.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db)
        if version is not None:
            conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
            conn.execute(
                "INSERT INTO metadata VALUES ('__schema__', 'db_version', ?)",
                (json.dumps(version),),
            )
            # The shape check (round-4) verifies required objects exist, not
            # just the version stamp — a version-matched DB must carry them.
            for name in (
                "sections",
                "cells",
                "functions",
                "globals",
                "verify_results",
                "history",
            ):
                conn.execute(f"CREATE TABLE {name} (id INTEGER)")
            conn.execute("CREATE VIEW section_cell_stats AS SELECT 1 AS x")
        conn.commit()
        conn.close()
        return db

    def test_version_mismatch_errors(self, tmp_path: Path) -> None:
        from rebrew.build_db import _check_db_version

        db = self._db(tmp_path, "999")
        with pytest.raises(typer.Exit):
            _check_db_version(db)

    def test_version_mismatch_force_deletes(self, tmp_path: Path) -> None:
        from rebrew.build_db import _check_db_version

        db = self._db(tmp_path, "999")
        _check_db_version(db, force=True)
        assert not db.exists()

    def test_missing_metadata_table_rebuilds(self, tmp_path: Path) -> None:
        """A DB file with no schema is rebuild debris (a failed build rolls
        back its DDL) — it must be unlinked for rebuild, not wedge every
        subsequent run behind --force."""
        from rebrew.build_db import _check_db_version

        db = self._db(tmp_path, None)  # no metadata table
        _check_db_version(db)  # warns and unlinks instead of raising
        assert not db.exists()

    def test_matching_version_passes(self, tmp_path: Path) -> None:
        from rebrew.build_db import _CURRENT_DB_VERSION, _check_db_version

        db = self._db(tmp_path, _CURRENT_DB_VERSION)
        _check_db_version(db)  # no raise
        # Matching version must leave the DB in place (force=False path).
        assert db.exists()

    def test_matching_version_missing_object_errors(self, tmp_path: Path) -> None:
        """A DB stamped with the current version but missing a required schema
        object must be rejected — the stamp alone is not proof of shape."""
        import sqlite3

        from rebrew.build_db import _CURRENT_DB_VERSION, _check_db_version

        db = self._db(tmp_path, _CURRENT_DB_VERSION)
        # Drop a required object after the fixture created the full shape.
        conn = sqlite3.connect(db)
        conn.execute("DROP TABLE history")
        conn.commit()
        conn.close()
        with pytest.raises(typer.Exit):
            _check_db_version(db)

    def test_non_json_version_string(self, tmp_path: Path) -> None:
        import sqlite3

        from rebrew.build_db import _check_db_version

        db = tmp_path / "db" / "coverage.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
        conn.execute("INSERT INTO metadata VALUES ('__schema__', 'db_version', 'plain-string')")
        conn.commit()
        conn.close()
        with pytest.raises(typer.Exit):
            _check_db_version(db)


class TestBuildDbEdgeData:
    def test_bad_va_strings_fall_back(self, tmp_path: Path) -> None:
        """Functions/globals with unparseable VAs degrade to 0 without crashing."""
        import sqlite3

        from rebrew.build_db import build_db

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {},
            "globals": {
                "bogus": {"name": "g_weird", "decl": "int g_weird;", "files": []},
            },
            "summary": {"totalFunctions": 1, "textSize": 64},
            "functions": {
                "f1": {
                    "name": "f1",
                    "vaStart": "not-a-va",
                    "size": 8,
                    "status": "STUB",
                },
            },
            "paths": {"originalDll": "/x.dll"},
        }
        (db_dir / "data_edge.json").write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        rows = conn.execute("SELECT va FROM functions").fetchall()
        conn.close()
        assert rows  # at least one row inserted with a fallback VA
