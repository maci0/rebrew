"""Tests for build_db.py pure helpers."""

import contextlib
import json
import logging
import sqlite3
from pathlib import Path

import pytest
import typer

from rebrew.build_db import (
    _clamp_nonneg_int,
    _clamp_unit_interval,
    _clamp_verify_similarity,
    _function_stats,
    _normalize_cell_row,
    _parse_int,
    resolve_db_dir,
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


class TestClampNonnegInt:
    def test_rejects_nonfinite_floats(self) -> None:
        """NaN/±inf must not become deltas (int(inf) raises; NaN→bound invents)."""
        assert _clamp_nonneg_int(float("nan")) is None
        assert _clamp_nonneg_int(float("inf")) is None
        assert _clamp_nonneg_int(float("-inf")) is None

    def test_clamps_negative(self) -> None:
        assert _clamp_nonneg_int(-3) == 0
        assert _clamp_nonneg_int(-1.5) == 0


class TestClampUnitInterval:
    def test_rejects_nonfinite(self) -> None:
        """NaN must not become 1.0 via max/min unordered-comparison quirk."""
        assert _clamp_unit_interval(float("nan")) is None
        assert _clamp_unit_interval(float("inf")) is None
        assert _clamp_unit_interval(float("-inf")) is None
        assert _clamp_unit_interval("nan") is None
        assert _clamp_unit_interval("NaN") is None
        assert _clamp_unit_interval("inf") is None
        assert _clamp_unit_interval("-inf") is None

    def test_clamps_finite_out_of_range(self) -> None:
        assert _clamp_unit_interval(1.5) == 1.0
        assert _clamp_unit_interval(-0.1) == 0.0
        assert _clamp_unit_interval("1.25") == 1.0
        assert _clamp_unit_interval(0.42) == 0.42


class TestClampVerifySimilarity:
    def test_scales_percent_scores(self) -> None:
        """Verify writes 0–100; DB stores 0–1 — 85.5 must not become 1.0."""
        assert _clamp_verify_similarity(85.5) == pytest.approx(0.855)
        assert _clamp_verify_similarity(100.0) == 1.0
        assert _clamp_verify_similarity(50) == 0.5
        assert _clamp_verify_similarity("72.5") == pytest.approx(0.725)

    def test_keeps_unit_interval(self) -> None:
        assert _clamp_verify_similarity(0.85) == 0.85
        assert _clamp_verify_similarity(0.0) == 0.0
        assert _clamp_verify_similarity(1.0) == 1.0

    def test_rejects_nonfinite_and_above_100(self) -> None:
        assert _clamp_verify_similarity(float("nan")) is None
        assert _clamp_verify_similarity(float("inf")) is None
        assert _clamp_verify_similarity(101.0) is None
        assert _clamp_verify_similarity(-0.1) == 0.0


class TestNormalizeCellRow:
    def test_basic(self) -> None:
        row = _normalize_cell_row(
            "T", ".text", {"start": 0, "end": 64, "span": 64, "state": "exact"}
        )
        assert row[2] == 0
        assert row[3] == 64
        assert row[5] == "exact"

    def test_unknown_state_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        """An out-of-set cell state (hand-edited JSON typo) must warn and
        coerce to ``unknown`` so the cells.state CHECK accepts the row
        (and it still lands in section_cell_stats.other_count)."""
        with caplog.at_level(logging.WARNING):
            row = _normalize_cell_row("T", ".text", {"state": "excat"})
        assert row[5] == "unknown"
        assert any("not in known set" in r.message for r in caplog.records)

    @pytest.mark.parametrize("state", ["extract_error", "invalid_va"])
    def test_persisted_function_statuses_are_known(self, state: str) -> None:
        """grid.py lowercases annotation STATUS into cell state; every
        KNOWN_STATUSES value (incl. EXTRACT_ERROR / INVALID_VA) must pass
        the sanitizer rather than being coerced to ``unknown``."""
        row = _normalize_cell_row("T", ".text", {"state": state})
        assert row[5] == state

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
        total, by_status, by_module, covered, matched = _function_stats(conn.cursor(), "T")
        # GLOBAL/DATA rows are excluded by the query's markerType filter.
        assert total == 2
        assert by_status["EXACT"] == 1
        assert by_status["STUB"] == 1
        assert len(by_module["GAME"]) == 2
        assert covered == 64 + 32  # identified: both FUNCTION rows
        assert matched == 64  # matched: EXACT/RELOC/PROVEN only (STUB excluded)
        conn.close()


class TestResolveDbDir:
    def test_no_config_falls_back_to_db(self, tmp_path: Path) -> None:
        assert resolve_db_dir(tmp_path) == tmp_path / "db"

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
        assert resolve_db_dir(tmp_path) == tmp_path / "custom_db"


class TestCheckDbVersion:
    def _db(self, tmp_path: Path, version: str | None) -> Path:
        import sqlite3

        db = tmp_path / "db" / "coverage.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db)
        if version is not None:
            # The shape check (round-4) verifies required objects AND the
            # query-critical columns — a version-matched DB must carry the
            # real schema, not just table names.
            conn.executescript(
                """
                CREATE TABLE metadata (target TEXT, key TEXT, value TEXT);
                CREATE TABLE sections (
                    target TEXT, name TEXT, va INTEGER, size INTEGER,
                    fileOffset INTEGER, unitBytes INTEGER, columns INTEGER
                );
                CREATE TABLE cells (
                    target TEXT, section_name TEXT, start INTEGER, end INTEGER,
                    span INTEGER, state TEXT, functions TEXT, label TEXT,
                    parent_function TEXT
                );
                CREATE TABLE functions (
                    target TEXT, va INTEGER, name TEXT, vaStart TEXT, size INTEGER,
                    fileOffset INTEGER, status TEXT, module TEXT, cflags TEXT,
                    symbol TEXT, markerType TEXT, ghidra_name TEXT, list_name TEXT,
                    is_thunk INTEGER, is_export INTEGER, sha256 TEXT, files TEXT,
                    detected_by TEXT, size_by_tool TEXT, textOffset INTEGER,
                    blocker TEXT, blockerDelta INTEGER, size_reason TEXT,
                    similarity REAL, updated_by TEXT, updated_at TEXT
                );
                CREATE TABLE globals (
                    target TEXT, va INTEGER, name TEXT, decl TEXT, files TEXT,
                    module TEXT, size INTEGER, status TEXT
                );
                CREATE TABLE verify_results (
                    target TEXT, va INTEGER, verified_at TEXT, byte_delta INTEGER,
                    diff_lines INTEGER, similarity REAL,
                    reg_delta INTEGER, effective_match INTEGER
                );
                CREATE TABLE history (
                    id INTEGER, target TEXT, va INTEGER, old_status TEXT,
                    new_status TEXT, changed_at TEXT, updated_by TEXT
                );
                CREATE VIEW section_cell_stats AS
                    SELECT target, section_name, COUNT(*) AS total_cells,
                    0 AS exact_count, 0 AS reloc_count, 0 AS near_match_count,
                    0 AS stub_count, 0 AS padding_count, 0 AS data_count,
                    0 AS thunk_count, 0 AS none_count, 0 AS proven_count,
                    0 AS size_mismatch_count, 0 AS other_count
                    FROM cells GROUP BY target, section_name;
                CREATE TABLE section_cells_json (
                    target TEXT, section_name TEXT, cells_zstd BLOB,
                    PRIMARY KEY (target, section_name)
                );
                """
            )
            conn.execute(
                "INSERT INTO metadata VALUES ('__schema__', 'db_version', ?)",
                (json.dumps(version),),
            )
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

    @pytest.mark.parametrize("force", [False, True])
    def test_missing_metadata_requires_force_to_delete(self, tmp_path: Path, force: bool) -> None:
        from rebrew.build_db import _check_db_version

        db = self._db(tmp_path, None)
        with contextlib.closing(sqlite3.connect(db)) as conn, conn:
            conn.execute("CREATE TABLE history (id INTEGER PRIMARY KEY, new_status TEXT)")
            conn.execute("INSERT INTO history VALUES (1, 'EXACT')")

        if force:
            _check_db_version(db, force=True)
            assert not db.exists()
        else:
            with pytest.raises(typer.Exit):
                _check_db_version(db)
            assert db.exists()
            with contextlib.closing(sqlite3.connect(db)) as conn:
                assert conn.execute("SELECT new_status FROM history").fetchall() == [("EXACT",)]

    @pytest.mark.parametrize("force", [False, True])
    @pytest.mark.parametrize("failed_connection", [1, 2])
    def test_read_error_never_deletes_database(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force: bool,
        failed_connection: int,
    ) -> None:
        from rebrew.build_db import _CURRENT_DB_VERSION, _check_db_version

        db = self._db(tmp_path, _CURRENT_DB_VERSION)
        original = db.read_bytes()
        connect = sqlite3.connect
        connections = 0

        def fail_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            nonlocal connections
            connections += 1
            if connections == failed_connection:
                raise sqlite3.OperationalError("disk I/O error")
            return connect(*args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", fail_connect)
        with pytest.raises(typer.Exit):
            _check_db_version(db, force=force)
        assert db.read_bytes() == original

    @pytest.mark.parametrize("force", [False, True])
    def test_corrupt_database_is_preserved(self, tmp_path: Path, force: bool) -> None:
        from rebrew.build_db import _check_db_version

        db = tmp_path / "coverage.db"
        original = b"not a SQLite database"
        db.write_bytes(original)
        with pytest.raises(typer.Exit):
            _check_db_version(db, force=force)
        assert db.read_bytes() == original

    @pytest.mark.parametrize("force", [False, True])
    def test_column_inspection_error_is_preserved(self, tmp_path: Path, force: bool) -> None:
        from rebrew.build_db import _CURRENT_DB_VERSION, _check_db_version

        db = self._db(tmp_path, _CURRENT_DB_VERSION)
        with contextlib.closing(sqlite3.connect(db)) as conn, conn:
            conn.execute("DROP VIEW section_cell_stats")
            conn.execute("CREATE VIEW section_cell_stats AS SELECT * FROM missing_table")
        original = db.read_bytes()
        with pytest.raises(typer.Exit):
            _check_db_version(db, force=force)
        assert db.read_bytes() == original

    def test_matching_version_passes(self, tmp_path: Path) -> None:
        from rebrew.build_db import _CURRENT_DB_VERSION, _check_db_version

        db = self._db(tmp_path, _CURRENT_DB_VERSION)
        _check_db_version(db)  # no raise
        # Matching version must leave the DB in place (force=False path).
        assert db.exists()

    def test_matching_version_missing_column_errors(self, tmp_path: Path) -> None:
        """A DB stamped with the current version but missing a query-critical
        column (e.g. functions.textOffset) must be rejected — the name-only
        check would pass it and the dashboard would 500 at query time."""
        import sqlite3

        from rebrew.build_db import _CURRENT_DB_VERSION, _check_db_version

        db = self._db(tmp_path, _CURRENT_DB_VERSION)
        conn = sqlite3.connect(db)
        conn.execute("ALTER TABLE functions DROP COLUMN textOffset")
        conn.commit()
        conn.close()
        with pytest.raises(typer.Exit):
            _check_db_version(db)

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
    def test_global_int_va_field_is_used(self, tmp_path: Path) -> None:
        """A global keyed by a name but carrying an int ``va`` (what the catalog
        emits) must be inserted at that VA — the old fallback called
        ``int(<int>, 16)`` and raised TypeError."""
        import sqlite3

        from rebrew.build_db import build_db

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {},
            "globals": {
                "g_weird": {
                    "name": "g_weird",
                    "va": 0x2000,
                    "decl": "int g_weird;",
                    "files": [],
                },
                "no_va": {"name": "g_gone", "decl": "int g_gone;", "files": []},
            },
            "summary": {"totalFunctions": 0, "textSize": 0},
            "functions": {},
            "paths": {"originalDll": "/x.dll"},
        }
        (db_dir / "data_edge.json").write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        rows = conn.execute("SELECT va, name FROM globals ORDER BY va").fetchall()
        conn.close()
        # The int-va entry lands at its real VA; the unusable one is skipped
        # (never a (target, 0) poison row).
        assert [(r[0], r[1]) for r in rows] == [(0x2000, "g_weird")]

    def test_bad_va_strings_skipped(self, tmp_path: Path) -> None:
        """Functions with unparseable VAs are skipped with a warning — never
        inserted as a (target, 0) poison row, and never aborting the rebuild."""
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
                "0x1000": {
                    "name": "good",
                    "size": 8,
                    "status": "STUB",
                },
            },
            "paths": {"originalDll": "/x.dll"},
        }
        (db_dir / "data_edge.json").write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        rows = conn.execute("SELECT va, name FROM functions").fetchall()
        conn.close()
        assert [(r[0], r[1]) for r in rows] == [(0x1000, "good")]

    def test_function_status_canonicalized_and_unknown_coerced(self, tmp_path: Path) -> None:
        """Lowercase / NEAR_MATCH aliases canonicalize; typos become UNKNOWN
        so the functions.status CHECK never aborts a rebuild."""
        import sqlite3

        from rebrew.build_db import build_db

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {},
            "globals": {},
            "summary": {"totalFunctions": 3, "textSize": 24},
            "functions": {
                "0x1000": {"name": "a", "size": 8, "status": "exact"},
                "0x2000": {"name": "b", "size": 8, "status": "NEAR_MATCH"},
                "0x3000": {"name": "c", "size": 8, "status": "TYPO_STATUS"},
            },
            "paths": {"originalDll": "/x.dll"},
        }
        (db_dir / "data_edge.json").write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        rows = conn.execute("SELECT va, status FROM functions ORDER BY va").fetchall()
        conn.close()
        assert rows == [
            (0x1000, "EXACT"),
            (0x2000, "NEAR_MATCHING"),
            (0x3000, "UNKNOWN"),
        ]

    def test_bool_size_does_not_become_one(self, tmp_path: Path) -> None:
        """bool is an int subclass; True must not land as size=1 under CHECK."""
        import sqlite3

        from rebrew.build_db import build_db

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {},
            "globals": {},
            "summary": {"totalFunctions": 1, "textSize": 0},
            "functions": {
                "0x1000": {
                    "name": "a",
                    "size": True,
                    "fileOffset": False,
                    "status": "STUB",
                },
            },
            "paths": {"originalDll": "/x.dll"},
        }
        (db_dir / "data_edge.json").write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        conn = sqlite3.connect(db_dir / "coverage.db")
        row = conn.execute(
            "SELECT size, fileOffset FROM functions WHERE va = ?", (0x1000,)
        ).fetchone()
        conn.close()
        assert row == (None, None)

    def test_bad_va_warning_names_target(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Warnings must name the target, not a leaked json_path from an
        earlier load loop (wrong on multi-target; NameError under --regen)."""
        from rebrew.build_db import build_db

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        data = {
            "sections": {},
            "globals": {},
            "summary": {},
            "functions": {
                "not-a-va": {"name": "bad", "size": 8, "status": "STUB"},
                "0x1000": {"name": "good", "size": 8, "status": "STUB"},
            },
            "paths": {},
        }
        (db_dir / "data_edge.json").write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        err = capsys.readouterr().err
        assert "edge:" in err
        assert "skipped 1" in err
        assert "data_edge.json" not in err
