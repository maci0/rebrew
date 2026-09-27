"""Tests for rebrew dashboard — read-only web dashboard over coverage.db."""

import gzip
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.build_db import build_db
from rebrew.dashboard import (
    _APP_JS,
    _APP_JS_URL,
    _APP_JS_VERSION,
    _BOOT_GUARD_JS,
    _BOOT_GUARD_JS_VERSION,
    _BOOTSTRAP_FUNCTION_LIMIT,
    _DEFAULT_LIMIT,
    Dashboard,
    _DashboardServer,
    _files_display,
)


class _NullWFile:
    """Swallow the response body of a handler built without a socket."""

    def write(self, data: bytes) -> int:
        return len(data)


def _run_script(script: str, **env: str) -> None:
    """Run a tests/dashboard_*.mjs interaction script against the dashboard JS."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for dashboard interaction tests")
    environ = os.environ.copy()
    environ.update(env)
    result = subprocess.run(
        [node, str(Path(__file__).with_name(script))],
        input=_APP_JS,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        env=environ,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _write_data(db_dir: Path, target: str = "server_dll") -> Path:
    db_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "functions": {
            "0x10001000": {
                "name": "func_a",
                "vaStart": "0x10001000",
                "size": 64,
                "status": "EXACT",
                "module": "SERVER",
                "symbol": "_func_a",
                "files": ["a.c"],
                "markerType": "FUNCTION",
            },
            "0x10002000": {
                "name": "func_b",
                "vaStart": "0x10002000",
                "size": 32,
                "status": "STUB",
                "module": "SERVER",
                "symbol": "_func_b",
                "files": ["b.c"],
                "markerType": "FUNCTION",
            },
        },
        "globals": {
            "0x50001000": {
                "name": "g_flag",
                "decl": "int g_flag;",
                "size": 4,
                "module": "SERVER",
            }
        },
        "sections": {
            ".text": {
                "va": 0x10001000,
                "size": 128,
                "fileOffset": 0x400,
                "unitBytes": 16,
                "columns": 8,
                "cells": [
                    {
                        "start": 0x10001000,
                        "end": 0x10001040,
                        "span": 16,
                        "state": "exact",
                        "functions": [{"va": 0x10001000}],
                    },
                    {
                        "start": 0x10001040,
                        "end": 0x10001060,
                        "span": 16,
                        "state": "stub",
                        "functions": [{"va": 0x10002000}],
                    },
                    {
                        "start": 0x10001060,
                        "end": 0x10001070,
                        "span": 16,
                        "state": "proven",
                        "functions": [],
                    },
                    {
                        "start": 0x10001070,
                        "end": 0x10001080,
                        "span": 16,
                        "state": "size_mismatch",
                        "functions": [],
                    },
                    {
                        "start": 0x10001080,
                        "end": 0x10001090,
                        "span": 16,
                        "state": "compile_error",
                        "functions": [],
                    },
                ],
            },
            ".data": {
                "va": 0x50001000,
                "size": 16,
                "fileOffset": 0x1000,
                "unitBytes": 4,
                "columns": 4,
                "cells": [
                    {
                        "start": 0x50001000,
                        "end": 0x50001004,
                        "span": 4,
                        "state": "data",
                        "functions": [],
                    }
                ],
            },
        },
        "summary": {"total_functions": 2, "total_bytes": 128},
        "paths": {"a.c": "src/a.c"},
    }
    path = db_dir / f"data_{target}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def dashboard(tmp_path: Path) -> Dashboard:
    _write_data(tmp_path / "db")
    build_db(tmp_path)
    return Dashboard(tmp_path / "db" / "coverage.db")


class TestQueryLayer:
    def test_targets(self, dashboard: Dashboard) -> None:
        assert dashboard.targets() == ["server_dll"]

    def test_conn_closes_on_success_and_error(self, dashboard: Dashboard) -> None:
        """The connection must be released on every exit path — under the
        threaded HTTP server a GC-only release pins one handle per request."""
        import sqlite3

        with dashboard._conn() as conn:
            conn.execute("SELECT 1")
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")

        with pytest.raises(RuntimeError), dashboard._conn() as conn2:
            raise RuntimeError("boom")
        with pytest.raises(sqlite3.ProgrammingError):
            conn2.execute("SELECT 1")

    def test_nested_queries_share_one_connection(self, dashboard: Dashboard) -> None:
        """First paint and target-scoped routes must not open a handle per query."""
        import sqlite3
        from unittest.mock import patch

        orig = sqlite3.connect
        counts = {"n": 0}

        def counting(*args: object, **kwargs: object) -> sqlite3.Connection:
            counts["n"] += 1
            return orig(*args, **kwargs)

        with patch("sqlite3.connect", counting):
            counts["n"] = 0
            dashboard.bootstrap()
            assert counts["n"] == 1

            counts["n"] = 0
            dashboard.handle("GET", "/api/functions", {"target": ["server_dll"]})
            assert counts["n"] == 1

            counts["n"] = 0
            dashboard.handle("GET", "/api/summary", {"target": ["server_dll"]})
            assert counts["n"] == 1

    def test_summary(self, dashboard: Dashboard) -> None:
        s = dashboard.summary("server_dll")
        assert s is not None
        assert s["function_stats"]["total"] == 2
        assert s["function_stats"]["by_status"] == {"EXACT": 1, "STUB": 1}
        # Headline coverage = MATCHED bytes only (EXACT/RELOC): the
        # EXACT function's 64B of 128B .text = 50%.  The STUB counts toward
        # identified_pct (96/128 = 75%), not matched (the old
        # coverage_pct counted every function, so an all-STUB binary showed
        # ~100% "coverage").
        assert s["coverage_pct"] == 50.0
        assert s["identified_pct"] == 75.0

    def test_summary_unknown_target(self, dashboard: Dashboard) -> None:
        assert dashboard.summary("nope") is None

    def test_summary_corrupt_function_stats_returns_none(self, tmp_path: Path) -> None:
        """Corrupt metadata must not present as a real empty/0% summary."""
        import sqlite3

        db = tmp_path / "coverage.db"
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE functions (target TEXT, va INT, name TEXT, symbol TEXT, "
                "size INT, status TEXT, module TEXT, files TEXT, markerType TEXT)"
            )
            conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
            conn.execute("INSERT INTO metadata VALUES ('broken', 'function_stats', '{not-json')")
        dashboard = Dashboard(db)
        assert dashboard.summary("broken") is None
        assert dashboard._summary_lookup("broken") == ("corrupt", None)

    def test_api_summary_corrupt_function_stats_500(self, tmp_path: Path) -> None:
        """Present-but-unreadable stats must not look like an unknown target."""
        import sqlite3

        db = tmp_path / "coverage.db"
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE functions (target TEXT, va INT, name TEXT, symbol TEXT, "
                "size INT, status TEXT, module TEXT, files TEXT, markerType TEXT)"
            )
            conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
            conn.execute("INSERT INTO metadata VALUES ('broken', 'function_stats', '{not-json')")
            conn.execute("INSERT INTO metadata VALUES ('notobj', 'function_stats', '[1, 2]')")
        dashboard = Dashboard(db)
        status, _, body = dashboard.handle("GET", "/api/summary", {"target": ["broken"]})
        assert status == 500
        assert json.loads(body) == {
            "error": "corrupt function_stats metadata",
            "code": "corrupt_function_stats",
        }
        status, _, body = dashboard.handle("GET", "/api/summary", {"target": ["notobj"]})
        assert status == 500
        assert "corrupt" in json.loads(body)["error"]
        # Sibling list route still treats the target as known.
        status, _, body = dashboard.handle("GET", "/api/functions", {"target": ["broken"]})
        assert status == 200
        assert json.loads(body)["target"] == "broken"

    def test_api_summary_non_numeric_byte_count_is_corrupt(self, tmp_path: Path) -> None:
        """A non-numeric byte count answers the documented corrupt 500, and
        bootstrap degrades to ``summary: null`` instead of failing whole."""
        import sqlite3

        db = tmp_path / "coverage.db"
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE functions (target TEXT, va INT, name TEXT, symbol TEXT, "
                "size INT, status TEXT, module TEXT, files TEXT, markerType TEXT)"
            )
            conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
            for target, stats in (
                ("a_text", '{"total_bytes": "lots"}'),
                ("b_nan", '{"total_bytes": NaN}'),
                ("c_inf", '{"matched_bytes": Infinity, "total_bytes": 10}'),
                ("d_list", '{"covered_bytes": [1], "total_bytes": 10}'),
                ("e_bool", '{"matched_bytes": true, "total_bytes": 10}'),
                ("f_false", '{"matched_bytes": false, "total_bytes": 10}'),
                ("g_frac", '{"matched_bytes": 1.5, "total_bytes": 10}'),
                ("h_float", '{"matched_bytes": 10.0, "total_bytes": 10}'),
                ("i_neg", '{"matched_bytes": -1, "total_bytes": 10}'),
                ("j_str", '{"matched_bytes": "12", "total_bytes": 10}'),
                ("z_ok", '{"matched_bytes": 0, "total_bytes": 10}'),
            ):
                conn.execute(
                    "INSERT INTO metadata VALUES (?, 'function_stats', ?)", (target, stats)
                )
        dashboard = Dashboard(db)
        for target in (
            "a_text",
            "b_nan",
            "c_inf",
            "d_list",
            "e_bool",
            "f_false",
            "g_frac",
            "h_float",
            "i_neg",
            "j_str",
        ):
            status, _, body = dashboard.handle("GET", "/api/summary", {"target": [target]})
            assert status == 500, target
            assert json.loads(body) == {
                "error": "corrupt function_stats metadata",
                "code": "corrupt_function_stats",
            }
        status, _, body = dashboard.handle("GET", "/api/summary", {"target": ["z_ok"]})
        assert status == 200
        assert json.loads(body)["coverage_pct"] == 0.0
        status, _, body = dashboard.handle("GET", "/api/bootstrap", {})
        assert status == 200
        boot = json.loads(body)
        assert boot["target"] == "a_text"
        assert boot["summary"] is None
        assert boot["functions"] is None

    def test_functions_all(self, dashboard: Dashboard) -> None:
        data = dashboard.functions("server_dll")
        assert data["total"] == 2
        assert data["cols"] == ["va", "name", "symbol", "size", "status", "module", "files"]
        assert data["functions"][0][0] == "0x10001000"
        assert data["functions"][0][6] == "a.c"

    def test_files_display_skips_json_loads_for_common_cells(self) -> None:
        assert _files_display(None) == ""
        assert _files_display("[]") == ""
        assert _files_display('["a.c"]') == "a.c"
        assert _files_display('["a.c", "b.h"]') == "a.c, b.h"
        assert _files_display('["a.c","b.h"]') == "a.c, b.h"
        assert _files_display(r'["dir\\file.c"]') == r"dir\file.c"

    def test_functions_status_filter(self, dashboard: Dashboard) -> None:
        data = dashboard.functions("server_dll", status="STUB")
        assert data["count"] == 1
        assert data["total"] == 1
        assert data["functions"][0][1] == "func_b"
        assert data["functions"][0][4] == "STUB"

    def test_functions_module_filter(self, dashboard: Dashboard) -> None:
        data = dashboard.functions("server_dll", module="SERVER")
        assert data["count"] == 2
        assert data["total"] == 2
        assert {row[5] for row in data["functions"]} == {"SERVER"}
        empty = dashboard.functions("server_dll", module="NOPE")
        assert empty["count"] == 0
        assert empty["total"] == 0
        assert empty["functions"] == []

    def test_functions_search(self, dashboard: Dashboard) -> None:
        data = dashboard.functions("server_dll", q="func_a")
        assert data["count"] == 1
        assert data["functions"][0][2] == "_func_a"

    def test_functions_search_by_address(self, dashboard: Dashboard) -> None:
        """A hex address finds the function when the name does not contain it."""
        for q in ("0x10001000", "0X10001000", "10001000", "010001000"):
            data = dashboard.functions("server_dll", q=q)
            assert data["total"] == 1, q
            assert data["functions"][0][1] == "func_a"
        # The address filter composes with status: func_a is EXACT, not STUB.
        assert dashboard.functions("server_dll", status="STUB", q="0x10001000")["total"] == 0
        assert dashboard.functions("server_dll", status="EXACT", q="0x10001000")["total"] == 1
        # Three hex digits stay a name search, so ``add`` is not address 0xadd.
        assert dashboard.functions("server_dll", q="add")["total"] == 0

    def test_sections(self, dashboard: Dashboard) -> None:
        payload = dashboard.sections("server_dll")
        sections = payload["sections"]
        assert payload["count"] == len(sections)
        assert payload["total"] == len(sections)
        # Rows ship positionally; name every column through ``cols``.
        named = [dict(zip(payload["cols"], row, strict=True)) for row in sections]
        by_name = {row["name"]: row for row in named}
        assert by_name[".text"]["exact"] == 1
        assert by_name[".text"]["stub"] == 1
        assert by_name[".text"]["size"] == 128
        assert by_name[".data"]["data"] == 1
        # All 14 view columns surface: proven/size_mismatch/other are real
        # columns, not dropped.
        assert by_name[".text"]["proven"] == 1
        assert by_name[".text"]["size_mismatch"] == 1
        assert by_name[".text"]["other"] == 1
        assert by_name[".text"]["total_cells"] == (
            by_name[".text"]["exact"]
            + by_name[".text"]["reloc"]
            + by_name[".text"]["near_match"]
            + by_name[".text"]["stub"]
            + by_name[".text"]["padding"]
            + by_name[".text"]["data"]
            + by_name[".text"]["thunk"]
            + by_name[".text"]["none"]
            + by_name[".text"]["proven"]
            + by_name[".text"]["size_mismatch"]
            + by_name[".text"]["other"]
        )

    def test_globals(self, dashboard: Dashboard) -> None:
        data = dashboard.globals("server_dll")
        assert data["count"] == 1
        assert data["total"] == 1
        assert data["globals"][0][1] == "g_flag"
        assert data["globals"][0][0] == "0x50001000"
        assert data["cols"] == ["va", "name", "decl", "size", "module"]

    def test_globals_search_by_address(self, dashboard: Dashboard) -> None:
        for q in ("0x50001000", "50001000"):
            data = dashboard.globals("server_dll", q=q)
            assert data["total"] == 1, q
            assert data["globals"][0][1] == "g_flag"

    def test_history_empty(self, dashboard: Dashboard) -> None:
        hist = dashboard.history("server_dll")
        assert hist["history"] == []
        assert hist["count"] == 0
        assert hist["total"] == 0

    def test_history_rows_carry_function_name(self, tmp_path: Path) -> None:
        """History rows name the function so a bare VA is not the only cue."""
        import sqlite3

        _write_data(tmp_path / "db")
        build_db(tmp_path)
        db_path = tmp_path / "db" / "coverage.db"
        with sqlite3.connect(db_path) as conn:
            conn.executemany(
                "INSERT INTO history (target, va, old_status, new_status, changed_at) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    ("server_dll", 0x10002000, "STUB", "EXACT", "2026-01-01T00:00:00Z"),
                    ("server_dll", 0x10009000, "STUB", "EXACT", "2026-01-02T00:00:00Z"),
                ],
            )
            conn.commit()
        rows = Dashboard(db_path).history("server_dll")["history"]
        assert rows == [
            ["0x10009000", "", "STUB", "EXACT", "2026-01-02T00:00:00Z"],
            ["0x10002000", "func_b", "STUB", "EXACT", "2026-01-01T00:00:00Z"],
        ]

    def test_history_null_status_is_an_empty_string(self, tmp_path: Path) -> None:
        """A VA's first recorded transition has NULL old_status.

        Every text column in a row under ``cols`` is a string, so a client
        reading rows never has to null-check this route and not the others.
        """
        import sqlite3

        _write_data(tmp_path / "db")
        build_db(tmp_path)
        db_path = tmp_path / "db" / "coverage.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO history (target, va, old_status, new_status, changed_at) "
                "VALUES ('server_dll', 0x10001000, NULL, 'EXACT', '2026-01-01T00:00:00Z')"
            )
            conn.commit()
        rows = Dashboard(db_path).history("server_dll")["history"]
        assert rows == [["0x10001000", "func_a", "", "EXACT", "2026-01-01T00:00:00Z"]]

    def test_functions_list_uses_partial_index(
        self, dashboard: Dashboard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The unfiltered list query must be served by idx_functions_list."""
        import sqlite3

        import rebrew.dashboard as dashboard_mod

        statements: list[str] = []
        real_open = dashboard_mod.open_sqlite_ro

        def _traced_open(path: Path) -> sqlite3.Connection:
            conn = real_open(path)
            conn.set_trace_callback(statements.append)
            return conn

        monkeypatch.setattr(dashboard_mod, "open_sqlite_ro", _traced_open)
        dashboard.functions("server_dll")
        list_sql = next(s for s in statements if s.startswith("SELECT va, name"))
        with sqlite3.connect(dashboard.db_path) as conn:
            plan = conn.execute(f"EXPLAIN QUERY PLAN {list_sql}").fetchall()
        assert any("idx_functions_list" in row[3] for row in plan)
        assert not any("TEMP B-TREE" in row[3] for row in plan)

    @pytest.mark.parametrize(
        ("kwargs", "index"),
        [
            ({"status": "EXACT"}, "idx_functions_status_va"),
            ({"module": "SERVER"}, "idx_functions_module_va"),
        ],
    )
    def test_filtered_functions_list_seeks_filter_index(
        self,
        dashboard: Dashboard,
        monkeypatch: pytest.MonkeyPatch,
        kwargs: dict[str, str],
        index: str,
    ) -> None:
        """A status/module page seeks its filter index and needs no sort."""
        import sqlite3

        import rebrew.dashboard as dashboard_mod

        statements: list[str] = []
        real_open = dashboard_mod.open_sqlite_ro

        def _traced_open(path: Path) -> sqlite3.Connection:
            conn = real_open(path)
            conn.set_trace_callback(statements.append)
            return conn

        monkeypatch.setattr(dashboard_mod, "open_sqlite_ro", _traced_open)
        dashboard.functions("server_dll", **kwargs)
        list_sql = next(s for s in statements if s.startswith("SELECT va, name"))
        with sqlite3.connect(dashboard.db_path) as conn:
            plan = conn.execute(f"EXPLAIN QUERY PLAN {list_sql}").fetchall()
        assert any(index in row[3] for row in plan)
        assert not any("TEMP B-TREE" in row[3] for row in plan)

    def test_filtered_globals_list_seeks_filter_index(
        self,
        dashboard: Dashboard,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A module-filtered globals page seeks idx_globals_module_va and needs no sort."""
        import sqlite3

        import rebrew.dashboard as dashboard_mod

        statements: list[str] = []
        real_open = dashboard_mod.open_sqlite_ro

        def _traced_open(path: Path) -> sqlite3.Connection:
            conn = real_open(path)
            conn.set_trace_callback(statements.append)
            return conn

        monkeypatch.setattr(dashboard_mod, "open_sqlite_ro", _traced_open)
        dashboard.globals("server_dll", module="SERVER")
        list_sql = next(s for s in statements if s.startswith("SELECT va, name, decl"))
        with sqlite3.connect(dashboard.db_path) as conn:
            plan = conn.execute(f"EXPLAIN QUERY PLAN {list_sql}").fetchall()
        assert any("idx_globals_module_va" in row[3] for row in plan)
        assert not any("TEMP B-TREE" in row[3] for row in plan)

    def test_functions_total_excludes_global_markers(self, tmp_path: Path) -> None:
        """total must apply the same markerType filter as the row query."""
        db_dir = tmp_path / "db"
        _write_data(db_dir)
        # Inject a GLOBAL row so an unfiltered COUNT would over-report.
        build_db(tmp_path)
        import sqlite3

        db_path = db_dir / "coverage.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO functions (target, va, name, size, status, module, symbol, "
                "markerType, files) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "server_dll",
                    0x50002000,
                    "g_extra",
                    4,
                    "STUB",
                    "SERVER",
                    "_g_extra",
                    "GLOBAL",
                    "[]",
                ),
            )
            conn.commit()
        dash = Dashboard(db_path)
        data = dash.functions("server_dll")
        assert data["count"] == 2
        assert data["total"] == 2  # not 3

    def test_vtable_and_string_markers_are_not_functions(self, tmp_path: Path) -> None:
        """VTABLE/STRING rows are data: neither listed nor counted in function_stats."""
        db_dir = tmp_path / "db"
        path = _write_data(db_dir)
        data = json.loads(path.read_text(encoding="utf-8"))
        for va, marker in (("0x50003000", "VTABLE"), ("0x50004000", "STRING")):
            data["functions"][va] = {
                "name": f"d_{marker.lower()}",
                "vaStart": va,
                "size": 16,
                "status": "EXACT",
                "module": "SERVER",
                "files": ["d.c"],
                "markerType": marker,
            }
        path.write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        dash = Dashboard(db_dir / "coverage.db")
        listed = dash.functions("server_dll")
        assert [row[1] for row in listed["functions"]] == ["func_a", "func_b"]
        assert listed["total"] == 2
        summary = dash.summary("server_dll")
        assert summary is not None
        assert summary["function_stats"]["total"] == 2
        assert summary["function_stats"]["covered_bytes"] == 96


class TestSummaryRequests:
    def test_latest_summary_wins(self) -> None:
        _run_script("dashboard_summary.mjs")


class TestHashState:
    def test_reload_restores_target_view_and_filters(self) -> None:
        _run_script("dashboard_hash_state.mjs")

    def test_restored_target_loads_summary_functions_and_view_in_parallel(self) -> None:
        _run_script("dashboard_parallel_boot.mjs")


class TestFocusManagement:
    def test_show_more_keeps_keyboard_focus(self) -> None:
        _run_script("dashboard_focus.mjs")


class TestListReset:
    def test_fresh_load_drops_stale_rows_and_title_names_the_target(self) -> None:
        _run_script("dashboard_list_reset.mjs")


class TestLoadErrors:
    def test_error_messages_carry_the_server_reason(self) -> None:
        _run_script("dashboard_errors.mjs")


class TestHistoryClock:
    def test_zone_less_instants_and_fallback_hour(self) -> None:
        _run_script("dashboard_time.mjs", TZ="America/New_York")


class TestReload:
    def test_reload_rereads_the_database(self) -> None:
        _run_script("dashboard_reload.mjs")


class TestHandle:
    def test_index_html(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("GET", "/", {})
        assert status == 200
        assert "text/html" in content_type
        assert "Rebrew coverage" in body

    def test_index_html_has_accessible_structure(self, dashboard: Dashboard) -> None:
        _, _, html = dashboard.handle("GET", "/", {})
        _, _, js = dashboard.handle("GET", "/app.js", {})
        body = html + js
        assert f'<script src="/app.js?v={_APP_JS_VERSION}" defer></script>' in html
        assert f'rel="preload" href="/app.js?v={_APP_JS_VERSION}" as="script"' in html
        assert 'fetchpriority="high"' in html
        assert "content-visibility: auto" in html
        assert "const $" in js
        assert '<main id="main" tabindex="-1">' in body
        assert 'href="#main"' in body
        assert "Skip to content" in body
        assert 'lang="en"' in body
        assert '<label for="q">Search name, symbol, or address</label>' in body
        assert '<label for="module">Module</label>' in body
        assert '<label for="gq">Search name or address</label>' in body
        assert 'role="group" aria-label="Coverage filters"' in body
        assert 'role="group" aria-label="Coverage metrics"' in body
        assert 'id="boot-status" role="status"' in body
        # Without JS the shell must not sit on "Loading coverage…" forever.
        assert "<noscript><style>#boot-status { display: none; }</style></noscript>" in body
        assert '<noscript><p id="no-script">The dashboard needs JavaScript' in body
        assert 'role="status" aria-live="polite"' in body
        assert 'id="dashboard-error" role="alert" hidden' in body
        assert '<caption class="visually-hidden">' in body
        assert body.count('scope="col"') >= 7
        assert 'aria-label="Function results"' in body
        assert 'aria-label="Section results"' in body
        assert 'aria-label="Global results"' in body
        assert 'aria-label="History results"' in body
        assert body.count('aria-busy="false"') == 5
        assert 'aria-selected="true"' in body
        assert 'role="tablist"' in body
        # APG tabs: panels open with non-focusable hints, so each is a tab stop.
        assert body.count('role="tabpanel" tabindex="0"') == 4
        assert "aria-pressed" in body
        assert "ArrowRight" in body  # tablist keyboard nav
        assert 'aria-label="Reload and retry"' in body
        assert 'id="reload"' in body  # re-reads coverage.db without a browser reload
        # A reload must drop what the previous boot marked as loaded, or a
        # second visit to a view would keep showing the rows it was painted with.
        assert "nothing already painted counts as loaded" in body
        assert body.count("viewLoaded.sections = false;") >= 1
        assert "border: 1px solid #767676" in body  # WCAG 1.4.11 non-text contrast
        assert "#ccc" not in body
        assert ".status-EXACT" in html  # same marks as the report
        assert "#475569" in html  # STUB
        assert "#15803d" in html  # EXACT
        assert "#e74c3c" not in body
        assert "#9b59b6" not in body
        assert "function statusText" in js
        # A status mark renders two classes ("st status-EXACT"); an unquoted
        # class value ends at the space and the colour class is dropped, so
        # every status in the tables renders in the default ink.
        assert "class=st" not in js
        assert "forced-colors" in body
        assert "prefers-reduced-motion" in body
        assert 'name="viewport"' in body
        assert "setStatusOptions" in body
        assert "setModuleOptions" in body
        assert 'id="no-targets"' in body
        assert 'id="boot-status"' in body
        assert 'id="empty-state"' in body
        assert "Showing " in body and "of " in body  # truncation copy in JS
        assert "aria-busy only" in body  # loading via aria-busy, not live-region chatter
        assert "Loading functions…" not in body
        assert "class=value" in body
        assert 'id="clear-filters"' in body
        assert 'id="show-more"' in body
        assert 'id="show-more-globals"' in body
        assert 'id="show-more-history"' in body
        assert 'id="globals-hint"' in body
        assert 'id="history-hint"' in body
        assert "formatWhen" in body
        # Zone-less ISO datetimes are forced to UTC (append Z) so a browser
        # in a DST zone cannot mis-parse them as local wall time.  "T", "t",
        # and a space separator are all local to Date.parse.
        assert 'raw += "Z"' in body
        assert "[Tt ]" in body
        # The fall-back hour is labeled (EDT vs EST); dateStyle cannot carry
        # a zone name, so the formatter spells the fields out.
        assert 'timeZoneName: "short"' in body
        assert "Reload dashboard" in body
        assert 'retry-summary").focus()' in body
        assert "No status changes recorded yet" in body
        assert "No section stats for this target" in body
        # An empty result says whether the filters or the target emptied it.
        assert '(filtersActive() ? " match" : " yet")' in body
        assert "setGlobalsEmptyMessage" in body
        assert "setFunctionsEmptyMessage" in body
        assert 'id="retry-summary"' in body
        assert 'id="views"' in body
        assert 'data-view="sections"' in body
        assert 'data-view="globals"' in body
        assert 'data-view="history"' in body
        assert "setLoadError" in body
        assert "data-status" in body
        assert "Use Show more below" in body
        assert "display stops at" in body
        assert "Old status" in body and "New status" in body
        assert body.index('id="results"') < body.index('id="show-more-wrap"')
        assert body.index('id="globals-results"') < body.index('id="globals-show-more-wrap"')
        assert body.index('id="history-results"') < body.index('id="history-show-more-wrap"')
        assert 'clear-filters").disabled' in body
        assert "Share of .text bytes in byte-matched (EXACT or RELOC) functions" in body
        assert "Retry sections" in body
        assert "Retry globals" in body
        assert "Retry history" in body
        assert "Total functions for this target" in body
        assert "<span class=visually-hidden>, " in body  # card title reaches AT after visible text
        assert "/api/bootstrap" in body
        assert "/api/sections" in body
        assert "/api/globals" in body
        assert "/api/history" in body
        assert "loadGlobals({ append: true })" in body
        assert "loadHistory({ append: true })" in body
        assert "loadedGlobalsCount" in body
        assert "Retry summary" in body
        # Errors announce via role=alert only (avoid double-speaking with status).
        assert 'results-status").textContent = message' not in body

    def test_app_js_route(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("GET", "/app.js", {})
        assert status == 200
        assert "javascript" in content_type
        assert body is _APP_JS
        assert 'get("/api/bootstrap")' in body

    def test_boot_guard_js_route(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("GET", "/boot-guard.js", {})
        assert status == 200
        assert "javascript" in content_type
        assert body is _BOOT_GUARD_JS

    def test_boot_guard_follows_the_client_and_keeps_its_message(
        self, dashboard: Dashboard
    ) -> None:
        """The shell must order the guard after the client, or it fires every load."""
        from rebrew.dashboard import _BOOT_GUARD_JS_URL

        _, _, html = dashboard.handle("GET", "/", {})
        _, _, guard = dashboard.handle("GET", "/boot-guard.js", {})
        assert f'<script src="{_APP_JS_URL}" defer></script>' in html
        assert f'<script src="{_BOOT_GUARD_JS_URL}" defer></script>' in html
        assert html.index(_APP_JS_URL) < html.index(_BOOT_GUARD_JS_URL)
        # Without this the guard would report a failure on a healthy load.
        assert "__rebrewBooted = true" in _APP_JS
        assert "!globalThis.__rebrewBooted" in guard
        # A stuck client leaves the user a message, not a permanent spinner.
        assert 'getElementById("boot-status")' in guard
        assert "Reload to retry" in guard
        # ...and a control that does what the message says, since the client
        # that normally reveals the Reload button is what failed.
        assert 'getElementById("reload")' in guard
        assert "location.reload()" in guard
        # Same-origin asset, not an inline handler the CSP would block.
        assert "onerror" not in html

    def test_api_bootstrap(self, dashboard: Dashboard) -> None:
        """Cold start packs targets + first target summary/functions in one response."""
        status, content_type, body = dashboard.handle("GET", "/api/bootstrap", {})
        assert status == 200
        assert "application/json" in content_type
        payload = json.loads(body)
        assert payload["targets"] == ["server_dll"]
        assert payload["target"] == "server_dll"
        assert payload["count"] == 1
        assert payload["summary"] is not None
        assert payload["summary"]["target"] == "server_dll"
        assert payload["functions"] is not None
        assert payload["functions"]["count"] >= 1
        assert payload["functions"]["limit"] == _BOOTSTRAP_FUNCTION_LIMIT
        # A first-paint page, not the interactive one: this body shares the cold
        # connection with the shell and /app.js.  Paging continues from it.
        assert _BOOTSTRAP_FUNCTION_LIMIT < _DEFAULT_LIMIT
        # Compact JSON: no space after colon/comma in the wire body.
        assert body == json.dumps(payload, separators=(",", ":"))

    def test_target_without_functions_is_discoverable(self, tmp_path: Path) -> None:
        data_path = _write_data(tmp_path / "db", target="empty")
        data = json.loads(data_path.read_text(encoding="utf-8"))
        data["functions"] = {}
        data_path.write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        dashboard = Dashboard(tmp_path / "db" / "coverage.db")

        status, _, body = dashboard.handle("GET", "/api/summary", {"target": ["empty"]})
        assert status == 200
        assert json.loads(body)["function_stats"]["total"] == 0

        status, _, body = dashboard.handle("GET", "/api/targets", {})
        assert status == 200
        assert json.loads(body) == {
            "targets": ["empty"],
            "count": 1,
            "total": 1,
            "limit": 1,
            "offset": 0,
            "paged": False,
        }

        status, _, body = dashboard.handle("GET", "/api/bootstrap", {})
        assert status == 200
        payload = json.loads(body)
        assert payload["targets"] == ["empty"]
        assert payload["target"] == "empty"
        assert payload["summary"]["function_stats"]["total"] == 0
        assert payload["functions"]["functions"] == []
        assert payload["functions"]["count"] == payload["functions"]["total"] == 0

    def test_api_targets(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("GET", "/api/targets", {})
        assert status == 200
        assert "application/json" in content_type
        payload = json.loads(body)
        assert payload["targets"] == ["server_dll"]
        assert payload["count"] == 1
        assert payload["total"] == 1
        assert payload["limit"] == 1
        assert payload["offset"] == 0

    def test_api_summary_missing_target_404(self, dashboard: Dashboard) -> None:
        status, _, body = dashboard.handle("GET", "/api/summary", {"target": ["nope"]})
        assert status == 404
        assert "unknown target" in body

    def test_api_missing_target_param_400(self, dashboard: Dashboard) -> None:
        for path in (
            "/api/summary",
            "/api/functions",
            "/api/sections",
            "/api/globals",
            "/api/history",
        ):
            status, _, body = dashboard.handle("GET", path, {})
            assert status == 400, path
            assert "target" in json.loads(body)["error"]

    def test_api_blank_target_param_400(self, dashboard: Dashboard) -> None:
        """Whitespace-only target is missing, not an unknown name."""
        for path in (
            "/api/summary",
            "/api/functions",
            "/api/sections",
            "/api/globals",
            "/api/history",
        ):
            status, _, body = dashboard.handle("GET", path, {"target": ["  "]})
            assert status == 400, path
            assert "target" in json.loads(body)["error"]

    def test_api_unknown_target_404_all_scoped(self, dashboard: Dashboard) -> None:
        for path in (
            "/api/summary",
            "/api/functions",
            "/api/sections",
            "/api/globals",
            "/api/history",
        ):
            status, _, body = dashboard.handle("GET", path, {"target": ["nope"]})
            assert status == 404, path
            assert "unknown target" in json.loads(body)["error"]

    def test_every_error_body_carries_a_code(self, dashboard: Dashboard) -> None:
        """A client branches on ``code``; ``error`` stays the human text."""
        cases = [
            ("GET", "/api/summary", {}, 400, "missing_target"),
            ("GET", "/api/summary", {"target": ["nope"]}, 404, "unknown_target"),
            ("GET", "/api/nope", {}, 404, "not_found"),
            ("POST", "/api/targets", {}, 405, "method_not_allowed"),
            (
                "GET",
                "/api/functions",
                {"target": ["server_dll"], "status": ["NOPE"]},
                400,
                "invalid_status",
            ),
        ]
        for method, path, query, expected_status, expected_code in cases:
            status, _, body = dashboard.handle(method, path, query)
            assert status == expected_status, path
            payload = json.loads(body)
            assert payload["code"] == expected_code, path
            assert payload["error"], path

    def test_api_functions_unknown_status_400(self, dashboard: Dashboard) -> None:
        """A typo in ``status`` is a client error, not an empty result page."""
        status, _, body = dashboard.handle(
            "GET", "/api/functions", {"target": ["server_dll"], "status": ["STTUB"]}
        )
        assert status == 400
        payload = json.loads(body)
        assert payload["code"] == "invalid_status"
        assert "STTUB" in payload["error"]
        # Every real status still filters (case- and alias-folded).
        for known in ("STUB", "stub", "exact", "NEAR_MATCHING", "UNKNOWN"):
            status, _, _ = dashboard.handle(
                "GET", "/api/functions", {"target": ["server_dll"], "status": [known]}
            )
            assert status == 200, known

    def test_list_envelopes_declare_paging(self, dashboard: Dashboard) -> None:
        """``paged`` says whether ``limit`` is a page size or the row count."""
        for path, paged in (
            ("/api/functions", True),
            ("/api/globals", True),
            ("/api/history", True),
            ("/api/sections", False),
            ("/api/targets", False),
        ):
            status, _, body = dashboard.handle("GET", path, {"target": ["server_dll"]})
            assert status == 200, path
            payload = json.loads(body)
            assert payload["paged"] is paged, path
            assert payload["offset"] == 0, path
        status, _, body = dashboard.handle("GET", "/api/bootstrap", {})
        assert json.loads(body)["paged"] is False
        # The nested functions page of bootstrap carries its own flag.
        assert json.loads(body)["functions"]["paged"] is True

    def test_api_functions_with_query(self, dashboard: Dashboard) -> None:
        status, _, body = dashboard.handle(
            "GET", "/api/functions", {"target": ["server_dll"], "status": ["STUB"]}
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["count"] == 1
        assert payload["total"] == 1
        assert payload["functions"][0][1] == "func_b"
        assert payload["functions"][0][4] == "STUB"

    def test_api_functions_status_case_insensitive(self, dashboard: Dashboard) -> None:
        """Status query parameter accepts lower-case and aliases."""
        status, _, body = dashboard.handle(
            "GET", "/api/functions", {"target": ["server_dll"], "status": ["stub"]}
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["count"] == 1
        assert payload["functions"][0][1] == "func_b"
        assert payload["functions"][0][4] == "STUB"

    def test_api_globals_module_filter(self, dashboard: Dashboard) -> None:
        """Globals endpoint supports module filtering like functions."""
        status, _, body = dashboard.handle(
            "GET", "/api/globals", {"target": ["server_dll"], "module": ["SERVER"]}
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["count"] == 1
        assert payload["globals"][0][1] == "g_flag"

        status, _, body = dashboard.handle(
            "GET", "/api/globals", {"target": ["server_dll"], "module": ["CLIENT"]}
        )
        assert status == 200
        assert json.loads(body)["count"] == 0

    def test_blank_module_matches_summary_counts(self, tmp_path: Path) -> None:
        """A blank module is its own summary bucket and ``module=`` selects it."""
        from io import BytesIO

        from rebrew.dashboard import _Handler, allowed_hosts_for

        data_path = _write_data(tmp_path / "db", target="mod")
        data = json.loads(data_path.read_text(encoding="utf-8"))
        data["functions"]["0x10001000"].pop("module")
        data["functions"]["0x10002000"]["module"] = "GAME"
        data["globals"]["0x50001000"].pop("module")
        data["globals"]["0x50002000"] = {
            "name": "g_game",
            "decl": "int g_game;",
            "size": 4,
            "module": "GAME",
        }
        data_path.write_text(json.dumps(data), encoding="utf-8")
        build_db(tmp_path)
        dash = Dashboard(tmp_path / "db" / "coverage.db")

        status, _, body = dash.handle("GET", "/api/summary", {"target": ["mod"]})
        assert status == 200
        assert json.loads(body)["function_stats"]["by_module_counts"] == {"": 1, "GAME": 1}

        status, _, body = dash.handle("GET", "/api/functions", {"target": ["mod"], "module": [""]})
        rows = json.loads(body)["functions"]
        assert status == 200
        assert [row[1] for row in rows] == ["func_a"]
        assert rows[0][5] == ""

        status, _, body = dash.handle(
            "GET", "/api/functions", {"target": ["mod"], "module": [" GAME "]}
        )
        assert [row[1] for row in json.loads(body)["functions"]] == ["func_b"]

        status, _, body = dash.handle("GET", "/api/functions", {"target": ["mod"]})
        assert json.loads(body)["total"] == 2

        status, _, body = dash.handle("GET", "/api/globals", {"target": ["mod"], "module": [""]})
        assert [row[1] for row in json.loads(body)["globals"]] == ["g_flag"]
        status, _, body = dash.handle(
            "GET", "/api/globals", {"target": ["mod"], "module": ["GAME"]}
        )
        assert [row[1] for row in json.loads(body)["globals"]] == ["g_game"]

        def _get(path: str) -> dict[str, object]:
            handler = _Handler.__new__(_Handler)
            handler.headers = {"Host": "127.0.0.1:8000"}
            handler.path = path
            handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
            handler.dashboard = dash
            sent: list[int] = []
            handler.send_response = lambda code: sent.append(code)  # type: ignore[method-assign]
            handler.send_header = lambda *_args: None  # type: ignore[method-assign]
            handler.end_headers = lambda: None  # type: ignore[method-assign]
            buf = BytesIO()
            handler.wfile = buf
            handler._respond("GET")
            assert sent == [200], path
            parsed: dict[str, object] = json.loads(buf.getvalue())
            return parsed

        # parse_qs drops a bare module= unless keep_blank_values is set.
        blank = _get("/api/functions?target=mod&module=")
        functions = blank["functions"]
        assert isinstance(functions, list)
        assert [row[1] for row in functions] == ["func_a"]
        everyone = _get("/api/functions?target=mod")
        assert everyone["total"] == 2
        globals_blank = _get("/api/globals?target=mod&module=%20")
        globals_rows = globals_blank["globals"]
        assert isinstance(globals_rows, list)
        assert [row[1] for row in globals_rows] == ["g_flag"]

    def test_va_zero_formatted_properly(self, tmp_path: Path) -> None:
        """VA 0 is a valid address and must format as 0x00000000, not ???."""
        import sqlite3

        db_path = tmp_path / "zero.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
            conn.execute("INSERT INTO metadata VALUES ('t', 'function_stats', '{}')")
            conn.execute(
                "CREATE TABLE functions (target TEXT, va INT, name TEXT, symbol TEXT, "
                "size INT, status TEXT, module TEXT, files TEXT, markerType TEXT)"
            )
            conn.execute(
                "INSERT INTO functions VALUES ('t', 0, 'f_zero', 'sym_zero', 16, 'EXACT', 'MOD', '[]', 'FUNCTION')"
            )
            conn.execute(
                "CREATE TABLE globals (target TEXT, va INT, name TEXT, decl TEXT, "
                "files TEXT, module TEXT, size INT, status TEXT)"
            )
            conn.execute(
                "INSERT INTO globals VALUES ('t', 0, 'g_zero', 'int g_zero;', '[]', 'MOD', 4, '')"
            )
            conn.execute(
                "CREATE TABLE history (id INTEGER PRIMARY KEY, target TEXT, va INT, "
                "old_status TEXT, new_status TEXT, changed_at TEXT)"
            )
            conn.execute(
                "INSERT INTO history VALUES (1, 't', 0, 'WIP', 'EXACT', '2026-01-01T00:00:00Z')"
            )

        d = Dashboard(db_path)
        fn_data = d.functions("t")
        assert fn_data["functions"][0][0] == "0x00000000"

        gl_data = d.globals("t")
        assert gl_data["globals"][0][0] == "0x00000000"

        hi_data = d.history("t")
        assert hi_data["history"][0][0] == "0x00000000"

    def test_functions_pages_do_not_repeat_rows(self, dashboard: Dashboard) -> None:
        pages = []
        for offset in (0, 1):
            status, _, body = dashboard.handle(
                "GET",
                "/api/functions",
                {"target": ["server_dll"], "limit": ["1"], "offset": [str(offset)]},
            )
            assert status == 200
            page = json.loads(body)
            assert page["count"] == 1
            assert page["total"] == 2
            assert page["limit"] == 1
            assert page["offset"] == offset
            pages.extend(page["functions"])
        assert pages == dashboard.functions("server_dll")["functions"]

    def test_functions_offset_past_end_keeps_total(self, dashboard: Dashboard) -> None:
        data = dashboard.functions("server_dll", limit=1, offset=50)
        assert data["count"] == 0
        assert data["total"] == 2
        assert data["offset"] == 50

    def test_offset_beyond_sqlite_int_is_empty_page(self, dashboard: Dashboard) -> None:
        huge = str(10**30)
        for path in ("/api/functions", "/api/globals", "/api/history"):
            status, _, body = dashboard.handle(
                "GET", path, {"target": ["server_dll"], "offset": [huge]}
            )
            assert status == 200, path
            page = json.loads(body)
            assert page["count"] == 0, path
            assert page["offset"] == 2**63 - 1, path

    def test_api_functions_nonpositive_limit_uses_default(self, dashboard: Dashboard) -> None:
        status, _, body = dashboard.handle(
            "GET", "/api/functions", {"target": ["server_dll"], "limit": ["0"]}
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["count"] == 2
        assert payload["total"] == 2
        assert payload["limit"] == 100
        assert payload["offset"] == 0

    def test_api_functions_offset_past_page_size_cap(self, dashboard: Dashboard) -> None:
        """offset must not be clamped to _MAX_LIMIT (page size ≠ skip)."""
        from rebrew.dashboard import _MAX_LIMIT

        status, _, body = dashboard.handle(
            "GET",
            "/api/functions",
            {
                "target": ["server_dll"],
                "limit": ["1"],
                "offset": [str(_MAX_LIMIT + 100)],
            },
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["offset"] == _MAX_LIMIT + 100
        assert payload["count"] == 0
        assert payload["total"] == 2

    def test_api_globals_honors_offset(self, dashboard: Dashboard) -> None:
        """globals must apply limit+offset like functions (not silently drop offset)."""
        status, _, body = dashboard.handle(
            "GET",
            "/api/globals",
            {"target": ["server_dll"], "limit": ["1"], "offset": ["0"]},
        )
        assert status == 200
        first = json.loads(body)
        assert first["count"] == 1
        assert first["total"] == 1
        assert first["offset"] == 0
        assert first["globals"][0][1] == "g_flag"

        status, _, body = dashboard.handle(
            "GET",
            "/api/globals",
            {"target": ["server_dll"], "limit": ["1"], "offset": ["1"]},
        )
        assert status == 200
        past = json.loads(body)
        assert past["count"] == 0
        assert past["total"] == 1
        assert past["offset"] == 1
        assert past["globals"] == []

    def test_api_history_honors_offset(self, dashboard: Dashboard) -> None:
        status, _, body = dashboard.handle(
            "GET",
            "/api/history",
            {"target": ["server_dll"], "limit": ["1"], "offset": ["50"]},
        )
        assert status == 200
        payload = json.loads(body)
        assert payload["offset"] == 50
        assert payload["count"] == 0
        assert payload["total"] == 0

    def test_api_sections_includes_count_total(self, dashboard: Dashboard) -> None:
        status, _, body = dashboard.handle("GET", "/api/sections", {"target": ["server_dll"]})
        assert status == 200
        payload = json.loads(body)
        assert payload["count"] == len(payload["sections"])
        assert payload["total"] == payload["count"]
        assert payload["count"] >= 1

    @pytest.mark.parametrize(
        ("path", "rows_key"),
        [
            ("/api/functions", "functions"),
            ("/api/sections", "sections"),
            ("/api/globals", "globals"),
            ("/api/history", "history"),
        ],
    )
    def test_list_rows_are_arrays_named_by_cols(
        self, dashboard: Dashboard, path: str, rows_key: str
    ) -> None:
        """Every list route ships positional rows, and ``cols`` names each cell.

        The one row shape a client can rely on: a SELECT that grows a column
        without growing ``cols`` would silently shift every cell after it.
        """
        status, _, body = dashboard.handle("GET", path, {"target": ["server_dll"]})
        assert status == 200
        payload = json.loads(body)
        cols = payload["cols"]
        assert len(set(cols)) == len(cols)
        for row in payload[rows_key]:
            assert isinstance(row, list)
            assert len(row) == len(cols)

    def test_bootstrap_rows_match_their_own_routes(self, dashboard: Dashboard) -> None:
        """``/api/bootstrap`` embeds the same payloads the dedicated routes serve.

        The cold start pages the functions list at
        ``_BOOTSTRAP_FUNCTION_LIMIT`` rather than the interactive default, so
        the comparison asks the route for that same page: the embedded rows
        must be the rows the route serves, not a differently sized page.
        """
        _, _, body = dashboard.handle("GET", "/api/bootstrap", {})
        boot = json.loads(body)
        _, _, funcs = dashboard.handle(
            "GET",
            "/api/functions",
            {
                "target": ["server_dll"],
                "limit": [str(_BOOTSTRAP_FUNCTION_LIMIT)],
            },
        )
        assert boot["functions"] == json.loads(funcs)
        assert boot["summary"]["target"] == boot["target"] == "server_dll"

    def test_post_rejected(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("POST", "/api/targets", {})
        assert status == 405
        assert "application/json" in content_type
        err = json.loads(body)["error"]
        assert "method not allowed" in err
        assert "HEAD" in err

    def test_put_rejected(self, dashboard: Dashboard) -> None:
        status, _, body = dashboard.handle("PUT", "/api/targets", {})
        assert status == 405
        assert "method not allowed" in json.loads(body)["error"]

    def test_patch_rejected(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("PATCH", "/api/targets", {})
        assert status == 405
        assert "application/json" in content_type
        assert "method not allowed" in json.loads(body)["error"]

    def test_unserved_path_is_404_for_every_method(self, dashboard: Dashboard) -> None:
        """405 is about a resource's methods; an unserved path has no resource.

        ``Allow: GET, HEAD`` on a 405 for ``/api/nope`` would advertise a
        resource that does not exist, and a GET of that same path already
        answers 404.
        """
        for method in ("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"):
            status, _, body = dashboard.handle(method, "/api/nope", {})
            assert status == 404, method
            assert json.loads(body) == {
                "error": "no such endpoint '/api/nope'",
                "code": "not_found",
            }

    def test_every_response_carries_the_log_request_id(self, dashboard: Dashboard) -> None:
        """``X-Request-Id`` is the id the access and error log lines carry.

        A caller holding a 500 hands the operator this one token instead of a
        timestamp and a path it has to guess at.
        """
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import _Handler, allowed_hosts_for

        ids: set[str] = set()
        for method, path in (("GET", "/api/targets"), ("POST", "/api/targets")):
            handler = _Handler.__new__(_Handler)
            handler.rfile = BytesIO(
                f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n".encode()
            )
            handler.wfile = BytesIO()
            handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
            handler.dashboard = dashboard
            handler.log_message = Mock()
            handler.handle()
            headers = handler.wfile.getvalue().split(b"\r\n\r\n", 1)[0]
            found = [line for line in headers.split(b"\r\n") if line.startswith(b"X-Request-Id:")]
            assert len(found) == 1
            ids.add(found[0].split(b":", 1)[1].strip().decode())
        # One id per request, never the pre-request placeholder.
        assert len(ids) == 2
        assert all(value.startswith("r") and value[1:].isdigit() for value in ids)

    def test_head_allowed_for_reads(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("HEAD", "/api/targets", {})
        assert status == 200
        assert "application/json" in content_type
        # handle() still returns the body; the HTTP layer omits writing it.
        assert json.loads(body)["targets"] == ["server_dll"]

    def test_unknown_endpoint_404(self, dashboard: Dashboard) -> None:
        status, _, _ = dashboard.handle("GET", "/api/nope", {})
        assert status == 404

    def test_db_read_only(self, dashboard: Dashboard) -> None:
        """A rogue query cannot mutate the database (mode=ro)."""
        import sqlite3

        status, _, _ = dashboard.handle("GET", "/api/targets", {})
        assert status == 200
        # The connection the dashboard itself hands out must be read-only;
        # a read-write handle here would let any query mutate the workspace.
        with pytest.raises(sqlite3.OperationalError), dashboard._conn() as conn:
            conn.execute("CREATE TABLE evil (x)")

    def test_reserved_path_chars_open_read_only(self, tmp_path: Path) -> None:
        """DB filenames with ``?``/``#`` must still open via the percent-encoded URI."""
        import sqlite3

        weird = tmp_path / "cov erage?#.db"
        with sqlite3.connect(weird) as conn:
            conn.execute(
                "CREATE TABLE functions (target TEXT, va INT, name TEXT, symbol TEXT, "
                "size INT, status TEXT, module TEXT, files TEXT, markerType TEXT)"
            )
            conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
            conn.execute("INSERT INTO metadata VALUES ('t', 'function_stats', '{}')")
            conn.execute(
                "INSERT INTO functions VALUES ('t', 1, 'f', 'f', 1, 'STUB', '', '[]', 'FUNC')"
            )
        assert Dashboard(weird).targets() == ["t"]


class TestCli:
    def test_missing_db_errors(self, tmp_path: Path) -> None:
        from rebrew.dashboard import app

        result = CliRunner().invoke(app, ["--root", str(tmp_path)])
        assert result.exit_code == 2
        assert "coverage.db" in result.output

    def test_registered_in_umbrella(self) -> None:
        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["--help"])
        assert result.exit_code == 0
        assert "dashboard" in result.output

    def test_target_option_is_not_advertised(self) -> None:
        """`--target` was accepted and silently ignored (the dashboard serves
        every target in the DB through per-request ?target=), so it must not
        appear in the command's options."""
        from rebrew.dashboard import app

        result = CliRunner().invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "--target" not in result.output

    def test_json_exits_without_serving(self, tmp_path: Path) -> None:
        """``--json`` is a bind-probe for scripts: print URL + db path and exit
        (never ``serve_forever``)."""
        import json
        import sqlite3

        from rebrew.dashboard import app

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        db_path = db_dir / "coverage.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE functions (target TEXT, va INT, name TEXT, symbol TEXT, "
                "size INT, status TEXT, module TEXT, files TEXT, markerType TEXT)"
            )
            conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
            conn.execute("INSERT INTO metadata VALUES ('t', 'function_stats', '{}')")

        result = CliRunner().invoke(app, ["--root", str(tmp_path), "--json", "--port", "9123"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload == {
            "url": "http://127.0.0.1:9123",
            "db": str(db_path.resolve()),
        }
        assert "serving" not in result.output.lower()
        assert "Rebrew dashboard" not in result.output

    def test_port_in_use_names_port_and_fix(self, tmp_path: Path) -> None:
        """A taken port says which one and how to pick another, not a bare errno."""
        import socket
        import sqlite3

        from rebrew.dashboard import app

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        with sqlite3.connect(db_dir / "coverage.db") as conn:
            conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")

        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 0))
            busy.listen()
            port = busy.getsockname()[1]
            result = CliRunner().invoke(app, ["--root", str(tmp_path), "--port", str(port)])
        assert result.exit_code == 2
        assert f"Port {port} on 127.0.0.1 is already in use" in result.output
        assert "pick a free port with --port" in result.output


class TestIntParam:
    """limit query parsing: non-positive / invalid → default, else clamp."""

    def test_missing_and_invalid(self) -> None:
        from rebrew.dashboard import _DEFAULT_LIMIT, _MAX_LIMIT, _int_param

        assert _int_param({}, "limit", _DEFAULT_LIMIT) == _DEFAULT_LIMIT
        assert _int_param({"limit": [""]}, "limit", _DEFAULT_LIMIT) == _DEFAULT_LIMIT
        assert _int_param({"limit": ["abc"]}, "limit", _DEFAULT_LIMIT) == _DEFAULT_LIMIT
        assert _int_param({"limit": ["0"]}, "limit", _DEFAULT_LIMIT) == _DEFAULT_LIMIT
        assert _int_param({"limit": ["-3"]}, "limit", 100) == 100
        assert _int_param({"limit": ["50"]}, "limit", _DEFAULT_LIMIT) == 50
        assert _int_param({"limit": [str(_MAX_LIMIT + 1)]}, "limit", _DEFAULT_LIMIT) == _MAX_LIMIT


class TestOffsetParam:
    """offset query parsing: zero valid, not clamped to page-size max."""

    def test_missing_invalid_and_large(self) -> None:
        from rebrew.dashboard import _MAX_LIMIT, _offset_param

        assert _offset_param({}, "offset") == 0
        assert _offset_param({"offset": [""]}, "offset") == 0
        assert _offset_param({"offset": ["abc"]}, "offset") == 0
        assert _offset_param({"offset": ["-1"]}, "offset") == 0
        assert _offset_param({"offset": ["0"]}, "offset") == 0
        assert _offset_param({"offset": ["50"]}, "offset") == 50
        # Page-size cap must not apply: otherwise rows past _MAX_LIMIT are unreachable.
        past_cap = _MAX_LIMIT + 1
        assert _offset_param({"offset": [str(past_cap)]}, "offset") == past_cap


class TestEscapeLike:
    """User search terms must match literally, not as SQL LIKE wildcards."""

    def test_wildcards_escaped(self) -> None:
        from rebrew.dashboard import _escape_like

        assert _escape_like("foo_1") == "foo\\_1"
        assert _escape_like("100%") == "100\\%"
        assert _escape_like("a\\b") == "a\\\\b"
        assert _escape_like("plain") == "plain"


class TestVaQuery:
    """Address-shaped search terms parse to the same integer the table shows."""

    def test_equivalent_spellings(self) -> None:
        from rebrew.dashboard import _va_query

        assert _va_query("0x10001000") == 0x10001000
        assert _va_query("0X10001000") == 0x10001000
        assert _va_query("10001000") == 0x10001000
        assert _va_query("00401000") == 0x401000
        assert _va_query("0x401000") == 0x401000
        assert _va_query("  0x10001000  ") == 0x10001000

    def test_name_fragments_are_not_addresses(self) -> None:
        from rebrew.dashboard import _va_query

        assert _va_query("func_a") is None
        assert _va_query("add") is None
        assert _va_query("0x") is None
        assert _va_query("0x123") is None
        assert _va_query("g_flag") is None
        assert _va_query("f" * 16) is None
        assert _va_query("f" * 17) is None


class TestHttpMethods:
    @pytest.mark.parametrize(
        "method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "PROPFIND"]
    )
    @pytest.mark.parametrize(
        "path",
        [
            "/",
            "/app.js",
            "/boot-guard.js",
            "/api/bootstrap",
            "/api/targets",
            "/api/summary",
            "/api/functions",
            "/api/sections",
            "/api/globals",
            "/api/history",
        ],
    )
    def test_unsupported_methods_return_json(self, method: str, path: str) -> None:
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.rfile = BytesIO(
            f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n".encode()
        )
        handler.wfile = BytesIO()
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        handler.log_message = Mock()

        handler.handle_one_request()

        headers, body = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        assert headers.startswith(b"HTTP/1.1 405 ")
        assert b"Content-Type: application/json; charset=utf-8\r\n" in headers
        assert b"Allow: GET, HEAD" in headers
        assert b"Cache-Control: no-store\r\n" in headers
        assert json.loads(body) == {
            "error": "method not allowed (read-only; GET, HEAD only)",
            "code": "method_not_allowed",
        }

    def test_http11_keeps_connection_for_pipelined_gets(self, dashboard: Dashboard) -> None:
        """HTTP/1.1 responses leave the socket open so shell + bootstrap share one TCP."""
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        assert _Handler.protocol_version == "HTTP/1.1"
        # Two GETs on one connection (browser: document, then /api/bootstrap).
        handler.rfile = BytesIO(
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n"
            b"GET /api/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n"
        )
        handler.wfile = BytesIO()
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.log_message = Mock()
        handler.handle()
        raw = handler.wfile.getvalue()
        assert raw.count(b"HTTP/1.1 200 ") == 2
        # Persistent framing: no Connection: close on either response.
        assert b"Connection: close" not in raw
        # Shell HTML + bootstrap JSON on one connection (no Accept-Encoding → uncompressed).
        assert b"Rebrew coverage" in raw
        assert b"Content-Type: text/html" in raw
        assert b'"targets"' in raw
        assert b"Content-Type: application/json" in raw

    def test_request_body_closes_connection(self, dashboard: Dashboard) -> None:
        """An unread request body must not be parsed as the next pipelined request."""
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.rfile = BytesIO(
            b"POST /api/targets HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n"
            b"Content-Length: 18\r\n\r\n"
            b"GET /x HTTP/1.1\r\n\r\n"
            b"GET /api/targets HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n"
        )
        handler.wfile = BytesIO()
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.log_message = Mock()
        handler.handle()
        raw = handler.wfile.getvalue()
        assert raw.startswith(b"HTTP/1.1 405 ")
        assert b"Connection: close\r\n" in raw
        # The body's bytes were never answered as a request of their own.
        assert raw.count(b"HTTP/1.1 ") == 1

    def test_malformed_request_line_returns_json(self) -> None:
        """http.server's own parse errors use the JSON envelope, not its HTML page."""
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.rfile = BytesIO(b"GET / HTTP/9.9\r\nHost: 127.0.0.1:8000\r\n\r\n")
        handler.wfile = BytesIO()
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        handler.log_message = Mock()
        handler.handle()

        headers, body = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        assert headers.startswith(b"HTTP/1.1 505 ")
        assert b"Content-Type: application/json; charset=utf-8\r\n" in headers
        assert b"Connection: close\r\n" in headers
        assert b"Cache-Control: no-store\r\n" in headers
        assert json.loads(body) == {
            "error": "Invalid HTTP version (9.9)",
            "code": "http_version_not_supported",
        }

    def test_parse_error_body_scrubs_bidi_formatting(self) -> None:
        """A pre-routing error body is scrubbed like every routed one.

        http.server quotes the request line in the 400 message, so a crafted
        RLO would otherwise ride back to the client as formatting text.
        """
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import _Handler, allowed_hosts_for

        rlo = "\u202e"  # RIGHT-TO-LEFT OVERRIDE
        handler = _Handler.__new__(_Handler)
        # Two words: the request-line arity check, not the version check.
        handler.rfile = BytesIO(f"GET /{rlo} HTTP\r\n\r\n".encode())
        handler.wfile = BytesIO()
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        handler.log_message = Mock()
        handler.handle()

        headers, body = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        assert headers.startswith(b"HTTP/1.1 400 ")
        error = json.loads(body)
        assert error["code"] == "bad_request"
        assert rlo not in error["error"]
        assert rlo.encode() not in body


class TestEncodingNegotiation:
    @pytest.mark.parametrize(
        ("accept", "encoding"),
        [
            ("", None),
            ("br", None),
            ("br, zstd", "zstd"),
            ("gzip", "gzip"),
            ("identity;q=0, gzip", "gzip"),
            ("GZIP; Q=0.5", "gzip"),
            ("gzip;q=0", None),
            ("gzip; q=0.000", None),
            ("zstd;q=0", None),
            ("*", "zstd"),
            ("*;q=0", None),
            # Explicit gzip;q=0 still allows zstd via *.
            ("gzip;q=0, *", "zstd"),
            ("*, gzip;q=0", "zstd"),
            ("*;q=0, gzip;q=0.5", "gzip"),
            ("*;q=0, zstd;q=0.5", "zstd"),
            ("gzip, zstd", "zstd"),
            ("gzip;q=1, zstd;q=0.5", "gzip"),
            ("zstd;q=0.8, gzip;q=0.9", "gzip"),
            ("gzip;q=invalid", None),
            ("gzip;q=nan", None),
            ("gzip;q=2", None),
            ("gzip;q=-1", None),
            ("zstd;q=invalid", None),
        ],
    )
    @pytest.mark.parametrize("path", ["/", "/app.js", "/boot-guard.js", "/api/bootstrap"])
    def test_response_encoding(
        self, dashboard: Dashboard, accept: str, encoding: str | None, path: str
    ) -> None:
        import gzip
        from io import BytesIO
        from unittest.mock import Mock

        import zstandard

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.headers = {"Host": "127.0.0.1:8000", "Accept-Encoding": accept}
        handler.path = path
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = BytesIO()

        handler._respond("GET")

        handler.send_response.assert_called_once_with(200)
        headers = dict(call.args for call in handler.send_header.call_args_list)
        body = handler.wfile.getvalue()
        assert headers.get("Content-Encoding") == encoding
        assert headers["Vary"] == "Accept-Encoding"
        assert int(headers["Content-Length"]) == len(body)
        expected = dashboard.handle("GET", path, {})[2].encode("utf-8")
        if encoding == "gzip":
            assert gzip.decompress(body) == expected
        elif encoding == "zstd":
            assert zstandard.ZstdDecompressor().decompress(body) == expected
        else:
            assert body == expected

    def test_zstd_preferred_over_gzip_when_both_listed(self, dashboard: Dashboard) -> None:
        """Modern browsers list zstd; prefer it for the smaller wire body."""
        from io import BytesIO
        from unittest.mock import Mock

        import zstandard

        from rebrew.dashboard import (
            _INDEX_HTML_BYTES,
            _INDEX_HTML_ZSTD,
            _Handler,
            allowed_hosts_for,
        )

        assert _INDEX_HTML_ZSTD is not None
        handler = _Handler.__new__(_Handler)
        handler.headers = {
            "Host": "127.0.0.1:8000",
            "Accept-Encoding": "gzip, deflate, br, zstd",
        }
        handler.path = "/"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = BytesIO()
        handler._respond("GET")
        headers = dict(call.args for call in handler.send_header.call_args_list)
        body = handler.wfile.getvalue()
        assert headers["Content-Encoding"] == "zstd"
        assert body == _INDEX_HTML_ZSTD
        assert zstandard.ZstdDecompressor().decompress(body) == _INDEX_HTML_BYTES
        assert len(body) < len(_INDEX_HTML_BYTES)

    def test_boot_guard_is_precompressed_not_compressed_per_request(
        self, dashboard: Dashboard
    ) -> None:
        """The guard is a static asset, so it ships the import-time blob."""
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.headers = {"Host": "127.0.0.1:8000", "Accept-Encoding": "gzip"}
        handler.path = "/boot-guard.js"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = BytesIO()
        handler._respond("GET")
        headers = dict(call.args for call in handler.send_header.call_args_list)
        body = handler.wfile.getvalue()
        assert headers["Content-Encoding"] == "gzip"
        assert gzip.decompress(body) == _BOOT_GUARD_JS.encode()
        assert len(body) < len(_BOOT_GUARD_JS.encode())

    @pytest.mark.parametrize("accept", ["gzip", "zstd"])
    def test_entry_assets_fit_initial_congestion_window(
        self, dashboard: Dashboard, accept: str
    ) -> None:
        """Cold-load wire bytes stay inside a 10-segment initcwnd (RFC 6928).

        Past it, first paint costs an extra round trip on a cold connection.
        The budget is the window minus a per-response header reserve, so every
        added entry asset pays for its own headers.
        """
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import (
            _ENTRY_PATHS,
            _ENTRY_WIRE_BUDGET_BYTES,
            _Handler,
            allowed_hosts_for,
        )

        wire = 0
        for path in _ENTRY_PATHS:
            handler = _Handler.__new__(_Handler)
            handler.headers = {"Host": "127.0.0.1:8000", "Accept-Encoding": accept}
            handler.path = path
            handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
            handler.dashboard = dashboard
            handler.send_response = Mock()
            handler.send_header = Mock()
            handler.end_headers = Mock()
            handler.wfile = BytesIO()
            handler._respond("GET")
            headers = dict(call.args for call in handler.send_header.call_args_list)
            assert headers["Content-Encoding"] == accept
            wire += len(handler.wfile.getvalue())
        assert wire <= _ENTRY_WIRE_BUDGET_BYTES, (
            f"entry assets {wire} B over {_ENTRY_WIRE_BUDGET_BYTES} B budget"
        )

    def test_bootstrap_json_compresses_at_max_effort(self) -> None:
        """The preloaded cold-start body pays max effort, later routes do not.

        ``/api/bootstrap`` shares the initial congestion window with the shell
        and ``/app.js`` and is a 304 on every load after the first, so it takes
        the same levels the import-time static blobs use.  The filter and paging
        routes are rebuilt on every interaction and stay at mid effort.
        """
        import zstandard

        from rebrew.dashboard import (
            _GZIP_LEVEL,
            _GZIP_PRECOMPRESS_LEVEL,
            _ZSTD_LEVEL,
            _ZSTD_PRECOMPRESS_LEVEL,
            _maybe_compress,
        )

        # A 100-function first page, the shape the cold start actually sends.
        body = json.dumps(
            {
                "targets": ["t"],
                "functions": [
                    [f"0x{0x401000 + i * 8:08x}", f"Sub_render_state_{i:05d}", i * 3, "EXACT"]
                    for i in range(100)
                ],
            },
            separators=(",", ":"),
        ).encode()
        assert len(body) > 256

        for accept, effort, max_effort in (
            ("gzip", _GZIP_LEVEL, _GZIP_PRECOMPRESS_LEVEL),
            ("zstd", _ZSTD_LEVEL, _ZSTD_PRECOMPRESS_LEVEL),
        ):
            mid, encoding = _maybe_compress(body, accept)
            cold, cold_encoding = _maybe_compress(body, accept, cold_start=True)
            assert encoding == cold_encoding == accept
            # Max effort has to actually pay, or the CPU is pure waste.
            assert len(cold) < len(mid), f"{accept}: max effort {len(cold)} >= {len(mid)}"
            assert effort < max_effort
            # Both decompress back to the served body.
            decode = (
                gzip.decompress if accept == "gzip" else zstandard.ZstdDecompressor().decompress
            )
            assert decode(mid) == decode(cold) == body

    @pytest.mark.parametrize("accept", ["gzip", "zstd"])
    def test_bootstrap_stays_inside_its_wire_budget(
        self, dashboard: Dashboard, accept: str
    ) -> None:
        """The preloaded cold-start body stays inside its own ceiling.

        ``/api/bootstrap`` rides the same cold connection as the shell and
        ``/app.js``, which already spend most of the entry window before any
        data is counted.  Nothing else in the cold flight is left to absorb a
        growing first page, so it is bounded on its own: carrying the full
        interactive page here measured 1083 B (zstd) and is over the ceiling.
        """
        from rebrew.dashboard import _BOOTSTRAP_WIRE_BUDGET_BYTES, _maybe_compress

        payload = dashboard.bootstrap()
        # A real target's first page, at the width the cold start sends.
        payload["functions"]["functions"] = [
            [
                f"0x{0x401000 + i * 0x40:08x}",
                f"Some::Sub_{chr(65 + i % 26)}_{i}",
                "?Some@@YAXH@Z",
                24 + i % 300,
                ("STUB", "NEAR_MATCHING", "EXACT", "RELOC", "PROVEN")[i % 5],
                "dllmain.c",
                "src/dllmain.c",
            ]
            for i in range(_BOOTSTRAP_FUNCTION_LIMIT)
        ]
        payload["functions"]["count"] = _BOOTSTRAP_FUNCTION_LIMIT
        payload["functions"]["total"] = 9000
        body = json.dumps(payload, separators=(",", ":")).encode()

        wire, encoding = _maybe_compress(body, accept, cold_start=True)
        assert encoding == accept
        assert len(wire) <= _BOOTSTRAP_WIRE_BUDGET_BYTES, (
            f"bootstrap {len(wire)} B over {_BOOTSTRAP_WIRE_BUDGET_BYTES} B budget"
        )

    def test_bootstrap_paginates_past_its_first_page(self, dashboard: Dashboard) -> None:
        """A short first page still reports the real total, so Show more works.

        ``Dashboard.functions`` skips its COUNT only when the page comes back
        genuinely short.  ``offset == 0`` at a page size below the row count
        has to take that branch, or the client reads a full page as the whole
        list and never offers Show more.
        """
        payload = dashboard.bootstrap()
        assert payload["functions"]["limit"] == _BOOTSTRAP_FUNCTION_LIMIT

        page = dashboard.functions(payload["target"], limit=_BOOTSTRAP_FUNCTION_LIMIT)
        assert page["count"] == len(page["functions"])
        assert page["total"] >= page["count"]


class TestServerTiming:
    """``Server-Timing`` reports route cost on API responses, not entry assets.

    The Network panel then separates the query from the transfer, and the
    three cold-load assets keep the header bytes their window budget pays for.
    """

    @staticmethod
    def _headers(dashboard: Dashboard, path: str) -> dict[str, str]:
        from io import BytesIO
        from unittest.mock import Mock

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.headers = {"Host": "127.0.0.1:8000", "Accept-Encoding": "gzip"}
        handler.path = path
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = BytesIO()
        handler._respond("GET")
        return dict(call.args for call in handler.send_header.call_args_list)

    def test_api_response_reports_route_duration(self, dashboard: Dashboard) -> None:
        from rebrew.dashboard import _APP_JS_URL

        timing = self._headers(dashboard, "/api/targets")["Server-Timing"]
        assert timing.startswith("route;dur=")
        assert float(timing.removeprefix("route;dur=")) >= 0.0
        # The shell and the content-hashed clients are on the congestion
        # window budget: no extra header bytes there.
        for path in ("/", _APP_JS_URL, "/boot-guard.js"):
            assert "Server-Timing" not in self._headers(dashboard, path), path

    def test_route_duration_tracks_the_query(self, dashboard: Dashboard) -> None:
        """The reported duration is the time the route actually took."""
        import time

        real_handle = dashboard.handle
        real_etag = dashboard.response_etag

        def slow_handle(*args: object, **kwargs: object) -> tuple[int, str, str]:
            time.sleep(0.05)
            return real_handle(*args, **kwargs)  # type: ignore[arg-type]

        def slow_etag(*args: object, **kwargs: object) -> str:
            time.sleep(0.05)
            return real_etag(*args, **kwargs)

        dashboard.handle = slow_handle  # type: ignore[method-assign]
        dashboard.response_etag = slow_etag  # type: ignore[method-assign]
        try:
            timing = self._headers(dashboard, "/api/targets")["Server-Timing"]
        finally:
            dashboard.handle = real_handle  # type: ignore[method-assign]
            dashboard.response_etag = real_etag  # type: ignore[method-assign]
        assert float(timing.removeprefix("route;dur=")) >= 50.0


class TestHostValidation:
    """Requests with a foreign Host header must be rejected (DNS rebinding)."""

    def test_loopback_bind_accepts_aliases(self) -> None:
        from rebrew.dashboard import _host_allowed, allowed_hosts_for

        allowed = allowed_hosts_for("127.0.0.1", 8000)
        assert "127.0.0.1:8000" in allowed
        assert "localhost:8000" in allowed
        assert "[::1]:8000" in allowed
        assert _host_allowed("LOCALHOST:8000", allowed)
        assert not _host_allowed("evil.example:8000", allowed)
        assert not _host_allowed("", allowed)

    def test_port_80_allows_bare_host(self) -> None:
        from rebrew.dashboard import _host_allowed, allowed_hosts_for

        allowed = allowed_hosts_for("127.0.0.1", 80)
        assert _host_allowed("localhost", allowed)
        assert _host_allowed("127.0.0.1", allowed)

    def test_non_loopback_bind_rejects_aliases(self) -> None:
        from rebrew.dashboard import _host_allowed, allowed_hosts_for

        allowed = allowed_hosts_for("192.168.1.10", 8000)
        assert _host_allowed("192.168.1.10:8000", allowed)
        assert not _host_allowed("localhost:8000", allowed)
        assert not _host_allowed("127.0.0.1:8000", allowed)

    def test_wildcard_bind_accepts_loopback_and_local_ips(self) -> None:
        """`--host 0.0.0.0` binds every interface, so the requests a user
        actually makes (`localhost`, `127.0.0.1`, the machine's own address)
        must be answered — the allow-list used to hold only the literal
        wildcard, so every real request got 403."""
        from rebrew.dashboard import _host_allowed, _local_interface_ips, allowed_hosts_for

        allowed = allowed_hosts_for("0.0.0.0", 8000)
        assert _host_allowed("0.0.0.0:8000", allowed)
        assert _host_allowed("localhost:8000", allowed)
        assert _host_allowed("127.0.0.1:8000", allowed)
        assert not _host_allowed("evil.example:8000", allowed)
        for ip in _local_interface_ips():
            display = f"[{ip}]" if ":" in ip else ip
            assert _host_allowed(f"{display}:8000", allowed), ip

    def test_handler_rejects_foreign_host(self) -> None:
        """A request whose Host is not the bound host gets 403 without touching the DB."""
        from rebrew.dashboard import Dashboard, _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)  # bypass __init__: no socket needed
        handler.headers = {"Host": "attacker.example:8000"}
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        sent: list[tuple] = []

        def fake_send_response(status: int) -> None:
            sent.append(("status", status))

        def fake_send_header(name: str, value: str) -> None:
            sent.append((name, value))

        def fake_end_headers() -> None:
            sent.append(("end", None))

        handler.send_response = fake_send_response
        handler.send_header = fake_send_header
        handler.end_headers = fake_end_headers
        written = []

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                written.append(data)
                return len(data)

        handler.wfile = _FakeWFile()
        handler._respond("GET")
        statuses = [v for k, v in sent if k == "status"]
        assert statuses == [403]
        assert b"not allowed" in bytes(written[0])
        header_names = {k for k, _ in sent if isinstance(k, str)}
        assert "X-Content-Type-Options" in header_names
        assert "X-Frame-Options" in header_names
        assert "Content-Security-Policy" in header_names
        assert "Referrer-Policy" in header_names
        assert "Permissions-Policy" in header_names
        assert ("Cache-Control", "no-store") in sent

    def test_handler_gzip_and_etag_on_index(self, dashboard: Dashboard) -> None:
        """HTML/JSON over Accept-Encoding: gzip shrink on the wire; ETag enables 304."""
        import gzip

        from rebrew.dashboard import _INDEX_ETAG, _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.headers = {
            "Host": "127.0.0.1:8000",
            "Accept-Encoding": "gzip, deflate, br",
        }
        handler.path = "/"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        sent: list[tuple] = []
        written: list[bytes] = []

        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                written.append(data)
                return len(data)

        handler.wfile = _FakeWFile()
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [200]
        assert ("Content-Encoding", "gzip") in sent
        assert ("ETag", _INDEX_ETAG) in sent
        assert ("Vary", "Accept-Encoding") in sent
        assert ("Cache-Control", "private, no-cache") in sent
        raw = b"".join(written)
        plain = gzip.decompress(raw)
        assert b"Rebrew coverage" in plain
        assert len(raw) < len(plain)

        # Revalidate with If-None-Match → empty 304 (no body re-download).
        sent.clear()
        written.clear()
        handler.headers = {
            "Host": "127.0.0.1:8000",
            "If-None-Match": _INDEX_ETAG,
        }
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [304]
        assert written == []

    @pytest.mark.parametrize(
        ("path", "cache_control"),
        [
            (f"/app.js?v={_APP_JS_VERSION}", "private, max-age=31536000, immutable"),
            ("/app.js?v=stale", "private, no-cache"),
            ("/app.js", "private, no-cache"),
            (f"/boot-guard.js?v={_BOOT_GUARD_JS_VERSION}", "private, max-age=31536000, immutable"),
            ("/boot-guard.js?v=stale", "private, no-cache"),
            ("/boot-guard.js", "private, no-cache"),
            ("/", "private, no-cache"),
        ],
    )
    def test_handler_caches_only_hashed_client_urls_immutable(
        self, dashboard: Dashboard, path: str, cache_control: str
    ) -> None:
        """The shell's hashed client URLs skip revalidation; other URLs revalidate."""
        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.path = path
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        sent: list[tuple] = []
        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                return len(data)

        handler.wfile = _FakeWFile()
        handler.headers = {"Host": "127.0.0.1:8000"}
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [200]
        assert ("Cache-Control", cache_control) in sent

        sent.clear()
        handler.headers = {
            "Host": "127.0.0.1:8000",
            "If-None-Match": dashboard.response_etag(path),
        }
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [304]
        assert ("Cache-Control", cache_control) in sent

    def test_index_html_links_favicon_inline(self, dashboard: Dashboard) -> None:
        """An inline icon keeps browsers from requesting /favicon.ico (a 404) per load."""
        _, _, html = dashboard.handle("GET", "/", {})
        assert '<link rel="icon" href="data:,">' in html

    def test_handler_304_skips_database_query(self, dashboard: Dashboard) -> None:
        """A matching If-None-Match on a JSON route answers 304 without querying."""
        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.path = "/api/functions?target=server_dll"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        etag = dashboard.response_etag(handler.path)
        handler.headers = {"Host": "127.0.0.1:8000", "If-None-Match": etag}
        sent: list[tuple] = []
        written: list[bytes] = []
        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                written.append(data)
                return len(data)

        handler.wfile = _FakeWFile()

        def _no_query(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
            raise AssertionError("revalidation must not run the query")

        dashboard.handle = _no_query  # type: ignore[method-assign]
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [304]
        assert ("ETag", etag) in sent
        assert written == []

        # Unrouted paths never 304, even with a matching validator.
        del dashboard.handle
        sent.clear()
        handler.path = "/nope"
        handler.headers = {"Host": "127.0.0.1:8000", "If-None-Match": "*"}
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [404]

        # A target-scoped route without ?target= keeps its 400, even for "*".
        for path in ("/api/functions", "/api/summary?target=%20"):
            sent.clear()
            handler.path = path
            handler.headers = {"Host": "127.0.0.1:8000", "If-None-Match": "*"}
            handler._respond("GET")
            assert [v for k, v in sent if k == "status"] == [400]

        # An unknown target has no representation: its 404 beats "*" and a
        # replayed DB-wide ETag.
        for inm in ("*", etag):
            sent.clear()
            handler.path = "/api/summary?target=nope"
            handler.headers = {"Host": "127.0.0.1:8000", "If-None-Match": inm}
            handler._respond("GET")
            assert [v for k, v in sent if k == "status"] == [404]

    def test_handler_etag_read_before_query(self, dashboard: Dashboard) -> None:
        """A DB rebuilt mid-query must not tag the old body with the new ETag."""
        import os

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.path = "/api/targets"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.headers = {"Host": "127.0.0.1:8000"}
        before = dashboard.response_etag(handler.path)
        sent: list[tuple] = []
        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                return len(data)

        handler.wfile = _FakeWFile()
        real_handle = dashboard.handle

        def _handle_then_rebuild(*args: object, **kwargs: object) -> tuple[int, str, str]:
            result = real_handle(*args, **kwargs)  # type: ignore[arg-type]
            st = dashboard.db_path.stat()
            os.utime(dashboard.db_path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
            return result

        dashboard.handle = _handle_then_rebuild  # type: ignore[method-assign]
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [200]
        assert dashboard.response_etag(handler.path) != before
        assert ("ETag", before) in sent

    def test_etag_separates_targets_and_filters(self, dashboard: Dashboard) -> None:
        """One validator per representation, not one per database file."""
        st = dashboard.db_path.stat()
        bare = f'W/"{st.st_mtime_ns:x}-{st.st_size:x}"'
        targets = dashboard.response_etag("/api/summary?target=server_dll")
        assert targets != dashboard.response_etag("/api/summary?target=other_dll")
        assert targets != dashboard.response_etag("/api/summary?target=server_dll&limit=5")
        # A different route on the same target answers a different body.
        assert targets != dashboard.response_etag("/api/functions?target=server_dll")
        # A query-less route has nothing to scope, so it keeps the bare DB tag.
        assert dashboard.response_etag("/api/targets") == bare
        assert dashboard.response_etag("/api/bootstrap") == bare

    def test_etag_of_one_route_does_not_304_another(self, dashboard: Dashboard) -> None:
        """A validator held from one route must not stand in for another."""
        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        sent: list[tuple] = []
        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                return len(data)

        handler.wfile = _FakeWFile()
        held = dashboard.response_etag("/api/functions?target=server_dll")
        handler.path = "/api/summary?target=server_dll"
        handler.headers = {"Host": "127.0.0.1:8000", "If-None-Match": held}
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [200]
        assert ("ETag", dashboard.response_etag(handler.path)) in sent

    def test_functions_omit_unused_marker_type(self, dashboard: Dashboard) -> None:
        """The table never reads markerType; keep it off the JSON wire."""
        row = dashboard.functions("server_dll")["functions"][0]
        assert dashboard.functions("server_dll")["cols"] == [
            "va",
            "name",
            "symbol",
            "size",
            "status",
            "module",
            "files",
        ]
        assert isinstance(row, list)
        assert len(row) == 7
        assert dashboard.globals("server_dll")["cols"] == [
            "va",
            "name",
            "decl",
            "size",
            "module",
        ]
        assert dashboard.history("server_dll")["cols"] == [
            "va",
            "name",
            "old_status",
            "new_status",
            "changed_at",
        ]

    def test_index_html_bootstraps_in_one_round_trip(self, dashboard: Dashboard) -> None:
        """Cold start uses /api/bootstrap; target changes still parallel-fetch."""
        _, _, html = dashboard.handle("GET", "/", {})
        _, _, js = dashboard.handle("GET", "/app.js", {})
        assert 'get("/api/bootstrap")' in js
        assert 'rel="preload" href="/api/bootstrap" as="fetch" crossorigin' in html
        assert 'fetchpriority="high"' in html
        assert f'rel="preload" href="/app.js?v={_APP_JS_VERSION}" as="script"' in html
        assert f'src="/app.js?v={_APP_JS_VERSION}" defer' in html
        # preload crossorigin=anonymous uses credentials "same-origin"; any other
        # fetch credentials mode misses the preload and downloads bootstrap twice.
        assert "await fetch(path, { signal })" in js
        assert "credentials:" not in js
        assert "Promise.all([loadSummary()," in js
        assert "loadFunctions()" in js
        assert "loadCurrentView(true)" in js
        assert "renderSummary" in js
        assert "renderFunctions" in js
        assert "renderSections" in js
        assert "renderGlobals" in js
        assert "renderHistory" in js

    @pytest.mark.parametrize(
        ("path", "accept", "encoding", "blob_attr", "raw_attr"),
        [
            ("/", "gzip", "gzip", "_INDEX_HTML_GZIP", "_INDEX_HTML_BYTES"),
            ("/", "zstd", "zstd", "_INDEX_HTML_ZSTD", "_INDEX_HTML_BYTES"),
            ("/app.js", "gzip", "gzip", "_APP_JS_GZIP", "_APP_JS_BYTES"),
            ("/app.js", "zstd", "zstd", "_APP_JS_ZSTD", "_APP_JS_BYTES"),
        ],
    )
    def test_handler_serves_precompressed_static(
        self,
        dashboard: Dashboard,
        path: str,
        accept: str,
        encoding: str,
        blob_attr: str,
        raw_attr: str,
    ) -> None:
        """Static shell and /app.js are compressed once at import, not per request."""
        import gzip

        import zstandard

        import rebrew.dashboard as dash
        from rebrew.dashboard import _Handler, allowed_hosts_for

        blob = getattr(dash, blob_attr)
        raw_bytes = getattr(dash, raw_attr)
        assert blob is not None
        assert len(blob) < len(raw_bytes)
        if blob_attr.endswith("_ZSTD"):
            gzip_attr = blob_attr.replace("_ZSTD", "_GZIP")
            gzip_blob = getattr(dash, gzip_attr)
            assert gzip_blob is not None
            assert len(blob) <= len(gzip_blob)

        handler = _Handler.__new__(_Handler)
        handler.headers = {
            "Host": "127.0.0.1:8000",
            "Accept-Encoding": accept,
        }
        handler.path = path
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        sent: list[tuple] = []
        written: list[bytes] = []

        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                written.append(data)
                return len(data)

        handler.wfile = _FakeWFile()
        handler._respond("GET")
        raw = b"".join(written)
        assert ("Content-Encoding", encoding) in sent
        assert raw == blob
        if encoding == "gzip":
            assert gzip.decompress(raw) == raw_bytes
            # mtime=0: the body is a pure function of the uncompressed bytes.
            assert int.from_bytes(raw[4:8], "little") == 0
        else:
            assert zstandard.ZstdDecompressor().decompress(raw) == raw_bytes

    @pytest.mark.parametrize("control", ["\x1b", "\n", "\r", "\x7f", "\x9b"])
    def test_handler_log_escapes_controls(
        self, control: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from io import StringIO

        from rich.console import Console

        from rebrew.dashboard import _Handler

        output = StringIO()
        monkeypatch.setattr(
            "rebrew.dashboard.console",
            Console(file=output, width=200, color_system=None, highlight=False),
        )
        handler = _Handler.__new__(_Handler)
        handler.client_address = ("127.0.0.1", 8000)
        handler.log_message('"%s" %s', f"GET /before{control}after HTTP/1.1", 200)
        rendered = output.getvalue()
        assert f"before\\x{ord(control):02x}after" in rendered
        assert rendered.count("\n") == 1
        assert "127.0.0.1" in rendered
        assert "200" in rendered

    def test_handler_log_stamps_utc_not_host_local(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Access and error lines share one UTC stamp whatever TZ the host has.

        A Europe/Warsaw host in summer is +02:00, so a localtime stamp puts the
        two streams an hour apart and a fall-back night repeats one.
        """
        import re
        from datetime import UTC, datetime
        from io import StringIO

        from rich.console import Console

        from rebrew.dashboard import _attach_server_log_handler, _Handler

        # TZ is set by hand: monkeypatch would restore the variable only after
        # the test body, leaving the process on Warsaw time for later tests.
        previous_tz = os.environ.get("TZ")
        os.environ["TZ"] = "Europe/Warsaw"
        time.tzset()
        try:
            access_out = StringIO()
            monkeypatch.setattr(
                "rebrew.dashboard.console",
                Console(file=access_out, width=200, color_system=None, highlight=False),
            )
            handler = _Handler.__new__(_Handler)
            handler.client_address = ("127.0.0.1", 8000)
            handler.log_message('"%s" %s', "GET / HTTP/1.1", 200)

            error_out = StringIO()
            _attach_server_log_handler()
            server_log = logging.getLogger("rebrew.dashboard")
            attached = [h for h in server_log.handlers if h.get_name() == "rebrew-dashboard"]
            try:
                for h in attached:
                    h.stream = error_out
                server_log.error("boom")
            finally:
                for h in attached:
                    server_log.removeHandler(h)
        finally:
            if previous_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous_tz
            time.tzset()

        stamp = re.compile(r"(\d{2}):(\d{2}):(\d{2}) UTC")
        now = datetime.now(UTC)
        for rendered, level in ((access_out.getvalue(), "INFO"), (error_out.getvalue(), "ERROR")):
            match = stamp.search(rendered)
            assert match is not None, rendered
            assert f" {level}" in rendered
            hh, mm, ss = (int(part) for part in match.groups())
            # The line was written at most a second ago: the stamp is UTC, not
            # the host's Europe/Warsaw wall clock.
            delta = abs(
                (
                    now - datetime(now.year, now.month, now.day, hh, mm, ss, tzinfo=UTC)
                ).total_seconds()
            )
            assert delta < 5, rendered

    def test_handler_unexpected_error_answers_500(self) -> None:
        """An unexpected route error must answer 500 JSON, not reset the connection."""
        from rebrew.dashboard import Dashboard, _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)  # bypass __init__: no socket needed
        handler.headers = {"Host": "127.0.0.1:8000"}
        handler.path = "/api/targets"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        # Simulate any non-sqlite failure inside a route (bug, OSError, ...).
        handler.dashboard.handle = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
        sent: list[tuple] = []

        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]
        written: list[bytes] = []

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                written.append(data)
                return len(data)

        handler.wfile = _FakeWFile()
        handler._respond("GET")
        statuses = [v for k, v in sent if k == "status"]
        assert statuses == [500]
        body = b"".join(written)
        assert b"internal server error" in body

    def test_handler_sqlite_error_hides_details(self, capsys: pytest.CaptureFixture[str]) -> None:
        """SQLite failures answer a generic 500 — no schema/path leak on the wire."""
        import sqlite3

        from rebrew.dashboard import Dashboard, _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.headers = {"Host": "127.0.0.1:8000"}
        handler.path = "/api/targets\x1b"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        handler.dashboard.handle = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[method-assign]
            sqlite3.DatabaseError("no such table: secrets\x1b")
        )
        sent: list[tuple] = []
        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]
        written: list[bytes] = []

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                written.append(data)
                return len(data)

        handler.wfile = _FakeWFile()
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [500]
        body = b"".join(written)
        assert b'"database error"' in body
        assert b"no such table" not in body
        assert b"secrets" not in body
        stderr = capsys.readouterr().err
        assert "\x1b" not in stderr
        assert "/api/targets\\x1b" in stderr
        assert "secrets\\x1b" in stderr

    def test_handler_revalidation_sqlite_error_answers_500(self) -> None:
        """A DB failure during the 304 target probe is a 500 JSON, not a reset."""
        from rebrew.dashboard import Dashboard, _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.headers = {"Host": "127.0.0.1:8000", "If-None-Match": "*"}
        handler.path = "/api/functions?target=server_dll"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        sent: list[tuple] = []
        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]
        written: list[bytes] = []

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                written.append(data)
                return len(data)

        handler.wfile = _FakeWFile()
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [500]
        assert b'"database error"' in b"".join(written)

    def test_handler_revalidation_corrupt_summary_answers_500(self, dashboard: Dashboard) -> None:
        """``If-None-Match: *`` on a corrupt summary gets the GET's 500, not 304."""
        import sqlite3

        from rebrew.dashboard import _Handler, allowed_hosts_for

        conn = sqlite3.connect(dashboard.db_path)
        conn.execute(
            "UPDATE metadata SET value = '[1]' WHERE target = 'server_dll' "
            "AND key = 'function_stats'"
        )
        conn.commit()
        conn.close()
        handler = _Handler.__new__(_Handler)
        handler.headers = {"Host": "127.0.0.1:8000", "If-None-Match": "*"}
        handler.path = "/api/summary?target=server_dll"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        sent: list[tuple] = []
        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                return len(data)

        handler.wfile = _FakeWFile()
        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [500]

    def test_handler_unexpected_error_logs_traceback(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A handler bug must leave a traceback, not just the wire's 500."""
        from rebrew.dashboard import Dashboard, _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)  # bypass __init__: no socket needed
        handler.headers = {"Host": "127.0.0.1:8000"}
        handler.path = "/api/targets"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        handler.dashboard.handle = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
        handler._request_id = "r7"
        handler.send_response = lambda status: None  # type: ignore[method-assign]
        handler.send_header = lambda name, value: None  # type: ignore[method-assign]
        handler.end_headers = lambda: None  # type: ignore[method-assign]
        handler.wfile = _NullWFile()

        with caplog.at_level(logging.ERROR, logger="rebrew.dashboard"):
            handler._respond("GET")

        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1
        text = errors[0].getMessage()
        assert "dashboard handler failed for /api/targets" in text
        assert "RuntimeError: boom" in text
        assert "Traceback" in text
        assert text.split()[0] == handler._request_id

    def test_route_level_500_is_logged_with_the_request(
        self, dashboard: Dashboard, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A route that answers 500 on its own still names the failing request."""
        from rebrew.dashboard import _Handler, allowed_hosts_for

        conn = sqlite3.connect(dashboard.db_path)
        conn.execute(
            "UPDATE metadata SET value = '[1]' WHERE target = 'server_dll' "
            "AND key = 'function_stats'"
        )
        conn.commit()
        conn.close()
        handler = _Handler.__new__(_Handler)
        handler.headers = {"Host": "127.0.0.1:8000"}
        handler.path = "/api/summary?target=server_dll"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.send_response = lambda status: None  # type: ignore[method-assign]
        handler.send_header = lambda name, value: None  # type: ignore[method-assign]
        handler.end_headers = lambda: None  # type: ignore[method-assign]
        handler.wfile = _NullWFile()

        with caplog.at_level(logging.ERROR, logger="rebrew.dashboard"):
            handler._respond("GET")

        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert [r.getMessage() for r in errors] == [
            "- dashboard GET /api/summary?target=server_dll returned 500"
        ]

    def test_failed_request_log_escapes_control_chars(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The traceback carries remote text, so it is escaped like the request line."""
        from rebrew.dashboard import _log_failed_request

        with caplog.at_level(logging.ERROR, logger="rebrew.dashboard"):
            try:
                raise RuntimeError("no such table: secrets\x1b")
            except RuntimeError as exc:
                _log_failed_request("dashboard query failed", "/api/targets\x1b", exc, "r3")

        text = caplog.records[-1].getMessage()
        assert "\x1b" not in text
        assert "/api/targets\\x1b" in text
        assert "secrets\\x1b" in text
        assert text.startswith("r3 dashboard query failed")


class TestAccessLog:
    """The access line has to answer status and how long the handler took."""

    def test_request_line_carries_handler_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from io import StringIO

        from rich.console import Console

        from rebrew.dashboard import _Handler

        output = StringIO()
        monkeypatch.setattr(
            "rebrew.dashboard.console",
            Console(file=output, width=40, color_system=None, highlight=False),
        )
        handler = _Handler.__new__(_Handler)
        handler.client_address = ("127.0.0.1", 8000)
        handler.requestline = "GET /api/summary?target=server_dll HTTP/1.1"
        handler._request_started = time.perf_counter() - 0.25
        handler.log_request(200, 1024)
        rendered = output.getvalue()
        assert '"GET /api/summary?target=server_dll HTTP/1.1" 200 1024' in rendered
        assert "ms" in rendered
        # width=40: a wrapped line would break log parsing.
        assert rendered.count("\n") == 1

    def test_each_request_on_a_connection_restamps_the_clock(self) -> None:
        """A keep-alive handler serves many requests; the clock must reset each time."""
        from io import BytesIO

        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.rfile = BytesIO(
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n"
            b"GET /api/targets HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n"
        )
        handler.wfile = BytesIO()
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        handler.log_message = lambda *a, **k: None  # type: ignore[method-assign]
        for _ in range(2):
            stale = time.perf_counter() - 60.0
            handler._request_started = stale
            handler.handle_one_request()
            assert handler._request_started > stale

    def test_each_request_gets_its_own_correlation_id(self) -> None:
        """The id has to advance per request, or an error line cannot be pivoted."""
        from io import BytesIO

        from rebrew.dashboard import Dashboard, _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.rfile = BytesIO(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n")
        handler.wfile = BytesIO()
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        handler.log_message = lambda *a, **k: None  # type: ignore[method-assign]
        handler.handle_one_request()
        first = handler._request_id
        assert first.startswith("r")
        handler._request_started = time.perf_counter()
        handler.handle_one_request()
        assert handler._request_id != first


class TestServedCounters:
    """The access log also feeds the lifetime totals printed on shutdown."""

    def test_requests_errors_and_slowest_are_counted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.dashboard import _Handler

        monkeypatch.setattr(_Handler, "_requests", 0)
        monkeypatch.setattr(_Handler, "_server_errors", 0)
        monkeypatch.setattr(_Handler, "_slowest_ms", 0.0)
        handler = _Handler.__new__(_Handler)
        handler.client_address = ("127.0.0.1", 8000)
        handler.requestline = "GET /api/targets HTTP/1.1"
        handler._request_id = "r1"
        handler.log_message = lambda *a, **k: None  # type: ignore[method-assign]
        handler._request_started = time.perf_counter() - 0.05
        handler.log_request(200, 1024)
        handler._request_started = time.perf_counter()
        handler.log_request(500, 64)
        assert _Handler._requests == 2
        assert _Handler._server_errors == 1
        assert _Handler._slowest_ms >= 50.0


class TestThreadFaults:
    """socketserver's default handle_error prints an unstampable traceback."""

    @staticmethod
    def _server() -> _DashboardServer:
        # handle_error reports through the module logger and _Handler's
        # counters only, so a server with no bound socket reports just as well.
        return _DashboardServer.__new__(_DashboardServer)

    def test_fault_is_logged_with_the_request_id(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.dashboard import _Handler, _stamp_request

        monkeypatch.setattr(_Handler, "_server_errors", 0)
        _stamp_request("r42", "GET /api/targets HTTP/1.1\x1b")
        with caplog.at_level(logging.ERROR, logger="rebrew.dashboard"):
            try:
                raise RuntimeError("boom")
            except RuntimeError:
                self._server().handle_error(None, ("127.0.0.1", 51234))  # type: ignore[arg-type]

        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1
        text = errors[0].getMessage()
        assert text.startswith("r42 unhandled RuntimeError from ('127.0.0.1', 51234) serving ")
        assert "/api/targets HTTP/1.1\\x1b" in text
        assert "RuntimeError: boom" in text
        assert _Handler._server_errors == 1

    def test_client_disconnect_is_info_and_not_a_server_error(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.dashboard import _Handler, _stamp_request

        monkeypatch.setattr(_Handler, "_server_errors", 0)
        _stamp_request("r43", "GET /api/functions HTTP/1.1")
        with caplog.at_level(logging.INFO, logger="rebrew.dashboard"):
            try:
                raise BrokenPipeError(32, "Broken pipe")
            except BrokenPipeError:
                self._server().handle_error(None, ("127.0.0.1", 51235))  # type: ignore[arg-type]

        assert [r.getMessage() for r in caplog.records] == [
            "r43 client disconnected serving GET /api/functions HTTP/1.1"
        ]
        assert _Handler._server_errors == 0

    def test_request_line_is_stamped_for_the_next_request(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A keep-alive thread must not blame the previous request's line."""
        from io import BytesIO

        from rebrew.dashboard import _Handler, _stamp_request

        _stamp_request("r44", "GET /api/globals HTTP/1.1")
        handler = _Handler.__new__(_Handler)
        handler.rfile = BytesIO(b"")  # no request: the handler returns at once
        handler.handle_one_request()
        with caplog.at_level(logging.ERROR, logger="rebrew.dashboard"):
            try:
                raise RuntimeError("boom")
            except RuntimeError:
                self._server().handle_error(None, ("127.0.0.1", 51236))  # type: ignore[arg-type]
        text = caplog.records[-1].getMessage()
        assert text.startswith(f"{handler._request_id} unhandled RuntimeError")
        assert "serving -\n" in text

    def test_fault_on_a_live_connection_names_its_request(
        self, dashboard: Dashboard, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The whole wiring, on a real socket: request line, id, and ERROR level."""
        import http.client
        import threading

        from rebrew.dashboard import _Handler, allowed_hosts_for

        class _FaultingHandler(_Handler):
            def _respond(self, method: str) -> None:
                super()._respond(method)
                raise RuntimeError("boom after the response")

        server = _DashboardServer(("127.0.0.1", 0), _FaultingHandler)
        server.daemon_threads = True
        _FaultingHandler.dashboard = dashboard
        _FaultingHandler.allowed_hosts = allowed_hosts_for("127.0.0.1", server.server_port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with caplog.at_level(logging.ERROR, logger="rebrew.dashboard"):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("GET", "/", headers={"Host": f"127.0.0.1:{server.server_port}"})
                assert conn.getresponse().status == 200
                conn.close()
                # The fault is reported on the handler thread after the response
                # is written, so the log line arrives a moment later.
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and not caplog.records:
                    time.sleep(0.02)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        assert not thread.is_alive()
        errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1
        assert "unhandled RuntimeError" in errors[0]
        assert "serving GET / HTTP/1.1\n" in errors[0]
        assert "RuntimeError: boom after the response" in errors[0]


class TestHealthRoute:
    """The probe must prove the database is readable, not just that we are up."""

    def test_health_reports_targets(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("GET", "/api/health", {})
        assert status == 200
        assert content_type.startswith("application/json")
        payload = json.loads(body)
        assert payload["status"] == "ok"
        assert payload["db"] == str(dashboard.db_path)
        assert payload["targets"] == len(dashboard.targets())

    def test_health_is_not_an_etag_route(self) -> None:
        """A 304 on the probe would report a stale 'healthy' for a dead db."""
        from rebrew.dashboard import _ROUTES

        assert "/api/health" not in _ROUTES

    def test_health_carries_no_validator_and_is_not_stored(self, dashboard: Dashboard) -> None:
        """The probe's 200 hands out no ETag and forbids storing the body.

        The route is outside ``_ROUTES``, so the server ignores
        ``If-None-Match`` itself; without the header a client (or a proxy) can
        still replay the validator by hand and read a stored "ok" long after
        the database read that produced it stopped working.
        """
        from rebrew.dashboard import _Handler, allowed_hosts_for

        handler = _Handler.__new__(_Handler)
        handler.path = "/api/health"
        handler.allowed_hosts = allowed_hosts_for("127.0.0.1", 8000)
        handler.dashboard = dashboard
        handler.headers = {
            "Host": "127.0.0.1:8000",
            "If-None-Match": dashboard.response_etag(handler.path),
        }
        sent: list[tuple] = []

        class _FakeWFile:
            def write(self, data: bytes) -> int:
                return len(data)

        handler.wfile = _FakeWFile()
        handler.send_response = lambda status: sent.append(("status", status))  # type: ignore[method-assign]
        handler.send_header = lambda name, value: sent.append((name, value))  # type: ignore[method-assign]
        handler.end_headers = lambda: sent.append(("end", None))  # type: ignore[method-assign]

        handler._respond("GET")
        assert [v for k, v in sent if k == "status"] == [200]
        assert not [v for k, v in sent if k == "ETag"]
        assert ("Cache-Control", "no-store") in sent

    def test_health_propagates_an_unreadable_database(self) -> None:
        """The probe's read must raise, which _respond turns into 500 database_error."""
        from rebrew.dashboard import Dashboard

        dashboard = Dashboard(Path("/nonexistent/coverage.db"))
        with pytest.raises(sqlite3.Error):
            dashboard.handle("GET", "/api/health", {})

    def test_health_rejects_writes(self, dashboard: Dashboard) -> None:
        status, _, body = dashboard.handle("POST", "/api/health", {})
        assert status == 405
        assert json.loads(body)["code"] == "method_not_allowed"


class TestKeepAliveTimeout:
    """Idle keep-alive clients must not pin a handler thread forever."""

    def test_idle_connection_is_closed_by_server(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import socket
        import threading
        from http.server import ThreadingHTTPServer

        from rebrew.dashboard import _KEEPALIVE_IDLE_TIMEOUT_S, _Handler

        assert _Handler.timeout == _KEEPALIVE_IDLE_TIMEOUT_S
        monkeypatch.setattr(_Handler, "timeout", 0.2)
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        serve = threading.Thread(target=server.serve_forever, daemon=True)
        serve.start()
        try:
            with socket.create_connection(server.server_address[:2], timeout=5) as client:
                # Send nothing: the server must hang up once its idle timeout
                # fires, well before the client's own 5s guard.
                assert client.recv(1) == b""
        finally:
            server.shutdown()
            server.server_close()
            serve.join(timeout=5)


class TestResponseFraming:
    """The cold-load response is one segment, with no interpreter banner.

    Headers and body are written separately, so Nagle would hold the body's
    first segment until the header block is acknowledged.  The stdlib
    ``Server`` banner adds 38 bytes to every response against the
    per-response header reserve and names the interpreter patch level.
    """

    def test_nagle_is_disabled(self) -> None:
        from rebrew.dashboard import _Handler

        assert _Handler.disable_nagle_algorithm is True

    def test_no_server_banner(self, dashboard: Dashboard) -> None:
        import socket
        import threading
        from http.server import ThreadingHTTPServer

        from rebrew.dashboard import _Handler, allowed_hosts_for

        class Bound(_Handler):
            allowed_hosts: frozenset[str] = frozenset()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Bound)
        server.daemon_threads = True
        Bound.dashboard = dashboard
        Bound.allowed_hosts = allowed_hosts_for("127.0.0.1", server.server_address[1])
        serve = threading.Thread(target=server.serve_forever, daemon=True)
        serve.start()
        try:
            with socket.create_connection(server.server_address[:2], timeout=5) as client:
                client.sendall(
                    b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                    b"Accept-Encoding: gzip\r\nConnection: close\r\n\r\n" % server.server_address[1]
                )
                chunks = []
                while chunk := client.recv(65536):
                    chunks.append(chunk)
        finally:
            server.shutdown()
            server.server_close()
            serve.join(timeout=5)
        head = b"".join(chunks).partition(b"\r\n\r\n")[0].decode()
        assert "Server:" not in head
        assert head.startswith("HTTP/1.1 200 OK")
        assert "Date:" in head


class TestInvisibleControlScrub:
    """API text must not carry bidi or zero-width controls into the DOM."""

    def test_nested_payload_scrubbed(self) -> None:
        from rebrew.dashboard import _scrub_invisible

        payload = {
            "target": "server\u202e_dll",
            "functions": [["0x1", "sub_A\u202etxt", None, 12, "EXACT", "", None]],
            "total": 1,
        }
        assert _scrub_invisible(payload) == {
            "target": "server_dll",
            "functions": [["0x1", "sub_Atxt", None, 12, "EXACT", "", None]],
            "total": 1,
        }

    def test_api_response_is_scrubbed(self, dashboard: Dashboard) -> None:
        import json
        from urllib.parse import parse_qs

        from rebrew.utils import _BIDI_FORMAT_CHARS

        _, _, body = dashboard.handle(
            "GET", "/api/functions", parse_qs("target=server_dll&limit=1")
        )
        assert not _BIDI_FORMAT_CHARS.intersection(body)
        assert json.loads(body)["functions"]


_SPEC = Path(__file__).resolve().parents[1] / "docs" / "dashboard-api.yaml"


def _spec() -> dict:
    import yaml

    return yaml.safe_load(_SPEC.read_text(encoding="utf-8"))


class TestOpenApiSpec:
    """The published contract is checked against the code, not trusted."""

    def test_spec_lists_exactly_the_served_routes(self) -> None:
        from rebrew.dashboard import _KNOWN_ROUTES

        assert set(_spec()["paths"]) == set(_KNOWN_ROUTES)

    def test_every_route_is_get_and_head_only(self) -> None:
        for path, item in _spec()["paths"].items():
            assert set(item) == {"get", "head"}, path
            # A HEAD response carries the same headers as its GET, so the
            # documented statuses and parameters must match.
            assert set(item["get"]["responses"]) == set(item["head"]["responses"]), path
            assert item["get"].get("parameters") == item["head"].get("parameters"), path

    def test_status_vocabulary_matches(self) -> None:
        """The documented filter set is the DB column's own vocabulary, so a
        status the summary renders as a card can always be filtered on."""
        from rebrew.workspace.status import COVERAGE_DB_STATUSES

        declared = _spec()["components"]["parameters"]["Status"]["schema"]["enum"]
        assert sorted(declared) == sorted(COVERAGE_DB_STATUSES)

    def test_error_codes_are_all_reachable(self) -> None:
        """A documented code the server can never emit is a lie to branch on."""
        from rebrew import dashboard

        from_http = set(dashboard._HTTP_ERROR_CODES.values()) | {"request_error"}
        source = Path(dashboard.__file__).read_text(encoding="utf-8")
        declared = _spec()["components"]["schemas"]["ErrorCode"]["enum"]
        for code in declared:
            assert code in from_http or f'"{code}"' in source, code

    def test_documented_envelope_fields_match_the_query_layer(self, dashboard: Dashboard) -> None:
        """The fields a schema declares are the fields the server populates."""
        schemas = _spec()["components"]["schemas"]
        for path, schema_name, payload in (
            ("/api/functions", "Functions", dashboard.functions("server_dll")),
            ("/api/sections", "Sections", dashboard.sections("server_dll")),
            ("/api/globals", "Globals", dashboard.globals("server_dll")),
            ("/api/history", "History", dashboard.history("server_dll")),
        ):
            declared = set(schemas[schema_name]["allOf"][1]["properties"])
            meta = set(schemas["ListMeta"]["properties"])
            assert declared | meta == set(payload), path
            assert declared <= set(payload), path

    def test_documented_cols_match_the_row_layout(self, dashboard: Dashboard) -> None:
        from rebrew import dashboard as module

        schemas = _spec()["components"]["schemas"]
        for schema_name, key, cols in (
            ("Functions", "functions", module._FUNCTION_COLS),
            ("Sections", "sections", module._SECTION_COLS),
            ("Globals", "globals", module._GLOBAL_COLS),
            ("History", "history", module._HISTORY_COLS),
        ):
            body = schemas[schema_name]["allOf"][1]["properties"]
            assert tuple(body["cols"]["const"]) == cols
            row = body[key]["items"]
            assert row["minItems"] == row["maxItems"] == len(cols)

    def test_bootstrap_and_targets_envelopes_match(self, dashboard: Dashboard) -> None:
        schemas = _spec()["components"]["schemas"]
        _, _, body = dashboard.handle("GET", "/api/bootstrap", {})
        payload = json.loads(body)
        assert set(schemas["Bootstrap"]["properties"]) == set(payload)
        _, _, body = dashboard.handle("GET", "/api/targets", {})
        assert set(schemas["Targets"]["properties"]) == set(json.loads(body))

    def test_every_ref_resolves(self) -> None:
        """A dangling `$ref` makes the spec unusable for a generated client.

        Nothing else in this class resolves the pointers, so a renamed
        response or schema would pass every check here and fail only in the
        consumer's code generator.
        """
        spec = _spec()

        def resolve(ref: str) -> object:
            node: object = spec
            for part in ref.removeprefix("#/").split("/"):
                assert isinstance(node, dict), ref
                assert part in node, ref
                node = node[part]
            return node

        def walk(node: object) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "$ref":
                        assert isinstance(value, str) and value.startswith("#/"), value
                        resolve(value)
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(spec)

    def test_every_route_declares_a_500(self) -> None:
        """The handler guard wraps every route, so no route is 500-free.

        A route with no declared 500 leaves a generated client with no
        branch for a server-side failure, and a client that treats it as
        an unlisted status either drops the body or reports success.
        """
        responses = _spec()["components"]["responses"]
        for path, item in _spec()["paths"].items():
            for method in ("get", "head"):
                ref = item[method]["responses"]["500"]["$ref"]
                name = ref.rsplit("/", 1)[-1]
                assert name in ("DatabaseError", "CorruptStats"), (path, method, name)
                assert (
                    responses[name]["content"]["application/json"]["schema"]["$ref"]
                    == "#/components/schemas/Error"
                ), (path, method, name)

    def test_va_pattern_accepts_a_64_bit_address(self, dashboard: Dashboard) -> None:
        """A `va` past 32 bits serializes to more than eight hex digits.

        The query layer pads to eight with ``:08x``, which is a minimum and
        not a width, and ``VA_MAX`` is the int64 range.  A pattern pinned to
        exactly eight digits would reject a perfectly valid response from a
        64-bit target and break a generated client's validator.
        """
        import re

        high = 0x140001000
        with sqlite3.connect(dashboard.db_path) as conn:
            conn.execute(
                "INSERT INTO functions (target, va, name, size, status) "
                "VALUES ('server_dll', ?, 'func_high', 16, 'EXACT')",
                (high,),
            )
        pattern = re.compile(_spec()["components"]["schemas"]["Va"]["pattern"])
        rows = dashboard.functions("server_dll")["functions"]
        assert high == 0x140001000  # the literal survives a round trip through SQLite
        rendered = {row[1]: row[0] for row in rows}["func_high"]
        assert rendered == "0x140001000"
        assert pattern.fullmatch(rendered), rendered
        # The 32-bit rows the dashboard actually serves still match.
        assert pattern.fullmatch("0x10001000")
        assert pattern.fullmatch("???")
