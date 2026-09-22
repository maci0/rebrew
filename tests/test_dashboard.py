"""Tests for rebrew dashboard — read-only web dashboard over coverage.db."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.build_db import build_db
from rebrew.dashboard import _APP_JS, Dashboard, _files_display


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


@pytest.fixture()
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
        # Headline coverage = MATCHED bytes only (EXACT/RELOC/PROVEN): the
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
        assert json.loads(body) == {"error": "corrupt function_stats metadata"}
        status, _, body = dashboard.handle("GET", "/api/summary", {"target": ["notobj"]})
        assert status == 500
        assert "corrupt" in json.loads(body)["error"]
        # Sibling list route still treats the target as known.
        status, _, body = dashboard.handle("GET", "/api/functions", {"target": ["broken"]})
        assert status == 200
        assert json.loads(body)["target"] == "broken"

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

    def test_sections(self, dashboard: Dashboard) -> None:
        payload = dashboard.sections("server_dll")
        sections = payload["sections"]
        assert payload["count"] == len(sections)
        assert payload["total"] == len(sections)
        by_name = {s["name"]: s for s in sections}
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


class TestSummaryRequests:
    def test_latest_summary_wins(self) -> None:
        node = shutil.which("node")
        if node is None:
            pytest.skip("Node.js is required for dashboard interaction tests")
        result = subprocess.run(
            [node, str(Path(__file__).with_name("dashboard_summary.mjs"))],
            input=_APP_JS,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr


class TestHashState:
    def test_reload_restores_target_view_and_filters(self) -> None:
        node = shutil.which("node")
        if node is None:
            pytest.skip("Node.js is required for dashboard interaction tests")
        result = subprocess.run(
            [node, str(Path(__file__).with_name("dashboard_hash_state.mjs"))],
            input=_APP_JS,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr


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
        assert '<script src="/app.js" defer></script>' in html
        assert 'rel="preload" href="/app.js" as="script"' in html
        assert 'fetchpriority="high"' in html
        assert "content-visibility: auto" in html
        assert "const $" in js
        assert '<main id="main" tabindex="-1">' in body
        assert 'href="#main"' in body
        assert "Skip to content" in body
        assert 'lang="en"' in body
        assert '<label for="q">Search name or symbol</label>' in body
        assert '<label for="module">Module</label>' in body
        assert '<label for="gq">Search global name</label>' in body
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
        assert 'role="tabpanel"' in body
        assert "aria-pressed" in body
        assert "ArrowRight" in body  # tablist keyboard nav
        assert 'aria-label="Retry failed loads"' in body
        assert "border: 1px solid #767676" in body  # WCAG 1.4.11 non-text contrast
        assert "#ccc" not in body
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
        # in a DST zone cannot mis-parse them as local wall time.
        assert 'raw += "Z"' in body
        assert "Reload dashboard" in body
        assert 'retry-summary").focus()' in body
        assert "No status changes recorded yet" in body
        assert "No section stats for this target" in body
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
        assert "Share of .text bytes at EXACT" in body
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
        assert payload["functions"]["limit"] == 100
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

        from rebrew.workspace import open_sqlite_ro

        status, _, _ = dashboard.handle("GET", "/api/targets", {})
        assert status == 200
        # Attempt a write through a fresh ro connection must fail.
        with pytest.raises(sqlite3.OperationalError):
            conn = open_sqlite_ro(dashboard.db_path)
            with conn:
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


class TestHttpMethods:
    @pytest.mark.parametrize(
        "method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"]
    )
    @pytest.mark.parametrize(
        "path",
        [
            "/",
            "/app.js",
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
        assert json.loads(body) == {"error": "method not allowed (read-only; GET, HEAD only)"}

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
    @pytest.mark.parametrize("path", ["/", "/app.js", "/api/bootstrap"])
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
        assert 'rel="preload" href="/app.js" as="script"' in html
        assert 'src="/app.js" defer' in html
        assert 'credentials: "omit"' in js
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
