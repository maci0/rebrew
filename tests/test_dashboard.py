"""Tests for rebrew dashboard — read-only web dashboard over coverage.db."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.build_db import build_db
from rebrew.dashboard import Dashboard


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

    def test_summary(self, dashboard: Dashboard) -> None:
        s = dashboard.summary("server_dll")
        assert s is not None
        assert s["function_stats"]["total"] == 2
        assert s["function_stats"]["by_status"] == {"EXACT": 1, "STUB": 1}
        # Headline coverage = MATCHED bytes only (EXACT/RELOC/PROVEN): the
        # EXACT function's 64B of 128B .text = 50%.  The STUB counts toward
        # identified_pct (96/128 = 75%), not matched (db-review F1 — the old
        # coverage_pct counted every function, so an all-STUB binary showed
        # ~100% "coverage").
        assert s["coverage_pct"] == 50.0
        assert s["identified_pct"] == 75.0

    def test_summary_unknown_target(self, dashboard: Dashboard) -> None:
        assert dashboard.summary("nope") is None

    def test_functions_all(self, dashboard: Dashboard) -> None:
        data = dashboard.functions("server_dll")
        assert data["total"] == 2
        assert data["functions"][0]["va"] == "0x10001000"
        assert data["functions"][0]["files"] == "a.c"

    def test_functions_status_filter(self, dashboard: Dashboard) -> None:
        data = dashboard.functions("server_dll", status="STUB")
        assert data["count"] == 1
        assert data["functions"][0]["name"] == "func_b"

    def test_functions_search(self, dashboard: Dashboard) -> None:
        data = dashboard.functions("server_dll", q="func_a")
        assert data["count"] == 1
        assert data["functions"][0]["symbol"] == "_func_a"

    def test_sections(self, dashboard: Dashboard) -> None:
        sections = dashboard.sections("server_dll")["sections"]
        by_name = {s["name"]: s for s in sections}
        assert by_name[".text"]["exact"] == 1
        assert by_name[".text"]["stub"] == 1
        assert by_name[".text"]["size"] == 128
        assert by_name[".data"]["data"] == 1

    def test_globals(self, dashboard: Dashboard) -> None:
        data = dashboard.globals("server_dll")
        assert data["count"] == 1
        assert data["total"] == 1
        assert data["globals"][0]["name"] == "g_flag"
        assert data["globals"][0]["va"] == "0x50001000"

    def test_history_empty(self, dashboard: Dashboard) -> None:
        hist = dashboard.history("server_dll")
        assert hist["history"] == []
        assert hist["count"] == 0
        assert hist["total"] == 0

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


class TestHandle:
    def test_index_html(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("GET", "/", {})
        assert status == 200
        assert "text/html" in content_type
        assert "Rebrew coverage" in body

    def test_index_html_has_accessible_structure(self, dashboard: Dashboard) -> None:
        _, _, body = dashboard.handle("GET", "/", {})
        assert "<main>" in body
        assert '<label for="q">Search name or symbol</label>' in body
        assert 'role="status" aria-live="polite"' in body
        assert 'id="dashboard-error" role="alert" hidden' in body
        assert '<caption class="visually-hidden">' in body
        assert body.count('scope="col"') == 7
        assert 'aria-label="Function results"' in body
        assert body.count('aria-busy="false"') == 2

    def test_api_targets(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("GET", "/api/targets", {})
        assert status == 200
        assert "application/json" in content_type
        assert json.loads(body)["targets"] == ["server_dll"]

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
        assert json.loads(body)["count"] == 1

    def test_post_rejected(self, dashboard: Dashboard) -> None:
        status, content_type, body = dashboard.handle("POST", "/api/targets", {})
        assert status == 405
        assert "application/json" in content_type
        assert "method not allowed" in json.loads(body)["error"]

    def test_put_rejected(self, dashboard: Dashboard) -> None:
        status, _, body = dashboard.handle("PUT", "/api/targets", {})
        assert status == 405
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

        status, _, _ = dashboard.handle("GET", "/api/targets", {})
        assert status == 200
        # Attempt a write through a fresh ro connection must fail.
        with pytest.raises(sqlite3.OperationalError):
            conn = sqlite3.connect(f"file:{dashboard.db_path.resolve()}?mode=ro", uri=True)
            with conn:
                conn.execute("CREATE TABLE evil (x)")


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


class TestEscapeLike:
    """User search terms must match literally, not as SQL LIKE wildcards."""

    def test_wildcards_escaped(self) -> None:
        from rebrew.dashboard import _escape_like

        assert _escape_like("foo_1") == "foo\\_1"
        assert _escape_like("100%") == "100\\%"
        assert _escape_like("a\\b") == "a\\\\b"
        assert _escape_like("plain") == "plain"
