"""Tests for rebrew solutions — the GA solutions database CLI."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from rebrew.main import app
from rebrew.solutions_db import _collect_best, _collect_solutions


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(root=tmp_path, target_name="SERVER")


def _write_solutions(tmp_path: Path) -> None:
    (tmp_path / ".rebrew").mkdir(exist_ok=True)
    (tmp_path / ".rebrew" / "solutions.json").write_text(
        json.dumps(
            [
                {
                    "symbol": "_malloc",
                    "cflags": "/O2 /Gd",
                    "size": 64,
                    "source_file": "src/malloc.c",
                    "target": "SERVER",
                    "score": 0.0,
                    "solved_at": "2026-01-01T00:00:00+00:00",
                    "generations": 3,
                },
                {
                    "symbol": "_free",
                    "cflags": "/O1",
                    "size": 32,
                    "source_file": "src/free.c",
                    "target": "SERVER",
                    "score": 1.5,
                    "solved_at": "2026-01-02T00:00:00+00:00",
                    "generations": 5,
                },
            ]
        ),
        encoding="utf-8",
    )


class TestCollect:
    def test_collect_solutions(self, tmp_path: Path) -> None:
        _write_solutions(tmp_path)
        rows = _collect_solutions(_cfg(tmp_path))
        assert {r["symbol"] for r in rows} == {"_malloc", "_free"}
        assert rows[0]["score"] == 0.0

    def test_collect_best_from_ga_runs(self, tmp_path: Path) -> None:
        (tmp_path / ".rebrew").mkdir(exist_ok=True)
        (tmp_path / ".rebrew" / "ga_runs.jsonl").write_text(
            "\n".join(
                [
                    '{"ts": "t1", "target": "SERVER", "va": "0x1000", "symbol": "_f", "matched": false, "score": 5.0}',
                    '{"ts": "t2", "target": "SERVER", "va": "0x1000", "symbol": "_f", "matched": true, "score": 0.0}',
                    '{"ts": "t3", "target": "SERVER", "va": "0x2000", "symbol": "_g", "matched": false, "score": 9.0}',
                ]
            ),
            encoding="utf-8",
        )
        best = _collect_best(_cfg(tmp_path))
        assert len(best) == 2
        by_va = {b["va"]: b for b in best}
        assert by_va["0x1000"]["score"] == 0.0  # best (lowest) score won
        assert by_va["0x1000"]["matched"] is True


class TestSolutionsCli:
    def test_list_json(self, tmp_path: Path, monkeypatch) -> None:
        _write_solutions(tmp_path)
        monkeypatch.setattr(
            "rebrew.solutions_db.require_config",
            lambda target=None, json_mode=False: _cfg(tmp_path),
        )
        result = CliRunner().invoke(app, ["solutions", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 2
        assert payload["rows"][0]["symbol"] == "_malloc"

    def test_symbol_filter(self, tmp_path: Path, monkeypatch) -> None:
        _write_solutions(tmp_path)
        monkeypatch.setattr(
            "rebrew.solutions_db.require_config",
            lambda target=None, json_mode=False: _cfg(tmp_path),
        )
        result = CliRunner().invoke(app, ["solutions", "--symbol", "malloc", "--json"])
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["rows"][0]["symbol"] == "_malloc"

    def test_best_json(self, tmp_path: Path, monkeypatch) -> None:
        (tmp_path / ".rebrew").mkdir(exist_ok=True)
        (tmp_path / ".rebrew" / "ga_runs.jsonl").write_text(
            '{"ts": "t1", "target": "SERVER", "va": "0x1000", "symbol": "_f", "matched": true, "score": 0.0}\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "rebrew.solutions_db.require_config",
            lambda target=None, json_mode=False: _cfg(tmp_path),
        )
        result = CliRunner().invoke(app, ["solutions", "--best", "--json"])
        payload = json.loads(result.stdout)
        assert payload["best"] is True
        assert payload["rows"][0]["va"] == "0x1000"
