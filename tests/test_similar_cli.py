"""Tests for the rebrew similar CLI command (via the umbrella app)."""

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.main
import rebrew.similar as similar_mod

runner = CliRunner()


def _patch(monkeypatch: pytest.MonkeyPatch, results: list[dict] | None = None) -> None:
    monkeypatch.setattr(
        similar_mod, "require_config", lambda target=None, json_mode=False: SimpleNamespace()
    )
    monkeypatch.setattr(similar_mod, "find_similar", lambda cfg, va, **kw: results or [])


class TestSimilarCli:
    def test_json_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(
            monkeypatch,
            [{"va": "0x00002000", "size": 6, "name": "_twin", "score": 100.0}],
        )
        r = runner.invoke(rebrew.main.app, ["similar", "0x1000", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload["query_va"] == "0x1000"
        assert payload["results"][0]["name"] == "_twin"

    def test_json_no_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, [])
        r = runner.invoke(rebrew.main.app, ["similar", "0x1000", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload["results"] == []

    def test_table_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(
            monkeypatch,
            [{"va": "0x00002000", "size": 6, "name": "_twin", "score": 100.0}],
        )
        r = runner.invoke(rebrew.main.app, ["similar", "0x1000"])
        assert r.exit_code == 0
        # The table must render the actual result row, not just an empty frame.
        assert "Functions similar to 0x1000" in r.output
        assert "_twin" in r.output
        assert "0x00002000" in r.output

    def test_invalid_va_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, [])
        r = runner.invoke(rebrew.main.app, ["similar", "not-a-va"])
        assert r.exit_code != 0

    def test_unknown_va_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A VA with no catalog entry must fail loudly, not print empty results."""

        def _raise(cfg, va, **kw):
            raise ValueError(f"No function found at VA 0x{va:08x}")

        monkeypatch.setattr(
            similar_mod, "require_config", lambda target=None, json_mode=False: SimpleNamespace()
        )
        monkeypatch.setattr(similar_mod, "find_similar", _raise)
        r = runner.invoke(rebrew.main.app, ["similar", "0x99999999", "--json"])
        assert r.exit_code == 2
        payload = json.loads(r.stdout)
        assert "No function found" in payload["error"]
