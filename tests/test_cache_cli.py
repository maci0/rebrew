"""Tests for rebrew cache CLI (stats / clear)."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.cache_cli as cache_cli

runner = CliRunner()


def _patch_cfg(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(
        cache_cli,
        "require_config",
        lambda target=None, json_mode=False: SimpleNamespace(root=root),
    )


class TestStats:
    def test_no_cache_dir_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(monkeypatch, tmp_path)
        r = runner.invoke(cache_cli.app, ["stats", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload == {"exists": False, "entries": 0, "volume_mb": 0}

    def test_no_cache_dir_human(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture
    ) -> None:
        _patch_cfg(monkeypatch, tmp_path)
        r = runner.invoke(cache_cli.app, ["stats"])
        assert r.exit_code == 0

    def test_existing_cache_reports(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        _patch_cfg(monkeypatch, tmp_path)
        stats_called: list[bool] = []

        def fake_cache(_dir: Path) -> SimpleNamespace:
            return SimpleNamespace(
                stats=lambda: (
                    stats_called.append(True)
                    or {
                        "entries": 3,
                        "volume_mb": 1.5,
                        "size_limit_mb": 100,
                        "session_hits": 2,
                        "session_misses": 1,
                        "session_hit_rate_pct": 66.7,
                    }
                ),
                close=lambda: None,
            )

        monkeypatch.setattr(cache_cli, "CompileCache", fake_cache)
        r = runner.invoke(cache_cli.app, ["stats"])
        assert r.exit_code == 0
        assert stats_called == [True]


class TestClear:
    def test_no_cache_dir_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(monkeypatch, tmp_path)
        r = runner.invoke(cache_cli.app, ["clear", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload["cleared"] == 0

    def test_force_clears_without_prompt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        _patch_cfg(monkeypatch, tmp_path)
        cleared: list[str] = []

        def fake_cache(_dir: Path) -> SimpleNamespace:
            return SimpleNamespace(
                count=4,
                clear=lambda: cleared.append("clear"),
                close=lambda: None,
            )

        monkeypatch.setattr(cache_cli, "CompileCache", fake_cache)
        r = runner.invoke(cache_cli.app, ["clear", "--force"])
        assert r.exit_code == 0
        assert cleared == ["clear"]

    def test_confirmation_prompt_clears(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        _patch_cfg(monkeypatch, tmp_path)
        cleared: list[str] = []

        def fake_cache(_dir: Path) -> SimpleNamespace:
            return SimpleNamespace(
                count=2,
                clear=lambda: cleared.append("clear"),
                close=lambda: None,
            )

        monkeypatch.setattr(cache_cli, "CompileCache", fake_cache)
        r = runner.invoke(cache_cli.app, ["clear"], input="y\n")
        assert r.exit_code == 0
        assert cleared == ["clear"]
