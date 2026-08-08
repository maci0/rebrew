"""Tests for rebrew cache_cli — stats/clear with a fake CompileCache."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.cache_cli import app


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(root=tmp_path)


def _patch_cache(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stats: dict | None = None,
    count: int = 3,
) -> None:
    class _FakeCache:
        def __init__(self, cache_dir: Path) -> None:
            pass

        def stats(self) -> dict:
            return (
                stats
                if stats is not None
                else {
                    "entries": 3,
                    "volume_mb": 1.5,
                    "size_limit_mb": 512,
                    "session_hits": 2,
                    "session_misses": 1,
                    "session_hit_rate_pct": 66.7,
                }
            )

        @property
        def count(self) -> int:
            return count

        def clear(self) -> None:
            return None

        def close(self) -> None:
            return None

    monkeypatch.setattr("rebrew.cache_cli.CompileCache", _FakeCache)


class TestCacheCli:
    def test_stats_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        monkeypatch.setattr("rebrew.cache_cli.require_config", lambda **kw: cfg)
        _patch_cache(monkeypatch)
        result = CliRunner().invoke(app, ["stats", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["entries"] == 3
        assert data["session_hits"] == 2

    def test_stats_missing_cache_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.cache_cli.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["stats"])
        assert result.exit_code == 0
        assert "No compile cache" in result.output

    def test_stats_text_with_hits(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        monkeypatch.setattr("rebrew.cache_cli.require_config", lambda **kw: cfg)
        _patch_cache(monkeypatch)
        result = CliRunner().invoke(app, ["stats"])
        assert result.exit_code == 0
        assert "2 hits" in result.output

    def test_stats_text_no_lookups(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        monkeypatch.setattr("rebrew.cache_cli.require_config", lambda **kw: cfg)
        _patch_cache(
            monkeypatch,
            stats={
                "entries": 0,
                "volume_mb": 0.0,
                "size_limit_mb": 512,
                "session_hits": 0,
                "session_misses": 0,
                "session_hit_rate_pct": 0.0,
            },
        )
        result = CliRunner().invoke(app, ["stats"])
        assert "no lookups this session" in result.output

    def test_clear_missing_cache_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.cache_cli.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["clear", "--json"])
        assert result.exit_code == 0
        assert json.loads(result.stdout)["cleared"] == 0

    def test_clear_force_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        monkeypatch.setattr("rebrew.cache_cli.require_config", lambda **kw: cfg)
        _patch_cache(monkeypatch, count=3)
        result = CliRunner().invoke(app, ["clear", "--force", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["cleared"] == 3

    def test_clear_json_requires_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        monkeypatch.setattr("rebrew.cache_cli.require_config", lambda **kw: cfg)
        _patch_cache(monkeypatch, count=3)

        result = CliRunner().invoke(app, ["clear", "--json"])

        assert result.exit_code == 1
        assert json.loads(result.stdout) == {
            "error": "--json cannot prompt for confirmation; pass --force to clear the cache",
            "code": 1,
        }
