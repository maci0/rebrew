"""Tests for exports.py — export-table verification (reccmp verexp equivalent)."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.cli import EXIT_ERROR, EXIT_MISMATCH
from rebrew.exports import app, compare_exports, parse_exports


class _Fn:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakePE:
    def __init__(self, names: list[str]) -> None:
        self.exported_functions = [_Fn(n) for n in names]


class TestParseExports:
    def test_sorted_unique(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("lief.PE.parse", lambda p: _FakePE(["b", "a", "b"]))
        assert parse_exports(Path("x.dll")) == ["a", "b"]

    def test_non_pe_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("lief.PE.parse", lambda p: None)
        assert parse_exports(Path("x.dll")) == []

    def test_parse_raises_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(p):
            raise ValueError("corrupt")

        monkeypatch.setattr("lief.PE.parse", _boom)
        assert parse_exports(Path("x.dll")) == []

    def test_unnamed_exports_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pe = _FakePE(["named"])
        pe.exported_functions.append(_Fn(""))
        monkeypatch.setattr("lief.PE.parse", lambda p: pe)
        assert parse_exports(Path("x.dll")) == ["named"]


class TestCompareExports:
    def test_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.exports as exports_mod

        monkeypatch.setattr(exports_mod, "parse_exports", lambda p: ["A", "B"])
        r = compare_exports(Path("orig.dll"), Path("recomp.dll"))
        assert r["match"] is True
        assert r["missing"] == []
        assert r["added"] == []
        assert r["original_count"] == r["recompiled_count"] == 2

    def test_missing_and_added(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.exports as exports_mod

        def _parse(p: Path) -> list[str]:
            return ["A", "B"] if "orig" in str(p) else ["A", "C"]

        monkeypatch.setattr(exports_mod, "parse_exports", _parse)
        r = compare_exports(Path("orig.dll"), Path("recomp.dll"))
        assert r["match"] is False
        assert r["missing"] == ["B"]
        assert r["added"] == ["C"]


class TestCli:
    def _patch(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        result: dict,
        recomp_name: str = "recomp.dll",
    ) -> Path:
        import rebrew.exports as exports_mod

        target = tmp_path / "orig.dll"
        target.write_bytes(b"MZfake")
        recomp = tmp_path / recomp_name
        recomp.write_bytes(b"MZfake")
        cfg = SimpleNamespace(target_binary=target)
        monkeypatch.setattr("rebrew.exports.require_config", lambda **kw: cfg)
        full = {
            "original": str(target),
            "recompiled": str(recomp),
            "original_count": 0,
            "recompiled_count": 0,
            "missing": [],
            "added": [],
            "match": True,
        }
        full.update(result)
        monkeypatch.setattr(exports_mod, "compare_exports", lambda o, r: full)
        return recomp

    def test_match_exit_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        recomp = self._patch(monkeypatch, tmp_path, {"original_count": 2, "recompiled_count": 2})
        result = CliRunner().invoke(app, [str(recomp)])
        assert result.exit_code == 0
        assert "match" in result.stderr.lower()

    def test_mismatch_exits_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        recomp = self._patch(
            monkeypatch,
            tmp_path,
            {
                "match": False,
                "original_count": 2,
                "recompiled_count": 1,
                "missing": ["B"],
            },
        )
        result = CliRunner().invoke(app, [str(recomp)])
        assert result.exit_code == EXIT_MISMATCH
        assert "missing" in result.stderr

    def test_missing_recomp_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "orig.dll"
        target.write_bytes(b"MZfake")
        cfg = SimpleNamespace(target_binary=target)
        monkeypatch.setattr("rebrew.exports.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, [str(tmp_path / "nope.dll")])
        assert result.exit_code == EXIT_ERROR
        assert "not found" in result.output

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        recomp = self._patch(
            monkeypatch,
            tmp_path,
            {
                "match": False,
                "original": "orig.dll",
                "recompiled": "recomp.dll",
                "original_count": 2,
                "recompiled_count": 1,
                "missing": ["B"],
                "added": [],
            },
        )
        result = CliRunner().invoke(app, ["--json", str(recomp)])
        assert result.exit_code == EXIT_MISMATCH
        data = json.loads(result.output)
        assert data["missing"] == ["B"]
