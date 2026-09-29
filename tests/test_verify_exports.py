"""Tests for verify_exports.py — export-table verification (reccmp verexp equivalent)."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.binary_loader import ExportParseError, parse_exports
from rebrew.cli import EXIT_ERROR, EXIT_MISMATCH
from rebrew.verify_exports import app, compare_exports


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
        monkeypatch.setattr("lief.is_pe", lambda p: False)
        assert parse_exports(Path("x.dll")) == []

    def test_pe_rejected_by_backend_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("lief.PE.parse", lambda p: None)
        monkeypatch.setattr("lief.is_pe", lambda p: True)
        with pytest.raises(ExportParseError, match="cannot parse exports"):
            parse_exports(Path("x.dll"))

    def test_parse_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(p):
            raise ValueError("corrupt")

        monkeypatch.setattr("lief.PE.parse", _boom)
        with pytest.raises(ExportParseError, match="cannot parse exports"):
            parse_exports(Path("x.dll"))

    def test_unnamed_exports_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pe = _FakePE(["named"])
        pe.exported_functions.append(_Fn(""))
        monkeypatch.setattr("lief.PE.parse", lambda p: pe)
        assert parse_exports(Path("x.dll")) == ["named"]


class TestCompareExports:
    def test_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.verify_exports as exports_mod

        monkeypatch.setattr(exports_mod, "parse_exports", lambda p: ["A", "B"])
        r = compare_exports(Path("orig.dll"), Path("recomp.dll"))
        assert r["match"] is True
        assert r["missing"] == []
        assert r["added"] == []
        assert r["original_count"] == r["recompiled_count"] == 2

    def test_missing_and_added(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.verify_exports as exports_mod

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
        import rebrew.verify_exports as exports_mod

        target = tmp_path / "orig.dll"
        target.write_bytes(b"MZfake")
        recomp = tmp_path / recomp_name
        recomp.write_bytes(b"MZfake")
        cfg = SimpleNamespace(target_binary=target)
        monkeypatch.setattr("rebrew.verify_exports.require_config", lambda **kw: cfg)
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
        assert "Export tables match." in result.stderr
        # "match" is a substring of "mismatch" too; pin the negative too.
        assert "differ" not in result.stderr
        assert "missing:" not in result.stderr

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
        # The named export, not the word "missing" (the "target binary
        # missing:" header carries it on any run).
        assert "missing: B" in result.stderr
        assert "Export tables differ." in result.stderr

    def test_missing_recomp_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "orig.dll"
        target.write_bytes(b"MZfake")
        cfg = SimpleNamespace(target_binary=target)
        monkeypatch.setattr("rebrew.verify_exports.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, [str(tmp_path / "nope.dll")])
        assert result.exit_code == EXIT_ERROR
        assert "not found" in result.output

    def test_unparseable_binary_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.verify_exports as exports_mod

        recomp = tmp_path / "recomp.dll"
        recomp.write_bytes(b"MZfake")
        cfg = SimpleNamespace(target_binary=tmp_path / "orig.dll")
        cfg.target_binary.write_bytes(b"MZfake")
        monkeypatch.setattr("rebrew.verify_exports.require_config", lambda **kw: cfg)

        def _boom(o: Path, r: Path) -> dict:
            raise ExportParseError(f"cannot parse exports of {o}: truncated")

        monkeypatch.setattr(exports_mod, "compare_exports", _boom)
        result = CliRunner().invoke(app, [str(recomp)])
        assert result.exit_code == EXIT_ERROR
        assert "cannot parse exports" in result.output

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
