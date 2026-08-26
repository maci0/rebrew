"""Tests for symbol_addrs.py — splat-style symbol CSV export."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.symbol_addrs as symbol_addrs

runner = CliRunner()


def _fake_ann(va: int, name: str, marker: str = "FUNCTION", symbol: str = "") -> SimpleNamespace:
    return SimpleNamespace(va=va, name=name, symbol=symbol, marker_type=marker)


def _patch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, annos: list[SimpleNamespace]
) -> SimpleNamespace:
    cfg = SimpleNamespace(
        target_binary=tmp_path / "x.dll",
        reversed_dir=tmp_path / "src",
        root=tmp_path,
        target_name="T",
        metadata_dir=tmp_path,
        marker="T",
        source_ext=".c",
    )
    cfg.reversed_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(
        symbol_addrs, "require_config", lambda target=None, json_mode=False, root=None: cfg
    )
    monkeypatch.setattr(
        symbol_addrs,
        "iter_annotations",
        lambda sources, target=None, metadata_dir=None: [(Path("a.c"), annos)],
    )
    return cfg


class TestSymbolAddrs:
    def test_writes_sorted_symbols(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(
            monkeypatch,
            tmp_path,
            [_fake_ann(0x2000, "later"), _fake_ann(0x1000, "earlier")],
        )
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--out", str(out)])
        assert r.exit_code == 0
        lines = out.read_text(encoding="utf-8").splitlines()
        assert lines == ["0x00001000,earlier", "0x00002000,later"]

    def test_excludes_globals_and_unnamed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(
            monkeypatch,
            tmp_path,
            [
                _fake_ann(0x1000, "func_a"),
                _fake_ann(0x2000, "", marker="GLOBAL"),  # excluded (marker)
                _fake_ann(0x3000, "", marker="FUNCTION"),  # excluded (unnamed)
            ],
        )
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--out", str(out), "--json"])
        assert r.exit_code == 0
        import json

        payload = json.loads(r.stdout)
        assert payload["symbols"] == 1
        assert payload["skipped_unnamed"] == 1
        lines = out.read_text(encoding="utf-8").splitlines()
        assert lines == ["0x00001000,func_a"]

    def test_prefers_symbol_over_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path, [_fake_ann(0x1000, "func_a", symbol="_func_a@8")])
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--out", str(out)])
        assert r.exit_code == 0
        assert out.read_text(encoding="utf-8").strip() == "0x00001000,_func_a@8"
