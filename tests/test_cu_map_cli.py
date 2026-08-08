"""CLI tests for rebrew cu_map — main() with stubbed registry/clustering."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.cu_map import app


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        root=tmp_path,
        target_binary=tmp_path / "x.dll",
        function_list=tmp_path / "functions.txt",
        reversed_dir=tmp_path / "src",
        target_name="T",
    )


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    registry: dict | None = None,
    clusters: list | None = None,
    binary_missing: bool = False,
) -> SimpleNamespace:
    cfg = _cfg(tmp_path)
    if not binary_missing:
        (tmp_path / "x.dll").write_bytes(b"MZ" + b"\x00" * 100)
    (tmp_path / "functions.txt").write_text("0x1000 64 fn_a\n", encoding="utf-8")
    monkeypatch.setattr("rebrew.cu_map.require_config", lambda **kw: cfg)
    monkeypatch.setattr("rebrew.cu_map.load_binary", lambda p: SimpleNamespace())
    monkeypatch.setattr("rebrew.cu_map.parse_function_list", lambda p: [])
    monkeypatch.setattr(
        "rebrew.cu_map.build_function_registry",
        lambda funcs, cfg, ghidra_path=None, bin_path=None: registry or {},
    )
    monkeypatch.setattr(
        "rebrew.cu_map.cluster_functions", lambda *a, **k: clusters if clusters is not None else []
    )
    return cfg


class TestCuMapCli:
    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        registry = {
            0x1000: {"canonical_size": 64, "is_thunk": False},
            0x2000: {"canonical_size": 32, "is_thunk": False},
        }
        cluster = SimpleNamespace(
            cluster_id=1,
            functions=[0x1000, 0x2000],
            gap_classes=[],
            confidence=0.9,
            evidence=["contiguous"],
        )
        _setup(tmp_path, monkeypatch, registry=registry, clusters=[cluster])
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["total_functions"] == 2
        assert data["clustered_functions"] == 2
        assert data["total_clusters"] == 1
        assert data["clusters"][0]["cluster_id"] == 1

    def test_json_unclustered_reasons(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = {
            0x1000: {"canonical_size": 0, "is_thunk": False},  # unknown size
            0x2000: {"canonical_size": 5, "is_thunk": True},  # thunk
        }
        _setup(tmp_path, monkeypatch, registry=registry, clusters=[])
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        reasons = {u["va"]: u["reason"] for u in data["unclustered"]}
        assert reasons["0x00001000"] == "unknown size"
        assert reasons["0x00002000"] == "thunk"

    def test_missing_binary_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _setup(tmp_path, monkeypatch, binary_missing=True)
        result = CliRunner().invoke(app, [])
        assert result.exit_code != 0
        assert "Target binary not found" in result.output

    def test_terminal_table(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        registry = {
            0x1000: {"canonical_size": 64, "is_thunk": False},
            0x2000: {"canonical_size": 32, "is_thunk": False},
        }
        cluster = SimpleNamespace(
            cluster_id=1,
            functions=[0x1000, 0x2000],
            gap_classes=[],
            confidence=0.9,
            evidence=["contiguous"],
        )
        _setup(tmp_path, monkeypatch, registry=registry, clusters=[cluster])
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 0
        assert "Compilation Unit Map" in result.output
