"""Tests for similarity-based prioritization in rebrew next."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.config import ProjectConfig
from rebrew.next import app

runner = CliRunner()


def _patch_next(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    ghidra_funcs: list[dict],
    existing: dict[int, dict[str, object]],
    covered_vas: dict[int, str],
    byte_map: dict[int, bytes],
) -> None:
    """Wire up all monkeypatches needed for next.py similarity tests."""
    # Create dummy binary so bin_path.exists() passes the guard
    (tmp_path / "fake.exe").write_bytes(b"\x00" * 16)

    def fake_get_config(*a, **kw):  # type: ignore[no-untyped-def]
        return ProjectConfig(
            root=tmp_path,
            target_name="",
            target_binary=tmp_path / "fake.exe",
            reversed_dir=tmp_path,
        )

    def fake_load_data(cfg):  # type: ignore[no-untyped-def]
        return ghidra_funcs, existing, covered_vas

    def fake_load_binary(path):  # type: ignore[no-untyped-def]
        class FakeBinaryInfo:
            pass

        return FakeBinaryInfo()

    def fake_extract_bytes(info, va, size, **kwargs):  # type: ignore[no-untyped-def]
        return byte_map.get(va, b"")

    monkeypatch.setattr("rebrew.next.get_config", fake_get_config)
    monkeypatch.setattr("rebrew.next.load_data", fake_load_data)
    monkeypatch.setattr("rebrew.next.load_binary", fake_load_binary)

    # Patch extract_bytes_at_va at every import site:
    # - rebrew.binary_loader: canonical def, read by lazy imports in next.py
    # - rebrew.naming: module-level import, used by detect_unmatchable
    import rebrew.binary_loader
    import rebrew.naming

    monkeypatch.setattr(rebrew.binary_loader, "extract_bytes_at_va", fake_extract_bytes)
    monkeypatch.setattr(rebrew.naming, "extract_bytes_at_va", fake_extract_bytes)


class TestSimilarityPrioritization:
    def test_similar_function_ranked_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_next(
            monkeypatch,
            tmp_path,
            ghidra_funcs=[
                {"va": 0x1000, "size": 50, "ghidra_name": "func_1000"},
                {"va": 0x2000, "size": 50, "ghidra_name": "func_2000"},
                {"va": 0x3000, "size": 50, "ghidra_name": "func_3000"},
            ],
            existing={
                0x1000: {"status": "EXACT", "size": 50, "origin": "GAME", "filename": "f.c"},
            },
            covered_vas={0x1000: "f.c"},
            byte_map={
                0x1000: b"\xaa\xbb\xcc\xdd\xee\xff\x00\x00\x00\x00",
                0x2000: b"\xaa\xbb\xcc\xdd\xee\xee\x00\x00\x00\x00",  # high similarity
                0x3000: b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00",  # low similarity
            },
        )

        res = runner.invoke(app, ["--json"])
        assert res.exit_code == 0, f"CLI failed: {res.output}"
        data = json.loads(res.output)

        assert data["mode"] == "recommendations"
        items = data["items"]
        assert len(items) == 2

        assert items[0]["va"] == "0x00002000"
        assert items[0]["similarity"] > 0.8

        assert items[1]["va"] == "0x00003000"
        assert items[1]["similarity"] < 0.5

    def test_zero_similarity_when_no_matched_funcs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_next(
            monkeypatch,
            tmp_path,
            ghidra_funcs=[
                {"va": 0x2000, "size": 50, "ghidra_name": "func_2000"},
                {"va": 0x3000, "size": 50, "ghidra_name": "func_3000"},
            ],
            existing={},
            covered_vas={},
            byte_map={
                0x2000: b"\x00" * 10,
                0x3000: b"\xff" * 10,
            },
        )

        res = runner.invoke(app, ["--json"])
        assert res.exit_code == 0, f"CLI failed: {res.output}"
        data = json.loads(res.output)

        items = data["items"]
        assert len(items) == 2
        assert items[0]["similarity"] == 0.0
        assert items[1]["similarity"] == 0.0

    def test_similarity_skipped_for_tiny_functions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_next(
            monkeypatch,
            tmp_path,
            ghidra_funcs=[
                {"va": 0x1000, "size": 50, "ghidra_name": "func_1000"},
                {"va": 0x2000, "size": 15, "ghidra_name": "func_2000"},  # below 20B threshold
            ],
            existing={
                0x1000: {"status": "EXACT", "size": 50, "origin": "GAME", "filename": "f.c"},
            },
            covered_vas={0x1000: "f.c"},
            byte_map={
                0x1000: b"\xaa\xbb\xcc\xdd\xee\xff\x00\x00\x00\x00",
                0x2000: b"\xaa\xbb\xcc\xdd\xee\xff\x00\x00\x00\x00",  # identical bytes
            },
        )

        res = runner.invoke(app, ["--json", "--min-size", "10"])
        assert res.exit_code == 0, f"CLI failed: {res.output}"
        data = json.loads(res.output)

        items = data["items"]
        assert len(items) == 1
        assert items[0]["va"] == "0x00002000"
        assert items[0]["similarity"] == 0.0  # skipped due to size <= 20
