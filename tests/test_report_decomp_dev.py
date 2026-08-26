"""Tests for report.generate_decomp_dev_report — objdiff-format report.json."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import rebrew.report as report


def _fake_ann(va: int, size: int, name: str, status: str) -> SimpleNamespace:
    return SimpleNamespace(
        va=va,
        size=size,
        name=name,
        symbol=f"_{name}",
        status=status,
        module="GAME",
        marker_type="FUNCTION",
        filepath=f"src/{name}.c",
    )


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        target_binary=tmp_path / "x.dll",
        reversed_dir=tmp_path / "src",
        root=tmp_path,
        target_name="T",
        metadata_dir=tmp_path,
        function_list=tmp_path / "functions.txt",
        compiler_profile="msvc6",
        source_ext=".c",
        marker="T",
    )


class TestDecompDevReport:
    def _setup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, annos: list[SimpleNamespace]
    ) -> SimpleNamespace:
        cfg = _cfg(tmp_path)
        src = cfg.reversed_dir
        src.mkdir(exist_ok=True)
        src_file = src / "funcs.c"
        monkeypatch.setattr("rebrew.sources.iter_sources", lambda d, cfg=None: [src_file])
        monkeypatch.setattr(
            "rebrew.cli.iter_annotations",
            lambda sources, target=None, metadata_dir=None: [(src_file, annos)],
        )
        monkeypatch.setattr("rebrew.catalog.loaders.parse_function_list", lambda _p: [])
        monkeypatch.setattr("rebrew.catalog.registry.build_function_registry", lambda *a, **k: {})
        monkeypatch.setattr("rebrew.catalog.sections.get_text_section_size", lambda _p: 0x1000)
        monkeypatch.setattr("rebrew.verify._load_verify_cache", lambda _p, _c: None)
        # No data sections → data measures stay 0 without erroring.
        monkeypatch.setattr(
            report,
            "load_binary",
            lambda _p: SimpleNamespace(sections={}),
        )
        return cfg

    def test_report_shape_and_status_mapping(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        annos = [
            _fake_ann(0x1000, 64, "exact_fn", "EXACT"),
            _fake_ann(0x2000, 32, "near_fn", "NEAR_MATCHING"),
            _fake_ann(0x3000, 16, "stub_fn", "STUB"),
        ]
        cfg = self._setup(tmp_path, monkeypatch, annos)
        out = tmp_path / "report.json"
        result = report.generate_decomp_dev_report(cfg, out)
        assert out.exists()

        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["version"] == 2
        m = doc["measures"]
        assert m["total_code"] == 0x1000
        assert m["total_functions"] == 3
        assert m["matched_functions"] == 1  # EXACT only
        assert m["matched_code"] == 64
        assert m["complete_code"] == 64
        assert m["complete_data"] == 0

        units = doc["units"]
        assert len(units) == 1
        fns = {f["name"]: f for f in units[0]["functions"]}
        assert fns["exact_fn"]["fuzzy_match_percent"] == 100.0
        assert fns["near_fn"]["fuzzy_match_percent"] == 0.0  # no cached match_percent
        assert fns["stub_fn"]["fuzzy_match_percent"] == 0.0
        # Addresses are numbers (objdiff's serde contract for uint64).
        assert fns["exact_fn"]["address"] == 0x1000

        assert result["total_functions"] == 3
        assert result["matched_functions"] == 1

    def test_near_matching_uses_cached_match_percent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        annos = [_fake_ann(0x2000, 32, "near_fn", "NEAR_MATCHING")]
        self._setup(tmp_path, monkeypatch, annos)

        class _Result:
            match_percent = 72.5

        class _Entry:
            result = _Result()

        class _Cache:
            entries = {0x2000: _Entry()}

        monkeypatch.setattr("rebrew.verify._load_verify_cache", lambda _p, _c: _Cache())
        out = tmp_path / "report.json"
        report.generate_decomp_dev_report(_cfg(tmp_path), out)
        doc = json.loads(out.read_text(encoding="utf-8"))
        fn = doc["units"][0]["functions"][0]
        assert fn["fuzzy_match_percent"] == 72.5

    def test_registry_denominator(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        annos = [_fake_ann(0x1000, 64, "exact_fn", "EXACT")]
        self._setup(tmp_path, monkeypatch, annos)
        # The binary has a second function nobody has annotated yet.
        monkeypatch.setattr(
            "rebrew.catalog.registry.build_function_registry",
            lambda *a, **k: {0x1000: {"canonical_size": 64}, 0x4000: {"canonical_size": 128}},
        )
        out = tmp_path / "report.json"
        result = report.generate_decomp_dev_report(_cfg(tmp_path), out)
        assert result["total_functions"] == 2  # registry total, not annotated total
        assert result["matched_functions"] == 1
