"""Tests for catalog/cli.py — the catalog orchestrator command surface."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.catalog.cli as catalog_cli

runner = CliRunner()


def _patch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    cfg = SimpleNamespace(
        target_binary=tmp_path / "x.dll",
        reversed_dir=tmp_path / "src",
        root=tmp_path,
        target_name="T",
        function_list=tmp_path / "functions.txt",
        metadata_dir=tmp_path,
        db_dir=tmp_path / "db",
    )
    cfg.reversed_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(
        catalog_cli, "require_config", lambda target=None, json_mode=False, root=None: cfg
    )
    monkeypatch.setattr(catalog_cli, "scan_reversed_dir", lambda _d, cfg=None: [])
    monkeypatch.setattr(catalog_cli, "parse_function_list", lambda _p: [])
    monkeypatch.setattr(catalog_cli, "build_function_registry", lambda *a, **k: {})
    monkeypatch.setattr(catalog_cli, "get_text_section_size", lambda _p: 0x1000)
    monkeypatch.setattr(catalog_cli, "generate_catalog", lambda *a, **k: "catalog md")
    monkeypatch.setattr(
        catalog_cli,
        "generate_data_json",
        lambda *a, **k: {"sections": {".text": {"va": 0, "cells": []}}, "summary": {}},
    )
    monkeypatch.setattr(catalog_cli, "generate_reccmp_csv", lambda *a, **k: "a|b|c|d|e\n")
    return cfg


class TestCatalogCli:
    def test_function_structure_refreshed_when_catalog_generated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The catalog-generated function_structure.json is provenance-stamped
        and REFRESHED on re-run after the function list changes — the old
        `not exists()` guard wrote it once and never updated it, leaving a
        stale structure cache diverging from the freshly-written data JSON
        (idempotency-review F5)."""
        cfg = _patch(monkeypatch, tmp_path)
        # load_func_list only calls parse_function_list when the list file
        # exists — provide the fixture so the mocked list is actually used.
        cfg.function_list.write_text("0x10001000 32 f_a\n0x10002000 64 f_b\n", encoding="utf-8")
        monkeypatch.setattr(
            catalog_cli,
            "parse_function_list",
            lambda _p: [
                {"va": "0x10001000", "size": 32, "name": "f_a"},
                {"va": "0x10002000", "size": 64, "name": "f_b"},
            ],
        )
        r1 = runner.invoke(catalog_cli.app, ["--data-json"])
        assert r1.exit_code == 0
        ghidra_path = cfg.reversed_dir / "function_structure.json"
        assert ghidra_path.exists()
        data1 = json.loads(ghidra_path.read_text())
        assert len(data1) == 2
        assert data1[0]["_generated_by"] == "rebrew catalog"

        # Function list changed — re-run must refresh the catalog-generated file.
        monkeypatch.setattr(
            catalog_cli,
            "parse_function_list",
            lambda _p: [
                {"va": "0x10001000", "size": 32, "name": "f_a"},
                {"va": "0x10003000", "size": 16, "name": "f_c"},
            ],
        )
        r2 = runner.invoke(catalog_cli.app, ["--data-json"])
        assert r2.exit_code == 0
        data2 = json.loads(ghidra_path.read_text())
        names = [d["name"] for d in data2]
        assert "f_c" in names  # refreshed
        assert "f_b" not in names  # stale entry gone

    def test_function_structure_never_overwrites_ghidra_export(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A REAL Ghidra export (no catalog marker) is authoritative and must
        never be overwritten by the catalog's compatibility export."""
        cfg = _patch(monkeypatch, tmp_path)
        ghidra_path = cfg.reversed_dir / "function_structure.json"
        ghidra_path.write_text(
            json.dumps([{"va": 0x10001000, "size": 32, "tool_name": "FUN_10001000"}]) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            catalog_cli,
            "parse_function_list",
            lambda _p: [{"va": "0x10001000", "size": 32, "name": "f_a"}],
        )
        r = runner.invoke(catalog_cli.app, ["--data-json"])
        assert r.exit_code == 0
        data = json.loads(ghidra_path.read_text())
        assert data[0]["tool_name"] == "FUN_10001000"  # untouched
        assert "_generated_by" not in data[0]

    def test_data_json_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _patch(monkeypatch, tmp_path)
        r = runner.invoke(catalog_cli.app, ["--data-json"])
        assert r.exit_code == 0
        out = cfg.db_dir / "data_T.json"
        assert out.exists()
        payload = json.loads(out.read_text())
        assert "summary" in payload

    def test_catalog_md_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path)
        r = runner.invoke(catalog_cli.app, ["--catalog"])
        assert r.exit_code == 0
        assert (tmp_path / "src" / "CATALOG.md").read_text() == "catalog md"

    def test_csv_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _patch(monkeypatch, tmp_path)
        r = runner.invoke(catalog_cli.app, ["--csv"])
        assert r.exit_code == 0
        assert (cfg.db_dir / "t_functions.csv").exists()

    def test_json_summary_to_stdout(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path)
        r = runner.invoke(catalog_cli.app, ["--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        expected = {
            "target": "T",
            "annotations": 0,
            "unique_vas": 0,
            "registry": 0,
            "total_functions": 0,
            "covered_bytes": 0,
            # No fabricated 0x24000 fallback: with the binary missing the
            # size is 0 and the payload says so (code-review F9).
            "text_size": 0,
            "coverage_pct": 0.0,
            "wrote_data_json": False,
            "wrote_catalog": False,
            "wrote_csv": False,
        }
        assert {k: v for k, v in payload.items() if k != "warning"} == expected
        assert payload["warning"].startswith("target binary missing (")
        assert "text_size=0" in payload["warning"]

    def test_export_ghidra_prints_instructions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path)
        r = runner.invoke(catalog_cli.app, ["--export-ghidra"])
        assert r.exit_code == 0
        assert "get-functions" in r.output

    def test_export_ghidra_json_refused(self, tmp_path: Path, monkeypatch) -> None:
        """--export-ghidra prints instructions and emits no JSON document —
        combining it with --json would break the JSON contract (cli-review
        F9), so the combination is refused up front."""
        _patch(monkeypatch, tmp_path)
        r = runner.invoke(catalog_cli.app, ["--export-ghidra", "--json"])
        assert r.exit_code != 0
        assert "cannot be combined with --json" in r.output

    def test_default_runs_all(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _patch(monkeypatch, tmp_path)
        r = runner.invoke(catalog_cli.app, [])
        assert r.exit_code == 0
        assert (tmp_path / "src" / "CATALOG.md").exists()
        assert (cfg.db_dir / "data_T.json").exists()
        assert (cfg.db_dir / "t_functions.csv").exists()

    def test_fix_sizes_updates_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path)
        updated: list[bool] = []

        def fake_update(
            cfile: object, va: object, size: object, metadata_dir: object = None
        ) -> bool:
            updated.append(True)
            return True

        monkeypatch.setattr("rebrew.annotation.update_size_annotation", fake_update)
        monkeypatch.setattr("rebrew.cli.iter_sources", lambda _d, _c: [])
        r = runner.invoke(catalog_cli.app, ["--fix-sizes"], input="y\n")
        assert r.exit_code == 0

    def test_fix_sizes_json_requires_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path)

        result = runner.invoke(catalog_cli.app, ["--fix-sizes", "--json"])

        assert result.exit_code == 2
        assert json.loads(result.stdout) == {
            "error": "--fix-sizes modifies metadata; pass --force to use it in --json mode",
            "code": 2,
        }


class TestCatalogCliSummary:
    def _entries(self) -> list[dict]:
        return [
            {"va": 0x1000, "module": "GAME", "marker_type": "FUNCTION", "status": "EXACT"},
            {"va": 0x2000, "module": "GAME", "marker_type": "FUNCTION", "status": "RELOC"},
            {"va": 0x3000, "module": "ZLIB", "marker_type": "FUNCTION", "status": "NEAR_MATCHING"},
            {"va": 0x4000, "module": "GAME", "marker_type": "FUNCTION", "status": "STUB"},
            {"va": 0x5000, "module": "GAME", "marker_type": "DATA", "status": "EXACT"},
        ]

    def test_summary_counts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path)
        monkeypatch.setattr(catalog_cli, "scan_reversed_dir", lambda _d, cfg=None: self._entries())
        registry = {
            0x1000: {
                "canonical_size": 64,
                "is_thunk": False,
                "detected_by": ["list"],
                "size_by_tool": {"list": 64, "ghidra": 64},
            },
            0x2000: {
                "canonical_size": 32,
                "is_thunk": False,
                "detected_by": ["ghidra"],
                "size_by_tool": {"ghidra": 32},
            },
            0x3000: {
                "canonical_size": 16,
                "is_thunk": False,
                "detected_by": ["list", "ghidra"],
                "size_by_tool": {"list": 16, "ghidra": 16},
            },
            0x4000: {
                "canonical_size": 8,
                "is_thunk": False,
                "detected_by": ["list"],
                "size_by_tool": {"list": 8, "ghidra": 8},
            },
        }
        monkeypatch.setattr(catalog_cli, "build_function_registry", lambda *a, **k: registry)
        result = runner.invoke(catalog_cli.app, ["--summary"])
        assert result.exit_code == 0
        assert "EXACT: 1" in result.output
        assert "RELOC: 1" in result.output
        assert "NEAR_MATCHING: 1" in result.output
        assert "STUB: 1" in result.output
        assert "GAME: 3" in result.output  # DATA entry excluded from fn_vas
        assert "ZLIB: 1" in result.output
        assert "func list only: 2" in result.output
        assert "Ghidra only:  1" in result.output
        assert "Both tools:   1" in result.output

    def test_export_ghidra_labels(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json as _json

        cfg = _patch(monkeypatch, tmp_path)
        monkeypatch.setattr(
            catalog_cli,
            "generate_data_json",
            lambda *a, **k: {
                "sections": {
                    ".text": {
                        "va": 0x1000,
                        "cells": [
                            {"start": 0, "end": 64, "state": "data", "label": "jpt"},
                            {"start": 64, "end": 96, "state": "thunk"},
                            {"start": 96, "end": 128, "state": "none"},
                        ],
                    }
                },
                "summary": {},
            },
        )
        result = runner.invoke(catalog_cli.app, ["--export-ghidra-labels"])
        assert result.exit_code == 0
        labels_path = cfg.reversed_dir / "ghidra_data_labels.json"
        assert labels_path.exists()
        labels = _json.loads(labels_path.read_text(encoding="utf-8"))
        assert labels[0]["label"] == "jpt"
        assert labels[1]["va"] == 0x1000 + 64
        # label defaults to switchdata_<va> when missing
        assert labels[1]["label"] == f"switchdata_{0x1000 + 64:08x}"
