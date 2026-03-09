"""Tests for rebrew status overview command."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.status import (
    StatusReport,
    VerifyInfo,
    collect_status,
)


def _make_cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    defaults: dict[str, Any] = {
        "root": tmp_path,
        "target_name": "test",
        "target_binary": tmp_path / "test.exe",
        "binary_format": "pe",
        "arch": "x86_32",
        "compiler_command": "gcc",
        "reversed_dir": tmp_path / "src",
        "metadata_dir": tmp_path,
        "function_list": tmp_path / "functions.txt",
        "bin_dir": tmp_path / "bin",
        "source_ext": ".c",
        "marker": "TEST",
        "iat_thunks": [],
        "ignored_symbols": [],
        "library_modules": set(),
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# StatusReport tests
# ---------------------------------------------------------------------------


class TestStatusReport:
    def test_empty_report_percentages(self) -> None:
        report = StatusReport()
        assert report.coverage_pct == 0.0
        assert report.matched_pct == 0.0
        assert report.byte_coverage_pct == 0.0

    def test_coverage_pct(self) -> None:
        report = StatusReport(total_functions=200, covered_functions=50)
        assert report.coverage_pct == 25.0

    def test_matched_pct(self) -> None:
        report = StatusReport(
            total_functions=100,
            status_counts={"EXACT": 20, "RELOC": 10, "MATCHING": 30, "STUB": 40},
        )
        assert report.matched_pct == 30.0

    def test_matched_pct_includes_proven(self) -> None:
        report = StatusReport(
            total_functions=100,
            status_counts={"EXACT": 10, "RELOC": 5, "PROVEN": 5, "STUB": 80},
        )
        assert report.matched_pct == 20.0

    def test_byte_coverage_pct(self) -> None:
        report = StatusReport(
            matched_bytes=1000,
            total_text_bytes=4000,
        )
        assert report.byte_coverage_pct == 25.0

    def test_byte_coverage_zero_text(self) -> None:
        report = StatusReport(matched_bytes=1000, total_text_bytes=0)
        assert report.byte_coverage_pct == 0.0


class TestStatusReportJson:
    def test_to_dict_minimal(self) -> None:
        report = StatusReport(target="server", binary="server.dll", arch="x86_32")
        d = report.to_dict()
        assert d["target"] == "server"
        assert d["binary"] == "server.dll"
        assert d["arch"] == "x86_32"
        assert d["functions"]["total"] == 0
        assert d["functions"]["covered"] == 0
        assert d["coverage_pct"] == 0.0
        assert d["matched_pct"] == 0.0
        assert "last_verify" not in d
        assert "matched_bytes" not in d  # excluded when total_text_bytes == 0

    def test_to_dict_with_bytes(self) -> None:
        report = StatusReport(
            target="t",
            binary="t.dll",
            arch="x86_32",
            matched_bytes=500,
            total_text_bytes=2000,
        )
        d = report.to_dict()
        assert d["matched_bytes"] == 500
        assert d["total_text_bytes"] == 2000
        assert d["byte_coverage_pct"] == 25.0

    def test_to_dict_with_verify_info(self) -> None:
        report = StatusReport(
            target="t",
            binary="t.dll",
            arch="x86_32",
            verify_info=VerifyInfo(
                timestamp="2026-03-09 00:00",
                passed=10,
                failed=2,
                total=12,
            ),
        )
        d = report.to_dict()
        assert "last_verify" in d
        assert d["last_verify"]["passed"] == 10
        assert d["last_verify"]["failed"] == 2
        assert d["last_verify"]["total"] == 12

    def test_to_dict_with_status_counts(self) -> None:
        report = StatusReport(
            target="t",
            binary="t.dll",
            arch="x86_32",
            total_functions=100,
            covered_functions=60,
            status_counts={"EXACT": 30, "RELOC": 10, "MATCHING": 15, "STUB": 5},
        )
        d = report.to_dict()
        assert d["status"]["EXACT"] == 30
        assert d["status"]["RELOC"] == 10
        assert d["coverage_pct"] == 60.0
        assert d["matched_pct"] == 40.0


# ---------------------------------------------------------------------------
# VerifyInfo tests
# ---------------------------------------------------------------------------


class TestVerifyInfo:
    def test_defaults(self) -> None:
        v = VerifyInfo()
        assert v.timestamp == ""
        assert v.passed == 0
        assert v.failed == 0
        assert v.total == 0


# ---------------------------------------------------------------------------
# collect_status tests
# ---------------------------------------------------------------------------


class TestCollectStatus:
    def test_empty_project(self, tmp_path: Path) -> None:
        """Fresh project with no data → zeroed report."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        # No function_structure.json → load_data will raise, graceful degradation
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.target == "test"
        assert report.total_functions == 0
        assert report.covered_functions == 0
        assert report.status_counts == {}

    def test_with_function_data(self, tmp_path: Path) -> None:
        """Project with function list and source files → populated report."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()

        # Create function_structure.json
        funcs = [
            {"va": 0x1000, "size": 100, "ghidra_name": "func_a"},
            {"va": 0x2000, "size": 200, "ghidra_name": "func_b"},
            {"va": 0x3000, "size": 50, "ghidra_name": "func_c"},
        ]
        (src / "function_structure.json").write_text(json.dumps(funcs), encoding="utf-8")

        # Create source files with annotations
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// STATUS: EXACT\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        (src / "func_b.c").write_text(
            "// FUNCTION: TEST 0x2000\n// STATUS: MATCHING\nvoid func_b(void) {}\n",
            encoding="utf-8",
        )

        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.total_functions == 3
        assert report.covered_functions == 2
        assert report.status_counts.get("EXACT") == 1
        assert report.status_counts.get("MATCHING") == 1
        assert report.source_files == 2

    def test_verify_cache_loaded(self, tmp_path: Path) -> None:
        """Verify cache present → verify_info populated."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")

        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        cache_data = {
            "version": 1,
            "entries": {
                "0x1000": {
                    "source_hash": "abc",
                    "filepath": "a.c",
                    "mtime_ns": 0,
                    "result": {
                        "status": "EXACT",
                        "va": "0x1000",
                        "size": 100,
                        "filepath": "a.c",
                        "name": "func_a",
                        "passed": True,
                    },
                },
                "0x2000": {
                    "source_hash": "def",
                    "filepath": "b.c",
                    "mtime_ns": 0,
                    "result": {
                        "status": "MISMATCH",
                        "va": "0x2000",
                        "size": 50,
                        "filepath": "b.c",
                        "name": "func_b",
                        "passed": False,
                    },
                },
            },
        }
        (cache_dir / "verify_cache.json").write_text(json.dumps(cache_data), encoding="utf-8")

        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.verify_info is not None
        assert report.verify_info.passed == 1
        assert report.verify_info.failed == 1
        assert report.verify_info.total == 2

    def test_verify_cache_missing(self, tmp_path: Path) -> None:
        """No verify cache → verify_info is None."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")

        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.verify_info is None

    def test_verify_overrides_annotation_status(self, tmp_path: Path) -> None:
        """Verify results override optimistic annotation statuses."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()

        # 3 functions in structure
        funcs = [
            {"va": 0x1000, "size": 100, "ghidra_name": "func_a"},
            {"va": 0x2000, "size": 200, "ghidra_name": "func_b"},
            {"va": 0x3000, "size": 50, "ghidra_name": "func_c"},
        ]
        (src / "function_structure.json").write_text(json.dumps(funcs), encoding="utf-8")

        # All annotated as RELOC
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// STATUS: RELOC\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        (src / "func_b.c").write_text(
            "// FUNCTION: TEST 0x2000\n// STATUS: RELOC\nvoid func_b(void) {}\n",
            encoding="utf-8",
        )
        (src / "func_c.c").write_text(
            "// FUNCTION: TEST 0x3000\n// STATUS: RELOC\nvoid func_c(void) {}\n",
            encoding="utf-8",
        )

        # Verify cache says func_b is MISMATCH and func_c is COMPILE_ERROR
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        cache_data = {
            "version": 1,
            "entries": {
                "0x1000": {
                    "source_hash": "a",
                    "filepath": "func_a.c",
                    "mtime_ns": 0,
                    "result": {"status": "RELOC", "va": "0x1000", "size": 100, "passed": True},
                },
                "0x2000": {
                    "source_hash": "b",
                    "filepath": "func_b.c",
                    "mtime_ns": 0,
                    "result": {
                        "status": "MISMATCH",
                        "va": "0x2000",
                        "size": 200,
                        "passed": False,
                    },
                },
                "0x3000": {
                    "source_hash": "c",
                    "filepath": "func_c.c",
                    "mtime_ns": 0,
                    "result": {
                        "status": "COMPILE_ERROR",
                        "va": "0x3000",
                        "size": 50,
                        "passed": False,
                    },
                },
            },
        }
        (cache_dir / "verify_cache.json").write_text(json.dumps(cache_data), encoding="utf-8")

        report = collect_status(cfg)  # type: ignore[arg-type]
        # Only func_a should count as RELOC; b and c overridden by verify
        assert report.status_counts.get("RELOC") == 1
        assert report.status_counts.get("MISMATCH") == 1
        assert report.status_counts.get("COMPILE_ERROR") == 1
        # matched_pct should reflect only the 1 actual RELOC out of 3
        assert report.matched_pct == round(100.0 * 1 / 3, 1)
