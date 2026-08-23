"""Tests for rebrew status overview command."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

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
            status_counts={"EXACT": 20, "RELOC": 10, "NEAR_MATCHING": 30, "STUB": 40},
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
            status_counts={"EXACT": 30, "RELOC": 10, "NEAR_MATCHING": 15, "STUB": 5},
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
            "// FUNCTION: TEST 0x2000\n// STATUS: NEAR_MATCHING\nvoid func_b(void) {}\n",
            encoding="utf-8",
        )

        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.total_functions == 3
        assert report.covered_functions == 2
        assert report.status_counts.get("EXACT") == 1
        assert report.status_counts.get("NEAR_MATCHING") == 1
        assert report.source_files == 2
        assert report.unresolved_blockers == 0
        assert report.to_dict()["unresolved_blockers"] == 0

    def test_naked_reconstruction_bucketed(self, tmp_path: Path) -> None:
        """A `// SOURCE: naked` EXACT function is byte-coverage but NOT
        decompiled: naked_matched counts it, decompiled_pct excludes it, and
        matched_pct still reflects byte-matching."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text(
            json.dumps([{"va": 0x1000, "size": 100, "ghidra_name": "func_a"}]),
            encoding="utf-8",
        )
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// SIZE: 100\n// STATUS: EXACT\n"
            "// SOURCE: naked\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.naked_matched == 1
        assert report.status_counts.get("EXACT") == 1  # still byte-matched
        assert report.matched_pct == 100.0
        assert report.decompiled_pct == 0.0  # nothing decompiled yet
        assert report.to_dict()["naked_matched"] == 1
        assert report.to_dict()["decompiled_pct"] == 0.0

    def test_unresolved_blockers_counted(self, tmp_path: Path) -> None:
        """Functions with a non-empty BLOCKER in rebrew-function.toml are counted."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()

        (src / "function_structure.json").write_text(
            json.dumps([{"va": 0x1000, "size": 100, "ghidra_name": "func_a"}]),
            encoding="utf-8",
        )
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// STATUS: STUB\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )

        # metadata_dir points at tmp_path (parent of reversed_dir); the metadata
        # file lives there with a per-module table keyed "MODULE.0xVA".
        (tmp_path / "rebrew-function.toml").write_text(
            '["TEST.0x1000"]\nblocker = "register allocation (eax/ecx swap)"\n',
            encoding="utf-8",
        )

        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.unresolved_blockers == 1
        assert report.to_dict()["unresolved_blockers"] == 1

    def test_empty_blocker_not_counted(self, tmp_path: Path) -> None:
        """An empty BLOCKER metadata entry is not an unresolved blocker."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()

        (src / "function_structure.json").write_text(
            json.dumps([{"va": 0x1000, "size": 100, "ghidra_name": "func_a"}]),
            encoding="utf-8",
        )
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// STATUS: STUB\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        (tmp_path / "rebrew-function.toml").write_text(
            '["TEST.0x1000"]\nblocker = ""\n',
            encoding="utf-8",
        )

        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.unresolved_blockers == 0

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
            "target": "test",
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

    def test_status_handles_annotated_vas_not_in_ghidra(self, tmp_path: Path) -> None:
        """When source annotations cover VAs that aren't in function_structure.json,
        total_functions must be the union so percentages stay <= 100%."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()

        # Ghidra knows only 2 functions
        funcs = [
            {"va": 0x1000, "size": 100, "ghidra_name": "func_a"},
            {"va": 0x2000, "size": 200, "ghidra_name": "func_b"},
        ]
        (src / "function_structure.json").write_text(json.dumps(funcs), encoding="utf-8")

        # Source tree has 4 annotated VAs — 2 inside Ghidra set, 2 outside it
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// STATUS: EXACT\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        (src / "func_b.c").write_text(
            "// FUNCTION: TEST 0x2000\n// STATUS: RELOC\nvoid func_b(void) {}\n",
            encoding="utf-8",
        )
        (src / "func_c.c").write_text(
            "// FUNCTION: TEST 0x3000\n// STATUS: STUB\nvoid func_c(void) {}\n",
            encoding="utf-8",
        )
        (src / "func_d.c").write_text(
            "// FUNCTION: TEST 0x4000\n// STATUS: STUB\nvoid func_d(void) {}\n",
            encoding="utf-8",
        )

        report = collect_status(cfg)  # type: ignore[arg-type]

        # total must be the union (4), not just Ghidra's 2
        assert report.total_functions == 4
        assert report.covered_functions == 4

        # All percentages must be <= 100%
        assert report.coverage_pct <= 100.0
        assert report.matched_pct <= 100.0
        for status, count in report.status_counts.items():
            pct = round(100.0 * count / report.total_functions, 1)
            assert pct <= 100.0, f"{status} pct {pct} > 100%"

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
            "target": "test",
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
        # The effective-status overlay is surfaced, not emergent.
        assert report.verify_overrides == 2  # func_b, func_c
        assert report.verify_missing_size == 0
        d = report.to_dict()
        assert d["verify_cache"] == {"overrides": 2, "missing_size": 0}

    def test_missing_size_overlay_surfaced(self, tmp_path: Path) -> None:
        """MISSING_SIZE (metadata SIZE absent) shows up as its own bucket."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text(
            json.dumps([{"va": 0x1000, "size": 100, "ghidra_name": "func_a"}]),
            encoding="utf-8",
        )
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// STATUS: EXACT\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        (cache_dir / "verify_cache.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "target": "test",
                    "entries": {
                        "0x1000": {
                            "source_hash": "a",
                            "filepath": "func_a.c",
                            "mtime_ns": 0,
                            "result": {
                                "status": "MISSING_SIZE",
                                "va": "0x1000",
                                "size": 0,
                                "passed": False,
                            },
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.status_counts.get("MISSING_SIZE") == 1
        assert report.verify_overrides == 1
        assert report.verify_missing_size == 1
        d = report.to_dict()
        assert d["verify_cache"] == {"overrides": 1, "missing_size": 1}


# ---------------------------------------------------------------------------
# E10 — W019 quick lint (inline metadata detection)
# ---------------------------------------------------------------------------


class TestInlineMetadataWarning:
    def test_no_inline_metadata(self, tmp_path: Path) -> None:
        """Source files with no inline metadata → warning count == 0."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 0

    def test_inline_status_detected(self, tmp_path: Path) -> None:
        """A file with // STATUS: inline → warning count == 1."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// STATUS: EXACT\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 1

    def test_inline_cflags_detected(self, tmp_path: Path) -> None:
        """A file with // CFLAGS: inline → warning count == 1."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// CFLAGS: /O2 /Gd\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 1

    def test_multiple_files_with_inline(self, tmp_path: Path) -> None:
        """Multiple files with inline metadata → count matches number of files."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// STATUS: EXACT\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        (src / "func_b.c").write_text(
            "// FUNCTION: TEST 0x2000\n// SIZE: 100\nvoid func_b(void) {}\n",
            encoding="utf-8",
        )
        # func_c.c has no inline metadata
        (src / "func_c.c").write_text(
            "// FUNCTION: TEST 0x3000\nvoid func_c(void) {}\n",
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 2

    def test_markerless_cflags_not_counted(self, tmp_path: Path) -> None:
        """A markerless // CFLAGS (naked-guard #else convention) is not counted.

        It is not migratable (no marker block) and lint's E023 documents the
        inline REBREW_ALLOW_NAKED CFLAGS form — the status warning must not nag
        about files lint cannot fix.
        """
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\nint func_a(void) {}\n"
            "#else\n// CFLAGS: /O2 /Gd /DREBREW_ALLOW_NAKED\n",
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 0

    def test_metadata_backed_inline_not_counted(self, tmp_path: Path) -> None:
        """An inline key already owned by rebrew-function.toml is not counted."""
        from rebrew.metadata import set_field

        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// SIZE: 42\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        set_field(tmp_path, 0x1000, "size", 42, module="TEST")
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 0

    def test_pending_cflags_before_marker_backed_not_counted(self, tmp_path: Path) -> None:
        """A // CFLAGS before the marker, backed by metadata, is not counted."""
        from rebrew.metadata import set_field

        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "func_a.c").write_text(
            "// CFLAGS: /O2 /Gd /DREBREW_ALLOW_NAKED\n// FUNCTION: TEST 0x1000\n"
            "void func_a(void) {}\n",
            encoding="utf-8",
        )
        set_field(tmp_path, 0x1000, "cflags", "/O2 /Gd /DREBREW_ALLOW_NAKED", module="TEST")
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 0

    def test_pending_cflags_before_marker_unbacked_counted(self, tmp_path: Path) -> None:
        """A // CFLAGS before the marker with no metadata backing is counted."""
        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "func_a.c").write_text(
            "// CFLAGS: /O2 /Gd\n// FUNCTION: TEST 0x1000\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 1

    def test_data_size_backed_not_counted(self, tmp_path: Path) -> None:
        """DATA blocks source size/section/note from rebrew-data.toml."""
        from rebrew.data_metadata import set_data_field

        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        (src / "function_structure.json").write_text("[]", encoding="utf-8")
        (src / "globals.c").write_text(
            "// DATA: TEST 0x1000\n// SIZE: 16\nint g_x;\n", encoding="utf-8"
        )
        set_data_field(tmp_path, 0x1000, "size", 16, "TEST")
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.inline_metadata_warning == 0

    def test_inline_warning_in_to_dict(self, tmp_path: Path) -> None:
        """inline_metadata_warning appears in to_dict() only when non-zero."""
        report_clean = StatusReport()
        assert "inline_metadata_warning" not in report_clean.to_dict()

        report_dirty = StatusReport(inline_metadata_warning=3)
        d = report_dirty.to_dict()
        assert d["inline_metadata_warning"] == 3


class TestVerifyCacheHelpers:
    def _cfg(self, tmp_path: Path) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(
            root=tmp_path,
            target_name="T",
            reversed_dir=tmp_path,
            target_binary=tmp_path / "x.dll",
            metadata_dir=tmp_path,
            source_ext=".c",
        )

    def _write_cache(self, tmp_path: Path, payload: object) -> None:
        import json

        d = tmp_path / ".rebrew"
        d.mkdir(exist_ok=True)
        (d / "verify_cache.json").write_text(json.dumps(payload), encoding="utf-8")

    def test_verify_info_missing_file(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_info

        assert _load_verify_info(self._cfg(tmp_path)) is None

    def test_verify_info_corrupt_json(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_info

        self._write_cache(tmp_path, "{not json")
        assert _load_verify_info(self._cfg(tmp_path)) is None

    def test_verify_info_wrong_version(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_info

        self._write_cache(tmp_path, {"version": 99, "entries": {"0x1": {}}})
        assert _load_verify_info(self._cfg(tmp_path)) is None

    def test_verify_info_empty_entries(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_info

        self._write_cache(tmp_path, {"version": 1, "entries": {}})
        assert _load_verify_info(self._cfg(tmp_path)) is None

    def test_verify_info_counts(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_info

        self._write_cache(
            tmp_path,
            {
                "version": 1,
                "target": "T",
                "entries": {
                    "0x1": {"result": {"passed": True}},
                    "0x2": {"result": {"passed": False}},
                    "0x3": "not-a-dict",  # skipped
                },
            },
        )
        info = _load_verify_info(self._cfg(tmp_path))
        assert info is not None
        assert info.passed == 1
        assert info.failed == 1
        assert info.total == 2

    def test_verify_statuses_hex_and_decimal(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_statuses

        self._write_cache(
            tmp_path,
            {
                "version": 1,
                "target": "T",
                "entries": {
                    "0x1000": {"result": {"status": "EXACT"}},
                    "zzz": {"result": {"status": "EXACT"}},  # bad VA skipped
                    "4097": {"result": {"status": "STUB"}},  # non-hex key skipped
                    "0x2000": {"result": {}},  # no status skipped
                },
            },
        )
        statuses = _load_verify_statuses(self._cfg(tmp_path))
        assert statuses == {0x1000: "EXACT"}

    def test_verify_info_wrong_target_ignored(self, tmp_path: Path) -> None:
        """A cache written for another target must not be presented as ours."""
        from rebrew.status import _load_verify_info

        self._write_cache(
            tmp_path,
            {
                "version": 1,
                "target": "OTHER",
                "entries": {"0x1": {"result": {"passed": True}}},
            },
        )
        assert _load_verify_info(self._cfg(tmp_path)) is None

    def test_verify_statuses_wrong_target_ignored(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_statuses

        self._write_cache(
            tmp_path,
            {
                "version": 1,
                "target": "OTHER",
                "entries": {"0x1": {"result": {"status": "EXACT"}}},
            },
        )
        assert _load_verify_statuses(self._cfg(tmp_path)) == {}

    def test_verify_info_null_result_skipped_not_failed(self, tmp_path: Path) -> None:
        """Null/truthy-non-dict results are skipped, never counted as failures."""
        from rebrew.status import _load_verify_info

        self._write_cache(
            tmp_path,
            {
                "version": 1,
                "target": "T",
                "entries": {
                    "0x1": {"result": None},  # skipped
                    "0x2": {"result": "COMPILE_ERROR"},  # skipped
                    "0x3": {"result": {"passed": False}},  # real failure
                },
            },
        )
        info = _load_verify_info(self._cfg(tmp_path))
        assert info is not None
        assert info.passed == 0
        assert info.failed == 1
        assert info.total == 1

    def test_verify_info_entries_list_no_crash(self, tmp_path: Path) -> None:
        """A malformed cache whose entries is a list is treated as absent."""
        from rebrew.status import _load_verify_info

        self._write_cache(tmp_path, {"version": 1, "target": "T", "entries": ["0x1", "0x2"]})
        assert _load_verify_info(self._cfg(tmp_path)) is None

    def test_verify_statuses_entries_list_no_crash(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_statuses

        self._write_cache(tmp_path, {"version": 1, "target": "T", "entries": ["0x1"]})
        assert _load_verify_statuses(self._cfg(tmp_path)) == {}

    def test_verify_statuses_missing_file(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_statuses

        assert _load_verify_statuses(self._cfg(tmp_path)) == {}

    def test_compute_text_size_missing_binary(self, tmp_path: Path) -> None:
        from rebrew.status import _compute_text_size

        assert _compute_text_size(self._cfg(tmp_path)) == 0

    def test_compute_text_size_available(self, tmp_path: Path, monkeypatch: object) -> None:
        from rebrew.status import _compute_text_size

        (tmp_path / "x.dll").write_bytes(b"MZ")
        monkeypatch.setattr("rebrew.catalog.sections.get_text_section_size", lambda _p: 0x1234)
        assert _compute_text_size(self._cfg(tmp_path)) == 0x1234


class TestStatusBranches:
    def test_verify_statuses_corrupt_json(self, tmp_path: Path) -> None:
        from rebrew.status import _load_verify_statuses

        cache = tmp_path / ".rebrew"
        cache.mkdir()
        (cache / "verify_cache.json").write_text("{broken", encoding="utf-8")
        cfg = SimpleNamespace(root=tmp_path)
        assert _load_verify_statuses(cfg) == {}  # type: ignore[arg-type]

    def test_verify_statuses_non_dict_raw(self, tmp_path: Path) -> None:
        import json

        from rebrew.status import _load_verify_statuses

        cache = tmp_path / ".rebrew"
        cache.mkdir()
        (cache / "verify_cache.json").write_text(json.dumps([1, 2]), encoding="utf-8")
        cfg = SimpleNamespace(root=tmp_path)
        assert _load_verify_statuses(cfg) == {}  # type: ignore[arg-type]

    def test_verify_statuses_non_dict_entry_skipped(self, tmp_path: Path) -> None:
        import json

        from rebrew.status import _load_verify_statuses

        cache = tmp_path / ".rebrew"
        cache.mkdir()
        (cache / "verify_cache.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "target": "T",
                    "entries": {
                        "0x1000": "junk",
                        "0x2000": {"result": {"status": "EXACT"}},
                        "0x3000": {"result": {}},  # no status → skipped
                    },
                }
            ),
            encoding="utf-8",
        )
        cfg = SimpleNamespace(root=tmp_path, target_name="T")
        statuses = _load_verify_statuses(cfg)  # type: ignore[arg-type]
        assert statuses == {0x2000: "EXACT"}

    def test_compute_text_size_import_error(self, tmp_path: Path, monkeypatch: object) -> None:
        from rebrew.status import _compute_text_size

        cfg = SimpleNamespace(target_binary=tmp_path / "fake.dll")
        (tmp_path / "fake.dll").write_bytes(b"\x00" * 4)

        def _boom(*a: object, **k: object) -> object:
            raise ValueError("bad binary")

        monkeypatch.setattr("rebrew.catalog.sections.get_text_section_size", _boom)
        assert _compute_text_size(cfg) == 0  # type: ignore[arg-type]

    def test_collect_status_load_data_error_returns_zeroed(
        self, tmp_path: Path, monkeypatch: object
    ) -> None:
        from rebrew.status import collect_status

        cfg = SimpleNamespace(
            target_name="SERVER",
            target_binary=tmp_path / "fake.dll",
            arch="x86",
            reversed_dir=tmp_path / "src",
            root=tmp_path,
            source_ext=".c",
        )

        def _boom(*a: object, **k: object) -> object:
            raise OSError("no data")

        monkeypatch.setattr("rebrew.naming.load_data", _boom)
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.total_functions == 0
        assert report.covered_functions == 0
        assert report.status_counts == {}


class TestStatusCli:
    def test_json_output(self, tmp_path: Path, monkeypatch: object) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.status import StatusReport, app

        cfg = SimpleNamespace(
            root=tmp_path,
            target_name="SERVER",
            target_binary=tmp_path / "fake.dll",
            arch="x86",
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.status.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.status.collect_status",
            lambda cfg: StatusReport(target="SERVER", binary="fake.dll", arch="x86"),
        )
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["target"] == "SERVER"


class TestRenderTerminal:
    def _report(self, **kw: object) -> StatusReport:
        base: dict = {
            "target": "SERVER",
            "binary": "server.dll",
            "arch": "x86",
            "total_functions": 10,
            "covered_functions": 6,
            "source_files": 3,
            "status_counts": {
                "EXACT": 4,
                "RELOC": 1,
                "PROVEN": 1,
                "NEAR_MATCHING": 1,
                "STUB": 3,
            },
            "matched_bytes": 512,
            "total_text_bytes": 1024,
            "verify_info": VerifyInfo(timestamp="2026-08-07 06:00", passed=5, failed=1),
            "inline_metadata_warning": 2,
        }
        base.update(kw)
        return StatusReport(**base)

    def _capture(self, monkeypatch: pytest.MonkeyPatch) -> object:
        from io import StringIO

        from rich.console import Console

        import rebrew.status as status_mod

        buf = StringIO()
        monkeypatch.setattr(
            status_mod,
            "console",
            Console(file=buf, force_terminal=True, width=120, no_color=True, highlight=False),
        )
        return buf

    def test_full_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.status import _render_terminal

        buf = self._capture(monkeypatch)
        _render_terminal(self._report())
        out = buf.getvalue()
        assert "SERVER" in out
        assert "server.dll" in out
        assert "EXACT" in out
        assert "5 passed" in out
        assert "1 failed" in out
        assert "3 source files" in out

    def test_empty_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.status import _render_terminal

        buf = self._capture(monkeypatch)
        _render_terminal(StatusReport(target="X"))  # zeroed → no divide-by-zero
        out = buf.getvalue()
        assert "X" in out
        assert "0/0" in out or "0%" in out

    def test_other_statuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.status import _render_terminal

        buf = self._capture(monkeypatch)
        report = self._report(status_counts={"EXACT": 2, "COMPILE_ERROR": 3, "SIZE_MISMATCH": 1})
        _render_terminal(report)
        out = buf.getvalue()
        assert "COMPILE_ERROR" in out
        assert "SIZE_MISMATCH" in out

    def test_no_verify_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.status import _render_terminal

        buf = self._capture(monkeypatch)
        _render_terminal(self._report(verify_info=None))
        out = buf.getvalue()
        assert "Last verify" not in out
        assert "SERVER" in out

    def test_no_inline_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.status import _render_terminal

        buf = self._capture(monkeypatch)
        _render_terminal(self._report(inline_metadata_warning=0))
        out = buf.getvalue()
        assert "SERVER" in out
        # Warning only emitted when inline_metadata_warning > 0.
        assert "inline STATUS" not in out


class TestCollectStatusSizeFallback:
    """matched_bytes must not collapse to 0 when function_structure.json is
    missing but annotation-metadata SIZE exists (round-4)."""

    def test_size_fallback_without_ghidra_sizes(self, tmp_path: Path) -> None:
        from rebrew.status import collect_status

        cfg = _make_cfg(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        # EXACT function with metadata SIZE but NO function_structure.json.
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// SIZE: 100\n// STATUS: EXACT\nvoid func_a(void) {}\n",
            encoding="utf-8",
        )
        report = collect_status(cfg)  # type: ignore[arg-type]
        assert report.status_counts.get("EXACT") == 1
        # Size came from the annotation metadata, not Ghidra.
        assert report.matched_bytes == 100
