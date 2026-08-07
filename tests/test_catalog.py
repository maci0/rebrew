"""Tests for rebrew.catalog — report generation and registry building."""

import json
from pathlib import Path

import pytest

from rebrew.annotation import Annotation
from rebrew.catalog import (
    build_function_registry,
    count_detection_sources,
    generate_catalog,
    generate_data_json,
    make_func_entry,
    make_ghidra_func,
    merge_ranges,
    parse_function_list,
    scan_reversed_dir,
)
from rebrew.config import ProjectConfig

# -------------------------------------------------------------------------
# Helper factories
# -------------------------------------------------------------------------


class TestMakeFactories:
    def test_make_func_entry(self) -> None:
        f = make_func_entry(0x10001000, 64, "_my_func")
        assert f["va"] == 0x10001000
        assert f["size"] == 64
        assert f["name"] == "_my_func"

    def test_make_ghidra_func(self) -> None:
        f = make_ghidra_func(0x10001000, 64, "my_func")
        assert f["va"] == 0x10001000
        assert f["size"] == 64
        assert f["ghidra_name"] == "my_func"


# -------------------------------------------------------------------------
# merge_ranges
# -------------------------------------------------------------------------


class TestMergeRanges:
    def test_empty(self) -> None:
        assert merge_ranges([]) == []

    def test_non_overlapping(self) -> None:
        result = merge_ranges([(1, 5), (10, 15)])
        assert result == [(1, 5), (10, 15)]

    def test_overlapping(self) -> None:
        result = merge_ranges([(1, 10), (5, 15)])
        assert result == [(1, 15)]

    def test_adjacent(self) -> None:
        result = merge_ranges([(1, 5), (5, 10)])
        assert result == [(1, 10)]

    def test_fully_contained(self) -> None:
        result = merge_ranges([(1, 20), (5, 10)])
        assert result == [(1, 20)]

    def test_unsorted_input(self) -> None:
        result = merge_ranges([(10, 20), (1, 5)])
        assert result == [(1, 5), (10, 20)]


# -------------------------------------------------------------------------
# build_function_registry
# -------------------------------------------------------------------------


class TestBuildFunctionRegistry:
    def setup_method(self) -> None:
        self.cfg = ProjectConfig(
            root=Path("/tmp"),
            iat_thunks=[],
            dll_exports={},
            ignored_symbols=[],
        )

    def test_basic(self) -> None:
        funcs = [
            make_func_entry(0x10001000, 64, "_func_a"),
            make_func_entry(0x10002000, 128, "_func_b"),
        ]
        reg = build_function_registry(funcs, self.cfg)
        assert 0x10001000 in reg
        assert 0x10002000 in reg
        assert "list" in reg[0x10001000]["detected_by"]

    def test_bogus_sizes_filtered(self) -> None:
        """Functions with VAs in cfg.r2_bogus_vas should still be in registry but size excluded."""
        bogus_va = 0xDEAD0000
        self.cfg.r2_bogus_vas = [bogus_va]
        funcs = [make_func_entry(bogus_va, 999999, "_bogus")]
        reg = build_function_registry(funcs, self.cfg)
        assert bogus_va in reg
        # Size should NOT be recorded for bogus VAs
        assert "list" not in reg[bogus_va]["size_by_tool"]
        # Effective size should be 0 (not the bogus 999999)
        assert reg[bogus_va].get("size", 0) == 0

    def test_with_ghidra(self, tmp_path: Path) -> None:
        funcs = [make_func_entry(0x10001000, 64, "_func_a")]
        ghidra_json = tmp_path / "function_structure.json"
        ghidra_data = [
            make_ghidra_func(0x10001000, 64, "func_a"),
            make_ghidra_func(0x10003000, 32, "func_c"),
        ]
        ghidra_json.write_text(json.dumps(ghidra_data), encoding="utf-8")
        reg = build_function_registry(funcs, self.cfg, ghidra_path=ghidra_json)
        assert 0x10001000 in reg
        assert 0x10003000 in reg
        assert "ghidra" in reg[0x10003000]["detected_by"]

    def test_iat_thunks(self) -> None:
        funcs = [make_func_entry(0x10001000, 6, "_thunk_func")]
        cfg = ProjectConfig(
            root=Path("/tmp"),
            iat_thunks=[0x10001000],
            dll_exports={},
            ignored_symbols=[],
        )
        reg = build_function_registry(funcs, cfg)
        assert reg[0x10001000].get("is_thunk") is True

    def test_exports(self) -> None:
        funcs = [make_func_entry(0x10001000, 64, "_my_export")]
        cfg = ProjectConfig(
            root=Path("/tmp"),
            iat_thunks=[],
            dll_exports={0x10001000: "MyExport"},
            ignored_symbols=[],
        )
        reg = build_function_registry(funcs, cfg)
        assert reg[0x10001000].get("is_export") is True


class TestCountDetectionSources:
    def test_empty_registry(self) -> None:
        assert count_detection_sources({}) == (0, 0, 0, 0)

    def test_breakdown(self) -> None:
        cfg = ProjectConfig(
            root=Path("/tmp"),
            iat_thunks=[0x10004000],
            dll_exports={},
            ignored_symbols=[],
        )
        funcs = [
            make_func_entry(0x10001000, 64, "_a"),  # list only
            make_func_entry(0x10002000, 64, "_b"),  # list + ghidra
        ]
        ghidra_json = Path("/tmp") / "function_structure.json"
        ghidra_json.write_text(
            json.dumps(
                [
                    make_ghidra_func(0x10002000, 64, "b"),
                    make_ghidra_func(0x10003000, 32, "c"),  # ghidra only
                    make_ghidra_func(0x10004000, 6, "thunk"),  # thunk
                ]
            ),
            encoding="utf-8",
        )
        reg = build_function_registry(funcs, cfg, ghidra_path=ghidra_json)
        ghidra_count, list_count, both_count, thunk_count = count_detection_sources(reg)
        assert ghidra_count == 3  # 0x10002000, 0x10003000, 0x10004000
        assert list_count == 2  # 0x10001000, 0x10002000
        assert both_count == 1  # 0x10002000
        assert thunk_count == 1  # 0x10004000


# -------------------------------------------------------------------------
# generate_catalog
# -------------------------------------------------------------------------


class TestGenerateCatalog:
    def test_basic(self) -> None:
        entries = [
            Annotation(
                va=0x10001000,
                name="func_a",
                status="EXACT",
                size=64,
                symbol="_func_a",
                filepath="/src/func_a.c",
                cflags="/O2",
                marker_type="FUNCTION",
            ),
            Annotation(
                va=0x10002000,
                name="func_b",
                status="STUB",
                size=32,
                symbol="_func_b",
                filepath="/src/func_b.c",
                cflags="/O2",
                marker_type="FUNCTION",
            ),
        ]
        funcs = [
            make_func_entry(0x10001000, 64, "_func_a"),
            make_func_entry(0x10002000, 32, "_func_b"),
        ]
        md = generate_catalog(entries, funcs, text_size=1000)
        assert isinstance(md, str)
        assert "func_a" in md
        assert "func_b" in md
        assert len(md) > 50

    def test_empty(self) -> None:
        md = generate_catalog([], [], text_size=1000)
        assert isinstance(md, str)
        assert "0 of" in md or "0%" in md or "0.0%" in md  # should report zero coverage


# -------------------------------------------------------------------------
# generate_data_json
# -------------------------------------------------------------------------


class TestGenerateDataJson:
    def test_basic(self) -> None:
        entries = [
            Annotation(
                va=0x10001000,
                name="func_a",
                status="EXACT",
                size=64,
                symbol="_func_a",
                filepath="/src/func_a.c",
                cflags="/O2",
                marker_type="FUNCTION",
            ),
        ]
        funcs = [make_func_entry(0x10001000, 64, "_func_a")]
        data = generate_data_json(entries, funcs, text_size=1000)
        assert isinstance(data, dict)
        assert "sections" in data
        assert "summary" in data
        assert "functions" in data
        assert data["summary"]["exactMatches"] == 1

    def test_empty_data(self) -> None:
        data = generate_data_json([], [], text_size=0)
        assert isinstance(data, dict)
        assert "sections" in data
        assert "summary" in data
        assert "functions" in data
        assert data["summary"]["totalFunctions"] == 0
        assert data["summary"]["exactMatches"] == 0
        assert len(data["functions"]) == 0

    def test_near_matching_status_counted(self) -> None:
        entries = [
            Annotation(
                va=0x10001000,
                name="func_a",
                status="NEAR_MATCHING",
                size=64,
                symbol="_func_a",
                filepath="/src/func_a.c",
                cflags="/O2",
                marker_type="FUNCTION",
            ),
        ]
        funcs = [make_func_entry(0x10001000, 64, "_func_a")]
        data = generate_data_json(entries, funcs, text_size=1000)

        assert data["summary"]["nearMatchCount"] == 1
        assert data["summary"]["stubCount"] == 0


# -------------------------------------------------------------------------
# parse_function_list (additional cases)
# -------------------------------------------------------------------------


class TestParseFunctionListExtended:
    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")
        result = parse_function_list(f)
        assert result == []

    def test_missing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "nonexistent.txt"
        with pytest.warns(UserWarning, match="Cannot read"):
            result = parse_function_list(f)
        assert result == []

    def test_malformed_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.txt"
        f.write_text("not a valid line\n0x10001000\nfoo bar baz\n", encoding="utf-8")
        result = parse_function_list(f)
        assert result == []


# -------------------------------------------------------------------------
# scan_reversed_dir (additional cases)
# -------------------------------------------------------------------------


class TestScanReversedDirExtended:
    def test_ignores_non_c(self, tmp_path: Path) -> None:
        (tmp_path / "readme.txt").write_text("ignore me", encoding="utf-8")
        (tmp_path / "notes.md").write_text("also ignore me", encoding="utf-8")
        result = scan_reversed_dir(tmp_path)
        assert result == []

    def test_ignores_bad_c(self, tmp_path: Path) -> None:
        (tmp_path / "bad.c").write_text("no annotations here\nint main() {}\n", encoding="utf-8")
        result = scan_reversed_dir(tmp_path)
        assert result == []


# ---------------------------------------------------------------------------
# Catalog imports and functional tests
# ---------------------------------------------------------------------------


class TestCatalogFunctional:
    def test_parse_function_list_parses_correctly(self, tmp_path: Path) -> None:
        from rebrew.catalog import parse_function_list

        func_list = tmp_path / "functions.txt"
        func_list.write_text(
            "0x10001000 64 _my_func\n"
            "0x10002000 128 _other_func\n"
            "# comment line\n"
            "0x10003000 32 _third_func\n",
            encoding="utf-8",
        )
        funcs = parse_function_list(func_list)
        assert len(funcs) == 3
        assert funcs[0]["va"] == 0x10001000
        assert funcs[0]["size"] == 64
        assert funcs[0]["name"] == "_my_func"

    def test_scan_reversed_dir_finds_annotated_files(self, tmp_path: Path) -> None:
        from rebrew.catalog import scan_reversed_dir

        c_file = tmp_path / "game_func.c"
        c_file.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _my_func\n"
            "void __cdecl _my_func(void) {}\n",
            encoding="utf-8",
        )
        (tmp_path / "readme.txt").write_text("ignore me", encoding="utf-8")
        entries = scan_reversed_dir(tmp_path)
        assert len(entries) == 1

    def test_r2_bogus_vas_via_config(self, tmp_path: Path) -> None:
        from pathlib import Path

        from rebrew.catalog import build_function_registry, make_func_entry
        from rebrew.config import ProjectConfig

        bogus_va = 0xBEEF0000
        cfg = ProjectConfig(
            root=Path("/tmp"), iat_thunks=[], dll_exports={}, r2_bogus_vas=[bogus_va]
        )
        funcs = [make_func_entry(bogus_va, 12345, "_bogus")]
        reg = build_function_registry(funcs, cfg)
        assert bogus_va in reg
        assert "list" not in reg[bogus_va]["size_by_tool"]
