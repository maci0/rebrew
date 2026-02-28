"""Tests for rebrew.catalog — report generation and registry building."""

import json
from pathlib import Path

from rebrew.catalog import (
    build_function_registry,
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

    def test_with_ghidra(self, tmp_path) -> None:
        funcs = [make_func_entry(0x10001000, 64, "_func_a")]
        ghidra_json = tmp_path / "ghidra_functions.json"
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


# -------------------------------------------------------------------------
# generate_catalog
# -------------------------------------------------------------------------


class TestGenerateCatalog:
    def test_basic(self) -> None:
        entries = [
            {
                "va": 0x10001000,
                "func_name": "func_a",
                "name": "func_a",
                "status": "EXACT",
                "origin": "GAME",
                "size": 64,
                "symbol": "_func_a",
                "filepath": "/src/func_a.c",
                "cflags": "/O2",
                "marker": "SERVER",
                "marker_type": "FUNCTION",
            },
        ]
        funcs = [make_func_entry(0x10001000, 64, "_func_a")]
        md = generate_catalog(entries, funcs, text_size=1000)
        assert isinstance(md, str)
        assert "func_a" in md

    def test_empty(self) -> None:
        md = generate_catalog([], [], text_size=1000)
        assert isinstance(md, str)


# -------------------------------------------------------------------------
# generate_data_json
# -------------------------------------------------------------------------


class TestGenerateDataJson:
    def test_basic(self) -> None:
        entries = [
            {
                "va": 0x10001000,
                "name": "func_a",
                "status": "EXACT",
                "origin": "GAME",
                "size": 64,
                "symbol": "_func_a",
                "filepath": "/src/func_a.c",
                "cflags": "/O2",
                "marker": "SERVER",
                "marker_type": "FUNCTION",
            },
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
        assert data["summary"]["totalFunctions"] == 0


# -------------------------------------------------------------------------
# parse_function_list (already tested in phase4, additional cases)
# -------------------------------------------------------------------------


class TestParseFunctionListExtended:
    def test_empty_file(self, tmp_path) -> None:
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")
        result = parse_function_list(f)
        assert result == []

    def test_missing_file(self, tmp_path) -> None:
        f = tmp_path / "nonexistent.txt"
        result = parse_function_list(f)
        assert result == []

    def test_malformed_lines(self, tmp_path) -> None:
        f = tmp_path / "bad.txt"
        f.write_text("not a valid line\n0x10001000\nfoo bar baz\n", encoding="utf-8")
        result = parse_function_list(f)
        assert result == []


# -------------------------------------------------------------------------
# scan_reversed_dir (additional cases)
# -------------------------------------------------------------------------


class TestScanReversedDirExtended:
    def test_ignores_non_c(self, tmp_path) -> None:
        (tmp_path / "readme.txt").write_text("ignore me", encoding="utf-8")
        (tmp_path / "notes.md").write_text("also ignore me", encoding="utf-8")
        result = scan_reversed_dir(tmp_path)
        assert result == []

    def test_ignores_bad_c(self, tmp_path) -> None:
        (tmp_path / "bad.c").write_text("no annotations here\nint main() {}\n", encoding="utf-8")
        result = scan_reversed_dir(tmp_path)
        assert result == []
