"""Tests for rebrew todo prioritized action dashboard."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.catalog.models import FunctionEntry
from rebrew.todo import (
    CAT_COMPILE_ERROR,
    CAT_FIX_DELTA,
    CAT_IDENTIFY_LIBRARY,
    CAT_IMPROVE_MATCH,
    CAT_MISSING_ANNOTATION,
    CAT_SETUP,
    CAT_START_FUNCTION,
    TodoItem,
    _collect_active_functions,
    _collect_library_candidates,
    _collect_new_functions,
    _collect_prover_candidates,
    _collect_setup_steps,
    calculate_roi,
    collect_all,
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
# Scoring tests
# ---------------------------------------------------------------------------


class TestScoring:
    def test_base_match_pct(self) -> None:
        # Match % 80, size 200 -> base 33.0. Size < 300 (+5). Total 38.0
        score = calculate_roi(200, 80.0, None, "NEAR_MATCHING")
        assert score == 38.0

    def test_small_delta_massive_boost(self) -> None:
        # Match % 80, size 200 -> base 33.0. 3b delta (+25.0). Size < 300 (+5). Total 63.0
        score_3b = calculate_roi(200, 80.0, 3, "NEAR_MATCHING")
        assert score_3b == 63.0

    def test_medium_delta_boost(self) -> None:
        # Match % 80, size 200 -> base 33.0. 15b delta (+15.0). Size < 300 (+5). Total 53.0
        score_15b = calculate_roi(200, 80.0, 15, "NEAR_MATCHING")
        assert score_15b == 53.0

    def test_size_modifiers(self) -> None:
        tiny = calculate_roi(20, 50.0, None, "STUB")  # +15 = 65
        small = calculate_roi(100, 50.0, None, "STUB")  # +10 = 60
        medium = calculate_roi(200, 50.0, None, "STUB")  # +5 = 55
        large = calculate_roi(500, 50.0, None, "STUB")  # +0 = 50
        huge = calculate_roi(1200, 50.0, None, "STUB")  # -10 = 40
        assert tiny > small > medium > large > huge

    def test_stubborn_diff_penalty(self) -> None:
        # High match, unknown delta: 99%, 200B -> bytes wrong = 2.0
        # Penalty adds 40.0 -> 42.0. 100 * exp(-42/150) ≈ 75.5.
        score = calculate_roi(200, 99.0, None, "NEAR_MATCHING")
        assert score < 80.0

        # High match, large delta
        score2 = calculate_roi(200, 96.0, 10, "NEAR_MATCHING")
        # delta = 10 => halved = 5.0 bytes wrong + penalty 40.0 => 45.0. 100*exp(-45/150) ≈ 74.0
        assert score2 < 80.0

    def test_missing_match_defaults_to_zero(self) -> None:
        # size 150, match None -> base 65.0. Size < 300 (+5). Total 70.0
        score = calculate_roi(150, None, None, "STUB")
        assert score == 70.0


# ---------------------------------------------------------------------------
# Collector tests
# ---------------------------------------------------------------------------


class TestCollectors:
    def test_active_functions_compile_error(self, tmp_path: Path) -> None:
        _cfg = _make_cfg(tmp_path)
        from rebrew.verify import VerifyCacheEntry, VerifyResult

        entries = {
            "0x00001000": VerifyCacheEntry(
                source_hash="",
                filepath="a.c",
                mtime_ns=0,
                result=VerifyResult(
                    status="COMPILE_ERROR",
                    va=0x1000,
                    size=100,
                    filepath="a.c",
                    name="a",
                    message="",
                    passed=False,
                ),
            )
        }
        items = _collect_active_functions({0x1000: {"status": "STUB"}}, {}, {}, entries)
        assert len(items) == 1
        assert items[0].category == CAT_COMPILE_ERROR
        assert items[0].roi_score == 200.0

    def test_active_functions_missing_annotation(self) -> None:
        existing = {0x1000: {"status": "STUB", "symbol": "", "filename": "a.c"}}
        items = _collect_active_functions(existing, {0x1000: 50}, {}, {})
        assert len(items) == 1
        assert items[0].category == CAT_MISSING_ANNOTATION
        assert items[0].name == "FUN_00001000"

    def test_active_functions_fix_delta(self) -> None:
        existing = {0x1000: {"status": "NEAR_MATCHING", "symbol": "func_a", "blocker_delta": "3"}}
        items = _collect_active_functions(existing, {0x1000: 50}, {}, {})
        assert len(items) == 1
        assert items[0].category == CAT_FIX_DELTA
        assert items[0].byte_delta == 3

    def test_active_functions_improve_match(self) -> None:
        existing = {
            0x1000: {"status": "NEAR_MATCHING", "symbol": "func_a", "blocker": "register swap"}
        }
        from rebrew.verify import VerifyCacheEntry, VerifyResult

        entries = {
            "0x00001000": VerifyCacheEntry(
                source_hash="",
                filepath="a.c",
                mtime_ns=0,
                result=VerifyResult(
                    status="NEAR_MATCHING",
                    va=0x1000,
                    size=100,
                    filepath="a.c",
                    name="func_a",
                    message="",
                    passed=False,
                    match_percent=85.0,
                ),
            )
        }
        items = _collect_active_functions(existing, {0x1000: 100}, {}, entries)
        assert len(items) == 1
        assert items[0].category == CAT_IMPROVE_MATCH
        assert items[0].match_percent == 85.0
        assert "register swap" in items[0].description

    def test_active_functions_skips_finished(self) -> None:
        existing = {
            0x1000: {"status": "EXACT", "symbol": "a"},
            0x2000: {"status": "RELOC", "symbol": "b"},
            0x3000: {"status": "PROVEN", "symbol": "c"},
        }
        items = _collect_active_functions(existing, {}, {}, {})
        assert len(items) == 0

    def test_library_candidates(self) -> None:
        msvcrt_func = SimpleNamespace(va=0x1000, size=100, name="__alloca", module="MSVCRT")
        other_func = SimpleNamespace(va=0x2000, size=200, name="game_func", module="")
        existing: dict[int, dict[str, str]] = {}
        cfg = SimpleNamespace(library_modules={"MSVCRT"})
        items = _collect_library_candidates([msvcrt_func, other_func], existing, cfg)  # type: ignore[arg-type]
        lib_items = [i for i in items if i.category == CAT_IDENTIFY_LIBRARY]
        assert any(i.va == 0x1000 for i in lib_items)
        assert not any(i.va == 0x2000 for i in lib_items)

    def test_new_functions_basic(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        ghidra_funcs = [
            FunctionEntry(va=0x1000, size=50, name="func_small"),
            FunctionEntry(va=0x2000, size=150, name="func_med"),
        ]
        items = _collect_new_functions(ghidra_funcs, {}, {}, cfg)
        assert len(items) == 2
        assert all(i.category == CAT_START_FUNCTION for i in items)

    def test_new_functions_skips_existing(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        ghidra_funcs = [FunctionEntry(va=0x1000, size=100, name="func")]
        existing = {
            0x1000: {"status": "EXACT", "symbol": "func", "filename": "f.c", "origin": "GAME"}
        }
        items = _collect_new_functions(ghidra_funcs, existing, {0x1000: "f.c"}, cfg)
        assert len(items) == 0

    def test_prover_candidates(self) -> None:
        existing = {
            0x1000: {"status": "NEAR_MATCHING", "symbol": "a", "size": "50"},
            0x2000: {"status": "STUB", "symbol": "b", "size": "50"},
            0x3000: {"status": "NEAR_MATCHING", "symbol": "c", "size": "600"},
        }
        items = _collect_prover_candidates(existing, {0x1000: 50, 0x2000: 50, 0x3000: 600}, {})
        # If angr is not installed, it returns 0. If it is, 1.
        assert len(items) in (0, 1)
        if items:
            assert items[0].va == 0x1000


# ---------------------------------------------------------------------------
# ROI ordering tests
# ---------------------------------------------------------------------------


class TestRoiOrdering:
    def test_small_delta_ranks_higher(self) -> None:
        small = TodoItem(
            category=CAT_FIX_DELTA,
            roi_score=calculate_roi(100, 50.0, 1, "NEAR_MATCHING"),
            va=0x1000,
            name="a",
            size=100,
            filename="",
            description="",
            command="",
            byte_delta=1,
        )
        large = TodoItem(
            category=CAT_FIX_DELTA,
            roi_score=calculate_roi(100, 50.0, 10, "NEAR_MATCHING"),
            va=0x2000,
            name="b",
            size=100,
            filename="",
            description="",
            command="",
            byte_delta=10,
        )
        items = sorted([large, small], key=lambda x: -x.roi_score)
        assert items[0].va == 0x1000


# ---------------------------------------------------------------------------
# TodoItem serialization
# ---------------------------------------------------------------------------


class TestJsonOutput:
    def test_to_dict_minimal(self) -> None:
        item = TodoItem(
            category=CAT_FIX_DELTA,
            roi_score=92.5,
            va=0x1000,
            name="func",
            size=100,
            filename="a.c",
            description="2B diff",
            command="rebrew match -d a.c",
        )
        d = item.to_dict()
        assert d["category"] == CAT_FIX_DELTA
        assert d["roi_score"] == 92.5
        assert d["va"] == "0x00001000"
        assert "byte_delta" not in d
        assert "difficulty" not in d
        assert "status" not in d

    def test_to_dict_with_optional_fields(self) -> None:
        item = TodoItem(
            category=CAT_FIX_DELTA,
            roi_score=90.0,
            va=0x1000,
            name="func",
            size=100,
            filename="a.c",
            description="",
            command="",
            byte_delta=2,
            difficulty=3,
            status="NEAR_MATCHING",
        )
        d = item.to_dict()
        assert d["byte_delta"] == 2
        assert d["difficulty"] == 3
        assert d["status"] == "NEAR_MATCHING"


# ---------------------------------------------------------------------------
# empty project / setup steps
# ---------------------------------------------------------------------------


class TestSetupSteps:
    def test_no_ghidra_json_no_funclist(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        (tmp_path / "src").mkdir()
        items = _collect_setup_steps(cfg, [], {})
        assert len(items) == 1
        assert "doctor" in items[0].command

    def test_no_ghidra_json_with_funclist(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "functions.txt").write_text("0x1000 func\n", encoding="utf-8")
        items = _collect_setup_steps(cfg, [], {})
        assert len(items) == 1
        assert "catalog" in items[0].command

    def test_ghidra_json_no_sources(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "function_structure.json").write_text("[]", encoding="utf-8")
        ghidra_funcs = [FunctionEntry(va=0x1000, size=100, name="f")]
        items = _collect_setup_steps(cfg, ghidra_funcs, {})
        assert len(items) == 2
        assert any("todo" in i.command for i in items)
        assert any("skeleton" in i.command for i in items)


class TestCollectAllIntegration:
    def test_fresh_project_shows_setup_and_start_functions(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "function_structure.json").write_text(
            json.dumps([{"va": 0x1000, "size": 100, "ghidra_name": "game_init"}]), encoding="utf-8"
        )
        ghidra_funcs = [FunctionEntry(va=0x1000, size=100, name="game_init")]
        items = collect_all(cfg, ghidra_funcs, {}, {})
        setup_items = [i for i in items if i.category == CAT_SETUP]
        start_items = [i for i in items if i.category == CAT_START_FUNCTION]
        assert len(setup_items) >= 1
        assert len(start_items) == 1
        assert items[0].category == CAT_SETUP
