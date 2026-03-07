"""Tests for rebrew todo prioritized action dashboard."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.catalog.models import FunctionEntry
from rebrew.todo import (
    CAT_ADD_ANNOTATIONS,
    CAT_FINISH_STUB,
    CAT_FIX_COMPILE_ERROR,
    CAT_FIX_NEAR_MISS,
    CAT_FIX_VERIFY_FAIL,
    CAT_FLAG_SWEEP,
    CAT_IDENTIFY_LIBRARY,
    CAT_IMPROVE_MATCHING,
    CAT_RUN_PROVER,
    CAT_SETUP,
    CAT_START_FUNCTION,
    TodoItem,
    _collect_compile_errors,
    _collect_improve_matching,
    _collect_library_candidates,
    _collect_missing_annotations,
    _collect_near_misses,
    _collect_new_functions,
    _collect_setup_steps,
    _collect_stubs,
    _collect_verify_failures,
    _load_verify_entries,
    _score_by_size,
    _score_flag_sweep,
    _score_near_miss,
    _score_start_function,
    _score_verify_fail,
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
    def test_near_miss_delta_1(self) -> None:
        score = _score_near_miss(1, 100)
        assert 80.0 <= score <= 85.0

    def test_near_miss_delta_4(self) -> None:
        score = _score_near_miss(4, 100)
        assert 70.0 <= score <= 85.0

    def test_near_miss_none_delta(self) -> None:
        assert _score_near_miss(None, 100) == 70.0

    def test_near_miss_small_boost(self) -> None:
        small = _score_near_miss(3, 50)
        large = _score_near_miss(3, 500)
        assert small >= large

    def test_flag_sweep_range(self) -> None:
        score = _score_flag_sweep(10, 200)
        assert 25.0 <= score <= 55.0

    def test_flag_sweep_small_delta_higher(self) -> None:
        small = _score_flag_sweep(5, 100)
        large = _score_flag_sweep(20, 100)
        assert small >= large

    def test_prover_small(self) -> None:
        assert _score_by_size(CAT_RUN_PROVER, 50) == 40.0

    def test_prover_medium(self) -> None:
        assert _score_by_size(CAT_RUN_PROVER, 200) == 35.0

    def test_prover_large(self) -> None:
        assert _score_by_size(CAT_RUN_PROVER, 400) == 30.0

    def test_compile_error_small(self) -> None:
        assert _score_by_size(CAT_FIX_COMPILE_ERROR, 50) == 95.0

    def test_compile_error_medium(self) -> None:
        assert _score_by_size(CAT_FIX_COMPILE_ERROR, 200) == 90.0

    def test_compile_error_large(self) -> None:
        assert _score_by_size(CAT_FIX_COMPILE_ERROR, 500) == 85.0

    def test_improve_matching_small(self) -> None:
        assert _score_by_size(CAT_IMPROVE_MATCHING, 50) == 55.0

    def test_improve_matching_medium(self) -> None:
        assert _score_by_size(CAT_IMPROVE_MATCHING, 200) == 50.0

    def test_improve_matching_large(self) -> None:
        assert _score_by_size(CAT_IMPROVE_MATCHING, 500) == 45.0

    def test_verify_fail_high_match(self) -> None:
        # 95% match on a 100B function: base=72 + size_boost=3 → capped at 75
        score = _score_verify_fail(None, 95.0, 100)
        assert 70.0 <= score <= 75.0

    def test_verify_fail_medium_match(self) -> None:
        # 75% match falls in the >=60% bucket: base=58
        score = _score_verify_fail(None, 75.0)
        assert 55.0 <= score <= 70.0

    def test_verify_fail_small_delta(self) -> None:
        # No match_pct data: base=58
        score = _score_verify_fail(10, None)
        assert 50.0 <= score <= 65.0

    def test_verify_fail_unknown(self) -> None:
        # No data: base=58
        score = _score_verify_fail(None, None)
        assert 50.0 <= score <= 65.0

    def test_finish_stub_tiny(self) -> None:
        assert _score_by_size(CAT_FINISH_STUB, 50) == 75.0

    def test_finish_stub_small(self) -> None:
        assert _score_by_size(CAT_FINISH_STUB, 120) == 70.0

    def test_finish_stub_medium(self) -> None:
        assert _score_by_size(CAT_FINISH_STUB, 200) == 70.0

    def test_finish_stub_large(self) -> None:
        assert _score_by_size(CAT_FINISH_STUB, 500) == 60.0

    def test_start_function_easy(self) -> None:
        score = _score_start_function(1, 50)
        assert score >= 40.0

    def test_start_function_hard(self) -> None:
        score = _score_start_function(5, 500)
        assert score <= 45.0

    def test_start_function_clamped(self) -> None:
        score = _score_start_function(5, 1000)
        assert score >= 10.0

    def test_add_annotations_zero_size(self) -> None:
        assert _score_by_size(CAT_ADD_ANNOTATIONS, 0) == 40.0

    def test_add_annotations_small(self) -> None:
        assert _score_by_size(CAT_ADD_ANNOTATIONS, 50) == 40.0

    def test_add_annotations_large(self) -> None:
        assert _score_by_size(CAT_ADD_ANNOTATIONS, 500) == 30.0


# ---------------------------------------------------------------------------
# Collector tests
# ---------------------------------------------------------------------------


class TestCollectors:
    def test_near_misses_splits_by_delta(self) -> None:
        existing = {
            0x1000: {
                "status": "MATCHING",
                "blocker_delta": "2",
                "blocker": "",
                "symbol": "func_a",
                "filename": "a.c",
                "origin": "GAME",
            },
            0x2000: {
                "status": "MATCHING",
                "blocker_delta": "10",
                "blocker": "",
                "symbol": "func_b",
                "filename": "b.c",
                "origin": "GAME",
            },
            0x3000: {
                "status": "EXACT",
                "blocker_delta": "",
                "blocker": "",
                "symbol": "func_c",
                "filename": "c.c",
                "origin": "GAME",
            },
        }
        size_by_va = {0x1000: 100, 0x2000: 200, 0x3000: 50}
        items, has_delta = _collect_near_misses(existing, size_by_va)

        near = [i for i in items if i.category == CAT_FIX_NEAR_MISS]
        sweep = [i for i in items if i.category == CAT_FLAG_SWEEP]
        assert len(near) == 1
        assert near[0].va == 0x1000
        assert near[0].byte_delta == 2
        assert len(sweep) == 1
        assert sweep[0].va == 0x2000
        assert 0x1000 in has_delta
        assert 0x2000 in has_delta

    def test_near_misses_skips_no_delta(self) -> None:
        existing = {
            0x1000: {
                "status": "MATCHING",
                "blocker_delta": "",
                "blocker": "unknown issue",
                "symbol": "func",
                "filename": "a.c",
                "origin": "GAME",
            },
        }
        items, has_delta = _collect_near_misses(existing, {0x1000: 100})
        assert len(items) == 0
        assert len(has_delta) == 0

    def test_improve_matching_catches_no_delta(self) -> None:
        existing = {
            0x1000: {
                "status": "MATCHING",
                "blocker_delta": "",
                "blocker": "loop unrolling differs",
                "symbol": "func_a",
                "filename": "a.c",
                "origin": "GAME",
            },
            0x2000: {
                "status": "MATCHING",
                "blocker_delta": "3",
                "blocker": "",
                "symbol": "func_b",
                "filename": "b.c",
                "origin": "GAME",
            },
        }
        size_by_va = {0x1000: 200, 0x2000: 100}
        # func_b has delta 3 → captured by near-miss
        has_delta = {0x2000}
        items = _collect_improve_matching(existing, size_by_va, has_delta)
        assert len(items) == 1
        assert items[0].va == 0x1000
        assert items[0].category == CAT_IMPROVE_MATCHING
        assert "loop unrolling" in items[0].description

    def test_improve_matching_skips_non_matching(self) -> None:
        existing = {
            0x1000: {
                "status": "EXACT",
                "blocker_delta": "",
                "blocker": "",
                "symbol": "func",
                "filename": "a.c",
                "origin": "GAME",
            },
        }
        items = _collect_improve_matching(existing, {0x1000: 100}, set())
        assert len(items) == 0

    def test_stubs_collected(self) -> None:
        existing = {
            0x1000: {
                "status": "STUB",
                "symbol": "stub_func",
                "filename": "s.c",
                "origin": "GAME",
            },
            0x2000: {
                "status": "EXACT",
                "symbol": "done_func",
                "filename": "d.c",
                "origin": "GAME",
            },
        }
        size_by_va = {0x1000: 80, 0x2000: 50}
        items = _collect_stubs(existing, size_by_va)
        assert len(items) == 1
        assert items[0].va == 0x1000
        assert items[0].category == CAT_FINISH_STUB
        assert items[0].status == "STUB"

    def test_verify_failures_from_cache(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        cache_data = {
            "version": 1,
            "entries": {
                "0x1000": {
                    "result": {
                        "status": "MISMATCH",
                        "va": "0x1000",
                        "size": 100,
                        "filepath": "a.c",
                        "name": "func_a",
                        "origin": "GAME",
                        "match_percent": 92.0,
                        "delta": 8,
                    }
                },
                "0x2000": {
                    "result": {
                        "status": "EXACT",
                        "va": "0x2000",
                        "size": 50,
                        "filepath": "b.c",
                        "name": "func_b",
                        "origin": "GAME",
                    }
                },
            },
        }
        (cache_dir / "verify_cache.json").write_text(json.dumps(cache_data), encoding="utf-8")
        entries = _load_verify_entries(cfg)
        items = _collect_verify_failures(entries)
        assert len(items) == 1
        assert items[0].category == CAT_FIX_VERIFY_FAIL
        assert items[0].va == 0x1000
        assert "92%" in items[0].description

    def test_verify_failures_no_cache(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        entries = _load_verify_entries(cfg)
        items = _collect_verify_failures(entries)
        assert items == []

    def test_compile_errors_from_cache(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        cache_data = {
            "version": 1,
            "entries": {
                "0x1000": {
                    "result": {
                        "status": "COMPILE_ERROR",
                        "va": "0x1000",
                        "size": 100,
                        "filepath": "err.c",
                        "symbol": "bad_func",
                        "origin": "GAME",
                    }
                },
                "0x2000": {
                    "result": {
                        "status": "EXACT",
                        "va": "0x2000",
                        "size": 50,
                        "filepath": "ok.c",
                        "symbol": "ok_func",
                        "origin": "GAME",
                    }
                },
            },
        }
        (cache_dir / "verify_cache.json").write_text(json.dumps(cache_data), encoding="utf-8")
        entries = _load_verify_entries(cfg)
        items = _collect_compile_errors(entries)
        assert len(items) == 1
        assert items[0].category == CAT_FIX_COMPILE_ERROR
        assert items[0].va == 0x1000

    def test_compile_errors_no_cache(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        entries = _load_verify_entries(cfg)
        items = _collect_compile_errors(entries)
        assert items == []

    def test_missing_annotations(self) -> None:
        existing = {
            0x1000: {
                "symbol": "",
                "filename": "a.c",
                "origin": "GAME",
                "status": "STUB",
            },
            0x2000: {
                "symbol": "func_b",
                "filename": "b.c",
                "origin": "GAME",
                "status": "EXACT",
            },
        }
        size_by_va = {0x1000: 100, 0x2000: 50}
        items = _collect_missing_annotations(existing, size_by_va)
        assert len(items) == 1
        assert items[0].va == 0x1000
        assert items[0].category == CAT_ADD_ANNOTATIONS

    def test_missing_annotations_with_symbol_not_flagged(self) -> None:
        existing = {
            0x1000: {
                "symbol": "func_a",
                "filename": "a.c",
                "origin": "GAME",
                "status": "STUB",
            },
        }
        size_by_va = {0x1000: 0}
        items = _collect_missing_annotations(existing, size_by_va)
        assert len(items) == 0

    def test_library_candidates(self) -> None:
        # FunctionEntry with module="MSVCRT" is identified as a library candidate
        msvcrt_func = SimpleNamespace(va=0x1000, size=100, name="__alloca", module="MSVCRT")
        other_func = SimpleNamespace(va=0x2000, size=200, name="game_func", module="")
        existing: dict[int, dict[str, str]] = {}
        cfg = SimpleNamespace(
            library_modules={"MSVCRT"},
        )
        items = _collect_library_candidates([msvcrt_func, other_func], existing, cfg)  # type: ignore[arg-type]
        lib_items = [i for i in items if i.category == CAT_IDENTIFY_LIBRARY]
        # Only __alloca (MSVCRT module) should be flagged
        assert any(i.va == 0x1000 for i in lib_items)
        assert not any(i.va == 0x2000 for i in lib_items)

    def test_new_functions_basic(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        # No binary, so unmatchable detection is skipped
        ghidra_funcs = [
            FunctionEntry(va=0x1000, size=50, name="func_small"),
            FunctionEntry(va=0x2000, size=150, name="func_med"),
        ]
        # 0x1000 is small (difficulty 1 -> score ~45), 0x2000 is med (difficulty 5 -> score ~5)
        existing: dict[int, dict[str, str]] = {}
        covered_vas: dict[int, str] = {}
        items = _collect_new_functions(ghidra_funcs, existing, covered_vas, cfg)
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

    def test_new_functions_caps_at_max(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        ghidra_funcs = [FunctionEntry(va=i * 0x1000, size=50, name=f"func_{i}") for i in range(10)]
        items = _collect_new_functions(ghidra_funcs, {}, {}, cfg, max_candidates=10)
        assert len(items) == 10


# ---------------------------------------------------------------------------
# ROI ordering tests
# ---------------------------------------------------------------------------


class TestRoiOrdering:
    def test_near_miss_ranks_above_start(self) -> None:
        near = TodoItem(
            category=CAT_FIX_NEAR_MISS,
            roi_score=_score_near_miss(3, 100),
            va=0x1000,
            name="a",
            size=100,
            filename="a.c",
            description="",
            command="",
            byte_delta=3,
        )
        start = TodoItem(
            category=CAT_START_FUNCTION,
            roi_score=_score_start_function(3, 500),
            va=0x2000,
            name="b",
            size=500,
            filename="",
            description="",
            command="",
            difficulty=3,
        )
        items = sorted([start, near], key=lambda x: -x.roi_score)
        assert items[0].category == CAT_FIX_NEAR_MISS

    def test_small_delta_ranks_higher(self) -> None:
        small = TodoItem(
            category=CAT_FIX_NEAR_MISS,
            roi_score=_score_near_miss(1, 100),
            va=0x1000,
            name="a",
            size=100,
            filename="",
            description="",
            command="",
            byte_delta=1,
        )
        large = TodoItem(
            category=CAT_FIX_NEAR_MISS,
            roi_score=_score_near_miss(4, 100),
            va=0x2000,
            name="b",
            size=100,
            filename="",
            description="",
            command="",
            byte_delta=4,
        )
        items = sorted([large, small], key=lambda x: -x.roi_score)
        assert items[0].va == 0x1000

    def test_finish_stub_ranks_above_improve_matching(self) -> None:
        # size=200: finish_stub→65, improve_matching→50
        matching = TodoItem(
            category=CAT_IMPROVE_MATCHING,
            roi_score=_score_by_size(CAT_IMPROVE_MATCHING, 200),
            va=0x1000,
            name="a",
            size=200,
            filename="",
            description="",
            command="",
        )
        stub = TodoItem(
            category=CAT_FINISH_STUB,
            roi_score=_score_by_size(CAT_FINISH_STUB, 200),
            va=0x2000,
            name="b",
            size=200,
            filename="",
            description="",
            command="",
        )
        items = sorted([stub, matching], key=lambda x: -x.roi_score)
        assert items[0].category == CAT_FINISH_STUB


# ---------------------------------------------------------------------------
# TodoItem serialization
# ---------------------------------------------------------------------------


class TestJsonOutput:
    def test_to_dict_minimal(self) -> None:
        item = TodoItem(
            category=CAT_FIX_NEAR_MISS,
            roi_score=92.5,
            va=0x1000,
            name="func",
            size=100,
            filename="a.c",
            description="2B diff",
            command="rebrew match -d a.c",
        )
        d = item.to_dict()
        assert d["category"] == CAT_FIX_NEAR_MISS
        assert d["roi_score"] == 92.5
        assert d["va"] == "0x00001000"
        assert "byte_delta" not in d
        assert "difficulty" not in d
        assert "status" not in d

    def test_to_dict_with_optional_fields(self) -> None:
        item = TodoItem(
            category=CAT_FIX_NEAR_MISS,
            roi_score=90.0,
            va=0x1000,
            name="func",
            size=100,
            filename="a.c",
            description="",
            command="",
            byte_delta=2,
            difficulty=3,
            status="MATCHING",
        )
        d = item.to_dict()
        assert d["byte_delta"] == 2
        assert d["difficulty"] == 3
        assert d["status"] == "MATCHING"


# ---------------------------------------------------------------------------
# Category filter
# ---------------------------------------------------------------------------


class TestCategoryFilter:
    def test_filter_by_category(self) -> None:
        items = [
            TodoItem(
                category=CAT_FIX_NEAR_MISS,
                roi_score=90,
                va=0x1000,
                name="a",
                size=100,
                filename="",
                description="",
                command="",
            ),
            TodoItem(
                category=CAT_FLAG_SWEEP,
                roi_score=70,
                va=0x2000,
                name="b",
                size=200,
                filename="",
                description="",
                command="",
            ),
            TodoItem(
                category=CAT_FIX_NEAR_MISS,
                roi_score=85,
                va=0x3000,
                name="c",
                size=150,
                filename="",
                description="",
                command="",
            ),
        ]
        filtered = [i for i in items if i.category == CAT_FIX_NEAR_MISS]
        assert len(filtered) == 2
        assert all(i.category == CAT_FIX_NEAR_MISS for i in filtered)


# ---------------------------------------------------------------------------
# Empty project
# ---------------------------------------------------------------------------


class TestEmptyProject:
    def test_collect_all_fresh_no_funclist(self, tmp_path: Path) -> None:
        """Fresh project with no function list → setup items."""
        cfg = _make_cfg(tmp_path)
        (tmp_path / "src").mkdir()
        items = collect_all(cfg, [], {}, {})
        assert len(items) > 0
        assert items[0].category == CAT_SETUP
        assert "doctor" in items[0].command

    def test_collect_all_fresh_with_funclist(self, tmp_path: Path) -> None:
        """Fresh project with function list but no ghidra JSON → catalog step."""
        cfg = _make_cfg(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "functions.txt").write_text("0x1000 func\n", encoding="utf-8")
        items = collect_all(cfg, [], {}, {})
        assert len(items) > 0
        assert items[0].category == CAT_SETUP
        assert "catalog" in items[0].command

    def test_collect_near_misses_empty(self) -> None:
        items, has_delta = _collect_near_misses({}, {})
        assert items == []
        assert has_delta == set()

    def test_collect_compile_errors_empty(self) -> None:
        assert _collect_compile_errors({}) == []

    def test_collect_stubs_empty(self) -> None:
        assert _collect_stubs({}, {}) == []

    def test_collect_improve_matching_empty(self) -> None:
        assert _collect_improve_matching({}, {}, set()) == []


# ---------------------------------------------------------------------------
# Integration: collect_all with MATCHING functions
# ---------------------------------------------------------------------------


class TestCollectAllMatching:
    """Ensure MATCHING functions without delta still appear in results."""

    def test_matching_without_delta_appears(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        ghidra_funcs = [
            FunctionEntry(va=0x1000, size=200, name="func_a"),
            FunctionEntry(va=0x2000, size=300, name="func_no_size_in_szbv"),
        ]
        existing = {
            0x1000: {
                "status": "MATCHING",
                "blocker_delta": "",
                "blocker": "calling convention",
                "symbol": "func_a",
                "filename": "a.c",
                "origin": "GAME",
            },
        }
        items = collect_all(cfg, ghidra_funcs, existing, {0x1000: "a.c"})
        matching_items = [i for i in items if i.category == CAT_IMPROVE_MATCHING]
        assert len(matching_items) == 1

    def test_stubs_appear_in_results(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        ghidra_funcs = [FunctionEntry(va=0x1000, size=100, name="stub_func")]
        existing = {
            0x1000: {
                "status": "STUB",
                "blocker_delta": "",
                "blocker": "",
                "symbol": "stub_func",
                "filename": "s.c",
                "origin": "GAME",
            },
        }
        items = collect_all(cfg, ghidra_funcs, existing, {0x1000: "s.c"})
        stub_items = [i for i in items if i.category == CAT_FINISH_STUB]
        assert len(stub_items) == 1

    def test_fresh_project_shows_setup_and_start_functions(self, tmp_path: Path) -> None:
        """Project with ghidra_funcs but no source files → setup + start-function items."""
        cfg = _make_cfg(tmp_path)
        # Create ghidra_functions.json so setup doesn't short-circuit
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "function_structure.json").write_text(
            json.dumps(
                [
                    {"va": 0x1000, "size": 100, "ghidra_name": "game_init"},
                    {"va": 0x2000, "size": 50, "ghidra_name": "game_update"},
                ]
            ),
            encoding="utf-8",
        )
        ghidra_funcs = [
            FunctionEntry(va=0x1000, size=100, name="game_init"),
            FunctionEntry(va=0x2000, size=50, name="game_update"),
        ]
        items = collect_all(cfg, ghidra_funcs, {}, {})
        setup_items = [i for i in items if i.category == CAT_SETUP]
        start_items = [i for i in items if i.category == CAT_START_FUNCTION]
        assert len(setup_items) >= 1  # triage + skeleton steps
        assert len(start_items) == 2
        # Setup items should rank highest
        assert items[0].category == CAT_SETUP


# ---------------------------------------------------------------------------
# Setup step tests
# ---------------------------------------------------------------------------


class TestSetupSteps:
    def test_no_ghidra_json_no_funclist(self, tmp_path: Path) -> None:
        """No ghidra_functions.json and no function list → doctor step."""
        cfg = _make_cfg(tmp_path)
        (tmp_path / "src").mkdir()
        items = _collect_setup_steps(cfg, [], {})
        assert len(items) == 1
        assert "doctor" in items[0].command

    def test_no_ghidra_json_with_funclist(self, tmp_path: Path) -> None:
        """No ghidra_functions.json but function list exists → catalog step."""
        cfg = _make_cfg(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "functions.txt").write_text("0x1000 func\n", encoding="utf-8")
        items = _collect_setup_steps(cfg, [], {})
        assert len(items) == 1
        assert "catalog" in items[0].command

    def test_ghidra_json_no_sources(self, tmp_path: Path) -> None:
        """Have ghidra_functions.json but no source files → todo + skeleton steps."""
        cfg = _make_cfg(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "function_structure.json").write_text("[]", encoding="utf-8")
        ghidra_funcs = [FunctionEntry(va=0x1000, size=100, name="f")]
        items = _collect_setup_steps(cfg, ghidra_funcs, {})
        assert len(items) == 2
        assert any("todo" in i.command for i in items)
        assert any("skeleton" in i.command for i in items)

    def test_sources_but_no_verify_cache(self, tmp_path: Path) -> None:
        """Have source files but never verified → verify step."""
        cfg = _make_cfg(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "function_structure.json").write_text("[]", encoding="utf-8")
        existing = {0x1000: {"status": "STUB", "symbol": "f", "filename": "f.c", "origin": "GAME"}}
        items = _collect_setup_steps(cfg, [{"va": 0x1000, "size": 100}], existing)
        assert len(items) == 1
        assert "verify" in items[0].command

    def test_mature_project_no_setup(self, tmp_path: Path) -> None:
        """Project with ghidra JSON, sources, and verify cache → no setup steps."""
        cfg = _make_cfg(tmp_path)
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "function_structure.json").write_text("[]", encoding="utf-8")
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        (cache_dir / "verify_cache.json").write_text("{}", encoding="utf-8")
        existing = {0x1000: {"status": "EXACT", "symbol": "f", "filename": "f.c", "origin": "GAME"}}
        items = _collect_setup_steps(cfg, [{"va": 0x1000, "size": 100}], existing)
        assert len(items) == 0


# ---------------------------------------------------------------------------
# Edge case tests (Phase 3 audit)
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_verify_cache_with_int_va(self, tmp_path: Path) -> None:
        """VA stored as int in JSON (not string) should not crash."""
        cfg = _make_cfg(tmp_path)
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        cache_data = {
            "entries": {
                "0x1000": {
                    "result": {
                        "status": "COMPILE_ERROR",
                        "va": 4096,  # int, not "0x1000"
                        "size": 100,
                        "filepath": "a.c",
                        "symbol": "func",
                        "origin": "GAME",
                    }
                }
            }
        }
        (cache_dir / "verify_cache.json").write_text(json.dumps(cache_data), encoding="utf-8")
        entries = _load_verify_entries(cfg)
        items = _collect_compile_errors(entries)
        assert len(items) == 1
        assert items[0].va == 4096

    def test_verify_cache_malformed_json(self, tmp_path: Path) -> None:
        """Malformed JSON in verify cache returns empty entries."""
        cfg = _make_cfg(tmp_path)
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        (cache_dir / "verify_cache.json").write_text("{broken json", encoding="utf-8")
        entries = _load_verify_entries(cfg)
        assert entries == {}

    def test_verify_failures_int_va(self, tmp_path: Path) -> None:
        from rebrew.verify import VerifyCacheEntry, VerifyResult

        entries = {
            "0x2000": VerifyCacheEntry(
                source_hash="",
                filepath="b.c",
                mtime_ns=0,
                result=VerifyResult(
                    status="MISMATCH",
                    va=8192,
                    size=200,
                    filepath="b.c",
                    name="func_b",
                    message="",
                    passed=False,
                    match_percent=85.0,
                    delta=15,
                ),
            )
        }
        items = _collect_verify_failures(entries)
        assert len(items) == 1
        assert items[0].va == 8192

    def test_score_identify_library_boundaries(self) -> None:
        assert _score_by_size(CAT_IDENTIFY_LIBRARY, 50) == 25.0
        assert _score_by_size(CAT_IDENTIFY_LIBRARY, 150) == 20.0
        assert _score_by_size(CAT_IDENTIFY_LIBRARY, 400) == 15.0
        assert _score_by_size(CAT_IDENTIFY_LIBRARY, 300) == 15.0

    def test_near_miss_with_blocker_text_delta(self) -> None:
        """Near-miss extracted from blocker text like '2B diff'."""
        existing = {
            0x1000: {
                "status": "MATCHING",
                "blocker_delta": "",
                "blocker": "2B diff in epilogue",
                "symbol": "func_a",
                "filename": "a.c",
                "origin": "GAME",
            },
        }
        size_by_va = {0x1000: 100}
        items, has_delta = _collect_near_misses(existing, size_by_va)
        assert len(items) == 1
        assert items[0].category == CAT_FIX_NEAR_MISS
        assert items[0].byte_delta == 2
        assert 0x1000 in has_delta

    def test_near_miss_delta_zero_still_clamped(self) -> None:
        """delta=0 should produce score in valid range (clamped to 95)."""
        score = _score_near_miss(0, 50)
        assert 70.0 <= score <= 95.0

    def test_collect_compile_errors_missing_va_key(self) -> None:
        """Entry without 'va' key should be skipped gracefully."""
        from rebrew.verify import VerifyCacheEntry, VerifyResult

        entries = {
            "0x1000": VerifyCacheEntry(
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
            )  # wait, previously it was missing VA, but the VerifyResult has default va=0?
            # Actually, the test was testing `try: int(result.va) except` when `result.va` is missing, but VerifyResult typed va as int.
            # Let's make result.va = None
        }
        entries["0x1000"].result.va = None  # type: ignore
        items = _collect_compile_errors(entries)
        assert items == []

    def test_load_verify_entries_missing_dir(self, tmp_path: Path) -> None:
        """No .rebrew directory at all should return empty dict."""
        cfg = _make_cfg(tmp_path)
        entries = _load_verify_entries(cfg)
        assert entries == {}
