"""Tests for rebrew todo prioritized action dashboard."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.catalog import FunctionEntry
from rebrew.todo import (
    CAT_COMPILE_ERROR,
    CAT_DOCUMENTED,
    CAT_EXTRACT_ERROR,
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

    def test_active_functions_extract_error_not_fix_delta(self, tmp_path: Path) -> None:
        """An EXTRACT_ERROR entry (symbol not found in .obj) has delta=0 but
        must NOT be classified as a '0B diff' fix-delta quick-win — a flag
        sweep cannot fix a missing symbol.  Regression: guild-rebrew's
        EXTRACT_ERROR stubs showed up as fix-delta with ROI 85."""
        _cfg = _make_cfg(tmp_path)
        from rebrew.verify import VerifyCacheEntry, VerifyResult

        entries = {
            "0x00001000": VerifyCacheEntry(
                source_hash="",
                filepath="a.c",
                mtime_ns=0,
                result=VerifyResult(
                    status="EXTRACT_ERROR",
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
        assert items[0].category == CAT_EXTRACT_ERROR
        assert items[0].byte_delta is None  # no bytes extracted → no measured delta
        assert items[0].command == "rebrew test 0x00001000"
        assert "Symbol not found" in items[0].description

    def test_active_functions_missing_annotation(self) -> None:
        existing = {0x1000: {"status": "STUB", "symbol": "", "filename": "a.c"}}
        items = _collect_active_functions(existing, {0x1000: 50}, {}, {})
        assert len(items) == 1
        assert items[0].category == CAT_MISSING_ANNOTATION
        assert items[0].name == "FUN_00001000"

    def test_active_functions_missing_size_not_fix_delta(self) -> None:
        """A MISSING_SIZE verify result has a vacuous 0-byte delta (nothing
        extracted) — it must NOT appear as a '0B diff' fix-delta quick-win.
        Regression: smygb's intake-documented stubs showed as 0B-diff while
        rebrew test refused them with 'Invalid SIZE: 0'."""
        from rebrew.verify import VerifyCacheEntry, VerifyResult

        entries = {
            "0x00001000": VerifyCacheEntry(
                source_hash="",
                filepath="fcn_0040e44d.c",
                mtime_ns=0,
                result=VerifyResult(
                    status="MISSING_SIZE",
                    va=0x1000,
                    size=0,
                    filepath="fcn_0040e44d.c",
                    name="fcn_0040e44d",
                    message="MISSING_SIZE: No SIZE annotation",
                    passed=False,
                ),
            )
        }
        existing = {
            0x1000: {
                "status": "STUB",
                "symbol": "fcn_0040e44d",
                "blocker": "Application code — pending per-function decompilation",
            }
        }
        items = _collect_active_functions(existing, {0x1000: 235}, {}, entries)
        assert len(items) == 1
        assert items[0].category == CAT_MISSING_ANNOTATION
        assert items[0].byte_delta is None  # vacuous delta must not leak
        assert "verify --fix-sizes" in items[0].command
        assert "SIZE" in items[0].description

    def test_active_functions_fix_delta(self) -> None:
        existing = {0x1000: {"status": "NEAR_MATCHING", "symbol": "func_a", "blocker_delta": "3"}}
        items = _collect_active_functions(existing, {0x1000: 50}, {}, {})
        assert len(items) == 1
        assert items[0].category == CAT_FIX_DELTA
        assert items[0].byte_delta == 3

    def test_active_functions_iat_thunk_is_documented_not_fix_delta(self) -> None:
        """Regression: smygb's 6-byte IAT import thunk at 0x40dce0 was listed
        as a '5B diff — try flag sweep, GA' fix-delta quick-win even though its
        blocker already documents it as not a decomp target.  Such functions
        belong in the audit-only documented category, never in fix-delta."""
        existing = {
            0x40DCE0: {
                "status": "STUB",
                "symbol": "fcn_0040dce0",
                "blocker": "IAT import thunk / jump stub — not a decomp target",
                "size": "6",
            }
        }
        items = _collect_active_functions(existing, {0x40DCE0: 6}, {}, {})
        assert len(items) == 1
        assert items[0].category == CAT_DOCUMENTED
        assert items[0].roi_score < 0  # never outranks actionable work
        assert "not a decomp target" in items[0].description
        assert items[0].command == ""  # no suggested action

    def test_active_functions_delphi_blocker_is_documented(self) -> None:
        """Delphi application code is documented as non-reproducible — same
        audit-only treatment as IAT thunks."""
        existing = {
            0x2000: {
                "status": "STUB",
                "symbol": "fcn_00002000",
                "blocker": (
                    "Borland Delphi application code — Delphi ABI not reproducible "
                    "with rebrew compilers; documented"
                ),
                "size": "120",
            }
        }
        items = _collect_active_functions(existing, {0x2000: 120}, {}, {})
        assert len(items) == 1
        assert items[0].category == CAT_DOCUMENTED

    def test_active_functions_generic_blocker_still_actionable(self) -> None:
        """'Application code — pending per-function decompilation' is a real
        pending target, not a documented non-target — it stays actionable."""
        existing = {
            0x3000: {
                "status": "STUB",
                "symbol": "fcn_00003000",
                "blocker": "Application code — pending per-function decompilation",
            }
        }
        items = _collect_active_functions(existing, {0x3000: 100}, {}, {})
        assert len(items) == 1
        assert items[0].category != CAT_DOCUMENTED

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

    def test_active_functions_parses_mutations_from_blocker(self) -> None:
        """A near-diag-written blocker carries '— try: mut_a, ...'; todo must
        expose it as structured data and a terminal hint."""
        existing = {
            0x1000: {
                "status": "NEAR_MATCHING",
                "symbol": "func_a",
                "blocker": (
                    "NEAR_MATCHING — REGISTER (57% of delta) — try: "
                    "mut_swap_register_keywords, mut_add_register_keyword, mut_toggle_volatile"
                ),
            }
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
        assert items[0].mutations == [
            "mut_swap_register_keywords",
            "mut_add_register_keyword",
            "mut_toggle_volatile",
        ]
        assert "try: mut_swap_register_keywords" in items[0].description
        d = items[0].to_dict()
        assert d["mutations"] == items[0].mutations

    def test_active_functions_blocker_without_mutations(self) -> None:
        """A plain blocker (no '— try:' marker) yields an empty mutation list."""
        existing = {
            0x1000: {"status": "NEAR_MATCHING", "symbol": "func_a", "blocker": "register swap"}
        }
        items = _collect_active_functions(existing, {}, {}, {})
        assert len(items) == 1
        assert items[0].mutations == []
        assert "mutations" not in items[0].to_dict()

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


class TestTodoItemToDict:
    def test_full_dict(self) -> None:
        from rebrew.todo import TodoItem

        item = TodoItem(
            category="start-function",
            roi_score=42.0,
            va=0x1000,
            name="f",
            size=64,
            filename="f.c",
            description="d",
            command="rebrew test f.c",
            byte_delta=2,
            status="STUB",
            match_percent=50.0,
        )
        d = item.to_dict()
        assert d["category"] == "start-function"
        assert d["va"] == "0x00001000"
        assert d["status"] == "STUB"
        assert d["match_percent"] == 50.0
        assert d["roi_score"] == 42.0

    def test_minimal_dict(self) -> None:
        from rebrew.todo import TodoItem

        item = TodoItem(
            category="c",
            roi_score=1.0,
            va=0,
            name="",
            size=0,
            filename="",
            description="",
            command="",
        )
        d = item.to_dict()
        assert d["category"] == "c"
        assert "status" not in d
        assert "match_percent" not in d


class TestLoadVerifyEntries:
    def _cfg(self, tmp_path: Path) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(root=tmp_path)

    def test_missing_file(self, tmp_path: Path) -> None:
        from rebrew.todo import _load_verify_entries

        assert _load_verify_entries(self._cfg(tmp_path)) == {}

    def test_corrupt_file(self, tmp_path: Path) -> None:

        from rebrew.todo import _load_verify_entries

        d = tmp_path / ".rebrew"
        d.mkdir()
        (d / "verify_cache.json").write_text("{broken", encoding="utf-8")
        assert _load_verify_entries(self._cfg(tmp_path)) == {}

    def test_wrong_version(self, tmp_path: Path) -> None:
        import json

        from rebrew.todo import _load_verify_entries

        d = tmp_path / ".rebrew"
        d.mkdir()
        (d / "verify_cache.json").write_text(
            json.dumps({"version": 99, "entries": {}}), encoding="utf-8"
        )
        assert _load_verify_entries(self._cfg(tmp_path)) == {}


class TestCalculateRoiEdges:
    """Uncovered calculate_roi bands: size 500-1000 and >1000 penalties."""

    def test_size_500_to_1000_penalty(self) -> None:
        from rebrew.todo import calculate_roi

        # 400 gets +5 (size < 500 → 300-500 band... actually <300 → +5 at 299 max).
        # 600 gets -5; 400 gets +5 → 600 must score lower.
        assert calculate_roi(600, 0.0, None, "STUB") < calculate_roi(400, 0.0, None, "STUB")

    def test_size_over_1000_penalty(self) -> None:
        from rebrew.todo import calculate_roi

        # 1100 gets -15; 600 gets -5.
        assert calculate_roi(1100, 0.0, None, "STUB") < calculate_roi(600, 0.0, None, "STUB")


class TestSetupStepsExtended:
    def test_ghidra_json_without_funcs_returns_empty(self, tmp_path: Path) -> None:
        from rebrew.config import FUNCTION_STRUCTURE_JSON
        from rebrew.todo import _collect_setup_steps

        cfg = _make_cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True, exist_ok=True)
        (cfg.reversed_dir / FUNCTION_STRUCTURE_JSON).write_text("[]", encoding="utf-8")
        assert _collect_setup_steps(cfg, [], {}) == []

    def test_sources_never_verified(self, tmp_path: Path) -> None:
        from types import SimpleNamespace as SN

        from rebrew.config import FUNCTION_STRUCTURE_JSON
        from rebrew.todo import CAT_SETUP, _collect_setup_steps

        cfg = _make_cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True, exist_ok=True)
        (cfg.reversed_dir / FUNCTION_STRUCTURE_JSON).write_text("[]", encoding="utf-8")
        items = _collect_setup_steps(cfg, [SN(va=1)], {0x1: {"status": "STUB"}})
        assert any(i.category == CAT_SETUP and i.command == "rebrew verify" for i in items)


class TestActiveFunctionsEdges:
    def test_unparseable_verify_va_skipped(self) -> None:
        from types import SimpleNamespace as SN

        from rebrew.todo import _collect_active_functions

        # A non-numeric VA key raises ValueError on int() and is skipped.
        verify_entries = {
            "bogus": SN(result=SN(status="COMPILE_ERROR", match_percent=None, delta=None))
        }
        items = _collect_active_functions({}, {}, {}, verify_entries)  # type: ignore[arg-type]
        assert items == []

    def test_blocker_delta_non_numeric_falls_back_to_blocker(self) -> None:
        from rebrew.todo import _collect_active_functions

        existing = {
            0x1000: {
                "status": "NEAR_MATCHING",
                "symbol": "f",
                "size": "50",
                "blocker_delta": "abc",  # non-numeric → parse blocker text
                "blocker": "(12B diff) tail call",
            }
        }
        items = _collect_active_functions(existing, {}, {}, {})
        assert len(items) == 1
        assert items[0].byte_delta == 12

    def test_fix_delta_uses_flag_sweep_cmd(self) -> None:
        from rebrew.todo import _collect_active_functions

        # delta 12 (>4, <=20) → --flag-sweep-only command.
        existing = {
            0x1000: {
                "status": "NEAR_MATCHING",
                "symbol": "f",
                "size": "50",
                "blocker_delta": "12",
            }
        }
        items = _collect_active_functions(existing, {}, {}, {})
        assert len(items) == 1
        assert "flag-sweep-only" in items[0].command


class TestProverCandidatesWithAngr:
    def test_prover_candidates_full_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        from types import SimpleNamespace as SN

        from rebrew.todo import CAT_RUN_PROVER, _collect_prover_candidates

        monkeypatch.setitem(sys.modules, "angr", SN())
        existing = {
            0x1000: {"status": "NEAR_MATCHING", "symbol": "a", "size": "50"},
            0x2000: {"status": "STUB", "symbol": "b", "size": "50"},
            0x3000: {"status": "NEAR_MATCHING", "symbol": "c", "size": "600"},
            0x4000: {"status": "EXACT", "symbol": "d", "size": "50"},
        }
        verify_entries = {
            "0x00001000": SN(result=SN(status="NEAR_MATCHING", match_percent=97.0, delta=8))
        }
        size_by_va = {0x1000: 50, 0x2000: 50, 0x3000: 600, 0x4000: 50}
        items = _collect_prover_candidates(existing, size_by_va, verify_entries)  # type: ignore[arg-type]
        assert len(items) == 1
        assert items[0].va == 0x1000
        assert items[0].category == CAT_RUN_PROVER
        assert items[0].match_percent == 97.0
        assert items[0].byte_delta == 8


class TestLoadVerifyEntriesValid:
    def test_valid_cache_returns_entries(self, tmp_path: Path) -> None:
        import json

        from rebrew.todo import _load_verify_entries

        d = tmp_path / ".rebrew"
        d.mkdir()
        (d / "verify_cache.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": {
                        "0x1000": {
                            "source_hash": "abc",
                            "filepath": "f.c",
                            "mtime_ns": 1,
                            "result": {"status": "COMPILE_ERROR", "va": "0x1000"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        cfg = SimpleNamespace(root=tmp_path)
        entries = _load_verify_entries(cfg)  # type: ignore[arg-type]
        assert set(entries) == {"0x1000"}


class TestCollectNewFunctionsExtended:
    def _cfg_with_binary(self, tmp_path: Path) -> SimpleNamespace:
        cfg = _make_cfg(tmp_path)
        (tmp_path / "bin.exe").write_bytes(b"\x90" * 64)
        cfg.target_binary = tmp_path / "bin.exe"
        return cfg

    def test_binary_loaded_for_unmatchable_detection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace as SN

        from rebrew.todo import _collect_new_functions

        cfg = self._cfg_with_binary(tmp_path)
        # Fake BinaryInfo with no sections → extract_bytes_at_va returns None.
        monkeypatch.setattr(
            "rebrew.binary_loader.load_binary",
            lambda p: SN(sections={}, data=b"", image_base=0x1000, text_raw_offset=0),
        )
        ghidra_funcs = [FunctionEntry(va=0x1000, size=50, name="func_small")]
        items = _collect_new_functions(ghidra_funcs, {}, {}, cfg)
        assert len(items) == 1

    def test_unmatchable_reason_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.todo import _collect_new_functions

        cfg = self._cfg_with_binary(tmp_path)
        monkeypatch.setattr("rebrew.todo.detect_unmatchable", lambda *a, **k: "IAT thunk (config)")
        ghidra_funcs = [FunctionEntry(va=0x1000, size=50, name="func_small")]
        assert _collect_new_functions(ghidra_funcs, {}, {}, cfg) == []

    def test_tiny_function_skipped(self, tmp_path: Path) -> None:
        from rebrew.todo import _collect_new_functions

        cfg = self._cfg_with_binary(tmp_path)
        monkeypatch_tiny = pytest.MonkeyPatch()
        monkeypatch_tiny.setattr(
            "rebrew.binary_loader.load_binary",
            lambda p: SimpleNamespace(sections={}, data=b"", image_base=0x1000, text_raw_offset=0),
        )
        try:
            ghidra_funcs = [FunctionEntry(va=0x1000, size=5, name="tiny")]
            assert _collect_new_functions(ghidra_funcs, {}, {}, cfg) == []
        finally:
            monkeypatch_tiny.undo()

    def test_neighbor_file_append_command(self, tmp_path: Path) -> None:
        from rebrew.todo import _collect_new_functions

        cfg = self._cfg_with_binary(tmp_path)
        ghidra_funcs = [FunctionEntry(va=0x1000, size=50, name="func_small")]
        covered = {0x1050: "neighbor.c"}  # within 0x1000 max_gap
        items = _collect_new_functions(ghidra_funcs, {}, covered, cfg)
        assert len(items) == 1
        assert "neighbor.c" in items[0].command
        assert "--append" in items[0].command

    def test_fifty_item_cap(self, tmp_path: Path) -> None:
        from rebrew.todo import _collect_new_functions

        cfg = self._cfg_with_binary(tmp_path)
        ghidra_funcs = [
            FunctionEntry(va=0x1000 + i * 0x20, size=50, name=f"f{i}") for i in range(60)
        ]
        items = _collect_new_functions(ghidra_funcs, {}, {}, cfg)
        assert len(items) <= 50

    def test_library_existing_skipped(self, tmp_path: Path) -> None:
        from rebrew.todo import _collect_library_candidates

        func = SimpleNamespace(va=0x1000, size=50, name="x", module="MSVCRT")
        existing = {0x1000: {"status": "STUB"}}
        cfg = SimpleNamespace(library_modules={"MSVCRT"})
        items = _collect_library_candidates([func], existing, cfg)  # type: ignore[arg-type]
        assert items == []


class TestTodoCli:
    """CLI-level tests for todo.main() via CliRunner."""

    def _invoke(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        ghidra_funcs: list | None = None,
        existing: dict | None = None,
        covered_vas: dict | None = None,
        args: list[str] | None = None,
        load_raises: Exception | None = None,
    ) -> object:
        from typer.testing import CliRunner

        from rebrew.todo import app

        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.todo.require_config", lambda **kw: cfg)
        if load_raises is not None:

            def _boom(*_a: object, **_k: object) -> object:
                raise load_raises

            monkeypatch.setattr("rebrew.todo.load_data", _boom)
        else:
            monkeypatch.setattr(
                "rebrew.todo.load_data",
                lambda cfg: (ghidra_funcs or [], existing or {}, covered_vas or {}),
            )
        return CliRunner().invoke(app, args or [])

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        result = self._invoke(
            tmp_path,
            monkeypatch,
            ghidra_funcs=[FunctionEntry(va=0x1000, size=100, name="my_func")],
            existing={0x1000: {"status": "NEAR_MATCHING", "symbol": "my_func", "size": "100"}},
            covered_vas={0x1000: "my_func.c"},
            args=["--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["coverage"]["ghidra_funcs"] == 1
        assert data["coverage"]["matching"] == 1
        assert data["total_items"] >= 1
        assert any(i["va"] == "0x00001000" for i in data["items"])

    def test_stats_text(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._invoke(
            tmp_path,
            monkeypatch,
            ghidra_funcs=[FunctionEntry(va=0x1000, size=100, name="my_func")],
            existing={0x1000: {"status": "EXACT", "symbol": "my_func", "size": "100"}},
            covered_vas={0x1000: "my_func.c"},
            args=["--stats"],
        )
        assert result.exit_code == 0
        assert "Coverage" in result.output
        assert "EXACT: 1" in result.output

    def test_pct_matched_never_exceeds_100(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """pct_matched must divide by the COVERED population, not the Ghidra
        function list — library-header functions are covered but absent from
        function_structure.json, and the old math produced >100% (regression:
        guild-rebrew reported 240.6%)."""
        import json

        # Covered population (3) is larger than ghidra_funcs (1).
        existing = {
            0x1000: {"status": "EXACT", "symbol": "a", "size": "100"},
            0x2000: {"status": "RELOC", "symbol": "b", "size": "100"},
            0x3000: {"status": "STUB", "symbol": "c", "size": "100"},
        }
        covered_vas = {0x1000: "a.c", 0x2000: "b.c", 0x3000: "c.c"}
        result = self._invoke(
            tmp_path,
            monkeypatch,
            ghidra_funcs=[FunctionEntry(va=0x1000, size=100, name="a")],
            existing=existing,
            covered_vas=covered_vas,
            args=["--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        cov = data["coverage"]
        assert cov["covered"] == 3
        assert cov["exact"] == 1
        assert cov["reloc"] == 1
        assert cov["pct_matched"] == 66.7  # 2/3 matched, not 2/1 = 200%
        assert cov["pct_matched"] <= 100.0

    def test_category_filter(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        existing = {
            0x1000: {"status": "NEAR_MATCHING", "symbol": "a", "size": "50", "blocker_delta": "12"},
            0x2000: {"status": "STUB", "symbol": "b", "size": "50"},
        }
        result = self._invoke(
            tmp_path,
            monkeypatch,
            ghidra_funcs=[
                FunctionEntry(va=0x1000, size=50, name="a"),
                FunctionEntry(va=0x2000, size=50, name="b"),
            ],
            existing=existing,
            covered_vas={},
            args=["--json", "-c", "fix-delta"],
        )
        data = json.loads(result.output)
        assert data["total_items"] == 1
        assert data["items"][0]["category"] == "fix-delta"

    def test_no_items_message(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        # A fully-set-up project with only finished functions → zero action items.
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / FUNCTION_STRUCTURE_JSON).write_text("[]", encoding="utf-8")
        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        (cache_dir / "verify_cache.json").write_text(
            json.dumps({"version": 1, "entries": {}}), encoding="utf-8"
        )
        result = self._invoke(
            tmp_path,
            monkeypatch,
            ghidra_funcs=[FunctionEntry(va=0x1000, size=100, name="done")],
            existing={0x1000: {"status": "EXACT", "symbol": "done", "size": "100"}},
            covered_vas={0x1000: "done.c"},
            args=[],
        )
        assert result.exit_code == 0
        assert "No action items found" in result.output

    def test_load_failure_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._invoke(tmp_path, monkeypatch, load_raises=OSError("no project data"))
        assert result.exit_code != 0
        assert "Failed to load project data" in result.output

    def test_verify_statuses_overlay(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        cache_dir = tmp_path / ".rebrew"
        cache_dir.mkdir()
        (cache_dir / "verify_cache.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "target": "test",  # must match cfg.target_name (target guard)
                    "entries": {
                        "0x1000": {
                            "source_hash": "h",
                            "filepath": "f.c",
                            "mtime_ns": 1,
                            "result": {"status": "COMPILE_ERROR", "va": "0x1000"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        result = self._invoke(
            tmp_path,
            monkeypatch,
            ghidra_funcs=[FunctionEntry(va=0x1000, size=100, name="f")],
            existing={0x1000: {"status": "STUB", "symbol": "f", "size": "100"}},
            covered_vas={},
            args=["--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Verify-cache COMPILE_ERROR wins over annotation STUB in status counts.
        assert data["coverage"]["stub"] == 0


class TestProverCandidateFiltering:
    """run-prover must not suggest functions whose bytes are far apart — the
    prover would just exhaust its timeout."""

    def _existing(self, size: str) -> dict[int, dict[str, str]]:
        return {0x1000: {"status": "NEAR_MATCHING", "symbol": "a", "size": size}}

    def test_low_match_excluded(self) -> None:
        import sys
        from types import SimpleNamespace as SN

        from rebrew.todo import _collect_prover_candidates

        sys.modules["angr"] = SN()  # type: ignore[assignment]
        existing = self._existing("50")
        verify = {"0x00001000": SN(result=SN(status="NEAR_MATCHING", match_percent=65.0, delta=17))}
        items = _collect_prover_candidates(existing, {0x1000: 50}, verify)  # type: ignore[arg-type]
        assert items == []

    def test_metadata_size_preferred_over_ghidra(self) -> None:
        import sys
        from types import SimpleNamespace as SN

        from rebrew.todo import _collect_prover_candidates

        sys.modules["angr"] = SN()  # type: ignore[assignment]
        # Ghidra says 50, but metadata SIZE (600) is the real extent → skipped.
        existing = self._existing("600")
        items = _collect_prover_candidates(existing, {0x1000: 50}, {})  # type: ignore[arg-type]
        assert items == []

    def test_metadata_size_smaller_than_ghidra_kept(self) -> None:
        import sys
        from types import SimpleNamespace as SN

        from rebrew.todo import _collect_prover_candidates

        sys.modules["angr"] = SN()  # type: ignore[assignment]
        # Ghidra says 600, metadata says 50 → the real extent is small → kept.
        existing = self._existing("50")
        verify = {"0x00001000": SN(result=SN(status="NEAR_MATCHING", match_percent=96.0, delta=2))}
        items = _collect_prover_candidates(existing, {0x1000: 600}, verify)  # type: ignore[arg-type]
        assert len(items) == 1
        assert items[0].va == 0x1000

    def test_unmeasured_candidate_kept(self) -> None:
        import sys
        from types import SimpleNamespace as SN

        from rebrew.todo import _collect_prover_candidates

        sys.modules["angr"] = SN()  # type: ignore[assignment]
        # No verify cache → match_pct unknown → still eligible.
        existing = self._existing("50")
        items = _collect_prover_candidates(existing, {0x1000: 50}, {})  # type: ignore[arg-type]
        assert len(items) == 1
