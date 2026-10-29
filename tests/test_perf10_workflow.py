"""Memoized type sizing and the single angr probe in todo (measured by tools/bench_perf10_workflow.py)."""

import random
from typing import Any

import pytest

from rebrew import prove
from rebrew.data_layout import estimate_type_size
from rebrew.metadata.functions import GA_CEILING_PREFIX
from rebrew.todo import (
    CAT_IMPROVE_MATCH,
    CAT_RUN_PROVER,
    _collect_active_functions,
    _rank_by_impact,
)
from tools import bench_perf10_workflow as bench

_TYPES = [
    "int",
    "unsigned int g;",
    "  char   buf [ 16 ] ",
    "void *",
    "char *[8]",
    "int [4]",
    "int [5]",
    "int [1 + 1]",
    "char (*)[4]",
    "int (*table[2])[3]",
    "struct Foo",
    "extern const short tbl[0x10]",
    "",
]


class TestEstimateTypeSizeMemo:
    @pytest.mark.parametrize("type_str", _TYPES)
    def test_matches_uncached_result(self, type_str: str) -> None:
        estimate_type_size.cache_clear()
        uncached = estimate_type_size.__wrapped__(type_str)
        assert estimate_type_size(type_str) == uncached
        assert estimate_type_size(type_str) == uncached

    def test_distinct_spellings_are_not_conflated(self) -> None:
        estimate_type_size.cache_clear()
        assert estimate_type_size("int [4]") == 16
        assert estimate_type_size("int [5]") == 20
        assert estimate_type_size("int [4]") == 16

    def test_repeat_is_served_from_the_memo(self) -> None:
        estimate_type_size.cache_clear()
        estimate_type_size("short [9]")
        estimate_type_size("short [9]")
        info = estimate_type_size.cache_info()
        assert (info.misses, info.hits) == (1, 1)


def _ga_rows(count: int) -> dict[int, dict[str, str]]:
    return {
        0x401000 + i * 0x10: {
            "status": "NEAR_MATCHING",
            "symbol": f"Func_{i}",
            "size": "64",
            "filename": "f.c",
            "blocker": f"{GA_CEILING_PREFIX} register-only delta",
        }
        for i in range(count)
    }


class TestProverProbe:
    @pytest.mark.parametrize(
        ("available", "category"), [(True, CAT_RUN_PROVER), (False, CAT_IMPROVE_MATCH)]
    )
    def test_probe_runs_once_for_many_rows(
        self, monkeypatch: pytest.MonkeyPatch, available: bool, category: str
    ) -> None:
        calls: list[None] = []

        def probe() -> bool:
            calls.append(None)
            return available

        monkeypatch.setattr(prove, "angr_available", probe)
        items = _collect_active_functions(_ga_rows(25), {}, {}, {})
        assert len(items) == 25
        assert {item.category for item in items} == {category}
        assert len(calls) == 1

    def test_probe_not_taken_without_ga_ceiling_rows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def probe() -> bool:
            raise AssertionError("angr probed without a GA ceiling row")

        monkeypatch.setattr(prove, "angr_available", probe)
        rows = _ga_rows(3)
        for row in rows.values():
            row["blocker"] = "2B diff"
        assert len(_collect_active_functions(rows, {}, {}, {})) == 3


class TestBenchmarkInputs:
    """The generators must exercise the kernels, or the benchmark times a no-op."""

    def test_todo_inputs_reach_every_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bench, "TODO_FUNCTIONS", 3000)
        monkeypatch.setattr(bench, "TODO_VERIFY_ONLY", 200)
        monkeypatch.setattr(prove, "angr_available", lambda: True)
        existing, sizes, names, verify, callees = bench._make_todo_inputs(random.Random(bench.SEED))
        ranked = _rank_by_impact(_collect_active_functions(existing, sizes, names, verify, callees))
        categories = {item.category for item in ranked}
        assert {
            "compile-error",
            "documented",
            "exact-only",
            "extract-error",
            "fix-delta",
            "improve-match",
            "missing-annotation",
            "naked-reconstruction",
            "run-prover",
        } <= categories
        assert any(item.affected_functions > 1 for item in ranked)
        assert any("declared by" in item.description for item in ranked)
        assert any(item.mutations for item in ranked)

    def test_data_inputs_reach_every_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.data_render import section_summary
        from rebrew.data_scan import enrich_with_sections, verify_bss_layout

        monkeypatch.setattr(bench, "DATA_GLOBALS", 2000)
        scan, sections = bench._make_scan(random.Random(bench.SEED + 1))
        enrich_with_sections(scan, sections)
        summary: list[dict[str, Any]] = section_summary(scan, sections)
        assert {row["name"] for row in summary} == {".data", ".rdata", ".bss", "unknown"}
        assert all(row["annotated_bytes"] > 0 for row in summary if row["name"] != "unknown")
        bss = verify_bss_layout(scan, sections)
        assert bss.known_entries
        assert bss.gaps
        assert len({g.type_str for g in scan.globals.values()}) > 50
