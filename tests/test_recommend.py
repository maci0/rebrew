"""Tests for :mod:`rebrew.recommend` — TU layout advice."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

from rebrew.recommend import (
    FIXABLE_LINT,
    flag_conflicts,
    recommend_backfill_blockers,
    recommend_build_check,
    recommend_cluster_fill,
    recommend_data_drift,
    recommend_default_names,
    recommend_duplicate_globals,
    recommend_fix_sizes,
    recommend_flag_split,
    recommend_foreign_sources,
    recommend_layout,
    recommend_link_order,
    recommend_lint_errors,
    recommend_lint_fixable,
    recommend_matched_orphans,
    recommend_merge_sweep_hint,
    recommend_missing_externs,
    recommend_next_action,
    recommend_orphans,
    recommend_shared_twins,
    recommend_stale_cache,
    recommend_stale_markers,
    recommend_start_data,
    recommend_stub_sort,
    recommend_verify_failures,
)


def _cluster(cid: int, vas: list[int], conf: float = 0.9) -> SimpleNamespace:
    return SimpleNamespace(
        cluster_id=cid, functions=list(vas), confidence=conf, evidence=["all gaps are padding"]
    )


class TestMerge:
    def test_split_cluster_across_files_recommends_merge(self) -> None:
        recs = recommend_layout(
            [_cluster(0, [0x1000, 0x1100, 0x1200, 0x1300])],
            {0x1000: "a.c", 0x1100: "a.c", 0x1200: "b.c", 0x1300: "b.c"},
        )
        assert len(recs) == 1
        assert recs[0].kind == "merge"
        assert recs[0].files == ["a.c", "b.c"]
        assert "rebrew merge" in recs[0].command

    def test_single_file_cluster_is_silent(self) -> None:
        recs = recommend_layout(
            [_cluster(0, [0x1000, 0x1100])],
            {0x1000: "a.c", 0x1100: "a.c"},
        )
        assert recs == []

    def test_low_confidence_cluster_skipped(self) -> None:
        recs = recommend_layout(
            [_cluster(0, [0x1000, 0x1100], conf=0.3)],
            {0x1000: "a.c", 0x1100: "b.c"},
            min_confidence=0.8,
        )
        assert recs == []


class TestMove:
    def test_one_stray_function_recommends_move(self) -> None:
        recs = recommend_layout(
            [_cluster(3, [0x1000, 0x1100, 0x1200])],
            {0x1000: "a.c", 0x1100: "a.c", 0x1200: "b.c"},
        )
        assert len(recs) == 1
        assert recs[0].kind == "move"
        assert recs[0].functions == [0x1200]


class TestSplit:
    def test_file_spanning_clusters_recommends_split(self) -> None:
        recs = recommend_layout(
            [_cluster(0, [0x1000]), _cluster(1, [0x2000])],
            {0x1000: "a.c", 0x2000: "a.c"},
        )
        kinds = [r.kind for r in recs]
        assert "split" in kinds

    def test_merged_file_not_also_split(self) -> None:
        recs = recommend_layout(
            [_cluster(0, [0x1000, 0x1100, 0x1200])],
            {0x1000: "a.c", 0x1100: "b.c", 0x1200: "b.c"},
        )
        assert all(r.kind != "split" for r in recs)


class TestFlagConflicts:
    def test_divergent_cflags_flagged_and_command_cleared(self) -> None:
        recs = recommend_layout(
            [_cluster(0, [0x1000, 0x1100])],
            {0x1000: "a.c", 0x1100: "b.c"},
        )
        assert recs and recs[0].kind == "move"
        recs = recommend_layout(
            [_cluster(0, [0x1000, 0x1100, 0x1200, 0x1300])],
            {0x1000: "a.c", 0x1100: "a.c", 0x1200: "b.c", 0x1300: "b.c"},
        )
        assert recs and recs[0].kind == "merge"
        flag_conflicts(recs, {0x1000: "/O1", 0x1100: "/O1", 0x1200: "/O2", 0x1300: "/O2"})
        assert "CFLAGS" in " ".join(recs[0].evidence)
        assert recs[0].command == ""

    def test_matching_cflags_keep_command(self) -> None:
        recs = recommend_layout(
            [_cluster(0, [0x1000, 0x1100, 0x1200, 0x1300])],
            {0x1000: "a.c", 0x1100: "a.c", 0x1200: "b.c", 0x1300: "b.c"},
        )
        flag_conflicts(recs, {})
        assert recs[0].command.startswith("rebrew merge")


class TestHygieneLanes:
    def test_link_order_silent_when_in_order(self) -> None:
        assert recommend_link_order(["a.c", "b.c"], ["a.c", "b.c"]) is None

    def test_link_order_fires_on_drift(self) -> None:
        rec = recommend_link_order(["b.c", "a.c"], ["a.c", "b.c"])
        assert rec is not None
        assert rec.kind == "link-order"
        assert rec.applyable
        assert rec.command == "rebrew link-order --apply"

    def test_orphans_empty_is_silent(self) -> None:
        assert recommend_orphans([]) is None

    def test_orphans_lists_prunable(self) -> None:
        rec = recommend_orphans([{"module": "m", "va": "0x1000"}])
        assert rec is not None
        assert rec.command == "rebrew orphans --prune"
        assert rec.applyable

    def test_lint_only_fixable_codes_fire(self) -> None:
        assert recommend_lint_fixable([("a.c", "W024")]) is None
        rec = recommend_lint_fixable([("a.c", "W019"), ("b.c", "W024")])
        assert rec is not None
        assert rec.command == "rebrew lint --fix"
        assert rec.files == ["a.c"]
        assert {"W019", "W029", "W016"} == FIXABLE_LINT

    def test_shared_twins_one_rec_per_group(self) -> None:
        recs = recommend_shared_twins([["b.c", "a.c"]])
        assert len(recs) == 1
        assert recs[0].files == ["a.c", "b.c"]
        assert "--shared" in recs[0].command
        assert recs[0].applyable

    def test_next_action_empty_is_silent(self) -> None:
        assert recommend_next_action("", "") is None

    def test_next_action_points_at_todo_command(self) -> None:
        rec = recommend_next_action("rebrew test 0x1000", "fix-delta: 4B diff")
        assert rec is not None
        assert rec.kind == "next-action"
        assert rec.command == "rebrew test 0x1000"

    def test_merge_sweep_hint_needs_unproven_clusters(self) -> None:
        assert recommend_merge_sweep_hint(0) is None
        assert recommend_merge_sweep_hint(1) is None
        rec = recommend_merge_sweep_hint(2)
        assert rec is not None
        assert rec.command == "rebrew merge-sweep --dry-run"


class TestRound1Lanes:
    def test_flag_split_silent_when_uniform(self) -> None:
        recs = recommend_flag_split(
            {0x1000: "a.c", 0x1100: "a.c"},
            {0x1000: ("", "/O1"), 0x1100: ("", "/O1")},
        )
        assert recs == []

    def test_flag_split_fires_on_mixed_flags(self) -> None:
        recs = recommend_flag_split(
            {0x1000: "a.c", 0x1100: "a.c"},
            {0x1000: ("", "/O1"), 0x1100: ("", "/O2")},
        )
        assert len(recs) == 1
        assert recs[0].kind == "flag-split"
        assert recs[0].files == ["a.c"]
        assert recs[0].command == "rebrew split a.c"

    def test_flag_split_ignores_functions_without_overrides(self) -> None:
        recs = recommend_flag_split({0x1000: "a.c"}, {})
        assert recs == []

    def test_fix_sizes_silent_when_sized(self) -> None:
        assert recommend_fix_sizes({0x1000: 64}) is None

    def test_fix_sizes_lists_unsized(self) -> None:
        rec = recommend_fix_sizes({0x1000: 0, 0x1100: 32})
        assert rec is not None
        assert rec.kind == "fix-sizes"
        assert rec.functions == [0x1000]
        assert rec.command == "rebrew verify --fix-sizes"

    def test_lint_errors_grouped_per_file(self) -> None:
        recs = recommend_lint_errors(
            [("a.c", "E013", "dup"), ("a.c", "E002", "va"), ("b.c", "E001", "marker")]
        )
        assert [r.files for r in recs] == [["a.c"], ["b.c"]]
        assert all(r.kind == "lint-errors" for r in recs)
        assert recs[0].command == "rebrew lint a.c"

    def test_lint_errors_empty_is_silent(self) -> None:
        assert recommend_lint_errors([]) == []

    def test_foreign_sources_empty_is_silent(self) -> None:
        assert recommend_foreign_sources([], "game") is None

    def test_foreign_sources_names_excluded_files(self) -> None:
        rec = recommend_foreign_sources(["other/tu.c"], "game")
        assert rec is not None
        assert rec.kind == "foreign-sources"
        assert rec.files == ["other/tu.c"]


class TestRound2Lanes:
    def test_cluster_fill_points_at_neighbor_file(self) -> None:
        recs = recommend_cluster_fill(
            [_cluster(0, [0x1000, 0x1100, 0x1200])],
            {0x1000: "a.c", 0x1100: "a.c"},
            {0x1000, 0x1100, 0x1200},
        )
        assert len(recs) == 1
        assert recs[0].kind == "cluster-fill"
        assert recs[0].functions == [0x1200]
        assert "rebrew skeleton 0x00001100" not in recs[0].command
        assert "0x00001200 --append a.c" in recs[0].command

    def test_cluster_fill_silent_when_fully_reversed(self) -> None:
        recs = recommend_cluster_fill(
            [_cluster(0, [0x1000, 0x1100])],
            {0x1000: "a.c", 0x1100: "a.c"},
            {0x1000, 0x1100},
        )
        assert recs == []

    def test_cluster_fill_ignores_non_inventory_vas(self) -> None:
        recs = recommend_cluster_fill(
            [_cluster(0, [0x1000, 0x9999])],
            {0x1000: "a.c"},
            {0x1000},
        )
        assert recs == []

    def test_matched_orphans_flag_reattach_not_prune(self) -> None:
        recs = recommend_matched_orphans(
            [{"module": "m", "va": "0x1000", "store": "rebrew-functions.toml", "status": "EXACT"}]
        )
        assert len(recs) == 1
        assert recs[0].kind == "matched-orphans"
        assert "never --include-matched" in recs[0].command

    def test_matched_orphans_silent_for_prunable(self) -> None:
        assert recommend_matched_orphans([{"module": "m", "va": "0x1", "status": "STUB"}]) == []

    def test_data_drift_points_at_verify_data(self) -> None:
        rec = recommend_data_drift([("m", 0x2000, "g_flag")])
        assert rec is not None
        assert rec.kind == "data-drift"
        assert rec.command == "rebrew verify --data"

    def test_data_drift_empty_is_silent(self) -> None:
        assert recommend_data_drift([]) is None

    def test_stub_sort_silent_when_covered(self) -> None:
        assert recommend_stub_sort([0x1000], {0x1000}) is None

    def test_stub_sort_lists_unannotated(self) -> None:
        rec = recommend_stub_sort([0x1000, 0x1100], {0x1000})
        assert rec is not None
        assert rec.functions == [0x1100]

    def test_build_check_points_at_command(self) -> None:
        rec = recommend_build_check([{"obj": "a.obj", "flag": "/O2"}])
        assert rec is not None
        assert rec.command == "rebrew build-check"

    def test_build_check_empty_is_silent(self) -> None:
        assert recommend_build_check([]) is None


class TestRound3Lanes:
    def test_verify_failures_surface_actionable_statuses(self) -> None:
        from types import SimpleNamespace as NS

        recs = recommend_verify_failures(
            {
                "0x00001000": NS(status="COMPILE_ERROR"),
                "0x00001100": NS(status="EXTRACT_ERROR"),
                "0x00001200": NS(status="MISSING_SIZE"),
                "0x00001300": NS(status="EXACT"),
                "0x00001400": NS(status="NEAR_MATCHING"),
            }
        )
        assert [r.command for r in recs] == [
            "rebrew test 0x00001000",
            "rebrew test 0x00001100",
            "rebrew verify --fix-sizes",
        ]
        assert all(r.kind == "verify-failures" for r in recs)

    def test_verify_failures_skips_bad_keys(self) -> None:
        from types import SimpleNamespace as NS

        assert recommend_verify_failures({"nope": NS(status="COMPILE_ERROR")}) == []
        assert recommend_verify_failures({}) == []

    def test_missing_externs_points_at_skeleton(self) -> None:
        recs = recommend_missing_externs(
            [("a.c", "helper"), ("b.c", "helper"), ("a.c", "known")],
            {"known", "_known"},
        )
        assert len(recs) == 1
        assert recs[0].command == "rebrew skeleton <va> --name helper"
        assert "2 file(s)" in recs[0].evidence[0]

    def test_missing_externs_silent_when_defined(self) -> None:
        assert recommend_missing_externs([("a.c", "helper")], {"helper", "_helper"}) == []

    def test_default_names_flagged(self) -> None:
        recs = recommend_default_names([(0x1000, "FUN_00001000"), (0x1100, "real_name")])
        assert len(recs) == 1
        assert recs[0].kind == "default-names"
        assert recs[0].functions == [0x1000]

    def test_default_names_silent_when_named(self) -> None:
        assert recommend_default_names([(0x1000, "real_name")]) == []

    def test_stale_cache_fires_when_sources_newer(self) -> None:
        rec = recommend_stale_cache(100.0, 200.0)
        assert rec is not None
        assert rec.command == "rebrew verify"

    def test_stale_cache_silent_when_fresh(self) -> None:
        assert recommend_stale_cache(200.0, 100.0) is None
        assert recommend_stale_cache(100.0, 100.0) is None


class TestRound4Lanes:
    def test_duplicate_globals_groups_files(self) -> None:
        recs = recommend_duplicate_globals([("a.c", "g_x"), ("b.c", "g_x"), ("a.c", "g_y")])
        assert len(recs) == 1
        assert recs[0].files == ["a.c", "b.c"]
        assert "g_x" in recs[0].evidence[0]

    def test_duplicate_globals_silent_when_unique(self) -> None:
        assert recommend_duplicate_globals([("a.c", "g_x")]) == []

    def test_stale_markers_groups_per_file(self) -> None:
        recs = recommend_stale_markers([("a.c", "0x1000"), ("a.c", "0x1100")])
        assert len(recs) == 1
        assert recs[0].command == "rebrew lint a.c"

    def test_stale_markers_empty_is_silent(self) -> None:
        assert recommend_stale_markers([]) == []

    def test_start_data_lists_unchecked(self) -> None:
        rec = recommend_start_data([("m", 0x2000, "g_a"), ("m", 0x2004, "g_b")])
        assert rec is not None
        assert rec.command == "rebrew verify --data"
        assert rec.functions == [0x2000, 0x2004]

    def test_start_data_empty_is_silent(self) -> None:
        assert recommend_start_data([]) is None

    def test_backfill_blockers_counts_bare_stubs(self) -> None:
        rec = recommend_backfill_blockers(3)
        assert rec is not None
        assert rec.command == "rebrew document-unmatched --backfill-blockers"

    def test_backfill_blockers_zero_is_silent(self) -> None:
        assert recommend_backfill_blockers(0) is None


class TestLaneIsolation:
    def test_failing_lane_is_logged_not_raised(
        self, tmp_path: Any, monkeypatch: Any, caplog: Any
    ) -> None:
        import rebrew.recommend as rec

        def _boom(_pairs: Any) -> list[Any]:
            raise RuntimeError("boom")

        monkeypatch.setattr(rec, "recommend_default_names", _boom)
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=tmp_path, metadata_dir=tmp_path, target_name="t"
        )
        with caplog.at_level(logging.WARNING, logger="rebrew.recommend"):
            recs = rec._collect_hygiene(cfg, set(), {0x1000: "FUN_00001000"})
        assert "default-names lane failed" in caplog.text
        assert "boom" in caplog.text
        assert isinstance(recs, list)
