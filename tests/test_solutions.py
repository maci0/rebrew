"""Tests for rebrew.matcher.solutions — cross-function solution transfer database."""

import json
from pathlib import Path

import pytest

from rebrew.matcher.solutions import (
    SolutionEntry,
    _normalize_cflags,
    find_similar,
    load_ga_runs,
    load_solutions,
    record_ga_run,
    save_solution,
)


@pytest.fixture()
def project_root(tmp_path: Path) -> Path:
    """Create a fake project root with .rebrew dir."""
    (tmp_path / ".rebrew").mkdir()
    return tmp_path


# -------------------------------------------------------------------------
# SolutionEntry
# -------------------------------------------------------------------------


class TestSolutionEntry:
    def test_basic_creation(self) -> None:
        e = SolutionEntry(
            symbol="_my_func",
            cflags="/O2 /Gd",
            size=128,
            source_file="src/game/func.c",
        )
        assert e.symbol == "_my_func"
        assert e.score == 0.0
        assert e.generations == 0

    def test_defaults(self) -> None:
        e = SolutionEntry(symbol="_f", cflags="/O2", size=10, source_file="f.c")
        assert isinstance(e.solved_at, str)
        assert len(e.solved_at) > 0
        assert e.score == 0.0
        assert e.generations == 0


# -------------------------------------------------------------------------
# load / save
# -------------------------------------------------------------------------


class TestLoadSave:
    def test_empty_returns_empty(self, project_root: Path) -> None:
        assert load_solutions(project_root) == []

    def test_save_and_load(self, project_root: Path) -> None:
        e = SolutionEntry(
            symbol="_func_a",
            cflags="/O2 /Gd",
            size=64,
            source_file="src/a.c",
            score=0.0,
        )
        save_solution(project_root, e)
        loaded = load_solutions(project_root)
        assert len(loaded) == 1
        assert loaded[0].symbol == "_func_a"
        assert loaded[0].cflags == "/O2 /Gd"

    def test_absolute_source_stored_root_relative(self, project_root: Path) -> None:
        abs_src = project_root / "src" / "a.c"
        abs_src.parent.mkdir(parents=True, exist_ok=True)
        abs_src.write_text("int f(void){return 0;}")
        save_solution(
            project_root,
            SolutionEntry(symbol="_f", cflags="/O2", size=8, source_file=str(abs_src)),
        )
        loaded = load_solutions(project_root)
        assert loaded[0].source_file == "src/a.c"
        # The reader resolves it as project_root / source_file.
        assert (project_root / loaded[0].source_file).exists()

    def test_source_outside_root_kept_absolute(self, tmp_path: Path, project_root: Path) -> None:
        outside = tmp_path.parent / "outside_b.c"  # sibling of the project root
        outside.write_text("int g(void){return 0;}")
        save_solution(
            project_root,
            SolutionEntry(symbol="_g", cflags="/O2", size=8, source_file=str(outside)),
        )
        assert Path(load_solutions(project_root)[0].source_file).is_absolute()

    def test_dedup_by_symbol(self, project_root: Path) -> None:
        e1 = SolutionEntry(
            symbol="_func_a",
            cflags="/O2 /Gd",
            size=64,
            source_file="src/a.c",
        )
        e2 = SolutionEntry(
            symbol="_func_a",
            cflags="/O1",
            size=64,
            source_file="src/a.c",
        )
        save_solution(project_root, e1)
        save_solution(project_root, e2)
        loaded = load_solutions(project_root)
        assert len(loaded) == 1
        assert loaded[0].cflags == "/O1"  # newer wins

    def test_multiple_symbols(self, project_root: Path) -> None:
        for sym in ["_a", "_b", "_c"]:
            save_solution(
                project_root,
                SolutionEntry(
                    symbol=sym,
                    cflags="/O2",
                    size=100,
                    source_file=f"{sym}.c",
                ),
            )
        loaded = load_solutions(project_root)
        assert len(loaded) == 3
        assert [e.symbol for e in loaded] == ["_a", "_b", "_c"]  # sorted

    def test_malformed_json_returns_empty(self, project_root: Path) -> None:
        p = project_root / ".rebrew" / "solutions.json"
        p.write_text("not json!", encoding="utf-8")
        assert load_solutions(project_root) == []

    def test_non_array_json_returns_empty(self, project_root: Path) -> None:
        p = project_root / ".rebrew" / "solutions.json"
        p.write_text('{"key": "value"}', encoding="utf-8")
        assert load_solutions(project_root) == []

    def test_extra_fields_ignored(self, project_root: Path) -> None:
        """Future-proofing: extra fields in JSON should be silently ignored."""
        p = project_root / ".rebrew" / "solutions.json"
        data = [
            {
                "symbol": "_f",
                "cflags": "/O2",
                "origin": "GAME",
                "size": 50,
                "source_file": "f.c",
                "score": 0.0,
                "solved_at": "2026-01-01T00:00:00Z",
                "generations": 10,
                "future_field": "should be ignored",
            }
        ]
        p.write_text(json.dumps(data), encoding="utf-8")
        loaded = load_solutions(project_root)
        assert len(loaded) == 1
        assert loaded[0].symbol == "_f"


# -------------------------------------------------------------------------
# find_similar
# -------------------------------------------------------------------------


class TestFindSimilar:
    def _seed_db(self, root: Path) -> None:
        """Seed the DB with a variety of solutions."""
        entries = [
            SolutionEntry("_small", "/O2 /Gd", 32, "small.c"),
            SolutionEntry("_medium", "/O2 /Gd", 128, "medium.c"),
            SolutionEntry("_large", "/O2 /Gd", 512, "large.c"),
            SolutionEntry("_crt_func", "/O1", 64, "crt.c"),
            SolutionEntry("_game_o1", "/O1", 100, "game_o1.c"),
        ]
        for e in entries:
            save_solution(root, e)

    def test_empty_db(self, project_root: Path) -> None:
        assert find_similar(project_root, 100) == []

    def test_sorts_by_size_distance(self, project_root: Path) -> None:
        self._seed_db(project_root)
        results = find_similar(project_root, 100, top_k=10)
        # _game_o1 (100B, dist 0) should be first, then _medium (128B, dist 28), then _crt_func (64B, dist 36)
        assert results[0].symbol == "_game_o1"

    def test_top_k_limits(self, project_root: Path) -> None:
        self._seed_db(project_root)
        results = find_similar(project_root, 100, top_k=2)
        assert len(results) == 2

    def test_cflags_tiebreak(self, project_root: Path) -> None:
        self._seed_db(project_root)
        # Both _game_o1 (100B, /O1) and _medium (128B, /O2 /Gd)
        # When querying with /O2 /Gd and size 114 (equidistant from 100 and 128):
        # 114-100=14 vs 128-114=14, but /O2 /Gd should break tie in favor of _medium
        results = find_similar(project_root, 114, cflags="/O2 /Gd")
        # Both are distance 14 from size 114, but _medium has matching cflags
        assert results[0].symbol == "_medium"

    def test_returns_all_when_below_top_k(self, project_root: Path) -> None:
        self._seed_db(project_root)
        results = find_similar(project_root, 100, top_k=100)
        assert len(results) == 5  # all 5 seeded entries


class TestNormalizeCflags:
    def test_strips_noise(self) -> None:
        assert _normalize_cflags("/nologo /c /O2 /Gd") == "/Gd /O2"

    def test_sorts(self) -> None:
        assert _normalize_cflags("/Gd /O2") == "/Gd /O2"

    def test_empty(self) -> None:
        assert _normalize_cflags("") == ""


class TestTargetScoping:
    """Multi-target: solutions dedupe by (target, symbol), not symbol alone."""

    def _entry(self, symbol: str, target: str = "", cflags: str = "/O2") -> SolutionEntry:
        return SolutionEntry(
            symbol=symbol,
            cflags=cflags,
            size=64,
            source_file=f"{symbol}.c",
            target=target,
        )

    def test_dedup_by_target_and_symbol(self, project_root: Path) -> None:
        save_solution(project_root, self._entry("_func_a", target="SERVER"))
        save_solution(project_root, self._entry("_func_a", target="CLIENT"))
        loaded = load_solutions(project_root)
        assert len(loaded) == 2
        assert {(e.target, e.symbol) for e in loaded} == {
            ("SERVER", "_func_a"),
            ("CLIENT", "_func_a"),
        }

    def test_same_target_same_symbol_replaced(self, project_root: Path) -> None:
        save_solution(project_root, self._entry("_func_a", target="SERVER", cflags="/O2"))
        save_solution(project_root, self._entry("_func_a", target="SERVER", cflags="/O1"))
        loaded = load_solutions(project_root)
        assert len(loaded) == 1
        assert loaded[0].cflags == "/O1"

    def test_legacy_entries_load_without_target(self, project_root: Path) -> None:
        """Old JSON without a 'target' field still loads (defaults to '')."""
        p = project_root / ".rebrew" / "solutions.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            '[{"symbol": "_old", "cflags": "/O2", "size": 16, "source_file": "old.c"}]\n',
            encoding="utf-8",
        )
        loaded = load_solutions(project_root)
        assert len(loaded) == 1
        assert loaded[0].target == ""
        assert loaded[0].symbol == "_old"

    def test_find_similar_prefers_same_target(self, project_root: Path) -> None:
        save_solution(project_root, self._entry("_a", target="CLIENT", cflags="/O2"))
        save_solution(project_root, self._entry("_b", target="SERVER", cflags="/O2"))
        result = find_similar(project_root, size=64, target="SERVER")
        assert result[0].target == "SERVER"
        assert result[0].symbol == "_b"

    def test_find_similar_without_target_keeps_legacy_order(self, project_root: Path) -> None:
        save_solution(project_root, self._entry("_a", target="", cflags="/O2"))
        save_solution(project_root, self._entry("_b", target="SERVER", cflags="/O2"))
        result = find_similar(project_root, size=64)
        # Unscoped query: legacy entries first (flag 0), then target-scoped.
        assert result[0].symbol == "_a"


class TestGaRunHistory:
    def test_record_appends(self, project_root: Path) -> None:
        record_ga_run(project_root, target="SERVER", va=0x1000, symbol="_a", matched=True)
        record_ga_run(project_root, target="SERVER", va=0x2000, symbol="_b", matched=False)
        runs = load_ga_runs(project_root)
        assert len(runs) == 2
        # Newest first
        assert runs[0]["symbol"] == "_b"
        assert runs[0]["matched"] is False
        assert runs[1]["symbol"] == "_a"

    def test_target_filter(self, project_root: Path) -> None:
        record_ga_run(project_root, target="SERVER", va=0x1000, symbol="_a", matched=True)
        record_ga_run(project_root, target="CLIENT", va=0x1000, symbol="_a", matched=False)
        runs = load_ga_runs(project_root, target="CLIENT")
        assert len(runs) == 1
        assert runs[0]["target"] == "CLIENT"

    def test_limit_and_missing_file(self, project_root: Path) -> None:
        assert load_ga_runs(project_root) == []
        for i in range(5):
            record_ga_run(project_root, target="S", va=0x1000 + i, symbol=f"_f{i}", matched=True)
        assert len(load_ga_runs(project_root, limit=2)) == 2

    def test_malformed_lines_skipped(self, project_root: Path) -> None:
        p = project_root / ".rebrew" / "ga_runs.jsonl"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('{"symbol": "ok"}\nnot-json\n[1, 2]\n', encoding="utf-8")
        runs = load_ga_runs(project_root)
        assert len(runs) == 1
        assert runs[0]["symbol"] == "ok"
