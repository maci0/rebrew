"""Tests for rebrew.solutions — cross-function solution transfer database."""

import json
from pathlib import Path

import pytest

from rebrew.solutions import (
    SolutionEntry,
    _normalize_cflags,
    find_similar,
    load_solutions,
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
            origin="GAME",
            size=128,
            source_file="src/game/func.c",
        )
        assert e.symbol == "_my_func"
        assert e.score == 0.0
        assert e.generations == 0

    def test_defaults(self) -> None:
        e = SolutionEntry(symbol="_f", cflags="/O2", origin="GAME", size=10, source_file="f.c")
        assert e.solved_at  # should have a timestamp


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
            origin="GAME",
            size=64,
            source_file="src/a.c",
            score=0.0,
        )
        save_solution(project_root, e)
        loaded = load_solutions(project_root)
        assert len(loaded) == 1
        assert loaded[0].symbol == "_func_a"
        assert loaded[0].cflags == "/O2 /Gd"

    def test_dedup_by_symbol(self, project_root: Path) -> None:
        e1 = SolutionEntry(
            symbol="_func_a",
            cflags="/O2 /Gd",
            origin="GAME",
            size=64,
            source_file="src/a.c",
        )
        e2 = SolutionEntry(
            symbol="_func_a",
            cflags="/O1",
            origin="GAME",
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
                    origin="GAME",
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
            SolutionEntry("_small", "/O2 /Gd", "GAME", 32, "small.c"),
            SolutionEntry("_medium", "/O2 /Gd", "GAME", 128, "medium.c"),
            SolutionEntry("_large", "/O2 /Gd", "GAME", 512, "large.c"),
            SolutionEntry("_crt_func", "/O1", "CRT", 64, "crt.c"),
            SolutionEntry("_game_o1", "/O1", "GAME", 100, "game_o1.c"),
        ]
        for e in entries:
            save_solution(root, e)

    def test_empty_db(self, project_root: Path) -> None:
        assert find_similar(project_root, "GAME", 100) == []

    def test_filters_by_origin(self, project_root: Path) -> None:
        self._seed_db(project_root)
        results = find_similar(project_root, "CRT", 64)
        assert all(r.origin == "CRT" for r in results)
        assert len(results) == 1

    def test_sorts_by_size_distance(self, project_root: Path) -> None:
        self._seed_db(project_root)
        results = find_similar(project_root, "GAME", 100, top_k=10)
        # _game_o1 (100B) should be first, then _medium (128B), etc.
        assert results[0].symbol == "_game_o1"
        assert results[1].symbol == "_medium"

    def test_top_k_limits(self, project_root: Path) -> None:
        self._seed_db(project_root)
        results = find_similar(project_root, "GAME", 100, top_k=2)
        assert len(results) == 2

    def test_cflags_tiebreak(self, project_root: Path) -> None:
        self._seed_db(project_root)
        # Both _game_o1 (100B, /O1) and _medium (128B, /O2 /Gd)
        # When querying with /O2 /Gd and size 114 (equidistant from 100 and 128):
        # 114-100=14 vs 128-114=14, but /O2 /Gd should break tie in favor of _medium
        results = find_similar(project_root, "GAME", 114, cflags="/O2 /Gd")
        # Both are distance 14 from size 114, but _medium has matching cflags
        assert results[0].symbol == "_medium"

    def test_no_origin_match(self, project_root: Path) -> None:
        self._seed_db(project_root)
        assert find_similar(project_root, "UNKNOWN", 100) == []


# -------------------------------------------------------------------------
# _normalize_cflags
# -------------------------------------------------------------------------


class TestNormalizeCflags:
    def test_strips_noise(self) -> None:
        assert _normalize_cflags("/nologo /c /O2 /Gd") == "/Gd /O2"

    def test_sorts(self) -> None:
        assert _normalize_cflags("/Gd /O2") == "/Gd /O2"

    def test_empty(self) -> None:
        assert _normalize_cflags("") == ""
