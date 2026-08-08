"""Tests for rebrew.match — BinaryMatchingGA initialization and population logic."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.match import BinaryMatchingGA, StubInfo

# ---------------------------------------------------------------------------
# BinaryMatchingGA — init and population
# ---------------------------------------------------------------------------


def _make_ga(tmp_path: Path, **kwargs) -> BinaryMatchingGA:
    """Create a GA instance with minimal valid parameters."""
    defaults = {
        "seed_source": "int f(void) { return 0; }",
        "target_bytes": b"\x55\x8b\xec\xc3",
        "cl_cmd": "wine CL.EXE",
        "inc_dir": "/fake/include",
        "cflags": "/O2 /Gd",
        "symbol": "_f",
        "out_dir": tmp_path / "ga_out",
        "pop_size": 8,
        "num_generations": 2,
        "num_jobs": 1,
        "rng_seed": 42,
    }
    defaults.update(kwargs)
    return BinaryMatchingGA(**defaults)


class TestBinaryMatchingGAInit:
    """Tests for BinaryMatchingGA constructor and _init_population."""

    def test_population_size(self, tmp_path: Path) -> None:
        """Population is initialized to pop_size."""
        ga = _make_ga(tmp_path, pop_size=16)
        assert len(ga.population) == 16

    def test_seed_source_in_population(self, tmp_path: Path) -> None:
        """Seed source is always the first member of the population."""
        seed = "int original(void) { return 42; }"
        ga = _make_ga(tmp_path, seed_source=seed)
        assert ga.population[0] == seed

    def test_best_score_starts_infinite(self, tmp_path: Path) -> None:
        """Best score starts at infinity before any evaluation."""
        ga = _make_ga(tmp_path)
        assert ga.best_score == float("inf")

    def test_best_source_starts_none(self, tmp_path: Path) -> None:
        """Best source starts as None before any evaluation."""
        ga = _make_ga(tmp_path)
        assert ga.best_source is None

    def test_stagnant_gens_starts_zero(self, tmp_path: Path) -> None:
        """Stagnation counter starts at zero."""
        ga = _make_ga(tmp_path)
        assert ga.stagnant_gens == 0

    def test_deterministic_with_seed(self, tmp_path: Path) -> None:
        """Same RNG seed produces same initial population."""
        ga1 = _make_ga(tmp_path / "run1", rng_seed=123, pop_size=8)
        ga2 = _make_ga(tmp_path / "run2", rng_seed=123, pop_size=8)
        assert ga1.population == ga2.population

    def test_different_seeds_differ(self, tmp_path: Path) -> None:
        """Different RNG seeds produce different populations."""
        ga1 = _make_ga(tmp_path / "run1", rng_seed=1, pop_size=8)
        ga2 = _make_ga(tmp_path / "run2", rng_seed=2, pop_size=8)
        # Count how many non-seed members differ between the two populations
        differ_count = sum(
            1 for a, b in zip(ga1.population[1:], ga2.population[1:], strict=True) if a != b
        )
        # At least half the non-seed members should differ
        assert differ_count >= len(ga1.population[1:]) // 2, (
            f"Only {differ_count}/{len(ga1.population) - 1} members differ between seeds"
        )

    def test_cache_created(self, tmp_path: Path) -> None:
        """Build cache is initialized."""
        ga = _make_ga(tmp_path)
        assert ga.cache is not None

    def test_mutation_weights_default_empty(self, tmp_path: Path) -> None:
        """Default mutation weights are empty dict."""
        ga = _make_ga(tmp_path)
        assert ga.mutation_weights == {}

    def test_custom_mutation_weights(self, tmp_path: Path) -> None:
        """Custom mutation weights are preserved."""
        weights = {"commute_add": 2.0, "flip_comparison": 0.5}
        ga = _make_ga(tmp_path, mutation_weights=weights)
        assert ga.mutation_weights == weights

    def test_compare_obj_default_true(self, tmp_path: Path) -> None:
        """compare_obj defaults to True (OBJ-only mode)."""
        ga = _make_ga(tmp_path)
        assert ga.compare_obj is True

    def test_elitism_default(self, tmp_path: Path) -> None:
        """Default elitism is 4."""
        ga = _make_ga(tmp_path)
        assert ga.elitism == 4

    def test_stagnation_limit_default(self, tmp_path: Path) -> None:
        """Default stagnation limit is 40."""
        ga = _make_ga(tmp_path)
        assert ga.stagnation_limit == 40

    def test_env_stored(self, tmp_path: Path) -> None:
        """Custom env dict is stored."""
        env = {"WINEDEBUG": "-all", "LIB": "/fake/lib"}
        ga = _make_ga(tmp_path, env=env)
        assert ga.env == env

    def test_output_dir_created(self, tmp_path: Path) -> None:
        """Output directory path is stored as Path."""
        ga = _make_ga(tmp_path)
        assert isinstance(ga.out_dir, Path)


# ---------------------------------------------------------------------------
# _compute_fitness edge cases
# ---------------------------------------------------------------------------


class TestComputeFitness:
    """Tests for _compute_fitness logic without actually compiling."""

    def test_failed_build_returns_high_score(self, tmp_path: Path) -> None:
        """Failed build result should return a very high penalty score."""
        from rebrew.matcher import BuildResult

        ga = _make_ga(tmp_path)
        res = BuildResult(ok=False, error_msg="compiler not found")
        score = ga._compute_fitness(res, "test_hash", "int f() { return 0; }")
        assert score == 10000000.0

    def test_none_obj_bytes_returns_high_score(self, tmp_path: Path) -> None:
        """Build result with ok=True but no obj_bytes returns high score."""
        from rebrew.matcher import BuildResult

        ga = _make_ga(tmp_path)
        res = BuildResult(ok=True, obj_bytes=None)
        score = ga._compute_fitness(res, "test_hash", "int f() { return 0; }")
        assert score == 10000000.0


# ---------------------------------------------------------------------------
# Batch orchestration (_run_all): discovery, filtering, dry-run, execution
# ---------------------------------------------------------------------------


class TestRunAllBatch:
    """The batch driver: discovery filtering, dry-run JSON, GA execution with
    per-run persistence, and error isolation (one bad stub must not abort)."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            reversed_dir=tmp_path / "src" / "T",
            root=tmp_path,
            target_name="T",
            ignored_symbols=[],
            metadata_dir=tmp_path,
            image_base=0x10000000,
            dll_exports={},
            target_binary=tmp_path / "test.dll",
            function_list="",
            all_targets=["T"],
        )

    def _stub(self, name: str, va: str = "0x10001000", size: int = 100) -> StubInfo:
        return StubInfo(
            filepath=Path(name),
            va=va,
            size=size,
            symbol=name,
            cflags="/O2",
            status="STUB",
            module="T",
        )

    def _run(
        self,
        cfg: SimpleNamespace,
        *,
        dry_run: bool = False,
        json_output: bool = False,
        min_size: int = 0,
        max_size: int = 9999,
        filter_str: str = "",
        max_stubs: int = 0,
        skip_recent_hours: int = 0,
        jobs: int = 1,
        seed_from_solved: bool = False,
        sweep_then_ga: bool = False,
        flag_sweep: bool = False,
    ) -> tuple[int, int]:
        from rebrew.match import _run_all

        return _run_all(
            cfg,
            jobs=jobs,
            generations=5,
            pop_size=4,
            timeout_min=1,
            dry_run=dry_run,
            min_size=min_size,
            max_size=max_size,
            filter_str=filter_str,
            near_miss=False,
            improve=False,
            threshold=10,
            flag_sweep=flag_sweep,
            fix_cflags=False,
            max_stubs=max_stubs,
            seed_from_solved=seed_from_solved,
            json_output=json_output,
            tier="targeted",
            sweep_then_ga=sweep_then_ga,
            skip_recent_hours=skip_recent_hours,
        )

    def test_dry_run_json_lists_stubs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        stubs = [self._stub("a.c"), self._stub("b.c", "0x10001010", 200)]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        out = self._run(self._cfg(tmp_path), dry_run=True, json_output=True)
        assert out == (0, 0)

    def test_size_and_string_filters(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        import json

        stubs = [
            self._stub("a.c", "0x10001000", 50),
            self._stub("b.c", "0x10001010", 200),
            self._stub("c.c", "0x10001020", 300),
        ]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        cfg = self._cfg(tmp_path)
        # min_size + filter_str + max_stubs compose.
        self._run(cfg, dry_run=True, json_output=True, min_size=100, filter_str="b.c")
        data = json.loads(capsys.readouterr().out)
        # Only b.c (200B) survives both filters.
        assert data["count"] == 1
        assert data["items"][0]["symbol"] == "b.c"

    def test_skip_recent_filters(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

        stubs = [self._stub("a.c"), self._stub("b.c")]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        monkeypatch.setattr("rebrew.match._filter_recently_run", lambda s, cfg, hours, j: [s[1]])
        out = self._run(self._cfg(tmp_path), dry_run=True, json_output=True, skip_recent_hours=24)
        assert out == (0, 0)

    def test_ga_run_persists_result(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

        stubs = [self._stub("a.c")]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        calls: list[tuple] = []

        def _fake_ga(stub, cfg, gens, pop, jobs, timeout, seeds, cflags_override=None):
            return True, "MATCHED"

        def _fake_record(root, *, target, va, symbol, matched):
            calls.append((str(root), target, va, symbol, matched))

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_ga)
        monkeypatch.setattr("rebrew.matcher.solutions.record_ga_run", _fake_record)
        matched, failed = self._run(self._cfg(tmp_path), json_output=True)
        assert (matched, failed) == (1, 0)
        assert calls == [(str(tmp_path), "T", "0x10001000", "a.c", True)]

    def test_failed_stub_does_not_abort_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        stubs = [self._stub("bad.c"), self._stub("good.c", "0x10001010")]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)

        def _fake_ga(stub, cfg, gens, pop, jobs, timeout, seeds, cflags_override=None):
            if "bad" in stub.symbol:
                raise RuntimeError("boom")
            return True, "MATCHED"

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_ga)
        matched, failed = self._run(self._cfg(tmp_path), json_output=True)
        assert (matched, failed) == (1, 1)

    def test_parallel_path_matches_serial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        stubs = [self._stub(f"f{i}.c", f"0x1000{i:04x}") for i in range(1, 4)]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        monkeypatch.setattr(
            "rebrew.match._run_one_stub_ga",
            lambda stub, cfg, gens, pop, jobs, timeout, seeds, cflags_override=None: (
                True,
                "MATCHED",
            ),
        )
        matched, failed = self._run(self._cfg(tmp_path), jobs=2, json_output=True)
        assert (matched, failed) == (3, 0)
