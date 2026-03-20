"""Tests for rebrew.match — BinaryMatchingGA initialization and population logic."""

from pathlib import Path

from rebrew.match import BinaryMatchingGA

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
