"""Tests for batch GA checkpoint/resume (H4)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from rebrew.match_ga import BinaryMatchingGA, _ga_args_hash, read_ga_checkpoint
from rebrew.matcher.core import BuildResult, GACheckpoint

_SOURCE = "int f(void) { return 0; }"
_TARGET = b"\x55\x8b\xec\x5d\xc3"


def _make_ga(
    tmp_path: Path, *, resume_from: GACheckpoint | None = None, seed: int = 1
) -> BinaryMatchingGA:
    return BinaryMatchingGA(
        _SOURCE,
        _TARGET,
        "cl",
        "/tmp/inc",
        "/O2",
        "_f",
        tmp_path / "out",
        pop_size=4,
        num_generations=5,
        num_jobs=1,
        rng_seed=seed,
        resume_from=resume_from,
    )


class TestGACheckpointData:
    def test_roundtrip(self) -> None:
        ckpt = GACheckpoint(
            generation=3,
            best_score=1.5,
            best_source="int f(void){return 1;}",
            population=["a", "b"],
            rng_state=(3, (1, 2, 3), None),
            args_hash="h",
        )
        restored = GACheckpoint.from_dict(ckpt.to_dict())
        assert restored.generation == 3
        assert restored.best_score == 1.5
        assert restored.population == ["a", "b"]
        assert restored.rng_state == (3, (1, 2, 3), None)

    def test_args_hash_stable(self) -> None:
        h1 = _ga_args_hash(_SOURCE, _TARGET, "_f", "/O2", 4, 5, 1)
        h2 = _ga_args_hash(_SOURCE, _TARGET, "_f", "/O2", 4, 5, 1)
        h3 = _ga_args_hash(_SOURCE, _TARGET, "_f", "/O1", 4, 5, 1)
        assert h1 == h2
        assert h1 != h3  # cflags change invalidates

    def test_args_hash_canonical_over_weight_order(self) -> None:
        """Equal mutation_weights built in different insertion orders must
        hash identically — the old str(dict) encoding inherited insertion
        order, so a resume rejected a checkpoint from the same logical run."""
        w1 = {"mut_a": 6.0, "mut_b": 1.0}
        w2 = {"mut_b": 1.0, "mut_a": 6.0}
        assert w1 == w2  # same mapping, different order
        h1 = _ga_args_hash(_SOURCE, _TARGET, "_f", "/O2", 4, 5, 1, mutation_weights=w1)
        h2 = _ga_args_hash(_SOURCE, _TARGET, "_f", "/O2", 4, 5, 1, mutation_weights=w2)
        assert h1 == h2
        h3 = _ga_args_hash(_SOURCE, _TARGET, "_f", "/O2", 4, 5, 1, mutation_weights={"mut_a": 1.0})
        assert h1 != h3  # different weights still invalidate


class TestCheckpointIO:
    def test_save_and_read(self, tmp_path: Path) -> None:
        ga = _make_ga(tmp_path)
        ga._save_checkpoint(2)
        ckpt_path = tmp_path / "out" / "checkpoints" / "_f.json"
        assert ckpt_path.is_file()
        loaded = read_ga_checkpoint(tmp_path / "out", "_f")
        assert loaded is not None
        assert loaded.generation == 2

    def test_missing_checkpoint_returns_none(self, tmp_path: Path) -> None:
        assert read_ga_checkpoint(tmp_path / "out", "_nope") is None

    def test_corrupt_checkpoint_returns_none(self, tmp_path: Path, caplog) -> None:
        """A truncated/corrupt checkpoint must not raise — but it must warn,
        because resume silently restarts from scratch (prior generations lost)."""
        import logging

        ckpt_dir = tmp_path / "out" / "checkpoints"
        ckpt_dir.mkdir(parents=True)
        (ckpt_dir / "_f.json").write_text('{"generation": 3, "trunc', encoding="utf-8")
        with caplog.at_level(logging.WARNING, logger="rebrew.match"):
            loaded = read_ga_checkpoint(tmp_path / "out", "_f")
        assert loaded is None
        assert any("restarts _f from scratch" in r.message for r in caplog.records)

    def test_failed_checkpoint_save_warns_once(self, tmp_path: Path, caplog) -> None:
        """A persistent checkpoint-save failure (e.g. disk full) silently
        disables --resume — warn once per run instead of logging at DEBUG."""
        import logging
        from unittest.mock import patch

        ga = _make_ga(tmp_path)
        with (
            caplog.at_level(logging.WARNING, logger="rebrew.match"),
            patch("rebrew.match_ga.atomic_write_text", side_effect=OSError("disk full")),
        ):
            ga._save_checkpoint(2)
            ga._save_checkpoint(3)
        warnings = [r for r in caplog.records if "--resume unavailable" in r.message]
        assert len(warnings) == 1  # once per run, not per generation


class TestResume:
    def test_resume_restores_state(self, tmp_path: Path) -> None:
        ga1 = _make_ga(tmp_path, seed=1)
        # Simulate a mid-run state: different population + best.
        ga1.population = ["int f(void){return 7;}", "int f(void){return 8;}"]
        ga1.best_score = 3.0
        ga1.best_source = "int f(void){return 7;}"
        ga1._save_checkpoint(4)

        ga2 = _make_ga(tmp_path, seed=1, resume_from=read_ga_checkpoint(tmp_path / "out", "_f"))
        assert ga2._start_generation == 4  # continues, not restarts
        assert ga2.population == ["int f(void){return 7;}", "int f(void){return 8;}"]
        assert ga2.best_score == 3.0
        assert ga2.best_source == "int f(void){return 7;}"

    def test_resume_restores_search_state(self, tmp_path: Path) -> None:
        """Preserve adaptive selection state and mutation provenance."""
        ga1 = _make_ga(tmp_path, seed=1)
        ga1.population = ["int f(void){return 7;}", "int f(void){return 8;}"]
        ga1.best_score = 3.0
        ga1.best_source = "int f(void){return 7;}"
        ga1.restarts = 1
        ga1.stagnant_gens = 9
        ga1._save_checkpoint(4)

        ga2 = _make_ga(tmp_path, seed=1, resume_from=read_ga_checkpoint(tmp_path / "out", "_f"))
        assert ga2.rng.getstate() == ga1.rng.getstate()
        assert ga2.population == ga1.population
        assert ga2.applied_mutations == ga1.applied_mutations
        assert ga2.restarts == ga1.restarts
        assert ga2.stagnant_gens == ga1.stagnant_gens

    @pytest.mark.parametrize("split_generation", [2, 5])
    def test_resumed_run_matches_uninterrupted_run(
        self, tmp_path: Path, split_generation: int
    ) -> None:
        saved: list[GACheckpoint] = []
        save_checkpoint = BinaryMatchingGA._save_checkpoint

        def capture_checkpoint(ga: BinaryMatchingGA, generation: int) -> None:
            save_checkpoint(ga, generation)
            if generation == split_generation:
                checkpoint = read_ga_checkpoint(ga.out_dir, ga.symbol)
                assert checkpoint is not None
                saved.append(checkpoint)

        def make_run(resume_from: GACheckpoint | None = None) -> BinaryMatchingGA:
            return BinaryMatchingGA(
                _SOURCE,
                _TARGET,
                "cl",
                "/tmp/inc",
                "/O2",
                "_f",
                tmp_path / "out",
                pop_size=6,
                elitism=1,
                num_generations=10,
                stagnation_limit=6,
                num_jobs=2,
                rng_seed=7,
                verbose=0,
                resume_from=resume_from,
            )

        with (
            patch.object(BinaryMatchingGA, "_compile_source", return_value=BuildResult(ok=False)),
            patch.object(BinaryMatchingGA, "_compute_fitness", return_value=1.0),
            patch("rebrew.match_ga._CHECKPOINT_INTERVAL", 1),
            make_run() as uninterrupted,
        ):
            with patch.object(BinaryMatchingGA, "_save_checkpoint", capture_checkpoint):
                expected = uninterrupted.run()
            checkpoint_path = uninterrupted.out_dir / "checkpoints" / "_f.json"
            expected_checkpoint = checkpoint_path.read_bytes()
            assert len(saved) == 1
            assert saved[0].stagnant_gens > 0
            assert saved[0].restarts == (0 if split_generation == 2 else 1)
            with make_run(saved[0]) as resumed:
                assert resumed.run() == expected
                assert resumed.population == uninterrupted.population
                assert resumed.rng.getstate() == uninterrupted.rng.getstate()
                assert checkpoint_path.read_bytes() == expected_checkpoint

    def test_stale_checkpoint_ignored(self, tmp_path: Path) -> None:
        ga1 = _make_ga(tmp_path, seed=1)
        ga1._save_checkpoint(2)
        stale = read_ga_checkpoint(tmp_path / "out", "_f")
        # Same GA params but a different rng seed → different args_hash.
        ga2 = _make_ga(tmp_path, seed=99, resume_from=stale)
        assert ga2.args_hash != stale.args_hash
        assert ga2._start_generation == 0  # fresh start
        assert _SOURCE in ga2.population

    def test_fresh_ga_starts_at_zero(self, tmp_path: Path) -> None:
        ga = _make_ga(tmp_path)
        assert ga._start_generation == 0
        assert _SOURCE in ga.population
