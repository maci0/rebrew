"""Tests for batch GA checkpoint/resume (H4)."""

from __future__ import annotations

from pathlib import Path

from rebrew.match import BinaryMatchingGA, _ga_args_hash, load_ga_checkpoint, read_ga_checkpoint
from rebrew.matcher.core import GACheckpoint

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


class TestCheckpointIO:
    def test_save_and_read(self, tmp_path: Path) -> None:
        ga = _make_ga(tmp_path)
        ga._save_checkpoint(2)
        ckpt_path = tmp_path / "out" / "checkpoints" / "_f.json"
        assert ckpt_path.is_file()
        loaded = read_ga_checkpoint(tmp_path / "out", "_f")
        assert loaded is not None
        assert loaded.generation == 2

    def test_load_validates_args_hash(self, tmp_path: Path) -> None:
        ga = _make_ga(tmp_path)
        ga._save_checkpoint(2)
        out = tmp_path / "out"
        assert load_ga_checkpoint(out, "_f", ga.args_hash) is not None
        assert load_ga_checkpoint(out, "_f", "stale-hash") is None

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
            patch("rebrew.match.atomic_write_text", side_effect=OSError("disk full")),
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
