"""Tests for rebrew.matcher.core — Score, BuildResult, BuildCache, GACheckpoint."""

import os

import pytest

from rebrew.matcher.core import (
    BuildCache,
    BuildResult,
    GACheckpoint,
    Score,
    compute_args_hash,
    load_checkpoint,
    save_checkpoint,
)

# -------------------------------------------------------------------------
# Score dataclass
# -------------------------------------------------------------------------


class TestScore:
    def test_creation(self) -> None:
        s = Score(
            length_diff=0,
            byte_score=0.0,
            reloc_score=0.0,
            mnemonic_score=0.0,
            prologue_bonus=0.0,
            total=0.0,
        )
        assert s.total == 0.0
        assert s.length_diff == 0


# -------------------------------------------------------------------------
# BuildResult dataclass
# -------------------------------------------------------------------------


class TestBuildResult:
    def test_ok(self) -> None:
        r = BuildResult(ok=True, obj_bytes=b"\x55\x8b")
        assert r.ok is True
        assert r.error_msg == ""

    def test_failed(self) -> None:
        r = BuildResult(ok=False, error_msg="compilation failed")
        assert r.ok is False
        assert r.score is None


# -------------------------------------------------------------------------
# BuildCache
# -------------------------------------------------------------------------


class TestBuildCache:
    def test_put_get(self, tmp_path) -> None:
        db = str(tmp_path / "test_cache.db")
        cache = BuildCache(db_path=db)
        result = BuildResult(ok=True, obj_bytes=b"\x55\x8b")
        cache.put("test_key", result)
        got = cache.get("test_key")
        assert got is not None
        assert isinstance(got, BuildResult)
        assert got.ok is True
        assert got.obj_bytes == b"\x55\x8b"
        assert got.error_msg == ""
        cache._cache.close()

    def test_get_missing(self, tmp_path) -> None:
        db = str(tmp_path / "test_cache.db")
        cache = BuildCache(db_path=db)
        assert cache.get("nonexistent") is None
        cache._cache.close()

    def test_overwrite(self, tmp_path) -> None:
        db = str(tmp_path / "test_cache.db")
        cache = BuildCache(db_path=db)
        r1 = BuildResult(ok=True, error_msg="first")
        r2 = BuildResult(ok=False, error_msg="second")
        cache.put("key", r1)
        cache.put("key", r2)
        got = cache.get("key")
        assert got.error_msg == "second"
        cache._cache.close()


# -------------------------------------------------------------------------
# GACheckpoint & save/load
# -------------------------------------------------------------------------


class TestGACheckpoint:
    def test_save_load(self, tmp_path) -> None:
        path = str(tmp_path / "ckpt.json")
        ckpt = GACheckpoint(
            generation=10,
            best_score=100.0,
            best_source="int f() { return 0; }",
            population=["src1", "src2"],
            rng_state=(3, (1, 2, 3)),
            stagnant_gens=5,
            elapsed_sec=30.0,
            args_hash="abc123",
        )
        save_checkpoint(path, ckpt)
        assert os.path.exists(path)

        loaded = load_checkpoint(path, "abc123")
        assert loaded is not None
        assert isinstance(loaded, GACheckpoint)
        assert loaded.generation == 10
        assert loaded.best_score == 100.0
        assert loaded.best_source == "int f() { return 0; }"
        assert loaded.population == ["src1", "src2"]
        assert loaded.stagnant_gens == 5
        assert loaded.elapsed_sec == 30.0

    def test_load_wrong_hash(self, tmp_path) -> None:
        path = str(tmp_path / "ckpt.json")
        ckpt = GACheckpoint(
            generation=1,
            best_score=0.0,
            best_source=None,
            population=[],
            rng_state=(),
            stagnant_gens=0,
            elapsed_sec=0.0,
            args_hash="correct",
        )
        save_checkpoint(path, ckpt)
        with pytest.warns(UserWarning, match="args hash mismatch"):
            loaded = load_checkpoint(path, "wrong_hash")
        assert loaded is None

    def test_load_nonexistent(self, tmp_path) -> None:
        path = str(tmp_path / "nonexistent.json")
        assert load_checkpoint(path, "hash") is None

    def test_rng_state_roundtrip(self, tmp_path) -> None:
        """rng_state with nested tuple must survive JSON serialization."""
        import random

        rng = random.Random(42)
        state = rng.getstate()
        path = str(tmp_path / "ckpt_rng.json")
        ckpt = GACheckpoint(
            generation=1,
            best_score=0.0,
            best_source=None,
            population=[],
            rng_state=state,
            stagnant_gens=0,
            elapsed_sec=0.0,
            args_hash="rng_test",
        )
        save_checkpoint(path, ckpt)
        loaded = load_checkpoint(path, "rng_test")
        assert loaded is not None
        # The loaded state must be usable by Random.setstate()
        rng2 = random.Random()
        rng2.setstate(loaded.rng_state)
        # Both rngs should now produce identical output
        assert rng.random() == rng2.random()
        assert rng.randint(0, 1000) == rng2.randint(0, 1000)


# -------------------------------------------------------------------------
# compute_args_hash
# -------------------------------------------------------------------------


class TestComputeArgsHash:
    def test_deterministic(self) -> None:
        args = {"target_exe": "test.exe", "target_va": "0x1000", "pop_size": 48}
        h1 = compute_args_hash(args)
        h2 = compute_args_hash(args)
        assert h1 == h2

    def test_different_args(self) -> None:
        a1 = {"target_exe": "a.exe"}
        a2 = {"target_exe": "b.exe"}
        assert compute_args_hash(a1) != compute_args_hash(a2)

    def test_irrelevant_keys_ignored(self) -> None:
        a1 = {"target_exe": "a.exe", "unrelated": True}
        a2 = {"target_exe": "a.exe"}
        assert compute_args_hash(a1) == compute_args_hash(a2)
