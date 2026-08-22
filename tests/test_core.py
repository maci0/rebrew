"""Tests for rebrew.matcher.core — Score, BuildResult, BuildCache."""

from pathlib import Path

from rebrew.matcher.core import (
    BuildCache,
    BuildResult,
    Score,
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
    def test_put_get(self, tmp_path: Path) -> None:
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

    def test_get_missing(self, tmp_path: Path) -> None:
        db = str(tmp_path / "test_cache.db")
        cache = BuildCache(db_path=db)
        assert cache.get("nonexistent") is None
        cache._cache.close()

    def test_overwrite(self, tmp_path: Path) -> None:
        db = str(tmp_path / "test_cache.db")
        cache = BuildCache(db_path=db)
        r1 = BuildResult(ok=True, error_msg="first")
        r2 = BuildResult(ok=False, error_msg="second")
        cache.put("key", r1)
        cache.put("key", r2)
        got = cache.get("key")
        assert got.error_msg == "second"
        cache._cache.close()


class TestBuildCacheDegradation:
    """A corrupt store must degrade to miss/skip, never raise: BuildCache.get
    sits in the GA per-candidate hot loop and an unhandled sqlite/diskcache
    error would kill an hours-long run (error-handling review)."""

    def test_corrupt_store_disables_cache(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "test_cache_cache"
        cache_dir.mkdir()
        (cache_dir / "cache.db").write_bytes(b"this is not sqlite\x00\x01\x02")
        cache = BuildCache(db_path=str(tmp_path / "test_cache.db"))
        assert cache._cache is None
        assert cache.get("k") is None  # miss, not raise
        cache.put("k", BuildResult(ok=True))  # skip, not raise
        cache.close()  # no-op, not raise

    def test_read_failure_degrades_to_miss(self, tmp_path: Path, monkeypatch) -> None:
        import sqlite3

        cache = BuildCache(db_path=str(tmp_path / "test_cache.db"))

        def _boom(*a: object, **kw: object) -> object:
            raise sqlite3.DatabaseError("database disk image is malformed")

        monkeypatch.setattr(cache._cache, "get", _boom)
        assert cache.get("k") is None
        cache.close()


# -------------------------------------------------------------------------
# Save/load
# -------------------------------------------------------------------------
