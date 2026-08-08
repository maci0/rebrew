"""core.py – Data types and caching for the GA matching engine.

Defines Score, BuildResult, and BuildCache (disk-backed) for the GA
matching engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import diskcache


# Python's random.Random.getstate() returns (version, internalstate, gauss_next).
# Providing a precise alias here avoids tuple[Any, ...] which gives no static guarantees.
@dataclass
class Score:
    """Multi-metric fitness score for a compiled candidate."""

    length_diff: int
    byte_score: float
    reloc_score: float
    mnemonic_score: float
    prologue_bonus: float
    total: float


@dataclass
class StructuralSimilarity:
    """Breakdown of structural vs flag-fixable differences.

    Helps distinguish when compiler flags might improve a match versus
    when differences are purely structural (register allocation, etc.)
    and flag sweeping will be fruitless.
    """

    total_insns: int
    exact: int
    reloc_only: int
    register_only: int
    structural: int
    mnemonic_match_ratio: float
    structural_ratio: float
    flag_sensitive: bool


@dataclass
class BuildResult:
    """Result of compiling and scoring a single candidate source."""

    ok: bool
    score: Score | None = None
    obj_bytes: bytes | None = None
    reloc_offsets: dict[int, str] | None = None
    error_msg: str = ""


class BuildCache:
    """Disk-backed cache mapping source hashes to build results."""

    def __init__(self, db_path: str | Path = "build_cache.db") -> None:
        """Open (or create) the disk-backed build cache.

        Cache directory is derived from *db_path* (suffix ``.db`` replaced with ``_cache/``).
        """
        cache_dir = str(db_path).removesuffix(".db") + "_cache"
        self._cache = diskcache.Cache(cache_dir)

    def get(self, key: str) -> BuildResult | None:
        """Return a cached build result for *key* if present."""
        res = self._cache.get(key, default=None)
        return res if isinstance(res, BuildResult) else None

    def put(self, key: str, result: BuildResult) -> None:
        """Store a build result in the cache under *key*."""
        self._cache.set(key, result)

    def close(self) -> None:
        """Close the underlying diskcache store."""
        self._cache.close()

    def __enter__(self) -> BuildCache:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
