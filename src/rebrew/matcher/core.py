"""core.py – Data types and caching for the GA matching engine.

Defines Score, BuildResult, and BuildCache (disk-backed) for the GA
matching engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    #: Memoized GA fitness (score.total + excess penalty).  Populated by
    #: rebrew.match's _compute_fitness; a warm-cache rerun of the same stub
    #: skips re-scoring.  ``None`` = not scored yet.  Backward-compatible:
    #: reads use getattr(res, "fitness", None) for pre-field pickles.
    fitness: float | None = None


class BuildCache:
    """Disk-backed cache mapping source hashes to build results."""

    def __init__(self, db_path: str | Path = "build_cache.db") -> None:
        """Open (or create) the disk-backed build cache.

        Cache directory is derived from *db_path* (suffix ``.db`` replaced with ``_cache/``).
        A store that cannot be opened (corrupt SQLite file, unwritable dir)
        leaves the cache disabled — every lookup misses and every write is
        skipped, so a GA run degrades to full recompiles instead of crashing.
        """
        cache_dir = str(db_path).removesuffix(".db") + "_cache"
        self._cache: diskcache.Cache | None
        try:
            self._cache = diskcache.Cache(cache_dir)
        except Exception as exc:  # noqa: BLE001 — any store failure must degrade, not raise
            logging.getLogger(__name__).warning(
                "GA build cache at %s unusable (%s: %s) — running without it "
                "(delete the _cache/ dir to reset a corrupted store)",
                cache_dir,
                type(exc).__name__,
                exc,
            )
            self._cache = None

    def get(self, key: str) -> BuildResult | None:
        """Return a cached build result for *key* if present.

        A failing store (corruption, lock contention timeout) degrades to a
        miss so the candidate is rebuilt via the compiler subprocess.
        """
        if self._cache is None:
            return None
        try:
            res = self._cache.get(key, default=None)
        except Exception as exc:  # noqa: BLE001 — degrade to miss, never kill the GA
            logging.getLogger(__name__).warning(
                "GA build cache read failed (%s: %s) — treating as miss",
                type(exc).__name__,
                exc,
            )
            return None
        return res if isinstance(res, BuildResult) else None

    def put(self, key: str, result: BuildResult) -> None:
        """Store a build result in the cache under *key* (skipped when unusable)."""
        if self._cache is None:
            return
        try:
            self._cache.set(key, result)
        except Exception as exc:  # noqa: BLE001 — a failed write only costs future hits
            logging.getLogger(__name__).warning(
                "GA build cache write failed (%s: %s)",
                type(exc).__name__,
                exc,
            )

    def close(self) -> None:
        """Close the underlying diskcache store."""
        if self._cache is not None:
            self._cache.close()

    def __enter__(self) -> BuildCache:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


@dataclass
class GACheckpoint:
    """Serializable GA state for resuming an interrupted run.

    Captured at the end of each generation: the next generation to run, the
    best result so far, the current population, and the RNG state.  JSON-safe
    (the ``random`` state is a flat tuple of ints/floats/None).
    """

    generation: int  # next generation index to run
    best_score: float
    best_source: str | None
    population: list[str]
    rng_state: Any
    args_hash: str  # rejects stale checkpoints when GA parameters change

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON (rng_state → list for round-tripping)."""
        return {
            "generation": self.generation,
            "best_score": self.best_score,
            "best_source": self.best_source,
            "population": self.population,
            "rng_state": list(self.rng_state),
            "args_hash": self.args_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GACheckpoint:
        """Deserialize from :meth:`to_dict` output.

        The ``random`` state's inner ``internalstate`` tuple survives JSON as
        a list; ``setstate`` requires tuples, so nested lists are converted
        back recursively.
        """
        return cls(
            generation=int(d["generation"]),
            best_score=float(d["best_score"]),
            best_source=d.get("best_source"),
            population=list(d.get("population", [])),
            rng_state=tuple(tuple(x) if isinstance(x, list) else x for x in d.get("rng_state", [])),
            args_hash=str(d.get("args_hash", "")),
        )
