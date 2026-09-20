"""core.py – Data types and caching for the GA matching engine.

Defines Score, StructuralSimilarity, BuildResult, BuildCache (disk-backed,
kept for import compatibility — the GA engine itself memoizes same-run
compiles in memory and persists across runs via the shared compile cache),
and GACheckpoint (serializable run state) for the GA matching engine.
"""

from __future__ import annotations

import base64
import json
import logging
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import diskcache

from rebrew.compile_cache import NoPickleDisk


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


def _encode_build_result(result: BuildResult) -> bytes:
    """Serialize *result* to JSON bytes (no pickle)."""
    score_obj: dict[str, float | int] | None = None
    if result.score is not None:
        s = result.score
        score_obj = {
            "length_diff": s.length_diff,
            "byte_score": s.byte_score,
            "reloc_score": s.reloc_score,
            "mnemonic_score": s.mnemonic_score,
            "prologue_bonus": s.prologue_bonus,
            "total": s.total,
        }
    payload: dict[str, Any] = {
        "v": 1,
        "ok": result.ok,
        "error_msg": result.error_msg,
        "fitness": result.fitness,
        "obj_bytes_b64": (
            base64.b64encode(result.obj_bytes).decode("ascii")
            if result.obj_bytes is not None
            else None
        ),
        "reloc_offsets": (
            {str(k): v for k, v in result.reloc_offsets.items()}
            if result.reloc_offsets is not None
            else None
        ),
        "score": score_obj,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _decode_build_result(data: bytes) -> BuildResult | None:
    """Decode JSON bytes from :func:`_encode_build_result`, or ``None`` if corrupt."""
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        return None
    if not isinstance(payload.get("ok"), bool):
        return None
    score: Score | None = None
    raw_score = payload.get("score")
    if isinstance(raw_score, dict):
        try:
            score = Score(
                length_diff=int(raw_score["length_diff"]),
                byte_score=float(raw_score["byte_score"]),
                reloc_score=float(raw_score["reloc_score"]),
                mnemonic_score=float(raw_score["mnemonic_score"]),
                prologue_bonus=float(raw_score["prologue_bonus"]),
                total=float(raw_score["total"]),
            )
        except (KeyError, TypeError, ValueError):
            return None
    obj_bytes: bytes | None = None
    b64 = payload.get("obj_bytes_b64")
    if b64 is not None:
        if not isinstance(b64, str):
            return None
        try:
            obj_bytes = base64.b64decode(b64.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError):
            return None
    reloc: dict[int, str] | None = None
    raw_reloc = payload.get("reloc_offsets")
    if raw_reloc is not None:
        if not isinstance(raw_reloc, dict):
            return None
        try:
            reloc = {int(k): str(v) for k, v in raw_reloc.items()}
        except (TypeError, ValueError):
            return None
    fitness = payload.get("fitness")
    if fitness is not None and not isinstance(fitness, (int, float)):
        return None
    error_msg = payload.get("error_msg", "")
    if not isinstance(error_msg, str):
        return None
    return BuildResult(
        ok=payload["ok"],
        score=score,
        obj_bytes=obj_bytes,
        reloc_offsets=reloc,
        error_msg=error_msg,
        fitness=float(fitness) if fitness is not None else None,
    )


class BuildCache:
    """Disk-backed cache mapping source hashes to build results.

    Kept for import compatibility (tests, external callers); the GA engine
    no longer instantiates one per run — same-run compiles memoize in
    memory and cross-run persistence lives in the shared compile cache.

    Entries are JSON-encoded bytes under :class:`~rebrew.compile_cache.NoPickleDisk`
    so a poisoned store cannot RCE via pickle (GHSA-w8v5-vhqr-4h9v).
    """

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
            self._cache = diskcache.Cache(cache_dir, disk=NoPickleDisk)
            with suppress(OSError):
                Path(cache_dir).chmod(0o700)
        except Exception as exc:  # any store failure must degrade, not raise
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
        except Exception as exc:  # degrade to miss, never kill the GA
            logging.getLogger(__name__).warning(
                "GA build cache read failed (%s: %s) — treating as miss",
                type(exc).__name__,
                exc,
            )
            return None
        if not isinstance(res, bytes):
            return None
        return _decode_build_result(res)

    def put(self, key: str, result: BuildResult) -> None:
        """Store a build result in the cache under *key* (skipped when unusable)."""
        if self._cache is None:
            return
        try:
            self._cache.set(key, _encode_build_result(result))
        except Exception as exc:  # a failed write only costs future hits
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

    Mutation provenance, restart budget, and stagnation count are preserved
    so resume retains the adaptive mutation rate and restart schedule.
    """

    generation: int  # next generation index to run
    best_score: float
    best_source: str | None
    population: list[str]
    rng_state: Any
    args_hash: str  # rejects stale checkpoints when GA parameters change
    applied_mutations: set[str] = field(default_factory=set)
    restarts: int = 0
    stagnant_gens: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON (rng_state → list for round-tripping)."""
        return {
            "generation": self.generation,
            "best_score": self.best_score,
            "best_source": self.best_source,
            "population": self.population,
            "rng_state": list(self.rng_state),
            "args_hash": self.args_hash,
            "applied_mutations": sorted(self.applied_mutations),
            "restarts": self.restarts,
            "stagnant_gens": self.stagnant_gens,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GACheckpoint:
        """Deserialize from :meth:`to_dict` output.

        The ``random`` state's inner ``internalstate`` tuple survives JSON as
        a list; ``setstate`` requires tuples, so nested lists are converted
        back recursively.  The versioned state tuple is (version, internalstate,
        gauss_next) where internalstate is a tuple of 625 ints — JSON roundtrip
        turns it into a list of lists, so we recursively restore tuples.
        """

        def _to_tuple(v: Any) -> Any:
            if isinstance(v, list):
                return tuple(_to_tuple(x) for x in v)
            return v

        raw_state = d.get("rng_state", [])
        mutations = d.get("applied_mutations", [])
        return cls(
            generation=int(d["generation"]),
            best_score=float(d["best_score"]),
            best_source=d.get("best_source"),
            population=list(d.get("population", [])),
            rng_state=_to_tuple(raw_state) if isinstance(raw_state, list) else raw_state,
            args_hash=str(d.get("args_hash", "")),
            applied_mutations={str(m) for m in mutations},
            restarts=int(d.get("restarts", 0)),
            stagnant_gens=int(d.get("stagnant_gens", 0)),
        )
