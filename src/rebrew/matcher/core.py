"""core.py – Data types for the GA matching engine.

Defines Score, StructuralSimilarity, BuildResult, and GACheckpoint
(serializable run state).  Same-run compiles memoize in memory; cross-run
persistence is the shared compile cache.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    #: Seed the run started from; replay it with ``--seed``.
    rng_seed: int | None = None

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
            "rng_seed": self.rng_seed,
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
        seed = d.get("rng_seed")
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
            rng_seed=seed if isinstance(seed, int) else None,
        )
