"""core.py – Data types for the GA matching engine.

Defines Score, StructuralSimilarity, BuildResult, and GACheckpoint
(serializable run state).  Same-run compiles memoize in memory; cross-run
persistence is the shared compile cache.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: A total below this is a byte-exact (or reloc-only) match.  Any non-reloc
#: byte difference costs >= 1000 while the prologue bonus is -100, so every
#: non-exact score sits far above it and every exact one is 0 or -100.
EXACT_SCORE_THRESHOLD = 0.1

#: Weights of the five components of :attr:`Score.total`.  They live here, not
#: in scoring.py, because ``total`` is derived from them: a stored total could
#: disagree with the fields it summarizes, and the weights a reader needs to
#: recompute it are the definition of the score rather than a scoring detail.
WEIGHT_LEN_DIFF = 3.0  # per missing/extra byte
WEIGHT_BYTE = 1000.0  # per raw byte difference (weighted)
WEIGHT_RELOC = 500.0  # per reloc-normalized byte difference
WEIGHT_MNEMONIC = 200.0  # per mnemonic-level difference (0-100 scale)


@dataclass
class Score:
    """Multi-metric fitness score for a compiled candidate.

    ``total`` is a property, not a field: it is the weighted sum of the five
    components, so storing it would let a mutated or hand-built Score carry a
    total its own fields do not imply.
    """

    length_diff: int
    byte_score: float
    reloc_score: float
    mnemonic_score: float
    prologue_bonus: float

    @property
    def total(self) -> float:
        """Weighted sum of the five components; lower is better."""
        return (
            (self.length_diff * WEIGHT_LEN_DIFF)
            + (self.byte_score * WEIGHT_BYTE)
            + (self.reloc_score * WEIGHT_RELOC)
            + (self.mnemonic_score * WEIGHT_MNEMONIC)
            + self.prologue_bonus
        )


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
    #: rebrew.match_ga's _compute_fitness; a warm-cache rerun of the same stub
    #: skips re-scoring.  ``None`` = not scored yet.
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
        raw_population = d.get("population", [])
        return cls(
            generation=int(d["generation"]),
            best_score=float(d["best_score"]),
            best_source=d.get("best_source"),
            # A non-list population (a hand-edited string would split into
            # characters) and a non-list rng_state (setstate would raise mid
            # resume) are dropped rather than passed through.
            population=list(raw_population) if isinstance(raw_population, list) else [],
            rng_state=_to_tuple(raw_state) if isinstance(raw_state, list) else None,
            args_hash=str(d.get("args_hash", "")),
            applied_mutations={str(m) for m in mutations},
            restarts=int(d.get("restarts", 0)),
            stagnant_gens=int(d.get("stagnant_gens", 0)),
            rng_seed=seed if isinstance(seed, int) else None,
        )
