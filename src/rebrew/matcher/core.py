"""core.py – Data types and caching for the GA matching engine.

Defines Score, BuildResult, BuildCache (SQLite-backed), and GACheckpoint
for persisting GA state across runs.
"""

import hashlib
import json
import warnings
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import diskcache

from rebrew.utils import atomic_write_text

# Python's random.Random.getstate() returns (version, internalstate, gauss_next).
# Providing a precise alias here avoids tuple[Any, ...] which gives no static guarantees.
RngState = tuple[int, tuple[int, ...], float | None]


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
        """Open (or create) the disk-backed build cache at *db_path*."""
        cache_dir = str(db_path).removesuffix(".db") + "_cache"
        self._cache = diskcache.Cache(cache_dir)

    def get(self, key: str) -> BuildResult | None:
        """Return a cached build result for *key* if present."""
        res = self._cache.get(key, default=None)
        return res if isinstance(res, BuildResult) else None

    def put(self, key: str, result: BuildResult) -> None:
        """Store a build result in the cache under *key*."""
        self._cache.set(key, result)


@dataclass
class GACheckpoint:
    """Serializable snapshot of GA state for resuming interrupted runs."""

    generation: int
    best_score: float
    best_source: str | None
    population: list[str]
    rng_state: RngState
    stagnant_gens: int
    elapsed_sec: float
    args_hash: str


def save_checkpoint(path: str | Path, ckpt: GACheckpoint) -> None:
    """Atomically write *ckpt* as JSON to *path* via a temporary file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(p, json.dumps(asdict(ckpt), indent=2))


def load_checkpoint(path: str | Path, expected_hash: str) -> GACheckpoint | None:
    """Load a checkpoint from *path*, returning ``None`` on hash mismatch or errors."""
    ckpt_path = Path(path)
    if not ckpt_path.exists():
        return None
    try:
        data = json.loads(ckpt_path.read_text(encoding="utf-8"))
        if data.get("args_hash") != expected_hash:
            warnings.warn("Checkpoint args hash mismatch, ignoring checkpoint.", stacklevel=2)
            return None
        # JSON deserialises all tuples as lists; Random.getstate() returns
        # (version, tuple_of_625_ints, gauss_next) — rebuild the precise 3-tuple.
        if "rng_state" in data and isinstance(data["rng_state"], list):
            rs = data["rng_state"]
            if len(rs) != 3 or not isinstance(rs[1], (list, tuple)):
                warnings.warn(
                    f"Checkpoint rng_state has unexpected structure (len={len(rs)}); "
                    "ignoring checkpoint.",
                    stacklevel=2,
                )
                return None
            # Validate and coerce each element of the internal state to int.
            # A corrupted checkpoint could contain floats or strings here,
            # which would cause random.Random.setstate() to raise ValueError
            # uncaught inside the GA loop.
            try:
                internalstate: tuple[int, ...] = tuple(int(x) for x in rs[1])
            except (TypeError, ValueError) as exc:
                warnings.warn(
                    f"Checkpoint rng_state internal state is invalid ({exc}); ignoring checkpoint.",
                    stacklevel=2,
                )
                return None
            data["rng_state"] = (int(rs[0]), internalstate, rs[2])
        return GACheckpoint(**data)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, OSError) as e:
        warnings.warn(f"Failed to load checkpoint: {e}", stacklevel=2)
        return None


def compute_args_hash(args_dict: dict[str, Any]) -> str:
    """Compute a hash of configuration arguments to validate checkpoints."""
    # Only include keys that affect the GA run logic
    keys = ["target_exe", "target_va", "target_size", "symbol", "cflags", "pop_size", "generations"]
    relevant = {k: args_dict.get(k) for k in keys if k in args_dict}
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()[:16]
