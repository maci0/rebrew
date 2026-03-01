"""core.py – Data types and caching for the GA matching engine.

Defines Score, BuildResult, BuildCache (SQLite-backed), and GACheckpoint
for persisting GA state across runs.
"""

import contextlib
import hashlib
import json
import warnings
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import diskcache


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

    def __init__(self, db_path: str = "build_cache.db") -> None:
        """Open (or create) the disk-backed build cache at *db_path*."""
        cache_dir = db_path.removesuffix(".db") + "_cache"
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
    rng_state: tuple[Any, ...]
    stagnant_gens: int
    elapsed_sec: float
    args_hash: str


def save_checkpoint(path: str, ckpt: GACheckpoint) -> None:
    """Atomically write *ckpt* as JSON to *path* via a temporary file."""
    import os
    import tempfile

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=p.parent, prefix=p.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(asdict(ckpt), indent=2))
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def load_checkpoint(path: str, expected_hash: str) -> GACheckpoint | None:
    """Load a checkpoint from *path*, returning ``None`` on hash mismatch or errors."""
    ckpt_path = Path(path)
    if not ckpt_path.exists():
        return None
    try:
        data = json.loads(ckpt_path.read_text(encoding="utf-8"))
        if data.get("args_hash") != expected_hash:
            warnings.warn("Checkpoint args hash mismatch, ignoring checkpoint.", stacklevel=2)
            return None
        # JSON deserializes arrays as lists; rng_state needs tuple nesting
        # Random.getstate() returns (version, internalstate_tuple, gauss_next)
        if "rng_state" in data and isinstance(data["rng_state"], list):
            rs = data["rng_state"]
            converted: list[Any] = [rs[0]] if rs else []
            if len(rs) > 1:
                converted.append(tuple(rs[1]) if isinstance(rs[1], list) else rs[1])
            converted.extend(rs[2:])
            data["rng_state"] = tuple(converted)
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
