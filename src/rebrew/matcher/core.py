"""core.py – Data types and caching for the GA matching engine.

Defines Score, BuildResult, BuildCache (SQLite-backed), and GACheckpoint
for persisting GA state across runs.
"""

import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from typing import Any

import diskcache


@dataclass
class Score:
    length_diff: int
    byte_score: float
    reloc_score: float
    mnemonic_score: float
    prologue_bonus: float
    total: float


@dataclass
class BuildResult:
    ok: bool
    score: Score | None = None
    obj_bytes: bytes | None = None
    reloc_offsets: list[int] | None = None
    error_msg: str = ""


class BuildCache:
    def __init__(self, db_path: str = "build_cache.db") -> None:
        cache_dir = db_path.removesuffix(".db") + "_cache"
        self._cache = diskcache.Cache(cache_dir)

    def get(self, key: str) -> BuildResult | None:
        return self._cache.get(key, default=None)

    def put(self, key: str, result: BuildResult) -> None:
        self._cache.set(key, result)


@dataclass
class GACheckpoint:
    generation: int
    best_score: float
    best_source: str | None
    population: list[str]
    rng_state: tuple[Any, ...]
    stagnant_gens: int
    elapsed_sec: float
    args_hash: str


def save_checkpoint(path: str, ckpt: GACheckpoint) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(asdict(ckpt), f, indent=2)
    os.replace(tmp, path)


def load_checkpoint(path: str, expected_hash: str) -> GACheckpoint | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("args_hash") != expected_hash:
            print("Checkpoint args hash mismatch, ignoring checkpoint.", file=sys.stderr)
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
        print(f"Failed to load checkpoint: {e}", file=sys.stderr)
        return None


def compute_args_hash(args_dict: dict[str, Any]) -> str:
    """Compute a hash of configuration arguments to validate checkpoints."""
    # Only include keys that affect the GA run logic
    keys = ["target_exe", "target_va", "target_size", "symbol", "cflags", "pop_size", "generations"]
    relevant = {k: args_dict.get(k) for k in keys if k in args_dict}
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()[:16]
