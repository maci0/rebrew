import hashlib
import json
import os
import pickle
import sqlite3
import threading
from dataclasses import asdict, dataclass


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
    def __init__(self, db_path: str = "build_cache.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS build_results (key TEXT PRIMARY KEY, result BLOB)"
            )
            conn.commit()
            conn.close()

    def get(self, key: str) -> BuildResult | None:
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("SELECT result FROM build_results WHERE key = ?", (key,))
            row = cur.fetchone()
            conn.close()
            if row:
                try:
                    return pickle.loads(row[0])
                except Exception:
                    return None
            return None

    def put(self, key: str, result: BuildResult):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT OR REPLACE INTO build_results (key, result) VALUES (?, ?)",
                (key, pickle.dumps(result)),
            )
            conn.commit()
            conn.close()

@dataclass
class GACheckpoint:
    generation: int
    best_score: float
    best_source: str | None
    population: list[str]
    rng_state: tuple
    stagnant_gens: int
    elapsed_sec: float
    args_hash: str

def save_checkpoint(path: str, ckpt: GACheckpoint):
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
            print("Checkpoint args hash mismatch, ignoring checkpoint.")
            return None
        return GACheckpoint(**data)
    except Exception as e:
        print(f"Failed to load checkpoint: {e}")
        return None

def compute_args_hash(args_dict: dict) -> str:
    """Compute a hash of configuration arguments to validate checkpoints."""
    # Only include keys that affect the GA run logic
    keys = ["target_exe", "target_va", "target_size", "symbol", "cflags", "pop_size", "generations"]
    relevant = {k: args_dict.get(k) for k in keys if k in args_dict}
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()[:16]
