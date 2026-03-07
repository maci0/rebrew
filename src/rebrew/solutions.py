"""solutions.py – Cross-function solution transfer database.

Records GA solution fingerprints (cflags, size) when functions reach
EXACT match. Seeds new GA runs from structurally similar solved functions to
reduce convergence time.

Storage: ``.rebrew/solutions.json`` — append-only JSON array, deduped by symbol.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from rebrew.utils import atomic_write_text

log = logging.getLogger(__name__)

_SOLUTIONS_DIR = ".rebrew"
_SOLUTIONS_FILE = "solutions.json"


@dataclass
class SolutionEntry:
    """Fingerprint of a GA-solved function."""

    symbol: str
    """Mangled symbol name (e.g. ``_my_func``)."""

    cflags: str
    """Winning compiler flags (e.g. ``/nologo /c /O2 /Gd``)."""

    size: int
    """Target function byte size."""

    source_file: str
    """Relative path to the source ``.c`` file."""

    score: float = 0.0
    """Best GA fitness score (0.0 = exact byte match)."""

    solved_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    """ISO 8601 timestamp of when the match was found."""

    generations: int = 0
    """How many GA generations the winning run used."""


def _solutions_path(project_root: Path) -> Path:
    """Return the solutions.json path (no side effects)."""
    return project_root / _SOLUTIONS_DIR / _SOLUTIONS_FILE


def _ensure_solutions_dir(project_root: Path) -> Path:
    """Return the solutions.json path, creating the directory if needed."""
    d = project_root / _SOLUTIONS_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d / _SOLUTIONS_FILE


def load_solutions(project_root: Path) -> list[SolutionEntry]:
    """Load all solution entries from ``.rebrew/solutions.json``.

    Returns an empty list if the file doesn't exist or is malformed.
    """
    p = _solutions_path(project_root)
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to read solutions.json: %s", exc)
        return []
    if not isinstance(raw, list):
        log.warning("solutions.json is not a JSON array, ignoring")
        return []
    entries: list[SolutionEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            known = {f.name for f in dataclasses.fields(SolutionEntry)}
            entries.append(SolutionEntry(**{k: v for k, v in item.items() if k in known}))
        except TypeError:
            continue
    return entries


def save_solution(project_root: Path, entry: SolutionEntry) -> None:
    """Append a solution entry to the DB, deduplicating by symbol.

    If an entry for the same symbol already exists, it is replaced
    (the newer solution wins — it may have better cflags or score).
    Uses ``atomic_write_text`` for crash-safe writes.
    """
    existing = load_solutions(project_root)
    # Replace existing entry for the same symbol
    updated = [e for e in existing if e.symbol != entry.symbol]
    updated.append(entry)
    # Sort by symbol for stable output
    updated.sort(key=lambda e: e.symbol)

    data = [asdict(e) for e in updated]
    p = _ensure_solutions_dir(project_root)
    atomic_write_text(p, json.dumps(data, indent=2) + "\n", encoding="utf-8")
    log.info("Saved solution for %s (%d total)", entry.symbol, len(updated))


def find_similar(
    project_root: Path,
    size: int,
    cflags: str = "",
    top_k: int = 5,
) -> list[SolutionEntry]:
    """Find solved functions most similar to the given target.

    Similarity heuristic (simple, deterministic, no ML):
      1. Closest function size (absolute difference)
      2. Tie-break: prefer matching cflags prefix

    Returns up to *top_k* entries, sorted by similarity (best first).
    """
    all_entries = load_solutions(project_root)
    if not all_entries:
        return []

    # Normalize cflags for prefix matching
    cflags_norm = _normalize_cflags(cflags)

    def _sort_key(e: SolutionEntry) -> tuple[int, int]:
        size_diff = abs(e.size - size)
        # Cflags similarity: 0 if prefix matches, 1 otherwise
        e_cflags = _normalize_cflags(e.cflags)
        cflags_match = 0 if cflags_norm and e_cflags == cflags_norm else 1
        return (size_diff, cflags_match)

    all_entries.sort(key=_sort_key)
    return all_entries[:top_k]


def _normalize_cflags(cflags: str) -> str:
    """Normalize cflags for comparison: strip /nologo /c, sort remainder."""
    parts = cflags.split()
    # Remove build-noise flags that don't affect codegen
    skip = {"/nologo", "/c"}
    meaningful = sorted(p for p in parts if p not in skip and not p.startswith(("/Fo", "/Fe")))
    return " ".join(meaningful)
