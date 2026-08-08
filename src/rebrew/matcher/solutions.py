"""solutions.py – Cross-function solution transfer database.

Records GA solution fingerprints (cflags, size) when functions reach
EXACT match. Seeds new GA runs from structurally similar solved functions to
reduce convergence time.

Storage: ``.rebrew/solutions.json`` — append-only JSON array, deduped by
``(target, symbol)`` so multi-target projects keep one winning entry per target.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
    """Path to the source ``.c`` file, **relative to the project root**.

    :func:`save_solution` normalizes whatever the caller passes into this form,
    because the only reader (``rebrew match --all`` seeding) resolves it as
    ``project_root / source_file``.  A path outside the project root is stored
    absolute and still resolves correctly."""

    target: str = ""
    """Target module name (e.g. ``SERVER``).  Empty for legacy single-target
    records.  Solutions are deduped by ``(target, symbol)`` so multi-target
    projects keep one winning entry per target."""

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
        log.warning("Failed to read solutions at %s: %s", p, exc)
        return []
    if not isinstance(raw, list):
        log.warning("solutions file %s is not a JSON array, ignoring", p)
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


def _relative_source(project_root: Path, source_file: str) -> str:
    """Normalize *source_file* to a path relative to *project_root*.

    Callers pass absolute paths, cwd-relative paths, or already-relative ones.
    Anything that resolves under the project root becomes root-relative;
    anything else is stored absolute so it still resolves unambiguously.
    """
    if not source_file:
        return source_file
    p = Path(source_file)
    try:
        resolved = p if p.is_absolute() else (Path.cwd() / p)
        return str(resolved.resolve().relative_to(project_root.resolve()))
    except (ValueError, OSError):
        return str(p) if p.is_absolute() else source_file


def save_solution(project_root: Path, entry: SolutionEntry) -> None:
    """Append a solution entry to the DB, deduplicating by ``(target, symbol)``.

    If an entry for the same (target, symbol) already exists, it is replaced
    (the newer solution wins — it may have better cflags or score).  Uses
    ``atomic_write_text`` for crash-safe writes.

    ``entry.source_file`` is normalized to a project-root-relative path so all
    writers agree on the base the reader assumes.
    """
    entry = dataclasses.replace(
        entry, source_file=_relative_source(project_root, entry.source_file)
    )
    existing = load_solutions(project_root)
    # Replace existing entry for the same (target, symbol)
    updated = [e for e in existing if not (e.symbol == entry.symbol and e.target == entry.target)]
    updated.append(entry)
    # Sort by (target, symbol) for stable output
    updated.sort(key=lambda e: (e.target, e.symbol))

    data = [asdict(e) for e in updated]
    p = _ensure_solutions_dir(project_root)
    atomic_write_text(p, json.dumps(data, indent=2) + "\n", encoding="utf-8")
    log.info("Saved solution for %s/%s (%d total)", entry.target, entry.symbol, len(updated))


def save_solutions(project_root: Path, entries: list[SolutionEntry]) -> None:
    """Batch-append solution entries, deduplicating by ``(target, symbol)``.

    Same semantics as :func:`save_solution` but loads and rewrites the whole
    file ONCE for *entries* — the batch flag-sweep path previously called
    ``save_solution`` per exact match (N whole-file reads + rewrites).
    """
    if not entries:
        return
    existing = load_solutions(project_root)
    existing_by_key = {(e.symbol, e.target): e for e in existing}
    for entry in entries:
        entry = dataclasses.replace(
            entry, source_file=_relative_source(project_root, entry.source_file)
        )
        existing_by_key[(entry.symbol, entry.target)] = entry
    updated = sorted(existing_by_key.values(), key=lambda e: (e.target, e.symbol))
    data = [asdict(e) for e in updated]
    p = _ensure_solutions_dir(project_root)
    atomic_write_text(p, json.dumps(data, indent=2) + "\n", encoding="utf-8")
    log.info("Saved %d solution(s) (%d total)", len(entries), len(updated))


def find_similar(
    project_root: Path,
    size: int,
    cflags: str = "",
    target: str = "",
    top_k: int = 5,
    entries: list[SolutionEntry] | None = None,
) -> list[SolutionEntry]:
    """Find solved functions most similar to the given target.

    Similarity heuristic (simple, deterministic, no ML):
      0. Same-target solutions rank before other targets' (empty *target*
         keeps legacy behavior — unscoped records match everything).
      1. Closest function size (absolute difference)
      2. Tie-break: prefer matching cflags (exact match after normalization)

    *entries* allows callers to pass a single preloaded solutions list when
    calling in a loop (e.g. the batch seeding loop), avoiding one file read
    + parse per stub.

    Returns up to *top_k* entries, sorted by similarity (best first).
    """
    all_entries = load_solutions(project_root) if entries is None else entries
    if not all_entries:
        return []
    # Normalize cflags for comparison
    cflags_norm = _normalize_cflags(cflags)

    def _sort_key(e: SolutionEntry) -> tuple[int, int, int]:
        size_diff = abs(e.size - size)
        # Cflags similarity: 0 if exact match, 1 otherwise
        e_cflags = _normalize_cflags(e.cflags)
        cflags_match = 0 if e_cflags == cflags_norm else 1
        same_target = 0 if e.target == target else 1
        return (same_target, size_diff, cflags_match)

    all_entries.sort(key=_sort_key)
    return all_entries[:top_k]


def _normalize_cflags(cflags: str) -> str:
    """Normalize cflags for comparison: strip /nologo /c /fo* /fe*, sort remainder case-insensitively."""
    parts = cflags.split()
    # Remove build-noise flags that don't affect codegen (case-insensitive)
    skip = {"/nologo", "/c"}
    meaningful = sorted(
        (p for p in parts if p.lower() not in skip and not p.lower().startswith(("/fo", "/fe"))),
        key=str.lower,
    )
    return " ".join(meaningful)


# ---------------------------------------------------------------------------
# GA run history — append-only JSONL of per-function batch outcomes.
# ---------------------------------------------------------------------------
#
# Unlike solutions.json (winning fingerprints), ga_runs.jsonl keeps the full
# history of every `rebrew match --all` attempt — matched/failed per run — so
# progress across runs and targets can be tracked and diffed.

_GA_RUNS_FILE = "ga_runs.jsonl"


def record_ga_run(
    project_root: Path,
    *,
    target: str,
    va: str | int,
    symbol: str,
    matched: bool,
    score: float | None = None,
    generations: int = 0,
) -> Path:
    """Append one GA outcome to ``.rebrew/ga_runs.jsonl`` (append-only)."""
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "target": target,
        "va": str(va),
        "symbol": symbol,
        "matched": bool(matched),
    }
    if score is not None:
        record["score"] = round(float(score), 2)
    if generations:
        record["generations"] = int(generations)
    p = project_root / ".rebrew" / _GA_RUNS_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return p


def load_ga_runs(
    project_root: Path,
    *,
    target: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Read recent GA run records, newest first, optionally filtered by *target*.

    Malformed lines are skipped.  Returns at most *limit* records.
    """
    p = project_root / ".rebrew" / _GA_RUNS_FILE
    if not p.exists():
        return []
    records: list[dict[str, Any]] = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    if target:
        records = [r for r in records if r.get("target") == target]
    records.reverse()  # newest first
    return records[:limit]
