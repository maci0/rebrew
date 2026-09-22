"""solutions.py – Cross-function solution transfer database.

Records GA solution fingerprints (cflags, size) when functions reach
EXACT match. Seeds new GA runs from structurally similar solved functions to
reduce convergence time.

Storage: ``.rebrew/ga_runs.jsonl`` — one append-only log for every GA
outcome.  A win record carries the full solution fingerprint (cflags, size,
source, mutations); ``load_solutions`` derives the winning entry per
``(target, symbol)`` (newest win) from the log.  Losses stay for
``--skip-recent`` / ``--ga-history``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rebrew.utils import file_lock

log = logging.getLogger(__name__)

_REBREW_DIR = ".rebrew"
_GA_RUNS_FILE = "ga_runs.jsonl"

#: Serializes in-process appends to ``ga_runs.jsonl``.  Parallel
#: ``match --all -j N`` stubs all call :func:`record_ga_run`; O_APPEND is
#: only atomic for writes ≤ PIPE_BUF, and a buffered text write of a large
#: win record can interleave with a sibling stub's line.
_GA_RUNS_APPEND_LOCK = threading.Lock()


@contextlib.contextmanager
def _ga_runs_append_lock(path: Path) -> Iterator[None]:
    """Thread + cross-process lock around one JSONL append.

    Same discipline as :func:`rebrew.utils.metadata_write_lock`: the thread
    lock covers in-process workers; an advisory ``flock`` on a ``.lock``
    sidecar covers concurrent processes.
    """
    with _GA_RUNS_APPEND_LOCK, file_lock(Path(str(path) + ".lock")):
        yield


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

    mutations: tuple[str, ...] = ()
    """Distinct ``mut_*`` operators applied during the winning run (the GA's
    ``applied_mutations`` at the win site).  Cross-function learning: a later
    function solved from a similar source can bias its own GA toward the
    operators that worked here (see ``rebrew match`` similar-solution
    seeding)."""


def _runs_path(project_root: Path) -> Path:
    """Return the ga_runs.jsonl path (no side effects)."""
    return project_root / _REBREW_DIR / _GA_RUNS_FILE


def _ensure_runs_dir(project_root: Path) -> Path:
    """Return the ga_runs.jsonl path, creating the directory if needed."""
    d = project_root / _REBREW_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d / _GA_RUNS_FILE


def _entry_from_record(item: dict[str, Any]) -> SolutionEntry | None:
    """Build a SolutionEntry from a win record.

    Returns None when the record is not a usable win (missing fields, wrong
    types) — a malformed record must not break seeding for the whole batch.
    """
    try:
        known = {f.name for f in dataclasses.fields(SolutionEntry)}
        entry = SolutionEntry(**{k: v for k, v in item.items() if k in known})
    except TypeError:
        return None  # missing required field
    # JSON round-trips the tuple-typed `mutations` field as a list —
    # normalize it so downstream seeding reads a tuple.
    if not isinstance(entry.mutations, tuple):
        try:
            entry = dataclasses.replace(entry, mutations=tuple(entry.mutations))
        except TypeError:
            return None
    # Type-check the fields the readers rely on: a malformed record
    # (e.g. {"size": "abc"}) constructs fine but would raise TypeError
    # inside find_similar's abs(e.size - size), which the per-stub
    # except Exception turns into "Solution lookup failed" for the whole
    # batch.  Skip bad records instead.
    if (
        not isinstance(entry.symbol, str)
        or not entry.symbol
        or not isinstance(entry.cflags, str)
        or not isinstance(entry.source_file, str)
        or not isinstance(entry.target, str)
        or not isinstance(entry.size, int)
        or isinstance(entry.size, bool)
        or not isinstance(entry.score, (int, float))
        or isinstance(entry.score, bool)
    ):
        return None
    return entry


def load_solutions(project_root: Path) -> list[SolutionEntry]:
    """Load winning solution entries (newest win per ``(target, symbol)``).

    Derived from ``.rebrew/ga_runs.jsonl`` win records.  Returns [] when
    nothing is stored (never raises).
    """
    wins: dict[tuple[str, str], SolutionEntry] = {}
    for rec in _iter_run_records(_runs_path(project_root)):
        if not rec.get("matched"):
            continue
        entry = _entry_from_record(rec)
        if entry is not None:
            wins[(entry.target, entry.symbol)] = entry  # log order: newest wins
    return sorted(wins.values(), key=lambda e: (e.target, e.symbol))


def _iter_run_records(path: Path) -> Any:
    """Yield dict records from a JSONL file (skips malformed lines)."""
    if not path.exists():
        return
    try:
        fh = path.open(encoding="utf-8")
    except OSError:
        log.warning("Cannot read GA run log %s — solution seeding disabled", path, exc_info=True)
        return
    bad_lines = 0
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                bad_lines += 1
                continue
            if isinstance(record, dict):
                yield record
    if bad_lines:
        # One corrupt line must not kill seeding, but zero signal would hide
        # a truncated write that drops every subsequent win record.
        log.warning(
            "Skipped %d malformed line(s) in GA run log %s — check for truncated writes",
            bad_lines,
            path,
        )


def load_solutions_file(path: Path) -> list[SolutionEntry]:
    """Load solution entries from another project's run log.

    Supports cross-project seeding: ``rebrew match --seed-solutions
    ../other-project/.rebrew/ga_runs.jsonl`` transfers winning
    cflags/source fingerprints between projects sharing a compiler.
    Returns an empty list when the file is missing or malformed (never
    raises).
    """
    if not path.exists():
        return []
    wins: dict[tuple[str, str], SolutionEntry] = {}
    for rec in _iter_run_records(path):
        if not rec.get("matched"):
            continue
        entry = _entry_from_record(rec)
        if entry is not None:
            wins[(entry.target, entry.symbol)] = entry
    return sorted(wins.values(), key=lambda e: (e.target, e.symbol))


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
        return resolved.resolve().relative_to(project_root.resolve()).as_posix()
    except (ValueError, OSError):
        return str(p) if p.is_absolute() else source_file


def save_solution(project_root: Path, entry: SolutionEntry) -> None:
    """Record a solution win (appended to the GA run log).

    A win is one record in ``ga_runs.jsonl`` carrying the full fingerprint —
    ``load_solutions`` derives the newest win per ``(target, symbol)`` from
    the log, so no dedup rewrite is needed here.

    ``entry.source_file`` is normalized to a project-root-relative path so all
    writers agree on the base the reader assumes.
    """
    record_ga_run(
        project_root,
        target=entry.target,
        va="",
        symbol=entry.symbol,
        matched=True,
        score=entry.score,
        generations=entry.generations,
        cflags=entry.cflags,
        size=entry.size,
        source_file=_relative_source(project_root, entry.source_file),
        mutations=list(entry.mutations),
        solved_at=entry.solved_at,
    )


def save_solutions(project_root: Path, entries: list[SolutionEntry]) -> None:
    """Record solution wins (batch form — one append per entry, no rewrite).

    Same record as :func:`save_solution`; the log is append-only so a batch
    costs N line-appends, never a whole-file read-modify-write.
    """
    for entry in entries:
        save_solution(project_root, entry)


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
# GA run log — one append-only JSONL for every outcome (wins + losses).
# ---------------------------------------------------------------------------
#
# Wins carry the full solution fingerprint, so `load_solutions` derives the
# winning entry per (target, symbol) from this same log — no second file.


def record_ga_run(
    project_root: Path,
    *,
    target: str,
    va: str | int,
    symbol: str,
    matched: bool,
    score: float | None = None,
    generations: int = 0,
    rng_seed: int | None = None,
    cflags: str = "",
    size: int = 0,
    source_file: str = "",
    mutations: list[str] | None = None,
    solved_at: str = "",
) -> Path:
    """Append one GA outcome to ``.rebrew/ga_runs.jsonl`` (append-only).

    Win-only fields (*cflags*, *size*, *source_file*, *mutations*) turn the
    record into a solution fingerprint readable by ``load_solutions``.
    *rng_seed* is the seed the GA ran from; replay the stub with
    ``rebrew match --seed <rng_seed>``.
    """
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
    if rng_seed is not None:
        record["rng_seed"] = rng_seed
    if matched:
        # Solution fingerprint (see SolutionEntry) — only wins seed later runs.
        record["cflags"] = cflags
        record["size"] = size if isinstance(size, int) and not isinstance(size, bool) else 0
        if source_file:
            record["source_file"] = source_file
        if mutations:
            record["mutations"] = list(mutations)
        record["solved_at"] = solved_at or datetime.now(UTC).isoformat()
    p = _ensure_runs_dir(project_root)
    line = json.dumps(record) + "\n"
    with _ga_runs_append_lock(p), p.open("a", encoding="utf-8") as f:
        f.write(line)
    return p


def load_ga_runs(
    project_root: Path,
    *,
    target: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Read recent GA run records, newest first, optionally filtered by *target*.

    Malformed lines are skipped.  Returns at most *limit* records.

    Uses a bounded deque (maxlen=limit): the log is append-only and
    chronological, so only the newest ``limit`` records can be returned —
    keeping the whole (unbounded) history in memory per call was wasted
    work once the log grows past thousands of runs (``--ga-history`` and
    batch ``--skip-recent`` read it every run).
    """
    from collections import deque

    p = _runs_path(project_root)
    if not p.exists():
        return []
    # Bounded deque: the log is append-only and chronological, so only the
    # newest ``limit`` records can be returned.  The bound is applied AFTER
    # target filtering so "limit" means "up to limit records for this
    # target" (a filtered target must not lose its older records to other
    # targets' newer ones).
    records: deque[dict[str, Any]] = deque(maxlen=limit)
    try:
        fh = p.open(encoding="utf-8")
    except OSError:
        log.warning("Cannot read GA run log %s", p, exc_info=True)
        return []
    bad_lines = 0
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                bad_lines += 1
                continue
            if not isinstance(record, dict):
                continue
            if target and record.get("target") != target:
                continue
            records.append(record)
    if bad_lines:
        log.warning(
            "Skipped %d malformed line(s) in GA run log %s — check for truncated writes",
            bad_lines,
            p,
        )
    out = list(records)
    out.reverse()  # newest first
    return out
