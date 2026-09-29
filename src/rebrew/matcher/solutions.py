"""solutions.py – Cross-function solution transfer database.

Records GA solution fingerprints (cflags, size) when functions reach
EXACT match. Seeds new GA runs from solved functions of the closest size
(same target first, matching cflags as tie-break) to reduce convergence time.

Storage: ``.rebrew/ga_runs.jsonl`` — one log line per GA
outcome, appended on the fly.  A win record carries the full solution
fingerprint (cflags, size, source, mutations); ``load_solutions`` derives
the winning entry per ``(target, symbol)`` (newest win) from the log.
Losses stay for ``--skip-recent`` / ``--ga-history``, capped at
``_LOSS_RECORD_RETENTION`` so the log does not grow without bound; wins are
never pruned.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import hashlib
import json
import logging
import math
import os
import threading
from collections import OrderedDict
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

    Same discipline as :func:`rebrew.metadata_doc.metadata_write_lock`: the thread
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

    source_sha: str = ""
    """SHA-256 of ``source_file`` at win time; empty when it could not be read.

    A solution is a claim about a specific source: its ``cflags`` and
    ``mutations`` were derived from those exact bytes.  Seeding a later GA
    from a file that has since changed hands back a stale, and a
    stale *successful* seed biases the run harder than no seed at all, so
    :func:`find_similar` drops a solution whose file no longer hashes to
    this value.  Empty means "unpinned" (a legacy record, or an unreadable
    file at win time) and is kept — the store degrades to its old
    behaviour instead of discarding every pre-existing win."""


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
        if isinstance(entry.mutations, str):
            return None  # a bare string would splat per character
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
    ):
        return None
    # A null score is a win whose GA fitness was not finite; the fingerprint
    # is still good, so the record seeds later runs with the field default
    # rather than being dropped.
    if entry.score is None:
        entry = dataclasses.replace(entry, score=0.0)
    elif not isinstance(entry.score, (int, float)) or isinstance(entry.score, bool):
        return None
    return entry


def _wins_from_records(path: Path) -> list[SolutionEntry]:
    """Newest winning entry per ``(target, symbol)`` from the run log at *path*.

    Records that are not usable wins are skipped; the log order makes the
    last entry for a key win.
    """
    wins: dict[tuple[str, str], SolutionEntry] = {}
    for rec in _iter_run_records(path):
        if not rec.get("matched"):
            continue
        entry = _entry_from_record(rec)
        if entry is not None:
            wins[(entry.target, entry.symbol)] = entry
    return sorted(wins.values(), key=lambda e: (e.target, e.symbol))


def load_solutions(project_root: Path) -> list[SolutionEntry]:
    """Load winning solution entries (newest win per ``(target, symbol)``).

    Derived from ``.rebrew/ga_runs.jsonl`` win records.  Returns [] when
    nothing is stored (never raises).
    """
    return _wins_from_records(_runs_path(project_root))


def _iter_run_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield dict records from a JSONL file (skips malformed lines)."""
    if not path.exists():
        return
    try:
        fh = path.open(encoding="utf-8", errors="replace")
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

    Supports cross-project seeding: ``rebrew match --seed-solutions-file
    ../other-project/.rebrew/ga_runs.jsonl`` transfers winning
    cflags/source fingerprints between projects sharing a compiler.
    Returns an empty list when the file is missing or malformed (never
    raises).
    """
    return _wins_from_records(path)


#: Bounded ``(path, mtime_ns, size, ino) -> sha256`` memo for
#: :func:`_source_sha`.  Batch seeding calls :func:`find_similar` once per
#: stub with the same preloaded entry list, so without this the same handful
#: of sources would be re-hashed once per stub.
_SOURCE_SHA_CACHE_MAX = 128

#: Bounded cache for :func:`_normalize_cflags`; one entry per distinct
#: cflags string in the solution DB plus the caller's own.
_NORMALIZED_CFLAGS_CACHE = 256
_SOURCE_SHA_CACHE: OrderedDict[tuple[str, int, int, int], str] = OrderedDict()
_SOURCE_SHA_LOCK = threading.Lock()


def _source_sha(path: Path) -> str:
    """SHA-256 of *path*, or "" when it cannot be read.

    Keyed on the file's inode metadata, so an in-place edit that changes size
    or mtime re-hashes; a missing or unreadable file returns "",
    which :func:`_is_stale` treats as "unverifiable, keep".
    """
    try:
        st = path.stat()
    except OSError:
        return ""
    key = (str(path), st.st_mtime_ns, st.st_size, st.st_ino)
    with _SOURCE_SHA_LOCK:
        hit = _SOURCE_SHA_CACHE.get(key)
        if hit is not None:
            _SOURCE_SHA_CACHE.move_to_end(key)
            return hit
    try:
        with path.open("rb") as fh:
            digest = hashlib.file_digest(fh, "sha256").hexdigest()
    except OSError:
        return ""
    with _SOURCE_SHA_LOCK:
        if key not in _SOURCE_SHA_CACHE and len(_SOURCE_SHA_CACHE) >= _SOURCE_SHA_CACHE_MAX:
            _SOURCE_SHA_CACHE.popitem(last=False)
        _SOURCE_SHA_CACHE[key] = digest
    return digest


def _is_stale(project_root: Path, entry: SolutionEntry) -> bool:
    """Whether *entry*'s source file changed since the win.

    Unpinned entries (no ``source_sha``, or a source that cannot be read) are
    never stale: the store keeps every pre-existing win rather than
    discarding wins it cannot verify.
    """
    if not entry.source_sha or not entry.source_file:
        return False
    p = Path(entry.source_file)
    if not p.is_absolute():
        p = project_root / p
    current = _source_sha(p)
    return bool(current) and current != entry.source_sha


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
    writers agree on the base the reader assumes.  The file's content hash is
    recorded at win time so :func:`find_similar` can drop the solution once
    the source moves on.
    """
    relative = _relative_source(project_root, entry.source_file)
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
        source_file=relative,
        source_sha=entry.source_sha or _source_sha(project_root / relative),
        mutations=list(entry.mutations),
        solved_at=entry.solved_at,
    )


def save_solutions(project_root: Path, entries: list[SolutionEntry]) -> None:
    """Record solution wins (batch form — one append per entry, no rewrite).

    Same record as :func:`save_solution`; the log is append-only so a batch
    costs N line-appends, never a whole-file read-modify-write.

    Entries append in entry-identity order, not caller order: parallel
    batch workers fill the list in completion order, and
    :func:`find_similar` breaks ties by file order.
    """
    # The key is total over the entry, so two wins recorded for one
    # (target, symbol) land in the same order whichever thread finished
    # first.  Sorting on (target, symbol) alone left the duplicate pair in
    # caller order, and the log keeps the later of the pair — so under -j N
    # thread timing, not the seed, decided which win was kept.
    for entry in sorted(
        entries, key=lambda e: (e.target, e.symbol, e.source_file, e.score, e.source_sha)
    ):
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

    A solution whose source file has changed since the win is dropped: its
    ``cflags`` and ``mutations`` describe bytes that no longer exist, and
    seeding from it biases the run toward flags the file no longer needs.
    Ranking happens first, so *top_k* is filled from the freshest
    candidates rather than short when a near-size match went stale.

    Returns up to *top_k* entries, sorted by similarity (best first).
    """
    all_entries = list(load_solutions(project_root) if entries is None else entries)
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
    fresh: list[SolutionEntry] = []
    for e in all_entries:
        if len(fresh) == top_k:
            break
        if not _is_stale(project_root, e):
            fresh.append(e)
    return fresh


@functools.lru_cache(maxsize=_NORMALIZED_CFLAGS_CACHE)
def _normalize_cflags(cflags: str) -> str:
    """Normalize cflags for comparison: strip /nologo /c /fo* /fe*, sort remainder case-insensitively.

    Cached: the result depends only on the string, and ranking a batch of
    solutions normalizes every entry on every call.
    """
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
#
# Replaying a stub (same seed, same source, same outcome) writes the same
# record again, so a repeat already in the log is dropped rather than
# appended: every consumer counts records (`--skip-recent`, `--ga-history`),
# and a duplicate says "ran twice" where the truth is "ran once, re-entered".
# The check spans the whole tail window, not just the final line, because a
# batch (`match --all`) appends one record per stub and a replayed batch only
# ever matches its own last record, never the first one it repeats.

#: Fields that differ between two otherwise identical runs.
_VOLATILE_RECORD_FIELDS = frozenset({"ts", "solved_at"})

#: How far back the repeat check reads.  Sized to hold a full-project batch
#: replay (a record is a few hundred bytes); a repeat that falls outside it is
#: appended, which is safe: the only cost of a miss is the duplicate the drop
#: was meant to avoid.
_TAIL_READ_BYTES = 1024 * 1024

#: How far before the window the tail read reaches to cover the record the
#: window opens inside.  A record is a few hundred bytes; this is the slack
#: that keeps one oversized line from putting the whole tail out of reach.
_TAIL_ALIGN_BYTES = 64 * 1024

#: Non-winning records the log keeps, and the log size that triggers a
#: prune.  The floor sits well above the repeat-check window, so a prune
#: never shrinks the log below what that window already read.
_LOSS_RECORD_RETENTION = 20_000
_PRUNE_MIN_BYTES = 4 * _TAIL_READ_BYTES


def _recent_records(path: Path) -> list[dict[str, Any]]:
    """Return the well-formed records in the tail window of *path*, oldest first.

    A torn or malformed line is skipped rather than aborting the scan: one
    unreadable line must not turn every later append into a duplicate.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            start = max(0, size - _TAIL_READ_BYTES)
            # Reach back far enough to cover the record the window opens
            # inside; its head is before `start`, so the window alone yields a
            # truncated line that json cannot read and the repeat check misses.
            aligned = max(0, start - _TAIL_ALIGN_BYTES)
            fh.seek(aligned)
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = tail.splitlines()
    if aligned:
        # The reach-back does not know where a record starts either, so the
        # first line is partial whenever the read clipped. Drop it alone.
        lines = lines[1:]
    records: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _run_key(record: dict[str, Any]) -> str:
    """Identity of the run a record describes, clock fields aside.

    Sorted, so two records differing only in JSON key order compare equal.
    """
    return json.dumps(
        {k: v for k, v in record.items() if k not in _VOLATILE_RECORD_FIELDS},
        sort_keys=True,
        default=str,
    )


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
    source_sha: str = "",
    mutations: list[str] | None = None,
    solved_at: str = "",
) -> Path:
    """Append one GA outcome to ``.rebrew/ga_runs.jsonl`` (append-only).

    Win-only fields (*cflags*, *size*, *source_file*, *mutations*) turn the
    record into a solution fingerprint readable by ``load_solutions``.
    *rng_seed* is the seed the GA ran from; replay the stub with
    ``rebrew match --seed <rng_seed>``.

    A record identical to one already in the log's tail window apart from
    *ts* / *solved_at* is a replay of a run already recorded, so it is
    dropped: re-running a seed, alone or as a batch, must not inflate the
    count ``--skip-recent`` and ``--ga-history`` read.

    The record is on disk before this returns (see :func:`_append_durable`):
    the log is the only copy of a run that cost hours to produce.
    """
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "target": target,
        "va": str(va),
        "symbol": symbol,
        "matched": bool(matched),
    }
    if score is not None:
        # A non-finite score is stored as null: json.dumps would write a bare
        # Infinity, which is not valid JSON and breaks every later reader.
        record["score"] = round(float(score), 2) if math.isfinite(score) else None
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
        if source_sha:
            record["source_sha"] = source_sha
        if mutations:
            record["mutations"] = list(mutations)
        record["solved_at"] = solved_at or datetime.now(UTC).isoformat()
    p = _ensure_runs_dir(project_root)
    line = json.dumps(record) + "\n"
    with _ga_runs_append_lock(p):
        if _run_key(record) in {_run_key(r) for r in _recent_records(p)}:
            return p
        _append_durable(p, line)
        _prune_loss_records(p)
    return p


def _append_durable(path: Path, line: str) -> None:
    """Append *line* to *path* and return only once it has reached the disk.

    This log is the only record of a GA outcome: a win costs the run that
    produced it, hours of compile-and-compare, and it is the fingerprint later
    runs seed from.  A buffered append acknowledged at close survives the
    process dying but not the host losing power, so the win could be gone with
    nothing left to say it ever happened.  One fsync per recorded run is
    nothing beside the run itself, and the directory is synced when the log is
    created so the file does not vanish with its own directory entry.
    """
    existed = path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o666)
    try:
        view = memoryview(line.encode("utf-8"))
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    if not existed:
        # A file created but not yet linked into a synced directory can be
        # dropped by a crash even though its own bytes were fsynced.
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            with contextlib.suppress(OSError):
                os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _prune_loss_records(path: Path) -> None:
    """Drop all but the newest ``_LOSS_RECORD_RETENTION`` non-winning records.

    Wins are never pruned: each carries a solution fingerprint
    ``load_solutions`` reads back, and losing one would strand a solved
    function.  Losses are the bulk of the log and no consumer needs the
    whole of them (``--skip-recent`` and ``--ga-history`` read a recent
    window), so an unpruned log grows forever.  A log under the size floor
    is left alone, so the cost of the check is a ``stat`` on the hot append
    path.  A line that does not parse is kept: pruning is housekeeping, not
    a filter, and dropping a record nobody can read loses data silently.
    """
    try:
        if path.stat().st_size <= _PRUNE_MIN_BYTES:
            return
    except OSError:
        return
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        log.warning("Cannot read GA run log %s for pruning", path, exc_info=True)
        return
    keep: list[bool] = []
    losses_kept = 0
    for raw in reversed(lines):
        stripped = raw.strip()
        parsed: Any = None
        if stripped:
            with contextlib.suppress(json.JSONDecodeError):
                parsed = json.loads(stripped)
        is_win = isinstance(parsed, dict) and bool(parsed.get("matched"))
        keep_now = is_win or losses_kept < _LOSS_RECORD_RETENTION
        if not is_win and keep_now:
            losses_kept += 1
        keep.append(keep_now)
    kept = [raw for raw, keep_now in zip(lines, reversed(keep), strict=True) if keep_now]
    if len(kept) == len(lines):
        return
    tmp = path.with_name(path.name + ".prune")
    try:
        tmp.write_text("".join(kept), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        log.warning("Cannot prune GA run log %s", path, exc_info=True)
        with contextlib.suppress(OSError):
            tmp.unlink()


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
    batch ``--skip-recent`` read it every run).  A consumer that needs the
    whole log (an aggregate, not a tail) iterates :func:`iter_ga_runs`.
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
        for record in iter_ga_runs(project_root, target=target):
            records.append(record)
    except OSError:
        log.warning("Cannot read GA run log %s", p, exc_info=True)
        return []
    out = list(records)
    out.reverse()  # newest first
    return out


def iter_ga_runs(project_root: Path, *, target: str = "") -> Iterator[dict[str, Any]]:
    """Yield every GA run record in *project_root*'s log, oldest first.

    Streams the append-only log, so a consumer that folds the records into
    an aggregate (the best score per function) sees the whole history
    instead of a newest-N window that silently drops an older, better run
    once the log grows past that N.  The filter is per record, so a
    targeted consumer never pays to decode another target's records.
    """
    for record in _iter_run_records(_runs_path(project_root)):
        if target and record.get("target") != target:
            continue
        yield record
