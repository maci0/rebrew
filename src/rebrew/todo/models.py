"""Data models, category constants, ROI scoring, extern cache, and verify-cache loading for todo."""

import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
lazy import json
lazy import math
lazy import os
lazy from collections.abc import Callable, Sequence
lazy from pathlib import Path

if TYPE_CHECKING:
    from rebrew.config import ProjectConfig
    from rebrew.verify.cache import VerifyCacheEntry

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Category constants
# ---------------------------------------------------------------------------

CAT_SETUP = "setup"
CAT_COMPILE_ERROR = "compile-error"
CAT_EXTRACT_ERROR = "extract-error"
CAT_FIX_DELTA = "fix-delta"
CAT_IMPROVE_MATCH = "improve-match"
CAT_START_FUNCTION = "start-function"
CAT_MISSING_ANNOTATION = "missing-annotation"
CAT_IDENTIFY_LIBRARY = "identify-library"
CAT_RUN_PROVER = "run-prover"
CAT_DOCUMENTED = "documented"
# Byte-exact via a generated naked skeleton (`source = "naked"`) — reproduced,
# NOT decompiled: it stays on the list until the real C body matches.
CAT_NAKED = "naked-reconstruction"
# Data symbol whose built bytes differ from the reference (`verify --data`
# wrote STATUS DRIFT in rebrew-data.toml).
CAT_DATA_DRIFT = "data-drift"
# Data symbol never verified (STATUS UNCHECKED or absent in rebrew-data.toml).
CAT_START_DATA = "start-data"
# RELOC match: byte-identical only after relocation masking, so the compiler /
# linker output is not identical on its own.  Closing it needs EXACT.
CAT_EXACT_ONLY = "exact-only"
# Span whose bytes in the shipped image a postlink fixer rewrote, so they are
# not what the toolchain emitted.  Needs a configured `raw_link` to detect.
CAT_POSTLINK = "postlink-mangled"

# Proving is only feasible when few bytes actually differ: symbolic execution
# over hundreds of mismatched bytes just times out.  Cap the estimated byte
# delta for measured (verify-cached) candidates; unmeasured ones stay eligible.
PROVE_MAX_DIFF_BYTES = 8

#: Largest function the angr prover is offered.  Symbolic execution over a
#: multi-kilobyte body exhausts its timeout regardless of how few bytes
#: differ, so the queue is capped by extent as well as by delta.  Unrelated to
#: the ROI size bands in ``calculate_roi``, which rank effort, not feasibility.
PROVE_MAX_FUNC_BYTES = 500

#: Blocker substrings that mark a STUB as a documented *non-target* (intake /
#: document-unmatched write these for IAT import thunks and Delphi application
#: code).  Such functions are explicitly not decomp work — they must never be
#: suggested as fix-delta quick-wins or flag-sweep targets.
NON_TARGET_MARKERS = ("not a decomp target", "not reproducible")

DATA_CATEGORIES = frozenset({CAT_DATA_DRIFT, CAT_START_DATA})

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TodoItem:
    """A single prioritized action item."""

    category: str
    roi_score: float
    va: int
    name: str
    size: int
    filename: str
    description: str
    command: str
    byte_delta: int | None = None
    difficulty: int = 0
    status: str = ""
    match_percent: float | None = None
    mutations: list[str] = field(default_factory=list)
    blocker: str = ""
    impact_bytes: int = 0
    affected_functions: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        d: dict[str, Any] = {
            "category": self.category,
            "roi_score": round(self.roi_score, 1),
            "va": f"0x{self.va:08x}",
            "name": self.name,
            "size": self.size,
            "filename": self.filename,
            "description": self.description,
            "command": self.command,
            "impact_bytes": self.impact_bytes,
            "affected_functions": self.affected_functions,
        }
        if self.byte_delta is not None:
            d["byte_delta"] = self.byte_delta
        if self.difficulty:
            d["difficulty"] = self.difficulty
        if self.status:
            d["status"] = self.status
        if self.match_percent is not None:
            d["match_percent"] = self.match_percent
        if self.mutations:
            d["mutations"] = self.mutations
        if self.blocker:
            d["blocker"] = self.blocker
        return d


#: Item fields accepted by ``--fields``. Optional fields may be absent from a row.
TODO_FIELDS = tuple(TodoItem.__dataclass_fields__)


def select_item_fields(items: list[TodoItem], selected: list[str] | None) -> list[dict[str, Any]]:
    """Project JSON rows without changing pagination or envelope metadata."""
    rows = [item.to_dict() for item in items]
    if selected is None:
        return rows
    return [{name: row[name] for name in selected if name in row} for row in rows]


def item_domain(item: TodoItem) -> str:
    """``data`` or ``code``. The two do not replace each other at one address."""
    if item.category in DATA_CATEGORIES:
        return "data"
    return "code"


# ---------------------------------------------------------------------------
# Unified Continuous Scoring & Impact Ranking
# ---------------------------------------------------------------------------


def calculate_roi(size: int, match_pct: float | None, delta: int | None) -> float:
    """Estimate effort for breaking ties between equally sized work scopes.

    User Workflow Heuristic: Higher match percentage is often HARDER to finish
    because it implies fighting the compiler (register allocation, instruction scheduling).
    Therefore, rewrite tasks (low match) win effort ties over near-match tasks,
    unless the near-match task has a small, actionable byte delta.
    """
    if match_pct is None:
        match_pct = 0.0
    # 0-100 only: a percent above 100 (corrupt cache row) drives the base
    # score negative and would rank a function as easier than a fresh one.
    # Non-finite reads as unmeasured (0.0): max/min with NaN is
    # order-dependent and silently passed the garbage through as a mid score.
    if not math.isfinite(match_pct):
        match_pct = 0.0
    match_pct = max(0.0, min(100.0, match_pct))

    # Invert the score: 0% match = 65 base, 100% match = 25 base
    base_score = 65.0 - (match_pct * 0.4)

    modifier = 0.0

    # 1. Delta Boosts (Small explicit byte differences are quick wins)
    if delta is not None:
        if delta <= 4:
            modifier += 25.0
        elif delta <= 20:
            modifier += 15.0

    # 2. Size Modifiers (Smaller functions are easier to cognitively load and rewrite)
    if size < 50:
        modifier += 15.0
    elif size < 150:
        modifier += 10.0
    elif size < 300:
        modifier += 5.0
    elif size > 1000:
        modifier -= 15.0
    elif size > 500:
        modifier -= 5.0

    # 3. Stubborn Diff Penalty (High match >= 90%, no explicit small delta)
    if match_pct >= 90.0 and (delta is None or delta > 20):
        modifier -= 15.0

    final_score = base_score + modifier
    return min(89.0, max(1.0, final_score))


def rank_by_impact(items: list[TodoItem]) -> list[TodoItem]:
    """Rank unfinished scope first and collapse shared translation-unit errors."""
    from rebrew.utils import merged_span_bytes

    audits = {CAT_EXACT_ONLY, CAT_POSTLINK}
    definitions = {CAT_COMPILE_ERROR, CAT_IMPROVE_MATCH, CAT_FIX_DELTA, CAT_RUN_PROVER, CAT_NAKED}
    files: dict[str, list[TodoItem]] = {}
    errors: dict[str, list[TodoItem]] = {}
    for item in items:
        item.impact_bytes = max(0, item.size)
        is_code = item_domain(item) == "code"
        item.affected_functions = int(item.category != CAT_SETUP and is_code)
        if item.filename and is_code and item.category in definitions:
            files.setdefault(item.filename, []).append(item)
            if item.category == CAT_COMPILE_ERROR:
                errors.setdefault(item.filename, []).append(item)
    suppressed: set[int] = set()
    for filename, failures in errors.items():
        affected = files[filename]
        first = min(failures, key=lambda item: item.va)
        first.impact_bytes = merged_span_bytes(
            [(item.va, item.va + item.size) for item in affected if item.size > 0]
        )
        first.affected_functions = len(affected)
        if len(affected) > 1:
            first.description += f" — {len(affected)} unfinished functions in {filename}"
        suppressed.update(id(item) for item in failures if item is not first)

    def order(item: TodoItem) -> tuple[int, int, float, int]:
        tier = (
            0
            if item.category == CAT_SETUP
            else 3
            if item.category == CAT_DOCUMENTED
            else 2
            if item.category in audits
            else 1
        )
        return tier, -item.impact_bytes, -item.roi_score, item.va

    return sorted((item for item in items if id(item) not in suppressed), key=order)


# ---------------------------------------------------------------------------
# Caller hints & extern-names cache
# ---------------------------------------------------------------------------

# Process-local extern names. The JSON file is the next process's cache.
# Bounded: one entry holds every source in a project, so a long-lived process
# that visits many roots must not retain each project's source names until exit.
EXTERN_CACHE: dict[str, dict[str, Any]] = {}
EXTERN_CACHE_MAX = 8
#: Guarded: the bounded insert is a multi-step next(iter)+pop on the shared
#: dict, and batch callers can materialize stubs from more than one thread.
EXTERN_CACHE_LOCK = threading.Lock()
#: Bump when the parser or the recorded name shape changes.  The per-file
#: stat only says the source did not change; it says nothing about the code
#: that produced the names, so a deploy must not reuse older semantics.
EXTERN_CACHE_VERSION = 2


def extern_path_key(path: Path) -> str:
    """Return a canonical string key for *path* without needless resolves."""
    # The source walk yields real absolute paths, so only a relative spelling
    # (or a symlinked config root) needs the component walk.
    if path.is_absolute():
        return str(path)
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def display_path(path: Path, base: Path, base_text: str) -> str:
    """``rel_display_path`` without a path walk for a plain descendant."""
    # base_text is the reversed root plus a trailing separator, and the
    # walk yields host paths.  posix_child slices either spelling; a path
    # with "." or a doubled separator still needs the full walk.
    from rebrew.utils import posix_child, rel_display_path

    root = base_text[:-1] if base_text.endswith(("/", "\\")) else base_text
    relative = posix_child(str(path), root)
    if relative and "//" not in relative and "/./" not in relative:
        return relative
    return rel_display_path(path, base)


def extern_source_stamp(path: Path) -> list[int] | None:
    """Return stat fingerprint ``[mtime_ns, size, ino, ctime_ns]`` for *path*."""
    try:
        stat = path.stat()
    except OSError:
        return None
    return [stat.st_mtime_ns, stat.st_size, stat.st_ino, stat.st_ctime_ns]


def extern_cache_dir(cfg: ProjectConfig) -> Path:
    """Directory holding ``.rebrew/extern-names.json`` for *cfg*."""
    directory = getattr(cfg, "metadata_dir", None) or cfg.reversed_dir
    return Path(directory)


def extern_entry(raw: object) -> dict[str, Any] | None:
    """Validate one persisted extern-names cache record."""
    if not isinstance(raw, dict):
        return None
    stamp = raw.get("stamp")
    names = raw.get("names")
    if (
        not isinstance(stamp, list)
        or len(stamp) != 4
        or any(type(part) is not int for part in stamp)
        or not isinstance(names, list)
        or any(not isinstance(name, str) for name in names)
    ):
        return None
    return {"stamp": stamp, "names": names}


def begin_extern_cache(directory: Path) -> dict[str, Any]:
    """Load or return the process-local extern-names cache record for *directory*."""
    key = extern_path_key(directory)
    with EXTERN_CACHE_LOCK:
        cached = EXTERN_CACHE.get(key)
    if cached is not None:
        return cached
    files: dict[str, dict[str, Any]] = {}
    cache_path = directory / ".rebrew" / "extern-names.json"
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        if cache_path.exists():
            logging.getLogger(__name__).warning(
                "Ignoring unreadable extern-names cache %s: %s", cache_path, exc
            )
        payload = None
    if isinstance(payload, dict) and payload.get("version") == EXTERN_CACHE_VERSION:
        stored_files = payload.get("files")
        if isinstance(stored_files, dict):
            for path_key, raw in stored_files.items():
                parsed = extern_entry(raw)
                if isinstance(path_key, str) and parsed is not None:
                    files[path_key] = parsed
    # One lock per record: concurrent batch callers share this object, and its
    # file map is mutated by a scan while its flush serializes it.  The outer
    # dict lock only guards the bounded insert and the re-check: a caller that
    # missed the first lookup left the lock to read the same cache file, and
    # publishing its own record would replace the map a peer is already
    # filling, so both scans would flush a different partial map.
    record: dict[str, Any] = {
        "dir": directory,
        "files": files,
        "dirty": False,
        "lock": threading.Lock(),
    }
    with EXTERN_CACHE_LOCK:
        existing = EXTERN_CACHE.get(key)
        if existing is not None:
            return existing
        if len(EXTERN_CACHE) >= EXTERN_CACHE_MAX:
            EXTERN_CACHE.pop(next(iter(EXTERN_CACHE)), None)
        EXTERN_CACHE[key] = record
    return record


def extern_cache_remember(
    cache: dict[str, Any], path: Path, stamp: list[int], names: list[str]
) -> None:
    """Record one source's extern names under the record lock."""
    key = extern_path_key(path)
    with cache["lock"]:
        cache["files"][key] = {"stamp": stamp, "names": names}
        cache["dirty"] = True


def flush_extern_cache(
    cache: dict[str, Any],
    *,
    write_text: Callable[..., Any] | None = None,
) -> None:
    """Write extern names for the next process. A failure leaves the counts.

    Snapshot and write share the record lock so a remember that lands during
    the write cannot be marked clean without reaching the file.
    """
    from rebrew.utils import atomic_write_text

    writer = write_text or atomic_write_text
    with cache["lock"]:
        if not cache.get("dirty"):
            return
        cache_path = Path(cache["dir"]) / ".rebrew" / "extern-names.json"
        try:
            writer(
                cache_path,
                json.dumps(
                    {"version": EXTERN_CACHE_VERSION, "files": cache["files"]},
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
        except OSError:
            return
        cache["dirty"] = False


def caller_counts(
    cfg: ProjectConfig,
    matched_files: set[str] | None = None,
    *,
    scanned: Sequence[Path] | None = None,
) -> dict[str, int]:
    """Count unresolved callers per callee name from extern declarations.

    Scans reversed sources for ``extern`` function declarations: each file
    whose own function is still unmatched counts as one unresolved caller
    of every extern callee it declares.  Best-effort (unparseable files
    skipped); returns ``{callee name: caller count}``.

    *matched_files* (relative paths, from the metadata store) are skipped: a
    caller that is already byte-matched no longer needs its callees
    implemented, so it must not add an effort bonus or a reference hint.
    The skip happens after the name lookup, so a matched file still fills
    the cache. Unchanged sources reuse ``.rebrew/extern-names.json``. A
    source that does not contain ``extern`` is stored empty and is not parsed.
    """
    from rebrew.c_syntax.parser import find_extern_function_names
    from rebrew.source.discovery import iter_sources
    from rebrew.utils import read_source_text

    counts: dict[str, int] = {}
    try:
        files = list(iter_sources(cfg.reversed_dir, cfg, scanned=scanned))
    except OSError:
        return counts
    cache = begin_extern_cache(extern_cache_dir(cfg))
    base = Path(cfg.reversed_dir)
    # The trailing separator is the host's: rstrip("/") leaves a Windows
    # drive path untouched and the child slice then never matches.
    base_text = str(base).rstrip("/\\") + os.sep
    for path in files:
        key = extern_path_key(path)
        stamp = extern_source_stamp(path)
        with cache["lock"]:
            entry = cache["files"].get(key)
        if stamp is not None and entry is not None and entry["stamp"] == stamp:
            names = entry["names"]
        else:
            try:
                text = read_source_text(path)[0]
            except OSError as exc:
                # Its externs contribute no call counts, which would misrank the
                # work list.  Say which file was dropped.
                log.warning("skipping unreadable source %s: %s", path, exc)
                continue
            names = [] if "extern" not in text else find_extern_function_names(text)
            if stamp is not None:
                extern_cache_remember(cache, path, stamp, names)
        if matched_files and display_path(path, base, base_text) in matched_files:
            continue
        for callee in names:
            counts[callee] = counts.get(callee, 0) + 1
    flush_extern_cache(cache)
    return counts


def caller_boost(name: str, caller_counts_map: dict[str, int] | None) -> float:
    """Effort tie-break bonus for unfinished-source declaration hints."""
    if not caller_counts_map:
        return 0.0
    callers = caller_counts_map.get(name, 0) + caller_counts_map.get("_" + name, 0)
    return min(15.0, 5.0 * callers)


def caller_suffix(desc: str, name: str, caller_counts_map: dict[str, int] | None) -> str:
    """Report declaration hints without claiming proven blocked callers."""
    if not caller_counts_map:
        return desc
    callers = caller_counts_map.get(name, 0) + caller_counts_map.get("_" + name, 0)
    if callers <= 0:
        return desc
    return f"{desc} — declared by {callers} unfinished source file(s)"


# ---------------------------------------------------------------------------
# Verify cache loading
# ---------------------------------------------------------------------------


def load_verify_entries(cfg: ProjectConfig) -> dict[str, VerifyCacheEntry]:
    """Load compatible verify cache entries keyed by canonical VA.

    Return an empty mapping if the cache is missing, unreadable, or fails
    the shared identity check used by status and verify.
    """
    from rebrew.verify.cache import load_verify_cache_raw

    raw = load_verify_cache_raw(cfg)
    if raw is None:
        return {}
    try:
        from rebrew.verify.cache import VerifyCache

        data = VerifyCache.from_dict(raw)
    except (ValueError, AttributeError, ImportError, TypeError) as exc:
        # An unreadable cache is not the same verdict as an empty one: every
        # category below is derived from these entries, so returning {} here
        # makes "your cache does not parse" print as "nothing to do".
        log.warning(
            "verify cache at %s is unreadable (%s: %s); todo is reporting against an empty cache",
            cfg.reversed_dir,
            type(exc).__name__,
            exc,
        )
        return {}
    # One shared identity guard: version, target, compiler config, and binary.
    # Re-deriving it here is how todo came to accept a cache the compile path
    # rejects — another target's entries surfaced as phantom quick-wins, and a
    # cache earned under a superseded compiler config kept driving categories
    # and deltas after `rebrew verify` had stopped serving it.
    from rebrew.verify.cache import cache_identity_matches

    if not cache_identity_matches(raw, cfg):
        return {}
    # Re-key canonically: a cached VA may be spelled "0x1000" instead of
    # "0x00001000" (the union in
    # `collect_active_functions` already normalizes with `canonical_va_key`,
    # and every consumer looks entries up with
    # `f"0x{va:08x}"` — an unnormalized key was seen by the coverage header but
    # missed by the category/delta selection and the prove queue).
    from rebrew.metadata.document import canonical_va_key

    normalized: dict[str, VerifyCacheEntry] = {}
    for key, entry in data.entries.items():
        va = canonical_va_key(key)
        normalized[f"0x{va:08x}" if isinstance(va, int) else str(key)] = entry
    return normalized


__all__ = [
    "CAT_COMPILE_ERROR",
    "CAT_DATA_DRIFT",
    "CAT_DOCUMENTED",
    "CAT_EXACT_ONLY",
    "CAT_EXTRACT_ERROR",
    "CAT_FIX_DELTA",
    "CAT_IDENTIFY_LIBRARY",
    "CAT_IMPROVE_MATCH",
    "CAT_MISSING_ANNOTATION",
    "CAT_NAKED",
    "CAT_POSTLINK",
    "CAT_RUN_PROVER",
    "CAT_SETUP",
    "CAT_START_DATA",
    "CAT_START_FUNCTION",
    "DATA_CATEGORIES",
    "EXTERN_CACHE",
    "EXTERN_CACHE_LOCK",
    "EXTERN_CACHE_MAX",
    "EXTERN_CACHE_VERSION",
    "NON_TARGET_MARKERS",
    "PROVE_MAX_DIFF_BYTES",
    "PROVE_MAX_FUNC_BYTES",
    "TODO_FIELDS",
    "TodoItem",
    "begin_extern_cache",
    "calculate_roi",
    "caller_boost",
    "caller_counts",
    "caller_suffix",
    "display_path",
    "extern_cache_dir",
    "extern_cache_remember",
    "extern_entry",
    "extern_path_key",
    "extern_source_stamp",
    "flush_extern_cache",
    "item_domain",
    "load_verify_entries",
    "rank_by_impact",
    "select_item_fields",
]
