"""verify_cache.py — the verify result cache.

The cache row IS the report row: ``VerifyCacheEntry`` carries the same
verdict fields (``status``, ``va``, ``passed``, ``match_percent``,
``delta``, ...) that ``rebrew verify --json`` emits per function, plus the
cache-identity inputs (``source_hash``, ``mtime_ns``, ``cflags``,
``size``, ``headers_fp``, ``toolchain``, ``defines``) alongside — no
``result`` nesting.  ``rebrew status``/``todo``/``report`` therefore read
the same shape the report writes.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import logging
import math
import threading
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rebrew.utils import atomic_write_text, file_lock
from rebrew.utils import canonical_va_key as canonical_va_key
from rebrew.verify_hash import (
    _compiler_config_hash,
    _headers_hash,
    entry_fingerprint,
)
from rebrew.workspace.status import MATCHED_STATUSES

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rebrew.annotation import Annotation
    from rebrew.config import ProjectConfig

#: Current cache schema version (flat rows).
CACHE_VERSION = 2

#: mtime-keyed memo of the raw verify-cache JSON: status and todo both decode
#: ``.rebrew/verify_cache.json`` every run — sometimes twice per command —
#: and the decode is linear in cache size.  At most one entry per path: a
#: rewrite changes mtime/size, and keeping the old key would retain the
#: previous full JSON payload for the process lifetime.  Cap distinct paths
#: so a long-lived process that touches many project roots cannot retain
#: every decoded payload.  Guarded: eviction is a multi-step mutation on a
#: shared dict; concurrent status/todo/build-db callers must not race it.
_VERIFY_CACHE_MEMO: dict[tuple[str, int, int], dict[str, Any] | None] = {}
_VERIFY_CACHE_MEMO_MAX = 8
_VERIFY_CACHE_MEMO_LOCK = threading.Lock()


def _memo_path_key(cache_path: Path) -> str:
    """Memo key for *cache_path*: resolved, so reads and invalidation agree
    when ``cfg.root`` is relative or reached through a symlink."""
    try:
        return str(cache_path.resolve())
    except OSError:
        return str(cache_path)


def _read_cache_document(cache_path: Path) -> dict[str, Any]:
    """Parse *cache_path* as a JSON object.

    Raises ``OSError`` or ``ValueError``; the latter covers malformed JSON,
    non-UTF-8 bytes (``UnicodeDecodeError``), and a non-object document.
    """
    raw = json.loads(cache_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"not a JSON object: {type(raw).__name__}")
    return raw


def _invalidate_verify_cache_memo(cache_path: Path) -> None:
    """Drop every memo entry for *cache_path* after a write.

    ``load_verify_cache_raw`` keys on ``(path, mtime_ns, size)``.  A rewrite
    that lands in the same mtime slot with the same byte length (coarse
    filesystems, same-second agent edits, truncated status strings of equal
    width) would otherwise keep serving the pre-write JSON for the rest of
    the process — status/todo then disagree with the file ``rebrew test`` /
    ``rebrew verify`` just patched.  Mirror ``atomic_write_text``'s source-
    text memo drop.
    """
    path_key = _memo_path_key(cache_path)
    with _VERIFY_CACHE_MEMO_LOCK:
        stale = [k for k in _VERIFY_CACHE_MEMO if k[0] == path_key]
        for old in stale:
            del _VERIFY_CACHE_MEMO[old]


def load_verify_cache_raw(cfg: Any) -> dict[str, Any] | None:
    """Load the shared ``.rebrew/verify_cache.json`` as a raw dict (memoized).

    Returns ``None`` when the file is missing or corrupt.  Target/version
    validation is the caller's responsibility — readers apply their own
    guards (status vs todo differ slightly).  Memoized by (path, mtime,
    size), so repeated loads within one command are free.
    """
    cache_path = Path(cfg.root) / ".rebrew" / "verify_cache.json"
    try:
        st = cache_path.stat()
    except OSError:
        return None
    path_key = _memo_path_key(cache_path)
    key = (path_key, st.st_mtime_ns, st.st_size)
    with _VERIFY_CACHE_MEMO_LOCK:
        if key in _VERIFY_CACHE_MEMO:
            cached = _VERIFY_CACHE_MEMO[key]
            return copy.deepcopy(cached) if cached is not None else None
    raw: dict[str, Any] | None
    try:
        raw = _read_cache_document(cache_path)
    except (OSError, ValueError) as exc:
        # Log so a corrupt cache is not mistaken for a cold start.
        logging.getLogger(__name__).warning("Ignoring corrupt verify cache %s: %s", cache_path, exc)
        raw = None
    with _VERIFY_CACHE_MEMO_LOCK:
        # Another thread may have filled the same key while we decoded.
        if key in _VERIFY_CACHE_MEMO:
            cached = _VERIFY_CACHE_MEMO[key]
            return copy.deepcopy(cached) if cached is not None else None
        # Drop prior fingerprints for this path before storing — otherwise each
        # verify rewrite orphans a full decoded dict under the old mtime key.
        stale = [k for k in _VERIFY_CACHE_MEMO if k[0] == path_key]
        for old in stale:
            del _VERIFY_CACHE_MEMO[old]
        # Evict another path's entry when at capacity (FIFO on insertion order).
        while len(_VERIFY_CACHE_MEMO) >= _VERIFY_CACHE_MEMO_MAX:
            oldest = next(iter(_VERIFY_CACHE_MEMO))
            del _VERIFY_CACHE_MEMO[oldest]
        _VERIFY_CACHE_MEMO[key] = raw
    return copy.deepcopy(raw) if raw is not None else None


#: Verdict fields shared by the report row and the cache row — one shape,
#: two envelopes.  The cache adds the identity inputs alongside (see
#: VerifyCacheEntry); the report nests rows under ``results``.
#: ``module`` rides along so a re-annotated function (same VA, new module)
#: cannot be served a stale verdict earned under its old module.
RESULT_FIELDS: tuple[str, ...] = (
    "status",
    "va",
    "size",
    "filepath",
    "name",
    "symbol",
    "module",
    "delta",
    "match_percent",
    "passed",
    "message",
    "similarity",
    "reg_delta",
    "effective_match",
    # report-only extras, carried so a cached row re-serves byte-identically
    "diff_lines",
    "context_hash",
)


@dataclass
class VerifyCacheEntry:
    """One cached verdict: the report row + its cache-identity inputs, flat.

    No ``result`` nesting — the verdict fields ARE the entry's fields, so
    ``rebrew status``/``todo``/``report`` read the same keys ``rebrew verify
    --json`` emits.
    """

    status: str = ""
    va: str | int = ""
    size: int = 0
    filepath: str = ""
    name: str = ""
    symbol: str = ""
    module: str = ""
    delta: int | None = None
    match_percent: float | None = None
    passed: bool = False
    message: str = ""
    similarity: float | None = None
    reg_delta: int | None = None
    effective_match: bool = False
    diff_lines: int | None = None
    context_hash: str | None = None
    source_hash: str = ""
    mtime_ns: int = 0
    cflags: str = ""
    """Per-function CFLAGS used for the cached run.

    CFLAGS live in ``rebrew-functions.toml``, not in the ``.c`` file, so the
    source hash alone cannot detect a flag change (``rebrew match
    --fix-cflags`` rewrites metadata and leaves the source untouched).
    Entries written before this field existed carry ``""`` and are re-verified
    once."""

    headers_fp: str = ""
    """Per-source header-dependency fingerprint (reached ``#include`` closure).

    Computed via ``compile_cache.header_dependency_hash`` over the same
    search dirs the compile uses, so editing a header re-verifies exactly the
    entries whose source reaches it.  This replaced the global
    ``headers_hash`` gate, which invalidated *every* entry on any header
    change.  Entries written before this field existed carry ``""`` and are
    re-verified once."""

    toolchain: str = ""
    """Resolved per-function toolchain override at cache time (e.g. ``watcom-2.0-win32``).

    The TOOLCHAIN field lives in ``rebrew-functions.toml`` / ``rebrew-libraries.toml``,
    not in the ``.c`` file, so the source hash cannot detect a toolchain
    change.  Only the resolved *cflags* were stored before this field, so a
    library ``TOOLCHAIN`` override edit served stale EXACT/RELOC for every
    function under it (the config fallback chain: per-function → per-library
    → project default).  ``"(default)"`` records "no override — project
    profile applies"; ``""`` marks a legacy entry, re-verified once."""

    defines: str = ""
    """Per-target compile-time defines at cache time (sorted, comma-joined).

    ``targets.<name>.defines`` feed ``#ifdef`` deltas in shared multi-version
    sources — they are compile inputs invisible to the source hash and the
    resolved cflags string, so a defines edit must invalidate the entry.
    ``""`` marks a legacy entry, re-verified once."""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VerifyCacheEntry:
        """Reconstruct a VerifyCacheEntry from a JSON dictionary (flat v2 form)."""
        return cls(**{f.name: d[f.name] for f in fields(cls) if f.name in d})

    def to_dict(self) -> dict[str, Any]:
        """Convert this VerifyCacheEntry to a JSON-serializable dictionary."""
        return asdict(self)

    def result_row(self) -> dict[str, Any]:
        """The report row: verdict fields only, no cache-identity inputs."""
        d = asdict(self)
        return {k: d[k] for k in RESULT_FIELDS if k in d}


@dataclass
class VerifyCache:
    """The root structure of the verification cache file."""

    version: int
    compiler_hash: str
    target: str
    entries: dict[str, VerifyCacheEntry]
    headers_hash: str = ""  # informational only — per-entry headers_fp is authoritative
    binary_id: str = ""  # SHA256 of target binary (mtime_ns + size); "" = legacy cache

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VerifyCache:
        """Reconstruct a VerifyCache from a JSON dictionary."""
        raw_entries = d.get("entries", {})
        if not isinstance(raw_entries, dict):
            raw_entries = {}
        return cls(
            version=int(d.get("version", 0)),
            compiler_hash=str(d.get("compiler_hash", "")),
            target=str(d.get("target", "")),
            headers_hash=str(d.get("headers_hash", "")),
            binary_id=str(d.get("binary_id", "")),
            entries={
                str(k): VerifyCacheEntry.from_dict(v)
                for k, v in raw_entries.items()
                if isinstance(v, dict)
            },
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert this VerifyCache to a JSON-serializable dictionary."""
        return asdict(self)


def _binary_id(cfg: ProjectConfig) -> str:
    """Stable id for the target binary (mtime_ns + size), "" when unreadable.

    Guards the verify cache: a rebuilt binary of the same target name must
    invalidate cached results, which the target-name check alone misses.
    """
    try:
        st = Path(cfg.target_binary).stat()
    except (OSError, TypeError):
        return ""
    return hashlib.sha256(f"{st.st_mtime_ns}:{st.st_size}".encode()).hexdigest()


_VERIFY_CACHE_LOCK = threading.Lock()


@contextlib.contextmanager
def _verify_cache_write_lock(cache_path: Path) -> Iterator[None]:
    """Thread + cross-process lock around a verify-cache read-modify-write.

    Same discipline as utils.py's ``metadata_write_lock``: the thread
    lock serializes in-process writers; an advisory ``flock`` on a sidecar
    ``.lock`` file serializes concurrent processes (e.g. ``rebrew verify
    --watch`` saving while ``rebrew test`` patches a promotion — without
    it, interleaved read-modify-writes silently drop one side's update and
    status/todo serve a stale entry).
    """
    with _VERIFY_CACHE_LOCK, file_lock(Path(str(cache_path) + ".lock")):
        yield


def _cache_identity_matches(raw: dict[str, Any], cfg: ProjectConfig) -> bool:
    """True when a parsed verify-cache document belongs to *cfg*'s identity.

    Single definition of the ``(target, compiler_hash)`` check shared by
    :func:`verify_cache_matches_cfg` (whole-file predicate) and
    :func:`patch_verify_cache_entries` (in-lock guard), so the two cannot
    drift.
    """
    return bool(
        raw.get("target") == cfg.target_name
        and raw.get("compiler_hash") == _compiler_config_hash(cfg)
    )


def verify_cache_matches_cfg(cache_path: Path, cfg: ProjectConfig) -> bool:
    """True when the verify cache was written for this project's identity.

    The cache stores its ``target``/``compiler_hash``/``headers_hash``/
    ``binary_id`` provenance; patchers (``rebrew test`` promoting a STATUS)
    must not write into a cache that belongs to a DIFFERENT target or
    compiler — in a multi-target project, ``rebrew test -t CLIENT`` would
    otherwise patch the entries a previous ``verify -t SERVER`` wrote, and
    the next SERVER verify would accept the whole file and serve CLIENT's
    status for SERVER functions at the same VA.

    NOTE: this reads the file WITHOUT the write lock — suitable for
    diagnostics/predicates.  Patchers must re-check the identity inside
    :func:`_verify_cache_write_lock` (as ``patch_verify_cache_entries``
    does): a check performed before acquiring the lock can be invalidated
    by a concurrent writer swapping the cache between check and patch.
    """
    if not cache_path.exists():
        return False
    try:
        data = _read_cache_document(cache_path)
    except (OSError, ValueError):
        return False
    return _cache_identity_matches(data, cfg)


def patch_verify_cache_entries(cfg: ProjectConfig, patches: list[dict[str, Any]]) -> None:
    """Apply verify-cache patches with ONE read + ONE write, guarded.

    Shared by every STATUS promotion site (``rebrew test``, ``rebrew match``
    GA splice, batch flag sweep) so ``rebrew status``/``rebrew todo`` agree
    with the freshly-promoted metadata immediately — previously only test
    patched the cache, so a match run's ``STUB → RELOC`` promotion left
    status/todo reporting the stale cached STUB until the next full verify.

    Guards: the cache must belong to THIS project's identity (target +
    compiler_hash — a multi-target `test -t CLIENT` must not patch entries a
    `verify -t SERVER` wrote), checked INSIDE the shared cross-process lock
    so a concurrent verify's full-cache save cannot swap the file between an
    outside check and the locked read-modify-write, and the read-modify-write
    itself runs under that lock so a concurrent ``verify --watch`` save
    cannot interleave and drop the patch.

    *patches*: list of dicts with ``va`` (int), ``status``, optional byte
    counts ``match_count`` and ``total``, optional ``delta`` (int|None),
    optional ``match_percent`` (float).  Without ``total``, a missing
    ``delta`` keeps the cached one.  When ``match_percent`` is supplied it is stored as-is —
    recomputing ``match_count / total`` disagrees with
    :func:`rebrew.compile.classify_compare_result` whenever lengths differ
    (SIZE_MISMATCH / truncated compare), and status/todo would then rank ROI
    from a wrong percent until the next full verify.
    """
    if not patches:
        return
    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    if not cache_path.exists():
        # Absent — nothing to patch.  (Checked before locking because taking
        # the lock would create the ``.lock`` sidecar in a possibly
        # not-yet-existing directory; a cache created after this point simply
        # gets patched by the next promotion.)
        return
    with _verify_cache_write_lock(cache_path):
        try:
            raw = _read_cache_document(cache_path)
        except (OSError, ValueError) as exc:
            logging.warning(
                "Could not read verify cache %s — status may be stale: %s", cache_path, exc
            )
            return

        if not _cache_identity_matches(raw, cfg):
            # Wrong identity — patching would misattribute status to the
            # wrong target/compiler.  Nothing to do; the next real verify
            # writes a correct cache.
            return

        entries = raw.get("entries", {})
        changed = False
        for p in patches:
            va_key = f"0x{p['va']:08x}"
            entry = entries.get(va_key)
            if not isinstance(entry, dict):
                continue  # No cached entry to patch
            total = p.get("total", 0)
            if p.get("match_percent") is not None:
                raw_pct = float(p["match_percent"])
                # Reject NaN/inf so a corrupt patch cannot poison status/todo
                # ranking (NaN sorts break; isfinite comparisons are always false).
                match_pct = round(raw_pct, 1) if math.isfinite(raw_pct) else 0.0
            else:
                match_pct = round(100.0 * p["match_count"] / total, 1) if total > 0 else 0.0
            passed = p["status"] in MATCHED_STATUSES
            if p.get("delta") is not None:
                delta = p["delta"]
            elif total > 0:
                delta = total - p["match_count"]
            else:
                delta = entry.get("delta")
            # An unchanged status can still carry a fresh match count/percent
            # (a GA run improving NEAR_MATCHING 60% -> 92%): skipping only on
            # status equality left todo's prover queue reading the stale
            # percent and dropping the candidate.
            if (
                entry.get("status", "") == p["status"]
                and entry.get("match_percent") == match_pct
                and entry.get("passed") == passed
                and entry.get("delta") == delta
            ):
                continue  # Already in sync
            entry["status"] = p["status"]
            entry["match_percent"] = match_pct
            entry["passed"] = passed
            entry["delta"] = delta
            entries[va_key] = entry
            changed = True

        if not changed:
            return
        raw["entries"] = entries
        # Refresh the patched entry's freshness guards so a test-run patch
        # cannot outlive the source it measured: without this, a later source
        # edit whose mtime lands in the same slot (coarse filesystems, git
        # checkout, sub-second agent edits) can pass the mtime fast-path and
        # the patch's metrics are re-served as current.  Refreshing the hash
        # is O(file size) but patches are rare (one per promotion).
        for p in patches:
            va_key = f"0x{p['va']:08x}"
            entry = entries.get(va_key)
            if entry is None:
                continue
            fpath = entry.get("filepath", "")
            if not fpath:
                continue
            fspath = cfg.reversed_dir / fpath
            try:
                st = fspath.stat()
            except OSError:
                continue
            entry["mtime_ns"] = st.st_mtime_ns
            try:
                from rebrew.verify_hash import _source_hash

                entry["source_hash"] = _source_hash(fspath)
            except OSError:
                continue
            entries[va_key] = entry

        try:
            atomic_write_text(cache_path, json.dumps(raw, indent=2), encoding="utf-8")
            _invalidate_verify_cache_memo(cache_path)
        except (OSError, TypeError) as exc:
            logging.warning(
                "Could not patch verify cache %s — status may be stale: %s", cache_path, exc
            )


def _load_verify_cache(cache_path: Path, cfg: ProjectConfig) -> VerifyCache | None:
    if not cache_path.exists():
        return None
    try:
        data = VerifyCache.from_dict(_read_cache_document(cache_path))
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        # A corrupt cache must not look like a cold start: status/todo would
        # silently fall back to metadata and the next verify would recompile
        # everything without explaining why the on-disk cache was ignored.
        logging.warning("Ignoring corrupt verify cache %s: %s", cache_path, exc)
        return None
    if data.version != CACHE_VERSION:
        return None
    if data.target != cfg.target_name:
        return None
    if data.compiler_hash != _compiler_config_hash(cfg):
        return None
    # Header invalidation is per-entry via VerifyCacheEntry.headers_fp (a
    # reached-header fingerprint), checked at serve time in prepare_entries —
    # the old global headers_hash gate re-verified the whole cache on any
    # header change, defeating per-source precision.
    # Legacy caches carry no binary_id — accept them; a cached binary_id that
    # no longer matches the current binary must invalidate.
    if data.binary_id and data.binary_id != _binary_id(cfg):
        return None
    return data


def _save_verify_cache(
    cache_path: Path,
    cfg: ProjectConfig,
    results: list[dict[str, Any]],
    entries: list[Annotation],
    raw_statuses: dict[str, tuple[str, bool]] | None = None,
    preserve_keys: set[str] | None = None,
) -> None:
    filepath_info: dict[str, tuple[int, str]] = {}
    fp_by_va: dict[str, Any] = {}
    for entry in entries:
        va_key = f"0x{entry.va:08x}"
        # One shared computation of every identity input (resolved flags,
        # toolchain, defines, size, header closure, source hash) — the hit
        # check in prepare_entries compares against these same values.
        fp = entry_fingerprint(cfg, entry)
        if fp is None:
            continue
        relative_path = getattr(entry, "filepath", "")
        if not relative_path:
            continue
        filepath_info[relative_path] = (fp.mtime_ns, fp.source_hash)
        fp_by_va[va_key] = fp

    cache_entries: dict[str, dict[str, Any]] = {}
    for result in results:
        va_key = result["va"]
        filepath = result.get("filepath", "")
        file_info = filepath_info.get(filepath)
        if file_info is None:
            continue
        # A tooling crash is not a verification verdict — never cache it: a
        # transient worker failure would otherwise be re-served forever as a
        # phantom failure (status count, coverage overlay, todo "0B diff"
        # quick-win) until a --full re-verify.
        if result.get("status") == "INTERNAL_ERROR":
            continue
        mtime, source_hash = file_info

        # The stored row IS the report row (verdict fields) plus the
        # cache-identity inputs alongside — one shape, no nesting.
        fp_entry = fp_by_va[str(va_key)]
        res_dict = {k: result.get(k) for k in RESULT_FIELDS}
        res_dict["va"] = va_key
        # Overlaid PROVEN entries store their pre-overlay byte result so a
        # later metadata STATUS demotion is not masked by a stale cache hit.
        if raw_statuses is not None and va_key in raw_statuses:
            res_dict["status"], res_dict["passed"] = raw_statuses[va_key]

        cache_entries[str(va_key)] = {
            **res_dict,
            "source_hash": source_hash,
            "mtime_ns": mtime,
            "cflags": fp_entry.cflags,
            "headers_fp": fp_entry.headers_fp,
            "toolchain": fp_entry.toolchain,
            "defines": fp_entry.defines,
            # Context digest the verdict was earned under (None = bare
            # source).  Part of the cache identity: a changed context is a
            # different compile input, not a still-valid match.
            "context_hash": result.get("context_hash"),
        }

    # A filtered run (--nolib) drops its excluded VAs from `results`, but this
    # function rewrites the whole cache file from `results` — without carrying
    # the excluded entries over, one `--nolib` run erases the measured truth
    # for every library function (`status`/`todo` then fall back to metadata
    # and the next plain run recompiles them all).  Copy them from the file
    # being replaced; a VA this run did produce always wins.
    #
    # If the prior cache exists but cannot be read (corrupt JSON, I/O error,
    # wrong shape), refuse to overwrite: falling back to `previous = {}` and
    # writing anyway would wipe every preserved VA with no signal.
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with _verify_cache_write_lock(cache_path):
        if preserve_keys and cache_path.exists():
            try:
                previous = json.loads(cache_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                logging.warning(
                    "Could not read verify cache %s to preserve %d excluded "
                    "entries — refusing to overwrite (would erase them): %s",
                    cache_path,
                    len(preserve_keys),
                    exc,
                )
                return
            prev_entries = previous.get("entries") if isinstance(previous, dict) else None
            if not isinstance(prev_entries, dict):
                logging.warning(
                    "Verify cache %s has no usable entries map — refusing to "
                    "overwrite while preserving %d excluded VAs",
                    cache_path,
                    len(preserve_keys),
                )
                return
            for key in preserve_keys:
                kept = prev_entries.get(key)
                if key not in cache_entries and isinstance(kept, dict):
                    cache_entries[key] = kept

        cache_data = VerifyCache(
            version=CACHE_VERSION,
            compiler_hash=_compiler_config_hash(cfg),
            headers_hash=_headers_hash(cfg),
            target=cfg.target_name,
            binary_id=_binary_id(cfg),
            entries={str(k): VerifyCacheEntry.from_dict(v) for k, v in cache_entries.items()},
        )
        atomic_write_text(cache_path, json.dumps(cache_data.to_dict(), indent=2), encoding="utf-8")
        _invalidate_verify_cache_memo(cache_path)


#: The --compare baseline: last good report, next to the cache (both local,
#: gitignored run state).  Carries the same identity guards as the cache so
#: a baseline from another target/compiler/binary never gates this project.
BASELINE_FILENAME = "verify_baseline.json"


def baseline_path(cfg: ProjectConfig) -> Path:
    """Path of the --compare baseline file for this project."""
    return cfg.root / ".rebrew" / BASELINE_FILENAME


def load_baseline(cfg: ProjectConfig) -> tuple[dict[str, Any] | None, str | None]:
    """Load the --compare baseline report, or (None, warning).

    Rejects baselines written for another target/compiler/binary — a stale
    baseline is a warning + no gate, never a false green or false red.
    """
    path = baseline_path(cfg)
    if not path.exists():
        return None, f"No previous verify baseline at {path}; skipping diff"
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"Could not read verify baseline at {path}: {exc}"
    if not isinstance(loaded, dict):
        return None, f"Verify baseline at {path} is invalid JSON object"
    if loaded.get("target") != cfg.target_name:
        return None, f"Verify baseline at {path} targets {loaded.get('target')!r}; skipping diff"
    if loaded.get("compiler_hash") != _compiler_config_hash(cfg):
        return None, f"Verify baseline at {path} was earned under different compiler config"
    if loaded.get("binary_id") and loaded.get("binary_id") != _binary_id(cfg):
        return None, f"Verify baseline at {path} was earned against a different binary"
    return loaded, None


def save_baseline(cfg: ProjectConfig, report: dict[str, Any]) -> None:
    """Persist *report* as the --compare baseline (with cache identity).

    Advances only on passing gates — the caller enforces that; this just
    stamps + writes under the shared write lock so a concurrent ``verify
    --watch`` save cannot interleave.
    """
    baseline = dict(report)
    baseline["compiler_hash"] = _compiler_config_hash(cfg)
    baseline["binary_id"] = _binary_id(cfg)
    path = baseline_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _verify_cache_write_lock(path):
        atomic_write_text(path, json.dumps(baseline, indent=2), encoding="utf-8")
