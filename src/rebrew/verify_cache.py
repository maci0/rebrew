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
import logging
import math
import threading
import tomllib
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from rebrew.utils import atomic_write_text, file_lock, read_toml_text
from rebrew.verify_hash import (
    compiler_config_hash,
    entry_fingerprint,
    headers_hash,
)
from rebrew.workspace.status import MATCHED_STATUSES

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rebrew.annotation import Annotation
    from rebrew.config import ProjectConfig

#: Current cache schema version (flat rows).  The container changed with the
#: rest of the stores (JSON to TOML); the row schema did not, so the version
#: stays: a document's *shape* is what it guards.
CACHE_VERSION = 2

#: The verify cache, beside the coverage documents.  One clear-text TOML file
#: like every other rebrew store: `.rebrew/verify_cache.toml`.
CACHE_FILENAME = "verify_cache.toml"


def cache_path_for(cfg: Any) -> Path:
    """Path of this project's verify cache."""
    return Path(cfg.root) / ".rebrew" / CACHE_FILENAME


#: Fields where ``None`` is a *reported value*, not an absent one.  The
#: compile-context digest is the case: a patch that measured a bare source
#: reports ``None`` and must overwrite the digest a previous run stored, while
#: a patch that had no context to report omits the key and must leave the
#: digest alone.  TOML has no null, so the empty string carries the reported
#: bare value; :func:`toml_document` encodes it and :func:`_decode_nulls`
#: decodes it back, so every reader keeps seeing ``None``.
_NULLABLE_FIELDS: frozenset[str] = frozenset({"context_hash"})


def toml_document(payload: Any) -> Any:
    """Return *payload* as a TOML-safe document.

    TOML has no null.  A field in :data:`_NULLABLE_FIELDS` whose value is
    ``None`` becomes the empty string (it was *reported* as nothing), and every
    other ``None`` is dropped — the dataclasses spell an absent value that way
    (``percent``, ``delta``, ``files``), and readers already treat a missing
    key as absent (``doc.get(key)``).
    """
    if isinstance(payload, dict):
        document: dict[str, Any] = {}
        for key, value in payload.items():
            if value is None:
                if key in _NULLABLE_FIELDS:
                    document[key] = ""
                continue
            document[key] = toml_document(value)
        return document
    if isinstance(payload, list):
        return [toml_document(item) for item in payload]
    return payload


def _decode_nulls(document: dict[str, Any]) -> dict[str, Any]:
    """Map every empty :data:`_NULLABLE_FIELDS` string back to ``None``.

    One decode point for the cache and the baseline, so the JSON-era ``null``
    and the TOML-era empty string are the same value to every reader.
    """
    entries = document.get("entries")
    tables: list[dict[str, Any]] = [document]
    if isinstance(entries, dict):
        # A malformed document may carry a list here; the readers treat that
        # as "no entries", and this decode must not be the one to crash.
        tables.extend(entry for entry in entries.values() if isinstance(entry, dict))
    for table in tables:
        for key in _NULLABLE_FIELDS:
            if table.get(key) == "":
                table[key] = None
    for row in document.get("results", []) if isinstance(document.get("results"), list) else []:
        if isinstance(row, dict):
            for key in _NULLABLE_FIELDS:
                if row.get(key) == "":
                    row[key] = None
    return document


#: Stat-keyed memo of the raw verify-cache document: status and todo both
#: decode ``.rebrew/verify_cache.toml`` every run — sometimes twice per command —
#: and the decode is linear in cache size.  At most one entry per path: a
#: rewrite changes mtime, size, or inode, and keeping the old key would
#: retain the previous full JSON payload for the process lifetime.  Cap
#: distinct paths so a long-lived process that touches many project roots
#: cannot retain every decoded payload.  Guarded: eviction is a multi-step
#: mutation on a shared dict; concurrent status/todo/build-db callers must
#: not race it.
_VERIFY_CACHE_MEMO: dict[tuple[str, int, int, int], dict[str, Any] | None] = {}
_VERIFY_CACHE_MEMO_MAX = 8
_VERIFY_CACHE_MEMO_LOCK = threading.Lock()


def _memo_path_key(cache_path: Path) -> str:
    """Memo key for *cache_path*: resolved, so reads and invalidation agree
    when ``cfg.root`` is relative or reached through a symlink."""
    try:
        return str(cache_path.resolve())
    except OSError:
        return str(cache_path)


def _clamp_percent(value: float) -> float:
    """A ``match_percent`` confined to ``[0.0, 100.0]``.

    A non-finite value becomes ``0.0``; anything outside the range is clamped,
    because every consumer treats the field as a fraction of the function's
    bytes: ``report`` multiplies it by a size, ``todo`` derives an estimated
    byte diff from ``size * (100 - pct) / 100``, and a percent above 100 makes
    that diff negative, so the "too far apart" gate never fires.
    """
    if not math.isfinite(value):
        return 0.0
    return max(0.0, min(100.0, value))


def _cached_percent(value: Any) -> float | None:
    """A cached ``match_percent`` as a float, ``None`` when absent or unusable.

    The cache is a JSON file on disk, so a hand-edit or a partial write can
    leave a non-numeric value behind; coercing it unguarded would raise
    ``ValueError`` out of the write path, taking the verify that produced the
    patch down with it.  Non-finite and out-of-range values are clamped rather
    than dropped, so a corrupt row still ranks last instead of vanishing.
    """
    if value is None:
        return None
    try:
        return _clamp_percent(float(value))
    except (TypeError, ValueError):
        return None


def _drop_memo_for(path_key: str) -> None:
    """Drop every memo fingerprint for *path_key*.  Caller holds the lock."""
    for old in [k for k in _VERIFY_CACHE_MEMO if k[0] == path_key]:
        del _VERIFY_CACHE_MEMO[old]


def _read_cache_document(cache_path: Path) -> dict[str, Any]:
    """Parse *cache_path* as a TOML document.

    Raises ``OSError`` or ``ValueError``; the latter covers malformed TOML and
    non-UTF-8 bytes (``UnicodeDecodeError``).
    """
    raw = tomllib.loads(read_toml_text(cache_path))
    if not isinstance(raw, dict):
        raise ValueError(f"not a TOML table: {type(raw).__name__}")
    _decode_nulls(raw)
    return raw


def _invalidate_verify_cache_memo(cache_path: Path) -> None:
    """Drop every memo entry for *cache_path* after a write.

    ``load_verify_cache_raw`` keys on ``(path, mtime_ns, size, inode)``.  A
    rewrite that lands in the same mtime slot with the same byte length
    (coarse filesystems, same-second agent edits, truncated status strings
    of equal width) would otherwise keep serving the pre-write JSON for the
    rest of the process — status/todo then disagree with the file
    ``rebrew test`` / ``rebrew verify`` just patched.  The inode distinguishes
    that rename-over even before this drop runs.  Mirror ``atomic_write_text``'s
    source-text memo drop.
    """
    with _VERIFY_CACHE_MEMO_LOCK:
        _drop_memo_for(_memo_path_key(cache_path))


def load_verify_cache_raw(cfg: Any) -> dict[str, Any] | None:
    """Load the shared ``.rebrew/verify_cache.toml`` as a raw dict (memoized).

    Returns ``None`` when the file is missing or corrupt.  Target/version
    validation is the caller's responsibility — readers apply their own
    guards (status vs todo differ slightly).  Memoized by (path, mtime,
    size, inode), so repeated loads within one command are free and a
    same-size rename-over in one mtime tick is a miss.
    """
    cache_path = cache_path_for(cfg)
    try:
        st = cache_path.stat()
    except OSError:
        return None
    path_key = _memo_path_key(cache_path)
    key = (path_key, st.st_mtime_ns, st.st_size, st.st_ino)
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
        _drop_memo_for(path_key)
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


def order_result_row(row: dict[str, Any]) -> dict[str, Any]:
    """*row*'s verdict fields in :data:`RESULT_FIELDS` order, extras dropped.

    One key order for a report row however it was produced.  A fresh compile
    builds its row with whatever literal order the verify loop reads
    naturally, while a cache hit rebuilds it from the entry's field order; the
    two orders differ, so the same verdict serialized to
    ``.rebrew/verify_baseline.toml`` (and to ``verify --output``) changed bytes
    on the first cache-served run even though nothing about the result had.
    Ordering both paths here keeps a second run byte-identical to the first.
    """
    return {k: row[k] for k in RESULT_FIELDS if k in row}


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

    def result_row(self) -> dict[str, Any]:
        """The report row: verdict fields only, no cache-identity inputs."""
        return order_result_row(asdict(self))


@dataclass
class VerifyCache:
    """The root structure of the verification cache file."""

    version: int
    compiler_hash: str
    target: str
    entries: dict[str, VerifyCacheEntry]
    headers_hash: str = ""  # informational only — per-entry headers_fp is authoritative
    binary_id: str = ""  # SHA256 of target binary (mtime_ns + size + inode); "" = legacy cache

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


def binary_id(cfg: ProjectConfig) -> str:
    """Stable id for the target binary (mtime_ns + size + inode), "" when unreadable.

    Guards the verify cache: a rebuilt binary of the same target name must
    invalidate cached results, which the target-name check alone misses.
    Inode covers a same-size rename-over in one mtime tick
    (``atomic_write_bytes``, ``cp --pop-size`` then ``mv``): mtime and size stay
    put, and verdicts earned against the previous image would otherwise
    be served for the new one.
    """
    try:
        st = Path(cfg.target_binary).stat()
    except (OSError, TypeError, AttributeError):
        return ""
    return hashlib.sha256(f"{st.st_mtime_ns}:{st.st_size}:{st.st_ino}".encode()).hexdigest()


_VERIFY_CACHE_LOCK = threading.Lock()


@contextlib.contextmanager
def _verify_cache_write_lock(cache_path: Path) -> Iterator[None]:
    """Thread + cross-process lock around a verify-cache read-modify-write.

    Same discipline as ``rebrew.metadata_doc.metadata_write_lock``: the thread
    lock serializes in-process writers; an advisory ``flock`` on a sidecar
    ``.lock`` file serializes concurrent processes (e.g. ``rebrew verify
    --watch`` saving while ``rebrew test`` patches a promotion — without
    it, interleaved read-modify-writes silently drop one side's update and
    status/todo serve a stale entry).
    """
    with _VERIFY_CACHE_LOCK, file_lock(Path(str(cache_path) + ".lock")):
        yield


#: Config fields :func:`rebrew.verify_hash.compiler_config_hash` reads.  A
#: config that does not carry all of them (a test fixture, a tool that knows
#: only the project root) cannot answer the compiler dimension.
_COMPILER_IDENTITY_FIELDS = (
    "compiler_command",
    "base_cflags",
    "compiler_includes",
    "compiler_libs",
)


def cache_identity_matches(raw: dict[str, Any], cfg: ProjectConfig) -> bool:
    """True when a parsed verify-cache document belongs to *cfg*'s identity.

    Single definition of the ``(version, target, compiler_hash, binary_id)``
    check, used by :func:`verify_cache_matches_cfg` (whole-file predicate),
    :func:`patch_verify_cache_entries` (in-lock guard), :func:`load_verify_cache`
    (the serve path), and every read-only consumer (``status``, ``todo``,
    ``residue``, ``build_db``), so they cannot drift.

    Drift is not cosmetic: a reader that omits the compiler dimension keeps
    reporting verdicts earned under a toolchain or comparison-logic version
    the compile path has already rejected, so ``status`` and ``verify``
    disagree about the same file until the next full verify.

    A dimension the config does not carry cannot reject — a partial config has
    no opinion on the compiler, and inventing a verdict for it would make
    every fixture look like a foreign cache.
    """
    if raw.get("version") != CACHE_VERSION:
        return False
    raw_bin = raw.get("binary_id")
    if raw_bin and raw_bin != binary_id(cfg):
        return False
    cache_target = raw.get("target")
    cfg_target = getattr(cfg, "target_name", None)
    if cache_target != cfg_target and (cache_target or cfg_target):
        return False
    if all(hasattr(cfg, field) for field in _COMPILER_IDENTITY_FIELDS):
        return raw.get("compiler_hash") == compiler_config_hash(cfg)
    return True


def verify_cache_matches_cfg(cache_path: Path, cfg: ProjectConfig) -> bool:
    """True when the verify cache was written for this project's identity.

    The cache stores its ``target``/``compiler_hash``/``headers_hash``/
    ``binary_id`` provenance; patchers (``rebrew test`` promoting a STATUS)
    must not write into a cache that belongs to a DIFFERENT target or
    compiler — in a multi-target project, ``rebrew test --target CLIENT`` would
    otherwise patch the entries a previous ``verify --target SERVER`` wrote, and
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
    return cache_identity_matches(data, cfg)


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
    ``delta`` keeps the cached one, and a missing ``match_percent`` keeps the
    cached percent rather than overwriting it with 0.  When ``match_percent`` is supplied it is stored as-is —
    recomputing ``match_count / total`` disagrees with
    :func:`rebrew.compile.classify_compare_result` whenever lengths differ
    (SIZE_MISMATCH / truncated compare), and status/todo would then rank ROI
    from a wrong percent until the next full verify.
    """
    if not patches:
        return
    cache_path = cache_path_for(cfg)
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

        if not cache_identity_matches(raw, cfg):
            # Wrong identity — patching would misattribute status to the
            # wrong target/compiler.  Nothing to do; the next real verify
            # writes a correct cache.
            return

        entries = raw.get("entries", {})
        if not isinstance(entries, dict):
            return  # Corrupt document: the loader's own shape check, on the write path
        changed = False
        for p in patches:
            va_key = f"0x{p['va']:08x}"
            entry = entries.get(va_key)
            if not isinstance(entry, dict):
                continue  # No cached entry to patch
            total = p.get("total", 0)
            match_pct: float | None
            if p.get("match_percent") is not None:
                raw_pct = float(p["match_percent"])
                # Reject NaN/inf so a corrupt patch cannot poison status/todo
                # ranking (NaN sorts break; isfinite comparisons are always false),
                # and clamp to 0-100: a percent above 100 makes the report's
                # fuzzy totals and todo's est_diff gate read as more matched than
                # the function has bytes.
                # Unrounded, like a full verify's rows: rounding lifted 59.96 to
                # 60.0, across the NEAR_MATCHING threshold todo ranks by.
                match_pct = _clamp_percent(raw_pct)
            elif total > 0:
                match_pct = 100.0 * p["match_count"] / total
            else:
                # No byte counts and no percent: keep what the last real
                # measurement recorded rather than overwriting it with 0.0.
                match_pct = _cached_percent(entry.get("match_percent"))
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
            cached_pct = _cached_percent(entry.get("match_percent"))
            pct_matches = (
                cached_pct == match_pct
                if cached_pct is None or match_pct is None
                else math.isclose(float(cached_pct), float(match_pct), rel_tol=1e-7, abs_tol=1e-7)
            )
            # ``context_hash`` is cache identity (see the writer), so a patch
            # that earned its metrics under a different compile context must
            # overwrite the stored one.  Absent key means "the caller has no
            # context to report", which is NOT the same as a reported ``None``
            # (bare source); only a present key is written.
            ctx_matches = "context_hash" not in p or entry.get("context_hash") == p["context_hash"]
            if (
                entry.get("status", "") == p["status"]
                and pct_matches
                and entry.get("passed") == passed
                and entry.get("delta") == delta
                and ctx_matches
            ):
                continue  # Already in sync
            entry["status"] = p["status"]
            if match_pct is not None:
                entry["match_percent"] = match_pct
            entry["passed"] = passed
            entry["delta"] = delta
            if "context_hash" in p:
                entry["context_hash"] = p["context_hash"]
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
            if not isinstance(entry, dict):
                continue
            fpath = entry.get("filepath", "")
            if not fpath or not isinstance(fpath, str):
                continue
            fspath = cfg.reversed_dir / fpath
            # The cache is a project file, but its ``filepath`` entries are
            # text: an absolute or ``..`` path would make the refresh hash an
            # arbitrary file outside reversed_dir.
            if not fspath.resolve().is_relative_to(cfg.reversed_dir.resolve()):
                continue
            try:
                st = fspath.stat()
            except OSError as exc:
                # The entry keeps the guards the patch was measured against.
                # Consumption re-stats and re-hashes, so a changed source is
                # still caught, but an operator debugging a stale verdict needs
                # to know the refresh was skipped.
                logging.warning(
                    "verify cache entry for %s keeps its pre-patch freshness guards: %s",
                    fspath,
                    exc,
                )
                continue
            entry["mtime_ns"] = st.st_mtime_ns
            try:
                from rebrew.verify_hash import entry_headers_fp, source_hash

                entry["source_hash"] = source_hash(fspath)
                entry["headers_fp"] = entry_headers_fp(cfg, fspath, entry.get("cflags", ""))
            except OSError as exc:
                logging.warning(
                    "verify cache entry for %s keeps its pre-patch freshness guards: %s",
                    fspath,
                    exc,
                )
                continue
            entries[va_key] = entry

        try:
            atomic_write_text(cache_path, tomlkit.dumps(toml_document(raw)), encoding="utf-8")
            _invalidate_verify_cache_memo(cache_path)
        except (OSError, TypeError) as exc:
            logging.warning(
                "Could not patch verify cache %s — status may be stale: %s", cache_path, exc
            )


def load_verify_cache(cache_path: Path, cfg: ProjectConfig) -> VerifyCache | None:
    """Read and identity-check the verify cache at *cache_path*.

    ``None`` means "treat this as a cold start" and covers three distinct
    cases a caller must not confuse: the file is absent, it is unreadable or
    corrupt (a warning is logged — a corrupt cache must not silently look like
    a clean slate), or the document's identity (target binary, compiler
    config) no longer matches *cfg*.  Per-entry staleness is not resolved
    here; that happens at serve time in ``prepare_entries``.
    """
    # The canonical path goes through the memoized raw loader: status/todo call
    # it in the same process before report/verify ask here, and re-reading +
    # JSON-decoding the whole document a second time was a full redundant pass
    # over every cached entry.  Any other path is read directly.
    root = getattr(cfg, "root", None)
    if root is not None and cache_path == Path(root) / ".rebrew" / CACHE_FILENAME:
        raw = load_verify_cache_raw(cfg)
        if raw is None:
            return None
    elif cache_path.exists():
        try:
            raw = _read_cache_document(cache_path)
        except (OSError, ValueError) as exc:
            logging.warning("Ignoring corrupt verify cache %s: %s", cache_path, exc)
            return None
    else:
        return None
    try:
        data = VerifyCache.from_dict(raw)
    except (ValueError, TypeError, AttributeError) as exc:
        # A corrupt cache must not look like a cold start: status/todo would
        # silently fall back to metadata and the next verify would recompile
        # everything without explaining why the on-disk cache was ignored.
        logging.warning("Ignoring corrupt verify cache %s: %s", cache_path, exc)
        return None
    # Header invalidation is per-entry via VerifyCacheEntry.headers_fp (a
    # reached-header fingerprint), checked at serve time in prepare_entries —
    # the old global headers_hash gate re-verified the whole cache on any
    # header change, defeating per-source precision.
    if not cache_identity_matches(raw, cfg):
        return None
    return data


def save_verify_cache(
    cache_path: Path,
    cfg: ProjectConfig,
    results: list[dict[str, Any]],
    entries: list[Annotation],
    preserve_keys: set[str] | None = None,
) -> None:
    """Rewrite *cache_path* from this run's *results*.

    The file is replaced wholesale, not merged, so a filtered run must pass
    the VAs it did not measure in *preserve_keys* or they are lost.
    ``INTERNAL_ERROR`` rows are dropped rather than stored, and a run with
    non-empty *preserve_keys* aborts the write rather than overwrite a prior
    cache it cannot read: the preserved VAs would be wiped with no signal. An
    unfiltered run has nothing to preserve, so it replaces the file whatever
    was there.
    """
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
        # filepath_info is keyed by path and fp_by_va by VA, so a row whose own
        # annotation has no fingerprint (fp is None above) can still find a
        # sibling's entry under a shared filepath.  Uncacheable, not fatal.
        fp_entry = fp_by_va.get(str(va_key))
        if fp_entry is None:
            continue
        res_dict = {k: result.get(k) for k in RESULT_FIELDS}
        res_dict["va"] = va_key

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
    #
    # A prior cache written for ANOTHER identity is root-scoped, not
    # target-scoped, so it can hold a sibling target's rows.  Carrying those
    # into a document about to be stamped with THIS target's identity would
    # misattribute the other target's verdicts to these VAs, and the stamped
    # header would then pass the serve-path identity check.  Preserve nothing
    # from it; the rows are the other target's to keep.
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with _verify_cache_write_lock(cache_path):
        if preserve_keys and cache_path.exists():
            try:
                previous = _decode_nulls(tomllib.loads(read_toml_text(cache_path)))
            except (OSError, tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
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
            if not cache_identity_matches(previous, cfg):
                # Rows earned for another target/compiler.  Keep none of
                # them; this run's own results are still written below.
                logging.warning(
                    "Verify cache %s was written for another target/compiler — "
                    "preserving none of its %d excluded VAs",
                    cache_path,
                    len(preserve_keys),
                )
                prev_entries = {}
            for key in preserve_keys:
                kept = prev_entries.get(key)
                if key not in cache_entries and isinstance(kept, dict):
                    cache_entries[key] = kept

        cache_data = VerifyCache(
            version=CACHE_VERSION,
            compiler_hash=compiler_config_hash(cfg),
            headers_hash=headers_hash(cfg),
            target=cfg.target_name,
            binary_id=binary_id(cfg),
            entries={str(k): VerifyCacheEntry.from_dict(v) for k, v in cache_entries.items()},
        )
        atomic_write_text(
            cache_path, tomlkit.dumps(toml_document(cache_data.to_dict())), encoding="utf-8"
        )
        # Status uses this mtime as the full verification instant. The atomic
        # writer preserves it for identical bytes; a completed full run must
        # still advance it. A filtered run cannot refresh unmeasured rows.
        if not preserve_keys:
            cache_path.touch()
        _invalidate_verify_cache_memo(cache_path)


#: The --compare baseline: last good report, next to the cache (both local,
#: gitignored run state).  Carries the same identity guards as the cache so
#: a baseline from another target/compiler/binary never gates this project.
BASELINE_FILENAME = "verify_baseline.toml"


def baseline_path(cfg: ProjectConfig) -> Path:
    """Path of the --compare baseline file for this project."""
    return Path(cfg.root) / ".rebrew" / BASELINE_FILENAME


def load_baseline(cfg: ProjectConfig) -> tuple[dict[str, Any] | None, str | None]:
    """Load the --compare baseline report, or (None, warning).

    Rejects baselines written for another target/compiler/binary — a stale
    baseline is a warning + no gate, never a false green or false red.
    """
    path = baseline_path(cfg)
    if not path.exists():
        return None, f"No previous verify baseline at {path}; skipping diff"
    try:
        loaded = _decode_nulls(tomllib.loads(read_toml_text(path)))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        # A TOML document is always a table, so a malformed file is the only
        # way this fails; the caller gets a warning and no gate.
        return None, f"Could not read verify baseline at {path}: {exc}"
    if loaded.get("target") != cfg.target_name:
        return None, f"Verify baseline at {path} targets {loaded.get('target')!r}; skipping diff"
    if loaded.get("compiler_hash") != compiler_config_hash(cfg):
        return None, f"Verify baseline at {path} was earned under different compiler config"
    if loaded.get("binary_id") and loaded.get("binary_id") != binary_id(cfg):
        return None, f"Verify baseline at {path} was earned against a different binary"
    return loaded, None


def save_baseline(cfg: ProjectConfig, report: dict[str, Any]) -> None:
    """Persist *report* as the --compare baseline (with cache identity).

    Advances only on passing gates — the caller enforces that; this just
    stamps + writes under the shared write lock so a concurrent ``verify
    --watch`` save cannot interleave.
    """
    baseline = dict(report)
    baseline["compiler_hash"] = compiler_config_hash(cfg)
    baseline["binary_id"] = binary_id(cfg)
    path = baseline_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _verify_cache_write_lock(path):
        atomic_write_text(path, tomlkit.dumps(toml_document(baseline)), encoding="utf-8")
