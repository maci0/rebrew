"""verify_cache.py — the verify result cache.

VerifyResult / VerifyCacheEntry / VerifyCache, the cache-identity predicate,
the atomic read/write helpers, and the VA-key canonicalisation shared by the
status, todo, report, and match views.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rebrew.metadata import MATCHED_STATUSES
from rebrew.utils import atomic_write_text
from rebrew.verify_hash import (
    _DEFAULT_TOOLCHAIN,
    _compiler_config_hash,
    _entry_headers_fp,
    _headers_hash,
    _source_hash,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rebrew.annotation import Annotation
    from rebrew.config import ProjectConfig


@dataclass
class VerifyResult:
    """Represents the verification result of a single compiled function."""

    status: str
    va: str | int
    size: int = 0
    filepath: str = ""
    name: str = ""
    symbol: str = ""
    delta: int | None = None
    match_percent: float | None = None
    passed: bool = False
    message: str = ""
    similarity: float | None = None
    reg_delta: int | None = None
    effective_match: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VerifyResult:
        """Reconstruct a VerifyResult from a JSON dictionary."""
        return cls(
            status=str(d.get("status", "")),
            va=d.get("va", ""),
            size=int(d.get("size", 0)),
            filepath=str(d.get("filepath", "")),
            name=str(d.get("name", "")),
            symbol=str(d.get("symbol", "")),
            delta=d.get("delta"),
            match_percent=d.get("match_percent"),
            passed=bool(d.get("passed", False)),
            message=str(d.get("message", "")),
            similarity=d.get("similarity"),
            reg_delta=d.get("reg_delta"),
            effective_match=bool(d.get("effective_match", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert this VerifyResult to a JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class VerifyCacheEntry:
    """A single cache entry linking a source file hash to its VerifyResult."""

    source_hash: str
    filepath: str
    mtime_ns: int
    result: VerifyResult
    cflags: str = ""
    """Per-function CFLAGS used for the cached run.

    CFLAGS live in ``rebrew-functions.toml``, not in the ``.c`` file, so the
    source hash alone cannot detect a flag change (``rebrew match
    --fix-cflags`` rewrites metadata and leaves the source untouched).
    Entries written before this field existed carry ``""`` and are re-verified
    once."""

    size: int = -1
    """Annotation SIZE at cache time.

    SIZE is metadata-only (``rebrew-functions.toml``) — editing it via
    ``rebrew catalog --fix-sizes`` never touches the ``.c`` mtime, so the
    source hash cannot detect it either.  Entries written before this field
    existed carry ``-1`` (unknown) and are re-verified once."""

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
        """Reconstruct a VerifyCacheEntry from a JSON dictionary."""
        return cls(
            source_hash=str(d.get("source_hash", "")),
            filepath=str(d.get("filepath", "")),
            mtime_ns=int(d.get("mtime_ns", 0)),
            result=VerifyResult.from_dict(d.get("result", {})),
            cflags=str(d.get("cflags", "")),
            size=int(d.get("size", -1)),
            headers_fp=str(d.get("headers_fp", "")),
            toolchain=str(d.get("toolchain", "")),
            defines=str(d.get("defines", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert this VerifyCacheEntry to a JSON-serializable dictionary."""
        return asdict(self)


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

    Same discipline as metadata.py's ``_metadata_write_lock``: the thread
    lock serializes in-process writers; an advisory ``flock`` on a sidecar
    ``.lock`` file serializes concurrent processes (e.g. ``rebrew verify
    --watch`` saving while ``rebrew test`` patches a promotion — without
    it, interleaved read-modify-writes silently drop one side's update and
    status/todo serve a stale entry).  Falls back to the thread lock alone
    on platforms without ``fcntl``.
    """
    try:
        import fcntl
    except ImportError:  # non-POSIX (no advisory file locks)
        fcntl = None  # type: ignore[assignment]

    with _VERIFY_CACHE_LOCK:
        if fcntl is None:
            yield
            return
        lock_path = Path(str(cache_path) + ".lock")
        with lock_path.open("w", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_fh, fcntl.LOCK_UN)


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
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
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

    *patches*: list of dicts with ``va`` (int), ``status``, ``match_count``,
    ``total``, optional ``delta`` (int|None).
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
            raw = json.loads(cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
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
            if entry is None:
                continue  # No cached entry to patch
            result = entry.get("result", {})
            total = p["total"]
            match_pct = round(100.0 * p["match_count"] / total, 1) if total > 0 else 0.0
            passed = p["status"] in MATCHED_STATUSES
            if p.get("delta") is not None:
                delta = p["delta"]
            elif total > 0:
                delta = total - p["match_count"]
            else:
                delta = result.get("delta")
            # An unchanged status can still carry a fresh match count/percent
            # (a GA run improving NEAR_MATCHING 60% -> 92%): skipping only on
            # status equality left todo's prover queue reading the stale
            # percent and dropping the candidate.
            if (
                result.get("status", "") == p["status"]
                and result.get("match_percent") == match_pct
                and result.get("passed") == passed
                and result.get("delta") == delta
            ):
                continue  # Already in sync
            result["status"] = p["status"]
            result["match_percent"] = match_pct
            result["passed"] = passed
            result["delta"] = delta
            entry["result"] = result
            entries[va_key] = entry
            changed = True

        if not changed:
            return
        raw["entries"] = entries

        try:
            from rebrew.utils import atomic_write_text

            atomic_write_text(cache_path, json.dumps(raw, indent=2), encoding="utf-8")
        except (OSError, TypeError) as exc:
            logging.warning(
                "Could not patch verify cache %s — status may be stale: %s", cache_path, exc
            )


def _load_verify_cache(cache_path: Path, cfg: ProjectConfig) -> VerifyCache | None:
    if not cache_path.exists():
        return None
    try:
        data = VerifyCache.from_dict(json.loads(cache_path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError, TypeError, ValueError, AttributeError):
        return None
    if data.version != 1:
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
    cflags_by_va: dict[str, str] = {}
    size_by_va: dict[str, int] = {}
    headers_fp_by_va: dict[str, str] = {}
    toolchain_by_va: dict[str, str] = {}
    defines_norm = ",".join(sorted(getattr(cfg, "defines", None) or [])) or "(none)"
    for entry in entries:
        va_key = f"0x{entry.va:08x}"
        # Store the RESOLVED effective flags (per-function metadata → module
        # preset → [compiler].cflags → default) — the flags the compile
        # actually used.  The old code stored only the metadata CFLAGS, so a
        # `rebrew cfg set-cflags` or [compiler].cflags edit changed the
        # effective flags without changing the cache key or entry guard, and
        # stale results kept being served (config-review F3).
        from rebrew.cli import resolve_compile_overrides

        _tc, _cf = resolve_compile_overrides(
            cfg,
            (cfg.reversed_dir / entry.filepath).parent if entry.filepath else cfg.root,
            getattr(entry, "toolchain", ""),
            getattr(entry, "cflags", ""),
            getattr(entry, "module", ""),
        )
        cflags_by_va[va_key] = _cf
        size_by_va[va_key] = entry.size or 0
        toolchain_by_va[va_key] = _tc or _DEFAULT_TOOLCHAIN
        relative_path = getattr(entry, "filepath", "")
        if not relative_path:
            continue
        filepath = cfg.reversed_dir / relative_path
        if filepath.exists():
            filepath_info[relative_path] = (filepath.stat().st_mtime_ns, _source_hash(filepath))
            headers_fp_by_va[va_key] = _entry_headers_fp(cfg, filepath, _cf)

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

        # Ensure result has default fields present
        res_dict = {
            "status": result.get("status", ""),
            "va": va_key,
            "size": result.get("size", 0),
            "filepath": filepath,
            "name": result.get("name", ""),
            "symbol": result.get("symbol", ""),
            "delta": result.get("delta", None),
            "match_percent": result.get("match_percent", None),
            "passed": result.get("passed", False),
            "message": result.get("message", ""),
            "similarity": result.get("similarity", None),
            # reg_delta/effective_match drive the prove queue (status.py) and
            # the coverage DB; dropping them here made every cached entry read
            # back as "not effective" and kept ``rebrew status`` reporting 0
            # effective matches.
            "reg_delta": result.get("reg_delta"),
            "effective_match": result.get("effective_match", False),
        }
        # Overlaid PROVEN entries store their pre-overlay byte result so a
        # later metadata STATUS demotion is not masked by a stale cache hit.
        if raw_statuses is not None and va_key in raw_statuses:
            res_dict["status"], res_dict["passed"] = raw_statuses[va_key]

        cache_entries[str(va_key)] = {
            "source_hash": source_hash,
            "filepath": filepath,
            "mtime_ns": mtime,
            "result": res_dict,
            "cflags": cflags_by_va.get(str(va_key), ""),
            "size": size_by_va.get(str(va_key), 0),
            "headers_fp": headers_fp_by_va.get(str(va_key), ""),
            "toolchain": toolchain_by_va.get(str(va_key), ""),
            "defines": defines_norm,
        }

    # A filtered run (--nolib) drops its excluded VAs from `results`, but this
    # function rewrites the whole cache file from `results` — without carrying
    # the excluded entries over, one `--nolib` run erases the measured truth
    # for every library function (`status`/`todo` then fall back to metadata
    # and the next plain run recompiles them all).  Copy them from the file
    # being replaced; a VA this run did produce always wins.
    if preserve_keys:
        try:
            previous = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            previous = {}
        prev_entries = previous.get("entries") if isinstance(previous, dict) else None
        if isinstance(prev_entries, dict):
            for key in preserve_keys:
                kept = prev_entries.get(key)
                if key not in cache_entries and isinstance(kept, dict):
                    cache_entries[key] = kept

    cache_data = VerifyCache(
        version=1,
        compiler_hash=_compiler_config_hash(cfg),
        headers_hash=_headers_hash(cfg),
        target=cfg.target_name,
        binary_id=_binary_id(cfg),
        entries={str(k): VerifyCacheEntry.from_dict(v) for k, v in cache_entries.items()},
    )
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with _verify_cache_write_lock(cache_path):
        atomic_write_text(cache_path, json.dumps(cache_data.to_dict(), indent=2), encoding="utf-8")


def canonical_va_key(va: Any) -> Any:
    """Normalize a verify-cache VA key to its canonical form.

    Hex strings (``0x1000`` vs ``0x00001000``) map to the same int so report
    format drift can't silently break diffing.  Non-hex values pass through
    unchanged (still unique).  This is the single parser for keys written by
    ``_save_verify_cache``; readers elsewhere must use it.
    """
    if isinstance(va, int):
        return va
    if isinstance(va, str):
        s = va.strip()
        if s[:2].lower() == "0x":
            try:
                return int(s, 16)
            except ValueError:
                return s
    return str(va)
