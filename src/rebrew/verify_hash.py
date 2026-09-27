"""verify_hash.py — cache-invalidation hashes for the verification pipeline.

The compiler-config, external-include, header-tree, per-source, and per-entry
hashes the verify cache keys on, plus the whole-package logic hash that
invalidates cached results when result-affecting code changes.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rebrew.config import ProjectConfig

#: Sentinel stored in VerifyCacheEntry.toolchain when no override names a
#: compiler (the project's default profile applies).  Distinct from ``""`` so
#: legacy entries (written before the field existed) are re-verified once.
DEFAULT_TOOLCHAIN = "(default)"

log = logging.getLogger(__name__)

#: Guard for :data:`_HEADERS_HASH_CACHE`.  Eviction is clear-then-store on a
#: shared dict; concurrent ``headers_hash`` callers (parallel saves / tests /
#: a ThreadingHTTPServer next to verify) must not race the compound mutation.
_HEADERS_HASH_CACHE_LOCK = threading.Lock()


@dataclass
class EntryFingerprint:
    """Every verify-cache identity input for one entry, computed once.

    Shared by the hit check (:func:`rebrew.verify.prepare_entries`) and the
    writer (:func:`rebrew.verify_cache.save_verify_cache`) so the two cannot
    drift — previously each recomputed resolved flags/toolchain/headers/
    source-hash independently.
    """

    toolchain: str
    cflags: str
    defines: str
    size: int
    headers_fp: str
    source_hash: str
    mtime_ns: int


def entry_fingerprint(cfg: ProjectConfig, entry: Any) -> EntryFingerprint | None:
    """Compute the cache identity for *entry*, or None when unreadable.

    Returns None when the entry has no source path or the file cannot be
    read — the caller treats that as a cache miss, never a hit.
    """
    from rebrew.compile_overrides import resolve_compile_overrides_cached

    relative_path = getattr(entry, "filepath", "") or ""
    if not relative_path:
        return None
    filepath = Path(cfg.reversed_dir) / relative_path
    try:
        st = filepath.stat()
    except OSError:
        return None
    try:
        source_bytes, source_digest = _source_body(
            str(filepath.resolve()), st.st_mtime_ns, st.st_size, st.st_ino
        )
    except OSError:
        return None
    toolchain, cflags = resolve_compile_overrides_cached(
        cfg,
        filepath.parent,
        getattr(entry, "toolchain", ""),
        getattr(entry, "cflags", ""),
        getattr(entry, "module", ""),
    )
    defines = "\x00".join(sorted(getattr(cfg, "defines", None) or [])) or "(none)"
    return EntryFingerprint(
        toolchain=toolchain or DEFAULT_TOOLCHAIN,
        cflags=cflags,
        defines=defines,
        size=getattr(entry, "size", 0) or 0,
        headers_fp=entry_headers_fp(cfg, filepath, cflags, source_bytes=source_bytes),
        source_hash=source_digest,
        mtime_ns=st.st_mtime_ns,
    )


def cflags_equivalent(stored: str, current: str) -> bool:
    """True when two CFLAGS strings compile identically.

    Raw strings may differ cosmetically (flag reorder, dedup) while landing
    in the same canonical equivalence class — only a material difference
    invalidates the entry.  A legacy/degenerate empty side is never
    equivalent (re-verify once).
    """
    import shlex

    if not (stored and current):
        return False
    if stored == current:
        return True
    from rebrew.compile_cache import canonicalize_cflags

    return canonicalize_cflags(shlex.split(stored)) == canonicalize_cflags(shlex.split(current))


def _package_source_fingerprint() -> tuple[tuple[str, int, int], ...]:
    """``(path, mtime_ns, size)`` for every ``.py`` file in the rebrew package.

    Not memoized, for the reason :func:`_headers_stat_fingerprint` is not: a
    long-lived process (``verify --watch``, the dashboard) must see an edit to
    the comparison logic, which is the whole point of the hash.
    """
    import rebrew

    pkg_root = Path(rebrew.__file__).resolve().parent
    entries: list[tuple[str, int, int]] = []
    for path in pkg_root.rglob("*.py"):
        try:
            st = path.stat()
        except OSError:
            # Dropping the module makes this digest identical to a tree that
            # never contained it, so a verify result earned before it
            # existed is re-served as current.  An unreadable marker keeps
            # the key distinct (same rule as
            # ``compile_cache.include_fingerprint``).
            entries.append((f"{path}\0unreadable", 0, 0))
            continue
        entries.append((str(path), st.st_mtime_ns, st.st_size))
    return tuple(sorted(entries))


#: Memo for :func:`_compare_logic_hash`, guarded by the package-source stat
#: fingerprint.  Lock-guarded: ``verify -j N`` computes cache identity from
#: worker threads.
_COMPARE_LOGIC_MEMO_LOCK = threading.Lock()
_COMPARE_LOGIC_MEMO: tuple[tuple[tuple[str, int, int], ...], str] | None = None


def _compare_logic_hash() -> str:
    """Hash of the rebrew modules whose logic changes verification RESULTS.

    The version string alone is static during development (editable installs
    stay "0.1.0" across code changes), so it cannot invalidate a cache written
    by an earlier build of the same version.  Hashing the source of the
    comparison pipeline means any code change invalidates cached results —
    stale EXTRACT_ERROR or wrong RELOC/NEAR_MATCHING entries can never be
    served as truth after a fix.

    Memoized on the package source's stat fingerprint rather than for the
    process lifetime: a process that outlives an edit to the comparison logic
    (an editable install being worked on under ``verify --watch``, or a
    dashboard with the cache open) would otherwise keep accepting verdicts the
    current code would not reach.  An edit preserving both mtime_ns and size is
    missed until the next process, as for every other stat-keyed memo here.

    The hash covers the WHOLE ``rebrew`` package source rather than a
    hand-maintained module list: result-affecting code lives across
    ``coff_reloc`` (reloc validation), ``msvc_env`` (compiler env),
    ``compile_overrides.resolve_cflags`` (flags), ``binary_loader`` (IAT masking) and
    others, and a manual list inevitably drifts — a missed module then ships
    a fix without invalidating caches written by the pre-fix build.
    """
    global _COMPARE_LOGIC_MEMO

    fingerprint = _package_source_fingerprint()
    with _COMPARE_LOGIC_MEMO_LOCK:
        memo = _COMPARE_LOGIC_MEMO
        if memo is not None and memo[0] == fingerprint:
            return memo[1]

    h = hashlib.sha256()
    # Deterministic order; only .py source (skip vendored binaries,
    # __pycache__, .so/.pyd extensions).
    for path_str, _mtime_ns, _size in fingerprint:
        if path_str.endswith("\0unreadable"):
            h.update(f"\0unreadable\0{path_str}\0".encode("utf-8", errors="surrogateescape"))
            h.update(b"\x00")
            continue
        try:
            h.update(Path(path_str).read_bytes())
        except OSError:
            # The stat succeeded but the read did not: fold the same
            # unreadable marker in rather than skipping the module.
            h.update(f"\0unreadable\0{path_str}\0".encode("utf-8", errors="surrogateescape"))
        h.update(b"\x00")
    digest = h.hexdigest()
    with _COMPARE_LOGIC_MEMO_LOCK:
        _COMPARE_LOGIC_MEMO = (fingerprint, digest)
    return digest


def compiler_config_hash(cfg: ProjectConfig) -> str:
    """Digest of the compile configuration shared by every cache entry.

    Deliberately excludes the per-entry inputs (resolved cflags, defines,
    header closure, source body) and the target binary's stat: those are
    compared individually so one changed source does not invalidate the
    whole cache.  What belongs here is a change that invalidates *every*
    entry at once, including the compare/extraction logic hash, so a fix to
    the comparison code re-measures results it would otherwise keep serving.
    """
    # Do NOT inline target binary mtime/size here — compiler config is an
    # input to the cache predicate, not a per-call probe of the binary.  The
    # binary identity is guarded separately via VerifyCache.binary_id and
    # cache_identity_matches; mixing it in would bust the cache on
    # every run that touches the binary even when nothing relevant changed.
    parts = [
        cfg.compiler_command,
        getattr(cfg, "compiler_runner", ""),
        cfg.base_cflags,
        str(cfg.compiler_includes),
        str(cfg.compiler_libs),
        # Content hash of the comparison/extraction logic: a code change that
        # alters results for the SAME source+compiler (e.g. the EXTRACT_ERROR
        # / STUB-symbol fixes) must invalidate cached results.  The package
        # version string alone is static during development.
        _compare_logic_hash(),
        # NOTE: cfg.cflags and cfg.cflags_presets are NOT hashed here — they
        # feed the effective-flags resolution, which is stored PER ENTRY in
        # the cache (see save_verify_cache) and compared at hit-check time,
        # so a config-level cflags/preset edit invalidates the affected
        # entries without nuking the whole cache.
    ]
    # NUL-joined, not "|": a compiler_command or include path containing the
    # separator would otherwise shift the field boundary and leave the hash
    # unchanged across a real compiler change.
    # surrogateescape, like every other hash of path text here: an include dir
    # named with a byte that is not valid UTF-8 reaches this string as a lone
    # surrogate, and a strict encode raised UnicodeEncodeError instead of
    # returning a digest.
    return hashlib.sha256("\x00".join(parts).encode("utf-8", errors="surrogateescape")).hexdigest()


def _external_includes_hash(cfg: ProjectConfig) -> str:
    """Digest of headers in the config-level ``-I`` include dirs.

    These live OUTSIDE ``reversed_dir`` (e.g. ``-Ireferences/zlib-1.1.3``),
    so the reversed-dir walk in :func:`headers_hash` misses them — but an
    edit to such a header changes every translation unit that includes it,
    and cached verify entries are served without recompiling.  Reuses the
    compile cache's ``include_fingerprint`` (name+size+mtime stat walk,
    memoized per directory) so both caches agree on the same dirs.
    """
    import shlex

    from rebrew.compile_cache import include_fingerprint

    inc_dirs: list[str] = []
    inc = getattr(cfg, "compiler_includes", None)
    if inc:
        inc_dirs.append(str(inc))
    for flag in shlex.split(getattr(cfg, "base_cflags", "") or ""):
        if flag.startswith("-I"):
            inc_dirs.append(flag[2:])
    h = hashlib.sha256()
    for d in sorted(set(inc_dirs)):
        h.update(include_fingerprint(d).encode("utf-8"))
        h.update(b"\x02")
    return h.hexdigest()


def headers_hash(cfg: ProjectConfig) -> str:
    """SHA256 of every header file reachable from the project's source tree.

    If a shared header changes, every translation unit that includes it must be
    re-verified.  Returns a stable hash that captures the union of all .h files
    under cfg.reversed_dir plus the config-level ``-I`` include dirs (see
    :func:`_external_includes_hash`).  (The compile cache tracks headers
    independently via ``compile_cache.include_fingerprint``; this hash guards
    the verify cache, which also covers include dirs outside ``reversed_dir``.)

    Memoized behind a cheap stat fingerprint (path + mtime_ns + size): when no
    header changed since the last call, the full content reads are skipped.
    The fingerprint is authoritative for the common cases (edit, create,
    delete); an edit that preserves BOTH mtime_ns and size is not detected
    within one process (the memo returns the cached digest).  Content hashing
    still runs on the first call per fingerprint, and each fresh process
    recomputes from content, so cross-run correctness is preserved.
    """
    src_dir = Path(cfg.reversed_dir)
    if not src_dir.exists():
        return ""

    ext_digest = _external_includes_hash(cfg)
    # The fingerprint holds paths RELATIVE to src_dir, so two project roots
    # with equal-size, equal-mtime header trees hash to the same tuple: the
    # resolved source directory is part of the key or the second root is
    # served the first root's digest.
    stat_fp: tuple[tuple[str, int, int] | str, ...] = (
        str(src_dir.resolve()),
        *_headers_stat_fingerprint(src_dir),
        ext_digest,
    )
    with _HEADERS_HASH_CACHE_LOCK:
        cached = _HEADERS_HASH_CACHE.get(stat_fp)
        if cached is not None:
            return cached

    h = hashlib.sha256()
    # Sorted for stable hashing across runs / platforms.
    for hfile in sorted(src_dir.rglob("*.h")):
        try:
            rel = hfile.relative_to(src_dir).as_posix()
        except ValueError:
            # rglob only yields paths under src_dir, so this is unreachable
            # in practice; fall through to the sentinel rather than dropping
            # the header, which would alias this tree onto a smaller one.
            rel = hfile.as_posix()
        try:
            # surrogateescape: a header filename is not required to be valid
            # UTF-8 (a cp1252 name is legal on Linux), and it arrives here as
            # a lone surrogate that a strict encode cannot hash.
            h.update(rel.encode("utf-8", errors="surrogateescape"))
            h.update(b"\x00")  # separator to prevent path/content collision
            h.update(hfile.read_bytes())
            h.update(b"\x01")  # entry separator
        except OSError as exc:
            # Skipping an unreadable header makes this digest identical to a
            # tree that never contained it, so an edit behind the failed read
            # stays a cache hit.  An unreadable marker keeps the key distinct
            # (same convention as compile_cache.include_fingerprint).
            log.warning("headers_hash: cannot read %s (%s); digesting it as unreadable", rel, exc)
            h.update(b"\x00unreadable\x00")
            h.update(b"\x01")
    h.update(ext_digest.encode("utf-8"))
    h.update(b"\x03")
    digest = h.hexdigest()
    with _HEADERS_HASH_CACHE_LOCK:
        # Re-check: another worker may have filled (or cleared) while we hashed.
        cached = _HEADERS_HASH_CACHE.get(stat_fp)
        if cached is not None:
            return cached
        if len(_HEADERS_HASH_CACHE) >= _HEADERS_HASH_CACHE_MAX:
            _HEADERS_HASH_CACHE.clear()
        _HEADERS_HASH_CACHE[stat_fp] = digest
    return digest


# Stat fingerprint of the header tree: (path, mtime_ns, size) per header,
# plus the external-includes digest as the final element.
# Key for the memoized headers_hash — avoids re-reading every .h when the
# tree is unchanged across the two calls per verify run.
# Guarded by :data:`_HEADERS_HASH_CACHE_LOCK` (clear-then-store eviction).
_HEADERS_HASH_CACHE: dict[tuple[tuple[str, int, int] | str, ...], str] = {}
_HEADERS_HASH_CACHE_MAX = 8  # one entry per distinct header-tree state


def expected_text_functions(cfg: ProjectConfig) -> dict[str, int]:
    """``{symbol: marker VA}`` for every annotated function.

    Shared by verify and ``text-audit`` so both classify the same binary.
    Marker symbols use the per-target ``// FUNCTION:`` name; ``lstrip("_")``
    normalizes leading underscores for export-table comparison.
    """
    from rebrew.annotation import iter_annotations
    from rebrew.sources import iter_sources, target_marker

    marker = target_marker(cfg)
    out: dict[str, int] = {}
    for path, annos in iter_annotations(
        iter_sources(cfg.reversed_dir, cfg), target=marker, metadata_dir=cfg.metadata_dir
    ):
        for ann in annos:
            sym = ann.symbol if ann.symbol and ann.symbol != "?" else "_" + path.stem
            out.setdefault(sym.lstrip("_"), ann.va)
    return out


def _headers_stat_fingerprint(src_dir: Path) -> tuple[tuple[str, int, int], ...]:
    """Return sorted (rel_path, mtime_ns, size) tuples for all .h files.

    Not memoized: headers can change within a process lifetime (``verify
    --watch`` re-runs in-process; tests mutate headers between calls), and a
    stale fingerprint would serve a stale ``headers_hash``.
    """
    entries: list[tuple[str, int, int]] = []
    for hfile in src_dir.rglob("*.h"):
        try:
            st = hfile.stat()
            rel = hfile.relative_to(src_dir).as_posix()
            entries.append((rel, st.st_mtime_ns, st.st_size))
        except OSError:
            # A header that cannot be stat'ed must still change the key, or
            # the memo serves a digest taken while it was unreadable.  -1 is
            # not a reachable mtime_ns or size, so the marker cannot collide
            # with a real entry.
            entries.append((hfile.as_posix(), -1, -1))
    return tuple(sorted(entries))


#: Retained source bodies, keyed by (resolved path, mtime_ns, size, inode), in
#: LRU order.  The value is ``(bytes, sha256)``: one read serves the digest
#: and the header-dependency fingerprint, and the digest is memoized beside
#: the bytes it was taken from instead of in a second cache keyed on those
#: same bytes — such a key pins a file body for as long as its digest entry
#: lives, so the bodies outlive their own read cache and every revision of
#: every source a watch session touched stays resident.
#: The bound is on retained bytes, not entries: an edit re-keys (see below),
#: so ``verify --watch`` adds a fresh body per save and an entry count would
#: let the total grow with the length of the session.
#: Guarded: ``verify -j N`` fingerprints entries from worker threads.
_SOURCE_MEMO_MAX_BYTES = 64 * 1024 * 1024
_SOURCE_MEMO: OrderedDict[tuple[str, int, int, int], tuple[bytes, str]] = OrderedDict()
_SOURCE_MEMO_BYTES = 0
_SOURCE_MEMO_LOCK = threading.Lock()


def clear_source_memo() -> None:
    """Drop every retained source body."""
    global _SOURCE_MEMO_BYTES
    with _SOURCE_MEMO_LOCK:
        _SOURCE_MEMO.clear()
        _SOURCE_MEMO_BYTES = 0


def _source_body(path_str: str, mtime_ns: int, size: int, ino: int) -> tuple[bytes, str]:
    """``(bytes, sha256)`` for *path_str*, memoized per stat identity.

    *mtime_ns* and *size* are part of the key so an edit within the process
    invalidates the cached bytes without clearing the whole memo.  Size alone
    catches same-ns rewrites and ``cp -p`` / restored-mtime copies that
    ``read_source_text`` already guards against; mtime alone does not.
    *ino* catches a same-size rename-over (editor save, ``atomic_write_text``)
    landing in the same mtime tick.
    """
    global _SOURCE_MEMO_BYTES
    key = (path_str, mtime_ns, size, ino)
    with _SOURCE_MEMO_LOCK:
        hit = _SOURCE_MEMO.get(key)
        if hit is not None:
            _SOURCE_MEMO.move_to_end(key)
            return hit
    data = Path(path_str).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    with _SOURCE_MEMO_LOCK:
        if key in _SOURCE_MEMO:  # raced with another thread's read of the same file
            _SOURCE_MEMO.move_to_end(key)
            return _SOURCE_MEMO[key]
        _SOURCE_MEMO[key] = (data, digest)
        _SOURCE_MEMO_BYTES += len(data)
        # Keep at least the newest entry: a source larger than the budget
        # would otherwise be evicted the moment it is stored.
        while _SOURCE_MEMO_BYTES > _SOURCE_MEMO_MAX_BYTES and len(_SOURCE_MEMO) > 1:
            _, (evicted, _) = _SOURCE_MEMO.popitem(last=False)
            _SOURCE_MEMO_BYTES -= len(evicted)
    return data, digest


def source_hash(filepath: Path) -> str:
    """SHA-256 of a source file's body, memoized on (path, mtime, size, inode).

    Callers already catch OSError.  A failed stat almost always means
    read_bytes would fail too — do not pretend a fallback hash exists.
    """
    st = filepath.stat()
    return _source_body(str(filepath.resolve()), st.st_mtime_ns, st.st_size, st.st_ino)[1]


def entry_headers_fp(
    cfg: ProjectConfig,
    filepath: Path,
    cflags_str: str,
    *,
    source_bytes: bytes | None = None,
) -> str:
    """Per-source header-dependency fingerprint for a verify-cache entry.

    Resolves the source's ``#include`` closure against the same dirs the
    compile would search (``compiler_includes``, the source's own dir, and
    the ``/I`` dirs of the base + resolved per-function flags) and hashes the
    reached headers via ``compile_cache.header_dependency_hash``.  Editing a
    header therefore re-verifies exactly the entries whose source reaches it
    — replacing the old global ``headers_hash`` gate that re-verified
    everything on any header change.  Returns ``""`` when the source cannot
    be read (the entry is treated as stale).

    Pass *source_bytes* when the caller already read the file (fingerprint
    path) so the second full-file read is skipped.
    """
    import shlex

    from rebrew.compile import extract_include_dirs, resolve_include_flags
    from rebrew.compile_cache import (
        FORCE_INCLUDE_PREFIXES,
        dir_fingerprint_hash,
        header_dependency_hash,
    )

    source_dir = filepath.parent
    inc_path = str(getattr(cfg, "compiler_includes", "") or "")
    flags = shlex.split(getattr(cfg, "base_cflags", "") or "") + shlex.split(cflags_str)
    flags = resolve_include_flags(flags, source_dir, cfg.root)
    include_dirs = [d for d in [inc_path, str(source_dir), *extract_include_dirs(flags)] if d]
    shared = getattr(cfg, "shared_dir", None)
    if shared is not None:
        try:
            if Path(source_dir).resolve().is_relative_to(Path(shared).resolve()):
                shared_str = str(Path(shared).resolve())
                if shared_str not in include_dirs:
                    include_dirs.append(shared_str)
        except (OSError, ValueError) as exc:
            # Dropping shared_dir here hashes the source over a different
            # include path than the compile used, so the mismatch is silent.
            log.warning(
                "shared_dir %s could not be resolved against %s (%s); hashing without it",
                shared,
                source_dir,
                exc,
            )

    force_include = any(f.startswith(FORCE_INCLUDE_PREFIXES) for f in flags)
    if force_include:
        return dir_fingerprint_hash(str(source_dir), include_dirs)

    try:
        if source_bytes is None:
            content = filepath.read_bytes().decode("utf-8", errors="surrogateescape")
        else:
            content = source_bytes.decode("utf-8", errors="surrogateescape")
    except OSError:
        return ""
    return header_dependency_hash(content, str(source_dir), include_dirs)
