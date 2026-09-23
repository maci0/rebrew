"""verify_hash.py — cache-invalidation hashes for the verification pipeline.

The compiler-config, external-include, header-tree, per-source, and per-entry
hashes the verify cache keys on, plus the whole-package logic hash that
invalidates cached results when result-affecting code changes.
"""

from __future__ import annotations

import functools
import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rebrew.config import ProjectConfig

_DEFAULT_TOOLCHAIN = "(default)"

#: Guard for :data:`_HEADERS_HASH_CACHE`.  Eviction is clear-then-store on a
#: shared dict; concurrent ``_headers_hash`` callers (parallel saves / tests /
#: a ThreadingHTTPServer next to verify) must not race the compound mutation.
_HEADERS_HASH_CACHE_LOCK = threading.Lock()


@dataclass
class EntryFingerprint:
    """Every verify-cache identity input for one entry, computed once.

    Shared by the hit check (:func:`rebrew.verify.prepare_entries`) and the
    writer (:func:`rebrew.verify_cache._save_verify_cache`) so the two cannot
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
    from rebrew.compile_overrides import resolve_compile_overrides

    relative_path = getattr(entry, "filepath", "") or ""
    if not relative_path:
        return None
    filepath = Path(cfg.reversed_dir) / relative_path
    try:
        st = filepath.stat()
    except OSError:
        return None
    try:
        source_bytes = _source_bytes(str(filepath.resolve()), st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        return None
    toolchain, cflags = resolve_compile_overrides(
        cfg,
        filepath.parent,
        getattr(entry, "toolchain", ""),
        getattr(entry, "cflags", ""),
        getattr(entry, "module", ""),
    )
    defines = ",".join(sorted(getattr(cfg, "defines", None) or [])) or "(none)"
    return EntryFingerprint(
        toolchain=toolchain or _DEFAULT_TOOLCHAIN,
        cflags=cflags,
        defines=defines,
        size=getattr(entry, "size", 0) or 0,
        headers_fp=_entry_headers_fp(cfg, filepath, cflags, source_bytes=source_bytes),
        source_hash=hashlib.sha256(source_bytes).hexdigest(),
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


@functools.lru_cache(maxsize=1)
def _compare_logic_hash() -> str:
    """Hash of the rebrew modules whose logic changes verification RESULTS.

    The version string alone is static during development (editable installs
    stay "0.1.0" across code changes), so it cannot invalidate a cache written
    by an earlier build of the same version.  Hashing the source of the
    comparison pipeline means any code change invalidates cached results —
    stale EXTRACT_ERROR or wrong RELOC/NEAR_MATCHING entries can never be
    served as truth after a fix.  Computed once per process (source files are
    stable for the lifetime of one rebrew invocation).

    The hash covers the WHOLE ``rebrew`` package source rather than a
    hand-maintained module list: result-affecting code lives across
    ``coff_reloc`` (reloc validation), ``msvc_env`` (compiler env),
    ``compile_overrides.resolve_cflags`` (flags), ``binary_loader`` (IAT masking) and
    others, and a manual list inevitably drifts — a missed module then ships
    a fix without invalidating caches written by the pre-fix build.

    The ``lru_cache`` lives on THIS function (not a nested helper): the old
    version decorated an inner ``_hash()`` re-created on every call, so the
    full-package source hash was recomputed on every verify run despite the
    "once per process" claim.
    """
    import rebrew

    h = hashlib.sha256()
    pkg_root = Path(rebrew.__file__).resolve().parent
    # Deterministic order; only .py source (skip vendored binaries,
    # __pycache__, .so/.pyd extensions).
    for path in sorted(pkg_root.rglob("*.py")):
        try:
            h.update(path.read_bytes())
        except OSError:
            continue
        h.update(b"\x00")
    return h.hexdigest()


def _compiler_config_hash(cfg: ProjectConfig) -> str:
    # Do NOT inline target binary mtime/size here — compiler config is an
    # input to the cache predicate, not a per-call probe of the binary.  The
    # binary identity is guarded separately via VerifyCache.binary_id and
    # _verify_cache_matches_identity; mixing it in would bust the cache on
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
        # the cache (see _save_verify_cache) and compared at hit-check time,
        # so a config-level cflags/preset edit invalidates the affected
        # entries without nuking the whole cache.
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _external_includes_hash(cfg: ProjectConfig) -> str:
    """Digest of headers in the config-level ``-I`` include dirs.

    These live OUTSIDE ``reversed_dir`` (e.g. ``-Ireferences/zlib-1.1.3``),
    so the reversed-dir walk in :func:`_headers_hash` misses them — but an
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


def _headers_hash(cfg: ProjectConfig) -> str:
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
    stat_fp = _headers_stat_fingerprint(src_dir) + (ext_digest,)
    with _HEADERS_HASH_CACHE_LOCK:
        cached = _HEADERS_HASH_CACHE.get(stat_fp)
        if cached is not None:
            return cached

    h = hashlib.sha256()
    # Sorted for stable hashing across runs / platforms.
    for hfile in sorted(src_dir.rglob("*.h")):
        try:
            rel = hfile.relative_to(src_dir).as_posix()
            h.update(rel.encode("utf-8"))
            h.update(b"\x00")  # separator to prevent path/content collision
            h.update(hfile.read_bytes())
            h.update(b"\x01")  # entry separator
        except OSError:
            continue
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
# Key for the memoized _headers_hash — avoids re-reading every .h when the
# tree is unchanged across the two calls per verify run.
# Guarded by :data:`_HEADERS_HASH_CACHE_LOCK` (clear-then-store eviction).
_HEADERS_HASH_CACHE: dict[tuple[tuple[str, int, int] | str, ...], str] = {}
_HEADERS_HASH_CACHE_MAX = 8  # one entry per distinct header-tree state


def _expected_text_functions(cfg: ProjectConfig) -> dict[str, int]:
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
    stale fingerprint would serve a stale ``_headers_hash``.
    """
    entries: list[tuple[str, int, int]] = []
    for hfile in src_dir.rglob("*.h"):
        try:
            st = hfile.stat()
            rel = hfile.relative_to(src_dir).as_posix()
            entries.append((rel, st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    return tuple(sorted(entries))


@functools.lru_cache(maxsize=4096)
def _source_bytes(path_str: str, _mtime_ns: int, _size: int, _ino: int) -> bytes:
    """Read *path_str* once per (path, mtime, size, inode) — multi-function files share it.

    *_mtime_ns* and *_size* are part of the key so an edit within the process
    invalidates the cached bytes without clearing the whole LRU.  Size alone
    catches same-ns rewrites and ``cp -p`` / restored-mtime copies that
    ``read_source_text`` already guards against; mtime alone does not.
    *_ino* catches a same-size rename-over (editor save, ``atomic_write_text``)
    landing in the same mtime tick.
    """
    return Path(path_str).read_bytes()


def _source_hash(filepath: Path) -> str:
    # Callers already catch OSError.  A failed stat almost always means
    # read_bytes would fail too — do not pretend a fallback hash exists.
    st = filepath.stat()
    return hashlib.sha256(
        _source_bytes(str(filepath.resolve()), st.st_mtime_ns, st.st_size, st.st_ino)
    ).hexdigest()


def _entry_headers_fp(
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
    from rebrew.compile_cache import header_dependency_hash

    source_dir = filepath.parent
    inc_path = str(getattr(cfg, "compiler_includes", "") or "")
    flags = shlex.split(getattr(cfg, "base_cflags", "") or "") + shlex.split(cflags_str)
    flags = resolve_include_flags(flags, source_dir, cfg.root)
    include_dirs = [d for d in [inc_path, str(source_dir), *extract_include_dirs(flags)] if d]
    try:
        if source_bytes is None:
            content = filepath.read_bytes().decode("utf-8", errors="surrogateescape")
        else:
            content = source_bytes.decode("utf-8", errors="surrogateescape")
    except OSError:
        return ""
    return header_dependency_hash(content, str(source_dir), include_dirs)
