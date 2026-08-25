"""Hash-based compile cache for skipping redundant Wine/wibo invocations.

Each Wine/wibo CL.EXE invocation costs 200-500ms of subprocess startup
overhead.  During ``rebrew match --all`` (100 gen × 30 pop × N functions) and
``rebrew match --flag-sweep`` (192-8.3M flag combinations), the same
``(source + flags)`` combination is frequently compiled multiple times.

This module provides a persistent, thread-safe, disk-backed cache that
maps compilation inputs to raw ``.obj`` bytes, skipping the subprocess
entirely on cache hit.

Cache location
~~~~~~~~~~~~~~
``{project_root}/.rebrew/compile_cache/`` — gitignored by convention.

Cache key
~~~~~~~~~
SHA-256 of ``(schema_version, source_content, source_filename, source_ext,
cflags, include_dirs, header_dependencies, toolchain_id)``.  Flags are
canonicalized first (see :func:`canonicalize_cflags`): order-insensitive
flag classes and duplicates collapse to one key, while order-sensitive
input (``/I`` search order, ``/D`` redefinitions, last-wins flag values)
keeps its order and still separates compilations.  Include dirs are hashed
in **order** because order affects search semantics.

Invalidation
~~~~~~~~~~~~
Automatic via content hash — different inputs produce different keys.
Header dependencies participate via :func:`header_dependency_hash`: the
source's ``#include`` closure (resolved transitively against the source
directory and the ``/I`` dirs) is fingerprinted **per reached header**
(name + size + mtime, ccache-style), so editing a header invalidates only
the entries whose translation unit reaches it — an edit to an unrelated
header in the same include dir is a cache hit.  Headers that cannot be
resolved on the host (e.g. the MSVC CRT headers inside the immutable
toolchain image) are not tracked: their content is pinned by the toolchain
image digest in the key.  When the closure cannot be resolved statically
(a non-literal ``#include MACRO``, a ``/FI`` force-include), the key falls
back to per-directory fingerprints of every include dir (the conservative
ccache-style mode, via :func:`include_fingerprint`).  Resolution is
memoized per process: a header *created* while a long GA run is in flight
is not picked up until the next invocation (content edits to already
resolved headers are still picked up, because each reached file is re-statted
at key time).
"""

from __future__ import annotations

import atexit
import hashlib
import logging
import re
import threading
from collections.abc import Callable, Iterator
from functools import lru_cache
from pathlib import Path
from typing import Protocol

import diskcache

logger = logging.getLogger(__name__)

# Bump on key semantics changes to invalidate stale entries.
CACHE_SCHEMA_VERSION = 5

# Warn once per process: a corrupt/contended store degrades every get/put,
# and one line per lookup would flood a GA batch's log without adding info.
_degraded_logged = False


def _warn_cache_failure(op: str, exc: Exception) -> None:
    """Log the first cache failure per process at WARNING.

    The cache is an accelerator: any failure must degrade to a miss/skip,
    never break compilation — but silently losing it would leave the user
    wondering why every compile suddenly pays full subprocess cost.
    """
    global _degraded_logged
    if not _degraded_logged:
        _degraded_logged = True
        logger.warning(
            "Compile cache %s failed (%s: %s) — continuing with degraded/no cache; "
            "delete .rebrew/compile_cache/ to reset a corrupted store",
            op,
            type(exc).__name__,
            exc,
        )


# Extensions treated as headers when fingerprinting an include directory.
_HEADER_SUFFIXES = frozenset({".h", ".hpp", ".hxx", ".inl", ".hh"})

# Default size limit: 500 MB with LRU eviction when the limit is reached.
_DEFAULT_SIZE_LIMIT = 500 * 1024 * 1024


class CompileCache:
    """Disk-backed cache mapping compile inputs to raw .obj bytes.

    Backed by ``diskcache.Cache`` (SQLite + filesystem), which is
    thread-safe and supports concurrent readers/writers.

    In-process hit/miss counters (``hits``, ``misses``) are incremented on
    every ``get`` call so that ``rebrew cache stats`` can report a per-session
    hit rate without any extra disk I/O.  Counters reset when the process exits.
    """

    def __init__(self, cache_dir: str | Path, size_limit: int = _DEFAULT_SIZE_LIMIT) -> None:
        """Open (or create) the disk-backed compile cache at *cache_dir*.

        Args:
            cache_dir: Directory where SQLite metadata and value files are stored.
                Created automatically if it does not exist.
            size_limit: Maximum on-disk footprint in bytes.  Oldest entries
                are evicted by ``diskcache`` when the limit is exceeded (LRU).

        """
        self.hits: int = 0
        self.misses: int = 0
        # ``CompileCache`` instances are shared across worker threads in
        # ``flag_sweep`` and ``BinaryMatchingGA``; the underlying diskcache is
        # thread-safe, but ``hits``/``misses`` are plain Python ints whose
        # ``+= 1`` is not atomic across the GIL — protect the increments so
        # stats are not silently undercounted under contention.
        self._counter_lock = threading.Lock()
        # None when the store could not be opened (corrupt SQLite file,
        # unwritable directory): the cache runs disabled instead of raising,
        # so callers keep compiling at full subprocess cost.
        self._cache: diskcache.Cache | None
        try:
            self._cache = diskcache.Cache(str(cache_dir), size_limit=size_limit)
        except Exception as exc:  # any store failure must degrade, not raise
            self._cache = None
            _warn_cache_failure(f"open ({cache_dir})", exc)

    def get(self, key: str) -> bytes | None:
        """Return cached .obj bytes for *key*, or ``None`` on miss.

        Increments ``self.hits`` on a cache hit, ``self.misses`` on a miss.
        A failing store (corruption, lock contention timeout) degrades to a
        miss so compilation proceeds via the compiler subprocess.
        """
        if self._cache is not None:
            try:
                result = self._cache.get(key, default=None)
            except Exception as exc:  # degrade to miss, never break compiles
                _warn_cache_failure("lookup", exc)
                result = None
            if isinstance(result, bytes):
                with self._counter_lock:
                    self.hits += 1
                return result
        with self._counter_lock:
            self.misses += 1
        return None

    def put(self, key: str, obj_bytes: bytes) -> None:
        """Store .obj bytes under *key* (skipped when the store is unusable)."""
        if self._cache is None:
            return
        try:
            self._cache.set(key, obj_bytes)
        except Exception as exc:  # a failed write only costs future hits
            _warn_cache_failure("store", exc)

    @property
    def volume(self) -> int:
        """Total bytes used by the cache on disk."""
        try:
            return int(self._cache.volume()) if self._cache is not None else 0
        except Exception:
            return 0

    @property
    def count(self) -> int:
        """Number of entries in the cache."""
        try:
            return len(self._cache) if self._cache is not None else 0
        except Exception:
            return 0

    def clear(self) -> None:
        """Remove all cached entries."""
        if self._cache is not None:
            try:
                self._cache.clear()
            except Exception as exc:
                _warn_cache_failure("clear", exc)

    def close(self) -> None:
        """Close the underlying diskcache store."""
        if self._cache is not None:
            try:
                self._cache.close()
            except Exception as exc:
                _warn_cache_failure("close", exc)

    def stats(self) -> dict[str, int | float]:
        """Return cache statistics as a dict.

        Includes in-process hit/miss counters under ``session_hits``,
        ``session_misses``, and ``session_hit_rate_pct``.  These reset
        when the process exits; they reflect only the current session.
        """
        total_lookups = self.hits + self.misses
        hit_rate = round(100.0 * self.hits / total_lookups, 1) if total_lookups > 0 else 0.0
        size_limit = self._cache.size_limit if self._cache is not None else 0
        return {
            "entries": self.count,
            "volume_bytes": self.volume,
            "volume_mb": round(self.volume / (1024 * 1024), 2),
            "size_limit_mb": round(size_limit / (1024 * 1024), 2),
            "session_hits": self.hits,
            "session_misses": self.misses,
            "session_hit_rate_pct": hit_rate,
        }


# ---------------------------------------------------------------------------
# Cache backend registry — the store is a component, the keying is not
# ---------------------------------------------------------------------------


#: Minimal store interface a cache backend must satisfy.  ``CompileCache``
#: (the packaged diskcache backend) implements it; a plugin backend plugs in
#: through the ``rebrew.cache_backends`` entry-point group.
#:
#: The *keying* (what makes a hit valid — source/flags/toolchain digests)
#: lives in the shared key functions below and is deliberately NOT part of
#: the contract: a different caching mechanism may store the bytes wherever
#: it likes, but it must not reinterpret what the keys mean.
class CacheBackend(Protocol):
    """Store interface for compile-cache backends."""

    hits: int
    misses: int

    def get(self, key: str) -> bytes | None: ...
    def put(self, key: str, obj_bytes: bytes) -> None: ...

    @property
    def volume(self) -> int: ...
    @property
    def count(self) -> int: ...

    def clear(self) -> None: ...
    def close(self) -> None: ...
    def stats(self) -> dict[str, int | float]: ...


#: setuptools entry-point group whose members register compile-cache
#: backends.  A member is a factory ``(cache_dir: Path, size_limit: int) ->
#: CacheBackend``; the packaged ``diskcache`` backend is the default, and a
#: project selects one through ``[cache] backend`` in rebrew-project.toml.
#: The factory contract takes the cache directory + size cap even for
#: remote/shared stores — the directory doubles as the per-project
#: namespace the backend keys under.
CACHE_BACKEND_ENTRY_POINT_GROUP = "rebrew.cache_backends"


def _discover_cache_backends() -> dict[str, Callable[[Path, int], CacheBackend]]:
    """The backend registry: packaged ``diskcache`` + entry-point members.

    A duplicate name (including a plugin claiming ``diskcache``) raises
    :class:`RegistryError` — a cache backend name has one provider."""
    from rebrew.registry import (
        RegistryError,
        entry_point_registrations,
        import_registration,
        merge_into,
    )

    backends: dict[str, Callable[[Path, int], CacheBackend]] = {"diskcache": CompileCache}
    for reg in entry_point_registrations(CACHE_BACKEND_ENTRY_POINT_GROUP):
        factory = import_registration(reg)
        if not callable(factory):
            raise RegistryError(
                f"bad {reg.group} registration {reg.name!r} from {reg.origin}: "
                f"expected a callable factory, got {type(factory).__name__}"
            )
        merge_into(backends, reg.name, factory, reg.origin, group=reg.group)
    return backends


_CACHE_BACKENDS: dict[str, Callable[[Path, int], CacheBackend]] = _discover_cache_backends()


def available_cache_backends() -> list[str]:
    """Names of every registered cache backend (packaged + plugin)."""
    return sorted(_CACHE_BACKENDS)


# ---------------------------------------------------------------------------
# Cache key computation
# ---------------------------------------------------------------------------


@lru_cache(maxsize=64)
def include_fingerprint(include_dir: str) -> str:
    """Return a digest of the headers reachable from *include_dir*.

    Hashes ``(relative path, size, mtime_ns)`` of every header under the
    directory rather than its contents: a stat walk costs microseconds where a
    content read of an MSVC6 include tree costs megabytes, and a GA run issues
    thousands of key computations per function.  This is the same tradeoff
    ccache makes in its default mode — it can only be fooled by an edit that
    preserves both size and mtime.

    Memoized per process (headers are assumed stable for the lifetime of one
    rebrew invocation), so each include directory is walked at most once.
    Returns ``""`` for a path that is not an existing directory.
    """
    root = Path(include_dir)
    if not root.is_dir():
        return ""
    h = hashlib.sha256()
    try:
        headers = sorted(
            p for p in root.rglob("*") if p.suffix.lower() in _HEADER_SUFFIXES and p.is_file()
        )
    except OSError:
        return ""
    for path in headers:
        try:
            st = path.stat()
        except OSError:
            continue
        h.update(f"{path.relative_to(root)}\0{st.st_size}\0{st.st_mtime_ns}\0".encode())
    return h.hexdigest()


@lru_cache(maxsize=1024)
def source_digest(source_content: str) -> str:
    """SHA-256 hex of C source text, memoized per unique string.

    Flag sweeps / GA runs call :func:`compile_cache_key` once per combo with
    the *same* source text; re-hashing the full source each time was pure CPU
    on a warm cache (perf-review F3: 1-8s per 258k-combo sweep).  Python
    strings cache their own ``hash()`` after the first call, so the
    lru_cache lookup is cheap once a source string has been seen.

    Encodes with ``errors="surrogateescape"``: sources are read with
    ``decode("utf-8", errors="surrogateescape")`` (lossless for legacy
    cp1252/shift_jis bytes), so the strict ``encode("utf-8")`` round-trip
    raised ``UnicodeEncodeError`` for any non-UTF-8 source — which
    ``compile_and_compare`` then mislabeled as a COMPILE_ERROR, making
    legacy-encoded files permanently untestable.
    """
    return hashlib.sha256(source_content.encode("utf-8", errors="surrogateescape")).hexdigest()


# ---------------------------------------------------------------------------
# Header dependency resolution (per-source #include closure)
# ---------------------------------------------------------------------------

_INCLUDE_RE = re.compile(r"include(?:_next)?\b")


def _strip_leading_comments(line: str) -> str:
    """Return *line* with leading whitespace and C comments removed.

    ``#include`` directives can follow a ``/* comment */`` on the same line
    (``/* c */ #include <x.h>``); skipping the comment prefix keeps those
    from being missed (an under-approximation would risk a stale cache hit).
    """
    s = line.lstrip()
    while True:
        if s.startswith("/*"):
            end = s.find("*/")
            if end == -1:
                return ""
            s = s[end + 2 :].lstrip()
        elif s.startswith("//"):
            return ""
        else:
            return s


def _iter_include_specs(text: str) -> Iterator[tuple[str, str]]:
    """Yield ``(kind, name)`` for every ``#include`` directive in *text*.

    *kind* is ``"quote"`` (``#include "x.h"``), ``"angle"`` (``#include
    <x.h>``), ``"next"`` (``#include_next`` — treated as an angle search of
    the remaining dirs), or ``"nonliteral"`` for a macro-expanded include
    (``#include LIB_H``) that cannot be resolved statically.  Malformed
    directives yield ``("nonliteral", "")``.  Includes inside comments and
    ``#include``-shaped text outside directives are not matched (lines are
    scanned only at directive position).
    """
    for raw in text.splitlines():
        line = _strip_leading_comments(raw)
        if not line.startswith("#"):
            continue
        rest = line[1:].lstrip()
        m = _INCLUDE_RE.match(rest)
        if not m:
            continue
        # #include_next is yielded as "angle": the resolver searches all dirs
        # (an over-approximation of "the remaining dirs" — never a stale hit).
        tail = rest[m.end() :].lstrip()
        if tail.startswith('"'):
            end = tail.find('"', 1)
            yield ("quote", tail[1:end]) if end != -1 else ("nonliteral", "")
        elif tail.startswith("<"):
            end = tail.find(">")
            yield ("angle", tail[1:end]) if end != -1 else ("nonliteral", "")
        else:
            yield ("nonliteral", "")


def _find_in_dirs(name: Path, dirs: list[Path]) -> Path | None:
    """Locate *name* in the first of *dirs* that contains it.

    Exact match first; falls back to a case-insensitive scan per directory
    (wine/Windows resolution is case-insensitive while the host FS is not —
    a header included with different case than on disk would otherwise go
    untracked and risk a stale hit).  Rejects path-traversal components
    (``..`` / absolute paths) to avoid escaping the include roots.
    """
    # Reject traversal — otherwise ``#include "../../etc/passwd"`` would escape.
    if name.is_absolute() or ".." in name.parts:
        return None
    for d in dirs:
        try:
            candidate = (d / name).resolve()
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    for d in dirs:
        try:
            if not d.is_dir():
                continue
            # Only try case-insensitive fallback for single-component names;
            # sub-path includes need exact directory structure.
            if len(name.parts) != 1:
                continue
            for child in d.iterdir():
                if child.is_file() and child.name.lower() == name.name.lower():
                    return child.resolve()
        except OSError:
            continue
    return None


@lru_cache(maxsize=1024)
def _resolve_include_paths(
    source_content: str, source_dir: str | None, include_dirs: tuple[str, ...]
) -> tuple[tuple[str, ...], bool]:
    """Resolve the transitive ``#include`` closure of one translation unit.

    Returns ``(sorted absolute header paths, fallback)``.  *fallback* is
    True when any include was non-literal (``#include MACRO``) and callers
    must use conservative per-directory fingerprints instead.  Includes that
    resolve nowhere on the host are left untracked: either they resolve
    inside the immutable toolchain image (pinned by the toolchain digest in
    the key) or the compile errors and nothing is cached.  A header created
    later in a searched dir changes the resolved set on the next key
    computation, which changes the key — so membership changes are caught
    even though the closure itself is memoized.  Memoized per process; same
    tradeoff as :func:`include_fingerprint` (a header structure change mid
    run is not picked up until the next invocation).
    """
    search_dirs: list[Path] = []
    if source_dir:
        search_dirs.append(Path(source_dir))
    search_dirs += [Path(d) for d in include_dirs]

    reached: set[str] = set()
    fallback = False

    def _scan(text: str, base_dir: Path | None) -> None:
        nonlocal fallback
        for kind, name in _iter_include_specs(text):
            if kind == "nonliteral" or not name:
                fallback = True
                continue
            # Quote includes search the including file's directory first,
            # then the /I dirs; angle includes search the /I dirs only.
            # #include_next is treated as an angle search of all dirs (an
            # over-approximation — never a stale hit).
            if kind == "quote" and base_dir is not None:
                found = _find_in_dirs(Path(name), [base_dir, *search_dirs])
            else:
                found = _find_in_dirs(Path(name), search_dirs)
            if found is None:
                continue
            found_str = str(found)
            if found_str in reached:
                continue
            reached.add(found_str)
            try:
                header_text = found.read_bytes().decode("utf-8", errors="surrogateescape")
            except OSError:
                continue
            _scan(header_text, found.parent)

    _scan(source_content, Path(source_dir) if source_dir else None)
    return tuple(sorted(reached)), fallback


def _header_key_entries(
    paths: tuple[str, ...], source_dir: str | None, include_dirs: list[str]
) -> list[tuple[int, str, int, int]]:
    """Map resolved header paths to sorted ``(anchor, rel_path, size, mtime)``.

    *anchor* is the index of the search dir the header lives under — 0 for
    the source directory, ``i + 1`` for ``include_dirs[i]`` — so the key is
    stable across runs of one project.  Paths unreachable from any anchor
    fall back to their basename.  Entries are stat'ed fresh (an edit to an
    already-resolved header is picked up within a process); a file that
    vanished mid-run is skipped, which changes the key and forces a miss.
    """
    anchors: list[Path] = []
    if source_dir:
        anchors.append(Path(source_dir).resolve())
    anchors += [Path(d).resolve() for d in include_dirs]

    entries: list[tuple[int, str, int, int]] = []
    for p_str in paths:
        p = Path(p_str).resolve()
        rel = p.name
        anchor_idx = 0
        for idx, anchor in enumerate(anchors):
            try:
                rel = p.relative_to(anchor).as_posix()
                anchor_idx = idx
                break
            except ValueError:
                continue
        try:
            st = p.stat()
        except OSError:
            continue
        entries.append((anchor_idx, rel, st.st_size, st.st_mtime_ns))
    return sorted(entries)


def _dir_fingerprint_hash(include_dirs: list[str]) -> str:
    """Conservative whole-directory header fingerprint (ccache-style)."""
    h = hashlib.sha256()
    for d in include_dirs:
        h.update(include_fingerprint(d).encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Flag canonicalization (observational equivalence of flag sets)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _flag_group_ids() -> dict[str, str]:
    """Map each known flag token to its compiler-option group id.

    Derived from the auto-synced decomp.me flag definitions
    (:mod:`rebrew.matcher.flag_data`): a ``FlagSet`` is one compiler option
    whose members are mutually exclusive, and a ``Checkbox`` an on/off toggle.
    Flags within one group are **last-wins** (MSVC uses the last occurrence);
    flags across groups set distinct options and commute.
    """
    from rebrew.matcher.flag_data import COMMON_MSVC_FLAGS, MSVC6_FLAGS
    from rebrew.matcher.flags import Checkbox

    lookup: dict[str, str] = {}
    for flags in (MSVC6_FLAGS, COMMON_MSVC_FLAGS):
        for item in flags:
            members: tuple[str, ...] = (
                item.flags if not isinstance(item, Checkbox) else (item.flag,)
            )
            for member in members:
                lookup.setdefault(member, item.id)
    return lookup


def canonicalize_cflags(cflags: list[str]) -> list[str]:
    """Reduce a flag list to a canonical form that preserves compilation.

    Two flag lists that differ only in the **order of flags that set distinct
    compiler options**, or in **duplicated flags**, canonicalize to the same
    list — so :func:`compile_cache_key` yields one key per equivalence class,
    the equivalence being "the compiler produces the same object" (the paper's
    observational equivalence, read through the compiler as observer).  Sound:

    - identical flags are deduplicated (repeating a flag never changes the
      object);
    - within one option group (one ``FlagSet``/``Checkbox``, e.g. ``/O1`` vs
      ``/O2`` or ``/Gd`` vs ``/Gz``) only the LAST occurrence matters (MSVC
      last-wins), so earlier members are dropped;
    - flags across different option groups commute, so they are sorted by
      group id for a deterministic order;
    - flags absent from the synced definitions are unknown — kept as fixed
      anchors in their original position and never reordered relative to
      anything (an unknown flag could in principle conflict with a known
      group, so moving it would be unsound).

    ``/I``/``/D``/``/U`` and their arguments are not in the flag definitions,
    so they fall into the anchor bucket and keep their order — include search
    order and macro redefinition order still shape the key.
    """
    groups = _flag_group_ids()

    # 1) Normalize + dedupe identical tokens (keep first).
    normalized: list[str] = []
    seen: set[str] = set()
    for flag in cflags:
        tok = flag.strip().strip('"').strip("'")
        if tok and tok not in seen:
            seen.add(tok)
            normalized.append(tok)

    # 2) Collapse last-wins groups; sort across groups between unknown
    #    anchors (which act as fixed boundaries).
    out: list[str] = []
    segment: list[tuple[str, str]] = []  # (group_id, flag) for known flags
    group_last: dict[str, str] = {}

    def _flush() -> None:
        for gid, flag in segment:
            group_last[gid] = flag  # last occurrence wins
        for _gid, flag in sorted(group_last.items()):
            out.append(flag)
        segment.clear()
        group_last.clear()

    for flag in normalized:
        gid = groups.get(flag)
        if gid is None:
            _flush()
            out.append(flag)  # unknown → fixed anchor
        else:
            segment.append((gid, flag))
    _flush()
    return out


#: Digest for a translation unit with no header dependencies.  Never ``""`` —
#: the verify cache uses ``""`` to mark legacy entries (written before
#: per-entry header tracking) for a one-time re-verify, so a current entry's
#: no-deps fingerprint must be a non-empty, stable value.
_NO_DEPS_HASH = hashlib.sha256(b"").hexdigest()


def header_dependency_hash(
    source_content: str, source_dir: str | None, include_dirs: list[str]
) -> str:
    """SHA-256 over the translation unit's reached-header dependencies.

    Resolves the transitive ``#include`` closure of *source_content* and
    hashes each reached header's ``(anchor, rel_path, size, mtime_ns)`` in
    sorted order.  An edit to a reached header changes the digest; an edit
    to an unreached header does not.  Falls back to conservative per-directory
    fingerprints when the closure cannot be resolved statically (non-literal
    ``#include``, or ``/FI``-style force-includes — the caller forces this).
    Returns :data:`_NO_DEPS_HASH` for a unit with no header dependencies
    (never ``""`` — the verify cache reserves ``""`` for legacy entries).

    Shared by the compile-cache key and the verify-cache per-entry guard, so
    both caches invalidate on exactly the same header dependency.
    """
    paths, fallback = _resolve_include_paths(source_content, source_dir, tuple(include_dirs))
    if fallback:
        return _dir_fingerprint_hash(include_dirs)
    if not paths:
        return _NO_DEPS_HASH
    h = hashlib.sha256()
    for anchor_idx, rel, size, mtime_ns in _header_key_entries(paths, source_dir, include_dirs):
        h.update(f"{anchor_idx}\0{rel}\0{size}\0{mtime_ns}\0".encode())
    return h.hexdigest()


def compile_cache_key(
    source_content: str,
    source_filename: str,
    cflags: list[str],
    include_dirs: list[str],
    toolchain_id: str,
    source_ext: str = ".c",
    source_dir: str | None = None,
) -> str:
    """Compute a SHA-256 cache key from compilation inputs.

    All inputs that affect the ``.obj`` output must be included:

    - **source_content** — the actual C code (not the file path)
    - **source_filename** — the filename the compiler sees (affects
      ``__FILE__`` expansion); use the basename, not a temp path
    - **cflags** — all compiler flags in order (base + user + include).
      Canonicalized via :func:`canonicalize_cflags` before hashing: flags
      that set distinct compiler options may appear in any order, duplicates
      are dropped, and last-wins groups collapse to their final value —
      so the key is shared by flag lists the compiler cannot tell apart,
      while genuinely different compilations (e.g. ``/O1`` vs ``/O2``, or
      ``/O1 /O2`` vs ``/O2 /O1``) still get distinct keys.
    - **include_dirs** — ordered list of ``/I`` directory paths.  The
      source's ``#include`` closure is resolved against them (plus
      *source_dir* for quote includes) and each **reached** header is
      fingerprinted individually (see :func:`header_dependency_hash`), so
      editing a header invalidates exactly the entries that reach it.
      ``/FI``/``-include`` force-includes and non-literal ``#include``
      directives fall back to whole-directory fingerprints.
    - **toolchain_id** — identifies the compiler binary and runner
      (e.g. ``"wine /abs/path/CL.EXE"``)
    - **source_ext** — file extension (``.c``, ``.cpp``)
    - **source_dir** — directory of the real source file (quote-include
      search anchor; may be ``None`` when compiling a bare source string)

    Returns a 64-char hex digest string.

    .. note:: Callers must include ``base_cflags`` in the *cflags* list —
       this function does not automatically prepend them.
    """
    h = hashlib.sha256()
    h.update(f"v{CACHE_SCHEMA_VERSION}\0".encode())
    # Source digest memoized per string (see source_digest) — the running
    # hash consumes the digest's hex form, not the raw source.
    h.update(source_digest(source_content).encode())
    h.update(f"\0filename={source_filename}\0".encode())
    h.update(f"\0ext={source_ext}\0".encode())
    # Flags are canonicalized first (see canonicalize_cflags): the hash sees
    # the equivalence class, not the raw list.  Flags and include dirs are
    # separated by \0 to prevent collisions (e.g. "flag1 flag2" !=
    # "flag1flag2").  This assumes none of the inputs contain embedded NUL
    # bytes, which is safe because MSVC flags, filenames, and C source are
    # NUL-free text.
    h.update(f"\0cflags={chr(0).join(canonicalize_cflags(cflags))}\0".encode())
    h.update(f"\0includes={chr(0).join(include_dirs)}\0".encode())
    # A /FI/-include force-include pulls a header's content into every
    # compile regardless of the source's directives — resolution cannot see
    # it, so fall back to conservative per-directory fingerprints.
    force_include = any(f.startswith(("/FI", "-include")) for f in cflags)
    headers = (
        header_dependency_hash(source_content, source_dir, include_dirs)
        if not force_include
        else _dir_fingerprint_hash(include_dirs)
    )
    h.update(f"\0headers={headers}\0".encode())
    h.update(f"\0toolchain={toolchain_id}\0".encode())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Module-level cache registry (avoids re-opening SQLite on every call)
# ---------------------------------------------------------------------------

_caches: dict[tuple[str, str], CacheBackend] = {}
_caches_lock = threading.Lock()


def get_compile_cache(project_root: Path, backend: str = "diskcache") -> CacheBackend:
    """Return a shared cache instance for a project root and backend.

    The diskcache backend stores at ``{project_root}/.rebrew/compile_cache/``.
    Multiple calls with the same ``(root, backend)`` return the same instance.

    Args:
        project_root: The project root (cache namespace).
        backend: Name of a registered cache backend (``[cache] backend`` in
            rebrew-project.toml; default ``diskcache``).

    Raises:
        ValueError: When *backend* is not a registered backend.
    """
    factory = _CACHE_BACKENDS.get(backend)
    if factory is None:
        raise ValueError(
            f"unknown cache backend {backend!r} (known: {available_cache_backends()}) — "
            f"set [cache] backend in rebrew-project.toml"
        )
    cache_dir = str((project_root / ".rebrew" / "compile_cache").resolve())
    key = (backend, cache_dir)
    with _caches_lock:
        if key not in _caches:
            _caches[key] = factory(Path(cache_dir), _DEFAULT_SIZE_LIMIT)
        return _caches[key]


def close_all_caches() -> None:
    """Close all open cache instances (for clean shutdown)."""
    with _caches_lock:
        for cache in _caches.values():
            cache.close()
        _caches.clear()


atexit.register(close_all_caches)
