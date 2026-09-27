"""Hash-based compile cache for skipping redundant compiler invocations.

Each docker-backed compile (and any native plugin toolchain without an
image) costs hundreds of milliseconds of container/subprocess startup.
During ``rebrew match --all`` (100 gen × 30 pop × N functions) and
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
flag classes and repeats within one option group collapse to one key, while order-sensitive
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
back to per-directory fingerprints of the source dir and every include dir (the conservative
ccache-style mode, via :func:`include_fingerprint`).  Resolution is
memoized per process keyed by search-directory mtimes: a header *created*
while a long GA run is in flight bumps the parent directory's mtime and is
picked up on the next key computation (content edits to already resolved
headers are still picked up, because each reached file is re-statted
at key time).
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import logging
import re
import threading
import unicodedata
from collections.abc import Callable, Iterator, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

import diskcache

logger = logging.getLogger(__name__)

# Bump on key semantics changes to invalidate stale entries.
CACHE_SCHEMA_VERSION = 6

# Warn once per process *and per operation*: a corrupt/contended store
# degrades every get/put, and one line per lookup would flood a GA batch's
# log without adding info.  Keying on the op keeps the repeat-suppression
# while still surfacing a failure mode the process has not reported yet (a
# close that fails long after the first get).  A GA batch has every worker
# hitting the same store, so the latch is a check-then-act and needs the
# lock to admit exactly one of them.
_degraded_lock = threading.Lock()
_degraded_logged: set[str] = set()


def _warn_cache_failure(op: str, exc: Exception) -> None:
    """Log the first cache failure per process and per operation at WARNING.

    The cache is an accelerator: any failure must degrade to a miss/skip,
    never break compilation — but silently losing it would leave the user
    wondering why every compile suddenly pays full subprocess cost.
    """
    with _degraded_lock:
        if op in _degraded_logged:
            return
        _degraded_logged.add(op)
    logger.warning(
        "Compile cache %s failed (%s: %s) — continuing with degraded/no cache; "
        "delete .rebrew/compile_cache/ to reset a corrupted store",
        op,
        type(exc).__name__,
        exc,
    )


# Extensions treated as headers when fingerprinting an include directory.
_HEADER_SUFFIXES = frozenset({".h", ".hpp", ".hxx", ".inl", ".hh"})

#: Bytes per mebibyte.  Every byte figure this module reports is binary
#: (1024-based), so the display unit is MiB, not the decimal MB.
_BYTES_PER_MIB = 1024 * 1024

#: Default size limit: 500 MiB with LRU eviction when the limit is reached.
#: Overridden per project by ``[cache] size_limit_mib`` in rebrew-project.toml.
DEFAULT_CACHE_SIZE_LIMIT_MIB = 500
_DEFAULT_SIZE_LIMIT = DEFAULT_CACHE_SIZE_LIMIT_MIB * _BYTES_PER_MIB


class NoPickleDisk(diskcache.Disk):  # type: ignore[misc]
    """diskcache Disk that never pickle-deserializes keys or values.

    Upstream diskcache (≤5.6.3, GHSA-w8v5-vhqr-4h9v) calls ``pickle.load`` on
    any cache entry stored with ``MODE_PICKLE``.  An attacker who can write the
    cache directory can plant such an entry and achieve RCE on the next read.
    Compile caches only ever store ``(str key, bytes value)``, which Disk already
    persists without pickling; this subclass refuses pickle modes so a poisoned
    store degrades to a miss instead of executing attacker bytes.
    """

    def get(self, key: object, raw: bool) -> object:
        if not raw:
            raise ValueError("refusing pickled cache key")
        return super().get(key, raw)

    def store(
        self, value: object, read: bool, key: object = diskcache.UNKNOWN
    ) -> tuple[int, int, str | None, object]:
        if not read and type(value) not in (bytes, str, int, float):
            raise TypeError(
                f"NoPickleDisk refuses non-primitive values ({type(value).__name__}); "
                "encode to bytes before caching"
            )
        return super().store(value, read, key=key)  # type: ignore[no-any-return]

    def fetch(self, mode: int, filename: str | None, value: object, read: bool) -> object:
        # MODE_PICKLE == 4 in diskcache.core; compare by int to avoid importing
        # a private constant that is not part of the public package API.
        if mode == 4:
            raise ValueError("refusing pickled cache value")
        return super().fetch(mode, filename, value, read)


class CompileCache:
    """Disk-backed cache mapping compile inputs to raw .obj bytes.

    Backed by ``diskcache.Cache`` (SQLite + filesystem), which is
    thread-safe and supports concurrent readers/writers.  Values are stored
    through :class:`NoPickleDisk` so a poisoned cache cannot RCE on read
    (GHSA-w8v5-vhqr-4h9v defense in depth; chmod 0o700 remains).

    The instance outlives any single call: a GA holds one for a whole run
    while another thread can close it.  ``close()`` is therefore serialized
    against store use, so a concurrent caller never reads a torn-down store.

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
        # diskcache is thread-safe, but ``close()`` is not: it tears down the
        # SQLite handle and nulls ``self._cache`` while a worker on another
        # target may be mid-``get()`` on the same instance.  The LRU eviction in
        # ``get_compile_cache`` reaches it once _CACHES_MAX project roots are
        # open, which ``match --all-targets`` does: each target compiles under
        # its own pool thread and calls get_compile_cache per compile, so one
        # target's eviction lands inside another's lookup.  Serialize store use
        # against close so the handle is never used after it is torn down.
        # Held only around a single SQLite call, never across a compile, so it
        # cannot order against any other lock.
        self._store_lock = threading.Lock()
        # None when the store could not be opened (corrupt SQLite file,
        # unwritable directory): the cache runs disabled instead of raising,
        # so callers keep compiling at full subprocess cost.
        self._cache: diskcache.Cache | None
        try:
            self._cache = diskcache.Cache(str(cache_dir), size_limit=size_limit, disk=NoPickleDisk)
            # Owner-only dir: even with NoPickleDisk, another local user should
            # not be able to replace value files or the SQLite DB.
            with contextlib.suppress(OSError):
                Path(cache_dir).chmod(0o700)
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
                with self._store_lock:
                    store = self._cache
                    result = store.get(key, default=None) if store is not None else None
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
            with self._store_lock:
                store = self._cache
                if store is not None:
                    store.set(key, obj_bytes)
        except Exception as exc:  # a failed write only costs future hits
            _warn_cache_failure("store", exc)

    @property
    def volume(self) -> int:
        """Total bytes used by the cache on disk."""
        try:
            with self._store_lock:
                store = self._cache
                return int(store.volume()) if store is not None else 0
        except Exception as exc:
            logging.getLogger(__name__).debug("cache volume failed: %s", exc)
            return 0

    @property
    def count(self) -> int:
        """Number of entries in the cache."""
        try:
            with self._store_lock:
                store = self._cache
                return len(store) if store is not None else 0
        except Exception as exc:
            logging.getLogger(__name__).debug("cache count failed: %s", exc)
            return 0

    def clear(self) -> None:
        """Remove all cached entries."""
        try:
            with self._store_lock:
                store = self._cache
                if store is not None:
                    store.clear()
        except Exception as exc:
            _warn_cache_failure("clear", exc)

    def is_open(self) -> bool:
        """True while the store is still usable.

        Read under the store lock, because ``close()`` nulls the handle from
        another thread: the registry uses this to drop a dead backend instead
        of handing it to the next compile.
        """
        with self._store_lock:
            return self._cache is not None

    def close(self) -> None:
        """Close the underlying diskcache store.

        Waits for an in-flight ``get``/``put`` on another thread to finish
        first, so the SQLite handle is never torn down under a live lookup.
        """
        with self._store_lock:
            store = self._cache
            if store is None:
                return
            try:
                store.close()
            except Exception as exc:
                _warn_cache_failure("close", exc)
            finally:
                self._cache = None

    def stats(self) -> dict[str, int | float]:
        """Return cache statistics as a dict.

        Includes in-process hit/miss counters under ``session_hits``,
        ``session_misses``, and ``session_hit_rate_pct``.  These reset
        when the process exits; they reflect only the current session.
        """
        with self._counter_lock:
            hits = self.hits
            misses = self.misses
        total_lookups = hits + misses
        hit_rate = round(100.0 * hits / total_lookups, 1) if total_lookups > 0 else 0.0
        with self._store_lock:
            store = self._cache
            size_limit = store.size_limit if store is not None else 0
        return {
            "entries": self.count,
            "volume_bytes": self.volume,
            "volume_mib": round(self.volume / _BYTES_PER_MIB, 2),
            "size_limit_mib": round(size_limit / _BYTES_PER_MIB, 2),
            "session_hits": hits,
            "session_misses": misses,
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
#:
#: ``is_open`` reports whether the store is still usable after ``close``; the
#: registry consults it under its own lock to drop a dead backend rather than
#: hand it to the next compile.  A plugin backend must answer it without
#: blocking, since the registry lock is process-wide.
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
    def is_open(self) -> bool: ...
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

#: Backend used when rebrew-project.toml has no ``[cache] backend``.
DEFAULT_CACHE_BACKEND = "diskcache"


def _discover_cache_backends() -> dict[str, Callable[[Path, int], CacheBackend]]:
    """The backend registry: packaged ``diskcache`` + entry-point members.

    An optional registry: a broken or conflicting member is skipped with a
    warning (the store falls back to ``diskcache``; a configured backend
    name that never registered still errors at ``get_compile_cache``)."""
    from rebrew.registry import (
        RegistryError,
        entry_point_registrations,
        load_registration_optional,
        merge_into,
    )

    backends: dict[str, Callable[[Path, int], CacheBackend]] = {"diskcache": CompileCache}
    for reg in entry_point_registrations(CACHE_BACKEND_ENTRY_POINT_GROUP):
        factory = load_registration_optional(reg, logger)
        if factory is None:
            continue
        if not callable(factory):
            logger.warning(
                "skipping %s registration %r: expected a callable factory, got %s",
                reg.group,
                reg.name,
                type(factory).__name__,
            )
            continue
        try:
            merge_into(backends, reg.name, factory, reg.origin, group=reg.group)
        except RegistryError as exc:
            logger.warning("skipping %s registration %r: %s", reg.group, reg.name, exc)
    return backends


_CACHE_BACKENDS: dict[str, Callable[[Path, int], CacheBackend]] = _discover_cache_backends()


def refresh_cache_backends() -> dict[str, Callable[[Path, int], CacheBackend]]:
    """Re-run discovery and refresh the :data:`_CACHE_BACKENDS` snapshot.

    Long-lived processes can pick up cache-backend plugins installed after
    startup without a restart."""
    global _CACHE_BACKENDS

    _CACHE_BACKENDS = _discover_cache_backends()
    return _CACHE_BACKENDS


def available_cache_backends() -> list[str]:
    """Names of every registered cache backend (packaged + plugin)."""
    return sorted(_CACHE_BACKENDS)


# ---------------------------------------------------------------------------
# Cache key computation
# ---------------------------------------------------------------------------


# Path-list memo for :func:`include_fingerprint`:
# ``dir → (((subdir, mtime_ns), ...), paths)``.  The list is reused only while
# the mtime of the root AND every subdirectory is unchanged: a create / delete /
# rename bumps only the immediate parent's mtime, so a header added under
# ``sys/`` must invalidate even though the root mtime is stable.  Each call
# still re-stats every listed header so an edit that preserves the directory
# mtimes still changes the digest.  Bounded + locked: verify -j N and GA
# workers share this map.
_INCLUDE_FP_PATHS: dict[str, tuple[tuple[tuple[str, int], ...], tuple[str, ...]]] = {}
_INCLUDE_FP_PATHS_MAX = 64
_INCLUDE_FP_LOCK = threading.Lock()


def _dir_mtimes_match(dir_mtimes: tuple[tuple[str, int], ...]) -> bool:
    """True when every recorded directory still exists with the same mtime."""
    try:
        return all(Path(d).stat().st_mtime_ns == m for d, m in dir_mtimes)
    except OSError:
        return False


def _clear_include_fingerprint_cache() -> None:
    """Drop the include-fingerprint path memo (tests / forced refresh)."""
    with _INCLUDE_FP_LOCK:
        _INCLUDE_FP_PATHS.clear()


def include_fingerprint(include_dir: str) -> str:
    """Return a digest of the headers reachable from *include_dir*.

    Hashes ``(relative path, size, mtime_ns)`` of every header under the
    directory rather than its contents: a stat walk costs microseconds where a
    content read of an MSVC6 include tree costs megabytes, and a GA run issues
    thousands of key computations per function.  This is the same tradeoff
    ccache makes in its default mode — it can only be fooled by an edit that
    preserves both size and mtime.

    The header *path list* is memoized per directory while the mtimes of the
    directory and all its subdirectories are stable (membership changes at any
    depth invalidate); each call re-stats
    those paths so content edits are visible mid-run without a process
    restart.  A walk whose directory mtimes change before it is published is
    not memoized, and a publish never replaces a still-valid peer entry that
    already lists at least as many headers: verify ``-j N`` and GA workers
    share this map, and a slow walk that missed a header created mid-scan
    must not clobber the snapshot that saw it.  Returns ``""`` for a path
    that is not an existing directory.
    An ``OSError`` while walking an existing directory returns a distinct
    unreadable sentinel (never ``""``) so header deps are not silently
    dropped from the compile-cache key.  A listed header that cannot be
    stat'd is mixed in as its own unreadable marker for the same reason:
    omitting it collides with a tree that does not contain the header.
    """
    root = Path(include_dir)
    if not root.is_dir():
        return ""
    with _INCLUDE_FP_LOCK:
        cached = _INCLUDE_FP_PATHS.get(include_dir)
    paths = cached[1] if cached is not None and _dir_mtimes_match(cached[0]) else None

    if paths is None:
        try:
            dir_mtimes = [(str(root), root.stat().st_mtime_ns)]
            path_list = []
            for p in root.rglob("*"):
                if p.is_dir():
                    dir_mtimes.append((str(p), p.stat().st_mtime_ns))
                elif p.suffix.lower() in _HEADER_SUFFIXES and p.is_file():
                    path_list.append(p)
            path_list.sort()
        except OSError as exc:
            # "" is reserved for a missing dir.  Returning it here drops header
            # deps from the cache key and can serve a stale .obj after edits.
            logging.getLogger(__name__).warning(
                "include fingerprint failed for %s: %s — treating as unreadable",
                include_dir,
                exc,
            )
            return hashlib.sha256(
                f"\0unreadable\0{include_dir}\0".encode("utf-8", errors="surrogateescape")
            ).hexdigest()
        paths = tuple(str(p) for p in path_list)
        recorded = tuple(dir_mtimes)
        with _INCLUDE_FP_LOCK:
            existing = _INCLUDE_FP_PATHS.get(include_dir)
            if (
                existing is not None
                and _dir_mtimes_match(existing[0])
                and len(existing[1]) >= len(paths)
            ):
                # A peer already published a snapshot that is still current
                # and at least as complete.  Keep it: our walk may have
                # started earlier and missed a header the peer saw.
                paths = existing[1]
            elif _dir_mtimes_match(recorded):
                if (
                    len(_INCLUDE_FP_PATHS) >= _INCLUDE_FP_PATHS_MAX
                    and include_dir not in _INCLUDE_FP_PATHS
                ):
                    oldest = next(iter(_INCLUDE_FP_PATHS))
                    _INCLUDE_FP_PATHS.pop(oldest, None)
                _INCLUDE_FP_PATHS[include_dir] = (recorded, paths)
            # else: a create/delete landed during the walk.  Hash this
            # snapshot for the caller, but do not pin it — the recorded
            # mtimes would no longer describe the path list.

    h = hashlib.sha256()
    for p_str in paths:
        path = Path(p_str)
        try:
            st = path.stat()
        except OSError:
            # Dropping the header makes this digest identical to a tree that
            # never contained it, so a compile from before it existed is a
            # hit.  An unreadable marker keeps the key distinct.
            try:
                ident = path.relative_to(root).as_posix()
            except ValueError:
                ident = p_str
            h.update(f"\0unreadable\0{ident}\0".encode("utf-8", errors="surrogateescape"))
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            # A real include that resolved outside the project root (a
            # system or toolchain header).  Dropping it would alias this
            # closure onto a smaller one, so it gets the same identity
            # treatment as the unreadable branch above.
            h.update(f"\0outside-root\0{p_str}\0".encode("utf-8", errors="surrogateescape"))
            continue
        h.update(
            f"{rel}\0{st.st_size}\0{st.st_mtime_ns}\0".encode("utf-8", errors="surrogateescape")
        )
    return h.hexdigest()


# Test / forced-refresh hook — same attribute name as the former ``lru_cache``.
include_fingerprint.cache_clear = _clear_include_fingerprint_cache  # type: ignore[attr-defined]


@lru_cache(maxsize=1024)
def source_digest(source_content: str) -> str:
    """SHA-256 hex of C source text, memoized per unique string.

    Flag sweeps / GA runs call :func:`compile_cache_key` once per combo with
    the *same* source text; re-hashing the full source each time was pure CPU
    on a warm cache (1-8s per 258k-combo sweep).  Python
    strings cache their own ``hash()`` after the first call, so the
    lru_cache lookup is cheap once a source string has been seen.

    Encodes with ``errors="surrogateescape"``: compile/GA paths read sources
    via ``decode("utf-8", errors="surrogateescape")`` /
    :func:`rebrew.utils.read_compile_source` (lossless for legacy
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
    <x.h>`` and ``#include_next``), or ``"nonliteral"`` for a macro-expanded
    include (``#include LIB_H``) that cannot be resolved statically.
    Malformed directives yield ``("nonliteral", "")``.  Includes inside
    comments and ``#include``-shaped text outside directives are not matched
    (lines are scanned only at directive position).
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
        try:
            if not d.is_dir():
                continue
            # Only try case-insensitive fallback for single-component names;
            # sub-path includes need exact directory structure.  The fallback
            # runs inside the same directory iteration as the exact match:
            # include search order is first-directory-wins, so a later
            # directory's exact hit must not outrank an earlier one's
            # case-folded hit (wine resolves case-insensitively per -I dir).
            if len(name.parts) != 1:
                continue
            norm_name = unicodedata.normalize("NFC", name.name).casefold()
            for child in d.iterdir():
                if (
                    child.is_file()
                    and unicodedata.normalize("NFC", child.name).casefold() == norm_name
                ):
                    return child.resolve()
        except OSError:
            continue
    return None


# Include-closure memo for :func:`_resolve_include_paths`:
# ``(source, source_dir, include_dirs, dir_mtimes) →
#   (paths, fallback, header_stats, unresolved)``.
# Bounded + locked: verify -j N and GA workers share this map.
_INCLUDE_CLOSURE_MEMO: dict[
    tuple[str, str | None, tuple[str, ...], tuple[int, ...]],
    tuple[
        tuple[str, ...],
        bool,
        tuple[tuple[int, int], ...],
        tuple[tuple[str, tuple[str, ...]], ...],
    ],
] = {}
_INCLUDE_CLOSURE_MEMO_MAX = 1024
_INCLUDE_CLOSURE_LOCK = threading.Lock()


def _search_dir_mtimes(source_dir: str | None, include_dirs: tuple[str, ...]) -> tuple[int, ...]:
    """Directory mtimes for include-resolution cache identity.

    Creating/deleting a header bumps the parent directory's mtime, so a
    mid-run membership change gets a fresh resolution without a process
    restart.
    """
    dirs: tuple[str, ...] = ((source_dir,) if source_dir else ()) + include_dirs
    mtimes: list[int] = []
    for d in dirs:
        try:
            mtimes.append(Path(d).stat().st_mtime_ns)
        except OSError:
            mtimes.append(0)
    return tuple(mtimes)


def _unresolved_still_missing(
    unresolved: Sequence[tuple[str, tuple[str, ...]]],
) -> bool:
    """True while every include that missed on the last scan still misses.

    A header created in a searched directory's *subdirectory* bumps no
    mtime the memo is keyed on, so without this recheck the closure would
    stay empty for the life of the process and every later edit to the new
    header would be a cache hit.
    """
    for name, dirs in unresolved:
        if _find_in_dirs(Path(name), [Path(d) for d in dirs]) is not None:
            return False
    return True


def _resolve_include_paths(
    source_content: str, source_dir: str | None, include_dirs: tuple[str, ...]
) -> tuple[tuple[str, ...], bool]:
    """Resolve the transitive ``#include`` closure of one translation unit.

    Returns ``(sorted absolute header paths, fallback)``.  *fallback* is
    True when any include was non-literal (``#include MACRO``) and callers
    must use conservative per-directory fingerprints instead.  Includes that
    resolve nowhere on the host are left untracked: either they resolve
    inside the immutable toolchain image (pinned by the toolchain digest in
    the key) or the compile errors and nothing is cached.

    Memoized on ``(source, dirs, dir_mtimes)`` and reused only while every
    reached header keeps its ``(mtime_ns, size)`` and every missed include
    still misses: a header created later in a searched dir bumps that
    directory's mtime, an in-place header edit
    (which may add or drop an ``#include``) changes that header's stat, so
    either forces a re-resolve.  A scan that races an edit is returned for
    this call but not published: storing the post-edit stats next to the
    pre-edit closure would make the next lookup trust a stale include set.
    A still-valid peer entry is kept instead of overwritten, so parallel
    flag-sweep workers cannot clobber a fresher closure with a slower scan.
    """
    key = (source_content, source_dir, include_dirs, _search_dir_mtimes(source_dir, include_dirs))
    with _INCLUDE_CLOSURE_LOCK:
        cached = _INCLUDE_CLOSURE_MEMO.get(key)
    if (
        cached is not None
        and _header_stats(cached[0]) == cached[2]
        and _unresolved_still_missing(cached[3])
    ):
        return cached[0], cached[1]
    misses: list[tuple[str, tuple[str, ...]]] = []
    paths, fallback, observed, consistent = _scan_include_closure(
        source_content, source_dir, include_dirs, unresolved=misses
    )
    if not consistent or _header_stats(paths) != observed or not _unresolved_still_missing(misses):
        return paths, fallback
    with _INCLUDE_CLOSURE_LOCK:
        existing = _INCLUDE_CLOSURE_MEMO.get(key)
        if (
            existing is not None
            and _header_stats(existing[0]) == existing[2]
            and _unresolved_still_missing(existing[3])
        ):
            return existing[0], existing[1]
        if _header_stats(paths) != observed or not _unresolved_still_missing(misses):
            return paths, fallback
        if (
            len(_INCLUDE_CLOSURE_MEMO) >= _INCLUDE_CLOSURE_MEMO_MAX
            and key not in _INCLUDE_CLOSURE_MEMO
        ):
            _INCLUDE_CLOSURE_MEMO.pop(next(iter(_INCLUDE_CLOSURE_MEMO)), None)
        _INCLUDE_CLOSURE_MEMO[key] = (paths, fallback, observed, tuple(misses))
    return paths, fallback


def _header_stats(paths: tuple[str, ...]) -> tuple[tuple[int, int], ...]:
    """``(mtime_ns, size)`` per path; ``(-1, -1)`` for one that cannot be stat'ed."""
    out: list[tuple[int, int]] = []
    for p in paths:
        try:
            st = Path(p).stat()
        except OSError:
            out.append((-1, -1))
            continue
        out.append((st.st_mtime_ns, st.st_size))
    return tuple(out)


def _scan_include_closure(
    source_content: str,
    source_dir: str | None,
    include_dirs: tuple[str, ...],
    *,
    unresolved: list[tuple[str, tuple[str, ...]]] | None = None,
) -> tuple[tuple[str, ...], bool, tuple[tuple[int, int], ...], bool]:
    """Uncached body of :func:`_resolve_include_paths`.

    The third element is ``(mtime_ns, size)`` captured around each header
    read, in the same order as the returned paths.  The fourth is False when
    a header's stat changed between the read's bracketing stats — the bytes
    and the snapshot do not describe the same file, so the caller must not
    memoize them.  Each include that resolved nowhere is appended to
    *unresolved* as ``(name, directories searched)``, so the caller can
    revalidate the memo when one of those headers is created later.
    """
    search_dirs: list[Path] = []
    if source_dir:
        search_dirs.append(Path(source_dir))
    search_dirs += [Path(d) for d in include_dirs]
    # Angle includes (and #include_next) never see the including file's own
    # directory, matching the compiler: pinning the source-dir copy of a
    # header the compiler ignores tracks the wrong file, so an edit to the
    # one actually read left the cache key unmoved.
    misses: list[tuple[str, tuple[str, ...]]] = [] if unresolved is None else unresolved

    reached: set[str] = set()
    observed: dict[str, tuple[int, int]] = {}
    fallback = False
    consistent = True

    def _scan(text: str, base_dir: Path | None) -> None:
        nonlocal fallback, consistent
        for kind, name in _iter_include_specs(text):
            if kind == "nonliteral" or not name:
                fallback = True
                return
            # Quote includes search the including file's directory first,
            # then the /I dirs; angle includes search the /I dirs only.
            # #include_next is treated as an angle search of all dirs (an
            # over-approximation — never a stale hit).
            if kind == "quote" and base_dir is not None:
                dirs = [base_dir, *search_dirs]
            else:
                dirs = [Path(d) for d in include_dirs]
            found = _find_in_dirs(Path(name), dirs)
            if found is None:
                # Creating a header bumps the mtime of its immediate parent,
                # which may sit below a searched directory and so never reach
                # the directory mtimes the memo is keyed on.  Record the miss
                # instead: re-running these lookups is a few stats per
                # unresolved include, and it is what makes a header added
                # mid-run invalidate the memo.
                misses.append((name, tuple(str(d) for d in dirs)))
                continue
            found_str = str(found)
            if found_str in reached:
                continue
            reached.add(found_str)
            try:
                before = found.stat()
                raw = found.read_bytes()
                after = found.stat()
            except OSError:
                # The compiler may still read this header and its includes.
                # Hashing only the stat (or skipping the file) serves an
                # object compiled against a different closure.  Fall back
                # for this call and do not memoize the failure.
                fallback = True
                consistent = False
                reached.discard(found_str)
                return
            if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
                consistent = False
            observed[found_str] = (after.st_mtime_ns, after.st_size)
            header_text = raw.decode("utf-8", errors="surrogateescape")
            _scan(header_text, found.parent)
            if fallback:
                return

    _scan(source_content, Path(source_dir) if source_dir else None)
    paths = tuple(sorted(reached))
    stats = tuple(observed.get(p, (-1, -1)) for p in paths)
    return paths, fallback, stats, consistent


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
            # Omitting the header makes this key identical to one where the
            # file does not exist, so a .obj compiled before the read failure
            # is served from cache.  -1 is not a reachable size or mtime_ns.
            entries.append((anchor_idx, rel, -1, -1))
            continue
        entries.append((anchor_idx, rel, st.st_size, st.st_mtime_ns))
    return sorted(entries)


def dir_fingerprint_hash(source_dir: str | None, include_dirs: list[str]) -> str:
    """Conservative whole-directory header fingerprint (ccache-style).

    Covers *source_dir* as well as the ``/I`` dirs: quote includes search it
    first, so leaving it out would miss an edit to a source-local header.
    """
    h = hashlib.sha256()
    for d in [source_dir, *include_dirs] if source_dir else include_dirs:
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
    (:mod:`rebrew.flag_data`): a ``FlagSet`` is one compiler option
    whose members are mutually exclusive, and a ``Checkbox`` an on/off toggle.
    Flags within one group are **last-wins** (MSVC uses the last occurrence);
    flags across groups set distinct options and commute.
    """
    from rebrew.flag_data import COMMON_MSVC_FLAGS, MSVC6_FLAGS
    from rebrew.flags import Checkbox

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
    compiler options**, or in **repeats within one option group**, canonicalize to the same
    list — so :func:`compile_cache_key` yields one key per equivalence class,
    the equivalence being "the compiler produces the same object" (the paper's
    observational equivalence, read through the compiler as observer).  Sound:

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

    # 1) Normalize.  No token dedupe: keeping the first of `/O1 /O2 /O1`
    #    drops the winning `/O1`, and an unknown repeated token (`-O2 -O0
    #    -O2`, `/D A /D B`) is not idempotent.  Known-group repeats collapse
    #    in step 2.
    normalized = [tok for flag in cflags if (tok := flag.strip().strip('"').strip("'"))]

    # 2) Collapse last-wins groups; sort across groups between unknown
    #    anchors (which act as fixed boundaries).
    out: list[str] = []
    segment: list[tuple[str, str]] = []  # (group_id, flag) for known flags
    group_last: dict[str, str] = {}

    def _flush() -> None:
        group_last.update(dict(segment))  # last occurrence wins
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

#: Flag prefixes that inject a header the source never ``#include``s:
#: MSVC ``/FI`` (also spelled ``-FI``), GCC/Clang ``-include`` /
#: ``--include`` / ``-imacros``, Watcom ``-fi=``.  Case-sensitive: MSVC
#: ``/Fi`` names the preprocessor output file instead.
FORCE_INCLUDE_PREFIXES = ("/FI", "-FI", "-include", "--include", "-imacros", "-fi=")


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
        return dir_fingerprint_hash(source_dir, include_dirs)
    if not paths:
        return _NO_DEPS_HASH
    h = hashlib.sha256()
    for anchor_idx, rel, size, mtime_ns in _header_key_entries(paths, source_dir, include_dirs):
        h.update(
            f"{anchor_idx}\0{rel}\0{size}\0{mtime_ns}\0".encode("utf-8", errors="surrogateescape")
        )
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
      that set distinct compiler options may appear in any order,
      and last-wins groups collapse to their final value —
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
    - **toolchain_id** — identifies the compiler: the docker image tag plus
      its content id when available (``compile._toolchain_cache_id``), or
      ``native:<name>[@<sha16>]`` for an image-less plugin toolchain
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
    h.update(f"\0filename={source_filename}\0".encode("utf-8", errors="surrogateescape"))
    h.update(f"\0ext={source_ext}\0".encode("utf-8", errors="surrogateescape"))
    # Flags are canonicalized first (see canonicalize_cflags): the hash sees
    # the equivalence class, not the raw list.  Flags and include dirs are
    # separated by \0 to prevent collisions (e.g. "flag1 flag2" !=
    # "flag1flag2").  This assumes none of the inputs contain embedded NUL
    # bytes, which is safe because MSVC flags, filenames, and C source are
    # NUL-free text.
    h.update(
        f"\0cflags={chr(0).join(canonicalize_cflags(cflags))}\0".encode(
            "utf-8", errors="surrogateescape"
        )
    )
    h.update(f"\0includes={chr(0).join(include_dirs)}\0".encode("utf-8", errors="surrogateescape"))
    # A force-include pulls a header's content into every compile regardless
    # of the source's directives — resolution cannot see it, so fall back to
    # conservative per-directory fingerprints.
    force_include = any(f.startswith(FORCE_INCLUDE_PREFIXES) for f in cflags)
    headers = (
        header_dependency_hash(source_content, source_dir, include_dirs)
        if not force_include
        else dir_fingerprint_hash(source_dir, include_dirs)
    )
    h.update(f"\0headers={headers}\0".encode())
    h.update(f"\0toolchain={toolchain_id}\0".encode("utf-8", errors="surrogateescape"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Module-level cache registry (avoids re-opening SQLite on every call)
# ---------------------------------------------------------------------------

_caches: dict[tuple[str, str, int], CacheBackend] = {}
_caches_lock = threading.Lock()
#: Cap open backends so a long-lived process that touches many project roots
#: does not retain every diskcache SQLite handle until atexit.
_CACHES_MAX = 8
#: atexit close armed once, with the first opened backend (registering at
#: import would run work at module load before any cache exists).
_CACHES_ATEXIT_REGISTERED = False


def get_compile_cache(
    project_root: Path,
    backend: str = DEFAULT_CACHE_BACKEND,
    size_limit: int = _DEFAULT_SIZE_LIMIT,
) -> CacheBackend:
    """Return a shared cache instance for a project root and backend.

    The diskcache backend stores at ``{project_root}/.rebrew/compile_cache/``.
    Multiple calls with the same ``(root, backend, size_limit)`` return the
    same instance.

    Args:
        project_root: The project root (cache namespace).
        backend: Name of a registered cache backend (``[cache] backend`` in
            rebrew-project.toml; default ``diskcache``).
        size_limit: On-disk cap in bytes; entries are LRU-evicted past it.
            Comes from ``[cache] size_limit_mib`` (see
            :attr:`rebrew.config.ProjectConfig.cache_size_limit`).  Part of
            the instance key because the cap is fixed when the store opens —
            a second caller asking for a different one gets its own handle
            rather than silently sharing the first cap.

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
    key = (backend, cache_dir, size_limit)
    with _caches_lock:
        existing = _caches.get(key)
        if existing is not None:
            if not existing.is_open():
                del _caches[key]
            else:
                # Refresh insertion order so repeated use is not FIFO-evicted.
                del _caches[key]
                _caches[key] = existing
                return existing
        while len(_caches) >= _CACHES_MAX:
            oldest_key = next(iter(_caches))
            old = _caches.pop(oldest_key)
            with contextlib.suppress(Exception):
                old.close()
        _caches[key] = factory(Path(cache_dir), size_limit)
        global _CACHES_ATEXIT_REGISTERED
        if not _CACHES_ATEXIT_REGISTERED:
            atexit.register(close_all_caches)
            _CACHES_ATEXIT_REGISTERED = True
        return _caches[key]


def get_project_cache(cfg: Any) -> CacheBackend:
    """The compile cache for a project config: its root, backend, and cap.

    One entry point so no caller re-derives the ``[cache]`` settings with its
    own ``getattr`` defaults — a site that read the root but not the cap
    would be handed a different store than the one the project configured.
    """
    return get_compile_cache(
        cfg.root,
        getattr(cfg, "cache_backend", DEFAULT_CACHE_BACKEND),
        getattr(cfg, "cache_size_limit", _DEFAULT_SIZE_LIMIT),
    )


def close_all_caches() -> None:
    """Close all open cache instances (for clean shutdown)."""
    with _caches_lock:
        for cache in _caches.values():
            cache.close()
        _caches.clear()
