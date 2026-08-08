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
cflags, include_dirs, include_fingerprints, toolchain_id)``.  Flags and
include dirs are hashed in **order** (not sorted) because order affects
semantics (``/I`` search order, ``/D`` redefinitions, last-wins flags).

Invalidation
~~~~~~~~~~~~
Automatic via content hash — different inputs produce different keys.
Header files reachable from the ``/I`` directories participate in the key via
:func:`include_fingerprint` (name + size + mtime, ccache-style), so editing a
``library_*.h`` or a shared header invalidates dependent entries without a
manual ``rebrew cache clear``.  The fingerprint is memoized per process: a
header edited *while* a long GA run is in flight is not picked up until the
next invocation.
"""

from __future__ import annotations

import atexit
import hashlib
import threading
from functools import lru_cache
from pathlib import Path

import diskcache

# Bump on key semantics changes to invalidate stale entries.
CACHE_SCHEMA_VERSION = 2

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
        self._cache = diskcache.Cache(str(cache_dir), size_limit=size_limit)
        self.hits: int = 0
        self.misses: int = 0
        # ``CompileCache`` instances are shared across worker threads in
        # ``flag_sweep`` and ``BinaryMatchingGA``; the underlying diskcache is
        # thread-safe, but ``hits``/``misses`` are plain Python ints whose
        # ``+= 1`` is not atomic across the GIL — protect the increments so
        # stats are not silently undercounted under contention.
        self._counter_lock = threading.Lock()

    def get(self, key: str) -> bytes | None:
        """Return cached .obj bytes for *key*, or ``None`` on miss.

        Increments ``self.hits`` on a cache hit, ``self.misses`` on a miss.
        """
        result = self._cache.get(key, default=None)
        if isinstance(result, bytes):
            with self._counter_lock:
                self.hits += 1
            return result
        with self._counter_lock:
            self.misses += 1
        return None

    def put(self, key: str, obj_bytes: bytes) -> None:
        """Store .obj bytes under *key*."""
        self._cache.set(key, obj_bytes)

    @property
    def volume(self) -> int:
        """Total bytes used by the cache on disk."""
        return int(self._cache.volume())

    @property
    def count(self) -> int:
        """Number of entries in the cache."""
        return len(self._cache)

    def clear(self) -> None:
        """Remove all cached entries."""
        self._cache.clear()

    def close(self) -> None:
        """Close the underlying diskcache store."""
        self._cache.close()

    def stats(self) -> dict[str, int | float]:
        """Return cache statistics as a dict.

        Includes in-process hit/miss counters under ``session_hits``,
        ``session_misses``, and ``session_hit_rate_pct``.  These reset
        when the process exits; they reflect only the current session.
        """
        total_lookups = self.hits + self.misses
        hit_rate = round(100.0 * self.hits / total_lookups, 1) if total_lookups > 0 else 0.0
        return {
            "entries": self.count,
            "volume_bytes": self.volume,
            "volume_mb": round(self.volume / (1024 * 1024), 2),
            "size_limit_mb": round(self._cache.size_limit / (1024 * 1024), 2),
            "session_hits": self.hits,
            "session_misses": self.misses,
            "session_hit_rate_pct": hit_rate,
        }


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


def compile_cache_key(
    source_content: str,
    source_filename: str,
    cflags: list[str],
    include_dirs: list[str],
    toolchain_id: str,
    source_ext: str = ".c",
) -> str:
    """Compute a SHA-256 cache key from compilation inputs.

    All inputs that affect the ``.obj`` output must be included:

    - **source_content** — the actual C code (not the file path)
    - **source_filename** — the filename the compiler sees (affects
      ``__FILE__`` expansion); use the basename, not a temp path
    - **cflags** — all compiler flags in order (base + user + include)
    - **include_dirs** — ordered list of ``/I`` directory paths, plus a
      :func:`include_fingerprint` of the headers each one contains, so a
      header edit invalidates the entry
    - **toolchain_id** — identifies the compiler binary and runner
      (e.g. ``"wine /abs/path/CL.EXE"``)
    - **source_ext** — file extension (``.c``, ``.cpp``)

    Returns a 64-char hex digest string.

    .. note:: Callers must include ``base_cflags`` in the *cflags* list —
       this function does not automatically prepend them.
    """
    h = hashlib.sha256()
    h.update(f"v{CACHE_SCHEMA_VERSION}\0".encode())
    h.update(source_content.encode("utf-8"))
    h.update(f"\0filename={source_filename}\0".encode())
    h.update(f"\0ext={source_ext}\0".encode())
    # Flags and include dirs are separated by \0 to prevent collisions
    # (e.g. "flag1 flag2" != "flag1flag2").  This assumes none of the inputs
    # contain embedded NUL bytes, which is safe because MSVC flags, filenames,
    # and C source are NUL-free text.
    h.update(f"\0cflags={chr(0).join(cflags)}\0".encode())
    h.update(f"\0includes={chr(0).join(include_dirs)}\0".encode())
    h.update(f"\0headers={chr(0).join(include_fingerprint(d) for d in include_dirs)}\0".encode())
    h.update(f"\0toolchain={toolchain_id}\0".encode())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Module-level cache registry (avoids re-opening SQLite on every call)
# ---------------------------------------------------------------------------

_caches: dict[str, CompileCache] = {}
_caches_lock = threading.Lock()


def get_compile_cache(project_root: Path) -> CompileCache:
    """Return a shared ``CompileCache`` instance for a project root.

    The cache is stored at ``{project_root}/.rebrew/compile_cache/``.
    Multiple calls with the same root return the same instance.
    """
    cache_dir = str(project_root / ".rebrew" / "compile_cache")
    with _caches_lock:
        if cache_dir not in _caches:
            _caches[cache_dir] = CompileCache(cache_dir)
        return _caches[cache_dir]


def close_all_caches() -> None:
    """Close all open cache instances (for clean shutdown)."""
    with _caches_lock:
        for cache in _caches.values():
            cache.close()
        _caches.clear()


atexit.register(close_all_caches)
