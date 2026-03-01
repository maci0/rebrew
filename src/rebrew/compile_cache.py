"""Hash-based compile cache for skipping redundant Wine/wibo invocations.

Each Wine/wibo CL.EXE invocation costs 200-500ms of subprocess startup
overhead.  During ``rebrew ga`` (100 gen × 30 pop × N functions) and
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
cflags, include_dirs, toolchain_id)``.  Flags and include dirs are hashed
in **order** (not sorted) because order affects semantics (``/I`` search
order, ``/D`` redefinitions, last-wins flags).

Invalidation
~~~~~~~~~~~~
Automatic via content hash — different inputs produce different keys.
Header file changes are NOT tracked (only include dir paths, not contents).
Use ``rebrew cache clear`` for manual invalidation after header edits.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any

import diskcache

# Bump when key semantics change to avoid stale hits across upgrades.
CACHE_SCHEMA_VERSION = 1

# Default size limit: 500 MB.  Most .obj files are 1-10 KB, so this
# holds 50K+ entries with LRU eviction when the limit is reached.
_DEFAULT_SIZE_LIMIT = 500 * 1024 * 1024


class CompileCache:
    """Disk-backed cache mapping compile inputs to raw .obj bytes.

    Backed by ``diskcache.Cache`` (SQLite + filesystem), which is
    thread-safe and supports concurrent readers/writers.
    """

    def __init__(self, cache_dir: str | Path, size_limit: int = _DEFAULT_SIZE_LIMIT) -> None:
        self._cache = diskcache.Cache(str(cache_dir), size_limit=size_limit)

    def get(self, key: str) -> bytes | None:
        """Return cached .obj bytes for *key*, or ``None`` on miss."""
        result = self._cache.get(key, default=None)
        return result if isinstance(result, bytes) else None

    def put(self, key: str, obj_bytes: bytes) -> None:
        """Store .obj bytes under *key*."""
        self._cache.set(key, obj_bytes)

    @property
    def volume(self) -> int:
        """Total bytes used by the cache on disk."""
        return self._cache.volume()

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

    def stats(self) -> dict[str, Any]:
        """Return cache statistics as a dict."""
        return {
            "entries": self.count,
            "volume_bytes": self.volume,
            "volume_mb": round(self.volume / (1024 * 1024), 2),
            "size_limit_mb": round(self._cache.size_limit / (1024 * 1024), 2),
        }


# ---------------------------------------------------------------------------
# Cache key computation
# ---------------------------------------------------------------------------


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
    - **include_dirs** — ordered list of ``/I`` directory paths
    - **toolchain_id** — identifies the compiler binary and runner
      (e.g. ``"wine:/abs/path/CL.EXE"``)
    - **source_ext** — file extension (``.c``, ``.cpp``)

    Returns a 64-char hex digest string.
    """
    h = hashlib.sha256()
    h.update(f"v{CACHE_SCHEMA_VERSION}\0".encode())
    h.update(source_content.encode("utf-8"))
    h.update(f"\0filename={source_filename}\0".encode())
    h.update(f"\0ext={source_ext}\0".encode())
    # Flags in order — separated by \0 to avoid "flag1 flag2" == "flag1flag2"
    h.update(f"\0cflags={chr(0).join(cflags)}\0".encode())
    h.update(f"\0includes={chr(0).join(include_dirs)}\0".encode())
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
    """Close all open cache instances (for clean shutdown in tests)."""
    with _caches_lock:
        for cache in _caches.values():
            cache.close()
        _caches.clear()
