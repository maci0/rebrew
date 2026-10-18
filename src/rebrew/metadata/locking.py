"""Reentrant thread and process transactions for metadata storage backends."""

import contextlib
import threading
from collections.abc import Iterator
from pathlib import Path

from rebrew.utils import file_lock
from rebrew.workspace.config import CONFIG_NAME

#: Per-file thread locks for :func:`file_transaction` (one lock per
#: metadata filename so the function and data stores don't contend).  Public
#: so a caller can assert the batch write gate publishes one lock per
#: filename rather than re-creating it per acquisition.
#: Reentrant: a caller may hold the lock across a compound operation whose
#: helpers take it again (the GA batch splices a stub and promotes its STATUS
#: through ``update_source_status`` inside the same critical section).
METADATA_WRITE_LOCKS: dict[str, threading.RLock] = {}
_METADATA_WRITE_LOCKS_LOCK = threading.Lock()

#: Per-thread reentrancy depth per resolved metadata path, so a nested acquisition
#: skips the ``flock`` (a second fd would deadlock against the first).
_METADATA_WRITE_DEPTH = threading.local()


@contextlib.contextmanager
def project_transaction(root: Path, filename: str) -> Iterator[None]:
    """Keep backend selection fixed until a metadata transaction completes."""
    if filename != CONFIG_NAME and (root / CONFIG_NAME).is_file():
        with file_transaction(root, CONFIG_NAME):
            yield
    else:
        yield


@contextlib.contextmanager
def file_transaction(directory: Path, filename: str) -> Iterator[None]:
    """Thread + cross-process lock around a metadata read-modify-write.

    Shared by ``metadata/functions.py`` (``rebrew-functions.toml``) and
    ``metadata/data.py`` (``rebrew-data.toml``).  The thread lock serializes
    in-process writers (``rebrew verify --jobs``, GA batch promotion); an
    advisory ``flock`` on a ``.lock`` sidecar serializes *concurrent
    processes* (e.g. ``rebrew verify --watch`` in one terminal while
    ``rebrew test`` promotes in another — without it, interleaved
    read-modify-writes silently drop one process's STATUS promotion).

    Reentrant within one thread: a nested acquisition on the same filename
    yields without re-``flock``ing (the flock is held until the outermost
    exit), so a compound critical section can call helpers that lock again.
    """
    path = (directory / filename).resolve()
    # Reject directory-traversal filenames (e.g. "../../etc/passwd") — the
    # lock file is derived from this path and would otherwise escape the
    # project root.
    if Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise ValueError(f"invalid metadata filename: {filename!r}")
    # Create the target directory before opening the ``.lock`` sidecar: the
    # first-ever write into a fresh metadata root would otherwise crash with
    # FileNotFoundError inside the lock acquisition (the data write itself
    # only runs later, inside atomic_write_text's own mkdir).  exist_ok
    # keeps concurrent creators safe.
    path.parent.mkdir(parents=True, exist_ok=True)
    with _METADATA_WRITE_LOCKS_LOCK:
        if filename not in METADATA_WRITE_LOCKS:
            METADATA_WRITE_LOCKS[filename] = threading.RLock()
        lock = METADATA_WRITE_LOCKS[filename]
    depth: dict[str, int] | None = getattr(_METADATA_WRITE_DEPTH, "depth", None)
    if depth is None:
        depth = {}
        _METADATA_WRITE_DEPTH.depth = depth
    # Depth is per resolved path, not per filename: a nested lock on the
    # same-named file in another root must still take that root's flock.
    key = str(path)
    with lock:
        if depth.get(key, 0):
            # Reentrant: this thread already holds the lock and the flock.
            # Re-opening the sidecar and flocking a second fd would block
            # against the first, so only track the depth here.
            depth[key] += 1
            try:
                yield
            finally:
                depth[key] -= 1
            return
        depth[key] = 1
        try:
            with file_lock(path.with_suffix(path.suffix + ".lock")):
                yield
        finally:
            depth.pop(key, None)
