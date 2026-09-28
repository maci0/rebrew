"""Shared helper: bounded joins for the thread-based concurrency tests.

A bare ``Thread.join()`` on a non-daemon thread turns a production deadlock
into a wedged suite: CI hangs until the job timeout and reports nothing about
which test caused it.  :func:`join_all` joins under a deadline and fails the
test naming the thread that outlived it.

Imports from a tests/ file work because pytest inserts the test directory into
``sys.path``.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable

JOIN_TIMEOUT_SECONDS = 30.0


def join_all(threads: Iterable[threading.Thread], timeout: float = JOIN_TIMEOUT_SECONDS) -> None:
    """Join every thread, failing if any is still alive after *timeout*."""
    remaining = list(threads)
    for thread in remaining:
        thread.join(timeout)
    stuck = [t.name for t in remaining if t.is_alive()]
    assert not stuck, f"threads still running after {timeout}s: {', '.join(stuck)}"
