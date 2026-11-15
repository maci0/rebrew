"""Shared helper: an address-space cap for tests that feed forged size fields.

A reader that sizes a buffer from a forged header field asks for gigabytes.
Under :func:`address_space_cap` that request fails inside the test as
``MemoryError`` instead of growing the worker until the kernel OOM-kills it,
along with whatever else shares the host's memory cgroup.  The cap is the
process's current mapping plus a headroom, so it holds in a worker that has
already loaded the suite's libraries, and the previous limit is restored on
exit.  Linux only: the current mapping is read from ``/proc/self/statm``.

Imports from a tests/ file work because pytest inserts the test directory into
``sys.path``.
"""

from __future__ import annotations

import contextlib
import resource
from pathlib import Path
lazy from collections.abc import Iterator

#: Address space a capped block may map beyond what the process already maps.
#: The forged-header cases parse files of a few KiB; a regression asks for GiBs.
CAP_HEADROOM_BYTES = 512 * 1024 * 1024


@contextlib.contextmanager
def address_space_cap(headroom: int = CAP_HEADROOM_BYTES) -> Iterator[None]:
    """Lower ``RLIMIT_AS`` to the current mapping plus *headroom* for the block."""
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    mapped = int(Path("/proc/self/statm").read_text().split()[0]) * resource.getpagesize()
    # Never raise an existing, tighter limit (a run under `prlimit --as`).
    cap = min(
        [mapped + headroom] + [limit for limit in (soft, hard) if limit != resource.RLIM_INFINITY]
    )
    resource.setrlimit(resource.RLIMIT_AS, (cap, hard))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
