"""Shared utilities for rebrew."""

import contextlib
import os
from pathlib import Path


def atomic_write_text(filepath: Path, text: str, encoding: str = "utf-8") -> None:
    """Write text to a file atomically to prevent corruption on crash.

    Strategy: write to a sibling .tmp file, then ``os.replace`` (which is
    atomic on POSIX and best-effort-atomic on Windows/NTFS).  If *any*
    exception occurs — including KeyboardInterrupt — the temp file is
    cleaned up so we never leave partial writes at the target path.

    The ``contextlib.suppress(OSError)`` in the except path is safe because
    it only guards the cleanup unlink: if the temp file was already removed
    (race, OS cleanup) the unlink would raise, but we don't care — the
    original exception is re-raised regardless.
    """
    tmp_path = filepath.with_suffix(filepath.suffix + ".tmp")
    try:
        tmp_path.write_text(text, encoding=encoding)
        os.replace(tmp_path, filepath)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
