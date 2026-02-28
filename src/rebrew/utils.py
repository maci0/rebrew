"""Shared utilities for rebrew."""

import contextlib
import os
from pathlib import Path


def atomic_write_text(filepath: Path, text: str, encoding: str = "utf-8") -> None:
    """Write text to a file atomically to prevent corruption on crash."""
    tmp_path = filepath.with_suffix(filepath.suffix + ".tmp")
    try:
        tmp_path.write_text(text, encoding=encoding)
        os.replace(tmp_path, filepath)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
