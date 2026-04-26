"""Shared utilities for rebrew."""

import contextlib
import os
import shlex
from pathlib import Path


def atomic_write_text(filepath: Path, text: str, encoding: str = "utf-8") -> None:
    """Write text to a file atomically to prevent corruption on crash.

    Strategy: write to a sibling .tmp file, then ``os.replace()`` (atomic
    on both POSIX and Windows/NTFS).  If *any* exception occurs —
    including KeyboardInterrupt — the temp file is cleaned up so we never
    leave partial writes at the target path.

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


def qualified_key(module: str | None, va: int) -> str:
    """Return the canonical TOML key for *(module, va)*.

    Used by both ``metadata.py`` and ``data_metadata.py`` for consistent
    key encoding in ``rebrew-function.toml`` / ``rebrew-data.toml``.

    Examples::

        >>> qualified_key("SERVER", 0x01006364)
        'SERVER.0x01006364'
        >>> qualified_key(None, 0x01006364)
        '0x01006364'

    """
    va_hex = f"0x{va:08x}"
    if module:
        return f"{module}.{va_hex}"
    return va_hex


def parse_metadata_key(key: str) -> tuple[str, int] | None:
    """Parse a metadata TOML key into ``(module, va_int)``.

    Only accepts the qualified ``MODULE.0xVA`` form.  Returns ``None`` for
    unrecognised keys.

    Examples::

        >>> parse_metadata_key("SERVER.0x01006364")
        ('SERVER', 16803684)
        >>> parse_metadata_key("not_a_key") is None
        True

    """
    if ".0x" in key:
        dot = key.index(".0x")
        module = key[:dot]
        hex_part = key[dot + 1 :]  # includes leading 0x
        try:
            return module, int(hex_part, 16)
        except ValueError:
            return None
    return None


def safe_shlex_split(command: str) -> list[str]:
    """Split a shell command string, falling back to str.split() on parse errors.

    Handles unbalanced quotes in compiler commands gracefully.
    """
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()
