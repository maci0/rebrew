"""Read-only access to a rebrew coverage.db.

The database is opened through a ``mode=ro`` URI so a stale or foreign reader
can never create or lock-write the file, and a missing or older database
degrades to ``None`` instead of raising.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

#: ``metadata.target`` value carrying database-level (not per-target) rows.
SCHEMA_TARGET = "__schema__"

#: ``metadata.key`` carrying the schema version stamp.
DB_VERSION_KEY = "db_version"


def sqlite_ro_uri(path: Path) -> str:
    """Return a SQLite URI that opens *path* read-only.

    The path must be percent-encoded (``Path.as_uri()``), not interpolated raw
    into ``file:{p}?mode=ro``: characters reserved by SQLite's URI grammar
    (``?`` starts the query, ``#`` starts the fragment, ``%`` introduces a
    percent-escape) would truncate or silently rewrite the filename.  A
    relative path is taken against the current working directory, since
    ``as_uri()`` requires an absolute path.
    """
    p = path if path.is_absolute() else Path.cwd() / path
    return f"{p.as_uri()}?mode=ro"


def read_db_version(db_path: Path) -> int | str | None:
    """The schema version stamped in *db_path*, or ``None`` when unstamped.

    Prefers the ``__schema__`` row; falls back to any per-target ``db_version``
    row for databases written before the schema-level row existed.  The value
    is JSON-decoded, so both ``6`` and ``"6"`` round-trip as stored.  A missing
    file, a missing ``metadata`` table or a missing row all yield ``None``.
    """
    row: tuple[object, ...] | None = None
    try:
        with contextlib.closing(sqlite3.connect(sqlite_ro_uri(db_path), uri=True)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM metadata WHERE target = ? AND key = ? LIMIT 1",
                (SCHEMA_TARGET, DB_VERSION_KEY),
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute(
                    "SELECT value FROM metadata WHERE key = ? LIMIT 1",
                    (DB_VERSION_KEY,),
                )
                row = cursor.fetchone()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    raw = row[0]
    if not isinstance(raw, str | bytes | bytearray):
        # A non-text column value (INTEGER/BLOB/NULL) is not JSON; stringify it
        # the same way rebrew's TypeError fallback does.
        return str(raw)
    try:
        loaded = json.loads(raw)
    except ValueError:
        # Invalid JSON text, or a blob that is not valid UTF-8.
        return str(raw)
    if isinstance(loaded, int | str):
        return loaded
    return str(raw)


def db_version_matches(stored: int | str | None, current: int | str) -> bool:
    """Whether *stored* is compatible with *current*.

    An unstamped database (``None``) always matches: there is no claim to
    contradict.  Otherwise the two are compared as strings, since a stored
    version may be JSON-encoded as either an int or a string.
    """
    return stored is None or str(stored) == str(current)
