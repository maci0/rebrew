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

#: Busy-wait budget for read-only opens (matches build_db / dashboard).
_SQLITE_TIMEOUT_SECONDS = 30.0

#: ``metadata.target`` value carrying database-level (not per-target) rows.
SCHEMA_TARGET = "__schema__"

#: ``metadata.key`` carrying the schema version stamp.
DB_VERSION_KEY = "db_version"

#: Table of per-section cell JSON (one row per target+section, zstd-compressed),
#: written by ``build_db`` and served verbatim by dashboards.
#:
#: This is a DERIVED CACHE: derived from ``cells``, whose only writer is
#: ``build_db``.  It therefore cannot go stale between builds, and a reader that
#: finds it absent (or written by an older codec) falls back to the live
#: ``cells`` query.
#:
#: It became part of the versioned schema at v7 — see ``build_db``'s
#: ``_missing_required_objects``, which is what makes the stamp meaningful — but
#: the fallback is what keeps a pre-v7 database *readable* rather than merely
#: rejected.
SECTION_CELLS_TABLE = "section_cells_json"

#: BLOB column of :data:`SECTION_CELLS_TABLE`.  Named for its codec, and
#: load-bearing rather than decorative: a reader probes for THIS column instead
#: of trusting ``db_version``, so a database still carrying a different codec's
#: column falls back to the live ``cells`` query instead of feeding an old blob
#: to the current decoder.  Changing the codec therefore means renaming this
#: constant (and the column) in the same commit — that rename IS the migration.
SECTION_CELLS_COLUMN = "cells_zstd"

#: The ``json_object(...)`` projection for ONE coverage cell.  Shared by the
#: producer (``build_db`` materializes it into :data:`SECTION_CELLS_TABLE`) and
#: every consumer (dashboards serve it, or rebuild it from ``cells`` when the
#: cache table is absent).  ONE definition, so a field added for the UI cannot
#: be written by one side and read by the other under a second name.
#:
#: ``id`` is deliberately NOT projected: no consumer reads it, and as a
#: monotonic autoincrement it was the only high-entropy field per row —
#: including it compressed 4.3x worse (322 KB vs 75 KB zstd on a 39k-cell
#: section), because every remaining column repeats heavily.
#:
#: Absent keys, not null ones: ``json_patch`` REMOVES a key whose patch value is
#: JSON null (RFC 7396), so ``functions``/``label``/``parent_function`` vanish
#: on the rows where they carry no information — which is nearly all of them.
#: Measured on the 38,918-cell section: 4.13 MB -> 2.14 MB of JSON, Python
#: ``json.loads`` 20.0 ms -> 10.8 ms, zstd 75.1 KB -> 63.2 KB.  Every consumer
#: already reads these with ``.get``/``??``/truthiness (``cell.functions &&
#: cell.functions[0]``, ``cell.get("label", "")``), so for them an absent key
#: and a null one are indistinguishable — and a blob built before this change,
#: which still carries the null keys, reads identically.  No schema bump.
#:
#: The two ``json_`` calls cost more than one flat ``json_object``; for a
#: materialized database that is paid at build time, and the smaller JSON is
#: paid back on every read (parse, compress, transfer).
CELLS_JSON_OBJECT_SQL = (
    "json_patch("
    "json_object('start', start, 'end', end, 'span', span, 'state', state), "
    "json_object('functions', json(nullif(functions, '[]')), 'label', label, "
    "'parent_function', parent_function))"
)

#: One section's cells as a JSON array in spatial order.  Shared by
#: ``build_db`` (materializes into :data:`SECTION_CELLS_TABLE`) and every
#: live ``cells`` fallback so the grid never depends on rowid/insertion
#: order.  Without ``ORDER BY start``, ``json_group_array`` follows the
#: plan's row order — which is *usually* the UNIQUE
#: ``(target, section_name, start)`` index, but is not a contract.
SECTION_CELLS_AGG_SQL = f"json_group_array({CELLS_JSON_OBJECT_SQL} ORDER BY start)"

#: zstd level for :data:`SECTION_CELLS_TABLE` blobs.  Measured over a database
#: holding 8.4 MB of cell JSON: level 3 gives 176 KB in 3 ms, levels 9 and 15
#: give *more* bytes (205 KB / 210 KB), and level 19 reaches 141 KB only by
#: spending 3.3 s.  (This table briefly used zlib at level 6: 460 KB, 28 ms.)
_CELLS_ZSTD_LEVEL = 3


def encode_section_cells(cells_json: str) -> bytes:
    """Compress one section's cell JSON for :data:`SECTION_CELLS_TABLE`."""
    import zstandard

    return zstandard.ZstdCompressor(level=_CELLS_ZSTD_LEVEL).compress(cells_json.encode("utf-8"))


def decode_section_cells(blob: bytes) -> str:
    """Inverse of :func:`encode_section_cells`.

    A fresh ``ZstdDecompressor`` per call, deliberately: python-zstandard
    documents no thread-safety for a shared instance (a shared *compressor*
    raced on one ZSTD_CCtx and reproducibly segfaulted the dashboard), and
    construction measures ~0.0001 ms against ~0.47 ms to inflate a 4.13 MB
    section — so sharing one would buy nothing and reintroduce that class of
    bug.  ``encode_section_cells`` writes the content size into the frame
    header, so no ``max_output_size`` is needed here.
    """
    import zstandard

    return zstandard.ZstdDecompressor().decompress(blob).decode("utf-8")


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


def open_sqlite_ro(path: Path) -> sqlite3.Connection:
    """Open *path* read-only with ``query_only`` defense-in-depth.

    ``mode=ro`` already rejects writes at the VFS layer; ``PRAGMA query_only=ON``
    is a second gate so a caller that somehow received a writable handle still
    cannot mutate the file.  Callers must close the connection (prefer
    ``contextlib.closing``).
    """
    conn = sqlite3.connect(sqlite_ro_uri(path), uri=True, timeout=_SQLITE_TIMEOUT_SECONDS)
    try:
        conn.execute("PRAGMA query_only=ON")
    except BaseException:
        # The caller never receives the handle, so it cannot close it.
        conn.close()
        raise
    return conn


def read_db_version(db_path: Path) -> int | str | None:
    """The schema version stamped in *db_path*, or ``None`` when unstamped.

    Prefers the ``__schema__`` row; falls back to any per-target ``db_version``
    row for databases written before the schema-level row existed.  The value
    is JSON-decoded, so both ``6`` and ``"6"`` round-trip as stored.  A missing
    file, a missing ``metadata`` table or a missing row all yield ``None``.
    """
    row: tuple[object, ...] | None = None
    try:
        with contextlib.closing(open_sqlite_ro(db_path)) as conn:
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
