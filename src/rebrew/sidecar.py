"""sidecar.py — Per-directory metadata store for rebrew.

Volatile annotation fields (STATUS, SIZE, CFLAGS, BLOCKER, NOTE, GHIDRA, …)
are stored in a ``rebrew-function.toml`` sidecar file alongside the reversed
``.c`` sources, rather than as comment annotations inside those files.

Key format
----------
The sidecar is keyed by *qualified module+VA string*::

    ["SERVER.0x01006364"]
    status = "EXACT"
    size   = 42

This allows a single ``rebrew-function.toml`` to hold metadata for **multiple
targets** (e.g. ``SERVER`` and ``CLIENT``) that share a directory or ``.c``
file — the full key is unambiguous even if two targets happen to have a
function at the same VA.  The format mirrors the ``// FUNCTION: SERVER
0x01006364`` marker.

Owned fields per entry::

    size, cflags, status, blocker, blocker_delta, note, ghidra,
    analysis, skip, source, globals, section

The ``// FUNCTION: MODULE 0xVA`` (and LIBRARY/STUB/GLOBAL/DATA) marker lines
remain in the ``.c`` files for reccmp compatibility.

Merge semantics
---------------
When a rebrew tool reads an ``Annotation`` from ``parse_c_file_multi()``, it
calls ``merge_into_annotation(ann, directory)`` which overlays *sidecar* values
on top.  Sidecar always wins for the fields it owns.

Atomicity
---------
Writes use ``tomlkit`` for round-trip-safe serialisation and the standard
``atomic_write_text`` helper (write to ``.tmp``, ``os.replace``).

Thread safety
-------------
Not thread-safe.  CLI tools are single-threaded; no locking is needed.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from rebrew.utils import atomic_write_text

if TYPE_CHECKING:
    from rebrew.annotation import Annotation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SIDECAR_FILENAME = "rebrew-function.toml"

# Fields that live in the sidecar — routing table used by update/delete helpers.
SIDECAR_FIELDS: frozenset[str] = frozenset(
    {
        "STATUS",
        "SIZE",
        "CFLAGS",
        "BLOCKER",
        "BLOCKER_DELTA",
        "NOTE",
        "GHIDRA",
        "ANALYSIS",
        "SKIP",
        "GLOBALS",
        # ORIGIN and SOURCE are handled differently (SOURCE may stay in .c for library
        # functions; ORIGIN is derivable from the FUNCTION: marker module field).
        # They are listed here so callers can ask ``is_sidecar_key("SOURCE")``.
        "SOURCE",
        # NOTE: SECTION is intentionally absent — it is owned by data_sidecar.py
        # for DATA/GLOBAL annotations and must not be written to rebrew-function.toml.
    }
)

# Internal tomlkit key name for each annotation field.
# Lower-case TOML keys map to Annotation attribute names.
_TOML_TO_ATTR: dict[str, str] = {
    "size": "size",
    "cflags": "cflags",
    "status": "status",
    "blocker": "blocker",
    "blocker_delta": "blocker_delta",
    "note": "note",
    "ghidra": "ghidra",
    "analysis": "analysis",
    "skip": "skip",
    "globals": "globals_list",
    "source": "source",
}

__all__ = [
    "SIDECAR_FILENAME",
    "SIDECAR_FIELDS",
    "is_sidecar_key",
    "sidecar_path",
    "load_sidecar",
    "save_sidecar",
    "get_entry",
    "set_field",
    "delete_field",
    "merge_into_annotation",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_sidecar_key(key: str) -> bool:
    """Return True if *key* (annotation KV name, upper-case) belongs in the sidecar."""
    return key.upper() in SIDECAR_FIELDS


def sidecar_path(source_or_dir: Path) -> Path:
    """Return the ``rebrew-function.toml`` path for a source file or its parent directory.

    Args:
        source_or_dir: Either a ``.c`` source file or the directory that
            contains it.  Both forms are accepted.

    """
    if source_or_dir.is_dir():
        return source_or_dir / SIDECAR_FILENAME
    return source_or_dir.parent / SIDECAR_FILENAME


def _qualified_key(module: str | None, va: int) -> str:
    """Return the canonical TOML key for *(module, va)*.

    Examples::

        >>> _qualified_key("SERVER", 0x01006364)
        'SERVER.0x01006364'
        >>> _qualified_key(None, 0x01006364)  # legacy / unknown module
        '0x01006364'

    """
    va_hex = f"0x{va:08x}"
    if module:
        return f"{module}.{va_hex}"
    return va_hex


def _parse_key(key: str) -> tuple[str, int] | None:
    """Parse a sidecar TOML key into ``(module, va_int)``.

    Only accepts the qualified ``MODULE.0xVA`` form.  Returns ``None`` for
    unrecognised keys.

    Examples::

        >>> _parse_key("SERVER.0x01006364")
        ('SERVER', 16803684)
        >>> _parse_key("not_a_key") is None
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


def _find_sidecar_dir(start: Path) -> Path:
    """Return the directory that owns ``rebrew-function.toml`` for *start*.

    Walks *start* → parent → grandparent … until a directory containing
    ``rebrew-function.toml`` is found.  If no ancestor has the file, returns
    *start* (so callers that write will create the file there).

    Args:
        start: Directory to begin the search from (typically ``filepath.parent``).

    """
    current = start.resolve()
    parent = current.parent
    while current != parent:  # filesystem root: parent of root is itself
        if (current / SIDECAR_FILENAME).exists():
            return current
        current, parent = parent, parent.parent
    return start


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


def load_sidecar(directory: Path) -> dict[tuple[str, int], dict[str, Any]]:
    """Load a ``rebrew-function.toml`` for sources in *directory*.

    Walks *directory* → parent → … until ``rebrew-function.toml`` is found,
    then loads and returns its contents.  This means a single sidecar file at
    a project root (e.g. ``src/server.dll/``) is shared by all subdirectories.

    Returns a mapping of ``{(module, va_int): {field_name: value}}``.
    Returns an empty dict if no sidecar file is found or it cannot be parsed.

    Args:
        directory: Starting directory (typically ``filepath.parent``).

    """
    path = _find_sidecar_dir(directory) / SIDECAR_FILENAME
    if not path.exists():
        return {}

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — tomlkit raises various types
        logger.warning("Failed to parse sidecar %s: %s", path, exc)
        return {}

    result: dict[tuple[str, int], dict[str, Any]] = {}
    for key, value in doc.items():
        parsed = _parse_key(key)
        if parsed is None:
            continue
        module, va_int = parsed
        if isinstance(value, dict):
            result[(module, va_int)] = dict(value)

    return result


def save_sidecar(
    directory: Path,
    data: dict[tuple[str, int], dict[str, Any]],
) -> None:
    """Atomically write *data* to ``rebrew-function.toml`` in *directory*.

    Args:
        directory: The directory to write into.
        data: Mapping of ``{(module, va_int): {field: value}}``.
    """
    path = directory / SIDECAR_FILENAME
    doc = tomlkit.document()

    # Write entries sorted by (module, va) for stable diffs.
    for module, va_int in sorted(data, key=lambda k: (k[0], k[1])):
        entry = data[(module, va_int)]
        if not entry:
            continue
        toml_key = _qualified_key(module, va_int)
        tbl = tomlkit.table()
        canonical_order = [
            "size",
            "cflags",
            "status",
            "blocker",
            "blocker_delta",
            "note",
            "ghidra",
            "analysis",
            "skip",
            "globals",
            "source",
        ]
        seen: set[str] = set()
        for field in canonical_order:
            if field in entry:
                tbl[field] = entry[field]
                seen.add(field)
        for field, val in entry.items():
            if field not in seen:
                tbl[field] = val
        doc[toml_key] = tbl

    atomic_write_text(path, tomlkit.dumps(doc))


# ---------------------------------------------------------------------------
# Granular read/write
# ---------------------------------------------------------------------------


def get_entry(directory: Path, va: int, module: str) -> dict[str, Any]:
    """Return sidecar fields for *(module, va)* in *directory*.

    Returns an empty dict if not found.

    Args:
        directory: Directory containing ``rebrew-function.toml``.
        va: Virtual address integer.
        module: Target module name (e.g. ``"SERVER"``).

    """
    return load_sidecar(directory).get((module, va), {})


def set_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Set one field for *(module, va)* in the sidecar.

    Walks up from *directory* to find the existing sidecar file.  If no
    ancestor sidecar exists, creates ``rebrew-function.toml`` in *directory*.
    Uses in-place ``tomlkit`` editing to preserve formatting and comments.

    Args:
        directory: Starting directory (typically ``filepath.parent``).
        va: Virtual address integer.
        key: Lower-case TOML key (e.g. ``"status"``, ``"size"``).
        value: Value to write.
        module: Target module name (e.g. ``"SERVER"``).

    """
    path = _find_sidecar_dir(directory) / SIDECAR_FILENAME
    toml_key = _qualified_key(module, va)

    if path.exists():
        try:
            doc = tomlkit.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse sidecar %s, starting fresh: %s", path, exc)
            doc = tomlkit.document()
    else:
        doc = tomlkit.document()

    if toml_key not in doc:
        doc[toml_key] = tomlkit.table()

    doc[toml_key][key] = value  # type: ignore[index]
    atomic_write_text(path, tomlkit.dumps(doc))


def delete_field(directory: Path, va: int, key: str, module: str) -> None:
    """Remove *key* from the sidecar entry for *(module, va)*.  No-op if not present.

    Walks up from *directory* to find the sidecar file.

    Args:
        directory: Starting directory (typically ``filepath.parent``).
        va: Virtual address integer.
        key: Lower-case TOML key to remove.
        module: Target module name.

    """
    path = _find_sidecar_dir(directory) / SIDECAR_FILENAME
    if not path.exists():
        return
    toml_key = _qualified_key(module, va)

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse sidecar %s: %s", path, exc)
        return

    if toml_key not in doc:
        return
    entry = doc[toml_key]
    if key in entry:
        del entry[key]  # type: ignore[attr-defined]
        atomic_write_text(path, tomlkit.dumps(doc))


# ---------------------------------------------------------------------------
# Annotation merge
# ---------------------------------------------------------------------------


def merge_into_annotation(ann: Annotation, directory: Path) -> Annotation:
    """Overlay sidecar values onto *ann*, returning the same object mutated.

    The sidecar wins for every field it defines.

    Lookup uses the qualified key ``(ann.module, ann.va)``.  Multi-target
    ``.c`` files (with multiple ``// FUNCTION: MODULE 0xVA`` markers) each
    receive their own sidecar entry and are merged in isolation.

    Args:
        ann: The ``Annotation`` object to mutate.
        directory: Directory containing ``rebrew-function.toml``.

    Returns:
        The mutated *ann* (same object, for chaining convenience).

    """
    module: str = getattr(ann, "module", None) or ""
    if not module:
        return ann
    entry = get_entry(directory, ann.va, module=module)
    if not entry:
        return ann

    if "size" in entry:
        with contextlib.suppress(ValueError, TypeError):
            ann.size = int(entry["size"])

    if "cflags" in entry:
        ann.cflags = str(entry["cflags"])

    if "status" in entry:
        ann.status = str(entry["status"])

    if "blocker" in entry:
        ann.blocker = str(entry["blocker"])

    if "blocker_delta" in entry:
        raw = entry["blocker_delta"]
        try:
            ann.blocker_delta = int(raw)
        except (ValueError, TypeError):
            ann.blocker_delta = None

    if "note" in entry:
        ann.note = str(entry["note"])

    if "ghidra" in entry:
        ann.ghidra = str(entry["ghidra"])

    if "analysis" in entry and not ann.note:
        ann.note = str(entry["analysis"])

    if "globals" in entry:
        raw_g = entry["globals"]
        if isinstance(raw_g, list):
            ann.globals_list = [str(g) for g in raw_g]
        elif isinstance(raw_g, str):
            ann.globals_list = [g.strip() for g in raw_g.split(",") if g.strip()]

    if "source" in entry:
        ann.source = str(entry["source"])

    return ann
