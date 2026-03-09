"""metadata.py — Per-directory metadata store for rebrew.

Volatile annotation fields (STATUS, SIZE, CFLAGS, BLOCKER, NOTE, GHIDRA, …)
are stored in a single ``rebrew-function.toml`` metadata file at the
``reversed_dir`` root (e.g. ``src/<target>/``), rather than as comment
annotations inside ``.c`` source files.

Location
--------
The metadata file lives **only** at ``cfg.reversed_dir``.  There is no walk-up
discovery — callers must pass the correct root directory.  Subdirectories
under ``reversed_dir`` do **not** have their own metadata files.

Key format
----------
The metadata is keyed by *qualified module+VA string*::

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

Status promotion
----------------
Use :func:`update_source_status` — the single canonical writer — to promote
a function's STATUS.  Both ``rebrew test`` and ``rebrew verify --fix-status``
call this function; it never touches the ``.c`` file.

Merge semantics
---------------
When a rebrew tool reads an ``Annotation`` from ``parse_c_file_multi()``, it
calls ``merge_into_annotation(ann, directory)`` which overlays *metadata* values
on top.  Metadata always wins for the fields it owns.

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
import typing
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

METADATA_FILENAME = "rebrew-function.toml"

# Fields that live in the metadata — routing table used by update/delete helpers.
METADATA_FIELDS: frozenset[str] = frozenset(
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
        # They are listed here so callers can ask ``is_metadata_key("SOURCE")``.
        "SOURCE",
        # NOTE: SECTION is intentionally absent — it is owned by data_metadata.py
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
    "METADATA_FILENAME",
    "METADATA_FIELDS",
    "is_metadata_key",
    "metadata_path",
    "load_metadata",
    "save_metadata",
    "get_entry",
    "set_field",
    "update_field",
    "remove_field",
    "merge_into_annotation",
    "update_source_status",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_metadata_key(key: str) -> bool:
    """Return True if *key* (annotation KV name, upper-case) belongs in the metadata."""
    return key.upper() in METADATA_FIELDS


def metadata_path(directory: Path) -> Path:
    """Return the ``rebrew-function.toml`` path for the metadata root directory.

    Args:
        directory: The ``reversed_dir`` root (e.g. ``src/<target>/``).

    """
    return directory / METADATA_FILENAME


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
    """Parse a metadata TOML key into ``(module, va_int)``.

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


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


def load_metadata(directory: Path) -> dict[tuple[str, int], dict[str, Any]]:
    """Load ``rebrew-function.toml`` from *directory*.

    *directory* must be the metadata root (``cfg.reversed_dir``).  There is
    no walk-up — the file is expected at exactly ``directory / rebrew-function.toml``.

    Returns a mapping of ``{(module, va_int): {field_name: value}}``.
    Returns an empty dict if no metadata file is found or it cannot be parsed.

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).

    """
    path = directory / METADATA_FILENAME
    if not path.exists():
        return {}

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — tomlkit raises various types
        logger.warning("Failed to parse metadata %s: %s", path, exc)
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


def save_metadata(
    directory: Path,
    data: dict[tuple[str, int], dict[str, Any]],
) -> None:
    """Atomically write *data* to ``rebrew-function.toml`` in *directory*.

    Args:
        directory: The directory to write into.
        data: Mapping of ``{(module, va_int): {field: value}}``.
    """
    path = directory / METADATA_FILENAME
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
    """Return metadata fields for *(module, va)* in *directory*.

    Returns an empty dict if not found.

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).
        va: Virtual address integer.
        module: Target module name (e.g. ``"SERVER"``).

    """
    return load_metadata(directory).get((module, va), {})


def _set_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Set one field for *(module, va)* in the metadata.  **Private** — use
    :func:`update_field` or :func:`update_source_status` instead.

    Writes directly to ``directory / rebrew-function.toml``.  No walk-up.
    Uses in-place ``tomlkit`` editing to preserve formatting and comments.
    """
    path = directory / METADATA_FILENAME
    toml_key = _qualified_key(module, va)

    if path.exists():
        try:
            doc = tomlkit.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse metadata %s, starting fresh: %s", path, exc)
            doc = tomlkit.document()
    else:
        doc = tomlkit.document()

    if toml_key not in doc:
        doc[toml_key] = tomlkit.table()

    doc[toml_key][key] = value  # type: ignore[index]
    atomic_write_text(path, tomlkit.dumps(doc))


def _delete_field(directory: Path, va: int, key: str, module: str) -> bool:
    """Remove *key* from the metadata entry for *(module, va)*.  **Private** —
    use :func:`remove_field` instead.

    Reads/writes directly at ``directory / rebrew-function.toml``.  No walk-up.
    Returns True if removed.
    """
    path = directory / METADATA_FILENAME
    if not path.exists():
        return False
    toml_key = _qualified_key(module, va)

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse metadata %s: %s", path, exc)
        return False

    # Use dict access for type checking on tomlkit Container
    doc_dict = typing.cast(dict[str, Any], doc)
    if toml_key not in doc_dict:
        return False
    entry = typing.cast(dict[str, Any], doc_dict[toml_key])
    if key in entry:
        del entry[key]
        atomic_write_text(path, tomlkit.dumps(doc))
        return True
    return False


def update_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Central gatekeeper for all metadata field writes.

    All external callers must use this function (or :func:`update_source_status`
    for STATUS changes) to write to ``rebrew-function.toml``.

    Business rules enforced here:
    - STATUS writes are blocked; callers must use :func:`update_source_status`.

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).
        va: Virtual address integer.
        key: Lower-case TOML key (e.g. ``"cflags"``, ``"blocker"``).
        value: Value to write.
        module: Target module name (e.g. ``"SERVER"``).

    Raises:
        ValueError: If *key* is ``"status"`` — use :func:`update_source_status`.

    """
    if key == "status":
        raise ValueError(
            "Use update_source_status() for STATUS changes — it enforces promotion rules"
        )
    _set_field(directory, va, key, value, module=module)


def set_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Raw field writer — sets *key* to *value* without any guards.

    Unlike :func:`update_field`, this does **not** reject STATUS writes.
    Use this only when you need to bypass business rules (e.g. tests,
    data migration scripts).

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).
        va: Virtual address integer.
        key: Lower-case TOML key (e.g. ``"cflags"``, ``"status"``).
        value: Value to write.
        module: Target module name (e.g. ``"SERVER"``).

    """
    _set_field(directory, va, key, value, module=module)


def remove_field(directory: Path, va: int, key: str, module: str) -> bool:
    """Central gatekeeper for metadata field deletes.

    All external callers must use this function to remove fields from
    ``rebrew-function.toml``.

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).
        va: Virtual address integer.
        key: Lower-case TOML key to remove.
        module: Target module name.

    Returns:
        True if the field was removed, False otherwise.

    Raises:
        ValueError: If *key* is ``"status"`` — cannot delete STATUS directly.

    """
    if key == "status":
        raise ValueError("Cannot delete STATUS directly")
    return _delete_field(directory, va, key, module=module)


# ---------------------------------------------------------------------------
# Status promotion
# ---------------------------------------------------------------------------


def update_source_status(
    metadata_dir: Path,
    new_status: str,
    module: str,
    va: int,
    *,
    clear_blockers: bool = True,
    force: bool = False,
) -> None:
    """Write STATUS for (module, va) to the metadata; never touches the .c file.

    This is the single canonical place to promote a function's STATUS.  Both
    ``rebrew test`` and ``rebrew verify --fix-status`` call this function.

    PROVEN is a post-verify promotion from ``rebrew prove`` and is never
    silently demoted.  Callers that need to override this must pass
    ``force=True``.

    Uses a single read-modify-write cycle instead of separate get/set/delete
    calls to minimise I/O and avoid partial-write windows.

    Args:
        metadata_dir: The metadata root directory (``cfg.reversed_dir``).
        new_status: New status string (e.g. ``EXACT``, ``RELOC``, ``NEAR_MATCH``).
        module: Target module name from the annotation (e.g. ``NP``).
        va: Virtual address of the function.
        clear_blockers: If ``True`` (default), remove ``blocker`` and
            ``blocker_delta`` from the metadata entry (correct for EXACT/RELOC).
            Pass ``False`` when demoting to NEAR_MATCH to preserve user-set blockers.
        force: If ``True``, allow demotion from PROVEN.  Default ``False``.

    """
    if not module:
        return

    path = metadata_dir / METADATA_FILENAME
    toml_key = _qualified_key(module, va)

    # Single read
    if path.exists():
        try:
            doc = tomlkit.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse metadata %s, starting fresh: %s", path, exc)
            doc = tomlkit.document()
    else:
        doc = tomlkit.document()

    # Use dict access for type checking on tomlkit Container
    doc_dict = typing.cast(dict[str, Any], doc)
    if toml_key not in doc_dict:
        doc_dict[toml_key] = tomlkit.table()

    entry = typing.cast(dict[str, Any], doc_dict[toml_key])

    # Idempotency guard — avoid write if nothing changed
    current_status = entry.get("status", "")
    current_blocker = entry.get("blocker", "")
    if current_status == new_status and (not clear_blockers or not current_blocker):
        return

    # PROVEN is a post-verify promotion from rebrew prove — never silently demote.
    if current_status == "PROVEN" and new_status != "PROVEN" and not force:
        return

    # Mutate in-place
    entry["status"] = new_status
    if clear_blockers:
        with contextlib.suppress(KeyError):
            del entry["blocker"]
        with contextlib.suppress(KeyError):
            del entry["blocker_delta"]

    # Single write
    atomic_write_text(path, tomlkit.dumps(doc))


# ---------------------------------------------------------------------------
# Annotation merge
# ---------------------------------------------------------------------------


def merge_into_annotation(ann: Annotation, directory: Path) -> Annotation:
    """Overlay metadata values onto *ann*, returning the same object mutated.

    The metadata wins for every field it defines.

    Lookup uses the qualified key ``(ann.module, ann.va)``.  Multi-target
    ``.c`` files (with multiple ``// FUNCTION: MODULE 0xVA`` markers) each
    receive their own metadata entry and are merged in isolation.

    Args:
        ann: The ``Annotation`` object to mutate.
        directory: The metadata root directory (``cfg.reversed_dir``).

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
