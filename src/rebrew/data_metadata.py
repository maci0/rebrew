"""data_metadata.py — Per-directory metadata store for DATA/GLOBAL annotations.

Volatile metadata for data annotations (NAME, SIZE, SECTION, NOTE) are stored in a
single ``rebrew-data.toml`` metadata file at the ``metadata_dir`` root
(``cfg.metadata_dir``).  This mirrors the pattern established by
``metadata.py`` for function annotations.

Location
--------
The metadata file lives **only** at ``cfg.metadata_dir``.  There is no walk-up
discovery — callers must pass the correct root directory.  Subdirectories
do **not** have their own data metadata files.

The ``.c`` file retains only the stable reccmp-compatible marker line and the
C declaration::

    // DATA: SERVER 0x10025000

    extern const unsigned char g_sprite_lut[256];

All rebrew-specific metadata lives in ``rebrew-data.toml``::

    ["SERVER.0x10025000"]
    size    = 256
    section = ".rdata"
    note    = "sprite index lookup table"

Key format
----------
Identical to ``rebrew-functions.toml``: ``"MODULE.0xVA"`` (qualified key).
This makes the metadata unambiguous across multi-target projects.  Reads key
on the parsed ``(module, va)``, so an entry spelled with different hex
padding than :func:`rebrew.utils.qualified_key` produces is still found and
updated in place, never shadowed by an appended twin.

Owned fields per entry::

    name, type, size, section, note, status

(``status`` is the data-verify verdict: ``VERIFIED`` / ``DRIFT`` / ``UNCHECKED``.)

Atomicity
---------
Writes use ``tomlkit`` for round-trip-safe serialisation and
``atomic_write_locked`` (``.tmp`` + ``os.replace``, then re-lock to 0444).
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from rebrew.metadata import as_metadata_int
from rebrew.utils import (
    MetadataDocCache,
    atomic_write_locked,
    build_metadata_key_index,
    load_metadata_doc,
    load_toml_for_write,
    metadata_write_lock,
    pop_metadata_doc_cache,
    resolve_metadata_key,
)

if TYPE_CHECKING:
    from rebrew.annotation import Annotation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory cache for load_data_metadata() — mirrors metadata.py's cache for
# rebrew-functions.toml.  Without it, batch paths that read data metadata per
# file (lint) or per function (smart_reloc_compare's global-name resolution)
# re-parse the TOML on every call.  Keyed by resolved Path; invalidated by
# mtime_ns change or by the write helpers below.
# ---------------------------------------------------------------------------

_data_metadata_cache: MetadataDocCache = {}


def _invalidate_data_cache(path: Path) -> None:
    """Drop the cached parse for *path* (resolved) after a write."""
    pop_metadata_doc_cache(_data_metadata_cache, path.resolve())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_METADATA_FILENAME = "rebrew-data.toml"

#: Fields owned by the data metadata.  Must match ``_CANONICAL_ORDER``: `type`
#: is written by `rebrew data --set-type` and the binsync import/overlay paths.
DATA_METADATA_FIELDS: frozenset[str] = frozenset(
    {"NAME", "TYPE", "SIZE", "SECTION", "NOTE", "STATUS"}
)

#: Data verification verdicts written by ``verify --data``.
DATA_STATUS_VERIFIED = "VERIFIED"
DATA_STATUS_DRIFT = "DRIFT"
DATA_STATUS_UNCHECKED = "UNCHECKED"
DATA_STATUSES: frozenset[str] = frozenset(
    {DATA_STATUS_VERIFIED, DATA_STATUS_DRIFT, DATA_STATUS_UNCHECKED}
)

# Canonical TOML key order when writing.
_CANONICAL_ORDER = ["name", "type", "size", "section", "note", "status"]

__all__ = [
    "DATA_METADATA_FILENAME",
    "DATA_METADATA_FIELDS",
    "load_data_metadata",
    "iter_data_symbols",
    "get_data_entry",
    "set_data_field",
    "set_data_fields_batch",
    "merge_into_data_annotation",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_data_field(key: str, value: Any) -> None:
    """Reject a key outside :data:`DATA_METADATA_FIELDS` or a non-verdict STATUS.

    Function-only fields (BLOCKER, CFLAGS, …) and function STATUS values have no
    meaning in the data store; accepting them would give a fact a second home.
    """
    if not key or key.upper() not in DATA_METADATA_FIELDS or key != key.lower():
        raise ValueError(
            f"unknown data metadata field {key!r} "
            f"(expected one of {sorted(k.lower() for k in DATA_METADATA_FIELDS)})"
        )
    if key == "status" and value not in DATA_STATUSES:
        raise ValueError(f"invalid data STATUS {value!r} (expected one of {sorted(DATA_STATUSES)})")


# ---------------------------------------------------------------------------
# Raw-document iteration
# ---------------------------------------------------------------------------


def iter_data_symbols(
    doc: dict[str, Any], section: str | None = ".data"
) -> Iterator[tuple[str, int, dict[str, Any]]]:
    """Yield ``(module, va, fields)`` for every entry in a parsed ``rebrew-data.toml``.

    The canonical key parser for raw (string-keyed) data-metadata documents:
    keys are ``"MODULE.0xVA"`` with the module possibly containing dots, so
    the VA is everything after the *last* dot.  Entries whose key has no dot
    or a non-hex VA are skipped.

    Args:
        doc: Parsed ``rebrew-data.toml`` content (string keys → field dicts).
        section: Keep only entries whose ``section`` field equals this;
            ``None`` keeps every entry.

    Yields:
        ``(module, va, fields)`` triples.

    """
    for key, val in doc.items():
        if not isinstance(val, dict):
            continue
        if section is not None and val.get("section") != section:
            continue
        module, sep, addr_text = str(key).rpartition(".")
        if not sep:
            continue
        try:
            va = int(addr_text, 16)
        except ValueError:
            continue
        yield module, va, val


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


def load_data_metadata(directory: Path) -> dict[tuple[str, int], dict[str, Any]]:
    """Load ``rebrew-data.toml`` from *directory*.

    *directory* must be the metadata root (``cfg.metadata_dir``).  There is
    no walk-up — the file is expected at exactly ``directory / rebrew-data.toml``.

    Returns a mapping of ``{(module, va_int): {field_name: value}}``.
    Returns an empty dict if no metadata file is found or it cannot be parsed.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).

    """
    path = (directory / DATA_METADATA_FILENAME).resolve()
    if not path.exists():
        return {}

    # Shared loader: tomllib reads (fast), mtime-keyed cache — same
    # mechanism as rebrew-functions.toml (metadata.py).  deepcopy=False:
    # this function already returns a shallow copy of the outer map and
    # each entry, so a full deep clone of the cache is wasted work.
    cached = load_metadata_doc(path, _data_metadata_cache, "data metadata", deepcopy=False)
    # Return a shallow copy of outer dict + each entry dict so callers cannot
    # mutate the cached object and corrupt subsequent reads.
    return {k: dict(v) for k, v in cached.items()}


# ---------------------------------------------------------------------------
# Granular read/write
# ---------------------------------------------------------------------------


def get_data_entry(directory: Path, va: int, module: str) -> dict[str, Any]:
    """Return data metadata fields for *(module, va)* in *directory*.

    Returns an empty dict if not found.  Copies only the selected entry, not
    the whole table, so per-symbol lookups in batch loops stay O(1).

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
        va: Virtual address integer.
        module: Target module name (e.g. ``"SERVER"``).

    """
    path = (directory / DATA_METADATA_FILENAME).resolve()
    cached = load_metadata_doc(path, _data_metadata_cache, "data metadata", deepcopy=False)
    entry = cached.get((module, va))
    return dict(entry) if entry is not None else {}


def set_data_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Set one field for *(module, va)* in the data metadata.

    Writes directly to ``directory / rebrew-data.toml``.  No walk-up.
    Uses in-place ``tomlkit`` editing to preserve formatting and comments.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
        va: Virtual address integer.
        key: Lower-case TOML key (e.g. ``"size"``, ``"section"``).
        value: Value to write.
        module: Target module name (e.g. ``"SERVER"``).

    """
    if not module:
        raise ValueError("data metadata writes require a non-empty module")
    _check_data_field(key, value)
    if va < 0:
        raise ValueError(f"VA must be non-negative, got {va:#x}")
    path = directory / DATA_METADATA_FILENAME

    with metadata_write_lock(directory, DATA_METADATA_FILENAME):
        doc = load_toml_for_write(path, "data metadata")
        toml_key = resolve_metadata_key(doc, module, va)

        if toml_key not in doc:
            doc[toml_key] = tomlkit.table()
        elif not isinstance(doc[toml_key], dict):
            # Same predicate the loader uses to skip unusable entries: a scalar
            # (or AoT) at the key cannot hold fields, and indexing it raised
            # TypeError out of `rebrew data --set-*`.  Failing loud beats
            # silently discarding whatever is there.
            raise ValueError(
                f"data metadata entry {toml_key!r} is not a table "
                f"({type(doc[toml_key]).__name__}); repair or remove it first"
            )

        from rebrew.metadata import toml_safe

        # Same-value short-circuit: a re-run that sets the field to what is
        # already stored must not rewrite the TOML (mtime churn would invalidate
        # verify caches and make an idempotent `--fix-bss` look dirty).
        entry = doc[toml_key]
        safe = toml_safe(value)
        if isinstance(entry, dict) and entry.get(key) == safe:
            return

        entry[key] = safe
        atomic_write_locked(path, tomlkit.dumps(doc))
        _invalidate_data_cache(path)


def set_data_fields_batch(directory: Path, updates: list[dict[str, Any]]) -> int:
    """Set fields for many ``(module, va)`` entries in one TOML read-modify-write.

    Sibling of :func:`rebrew.metadata.set_fields_batch` for the data store.
    Each update is ``{"module", "va", "fields": {key: value, ...}}``.  Same-value
    short-circuit is preserved per field.  Returns the number of entries that
    changed at least one field.
    """
    if not updates:
        return 0
    path = directory / DATA_METADATA_FILENAME
    changed_entries = 0
    with metadata_write_lock(directory, DATA_METADATA_FILENAME):
        doc = load_toml_for_write(path, "data metadata")
        key_index = build_metadata_key_index(doc)
        from rebrew.metadata import toml_safe

        for u in updates:
            module = str(u.get("module") or "")
            if not module:
                raise ValueError("data metadata writes require a non-empty module")
            va = u.get("va")
            if va is None:
                continue
            va_int = int(va)
            if va_int < 0:
                raise ValueError(f"VA must be non-negative, got {va_int:#x}")
            fields = u.get("fields") or {}
            if not fields:
                continue
            toml_key = resolve_metadata_key(doc, module, va_int, index=key_index)
            if toml_key not in doc:
                doc[toml_key] = tomlkit.table()
                key_index[(module, va_int)] = toml_key
            elif not isinstance(doc[toml_key], dict):
                raise ValueError(
                    f"data metadata entry {toml_key!r} is not a table "
                    f"({type(doc[toml_key]).__name__}); repair or remove it first"
                )
            entry = doc[toml_key]
            changed = False
            for key, value in fields.items():
                _check_data_field(key, value)
                safe = toml_safe(value)
                if isinstance(entry, dict) and entry.get(key) == safe:
                    continue
                entry[key] = safe
                changed = True
            if changed:
                changed_entries += 1
        if changed_entries:
            atomic_write_locked(path, tomlkit.dumps(doc))
            _invalidate_data_cache(path)
    return changed_entries


def delete_data_entries_batch(directory: Path, targets: list[tuple[str, int]]) -> int:
    """Drop whole ``(module, va)`` entries from ``rebrew-data.toml`` in one rewrite.

    Sibling of :func:`rebrew.metadata.delete_entries_batch` for the data
    store (orphan pruning: DATA/GLOBAL blocks whose VA has no source
    annotation).  Returns the number of entries removed.  Missing entries
    are no-ops.  Only touches the metadata file — never a source file.
    """
    if not targets:
        return 0
    path = (directory / DATA_METADATA_FILENAME).resolve()
    if not path.exists():
        return 0
    removed = 0
    with metadata_write_lock(directory, DATA_METADATA_FILENAME):
        doc = load_toml_for_write(path, "data metadata")
        key_index = build_metadata_key_index(doc)
        for module, va in targets:
            if not module:
                continue
            va_int = int(va)
            toml_key = resolve_metadata_key(doc, str(module), va_int, index=key_index)
            if toml_key not in doc:
                continue
            del doc[toml_key]
            key_index.pop((str(module), va_int), None)
            removed += 1
        if removed:
            atomic_write_locked(path, tomlkit.dumps(doc))
            _invalidate_data_cache(path)
    return removed


# ---------------------------------------------------------------------------
# Annotation merge
# ---------------------------------------------------------------------------


def merge_into_data_annotation(ann: Annotation, directory: Path) -> Annotation:
    """Overlay data metadata values onto *ann*, returning the same object mutated.

    The metadata wins for every field it defines (SIZE, SECTION, NOTE).

    Lookup uses the qualified key ``(ann.module, ann.va)``.

    Args:
        ann: The ``Annotation`` object to mutate (must have ``marker_type``
            of ``DATA`` or ``GLOBAL``).
        directory: The metadata root directory (``cfg.metadata_dir``).

    Returns:
        The mutated *ann* (same object, for chaining convenience).

    """
    module: str = getattr(ann, "module", None) or ""
    if not module:
        return ann
    entry = get_data_entry(directory, ann.va, module=module)
    if not entry:
        return ann

    if name := entry.get("name"):
        ann.name = str(name)

    if "size" in entry:
        with contextlib.suppress(ValueError, TypeError):
            ann.size = as_metadata_int(entry["size"])

    if "section" in entry:
        ann.section = str(entry["section"])

    if "note" in entry:
        ann.note = str(entry["note"])

    if "status" in entry:
        ann.status = str(entry["status"])

    return ann
