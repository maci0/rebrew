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
This makes the metadata unambiguous across multi-target projects.

Owned fields per entry::

    name, size, section, note

Atomicity
---------
Writes use ``tomlkit`` for round-trip-safe serialisation and the standard
``atomic_write_text`` helper (write to ``.tmp``, ``os.replace``).
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from rebrew.utils import (
    atomic_write_text,
    load_metadata_doc,
    load_toml_for_write,
    metadata_write_lock,
    qualified_key,
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

_data_metadata_cache: dict[Path, tuple[int, dict[tuple[str, int], dict[str, Any]]]] = {}


def _invalidate_data_cache(path: Path) -> None:
    """Drop the cached parse for *path* (resolved) after a write."""
    _data_metadata_cache.pop(path.resolve(), None)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_METADATA_FILENAME = "rebrew-data.toml"

#: Fields owned by the data metadata.
DATA_METADATA_FIELDS: frozenset[str] = frozenset({"NAME", "SIZE", "SECTION", "NOTE"})

# Canonical TOML key order when writing.
_CANONICAL_ORDER = ["name", "type", "size", "section", "note"]

__all__ = [
    "DATA_METADATA_FILENAME",
    "DATA_METADATA_FIELDS",
    "load_data_metadata",
    "iter_data_symbols",
    "get_data_entry",
    "set_data_field",
    "merge_into_data_annotation",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    # mechanism as rebrew-functions.toml (metadata.py).
    cached = load_metadata_doc(path, _data_metadata_cache, "data metadata")
    # Return a shallow copy of outer dict + each entry dict so callers cannot
    # mutate the cached object and corrupt subsequent reads.
    return {k: dict(v) for k, v in cached.items()}


# ---------------------------------------------------------------------------
# Granular read/write
# ---------------------------------------------------------------------------


def get_data_entry(directory: Path, va: int, module: str) -> dict[str, Any]:
    """Return data metadata fields for *(module, va)* in *directory*.

    Returns an empty dict if not found.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
        va: Virtual address integer.
        module: Target module name (e.g. ``"SERVER"``).

    """
    entry = load_data_metadata(directory).get((module, va))
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
    if not key or not key.isidentifier():
        raise ValueError(f"invalid data metadata key {key!r}")
    if va < 0:
        raise ValueError(f"VA must be non-negative, got {va:#x}")
    path = directory / DATA_METADATA_FILENAME
    toml_key = qualified_key(module, va)

    with metadata_write_lock(directory, DATA_METADATA_FILENAME):
        doc = load_toml_for_write(path, "data metadata")

        if toml_key not in doc:
            doc[toml_key] = tomlkit.table()

        doc[toml_key][key] = value  # type: ignore[index]
        atomic_write_text(path, tomlkit.dumps(doc))
        _invalidate_data_cache(path)


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

    if "name" in entry and entry["name"]:
        ann.name = str(entry["name"])

    if "size" in entry:
        with contextlib.suppress(ValueError, TypeError):
            ann.size = int(entry["size"])

    if "section" in entry:
        ann.section = str(entry["section"])

    if "note" in entry:
        ann.note = str(entry["note"])

    return ann
