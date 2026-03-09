"""data_metadata.py — Per-directory metadata store for DATA/GLOBAL annotations.

Volatile metadata for data annotations (SIZE, SECTION, NOTE) are stored in a
single ``rebrew-data.toml`` metadata file at the ``reversed_dir`` root
(e.g. ``src/<target>/``).  This mirrors the pattern established by
``metadata.py`` for function annotations.

Location
--------
The metadata file lives **only** at ``cfg.reversed_dir``.  There is no walk-up
discovery — callers must pass the correct root directory.  Subdirectories
under ``reversed_dir`` do **not** have their own data metadata files.

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
Identical to ``rebrew-function.toml``: ``"MODULE.0xVA"`` (qualified key).
This makes the metadata unambiguous across multi-target projects.

Owned fields per entry::

    size, section, note

Atomicity
---------
Writes use ``tomlkit`` for round-trip-safe serialisation and the standard
``atomic_write_text`` helper (write to ``.tmp``, ``os.replace``).
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

DATA_METADATA_FILENAME = "rebrew-data.toml"

#: Fields owned by the data metadata.
DATA_METADATA_FIELDS: frozenset[str] = frozenset({"NAME", "SIZE", "SECTION", "NOTE"})

# Canonical TOML key order when writing.
_CANONICAL_ORDER = ["name", "size", "section", "note"]

__all__ = [
    "DATA_METADATA_FILENAME",
    "DATA_METADATA_FIELDS",
    "is_data_metadata_key",
    "data_metadata_path",
    "load_data_metadata",
    "save_data_metadata",
    "get_data_entry",
    "set_data_field",
    "delete_data_field",
    "merge_into_data_annotation",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_data_metadata_key(key: str) -> bool:
    """Return True if *key* (upper-case annotation KV name) belongs in the data metadata."""
    return key.upper() in DATA_METADATA_FIELDS


def data_metadata_path(directory: Path) -> Path:
    """Return the ``rebrew-data.toml`` path for the metadata root directory.

    Args:
        directory: The ``reversed_dir`` root (e.g. ``src/<target>/``).

    """
    return directory / DATA_METADATA_FILENAME


def _qualified_key(module: str | None, va: int) -> str:
    """Return the canonical TOML key for *(module, va)*.

    Examples::

        >>> _qualified_key("SERVER", 0x10025000)
        'SERVER.0x10025000'
        >>> _qualified_key(None, 0x10025000)
        '0x10025000'

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

        >>> _parse_key("SERVER.0x10025000")
        ('SERVER', 268587008)
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


def load_data_metadata(directory: Path) -> dict[tuple[str, int], dict[str, Any]]:
    """Load ``rebrew-data.toml`` from *directory*.

    *directory* must be the metadata root (``cfg.reversed_dir``).  There is
    no walk-up — the file is expected at exactly ``directory / rebrew-data.toml``.

    Returns a mapping of ``{(module, va_int): {field_name: value}}``.
    Returns an empty dict if no metadata file is found or it cannot be parsed.

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).

    """
    path = directory / DATA_METADATA_FILENAME
    if not path.exists():
        return {}

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse data metadata %s: %s", path, exc)
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


def save_data_metadata(
    directory: Path,
    data: dict[tuple[str, int], dict[str, Any]],
) -> None:
    """Atomically write *data* to ``rebrew-data.toml`` in *directory*.

    Args:
        directory: The directory to write into.
        data: Mapping of ``{(module, va_int): {field: value}}``.
    """
    path = directory / DATA_METADATA_FILENAME
    doc = tomlkit.document()

    for module, va_int in sorted(data, key=lambda k: (k[0], k[1])):
        entry = data[(module, va_int)]
        if not entry:
            continue
        toml_key = _qualified_key(module, va_int)
        tbl = tomlkit.table()
        seen: set[str] = set()
        for field in _CANONICAL_ORDER:
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


def get_data_entry(directory: Path, va: int, module: str) -> dict[str, Any]:
    """Return data metadata fields for *(module, va)* in *directory*.

    Returns an empty dict if not found.

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).
        va: Virtual address integer.
        module: Target module name (e.g. ``"SERVER"``).

    """
    return load_data_metadata(directory).get((module, va), {})


def set_data_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Set one field for *(module, va)* in the data metadata.

    Writes directly to ``directory / rebrew-data.toml``.  No walk-up.
    Uses in-place ``tomlkit`` editing to preserve formatting and comments.

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).
        va: Virtual address integer.
        key: Lower-case TOML key (e.g. ``"size"``, ``"section"``).
        value: Value to write.
        module: Target module name (e.g. ``"SERVER"``).

    """
    path = directory / DATA_METADATA_FILENAME
    toml_key = _qualified_key(module, va)

    if path.exists():
        try:
            doc = tomlkit.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse data metadata %s, starting fresh: %s", path, exc)
            doc = tomlkit.document()
    else:
        doc = tomlkit.document()

    if toml_key not in doc:
        doc[toml_key] = tomlkit.table()

    doc[toml_key][key] = value  # type: ignore[index]
    atomic_write_text(path, tomlkit.dumps(doc))


def delete_data_field(directory: Path, va: int, key: str, module: str) -> None:
    """Remove *key* from the data metadata entry for *(module, va)*.  No-op if not present.

    Reads/writes directly at ``directory / rebrew-data.toml``.  No walk-up.

    Args:
        directory: The metadata root directory (``cfg.reversed_dir``).
        va: Virtual address integer.
        key: Lower-case TOML key to remove.
        module: Target module name.

    """
    path = directory / DATA_METADATA_FILENAME
    if not path.exists():
        return
    toml_key = _qualified_key(module, va)

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse data metadata %s: %s", path, exc)
        return

    # Use dict access for type checking on tomlkit Container
    doc_dict = typing.cast(dict[str, Any], doc)
    if toml_key not in doc_dict:
        return
    entry = typing.cast(dict[str, Any], doc_dict[toml_key])
    if key in entry:
        del entry[key]
        atomic_write_text(path, tomlkit.dumps(doc))


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
        directory: The metadata root directory (``cfg.reversed_dir``).

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
