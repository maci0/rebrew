"""data_sidecar.py — Per-directory metadata store for DATA/GLOBAL annotations.

Volatile metadata for data annotations (SIZE, SECTION, NOTE) are stored in a
``rebrew-data.toml`` sidecar file alongside the reversed ``.c`` sources.  This
mirrors the pattern established by ``sidecar.py`` for function annotations.

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
This makes the sidecar unambiguous across multi-target projects.

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

DATA_SIDECAR_FILENAME = "rebrew-data.toml"

#: Fields owned by the data sidecar.
DATA_SIDECAR_FIELDS: frozenset[str] = frozenset({"NAME", "SIZE", "SECTION", "NOTE"})

# Canonical TOML key order when writing.
_CANONICAL_ORDER = ["name", "size", "section", "note"]

__all__ = [
    "DATA_SIDECAR_FILENAME",
    "DATA_SIDECAR_FIELDS",
    "is_data_sidecar_key",
    "data_sidecar_path",
    "load_data_sidecar",
    "save_data_sidecar",
    "get_data_entry",
    "set_data_field",
    "delete_data_field",
    "merge_into_data_annotation",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_data_sidecar_key(key: str) -> bool:
    """Return True if *key* (upper-case annotation KV name) belongs in the data sidecar."""
    return key.upper() in DATA_SIDECAR_FIELDS


def data_sidecar_path(source_or_dir: Path) -> Path:
    """Return the ``rebrew-data.toml`` path for a source file or its parent directory.

    Args:
        source_or_dir: Either a ``.c`` source file or the directory that
            contains it.  Both forms are accepted.

    """
    if source_or_dir.is_dir():
        return source_or_dir / DATA_SIDECAR_FILENAME
    return source_or_dir.parent / DATA_SIDECAR_FILENAME


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
    """Parse a sidecar TOML key into ``(module, va_int)``.

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


def _find_data_sidecar_dir(start: Path) -> Path:
    """Return the directory that owns ``rebrew-data.toml`` for *start*.

    Walks *start* → parent → grandparent … until a directory containing
    ``rebrew-data.toml`` is found.  If no ancestor has the file, returns
    *start* (so callers that write will create the file there).

    Args:
        start: Directory to begin the search from (typically ``filepath.parent``).

    """
    current = start.resolve()
    parent = current.parent
    while current != parent:  # filesystem root: parent of root is itself
        if (current / DATA_SIDECAR_FILENAME).exists():
            return current
        current, parent = parent, parent.parent
    return start


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


def load_data_sidecar(directory: Path) -> dict[tuple[str, int], dict[str, Any]]:
    """Load a ``rebrew-data.toml`` for sources in *directory*.

    Walks *directory* → parent → … until ``rebrew-data.toml`` is found,
    then loads and returns its contents.  A single sidecar at a project root
    is shared by all subdirectories.

    Returns a mapping of ``{(module, va_int): {field_name: value}}``.
    Returns an empty dict if no sidecar file is found or it cannot be parsed.

    Args:
        directory: Starting directory (typically ``filepath.parent``).

    """
    path = _find_data_sidecar_dir(directory) / DATA_SIDECAR_FILENAME
    if not path.exists():
        return {}

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse data sidecar %s: %s", path, exc)
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


def save_data_sidecar(
    directory: Path,
    data: dict[tuple[str, int], dict[str, Any]],
) -> None:
    """Atomically write *data* to ``rebrew-data.toml`` in *directory*.

    Args:
        directory: The directory to write into.
        data: Mapping of ``{(module, va_int): {field: value}}``.
    """
    path = directory / DATA_SIDECAR_FILENAME
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
    """Return data sidecar fields for *(module, va)* in *directory* (or any parent).

    Returns an empty dict if not found.

    Args:
        directory: Starting directory (typically ``filepath.parent``).
        va: Virtual address integer.
        module: Target module name (e.g. ``"SERVER"``).

    """
    return load_data_sidecar(directory).get((module, va), {})


def set_data_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Set one field for *(module, va)* in the data sidecar.

    Walks up from *directory* to find the existing sidecar file.  If no
    ancestor sidecar exists, creates ``rebrew-data.toml`` in *directory*.
    Uses in-place ``tomlkit`` editing to preserve formatting and comments.

    Args:
        directory: Starting directory (typically ``filepath.parent``).
        va: Virtual address integer.
        key: Lower-case TOML key (e.g. ``"size"``, ``"section"``).
        value: Value to write.
        module: Target module name (e.g. ``"SERVER"``).

    """
    path = _find_data_sidecar_dir(directory) / DATA_SIDECAR_FILENAME
    toml_key = _qualified_key(module, va)

    if path.exists():
        try:
            doc = tomlkit.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse data sidecar %s, starting fresh: %s", path, exc)
            doc = tomlkit.document()
    else:
        doc = tomlkit.document()

    if toml_key not in doc:
        doc[toml_key] = tomlkit.table()

    doc[toml_key][key] = value  # type: ignore[index]
    atomic_write_text(path, tomlkit.dumps(doc))


def delete_data_field(directory: Path, va: int, key: str, module: str) -> None:
    """Remove *key* from the data sidecar entry for *(module, va)*.  No-op if not present.

    Walks up from *directory* to find the sidecar file.

    Args:
        directory: Starting directory (typically ``filepath.parent``).
        va: Virtual address integer.
        key: Lower-case TOML key to remove.
        module: Target module name.

    """
    path = _find_data_sidecar_dir(directory) / DATA_SIDECAR_FILENAME
    if not path.exists():
        return
    toml_key = _qualified_key(module, va)

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse data sidecar %s: %s", path, exc)
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


def merge_into_data_annotation(ann: Annotation, directory: Path) -> Annotation:
    """Overlay data sidecar values onto *ann*, returning the same object mutated.

    The sidecar wins for every field it defines (SIZE, SECTION, NOTE).

    Lookup uses the qualified key ``(ann.module, ann.va)``.

    Args:
        ann: The ``Annotation`` object to mutate (must have ``marker_type``
            of ``DATA`` or ``GLOBAL``).
        directory: Directory containing ``rebrew-data.toml``.

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
