"""metadata.py — Per-directory metadata store for rebrew.

Volatile annotation fields (STATUS, SIZE, CFLAGS, BLOCKER, NOTE, GHIDRA, …)
are stored in a single ``rebrew-functions.toml`` metadata file at the
``metadata_dir`` root (``cfg.metadata_dir``, i.e. ``reversed_dir.parent``),
rather than as comment annotations inside ``.c`` source files.

Location
--------
The metadata file lives **only** at ``cfg.metadata_dir``.  There is no walk-up
discovery — callers must pass the correct root directory.  Subdirectories
under ``metadata_dir`` do **not** have their own metadata files.

Key format
----------
The metadata is keyed by *qualified module+VA string*::

    ["SERVER.0x01006364"]
    status = "EXACT"
    size   = 42

This allows a single ``rebrew-functions.toml`` to hold metadata for **multiple
targets** (e.g. ``SERVER`` and ``CLIENT``) that share a directory or ``.c``
file — the full key is unambiguous even if two targets happen to have a
function at the same VA.  The format mirrors the ``// FUNCTION: SERVER
0x01006364`` marker.

Tools write :func:`rebrew.utils.qualified_key`'s zero-padded spelling.  Reads
key on the parsed ``(module, va)``, so a file carrying another hex padding
(``SERVER.0x1000`` beside ``SERVER.0x00001000``) resolves to one entry, and
writes update the spelling the file already uses instead of appending a twin.

Owned fields per entry::

    size, cflags, toolchain, status, blocker, blocker_delta, note, ghidra,
    analysis, skip, source, globals, prove_constraints

The full canonical set is :data:`METADATA_FIELDS` (upper-case marker names).
``SECTION`` is intentionally *not* owned here — it lives in
``rebrew-data.toml`` (see :mod:`rebrew.data_metadata`) for DATA/GLOBAL
annotations.

The ``// FUNCTION: MODULE 0xVA`` (and LIBRARY/STUB/GLOBAL/DATA) marker lines
remain in the ``.c`` files for reccmp compatibility.

Status promotion
----------------
Use :func:`update_source_status` — the single canonical writer — to promote
a function's STATUS.  ``rebrew test`` calls it directly; the bulk tool
``rebrew verify`` goes through :func:`update_statuses_batch`, which enforces
the same promotion rules.  Neither ever touches the ``.c`` file.

BLOCKER writes
--------------
``BLOCKER`` / ``BLOCKER_DELTA`` are equally programmatic — use
``rebrew blocker set/clear`` (or ``rebrew diff --fix-blocker`` /
``rebrew near-diag --fix-blocker`` / ``rebrew document-unmatched`` for
auto-classified cases).  The Python gate is :func:`update_field` /
:func:`remove_field` with *key* ``"blocker"`` / ``"blocker_delta"``.
No hand-edits to ``rebrew-functions.toml`` — every write goes through the
lock + ``atomic_write_locked`` (chmod writable → atomic replace → mode 0444).

Merge semantics
---------------
When a rebrew tool reads an ``Annotation`` from ``parse_c_file_multi()``, it
calls ``merge_into_annotation(ann, directory)`` which overlays *metadata* values
on top.  Metadata always wins for the fields it owns.  The legacy ``analysis``
field is mapped to ``note`` when the annotation has no explicit note.

Atomicity
---------
Writes use ``tomlkit`` for round-trip-safe serialisation and
``atomic_write_locked`` (``.tmp`` + ``os.replace``, then re-lock to 0444).

Thread safety
-------------
Writes to the metadata file are serialised by a module-level lock because
``rebrew verify --jobs > 1`` and the GA batch promote STATUS from worker
threads.  Each write is atomic (rename), but read-modify-write cycles from
different threads would otherwise race.
"""

from __future__ import annotations

import contextlib
import copy
import logging
import math
import threading
import tomllib
import typing
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from rebrew.errors import RebrewError
from rebrew.utils import (
    MetadataDocCache,
    atomic_write_locked,
    build_metadata_doc,
    build_metadata_key_index,
    clear_metadata_doc_cache,
    load_metadata_doc,
    load_toml_for_write,
    metadata_write_lock,
    pop_metadata_doc_cache,
    resolve_metadata_key,
)
from rebrew.workspace.status import KNOWN_STATUSES as KNOWN_STATUSES
from rebrew.workspace.status import MATCHED_STATUSES as MATCHED_STATUSES

if TYPE_CHECKING:
    from rebrew.annotation import Annotation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory cache for load_metadata() — avoids re-parsing the same TOML file
# hundreds of times during batch operations (verify, status, merge).
# Keyed by resolved Path; invalidated by mtime_ns change or explicit clear.
# ---------------------------------------------------------------------------

_metadata_cache: MetadataDocCache = {}


def clear_metadata_cache() -> None:
    """Clear the in-memory metadata cache.

    Call between top-level CLI commands if running multiple in-process,
    or after writing metadata to ensure subsequent reads see fresh data.
    """
    clear_metadata_doc_cache(_metadata_cache)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

METADATA_FILENAME = "rebrew-functions.toml"

# Canonical TOML key order when writing an entry; unlisted fields follow, in
# insertion order.  Mirrors ``data_metadata._CANONICAL_ORDER``.
_CANONICAL_ORDER = [
    "size",
    "cflags",
    "toolchain",
    "status",
    "blocker",
    "blocker_delta",
    "note",
    "ghidra",
    "analysis",
    "skip",
    "globals",
    "locals",
    "comments",
    "source",
    "prove_constraints",
    "updated_by",
    "updated_at",
]

# Fields that live in the metadata — routing table used by update/delete helpers.
METADATA_FIELDS: frozenset[str] = frozenset(
    {
        "STATUS",
        "SIZE",
        "CFLAGS",
        "TOOLCHAIN",
        "BLOCKER",
        "BLOCKER_DELTA",
        "NOTE",
        "GHIDRA",
        "ANALYSIS",
        "SKIP",
        "GLOBALS",
        # LOCALS is the stack-variable map (rebrew-functions.toml [<mod>.<va>.locals]);
        # COMMENTS is the per-instruction comment map.  Both are declib-backed.
        "LOCALS",
        "COMMENTS",
        # ORIGIN is derivable from the FUNCTION: marker module field.
        "SOURCE",
        "PROVE_CONSTRAINTS",
        # Provenance of the last STATUS write (writer + timestamp).
        "UPDATED_BY",
        "UPDATED_AT",
        # NOTE: SECTION is intentionally absent — it is owned by data_metadata.py
        # for DATA/GLOBAL annotations and must not be written to rebrew-functions.toml.
    }
)

__all__ = [
    "GA_CEILING_PREFIX",
    "KNOWN_STATUSES",
    "LIBRARY_METADATA_FILE",
    "LIBRARY_PRESET_ENTRY_POINT_GROUP",
    "LibraryOverride",
    "LibraryOverrideError",
    "MATCHED_STATUSES",
    "METADATA_FIELDS",
    "METADATA_FILENAME",
    "all_library_presets",
    "apply_library_presets",
    "canonical_status",
    "clear_library_override_cache",
    "clear_metadata_cache",
    "as_metadata_int",
    "coerce_metadata_value",
    "delete_entries_batch",
    "delete_metadata_entry",
    "find_library_override",
    "get_entry",
    "is_metadata_key",
    "is_status_parked",
    "is_status_sticky",
    "is_table_field",
    "load_metadata",
    "merge_into_annotation",
    "metadata_path",
    "parse_library_metadata",
    "refresh_library_presets",
    "remove_field",
    "remove_fields_batch",
    "save_metadata",
    "set_fields",
    "set_fields_batch",
    "should_promote_status",
    "toml_safe",
    "update_field",
    "update_source_status",
    "update_statuses_batch",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_metadata_key(key: str) -> bool:
    """Return True if *key* (annotation KV name, upper-case) belongs in the metadata."""
    return key.upper() in METADATA_FIELDS


def is_table_field(key: str) -> bool:
    """True when *key*'s metadata value is a TOML table (``dict``), not a scalar.

    Inline ``// KEY: value`` comments carry scalars only, so a caller migrating
    an inline key must not hand a string to a table field — ``update_field``
    rejects it (``_validate_field``), which surfaced as a traceback out of
    ``rebrew lint --fix``.
    """
    return _FIELD_TYPES.get(key.lower()) is dict


def metadata_path(directory: Path) -> Path:
    """Return the ``rebrew-functions.toml`` path for the metadata root directory.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).

    """
    return directory / METADATA_FILENAME


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


def load_metadata(
    directory: Path,
    *,
    deepcopy: bool = True,
) -> dict[tuple[str, int], dict[str, Any]]:
    """Load ``rebrew-functions.toml`` from *directory*.

    *directory* must be the metadata root (``cfg.metadata_dir``).  There is
    no walk-up — the file is expected at exactly ``directory / rebrew-functions.toml``.

    Returns a mapping of ``{(module, va_int): {field_name: value}}``.
    Returns an empty dict if no metadata file is found or it cannot be parsed.

    Results are cached in-memory keyed by resolved path and file mtime.
    Call :func:`clear_metadata_cache` to force a re-read.

    When *deepcopy* is True (default), callers receive an isolated copy.
    Pass ``deepcopy=False`` only for read-only consumers that must not
    mutate the returned mapping (or any nested entry dict).

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
        deepcopy: Isolate the returned mapping from the process cache.

    """
    # Resolve so cache keys are stable across relative/absolute call sites.
    path = (directory / METADATA_FILENAME).resolve()
    if not path.exists():
        pop_metadata_doc_cache(_metadata_cache, path)
        return {}

    return load_metadata_doc(path, _metadata_cache, "metadata", deepcopy=deepcopy)


def save_metadata(
    directory: Path,
    data: dict[tuple[str, int], dict[str, Any]],
) -> None:
    """Atomically write *data* to ``rebrew-functions.toml`` in *directory*.

    Args:
        directory: The directory to write into.
        data: Mapping of ``{(module, va_int): {field: value}}``.

    """
    path = (directory / METADATA_FILENAME).resolve()
    doc = build_metadata_doc(data, _CANONICAL_ORDER)
    with metadata_write_lock(directory, METADATA_FILENAME):
        atomic_write_locked(path, tomlkit.dumps(doc))
        pop_metadata_doc_cache(_metadata_cache, path)


# ---------------------------------------------------------------------------
# Granular read/write
# ---------------------------------------------------------------------------


def get_entry(directory: Path, va: int, module: str) -> dict[str, Any]:
    """Return metadata fields for *(module, va)* in *directory*.

    Returns an empty dict if not found.  Loads with ``deepcopy=False`` and
    deep-copies only the selected entry, isolating nested values from the
    process cache without copying the entire metadata table.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
        va: Virtual address integer.
        module: Target module name (e.g. ``"SERVER"``).

    """
    entry = load_metadata(directory, deepcopy=False).get((module, va))
    return copy.deepcopy(entry) if entry else {}


def _require_module(module: str) -> None:
    """Reject empty modules on metadata writes.

    A module-less key (``0xVA``) can be written but never read back —
    ``parse_metadata_key`` only accepts the qualified ``MODULE.0xVA`` form.
    The batch/status writers skip empty modules themselves; this guard
    covers the single-entry helpers that would otherwise silently write a
    key the loader drops.
    """
    if not module:
        raise ValueError("metadata writes require a non-empty module")


_FIELD_TYPES: dict[str, type | tuple[type, ...]] = {
    "size": int,
    "blocker_delta": (int, str),
    "cflags": str,
    "toolchain": str,
    "status": str,
    "blocker": str,
    "note": str,
    "ghidra": str,
    "analysis": str,
    "skip": (str, int, bool),
    "globals": (list, str),
    "locals": dict,
    "comments": dict,
    "source": str,
    "prove_constraints": dict,
    "updated_by": str,
    "updated_at": str,
}
"""Lower-case TOML key → accepted value type(s) for :func:`update_field`.

Fields absent here accept any value (no single unambiguous type).
``size`` is strictly int (coerced from hex/decimal strings); ``skip`` accepts
the truthy spellings the readers understand.
"""


def _validate_field(key: str, value: Any) -> Any:
    """Validate *value* for lower-case TOML *key*; return the value to store.

    Raises :class:`ValueError` on an unknown key or a wrongly-typed value.
    ``size`` accepts hex/decimal string spellings (``"0x2A"``) and coerces
    them to int; ``blocker_delta`` coerces the same way when parseable and
    passes other spellings through (the merge layer treats them as unknown).
    Callers may pass mixed-case keys; they are normalized to lower-case for
    the type table (stored keys are always lower-case).
    """
    key = key.lower()
    if key.upper() not in METADATA_FIELDS:
        raise ValueError(
            f"unknown metadata field {key!r} (expected one of {sorted(METADATA_FIELDS)})"
        )
    if key == "size":
        if isinstance(value, bool):
            raise ValueError(f"size must be an int, got {value!r}")
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value.strip(), 0)
            except ValueError:
                raise ValueError(f"size must be an int, got {value!r}") from None
        raise ValueError(f"size must be an int, got {value!r}")
    if key == "blocker_delta" and isinstance(value, str):
        with contextlib.suppress(ValueError):
            return int(value.strip(), 0)
        return value
    want = _FIELD_TYPES.get(key)
    if want is not None and not isinstance(value, want):
        raise ValueError(f"{key} must be {want}, got {type(value).__name__}")
    return value


def toml_safe(value: Any) -> Any:
    """Strip control characters from strings before TOML serialization.

    tomlkit>=0.15 emits some controls (e.g. ESC) as ``\\e``, which is not
    valid TOML and fails the next parse — a Ghidra comment or note carrying
    one would corrupt the whole metadata file.  Tab/newline survive (valid
    TOML escapes); other C0/C1 controls are dropped.
    """
    if not isinstance(value, str):
        return value
    return "".join(ch for ch in value if ord(ch) >= 0x20 or ch in ("\t", "\n"))


def _set_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Set one field for *(module, va)* in the metadata.  **Private** — use
    :func:`update_field` or :func:`update_source_status` instead.

    Writes directly to ``directory / rebrew-functions.toml``.  No walk-up.
    Uses in-place ``tomlkit`` editing to preserve formatting and comments.
    """
    _require_module(module)
    path = (directory / METADATA_FILENAME).resolve()

    with metadata_write_lock(directory, METADATA_FILENAME):
        doc = load_toml_for_write(path, "metadata")
        toml_key = resolve_metadata_key(doc, module, va)

        if toml_key not in doc:
            doc[toml_key] = tomlkit.table()

        # Same-value short-circuit (mirrors set_fields / update_statuses_batch):
        # a retry that re-sets the stored value must not rewrite the TOML.
        safe = toml_safe(value)
        entry = doc[toml_key]
        if isinstance(entry, dict) and entry.get(key) == safe:
            return

        entry[key] = safe
        atomic_write_locked(path, tomlkit.dumps(doc))
        pop_metadata_doc_cache(_metadata_cache, path)


def set_fields(directory: Path, va: int, fields: dict[str, Any], module: str) -> None:
    """Write several fields for *(module, va)* in a single read-modify-write.

    Batches what would otherwise be N full TOML rewrites.  Skips fields whose
    value is unchanged.  Prefer :func:`update_field` for one key, or
    :func:`update_source_status` for STATUS; use this when several non-STATUS
    fields must land in one atomic write (e.g. ``blocker`` + ``blocker_delta``).
    """
    if not fields:
        return
    _require_module(module)
    path = (directory / METADATA_FILENAME).resolve()

    with metadata_write_lock(directory, METADATA_FILENAME):
        doc = load_toml_for_write(path, "metadata")
        doc_dict = typing.cast(dict[str, Any], doc)
        toml_key = resolve_metadata_key(doc_dict, module, va)
        if toml_key not in doc_dict:
            doc_dict[toml_key] = tomlkit.table()
        entry = typing.cast(dict[str, Any], doc_dict[toml_key])

        changed = False
        for key, value in fields.items():
            key = key.lower()
            if key == "status":
                raise ValueError(
                    "Use update_source_status() for STATUS changes — it enforces promotion rules"
                )
            safe = toml_safe(_validate_field(key, value))
            if entry.get(key) != safe:
                entry[key] = safe
                changed = True
        if changed:
            atomic_write_locked(path, tomlkit.dumps(doc))
            pop_metadata_doc_cache(_metadata_cache, path)


def set_fields_batch(metadata_dir: Path, updates: list[dict[str, Any]]) -> int:
    """Set fields for many ``(module, va)`` entries in ONE TOML read-modify-write.

    ``verify --fix-sizes`` called ``_set_field`` per
    entry — each a full tomlkit parse + dumps + atomic write under the
    global lock.  Batches the I/O while keeping per-field idempotency.
    Rejects ``status`` (use :func:`update_statuses_batch`, which enforces
    promotion rules).  Returns the number of entries whose fields changed.
    """
    if not updates:
        return 0
    path = (metadata_dir / METADATA_FILENAME).resolve()
    changed_entries = 0
    with metadata_write_lock(metadata_dir, METADATA_FILENAME):
        doc = load_toml_for_write(path, "metadata")
        doc_dict = typing.cast(dict[str, Any], doc)
        key_index = build_metadata_key_index(doc_dict)
        for u in updates:
            module = u.get("module") or ""
            if not module:
                continue
            va = u.get("va")
            if va is None:
                continue
            va_int = int(va)
            toml_key = resolve_metadata_key(doc_dict, module, va_int, index=key_index)
            if toml_key not in doc_dict:
                doc_dict[toml_key] = tomlkit.table()
                key_index[(module, va_int)] = toml_key
            entry = typing.cast(dict[str, Any], doc_dict[toml_key])
            changed = False
            for key, value in (u.get("fields") or {}).items():
                key = key.lower()
                if key == "status":
                    raise ValueError("Use update_statuses_batch() for STATUS changes")
                safe = toml_safe(_validate_field(key, value))
                if entry.get(key) != safe:
                    entry[key] = safe
                    changed = True
            if changed:
                changed_entries += 1
        if changed_entries:
            atomic_write_locked(path, tomlkit.dumps(doc))
        pop_metadata_doc_cache(_metadata_cache, path)
    return changed_entries


def remove_fields_batch(metadata_dir: Path, updates: list[dict[str, Any]]) -> int:
    """Drop named fields from many ``(module, va)`` entries in one TOML rewrite.

    Sibling of :func:`set_fields_batch` for bulk deletes (``lint --fix`` W029
    dropping redundant per-function ``cflags``).  Rejects ``status`` (use
    :func:`update_statuses_batch`).  Returns the number of entries that lost
    at least one named field.  Missing entries / missing keys are no-ops.
    """
    if not updates:
        return 0
    path = (metadata_dir / METADATA_FILENAME).resolve()
    if not path.exists():
        return 0
    changed_entries = 0
    with metadata_write_lock(metadata_dir, METADATA_FILENAME):
        doc = load_toml_for_write(path, "metadata")
        doc_dict = typing.cast(dict[str, Any], doc)
        key_index = build_metadata_key_index(doc_dict)
        for u in updates:
            module = u.get("module") or ""
            if not module:
                continue
            va = u.get("va")
            if va is None:
                continue
            keys = u.get("keys") or ()
            if not keys:
                continue
            toml_key = resolve_metadata_key(doc_dict, str(module), int(va), index=key_index)
            if toml_key not in doc_dict:
                continue
            entry = typing.cast(dict[str, Any], doc_dict[toml_key])
            changed = False
            for key in keys:
                key = key.lower() if isinstance(key, str) else key
                if key == "status":
                    raise ValueError("Cannot delete STATUS directly")
                if key in entry:
                    del entry[key]
                    changed = True
            if changed:
                changed_entries += 1
        if changed_entries:
            atomic_write_locked(path, tomlkit.dumps(doc))
            pop_metadata_doc_cache(_metadata_cache, path)
    return changed_entries


def delete_entries_batch(metadata_dir: Path, targets: list[tuple[str, int]]) -> int:
    """Drop whole ``(module, va)`` entries in one TOML rewrite.

    Sibling of :func:`remove_fields_batch` for bulk entry deletes (orphan
    pruning: metadata blocks whose VA has no source annotation).  Returns the
    number of entries removed.  Missing entries are no-ops.  Only touches the
    metadata file — never a source file.
    """
    if not targets:
        return 0
    path = (metadata_dir / METADATA_FILENAME).resolve()
    if not path.exists():
        return 0
    removed = 0
    with metadata_write_lock(metadata_dir, METADATA_FILENAME):
        doc = load_toml_for_write(path, "metadata")
        doc_dict = typing.cast(dict[str, Any], doc)
        key_index = build_metadata_key_index(doc_dict)
        for module, va in targets:
            if not module:
                continue
            va_int = int(va)
            toml_key = resolve_metadata_key(doc_dict, str(module), va_int, index=key_index)
            if toml_key not in doc_dict:
                continue
            del doc_dict[toml_key]
            key_index.pop((str(module), va_int), None)
            removed += 1
        if removed:
            atomic_write_locked(path, tomlkit.dumps(doc))
            pop_metadata_doc_cache(_metadata_cache, path)
    return removed


def _mutate_entry_doc(
    directory: Path,
    va: int,
    module: str,
    mutate: Callable[[dict[str, Any], str], bool],
) -> bool:
    """Apply *mutate*(doc_dict, toml_key) to the entry for *(module, va)*.

    Opens ``directory / rebrew-functions.toml`` under the metadata write lock,
    hands the parsed document and the qualified key to *mutate*, and writes
    the document back only when *mutate* returns True.  No walk-up.
    Returns True if the file was modified.
    """
    path = (directory / METADATA_FILENAME).resolve()
    _require_module(module)

    with metadata_write_lock(directory, METADATA_FILENAME):
        doc = load_toml_for_write(path, "metadata")
        if not doc:
            return False

        # Use dict access for type checking on tomlkit Container
        doc_dict = typing.cast(dict[str, Any], doc)
        toml_key = resolve_metadata_key(doc_dict, module, va)
        if toml_key not in doc_dict:
            return False
        if not mutate(doc_dict, toml_key):
            return False
        atomic_write_locked(path, tomlkit.dumps(doc))
        pop_metadata_doc_cache(_metadata_cache, path)
        return True


def _delete_field(directory: Path, va: int, key: str, module: str) -> bool:
    """Remove *key* from the metadata entry for *(module, va)*.  **Private** —
    use :func:`remove_field` instead.

    Reads/writes directly at ``directory / rebrew-functions.toml``.  No walk-up.
    Returns True if removed.
    """

    def _drop(doc_dict: dict[str, Any], toml_key: str) -> bool:
        entry = typing.cast(dict[str, Any], doc_dict[toml_key])
        if key in entry:
            del entry[key]
            return True
        return False

    return _mutate_entry_doc(directory, va, module, _drop)


def delete_metadata_entry(directory: Path, va: int, module: str) -> bool:
    """Remove the entire metadata entry for *(module, va)*.

    Used when a function disappears from the target on re-discovery (e.g.
    ``rebrew intake`` stale-stub pruning after an enumeration fix).  Only
    touches the metadata file — never a source file.
    """

    def _drop_entry(doc_dict: dict[str, Any], toml_key: str) -> bool:
        del doc_dict[toml_key]
        return True

    return _mutate_entry_doc(directory, va, module, _drop_entry)


def update_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Central gatekeeper for all metadata field writes.

    All external callers must use this function (or :func:`update_source_status`
    for STATUS changes) to write to ``rebrew-functions.toml``.

    Business rules enforced here:
    - STATUS writes are blocked; callers must use :func:`update_source_status`.
    - *key* must be a known metadata field (:data:`METADATA_FIELDS`) of the
      right value type — unknown keys and mistyped values raise.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
        va: Virtual address integer.
        key: Lower-case TOML key (e.g. ``"cflags"``, ``"blocker"``).
        value: Value to write.
        module: Target module name (e.g. ``"SERVER"``).

    Raises:
        ValueError: If *key* is ``"status"`` — use :func:`update_source_status`.
        ValueError: If *key* is unknown or *value* has the wrong type.

    """
    key = key.lower()
    if key == "status":
        raise ValueError(
            "Use update_source_status() for STATUS changes — it enforces promotion rules"
        )
    _set_field(directory, va, key, _validate_field(key, value), module=module)


def remove_field(directory: Path, va: int, key: str, module: str) -> bool:
    """Central gatekeeper for metadata field deletes.

    All external callers must use this function to remove fields from
    ``rebrew-functions.toml``.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
        va: Virtual address integer.
        key: Lower-case TOML key to remove.
        module: Target module name.

    Returns:
        True if the field was removed, False otherwise.

    Raises:
        ValueError: If *key* is ``"status"`` — cannot delete STATUS directly.

    """
    key = key.lower()
    if key == "status":
        raise ValueError("Cannot delete STATUS directly")
    if key not in {f.lower() for f in METADATA_FIELDS}:
        raise ValueError(
            f"unknown metadata field {key!r} (expected one of {sorted(METADATA_FIELDS)})"
        )
    return _delete_field(directory, va, key, module=module)


# ---------------------------------------------------------------------------
# Status promotion
# ---------------------------------------------------------------------------


#: Legacy / hand-edited spellings normalized by :func:`canonical_status`.
#: Catalog/grid already treats ``NEAR_MATCH`` as ``NEAR_MATCHING``; without
#: this map a legacy TOML value is valid to the grid but rejected by
#: ``KNOWN_STATUSES`` / lint E004.
_STATUS_ALIASES: dict[str, str] = {
    "NEAR_MATCH": "NEAR_MATCHING",
}


#: Canonical STATUS spelling: every persisted/compared status is upper-case.
#: The validation layer (``metadata_model``) accepts any case via ``.upper()``,
#: and hand-edited TOML or library-header KV lines may carry lower-case values;
#: normalizing at every read/write keeps the exact-case consumers (dashboards,
#: promotion policy) consistent instead of silently dropping such entries.
def canonical_status(status: str) -> str:
    """Return *status* in its canonical (upper-case, trimmed) spelling."""
    folded = status.strip().upper()
    return _STATUS_ALIASES.get(folded, folded)


def is_status_sticky(current_status: str) -> bool:
    """True when *current_status* should never be demoted by test/verify.

    PROVEN is a post-verify promotion from ``rebrew prove`` — byte-level
    comparison cannot reproduce it, so test/verify must preserve it.
    Comparison is case-insensitive so a hand-edited ``"proven"`` entry
    keeps its stickiness.
    """
    return canonical_status(current_status) == "PROVEN"


def is_status_parked(current_status: str) -> bool:
    """True when *current_status* is user-parked (``SKIP``) and must not change.

    Unlike PROVEN (which yields to a real EXACT/RELOC byte match), SKIP is an
    intentional "don't touch" parking classification — test/verify must not
    overwrite it without ``force=True``.
    """
    return canonical_status(current_status) == "SKIP"


def should_promote_status(current_status: str, new_status: str) -> bool:
    """True when *new_status* should overwrite *current_status* in metadata.

    Single canonical promotion decision, enforced both by ``rebrew test`` /
    ``rebrew verify`` call sites and inside :func:`update_statuses_batch`
    (the writer layer).  Refuses to promote when the current status is
    sticky (PROVEN), parked (SKIP), when a STUB's placeholder size-mismatch
    would erase the user's STUB classification, or when the status did not
    change.  Both sides are compared case-insensitively.

    The one exception to PROVEN stickiness is a byte match: EXACT/RELOC mean
    the compiler reproduced the target's bytes, which is strictly stronger
    than the semantic equivalence PROVEN records.  Without it a function that
    finally byte-matches would keep reporting PROVEN and the win would never
    be recorded.  SKIP has no such carve-out — unparking requires force.
    """
    current = canonical_status(current_status)
    new = canonical_status(new_status)
    if is_status_parked(current):
        return False
    if is_status_sticky(current):
        return new in ("EXACT", "RELOC")
    if current == "STUB" and new in ("SIZE_MISMATCH", "MISSING_SIZE"):
        # A documented STUB (typically blocker-documented) must not be
        # demoted by a placeholder size-mismatch or a missing-size
        # evaluation — that would erase the user's classification.
        return False
    return current != new


def update_source_status(
    metadata_dir: Path,
    new_status: str,
    module: str,
    va: int,
    *,
    clear_blockers: bool = True,
    force: bool = False,
    updated_by: str = "",
) -> None:
    """Write STATUS for (module, va) to the metadata; never touches the .c file.

    This is the single canonical place to promote a function's STATUS.
    ``rebrew test`` calls it directly; ``rebrew verify`` goes through
    :func:`update_statuses_batch` (same promotion rules, batched).

    PROVEN is a post-verify promotion from ``rebrew prove`` and is never
    silently demoted.  Callers that need to override this must pass
    ``force=True``.

    Uses a single read-modify-write cycle instead of separate get/set/delete
    calls to minimise I/O.  Atomicity is provided by ``atomic_write_locked``.

    Args:
        metadata_dir: The metadata root directory (``cfg.metadata_dir``).
        new_status: New status string (e.g. ``EXACT``, ``RELOC``, ``NEAR_MATCHING``).
        module: Target module name from the annotation (e.g. ``NP``).
        va: Virtual address of the function.
        clear_blockers: If ``True`` (default), remove ``blocker`` and
            ``blocker_delta`` from the metadata entry (correct for EXACT/RELOC).
            Pass ``False`` when demoting to NEAR_MATCHING to preserve user-set blockers.
        force: If ``True``, allow demotion from PROVEN.  Default ``False``.
        updated_by: Provenance tag for the write (``test``/``verify``/``prove``/
            ``lint``/``binsync-import``/``intake``/``match``).  Recorded as
            ``updated_by`` with a UTC ``updated_at`` timestamp.

    Raises:
        ValueError: If *module* is empty — nothing would be written (the
            loader only reads qualified ``MODULE.0xVA`` keys).

    """
    _require_module(module)
    update_statuses_batch(
        metadata_dir,
        [
            {
                "module": module,
                "va": va,
                "new_status": new_status,
                "clear_blockers": clear_blockers,
                "force": force,
                "updated_by": updated_by,
            }
        ],
    )


def update_statuses_batch(metadata_dir: Path, updates: list[dict[str, Any]]) -> int:
    """Apply many STATUS updates in ONE TOML read-modify-write.

    ``verify``'s STATUS sync and ``test --all`` previously called
    ``update_source_status`` per entry — each a full tomlkit parse + dumps +
    atomic write serialized under the global lock.  Measured: 260 entries ≈
    9s, extrapolated ≈ 28 min at 3000 entries.  The
    promotion/stickiness rules are identical per entry; only the I/O is
    batched (one parse, N in-memory edits, one write).

    *updates*: list of dicts with keys ``module``, ``va``, ``new_status``
    and optional ``clear_blockers`` (default True), ``force`` (default
    False).  Returns the number of statuses actually changed.

    Each changed status passes through :func:`should_promote_status` —
    the single canonical promotion policy (PROVEN never silently demoted,
    SKIP never silently unparked, a documented STUB kept against placeholder
    size-mismatch verdicts).  ``force=True`` bypasses that policy for
    manual/repair writes.
    Same-status updates still fall through when they will clear blockers
    (the stale-blocker cleanup path).
    """
    if not updates:
        return 0
    path = (metadata_dir / METADATA_FILENAME).resolve()
    changed = 0
    with metadata_write_lock(metadata_dir, METADATA_FILENAME):
        # Single read for the whole batch
        doc = load_toml_for_write(path, "metadata")
        doc_dict = typing.cast(dict[str, Any], doc)
        key_index = build_metadata_key_index(doc_dict)

        for u in updates:
            module = u.get("module") or ""
            if not module:
                continue
            va = u.get("va")
            if va is None:
                continue
            if u.get("new_status") is None:
                continue
            try:
                new_status = canonical_status(str(u.get("new_status")))
            except (TypeError, ValueError, AttributeError):
                continue
            if not new_status:
                continue
            # Same gate as MetadataEntry.apply: refuse to persist a STATUS the
            # vocabulary does not know.  Without this, verify/test/lint could
            # write a typo that problems()/lint E004 then rejects.
            if new_status not in KNOWN_STATUSES:
                raise ValueError(
                    f"unknown STATUS {new_status!r} (expected one of {sorted(KNOWN_STATUSES)})"
                )
            va_int = int(va)
            toml_key = resolve_metadata_key(doc_dict, module, va_int, index=key_index)
            if toml_key not in doc_dict:
                doc_dict[toml_key] = tomlkit.table()
                key_index[(module, va_int)] = toml_key
            entry = typing.cast(dict[str, Any], doc_dict[toml_key])

            clear_blockers = u.get("clear_blockers", True)
            force = u.get("force", False)

            # Idempotency guard — avoid a write when nothing changed
            current_status = canonical_status(str(entry.get("status", "")))
            current_blocker = entry.get("blocker", "")
            current_blocker_delta = entry.get("blocker_delta")
            if current_status == new_status and (
                not clear_blockers or (not current_blocker and current_blocker_delta is None)
            ):
                continue

            # Canonical promotion policy — only consulted for actual status
            # changes; same-status writes proceed so clear_blockers can
            # strip a stale blocker from an already-classified entry.
            if (
                current_status != new_status
                and not force
                and not should_promote_status(current_status, new_status)
            ):
                continue

            entry["status"] = new_status
            if clear_blockers:
                with contextlib.suppress(KeyError):
                    del entry["blocker"]
                with contextlib.suppress(KeyError):
                    del entry["blocker_delta"]
            updated_by = str(u.get("updated_by") or "")
            if updated_by:
                entry["updated_by"] = updated_by
                entry["updated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
            changed += 1

        # Single write for the whole batch
        if changed:
            atomic_write_locked(path, tomlkit.dumps(doc))
        pop_metadata_doc_cache(_metadata_cache, path)
    return changed


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
        directory: The metadata root directory (``cfg.metadata_dir``).

    Returns:
        The mutated *ann* (same object, for chaining convenience).

    """
    module: str = getattr(ann, "module", None) or ""
    if not module:
        return ann
    entry = get_entry(directory, ann.va, module=module)
    if not entry:
        return ann
    apply_metadata_entry(ann, entry)
    return ann


def apply_metadata_entry(ann: Annotation, entry: dict[str, Any]) -> None:
    """Overlay one ``{field: value}`` metadata *entry* onto *ann* in place.

    Shared by :func:`merge_into_annotation` (single function) and
    :func:`rebrew.annotation.parse_c_file_text` (whole-file batches, which
    load the metadata once and apply it per function instead of re-loading
    the TOML for every annotation — the per-function hot path).
    """
    if "size" in entry:
        with contextlib.suppress(ValueError, TypeError):
            ann.size = as_metadata_int(entry["size"])

    if "cflags" in entry:
        ann.cflags = str(entry["cflags"])

    if "toolchain" in entry:
        ann.toolchain = str(entry["toolchain"])

    if "status" in entry:
        ann.status = canonical_status(str(entry["status"]))

    if "blocker" in entry:
        ann.blocker = str(entry["blocker"])

    if "blocker_delta" in entry:
        raw = entry["blocker_delta"]
        try:
            ann.blocker_delta = as_metadata_int(raw)
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

    if "locals" in entry:
        raw_locals = entry["locals"]
        if isinstance(raw_locals, dict):
            ann.locals = {str(k): v for k, v in raw_locals.items()}

    if "comments" in entry:
        raw_comments = entry["comments"]
        if isinstance(raw_comments, dict):
            ann.comments = {str(k): v for k, v in raw_comments.items()}

    if "source" in entry:
        ann.source = str(entry["source"])

    if "prove_constraints" in entry:
        raw_pc = entry["prove_constraints"]
        if isinstance(raw_pc, dict):
            ann.prove_constraints = dict(raw_pc)

    if "updated_by" in entry:
        ann.updated_by = str(entry["updated_by"])

    if "updated_at" in entry:
        ann.updated_at = str(entry["updated_at"])


# ---------------------------------------------------------------------------
# Typed facade
# ---------------------------------------------------------------------------
#
# The typed entry layer is ``metadata_model.MetadataEntry`` (used by
# annotation.py); the earlier ``FunctionMetadata``/``load_entry``/``save_entry``/
# ``field_kind`` facade was deleted — it had drifted from the live model
# (case-sensitive vs upper() status checks) and only its tests referenced it.
# ``KNOWN_STATUSES`` / ``MATCHED_STATUSES`` are owned by
# :mod:`rebrew.workspace.status` (stdlib-light vocabulary).  Import the
# vocabulary from there (or ``rebrew.workspace``); this module re-exports
# them only so metadata *writers* that already import ``rebrew.metadata``
# need not take a second import.  ``coerce_metadata_value`` below remains live:
# metadata_model validates against KNOWN_STATUSES, and lint --fix coerces
# values through coerce_metadata_value.

#: Blocker prefix marking a function whose residual byte delta is
#: register-only ("effective match") — the GA ceiling.  Written by
#: ``rebrew match`` after the GA exhausts on such a delta; GA batch
#: selectors skip these entries while ``rebrew prove --all --ceiling``
#: targets exactly them (the sanctioned next step to PROVEN).
GA_CEILING_PREFIX = "GA_CEILING:"


def as_metadata_int(value: Any) -> int:
    """Coerce *value* to int for ``size`` / ``blocker_delta``.

    Accepts plain ``int`` (not ``bool``), decimal/hex strings, and finite
    integral floats (``12.0``).  Non-integral floats (``12.9``) and
    non-finite values are rejected: bare ``int()`` would truncate toward
    zero or raise ``OverflowError`` on ``±inf``, inventing a wrong size
    or crashing a merge that only catches ``ValueError``.
    """
    if isinstance(value, bool):
        raise ValueError(f"expected int, got {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise ValueError(f"expected int, got {value!r}")
        return int(value)
    if isinstance(value, str):
        return int(value.strip(), 0)
    raise ValueError(f"expected int, got {value!r}")


def coerce_metadata_value(key: str, value: Any) -> Any:
    """Coerce *value* to the canonical type for metadata field *key* (lower-case TOML key).

    Only fields with a single unambiguous type are coerced; everything else
    passes through untouched.  String spellings follow ``metadata_model._coerce``:
    both decimal (``"42"``) and hex (``"0x2A"``) are accepted.
    """
    if key in ("size", "blocker_delta") and not isinstance(value, int):
        with contextlib.suppress(ValueError, TypeError):
            return as_metadata_int(value)
    return value


# ---------------------------------------------------------------------------
# Per-library toolchain/flags overrides (rebrew-libraries.toml)
# ---------------------------------------------------------------------------
#
# A library is a source-directory subtree whose functions were all built with
# the same compiler + flags (the normal case — one codebase, one toolchain).
# Declaring a ``rebrew-libraries.toml`` at the library root applies to every
# function under it, instead of tagging each function's rebrew-functions.toml.
# Discovery is walk-up (nearest ancestor file wins), unlike the function
# metadata which lives only at cfg.metadata_dir.


#: File name of the per-library override (looked up by walking up from the
#: function's directory toward the project root).
LIBRARY_METADATA_FILE = "rebrew-libraries.toml"


class LibraryOverrideError(RebrewError, RuntimeError):
    """A declared library override is malformed (bad TOML / bad fields)."""


@dataclass(frozen=True)
class LibraryOverride:
    """Effective per-library compile override found for a source directory.

    Empty fields mean "inherit" (project default or a wider library file);
    *presets* lists any known-library defaults that were merged in.
    """

    path: Path  # the rebrew-libraries.toml that matched (nearest ancestor)
    toolchain: str = ""  # override compiler profile, e.g. "msvc-6.0"
    cflags: str = ""  # override flags, e.g. "/O2 /Gd /MT"
    library: str = ""  # declared library name (may drive presets)
    presets: tuple[str, ...] = ()  # preset names that filled empty fields


#: Known shipped-library build settings.  ``library = "<name>"`` in a
#: rebrew-libraries.toml fills the *missing* fields from this table — rebrew
#: knows what the shipped runtimes were built with (the standard MSVC /MT
#: vs /MD shapes, the 16-bit models, Borland/Watcom defaults), so users
#: declare ``library = "msvcrt-static"`` instead of handwriting flags.
#: This is the packaged base; ``rebrew.library_presets`` entry-point
#: providers extend/override it per name (see :func:`all_library_presets`).
LIBRARY_PRESETS: dict[str, dict[str, str]] = {
    # MSVC shipped CRT: libc.lib (static single-thread), libcmt.lib (static
    # multi-thread = /MT), msvcrt.lib (dynamic = /MD) — the classic /O2 /Gd
    "msvcrt-static": {"toolchain": "msvc-6.0", "cflags": "/O2 /Gd /MT"},
    "msvcrt-dynamic": {"toolchain": "msvc-6.0", "cflags": "/O2 /Gd /MD"},
    "msvc16-runtime": {"toolchain": "msvc-1.52", "cflags": "/O1 /Gd"},
    "borland-runtime": {"toolchain": "borland-3.1", "cflags": "-O2"},
    "watcom-runtime": {"toolchain": "watcom-2.0-win32", "cflags": "-ot"},
}

#: setuptools entry-point group whose members register library presets.  A
#: member is a zero-arg callable returning ``dict[name, {toolchain, cflags}]``
#: — e.g. a toolchain plugin declaring "this shipped library is built with
#: my compiler".  Presets are tuning data: a provider may override a
#: packaged name (the plugin's knowledge wins).
LIBRARY_PRESET_ENTRY_POINT_GROUP = "rebrew.library_presets"


def _merged_library_presets() -> dict[str, dict[str, str]]:
    """Packaged presets + ``rebrew.library_presets`` providers (override).

    An optional registry: a broken provider is skipped with a warning (the
    packaged presets stand) instead of bricking metadata resolution."""
    from rebrew.registry import iter_optional_provider_dicts

    presets = dict(LIBRARY_PRESETS)
    for reg, provided in iter_optional_provider_dicts(
        LIBRARY_PRESET_ENTRY_POINT_GROUP, logger, expected="dict[name, {toolchain, cflags}]"
    ):
        for name, fields in provided.items():
            if not isinstance(fields, dict):
                logger.warning(
                    "skipping %s provider %r: preset %r must be a table, got %s",
                    reg.group,
                    reg.name,
                    name,
                    type(fields).__name__,
                )
                continue
            presets[name] = {str(k): str(v) for k, v in fields.items()}
    return presets


_LIBRARY_PRESETS_ALL: dict[str, dict[str, str]] = _merged_library_presets()


def refresh_library_presets() -> dict[str, dict[str, str]]:
    """Re-run discovery and refresh the :data:`_LIBRARY_PRESETS_ALL` snapshot.

    Long-lived processes can pick up library-preset plugins installed after
    startup without a restart."""
    global _LIBRARY_PRESETS_ALL

    _LIBRARY_PRESETS_ALL = _merged_library_presets()
    return _LIBRARY_PRESETS_ALL


def all_library_presets() -> dict[str, dict[str, str]]:
    """The full library-preset registry (packaged + plugin-provided)."""
    return _LIBRARY_PRESETS_ALL


#: Process-level memo for :func:`parse_library_metadata`, keyed by file path.
#: Entries hold ``((mtime_ns, size), parsed_dict)`` so a repeated resolution
#: skips the read+parse while any rewrite (new mtime/size) re-parses.  Cleared
#: wholesale when full — library files per project are few.
#: Guarded: ``rebrew verify -j N`` resolves overrides from worker threads; the
#: walk cache's check-then-``del`` and the meta cache's clear-then-store are
#: multi-step mutations on shared dicts.
_LIBRARY_META_CACHE: dict[str, tuple[tuple[int, int], dict[str, Any]]] = {}
_LIBRARY_META_CACHE_MAX = 64
_LIBRARY_CACHE_LOCK = threading.Lock()


def parse_library_metadata(path: Path) -> dict[str, Any]:
    """Parse a ``rebrew-libraries.toml`` into a plain dict.

    Returns ``{}`` for an absent file.  Raises :class:`LibraryOverrideError`
    on malformed TOML or a non-dict document.

    Memoized per process behind an ``mtime_ns``+``size`` stat guard:
    override resolution runs once per function (verify's cache-hit check,
    per-entry save, and every compile site re-resolve), so a batch over a
    library directory re-read and re-parsed the same small TOML thousands
    of times per run.  The stat guard keeps edits visible — a rewritten
    file has a new fingerprint and is parsed fresh (the resolution-confluence
    property tests rely on this).
    """
    key = str(path)
    try:
        st = path.stat()
    except OSError:
        with _LIBRARY_CACHE_LOCK:
            _LIBRARY_META_CACHE.pop(key, None)
        return {}
    fp = (st.st_mtime_ns, st.st_size)
    with _LIBRARY_CACHE_LOCK:
        cached = _LIBRARY_META_CACHE.get(key)
        if cached is not None and cached[0] == fp:
            return dict(cached[1])
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise LibraryOverrideError(f"bad {LIBRARY_METADATA_FILE} at {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise LibraryOverrideError(f"{path} must be a TOML table")
    with _LIBRARY_CACHE_LOCK:
        # Re-check: another worker may have filled it while we parsed.
        cached = _LIBRARY_META_CACHE.get(key)
        if cached is not None and cached[0] == fp:
            return dict(cached[1])
        if len(_LIBRARY_META_CACHE) >= _LIBRARY_META_CACHE_MAX:
            _LIBRARY_META_CACHE.clear()
        _LIBRARY_META_CACHE[key] = (fp, raw)
    return dict(raw)


def apply_library_presets(meta: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Fill missing toolchain/cflags from the known-library presets.

    Returns ``(merged, preset_names_used)``.  Explicit fields always win.
    The preset table is the merged registry (:func:`all_library_presets`),
    so plugin-provided presets apply here too."""
    name = str(meta.get("library") or "").strip()
    preset = _LIBRARY_PRESETS_ALL.get(name, {})
    if not preset:
        return meta, ()
    merged = {**meta}
    for key, value in preset.items():
        if not str(merged.get(key) or "").strip():
            merged[key] = value
    return merged, (name,)


_LIBRARY_WALK_CACHE: dict[tuple[str, str], Path | None] = {}
_LIBRARY_WALK_CACHE_MAX = 256


def clear_library_override_cache() -> None:
    """Forget cached ``rebrew-libraries.toml`` walk + parse results (call after writes)."""
    with _LIBRARY_CACHE_LOCK:
        _LIBRARY_WALK_CACHE.clear()
        _LIBRARY_META_CACHE.clear()


def find_library_override(
    start_dir: str | Path, root: str | Path | None = None
) -> LibraryOverride | None:
    """Find the nearest ``rebrew-libraries.toml`` by walking up from *start_dir*.

    The walk stops at *root* (project root — ``cfg.root``) inclusive.  Returns
    the merged override (explicit fields + known-library presets) or ``None``
    when no library file exists on the path.

    The located path is memoized per ``(start_dir, root)`` so bulk callers
    (verify/match over thousands of functions) pay the directory walk once
    on a hit; misses are never stored so a newly created library file is
    visible on the next call without requiring
    :func:`clear_library_override_cache`.  Field values still re-parse
    through :func:`parse_library_metadata`, whose mtime/size validation
    picks up content edits.  Cap the memo so a long-lived process over
    many library trees cannot grow the dict without bound."""
    cur = Path(start_dir).resolve()
    root_p = Path(root).resolve() if root is not None else None
    key = (str(cur), str(root_p) if root_p is not None else "")

    with _LIBRARY_CACHE_LOCK:
        cached = _LIBRARY_WALK_CACHE.get(key)
        present = key in _LIBRARY_WALK_CACHE

    # Stale-path check outside the lock so a deleted library file does not
    # serialize every worker on a filesystem round-trip.
    if present and cached is not None and not cached.exists():
        with _LIBRARY_CACHE_LOCK:
            # pop, not del: concurrent workers can both observe a deleted path
            # and race the invalidate — del would KeyError the loser.
            _LIBRARY_WALK_CACHE.pop(key, None)
        present = False
        cached = None

    # Drop legacy negative entries (None was cached before positive-only
    # memoization): a newly created rebrew-libraries.toml must not stay
    # invisible for the process lifetime.
    if present and cached is None:
        with _LIBRARY_CACHE_LOCK:
            _LIBRARY_WALK_CACHE.pop(key, None)
        present = False

    if not present:
        found: Path | None = None
        walk = cur
        while True:
            candidate = walk / LIBRARY_METADATA_FILE
            if candidate.exists():
                found = candidate
                break
            if root_p is not None and walk == root_p:
                break
            if walk.parent == walk:
                break
            walk = walk.parent
        # Positive-only: never memoize a miss.  Caching None hid a library
        # file created later in the same process (hand-edit, sibling tool,
        # or a writer that skipped clear_library_override_cache) and served
        # project defaults until restart — wrong toolchain/cflags.
        if found is not None:
            with _LIBRARY_CACHE_LOCK:
                if key not in _LIBRARY_WALK_CACHE:
                    if len(_LIBRARY_WALK_CACHE) >= _LIBRARY_WALK_CACHE_MAX:
                        _LIBRARY_WALK_CACHE.clear()
                    _LIBRARY_WALK_CACHE[key] = found
                cached = _LIBRARY_WALK_CACHE[key]
        else:
            cached = None

    if cached is None:
        return None
    meta = parse_library_metadata(cached)
    merged, presets = apply_library_presets(meta)
    return LibraryOverride(
        path=cached,
        toolchain=str(merged.get("toolchain") or "").strip(),
        cflags=str(merged.get("cflags") or "").strip(),
        library=str(merged.get("library") or "").strip(),
        presets=presets,
    )
