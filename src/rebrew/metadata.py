"""metadata.py — Per-directory metadata store for rebrew.

Volatile annotation fields (STATUS, SIZE, CFLAGS, BLOCKER, NOTE, GHIDRA, …)
are stored in a single ``rebrew-function.toml`` metadata file at the
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

This allows a single ``rebrew-function.toml`` to hold metadata for **multiple
targets** (e.g. ``SERVER`` and ``CLIENT``) that share a directory or ``.c``
file — the full key is unambiguous even if two targets happen to have a
function at the same VA.  The format mirrors the ``// FUNCTION: SERVER
0x01006364`` marker.

Owned fields per entry::

    size, cflags, status, blocker, blocker_delta, note, ghidra,
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
a function's STATUS.  Both ``rebrew test`` and ``rebrew verify`` call this
function; it never touches the ``.c`` file.

Merge semantics
---------------
When a rebrew tool reads an ``Annotation`` from ``parse_c_file_multi()``, it
calls ``merge_into_annotation(ann, directory)`` which overlays *metadata* values
on top.  Metadata always wins for the fields it owns.  The legacy ``analysis``
field is mapped to ``note`` when the annotation has no explicit note.

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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from rebrew.utils import (
    atomic_write_text,
    build_metadata_doc,
    load_toml_for_write,
    parse_metadata_doc,
    qualified_key,
)

if TYPE_CHECKING:
    from rebrew.annotation import Annotation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory cache for load_metadata() — avoids re-parsing the same TOML file
# hundreds of times during batch operations (verify, status, merge).
# Keyed by resolved Path; invalidated by mtime_ns change or explicit clear.
# ---------------------------------------------------------------------------

_metadata_cache: dict[Path, tuple[int, dict[tuple[str, int], dict[str, Any]]]] = {}


def clear_metadata_cache() -> None:
    """Clear the in-memory metadata cache.

    Call between top-level CLI commands if running multiple in-process,
    or after writing metadata to ensure subsequent reads see fresh data.
    """
    _metadata_cache.clear()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

METADATA_FILENAME = "rebrew-function.toml"

# Canonical TOML key order when writing an entry; unlisted fields follow, in
# insertion order.  Mirrors ``data_metadata._CANONICAL_ORDER``.
_CANONICAL_ORDER = [
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
        # ORIGIN is derivable from the FUNCTION: marker module field.
        "SOURCE",
        "PROVE_CONSTRAINTS",
        # NOTE: SECTION is intentionally absent — it is owned by data_metadata.py
        # for DATA/GLOBAL annotations and must not be written to rebrew-function.toml.
    }
)

__all__ = [
    "METADATA_FILENAME",
    "METADATA_FIELDS",
    "KNOWN_STATUSES",
    "FILE_ONLY_KEYS",
    "LEGACY_KEYS",
    "FunctionMetadata",
    "clear_metadata_cache",
    "field_kind",
    "is_metadata_key",
    "metadata_path",
    "load_metadata",
    "save_metadata",
    "get_entry",
    "set_field",
    "update_field",
    "remove_field",
    "load_entry",
    "save_entry",
    "coerce_metadata_value",
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
        directory: The metadata root directory (``cfg.metadata_dir``).

    """
    return directory / METADATA_FILENAME


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


def load_metadata(directory: Path) -> dict[tuple[str, int], dict[str, Any]]:
    """Load ``rebrew-function.toml`` from *directory*.

    *directory* must be the metadata root (``cfg.metadata_dir``).  There is
    no walk-up — the file is expected at exactly ``directory / rebrew-function.toml``.

    Returns a mapping of ``{(module, va_int): {field_name: value}}``.
    Returns an empty dict if no metadata file is found or it cannot be parsed.

    Results are cached in-memory keyed by resolved path and file mtime.
    Call :func:`clear_metadata_cache` to force a re-read.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).

    """
    # Resolve so cache keys are stable across relative/absolute call sites.
    path = (directory / METADATA_FILENAME).resolve()
    if not path.exists():
        return {}

    # Fast mtime-based cache check — avoids re-parsing the same TOML file
    # hundreds of times during batch operations (verify, status, match --all).
    try:
        current_mtime = path.stat().st_mtime_ns
    except OSError:
        current_mtime = 0
    cached = _metadata_cache.get(path)
    if cached is not None and cached[0] == current_mtime:
        return cached[1]

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — tomlkit raises various types
        logger.warning("Failed to parse metadata %s: %s", path, exc)
        return {}

    result = parse_metadata_doc(doc)
    _metadata_cache[path] = (current_mtime, result)
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
    path = (directory / METADATA_FILENAME).resolve()
    doc = build_metadata_doc(data, _CANONICAL_ORDER)
    atomic_write_text(path, tomlkit.dumps(doc))
    _metadata_cache.pop(path, None)


# ---------------------------------------------------------------------------
# Granular read/write
# ---------------------------------------------------------------------------


def get_entry(directory: Path, va: int, module: str) -> dict[str, Any]:
    """Return metadata fields for *(module, va)* in *directory*.

    Returns an empty dict if not found.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
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
    path = (directory / METADATA_FILENAME).resolve()
    toml_key = qualified_key(module, va)

    doc = load_toml_for_write(path, "metadata")

    if toml_key not in doc:
        doc[toml_key] = tomlkit.table()

    doc[toml_key][key] = value  # type: ignore[index]
    atomic_write_text(path, tomlkit.dumps(doc))
    _metadata_cache.pop(path, None)


def _set_fields(directory: Path, va: int, fields: dict[str, Any], module: str) -> None:
    """Write several fields for *(module, va)* in a single read-modify-write.

    Batches what would otherwise be N full TOML rewrites (used by
    :func:`save_entry`).  Skips fields whose value is unchanged.  **Private** —
    use :func:`update_field` / :func:`update_source_status` instead.
    """
    if not fields:
        return
    path = (directory / METADATA_FILENAME).resolve()
    toml_key = qualified_key(module, va)

    doc = load_toml_for_write(path, "metadata")
    doc_dict = typing.cast(dict[str, Any], doc)
    if toml_key not in doc_dict:
        doc_dict[toml_key] = tomlkit.table()
    entry = typing.cast(dict[str, Any], doc_dict[toml_key])

    changed = False
    for key, value in fields.items():
        if key == "status":
            raise ValueError(
                "Use update_source_status() for STATUS changes — it enforces promotion rules"
            )
        if entry.get(key) != value:
            entry[key] = value
            changed = True
    if changed:
        atomic_write_text(path, tomlkit.dumps(doc))
        _metadata_cache.pop(path, None)


def _delete_field(directory: Path, va: int, key: str, module: str) -> bool:
    """Remove *key* from the metadata entry for *(module, va)*.  **Private** —
    use :func:`remove_field` instead.

    Reads/writes directly at ``directory / rebrew-function.toml``.  No walk-up.
    Returns True if removed.
    """
    path = (directory / METADATA_FILENAME).resolve()
    if not path.exists():
        return False
    toml_key = qualified_key(module, va)

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
        _metadata_cache.pop(path, None)
        return True
    return False


def update_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Central gatekeeper for all metadata field writes.

    All external callers must use this function (or :func:`update_source_status`
    for STATUS changes) to write to ``rebrew-function.toml``.

    Business rules enforced here:
    - STATUS writes are blocked; callers must use :func:`update_source_status`.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``).
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
        directory: The metadata root directory (``cfg.metadata_dir``).
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
        directory: The metadata root directory (``cfg.metadata_dir``).
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
    ``rebrew test`` and ``rebrew verify`` call this function (always-on).

    PROVEN is a post-verify promotion from ``rebrew prove`` and is never
    silently demoted.  Callers that need to override this must pass
    ``force=True``.

    Uses a single read-modify-write cycle instead of separate get/set/delete
    calls to minimise I/O.  Atomicity is provided by ``atomic_write_text``.

    Args:
        metadata_dir: The metadata root directory (``cfg.metadata_dir``).
        new_status: New status string (e.g. ``EXACT``, ``RELOC``, ``NEAR_MATCHING``).
        module: Target module name from the annotation (e.g. ``NP``).
        va: Virtual address of the function.
        clear_blockers: If ``True`` (default), remove ``blocker`` and
            ``blocker_delta`` from the metadata entry (correct for EXACT/RELOC).
            Pass ``False`` when demoting to NEAR_MATCHING to preserve user-set blockers.
        force: If ``True``, allow demotion from PROVEN.  Default ``False``.

    """
    if not module:
        return

    path = (metadata_dir / METADATA_FILENAME).resolve()
    toml_key = qualified_key(module, va)

    # Single read
    doc = load_toml_for_write(path, "metadata")

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
    from rebrew.cli import is_status_sticky

    if is_status_sticky(current_status) and new_status != current_status and not force:
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
    _metadata_cache.pop(path, None)


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

    if "prove_constraints" in entry:
        raw_pc = entry["prove_constraints"]
        if isinstance(raw_pc, dict):
            ann.prove_constraints = dict(raw_pc)

    return ann


# ---------------------------------------------------------------------------
# Typed facade
# ---------------------------------------------------------------------------
#
# A thin typed layer over the raw ``{(module, va): {field: value}}`` dict
# API above.  ``FunctionMetadata`` gives each entry concrete, validated
# fields, and :func:`field_kind` is the single routing table for the
# "file-only vs metadata-only" distinction that historically caused the
# lint --fix STATUS crash and the add-module tomlkit persistence bug.
#
# Routing rules:
# - "metadata"  → owned by rebrew-function.toml (writing inline fires W019).
# - "file"      → must stay in the .c marker/comment block.
# - "legacy"    → deprecated inline keys metadata does NOT own: ORIGIN is
#                 derivable from the marker module, SECTION belongs to
#                 rebrew-data.toml.  Inline → W019, but never stored here.
# - "unknown"   → not a known annotation key.
#
# The status vocabulary is deliberately the annotation-level set; the raw
# :func:`update_source_status` gatekeeper stays permissive because test/verify
# also persist operational statuses (COMPILE_ERROR, SIZE_MISMATCH, …) that are
# not annotation statuses.

KNOWN_STATUSES: frozenset[str] = frozenset(
    {"STUB", "EXACT", "RELOC", "PROVEN", "NEAR_MATCHING", "SKIP"}
)

FILE_ONLY_KEYS: frozenset[str] = frozenset({"MARKER", "VA", "MODULE", "SYMBOL"})

LEGACY_KEYS: frozenset[str] = frozenset({"ORIGIN", "SECTION"})


def field_kind(key: str) -> str:
    """Classify an annotation key: ``"metadata"`` | ``"file"`` | ``"legacy"`` | ``"unknown"``."""
    upper = key.upper()
    if upper in METADATA_FIELDS:
        return "metadata"
    if upper in FILE_ONLY_KEYS:
        return "file"
    if upper in LEGACY_KEYS:
        return "legacy"
    return "unknown"


def coerce_metadata_value(key: str, value: Any) -> Any:
    """Coerce *value* to the canonical type for metadata field *key* (lower-case TOML key).

    Only fields with a single unambiguous type are coerced; everything else
    passes through untouched.
    """
    if key in ("size", "blocker_delta") and not isinstance(value, int):
        with contextlib.suppress(ValueError, TypeError):
            return int(value)
    return value


# Lower-case TOML key per dataclass attribute (everything except globals_list).
_TOML_FIELD_NAMES: dict[str, str] = {
    "globals_list": "globals",
}


@dataclass
class FunctionMetadata:
    """Typed view of one ``rebrew-function.toml`` entry for ``(module, va)``.

    ``from_entry`` / ``to_entry`` map to the raw TOML entry dict; ``validate``
    reports type/domain errors; :func:`save_entry` refuses invalid entries.
    None-valued fields are absent from the store (not written/cleared).
    """

    module: str
    va: int
    status: str | None = None
    size: int | None = None
    cflags: str | None = None
    blocker: str | None = None
    blocker_delta: int | None = None
    note: str | None = None
    ghidra: str | None = None
    analysis: str | None = None
    skip: bool | str | None = None
    globals_list: list[str] | None = None
    source: str | None = None
    prove_constraints: dict[str, Any] | None = None

    @classmethod
    def from_entry(cls, module: str, va: int, entry: dict[str, Any]) -> FunctionMetadata:
        """Build a typed entry from a raw metadata entry dict (lower-case keys)."""
        kwargs: dict[str, Any] = {"module": module, "va": va}
        for attr, toml_key in _TOML_FIELD_NAMES.items():
            if toml_key in entry:
                kwargs[attr] = entry[toml_key]
        for field_name in (
            "status",
            "size",
            "cflags",
            "blocker",
            "blocker_delta",
            "note",
            "ghidra",
            "analysis",
            "skip",
            "source",
            "prove_constraints",
        ):
            if field_name in entry:
                kwargs[field_name] = coerce_metadata_value(field_name, entry[field_name])
        return cls(**kwargs)

    def to_entry(self) -> dict[str, Any]:
        """Return the raw TOML entry dict (lower-case keys), dropping None fields."""
        out: dict[str, Any] = {}
        for attr in (
            "status",
            "size",
            "cflags",
            "blocker",
            "blocker_delta",
            "note",
            "ghidra",
            "analysis",
            "skip",
            "source",
            "prove_constraints",
        ):
            value = getattr(self, attr)
            if value is not None:
                out[attr] = value
        for attr, toml_key in _TOML_FIELD_NAMES.items():
            value = getattr(self, attr)
            if value is not None:
                out[toml_key] = value
        return out

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty when the entry is valid)."""
        errors: list[str] = []
        if not self.module:
            errors.append("module must not be empty")
        if self.va <= 0:
            errors.append(f"va must be a positive int, got {self.va!r}")
        if self.status is not None and self.status not in KNOWN_STATUSES:
            errors.append(f"status {self.status!r} not in {sorted(KNOWN_STATUSES)}")
        if self.size is not None and not (isinstance(self.size, int) and self.size > 0):
            errors.append(f"size must be a positive int, got {self.size!r}")
        if self.blocker_delta is not None and not isinstance(self.blocker_delta, int):
            errors.append(f"blocker_delta must be an int, got {self.blocker_delta!r}")
        if self.skip is not None and not isinstance(self.skip, (bool, str)):
            errors.append(f"skip must be bool or str, got {self.skip!r}")
        if self.globals_list is not None and not all(isinstance(g, str) for g in self.globals_list):
            errors.append(f"globals must be a list of str, got {self.globals_list!r}")
        for name in ("cflags", "blocker", "note", "ghidra", "analysis", "source"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                errors.append(f"{name} must be a str, got {value!r}")
        return errors


def load_entry(directory: Path, va: int, module: str) -> FunctionMetadata | None:
    """Load the entry for *(module, va)* as a typed :class:`FunctionMetadata`.

    Returns ``None`` when the entry does not exist.  The raw entry is
    coerced (size/blocker_delta to int) so callers get typed values.
    """
    raw = get_entry(directory, va, module)
    if not raw:
        return None
    return FunctionMetadata.from_entry(module, va, raw)


def save_entry(directory: Path, entry: FunctionMetadata) -> None:
    """Validate *entry* and persist it, writing each non-None field.

    Raises:
        ValueError: If :meth:`FunctionMetadata.validate` reports any errors.

    STATUS is routed through :func:`update_source_status` (promotion
    semantics), then the remaining non-None fields are batched into a single
    read-modify-write.  Clearing a field remains an explicit
    :func:`remove_field` call; ``save_entry`` never deletes.
    """
    errors = entry.validate()
    if errors:
        raise ValueError("invalid metadata entry: " + "; ".join(errors))
    # STATUS routes through update_source_status (promotion semantics); the
    # remaining fields are batched into a single read-modify-write instead of
    # one TOML rewrite per field.  Clearing a field remains an explicit
    # remove_field call; save_entry never deletes.
    if entry.status is not None:
        update_source_status(directory, entry.status, entry.module, entry.va, force=True)
    fields = {k: v for k, v in entry.to_entry().items() if k != "status"}
    if fields:
        _set_fields(directory, entry.va, fields, module=entry.module)
