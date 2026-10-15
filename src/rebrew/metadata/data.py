"""Locked format-2 data identities, extents, storage relationships and verdicts.

All fields belong in rebrew-data.toml at cfg.metadata_dir. Optional source
addresses bind real declarations; externs and aliases do not allocate storage.
Writers validate current documents and use the shared lock and atomic mode-0444
replacement. Data comparison evidence remains separate from ordinary edit stamps.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import unicodedata
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from rebrew.metadata.document import (
    MetadataDocCache,
    build_metadata_key_index,
    load_metadata_doc,
    load_metadata_for_write,
    metadata_write_lock,
    pop_metadata_doc_cache,
    qualified_key,
    resolve_metadata_key,
    stamp_format,
)
from rebrew.metadata.functions import (
    METADATA_FIELD_TYPES,
    PROVENANCE_TAGS,
    as_metadata_int,
    canonical_status,
    record_verification,
    resolve_metadata_dir,
    stamp_provenance,
    validate_identity_file,
    validate_provenance_table,
)
from rebrew.utils import atomic_write_locked

if TYPE_CHECKING:
    from rebrew.metadata.bindings import SourceBinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory cache for load_data_metadata() — mirrors metadata/functions.py's cache for
# rebrew-functions.toml.  Without it, batch paths that read data metadata per
# file (lint) or per function (smart_reloc_compare's global-name resolution)
# re-parse the TOML on every call.  Keyed by resolved Path; invalidated by
# mtime_ns change or by the write helpers below.
# ---------------------------------------------------------------------------

_data_metadata_cache: MetadataDocCache = {}

#: Stored ``file`` path -> rows, keyed by the identity of the cached document.
#: A scan looks up one path per source; without the index each lookup walks
#: the whole table.  The owner pin stops a freed document's ``id`` from being
#: reused as a live key.  Cleared on every data-store write.
_DATA_FILE_INDEX: dict[int, dict[str, list[tuple[str, int, dict[str, Any]]]]] = {}
_DATA_FILE_INDEX_OWNER: dict[int, dict[tuple[str, int], dict[str, Any]]] = {}
_DATA_FILE_INDEX_LOCK = threading.Lock()
_DATA_FILE_INDEX_MAX = 4


def _invalidate_data_cache(path: Path) -> None:
    """Drop the cached parse for *path* (resolved) after a write."""
    pop_metadata_doc_cache(_data_metadata_cache, path.resolve())
    with _DATA_FILE_INDEX_LOCK:
        _DATA_FILE_INDEX.clear()
        _DATA_FILE_INDEX_OWNER.clear()


def data_file_index(
    directory: Path | str | Any,
) -> dict[str, list[tuple[str, int, dict[str, Any]]]]:
    """Index ``rebrew-data.toml`` rows by their stored ``file`` path.

    The returned lists alias the cached entry dicts.  Callers read them and
    do not mutate them.  An empty store returns an empty index.
    """
    dir_path = resolve_metadata_dir(directory)
    path = (dir_path / DATA_METADATA_FILENAME).resolve()
    cached = load_metadata_doc(
        path,
        _data_metadata_cache,
        "data metadata",
        deepcopy=False,
        known_fields=DATA_METADATA_FIELDS,
    )
    if not cached:
        return {}
    key = id(cached)
    with _DATA_FILE_INDEX_LOCK:
        if _DATA_FILE_INDEX_OWNER.get(key) is cached:
            found = _DATA_FILE_INDEX.get(key)
            if found is not None:
                return found
    index: dict[str, list[tuple[str, int, dict[str, Any]]]] = {}
    for (module, va), entry in cached.items():
        stored = str(entry.get("file", "")).replace("\\", "/")
        if stored:
            index.setdefault(stored, []).append((module, va, entry))
    with _DATA_FILE_INDEX_LOCK:
        if len(_DATA_FILE_INDEX) >= _DATA_FILE_INDEX_MAX:
            _DATA_FILE_INDEX.clear()
            _DATA_FILE_INDEX_OWNER.clear()
        _DATA_FILE_INDEX[key] = index
        _DATA_FILE_INDEX_OWNER[key] = cached
    return index


def data_rows_for_path(
    directory: Path | str | Any, filepath: Path
) -> list[tuple[str, int, dict[str, Any]]]:
    """Return data rows whose ``file`` matches *filepath*.

    The match is the exact metadata-root-relative path. Sibling files with
    the same basename never inherit one another's rows.
    """
    dir_path = resolve_metadata_dir(directory)
    try:
        rel = filepath.resolve().relative_to(dir_path.resolve()).as_posix()
    except ValueError:
        rel = Path(os.path.relpath(filepath, dir_path)).as_posix()
    seen: set[tuple[str, int]] = set()
    rows: list[tuple[str, int, dict[str, Any]]] = []
    index = data_file_index(directory)
    for candidate in (rel,):
        for module, va, entry in index.get(candidate, ()):
            identity = (module, va)
            if identity in seen:
                continue
            seen.add(identity)
            rows.append((module, va, entry))
    return rows


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_METADATA_FILENAME = "rebrew-data.toml"

#: Fields owned by the data metadata.  Must match ``_CANONICAL_ORDER``: `type`
#: is written by `rebrew data set --type` and the binsync import/overlay paths.
#: ``UPDATED_BY`` / ``UPDATED_AT`` are the write provenance pair the gated
#: writers stamp on every change, so "who decided this symbol is DRIFT, and
#: when" is answerable from the canonical store — the coverage document's
#: ``verify_results[]`` row is derived and gitignored, and a rebuild carries it
#: forward but does not recreate it.
DATA_METADATA_FIELD_TYPES: dict[str, type | tuple[type, ...]] = {
    "file": str,
    "kind": str,
    "name": str,
    "type": str,
    **{
        key: METADATA_FIELD_TYPES[key]
        for key in ("size", "note", "status", "updated_by", "updated_at", "origins", "verification")
    },
    "section": str,
    "storage_kind": str,
    "backing": str,
    "link_symbol": str,
}
DATA_METADATA_FIELDS = frozenset(key.upper() for key in DATA_METADATA_FIELD_TYPES)

#: Data verification verdicts written by ``verify --data``, strongest first.
#: EXACT: the link map puts the symbol at its reference VA and its bytes match.
#: VERIFIED: the bytes at the reference VA match; placement was not checked
#: (no link map, or the map does not name the symbol).
#: DISPLACED: the link map puts the symbol at another VA. A zero-filled symbol
#: compares equal anywhere in BSS, so only the map can tell.
#: DRIFT: the bytes at the reference VA differ or are missing.
DATA_STATUS_EXACT = "EXACT"
DATA_STATUS_VERIFIED = "VERIFIED"
DATA_STATUS_DISPLACED = "DISPLACED"
DATA_STATUS_DRIFT = "DRIFT"
DATA_STATUS_UNCHECKED = "UNCHECKED"
DATA_STATUSES: frozenset[str] = frozenset(
    {
        DATA_STATUS_EXACT,
        DATA_STATUS_VERIFIED,
        DATA_STATUS_DISPLACED,
        DATA_STATUS_DRIFT,
        DATA_STATUS_UNCHECKED,
    }
)

# Canonical TOML key order when writing.  Identity first, then the fields
# `rebrew data set` and the verdict writers already emit.
_CANONICAL_ORDER = [
    "file",
    "kind",
    "name",
    "type",
    "size",
    "section",
    "storage_kind",
    "backing",
    "link_symbol",
    "note",
    "status",
    "updated_by",
    "updated_at",
    "origins",
    "verification",
]

#: Canonical data identity keys. ``name`` fills an absent value, preserving
#: explicit renames on repeated registration. Written by :func:`record_data_rows`
#: rather than :func:`set_data_fields_batch`, which clears a verdict when
#: ``name`` / ``type`` / ``size`` / ``section`` change.
_DATA_MARKER_IDENTITY = ("file", "kind", "name")
_DATA_MARKER_FILL = ("type", "size", "section", "note")

__all__ = [
    "DATA_METADATA_FILENAME",
    "DATA_METADATA_FIELDS",
    "DATA_METADATA_FIELD_TYPES",
    "data_definition_hash",
    "load_data_metadata",
    "save_data_metadata",
    "iter_data_symbols",
    "get_data_entry",
    "delete_data_entries_batch",
    "move_data_entry",
    "module_visible_to_target",
    "set_data_field",
    "set_data_fields_batch",
    "patch_data_fields_batch",
    "validate_data_field",
    "merge_into_data_binding",
    "record_data_rows",
    "data_file_index",
    "data_rows_for_path",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def validate_data_field(key: str, value: Any) -> Any:
    """Validate and normalize one lower-case data metadata field.

    Function-only fields (BLOCKER, CFLAGS, …) and function STATUS values have no
    meaning in the data store; accepting them would give a fact a second home.
    """
    if not key or key.upper() not in DATA_METADATA_FIELDS or key != key.lower():
        raise ValueError(
            f"unknown data metadata field {key!r} "
            f"(expected one of {sorted(k.lower() for k in DATA_METADATA_FIELDS)})"
        )
    if key in {"origins", "verification"}:
        return validate_provenance_table(key, value)
    if key == "size":
        try:
            size = as_metadata_int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"size must be a non-negative integer, got {value!r}") from exc
        if size < 0:
            raise ValueError(f"size must be a non-negative integer, got {value!r}")
        return size
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string, got {value!r}")
    if key == "storage_kind" and value not in {"object", "alias", "literal", "span", "import"}:
        raise ValueError(f"invalid storage_kind {value!r}")
    if key == "status" and value not in DATA_STATUSES:
        raise ValueError(
            f"invalid data STATUS {value!r}: not one of {', '.join(sorted(DATA_STATUSES))}"
        )
    if key == "file":
        return validate_identity_file(value)
    if key == "kind":
        # Lazy: annotation synthesizes data rows from this module, so a
        # module-level import here would cycle at import time.
        from rebrew.metadata.bindings import DATA_KINDS

        if value not in DATA_KINDS:
            raise ValueError(f"kind must be one of {', '.join(sorted(DATA_KINDS))}, got {value!r}")
    return value


# ---------------------------------------------------------------------------
# Raw-document iteration
# ---------------------------------------------------------------------------


def iter_data_symbols(
    doc: dict[str, Any], section: str | None = ".data"
) -> Iterator[tuple[str, int, dict[str, Any]]]:
    """Yield typed rows from a current data metadata document."""
    from rebrew.metadata.document import parse_metadata_doc

    for (module, va), entry in parse_metadata_doc(doc, known_fields=DATA_METADATA_FIELDS).items():
        if section is None or entry.get("section") == section:
            yield module, va, entry


# ---------------------------------------------------------------------------
# Target scope
# ---------------------------------------------------------------------------


_SCOPE_LOCK = threading.Lock()
_scope_memo: tuple[Any, str, frozenset[str]] | None = None


def _target_scope(cfg: Any) -> tuple[str, frozenset[str]]:
    """``(active marker key, set of every target marker key)`` for *cfg*.

    Both are config-constant for the process, but this predicate runs once per
    data row, so the derivation (including the ``all_markers`` set build) is
    memoised against the last config seen.  A single slot bounds the memory.
    """
    global _scope_memo
    from rebrew.config import module_marker
    from rebrew.utils import preset_module_key

    with _SCOPE_LOCK:
        memo = _scope_memo
        if memo is not None and memo[0] is cfg:
            return memo[1], memo[2]
    active = preset_module_key(module_marker(cfg))
    others = frozenset(preset_module_key(m) for m in (getattr(cfg, "all_markers", None) or ()))
    with _SCOPE_LOCK:
        _scope_memo = (cfg, active, others)
    return active, others


def module_visible_to_target(module: str, cfg: Any) -> bool:
    """Whether a data row's module belongs on the active target's reports.

    One ``rebrew-data.toml`` holds every binary in a shared tree. Another
    target's marker does not belong on this target's ``status``, ``data``,
    ``todo``, or ``verify --data`` output. The active marker does. A module
    that is not any target's marker (``MSVCRT``, ``ZLIB``) does too: that
    data is linked into this binary. With no config, or no marker, every
    module belongs.
    """
    if cfg is None:
        return True
    from rebrew.utils import preset_module_key

    active, others = _target_scope(cfg)
    if not active:
        return True
    mod = preset_module_key(module)
    if not mod or mod == active:
        return True
    if not others:
        return False
    return mod not in others


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


def load_data_metadata(directory: Path | str | Any) -> dict[tuple[str, int], dict[str, Any]]:
    """Load ``rebrew-data.toml`` from *directory*.

    *directory* must be the metadata root (``cfg.metadata_dir``), path string, or config.  There is
    no walk-up — the file is expected at exactly ``directory / rebrew-data.toml``.

    Returns a mapping of ``{(module, va_int): {field_name: value}}``.
    Returns an empty dict if no metadata file is found or it cannot be parsed.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``), path string, or config.

    """
    dir_path = resolve_metadata_dir(directory)
    path = (dir_path / DATA_METADATA_FILENAME).resolve()
    if not path.exists():
        # Drop any parse of a file that has since been deleted: the early
        # return bypasses load_metadata_doc, which pops on a missing path, so
        # the table would otherwise stay pinned for the process lifetime.
        pop_metadata_doc_cache(_data_metadata_cache, path)
        return {}

    # Shared loader: tomllib reads (fast), mtime-keyed cache — same
    # mechanism as rebrew-functions.toml (metadata/functions.py).  deepcopy=False:
    # this function already returns a shallow copy of the outer map and
    # each entry, so a full deep clone of the cache is wasted work.
    cached = load_metadata_doc(
        path,
        _data_metadata_cache,
        "data metadata",
        deepcopy=False,
        known_fields=DATA_METADATA_FIELDS,
    )
    # Return a shallow copy of outer dict + each entry dict so callers cannot
    # mutate the cached object and corrupt subsequent reads.
    return {k: dict(v) for k, v in cached.items()}


# ---------------------------------------------------------------------------
# Granular read/write
# ---------------------------------------------------------------------------


def get_data_entry(directory: Path | str | Any, va: int, module: str) -> dict[str, Any]:
    """Return data metadata fields for *(module, va)* in *directory*.

    Returns an empty dict if not found.  Copies only the selected entry, not
    the whole table, so per-symbol lookups in batch loops stay O(1).

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``), path string, or config.
        va: Virtual address integer.
        module: Target module name (e.g. ``"SERVER"``).

    """
    dir_path = resolve_metadata_dir(directory)
    path = (dir_path / DATA_METADATA_FILENAME).resolve()
    cached = load_metadata_doc(
        path,
        _data_metadata_cache,
        "data metadata",
        deepcopy=False,
        known_fields=DATA_METADATA_FIELDS,
    )
    entry = cached.get((unicodedata.normalize("NFC", module), va))
    return dict(entry) if entry is not None else {}


def set_data_field(
    directory: Path | str | Any,
    va: int,
    key: str,
    value: Any,
    module: str,
    *,
    updated_by: str = "",
    now: datetime | None = None,
) -> None:
    """Set one field for *(module, va)* in the data metadata.

    Writes directly to ``directory / rebrew-data.toml``.  No walk-up.
    Uses in-place ``tomlkit`` editing to preserve formatting and comments.

    Args:
        directory: The metadata root directory (``cfg.metadata_dir``), path string, or config.
        va: Virtual address integer.
        key: Lower-case TOML key (e.g. ``"size"``, ``"section"``).
        value: Value to write.
        module: Target module name (e.g. ``"SERVER"``).
        updated_by: Provenance tag of the writing tool (``verify``, ``data``,
            ``rename``, ``lint``, ``binsync-import``, …).  When set, the same
            write records ``updated_by`` plus a UTC ``updated_at``; callers
            that pass "" leave the row's existing stamp alone.
        now: Instant that ``updated_at`` records, for a run replaying its own
            writes (see :func:`rebrew.metadata.functions.stamp_provenance`).  Unset reads
            the wall clock.

    """
    set_data_fields_batch(
        directory,
        [
            {
                "module": module,
                "va": va,
                "fields": {key: value},
                "updated_by": updated_by,
            }
        ],
        now=now,
    )


def set_data_fields_batch(
    directory: Path | str | Any, updates: list[dict[str, Any]], *, now: datetime | None = None
) -> int:
    """Set fields for many ``(module, va)`` entries in one TOML read-modify-write.

    Sibling of :func:`rebrew.metadata.functions.set_fields_batch` for the data store.
    Each update is ``{"module", "va", "fields": {key: value, ...}}`` plus an
    optional ``"updated_by"`` provenance tag, which stamps the entry's
    ``updated_by`` / ``updated_at`` pair in the same write when the update
    changes something.  Same-value short-circuit is preserved per field.
    Returns the number of entries that changed at least one field.

    Changing a symbol's name/type/size/section removes its previous STATUS
    unless the update includes a fresh verdict. Notes and no-ops preserve it.

    *now* fixes the instant every row the batch stamps records, so a replay
    lands the same bytes (see :func:`rebrew.metadata.functions.stamp_provenance`).

    Raises :class:`ValueError` for an update missing ``module`` or ``va``, or
    naming a negative VA.  A malformed update used to be skipped, so the rest
    of the batch landed while the caller still believed every row had been
    written — the function store's twin raises for the same reason.
    """
    if not updates:
        return 0
    dir_path = resolve_metadata_dir(directory)
    path = dir_path / DATA_METADATA_FILENAME
    changed_entries = 0
    with metadata_write_lock(dir_path, DATA_METADATA_FILENAME):
        doc = load_metadata_for_write(path, "data metadata", known_fields=DATA_METADATA_FIELDS)
        changed_entries = _patch_data_document(doc, updates, now=now)
        if changed_entries:
            stamp_format(doc)
            atomic_write_locked(path, tomlkit.dumps(doc))
            _invalidate_data_cache(path)
    return changed_entries


_DATA_PATCH_FIELDS = frozenset(
    {
        "file",
        "kind",
        "name",
        "type",
        "size",
        "section",
        "storage_kind",
        "backing",
        "link_symbol",
        "note",
    }
)


def _data_document_digest(path: Path) -> str:
    """Hash complete input bytes, distinguishing an absent store from an empty one."""
    try:
        content = b"present\0" + path.read_bytes()
    except FileNotFoundError:
        content = b"absent\0"
    return hashlib.sha256(content).hexdigest()


def patch_data_fields_batch(
    directory: Path | str | Any,
    updates: list[dict[str, Any]],
    *,
    dry_run: bool = False,
    expected_digest: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Preview or atomically apply non-verdict edits with a complete-input guard.

    Previews never acquire the writer lock or create directories/sidecars. A
    reviewed digest is rechecked under the lock before any actual publication.
    Conflicting repeated fields and attempts to supply verdict/evidence fields
    are rejected before locking. Existing verification evidence is retained;
    definition and placement edits invalidate only the current verdict.
    """
    if expected_digest is not None and (
        len(expected_digest) != 64 or any(c not in "0123456789abcdef" for c in expected_digest)
    ):
        raise ValueError("expected digest must be a lowercase SHA-256 hex digest")
    merged: dict[tuple[str, int], dict[str, Any]] = {}
    for update in updates:
        if set(update) - {"module", "va", "fields"}:
            raise ValueError("data patches accept only module, va and non-verdict fields")
        module = update.get("module")
        if not isinstance(module, str) or not module:
            raise ValueError("data patches require a non-empty module")
        va = as_metadata_int(update.get("va"))
        if va < 0:
            raise ValueError("data patches require a non-negative VA")
        fields = update.get("fields")
        if not isinstance(fields, dict) or not fields:
            raise ValueError("data patches require a non-empty fields table")
        target = merged.setdefault((unicodedata.normalize("NFC", module), va), {})
        for field, value in fields.items():
            if field not in _DATA_PATCH_FIELDS:
                raise ValueError(f"{field!r} is not a non-verdict data patch field")
            value = validate_data_field(field, value)
            if field in target and target[field] != value:
                raise ValueError(f"conflicting repeated {field} for {module}.0x{va:x}")
            target[field] = value
    normalized = [
        {"module": module, "va": va, "fields": fields, "updated_by": "data"}
        for (module, va), fields in merged.items()
    ]
    directory = resolve_metadata_dir(directory)
    path = directory / DATA_METADATA_FILENAME

    def prepare() -> tuple[Any, str, int]:
        digest = _data_document_digest(path)
        if expected_digest is not None and digest != expected_digest:
            raise ValueError("data metadata changed since preview; review a new preview")
        doc = load_metadata_for_write(path, "data metadata", known_fields=DATA_METADATA_FIELDS)
        if _data_document_digest(path) != digest:
            raise ValueError("data metadata changed while reading; retry")
        changed = _patch_data_document(doc, normalized, now=now)
        return doc, digest, changed

    # Validate the whole operation before the lock can create any files.
    doc, digest, changed = prepare()
    if not dry_run:
        with metadata_write_lock(directory, DATA_METADATA_FILENAME):
            doc, digest, changed = prepare()
            if changed:
                stamp_format(doc)
                atomic_write_locked(path, tomlkit.dumps(doc))
                _invalidate_data_cache(path)
    return {"dry_run": dry_run, "input_digest": digest, "changed": changed}


def _patch_data_document(
    doc: Any, updates: list[dict[str, Any]], *, now: datetime | None = None
) -> int:
    """Apply validated edits to an unpublished document shared by preview and writers."""
    changed_entries = 0
    key_index = build_metadata_key_index(doc)
    from rebrew.utils import toml_safe

    for u in updates:
        module = str(u.get("module") or "")
        if not module:
            raise ValueError("data metadata writes require a non-empty module")
        va = u.get("va")
        if va is None:
            raise ValueError(f"data field update for {module!r} missing 'va': {u!r}")
        va_int = as_metadata_int(va)
        if va_int < 0:
            raise ValueError(f"VA must be non-negative, got {va_int:#x}")
        fields = u.get("fields") or {}
        if not fields:
            continue
        tag = str(u.get("updated_by") or "")
        if tag and tag not in PROVENANCE_TAGS:
            raise ValueError(
                f"data field update for {module!r} 0x{va_int:x} names unknown "
                f"provenance tag {tag!r}, not in {sorted(PROVENANCE_TAGS)}"
            )
        toml_key = resolve_metadata_key(doc, module, va_int, index=key_index)
        if toml_key not in doc:
            doc[toml_key] = tomlkit.table()
            # The index is keyed on the NFC-normalized module
            # (build_metadata_key_index parses with parse_metadata_key),
            # so store it in that spelling or a later resolve misses.
            key_index[(unicodedata.normalize("NFC", module), va_int)] = toml_key
        elif not isinstance(doc[toml_key], dict):
            raise ValueError(
                f"data metadata entry {toml_key!r} is not a table "
                f"({type(doc[toml_key]).__name__}); repair or remove it first"
            )
        entry = doc[toml_key]
        changed = False
        definition_changed = False
        for key, value in fields.items():
            safe = toml_safe(validate_data_field(key, value))
            if isinstance(entry, dict) and entry.get(key) == safe:
                continue
            entry[key] = safe
            changed = True
            definition_changed |= key in (
                "name",
                "type",
                "size",
                "section",
                "file",
                "kind",
                "storage_kind",
                "backing",
                "link_symbol",
            )
        evidence_changed = False
        evidence = u.get("verification")
        if evidence is not None:
            if tag != "verify" or evidence.get("status") != fields.get("status"):
                raise ValueError("data verification evidence requires its verify verdict")
            evidence_changed = record_verification(entry, evidence, now=now)
        if changed or evidence_changed:
            # A verdict measured the old symbol extent/identity. Notes and
            # provenance leave it valid; a new measurement may set it in
            # the same update as the definition it verified.
            if definition_changed and "status" not in fields:
                entry.pop("status", None)
            tag = str(u.get("updated_by") or "")
            if tag and changed:
                stamp_provenance(entry, tag, now=now)
            changed_entries += 1
    return changed_entries


def delete_data_entries_batch(directory: Path | str | Any, targets: list[tuple[str, int]]) -> int:
    """Drop whole ``(module, va)`` entries from ``rebrew-data.toml`` in one rewrite.

    Sibling of :func:`rebrew.metadata.functions.delete_entries_batch` for the data
    store (orphan pruning: DATA/GLOBAL blocks whose VA has no source
    annotation).  Returns the number of entries removed.  Missing entries
    are no-ops.  Only touches the metadata file — never a source file.
    """
    if not targets:
        return 0
    dir_path = resolve_metadata_dir(directory)
    path = (dir_path / DATA_METADATA_FILENAME).resolve()
    if not path.exists():
        return 0
    removed = 0
    with metadata_write_lock(dir_path, DATA_METADATA_FILENAME):
        doc = load_metadata_for_write(path, "data metadata", known_fields=DATA_METADATA_FIELDS)
        key_index = build_metadata_key_index(doc)
        for module, va in targets:
            if not module:
                continue
            va_int = int(va)
            norm_mod = unicodedata.normalize("NFC", str(module))
            toml_key = resolve_metadata_key(doc, norm_mod, va_int, index=key_index)
            if toml_key not in doc:
                continue
            del doc[toml_key]
            key_index.pop((norm_mod, va_int), None)
            removed += 1
        if removed:
            stamp_format(doc)
            atomic_write_locked(path, tomlkit.dumps(doc))
            _invalidate_data_cache(path)
    return removed


def move_data_entry(
    directory: Path | str | Any,
    module: str,
    old_va: int,
    new_va: int,
    *,
    dry_run: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-address the ``(module, old_va)`` row to *new_va* in one locked rewrite.

    Every field moves with the row except ``status``: a verdict compared the
    reference bytes at the old address, so it is dropped and the next
    ``rebrew verify --data`` measures the new one.  The ``verification``
    table stays as the record of that last measurement; its
    ``definition_hash`` names the old VA, so a reader comparing it with the
    row sees it is stale.  The move stamps ``updated_by = "data"``.

    Raises :class:`ValueError` when the VAs are equal, no row is at
    *old_va*, a row already holds *new_va*, or the row's ``file`` still
    carries an address anchor for *old_va* (update or remove that anchor
    before moving the canonical row).  Returns the move as
    ``{module, from, to, name, status_was}``; *dry_run* checks without writing.
    """
    from rebrew.metadata.bindings import address_pairs

    module = unicodedata.normalize("NFC", module)
    if not module:
        raise ValueError("data metadata writes require a non-empty module")
    if old_va == new_va:
        raise ValueError(f"0x{old_va:x} and 0x{new_va:x} are the same address")
    if new_va < 0:
        raise ValueError(f"VA must be non-negative, got {new_va:#x}")
    dir_path = resolve_metadata_dir(directory)
    path = dir_path / DATA_METADATA_FILENAME
    with metadata_write_lock(dir_path, DATA_METADATA_FILENAME):
        doc = load_metadata_for_write(path, "data metadata", known_fields=DATA_METADATA_FIELDS)
        index = build_metadata_key_index(doc)
        old_key = index.get((module, old_va))
        if old_key is None or old_key not in doc:
            raise ValueError(f"no data row at {module}.0x{old_va:x}")
        new_key = index.get((module, new_va))
        if new_key is not None and new_key in doc:
            raise ValueError(f"{new_key} already holds a data row")
        entry = doc[old_key]
        if not isinstance(entry, dict):
            raise ValueError(f"data metadata entry {old_key!r} is not a table")
        source = dir_path / str(entry.get("file") or "")
        if (
            entry.get("file")
            and source.is_file()
            and (module, old_va)
            in address_pairs(source.read_text(encoding="utf-8", errors="replace"))
        ):
            raise ValueError(
                f"{entry['file']} still binds {module} 0x{old_va:x}; "
                "update or remove that ADDRESS anchor before moving the row"
            )
        moved = {
            "module": module,
            "from": f"0x{old_va:x}",
            "to": f"0x{new_va:x}",
            "name": entry.get("name"),
            "status_was": entry.get("status"),
        }
        if dry_run:
            return moved
        fields = entry.unwrap() if hasattr(entry, "unwrap") else dict(entry)
        fields.pop("status", None)
        del doc[old_key]
        table = tomlkit.table()
        for key in _CANONICAL_ORDER:
            if key in fields:
                table[key] = fields.pop(key)
        for key, value in fields.items():
            table[key] = value
        stamp_provenance(table, "data", now=now)
        doc[qualified_key(module, new_va)] = table
        stamp_format(doc)
        atomic_write_locked(path, tomlkit.dumps(doc))
        _invalidate_data_cache(path)
    return moved


def record_data_rows(metadata_dir: Path | str | Any, rows: list[dict[str, Any]]) -> None:
    """Write canonical data identity rows into ``rebrew-data.toml`` in one edit.

    Each row carries ``module``, ``va``, ``identity`` (``file``,
    ``kind``, and ``name``; empty values are skipped and ``name`` is
    set only when the entry has none) and ``fill`` (``type``, ``size``,
    ``section``, ``note``, written only when the entry lacks that key).  A stored
    verdict is left in place: this writer does not go through
    :func:`set_data_fields_batch`, which drops ``status`` when a definition
    field changes.  It also does not stamp ``updated_by``.  STATUS in either
    map is rejected.

    Raises:
        ValueError: The existing store cannot be parsed (it is left untouched),
            a row has no module, or a field fails validation.

    """
    if not rows:
        return
    from rebrew.utils import toml_safe

    dir_path = resolve_metadata_dir(metadata_dir)
    path = (dir_path / DATA_METADATA_FILENAME).resolve()
    with metadata_write_lock(dir_path, DATA_METADATA_FILENAME):
        doc = load_metadata_for_write(path, "data metadata", known_fields=DATA_METADATA_FIELDS)
        key_index = build_metadata_key_index(doc)
        changed = False
        for row in rows:
            module = str(row.get("module") or "")
            if not module:
                raise ValueError("data metadata writes require a non-empty module")
            va_int = as_metadata_int(row["va"])
            if va_int < 0:
                raise ValueError(f"VA must be non-negative, got {va_int:#x}")
            toml_key = resolve_metadata_key(doc, module, va_int, index=key_index)
            if toml_key not in doc:
                doc[toml_key] = tomlkit.table()
                key_index[(unicodedata.normalize("NFC", module), va_int)] = toml_key
            elif not isinstance(doc[toml_key], dict):
                raise ValueError(
                    f"data metadata entry {toml_key!r} is not a table "
                    f"({type(doc[toml_key]).__name__}); repair or remove it first"
                )
            entry = doc[toml_key]
            updates: dict[str, Any] = {}
            for key, value in (row.get("identity") or {}).items():
                if key == "status":
                    raise ValueError("data registration does not write STATUS")
                if key not in _DATA_MARKER_IDENTITY:
                    raise ValueError(f"unknown data marker identity field {key!r}")
                if value and not (key == "name" and entry.get("name")):
                    stored = validate_data_field(key, value)
                    if stored:
                        updates[key] = toml_safe(stored)
            for key, value in (row.get("fill") or {}).items():
                if key == "status":
                    raise ValueError("data registration does not write STATUS")
                if key not in _DATA_MARKER_FILL:
                    raise ValueError(f"unknown data marker fill field {key!r}")
                if value in (None, "", 0):
                    continue
                if entry.get(key) not in (None, ""):
                    continue
                updates[key] = toml_safe(validate_data_field(key, value))
            for key, value in updates.items():
                if entry.get(key) != value:
                    entry[key] = value
                    changed = True
        if changed:
            stamp_format(doc)
            atomic_write_locked(path, tomlkit.dumps(doc))
            _invalidate_data_cache(path)


# ---------------------------------------------------------------------------
# SourceBinding merge
# ---------------------------------------------------------------------------


def merge_into_data_binding(ann: SourceBinding, directory: Path | str | Any) -> SourceBinding:
    """Overlay data metadata values onto *ann*, returning the same object mutated.

    The metadata wins for every field it defines (SIZE, SECTION, NOTE).

    Lookup uses the qualified key ``(ann.module, ann.va)``.

    Args:
        ann: The ``SourceBinding`` object to mutate (must have ``kind``
            of ``DATA`` or ``GLOBAL``).
        directory: The metadata root directory (``cfg.metadata_dir``), path string, or config.

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
        # Another C declaration at the same VA can be an interior/first-field view.
        if ann.name and ann.name != name:
            return ann
        ann.name = str(name)

    if "size" in entry:
        try:
            ann.size = as_metadata_int(entry["size"])
        except (ValueError, TypeError) as exc:
            # Leaving ann.size at 0 makes every later size comparison read the
            # extent as genuinely unknown, and the coverage grid renders a
            # zero-width cell for it.  Same guard as
            # rebrew.metadata.functions.apply_metadata_entry: name the entry and the value.
            logger.warning(
                "rebrew-data.toml size for %s[0x%x] is not an integer (%r: %s); "
                "leaving the annotation's own size",
                getattr(ann, "module", None) or getattr(ann, "name", None) or "?",
                getattr(ann, "va", 0) or 0,
                entry["size"],
                exc,
            )

    if "section" in entry:
        ann.section = str(entry["section"])

    if "note" in entry:
        ann.note = str(entry["note"])

    if "status" in entry:
        ann.status = canonical_status(str(entry["status"]))

    if updated_by := entry.get("updated_by"):
        ann.updated_by = str(updated_by)

    if updated_at := entry.get("updated_at"):
        ann.updated_at = str(updated_at)

    return ann


def data_definition_hash(
    module: str, va: int, fields: dict[str, Any], *, arch: str = "x86_32"
) -> str:
    """Fingerprint the canonical definition without its label, note or edit stamps."""
    import hashlib
    import json

    definition = {
        "module": module,
        "va": va,
        "arch": arch,
        **{field: fields.get(field, "") for field in ("size", "type", "section")},
    }
    return hashlib.sha256(json.dumps(definition, sort_keys=True).encode()).hexdigest()


def save_data_metadata(
    directory: Path, rows: dict[tuple[str, int], dict[str, Any]], *, expected_hash: str | None
) -> None:
    """Write reviewed complete data rows, preserving their existing verdict evidence."""
    import hashlib

    from rebrew.metadata.document import build_metadata_doc

    validated = {
        key: {field: validate_data_field(field, value) for field, value in row.items()}
        for key, row in rows.items()
    }
    doc = build_metadata_doc(
        validated, ("file", "name", "kind", "type", "size", "section", "status")
    )
    path = directory / DATA_METADATA_FILENAME
    with metadata_write_lock(directory, DATA_METADATA_FILENAME):
        current = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        if current != expected_hash:
            raise ValueError(f"{path} changed since its rows were reviewed")
        atomic_write_locked(path, tomlkit.dumps(doc))
        pop_metadata_doc_cache(_data_metadata_cache, path.resolve())
