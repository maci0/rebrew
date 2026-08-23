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
No hand-edits to ``rebrew-function.toml`` — every write goes through the
lock + ``atomic_write_text``.

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
Writes to the metadata file are serialised by a module-level lock because
``rebrew verify --jobs > 1`` and the GA batch promote STATUS from worker
threads.  Each write is atomic (rename), but read-modify-write cycles from
different threads would otherwise race.
"""

from __future__ import annotations

import contextlib
import logging
import tomllib
import typing
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from rebrew.utils import (
    atomic_write_text,
    build_metadata_doc,
    load_metadata_doc,
    load_toml_for_write,
    metadata_write_lock,
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


@contextlib.contextmanager
def _metadata_write_lock(directory: Path) -> Iterator[None]:
    """Thread + cross-process lock around a metadata read-modify-write.

    Delegates to the shared :func:`rebrew.utils.metadata_write_lock`
    (per-filename lock + advisory ``flock`` sidecar) so the function and
    data stores serialize on the same mechanism.
    """
    with metadata_write_lock(directory, METADATA_FILENAME):
        yield


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
    "toolchain",
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
        "TOOLCHAIN",
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
    "clear_metadata_cache",
    "is_metadata_key",
    "metadata_path",
    "load_metadata",
    "save_metadata",
    "get_entry",
    "set_field",
    "update_field",
    "remove_field",
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

    return load_metadata_doc(path, _metadata_cache, "metadata")


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
    with _metadata_write_lock(directory):
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


def _set_field(directory: Path, va: int, key: str, value: Any, module: str) -> None:
    """Set one field for *(module, va)* in the metadata.  **Private** — use
    :func:`update_field` or :func:`update_source_status` instead.

    Writes directly to ``directory / rebrew-function.toml``.  No walk-up.
    Uses in-place ``tomlkit`` editing to preserve formatting and comments.
    """
    _require_module(module)
    path = (directory / METADATA_FILENAME).resolve()
    toml_key = qualified_key(module, va)

    with _metadata_write_lock(directory):
        doc = load_toml_for_write(path, "metadata")

        if toml_key not in doc:
            doc[toml_key] = tomlkit.table()

        doc[toml_key][key] = value  # type: ignore[index]
        atomic_write_text(path, tomlkit.dumps(doc))
        _metadata_cache.pop(path, None)


def _set_fields(directory: Path, va: int, fields: dict[str, Any], module: str) -> None:
    """Write several fields for *(module, va)* in a single read-modify-write.

    Batches what would otherwise be N full TOML rewrites.  Skips fields whose
    value is unchanged.  **Private** — use :func:`update_field` /
    :func:`update_source_status` instead.
    """
    if not fields:
        return
    _require_module(module)
    path = (directory / METADATA_FILENAME).resolve()
    toml_key = qualified_key(module, va)

    with _metadata_write_lock(directory):
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


def set_fields_batch(metadata_dir: Path, updates: list[dict[str, Any]]) -> int:
    """Set fields for many ``(module, va)`` entries in ONE TOML read-modify-write.

    Perf-review F2 sibling: ``verify --fix-sizes`` called ``set_field`` per
    entry — each a full tomlkit parse + dumps + atomic write under the
    global lock.  Batches the I/O while keeping per-field idempotency.
    Rejects ``status`` (use :func:`update_statuses_batch`, which enforces
    promotion rules).  Returns the number of entries whose fields changed.
    """
    if not updates:
        return 0
    path = (metadata_dir / METADATA_FILENAME).resolve()
    changed_entries = 0
    with _metadata_write_lock(metadata_dir):
        doc = load_toml_for_write(path, "metadata")
        doc_dict = typing.cast(dict[str, Any], doc)
        for u in updates:
            module = u.get("module") or ""
            if not module:
                continue
            toml_key = qualified_key(module, u["va"])
            if toml_key not in doc_dict:
                doc_dict[toml_key] = tomlkit.table()
            entry = typing.cast(dict[str, Any], doc_dict[toml_key])
            changed = False
            for key, value in (u.get("fields") or {}).items():
                if key == "status":
                    raise ValueError("Use update_statuses_batch() for STATUS changes")
                if entry.get(key) != value:
                    entry[key] = value
                    changed = True
            if changed:
                changed_entries += 1
        if changed_entries:
            atomic_write_text(path, tomlkit.dumps(doc))
    _metadata_cache.pop(path, None)
    return changed_entries


def _mutate_entry_doc(
    directory: Path,
    va: int,
    module: str,
    mutate: Callable[[dict[str, Any], str], bool],
) -> bool:
    """Apply *mutate*(doc_dict, toml_key) to the entry for *(module, va)*.

    Opens ``directory / rebrew-function.toml`` under the metadata write lock,
    hands the parsed document and the qualified key to *mutate*, and writes
    the document back only when *mutate* returns True.  No walk-up.
    Returns True if the file was modified.
    """
    path = (directory / METADATA_FILENAME).resolve()
    if not path.exists():
        return False
    _require_module(module)
    toml_key = qualified_key(module, va)

    with _metadata_write_lock(directory):
        try:
            doc = tomlkit.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to parse metadata %s: %s", path, exc)
            return False

        # Use dict access for type checking on tomlkit Container
        doc_dict = typing.cast(dict[str, Any], doc)
        if toml_key not in doc_dict:
            return False
        if not mutate(doc_dict, toml_key):
            return False
        atomic_write_text(path, tomlkit.dumps(doc))
        _metadata_cache.pop(path, None)
        return True


def _delete_field(directory: Path, va: int, key: str, module: str) -> bool:
    """Remove *key* from the metadata entry for *(module, va)*.  **Private** —
    use :func:`remove_field` instead.

    Reads/writes directly at ``directory / rebrew-function.toml``.  No walk-up.
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


def is_status_sticky(current_status: str) -> bool:
    """True when *current_status* should never be demoted by test/verify.

    PROVEN is a post-verify promotion from ``rebrew prove`` — byte-level
    comparison cannot reproduce it, so test/verify must preserve it.
    """
    return current_status == "PROVEN"


def should_promote_status(current_status: str, new_status: str) -> bool:
    """True when *new_status* should overwrite *current_status* in metadata.

    Single canonical promotion decision, enforced both by ``rebrew test`` /
    ``rebrew verify`` call sites and inside :func:`update_statuses_batch`
    (the writer layer).  Refuses to promote when the current status is
    sticky (PROVEN), when a STUB's placeholder size-mismatch would erase
    the user's STUB classification, or when the status did not change.
    """
    if is_status_sticky(current_status):
        return False
    if current_status == "STUB" and new_status in ("SIZE_MISMATCH", "MISSING_SIZE"):
        # A documented STUB (typically blocker-documented) must not be
        # demoted by a placeholder size-mismatch or a missing-size
        # evaluation — that would erase the user's classification.
        return False
    return current_status != new_status


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
    update_statuses_batch(
        metadata_dir,
        [
            {
                "module": module,
                "va": va,
                "new_status": new_status,
                "clear_blockers": clear_blockers,
                "force": force,
            }
        ],
    )


def update_statuses_batch(metadata_dir: Path, updates: list[dict[str, Any]]) -> int:
    """Apply many STATUS updates in ONE TOML read-modify-write.

    ``verify``'s STATUS sync and ``test --all`` previously called
    ``update_source_status`` per entry — each a full tomlkit parse + dumps +
    atomic write serialized under the global lock.  Measured: 260 entries ≈
    9s, extrapolated ≈ 28 min at 3000 entries (perf-review F2).  The
    promotion/stickiness rules are identical per entry; only the I/O is
    batched (one parse, N in-memory edits, one write).

    *updates*: list of dicts with keys ``module``, ``va``, ``new_status``
    and optional ``clear_blockers`` (default True), ``force`` (default
    False).  Returns the number of statuses actually changed.

    Each changed status passes through :func:`should_promote_status` —
    the single canonical promotion policy (PROVEN never silently demoted,
    a documented STUB kept against placeholder size-mismatch verdicts).
    ``force=True`` bypasses that policy for manual/repair writes.
    Same-status updates still fall through when they will clear blockers
    (the stale-blocker cleanup path).
    """
    if not updates:
        return 0
    path = (metadata_dir / METADATA_FILENAME).resolve()
    changed = 0
    with _metadata_write_lock(metadata_dir):
        # Single read for the whole batch
        doc = load_toml_for_write(path, "metadata")
        doc_dict = typing.cast(dict[str, Any], doc)

        for u in updates:
            module = u.get("module") or ""
            if not module:
                continue
            toml_key = qualified_key(module, u["va"])
            if toml_key not in doc_dict:
                doc_dict[toml_key] = tomlkit.table()
            entry = typing.cast(dict[str, Any], doc_dict[toml_key])

            new_status = u["new_status"]
            clear_blockers = u.get("clear_blockers", True)
            force = u.get("force", False)

            # Idempotency guard — avoid a write when nothing changed
            current_status = entry.get("status", "")
            current_blocker = entry.get("blocker", "")
            if current_status == new_status and (not clear_blockers or not current_blocker):
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
            changed += 1

        # Single write for the whole batch
        if changed:
            atomic_write_text(path, tomlkit.dumps(doc))
    _metadata_cache.pop(path, None)
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
    _apply_metadata_entry(ann, entry)
    return ann


def _apply_metadata_entry(ann: Annotation, entry: dict[str, Any]) -> None:
    """Overlay one ``{field: value}`` metadata *entry* onto *ann* in place.

    Shared by :func:`merge_into_annotation` (single function) and
    :func:`rebrew.annotation.parse_c_file_text` (whole-file batches, which
    load the metadata once and apply it per function instead of re-loading
    the TOML for every annotation — the per-function hot path).
    """
    if "size" in entry:
        with contextlib.suppress(ValueError, TypeError):
            ann.size = int(entry["size"])

    if "cflags" in entry:
        ann.cflags = str(entry["cflags"])

    if "toolchain" in entry:
        ann.toolchain = str(entry["toolchain"])

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


# ---------------------------------------------------------------------------
# Typed facade
# ---------------------------------------------------------------------------
#
# The typed entry layer is ``metadata_model.MetadataEntry`` (used by
# annotation.py); the earlier ``FunctionMetadata``/``load_entry``/``save_entry``/
# ``field_kind`` facade was deleted — it had drifted from the live model
# (case-sensitive vs upper() status checks) and only its tests referenced it.
# ``KNOWN_STATUSES`` and ``coerce_metadata_value`` below remain live:
# metadata_model validates against KNOWN_STATUSES, and lint --fix coerces
# values through coerce_metadata_value.

KNOWN_STATUSES: frozenset[str] = frozenset(
    {
        # User classification (annotation / user edits).
        "STUB",
        "EXACT",
        "RELOC",
        "PROVEN",
        "NEAR_MATCHING",
        "SKIP",
        # Machine outcomes persisted by `rebrew test` / `rebrew verify`
        # (they pass CompareResult.status straight to update_source_status,
        # so the validation gate must accept the same vocabulary).
        # INVALID_VA is a persisted annotation-problem verdict (verify_entry
        # emits it below the arch-aware VA floor); INTERNAL_ERROR is
        # deliberately absent — verify never persists tooling crashes.
        "SIZE_MISMATCH",
        "COMPILE_ERROR",
        "EXTRACT_ERROR",
        "MISSING_SIZE",
        "MISSING_FILE",
        "INVALID_VA",
    }
)

# Statuses that count as matched work (byte-identical or proven-equivalent),
# in canonical display order.  Single source of truth: use these instead of
# re-spelling the tuple locally.
MATCHED_STATUSES: tuple[str, ...] = ("EXACT", "RELOC", "PROVEN")


def coerce_metadata_value(key: str, value: Any) -> Any:
    """Coerce *value* to the canonical type for metadata field *key* (lower-case TOML key).

    Only fields with a single unambiguous type are coerced; everything else
    passes through untouched.  String spellings follow ``metadata_model._coerce``:
    both decimal (``"42"``) and hex (``"0x2A"``) are accepted.
    """
    if key in ("size", "blocker_delta") and not isinstance(value, int):
        with contextlib.suppress(ValueError, TypeError):
            return int(value, 0) if isinstance(value, str) else int(value)
    return value


# ---------------------------------------------------------------------------
# Per-library toolchain/flags overrides (rebrew-library.toml)
# ---------------------------------------------------------------------------
#
# A library is a source-directory subtree whose functions were all built with
# the same compiler + flags (the normal case — one codebase, one toolchain).
# Declaring a ``rebrew-library.toml`` at the library root applies to every
# function under it, instead of tagging each function's rebrew-function.toml.
# Discovery is walk-up (nearest ancestor file wins), unlike the function
# metadata which lives only at cfg.metadata_dir.


#: File name of the per-library override (looked up by walking up from the
#: function's directory toward the project root).
LIBRARY_METADATA_FILE = "rebrew-library.toml"


class LibraryOverrideError(RuntimeError):
    """A declared library override is malformed (bad TOML / bad fields)."""


@dataclass(frozen=True)
class LibraryOverride:
    """Effective per-library compile override found for a source directory.

    Empty fields mean "inherit" (project default or a wider library file);
    *presets* lists any known-library defaults that were merged in.
    """

    path: Path  # the rebrew-library.toml that matched (nearest ancestor)
    toolchain: str = ""  # override compiler profile, e.g. "msvc6"
    cflags: str = ""  # override flags, e.g. "/O2 /Gd /MT"
    library: str = ""  # declared library name (may drive presets)
    presets: tuple[str, ...] = ()  # preset names that filled empty fields


#: Known shipped-library build settings.  ``library = "<name>"`` in a
#: rebrew-library.toml fills the *missing* fields from this table — rebrew
#: knows what the shipped runtimes were built with (the standard MSVC /MT
#: vs /MD shapes, the 16-bit models, Borland/Watcom defaults), so users
#: declare ``library = "msvcrt-static"`` instead of handwriting flags.
LIBRARY_PRESETS: dict[str, dict[str, str]] = {
    # MSVC shipped CRT: libc.lib (static single-thread), libcmt.lib (static
    # multi-thread = /MT), msvcrt.lib (dynamic = /MD) — the classic /O2 /Gd
    "msvcrt-static": {"toolchain": "msvc6", "cflags": "/O2 /Gd /MT"},
    "msvcrt-dynamic": {"toolchain": "msvc6", "cflags": "/O2 /Gd /MD"},
    "msvc16-runtime": {"toolchain": "msvc1.52", "cflags": "/O1 /Gd"},
    "borland-runtime": {"toolchain": "tc16", "cflags": "-O2"},
    "watcom-runtime": {"toolchain": "watcom", "cflags": "-ot"},
}


#: Process-level memo for :func:`parse_library_metadata`, keyed by file path.
#: Entries hold ``((mtime_ns, size), parsed_dict)`` so a repeated resolution
#: skips the read+parse while any rewrite (new mtime/size) re-parses.  Cleared
#: wholesale when full — library files per project are few.
_LIBRARY_META_CACHE: dict[str, tuple[tuple[int, int], dict[str, Any]]] = {}
_LIBRARY_META_CACHE_MAX = 64


def parse_library_metadata(path: Path) -> dict[str, Any]:
    """Parse a ``rebrew-library.toml`` into a plain dict.

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
        _LIBRARY_META_CACHE.pop(key, None)
        return {}
    fp = (st.st_mtime_ns, st.st_size)
    cached = _LIBRARY_META_CACHE.get(key)
    if cached is not None and cached[0] == fp:
        return dict(cached[1])
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise LibraryOverrideError(f"bad {LIBRARY_METADATA_FILE} at {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise LibraryOverrideError(f"{path} must be a TOML table")
    if len(_LIBRARY_META_CACHE) >= _LIBRARY_META_CACHE_MAX:
        _LIBRARY_META_CACHE.clear()
    _LIBRARY_META_CACHE[key] = (fp, raw)
    return dict(raw)


def apply_library_presets(meta: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Fill missing toolchain/cflags from the known-library presets.

    Returns ``(merged, preset_names_used)``.  Explicit fields always win.
    """
    name = str(meta.get("library") or "").strip()
    preset = LIBRARY_PRESETS.get(name, {})
    if not preset:
        return meta, ()
    merged = {**meta}
    for key, value in preset.items():
        if not str(merged.get(key) or "").strip():
            merged[key] = value
    return merged, (name,)


_LIBRARY_WALK_CACHE: dict[tuple[str, str], Path | None] = {}


def clear_library_override_cache() -> None:
    """Forget cached ``rebrew-library.toml`` walk results (call after writes)."""
    _LIBRARY_WALK_CACHE.clear()


def find_library_override(
    start_dir: str | Path, root: str | Path | None = None
) -> LibraryOverride | None:
    """Find the nearest ``rebrew-library.toml`` by walking up from *start_dir*.

    The walk stops at *root* (project root — ``cfg.root``) inclusive.  Returns
    the merged override (explicit fields + known-library presets) or ``None``
    when no library file exists on the path.

    The located path is memoized per ``(start_dir, root)`` so bulk callers
    (verify/match over thousands of functions) pay the directory walk once;
    field values still re-parse through :func:`parse_library_metadata`, whose
    mtime/size validation picks up content edits."""
    cur = Path(start_dir).resolve()
    root_p = Path(root).resolve() if root is not None else None
    key = (str(cur), str(root_p) if root_p is not None else "")
    cached = _LIBRARY_WALK_CACHE.get(key)
    if cached is not None and not cached.exists():
        del _LIBRARY_WALK_CACHE[key]  # deleted since the walk — re-walk
        cached = None
    if key not in _LIBRARY_WALK_CACHE:
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
        _LIBRARY_WALK_CACHE[key] = found
        cached = found
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
