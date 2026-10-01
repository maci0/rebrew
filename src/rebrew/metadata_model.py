"""metadata_model.py — typed facade over ``rebrew-functions.toml`` entries.

The raw metadata layer (:mod:`rebrew.metadata`) stores entries as plain
``dict[str, Any]`` keyed by ``(module, va)``.  Field routing bugs live in the
gaps: callers guessing whether a key belongs in metadata or the ``.c`` file,
writing STATUS through the wrong writer, or storing the wrong value type.

This module provides a typed, validated view of one entry:

* :class:`MetadataEntry.load` — read + coerce an entry into typed fields.
* :meth:`MetadataEntry.apply` — validate every field, route STATUS through
  the promotion gate (:func:`rebrew.metadata.update_statuses_batch`) and
  write the rest in a single read-modify-write.
* :meth:`MetadataEntry.remove` — typed removal with the STATUS guard.
* :meth:`MetadataEntry.problems` — human-readable validation problems.

Routing is enforced by construction: only keys in
``rebrew.metadata.METADATA_FIELDS`` can be written (``file``/``legacy``/
``unknown`` keys raise :class:`MetadataValidationError`), STATUS only via the
promotion gate, and ``size``/``blocker_delta`` are coerced to ``int``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rebrew.errors import RebrewError
from rebrew.metadata import (
    METADATA_FIELD_TYPES,
    METADATA_FIELDS,
    as_metadata_int,
    canonical_status,
    get_entry,
    remove_field,
    set_fields,
    update_statuses_batch,
    validate_metadata_field,
)
from rebrew.workspace.status import KNOWN_STATUSES, MATCHED_STATUSES

# Field names (lower-case TOML keys) with a single canonical Python type.
_INT_FIELDS = frozenset({"size", "blocker_delta"})
_JSON_FIELDS = frozenset(k for k, v in METADATA_FIELD_TYPES.items() if v is dict)
_STR_FIELDS = frozenset(k for k, v in METADATA_FIELD_TYPES.items() if v is str)

# Field → typed dataclass attribute (public: annotation overlays use the same map).
FIELD_TO_ATTR: dict[str, str] = {key: key for key in METADATA_FIELD_TYPES}


class MetadataValidationError(RebrewError, ValueError):
    """Raised when a typed metadata write violates a field rule."""


def _coerce(key: str, value: Any) -> Any:
    """Coerce *value* to the canonical type for *key* (raises on failure)."""
    if key in _INT_FIELDS:
        try:
            # Shared with coerce_metadata_value / apply_metadata_entry so a
            # hand-edited ``size = 12.9`` cannot truncate to 12, and ``±inf``
            # cannot raise OverflowError past load's MetadataValidationError
            # catch.
            return as_metadata_int(value)
        except (TypeError, ValueError) as exc:
            raise MetadataValidationError(f"{key} must be an int, got {value!r}") from exc
    if key in _JSON_FIELDS and not isinstance(value, dict):
        raise MetadataValidationError(f"{key} must be a table, got {value!r}")
    if key == "globals":
        # Store accepts list | str (metadata._FIELD_TYPES); Annotation merge
        # turns lists into globals_list.  Normalize to the comma-string form
        # so update_annotation_key idempotency compares like-for-like.
        if isinstance(value, list):
            return ", ".join(str(g) for g in value)
        if not isinstance(value, str):
            raise MetadataValidationError(f"globals must be a str or list, got {value!r}")
        return value
    if key in _STR_FIELDS and not isinstance(value, str):
        # Left uncoerced, `status = 5` crashed `problems()` on `.upper()`.
        raise MetadataValidationError(f"{key} must be a str, got {value!r}")
    return value


@dataclass
class MetadataEntry:
    """Typed, validated view of one ``(module, va)`` metadata entry."""

    module: str
    va: int
    size: int | None = None
    cflags: str | None = None
    toolchain: str | None = None
    status: str | None = None
    blocker: str | None = None
    blocker_delta: int | None = None
    note: str | None = None
    ghidra: str | None = None
    analysis: str | None = None
    skip: str | None = None
    globals: str | None = None
    locals: dict[str, Any] | None = None
    comments: dict[str, Any] | None = None
    source: str | None = None
    prove_constraints: dict[str, Any] | None = None
    updated_by: str | None = None
    updated_at: str | None = None
    origins: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    load_problems: list[str] = field(default_factory=list, repr=False)
    """Per-field coercion failures seen by :meth:`load` (empty when clean).

    A corrupt value (e.g. ``size = "abc"``) no longer kills the whole read:
    the field is left unset and the problem recorded here, so
    :meth:`problems` / :meth:`validate` report it instead.
    """

    @classmethod
    def load(cls, directory: Path, va: int, module: str) -> MetadataEntry:
        """Load + coerce the entry for *(module, va)* from *directory*.

        Uncoercible values are collected into :attr:`load_problems` instead
        of raising — use :meth:`problems` / :meth:`validate` to surface them.
        """
        raw = get_entry(directory, va, module)
        kwargs: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        load_problems: list[str] = []
        for key, value in raw.items():
            attr = FIELD_TO_ATTR.get(key)
            if attr is None:
                extra[key] = value
            else:
                try:
                    kwargs[attr] = _coerce(key, value)
                except MetadataValidationError as exc:
                    load_problems.append(f"unreadable {key}={value!r}: {exc}")
        return cls(module=module, va=va, extra=extra, load_problems=load_problems, **kwargs)

    # -- validation -------------------------------------------------------

    def problems(self) -> list[str]:
        """Return human-readable validation problems (empty when valid)."""
        out: list[str] = list(self.load_problems)
        if self.status is not None and canonical_status(self.status) not in KNOWN_STATUSES:
            out.append(f"unknown STATUS {self.status!r} (expected one of {sorted(KNOWN_STATUSES)})")
        if self.size is not None and self.size < 0:
            out.append(f"negative SIZE {self.size}")
        if self.blocker_delta is not None and self.blocker_delta < 0:
            out.append(f"negative blocker_delta {self.blocker_delta}")
        return out

    def validate(self) -> None:
        """Raise :class:`MetadataValidationError` on the first problem."""
        problems = self.problems()
        if problems:
            raise MetadataValidationError(
                f"invalid metadata for {self.module}.0x{self.va:08x}: {problems[0]}"
            )

    # -- writers ----------------------------------------------------------

    def apply(
        self,
        directory: Path,
        force: bool = False,
        *,
        updated_by: str = "",
        **fields: Any,
    ) -> None:
        """Validate + write *fields* for this entry.

        * STATUS routes through the promotion gate
          (:func:`rebrew.metadata.update_statuses_batch`) — *force* (default
          False) decides whether parked SKIP may be overwritten, exactly
          like the raw writer.  Pass ``force=True`` only for explicit
          user-intent writes.  Blockers are cleared only for byte-identical
          statuses (EXACT/RELOC), matching ``rebrew test`` / ``rebrew verify``
          for those verdicts; PROVEN, NEAR_MATCHING, STUB and error verdicts
          keep them.
        * Every other key must be a metadata-owned field; ``size`` /
          ``blocker_delta`` are coerced to ``int``.  The non-STATUS fields go
          out with STATUS in one atomic read-modify-write, so readers cannot
          observe a promotion without its associated fields and a failed
          serialization cannot leave the promotion behind.
        * *updated_by* is the provenance tag recorded alongside the write
          (``updated_by`` / UTC ``updated_at``), the same pair the CLI writers
          stamp.  It is keyword-only so it can never be read as a field value.
        """
        unknown = [k for k in fields if k.upper() not in METADATA_FIELDS]
        if unknown:
            raise MetadataValidationError(
                f"not metadata-owned fields: {unknown} — file-only keys "
                "belong in the .c annotation, not rebrew-functions.toml"
            )
        # Normalize key case (callers may pass "SIZE" or "size") and coerce.
        try:
            coerced = {
                k.lower(): validate_metadata_field(k.lower(), _coerce(k.lower(), v))
                for k, v in fields.items()
            }
        except ValueError as exc:
            raise MetadataValidationError(str(exc)) from exc
        for key in _INT_FIELDS:
            if key in coerced and coerced[key] < 0:
                raise MetadataValidationError(f"{key} must be non-negative, got {coerced[key]}")

        status = coerced.pop("status", None)
        canon: str | None = None
        if status is not None:
            canon = canonical_status(str(status))
            if canon not in KNOWN_STATUSES:
                raise MetadataValidationError(
                    f"unknown STATUS {status!r} (expected one of {sorted(KNOWN_STATUSES)})"
                )
        if canon is not None:
            update_statuses_batch(
                directory,
                [
                    {
                        "module": self.module,
                        "va": self.va,
                        "new_status": canon,
                        "clear_blockers": canon in MATCHED_STATUSES,
                        "force": force,
                        "updated_by": updated_by,
                        "fields": coerced,
                    }
                ],
            )
        elif coerced:
            set_fields(directory, self.va, coerced, module=self.module, updated_by=updated_by)

    def remove(self, directory: Path, key: str) -> bool:
        """Remove one metadata-owned *key*; returns True if anything changed."""
        if key.upper() not in METADATA_FIELDS:
            raise MetadataValidationError(
                f"not a metadata-owned field: {key!r} — use the file-only "
                "removal path for .c annotation keys"
            )
        return remove_field(directory, self.va, key.lower(), module=self.module)
