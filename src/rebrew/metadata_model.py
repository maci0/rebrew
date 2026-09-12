"""metadata_model.py — typed facade over ``rebrew-functions.toml`` entries.

The raw metadata layer (:mod:`rebrew.metadata`) stores entries as plain
``dict[str, Any]`` keyed by ``(module, va)``.  Field routing bugs live in the
gaps: callers guessing whether a key belongs in metadata or the ``.c`` file,
writing STATUS through the wrong writer, or storing the wrong value type.

This module provides a typed, validated view of one entry:

* :class:`MetadataEntry.load` — read + coerce an entry into typed fields.
* :meth:`MetadataEntry.apply` — validate every field, route STATUS through
  the promotion gate (:func:`rebrew.metadata.update_source_status`) and
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

from rebrew.metadata import (
    KNOWN_STATUSES,
    METADATA_FIELDS,
    _set_fields,
    get_entry,
    remove_field,
    update_source_status,
)

# Field names (lower-case TOML keys) with a single canonical Python type.
_INT_FIELDS = frozenset({"size", "blocker_delta"})
_JSON_FIELDS = frozenset({"prove_constraints", "locals", "comments"})

#: Fields whose canonical type is exactly ``str`` (mirrors
#: ``metadata._FIELD_TYPES``).  ``skip``/``globals`` accept more than one type
#: and are deliberately not listed.
_STR_FIELDS = frozenset(
    {"cflags", "toolchain", "status", "blocker", "note", "ghidra", "analysis", "source"}
)

# Field → typed dataclass attribute.
_FIELD_TO_ATTR: dict[str, str] = {
    "size": "size",
    "cflags": "cflags",
    "toolchain": "toolchain",
    "status": "status",
    "blocker": "blocker",
    "blocker_delta": "blocker_delta",
    "note": "note",
    "ghidra": "ghidra",
    "analysis": "analysis",
    "skip": "skip",
    "globals": "globals",
    "locals": "locals",
    "comments": "comments",
    "source": "source",
    "prove_constraints": "prove_constraints",
}


class MetadataValidationError(ValueError):
    """Raised when a typed metadata write violates a field rule."""


def _coerce(key: str, value: Any) -> Any:
    """Coerce *value* to the canonical type for *key* (raises on failure)."""
    if key in _INT_FIELDS:
        if isinstance(value, bool):
            # bool is an int subclass: `int(True)` would become a plausible 1.
            # metadata._validate_field rejects bools for the same reason.
            raise MetadataValidationError(f"{key} must be an int, got {value!r}")
        if not isinstance(value, int):
            try:
                # Accept "42" and "0x2A" (hex) string spellings.
                return int(value, 0) if isinstance(value, str) else int(value)
            except (TypeError, ValueError):
                raise MetadataValidationError(f"{key} must be an int, got {value!r}")
        return value
    if key in _JSON_FIELDS and not isinstance(value, dict):
        raise MetadataValidationError(f"{key} must be a table, got {value!r}")
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
            attr = _FIELD_TO_ATTR.get(key)
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
        if self.status is not None and self.status.upper() not in KNOWN_STATUSES:
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

    def apply(self, directory: Path, force: bool = False, **fields: Any) -> None:
        """Validate + write *fields* for this entry.

        * STATUS routes through the promotion gate
          (:func:`rebrew.metadata.update_source_status`) — *force* (default
          False) decides whether stickiness (PROVEN) may be demoted, exactly
          like the raw writer.  Pass ``force=True`` only for explicit
          user-intent writes.
        * Every other key must be a metadata-owned field; ``size`` /
          ``blocker_delta`` are coerced to ``int``.  Writes are batched into
          a single read-modify-write (except STATUS, which has its own).
        """
        unknown = [k for k in fields if k.upper() not in METADATA_FIELDS]
        if unknown:
            raise MetadataValidationError(
                f"not metadata-owned fields: {unknown} — file-only keys "
                "belong in the .c annotation, not rebrew-functions.toml"
            )
        # Normalize key case (callers may pass "SIZE" or "size") and coerce.
        coerced = {k.lower(): _coerce(k.lower(), v) for k, v in fields.items()}

        status = coerced.pop("status", None)
        if status is not None:
            if str(status).upper() not in KNOWN_STATUSES:
                raise MetadataValidationError(
                    f"unknown STATUS {status!r} (expected one of {sorted(KNOWN_STATUSES)})"
                )
            update_source_status(directory, str(status), self.module, self.va, force=force)
        if coerced:
            _set_fields(directory, self.va, coerced, module=self.module)

    def remove(self, directory: Path, key: str) -> bool:
        """Remove one metadata-owned *key*; returns True if anything changed."""
        if key.upper() not in METADATA_FIELDS:
            raise MetadataValidationError(
                f"not a metadata-owned field: {key!r} — use the file-only "
                "removal path for .c annotation keys"
            )
        return remove_field(directory, self.va, key.lower(), module=self.module)
