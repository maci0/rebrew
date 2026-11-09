"""Function status vocabulary shared by the coverage consumers.

Owns the canonical STATUS sets so :mod:`rebrew.workspace` stays free of the
metadata writers.  Import from here (or :mod:`rebrew.workspace`).  Reportal's
portal status set is a superset: it also carries ``MATCHED``, the aggregate display label, so
portal statuses are not interchangeable with this tuple.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any
lazy from collections.abc import Mapping


@dataclass(frozen=True)
class TrustedVerification:
    """A backend-authenticated verdict for one retained source and extent."""

    source: str
    va: int
    size: int
    status: str
    match_count: int = 0


@dataclass(frozen=True)
class TrustedCoverage:
    """Per-invocation verdicts; caller validates custody before constructing this."""

    records: tuple[TrustedVerification, ...]
    _by_va: Mapping[int, TrustedVerification] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        records = {record.va: record for record in self.records}
        if len(records) != len(self.records):
            raise ValueError("duplicate trusted verification address")
        object.__setattr__(self, "_by_va", MappingProxyType(records))

    def verdict(self, root: Path, source: Path, va: int) -> TrustedVerification | None:
        root = root.resolve()
        source = source.resolve()
        if not source.is_relative_to(root):
            return None
        name = source.relative_to(root).as_posix()
        record = self._by_va.get(va)
        return record if record is not None and record.source == name else None

    def bind(self, cfg: Any, entries: list[Any], funcs: list[dict[str, Any]]) -> list[Any]:
        inventory = {int(item["va"]): int(item["size"]) for item in funcs}
        records = self._by_va
        counts = Counter(entry.va for entry in entries if not entry.is_data and entry.va in records)
        if any(counts[va] != 1 for va in records):
            raise ValueError("ambiguous trusted verification binding")
        for record in self.records:
            if (
                record.status not in {"EXACT", "RELOC", "SIZE_MISMATCH", "STUB", "NEAR_MATCHING"}
                or record.size <= 0
                or inventory.get(record.va) != record.size
                or not 0 <= record.match_count <= record.size
                or (record.status in {"EXACT", "RELOC"} and record.match_count != record.size)
                or (
                    record.status in {"STUB", "NEAR_MATCHING"} and record.match_count == record.size
                )
            ):
                raise ValueError("unsupported or unbound trusted verification")
        bound: set[int] = set()
        result = []
        root = Path(cfg.root).resolve()
        for entry in entries:
            if not entry.is_data and entry.va not in inventory:
                continue
            rec = records.get(entry.va)
            source = (Path(cfg.reversed_dir) / entry.filepath).resolve()
            matched = (
                rec is not None
                and source.is_relative_to(root)
                and source.relative_to(root).as_posix() == rec.source
                and not entry.is_data
            )
            if matched:
                if entry.va in bound:
                    raise ValueError("ambiguous trusted verification binding")
                bound.add(entry.va)
            result.append(
                replace(
                    entry,
                    status=rec.status if (matched and rec is not None) else "UNKNOWN",
                    size=rec.size
                    if (matched and rec is not None)
                    else max(inventory.get(entry.va, 0), 0),
                    kind="FUNCTION" if entry.kind == "LIBRARY" else entry.kind,
                )
            )
        if bound != records.keys():
            raise ValueError("trusted verification has no unique source binding")
        return result


#: Legacy / hand-edited spellings normalized by :func:`canonical_status`.
#: Single owner for the alias so the writer, the status overlay and the
#: catalog grid cannot drift apart on which spellings they accept.
STATUS_ALIASES: dict[str, str] = {
    "NEAR_MATCH": "NEAR_MATCHING",
}


def canonical_status(status: str) -> str:
    """Return *status* in its canonical (upper-case, trimmed) spelling."""
    folded = status.strip().upper()
    return STATUS_ALIASES.get(folded, folded)


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

#: Statuses a stored function row may hold: ``KNOWN_STATUSES`` plus ``UNKNOWN``,
#: what a catalog row with no STATUS gets.  The writer's insert-time sanitizer
#: and the dashboard status filter read this, so a value the document can hold
#: can never be rejected as unknown by a reader of that same document.
#: The name keeps its database-era spelling because three modules import it by
#: name; a rename is a public-surface change and not worth one.
COVERAGE_DB_STATUSES: frozenset[str] = frozenset({*KNOWN_STATUSES, "UNKNOWN"})

# Statuses whose compiled bytes equal the target (RELOC after relocation
# masking), in canonical display order.  PROVEN is semantic equivalence
# with differing bytes and is deliberately absent.
MATCHED_STATUSES: tuple[str, ...] = ("EXACT", "RELOC")

# Statuses that record work a reverser would lose: a byte match, or a PROVEN
# result (no byte match, but only a new prove run restores it).  Callers that
# protect earned work — orphan pruning, size-fix partitions, lint E017, the
# proof queue — read this instead of re-spelling ``("EXACT", "RELOC",
# "PROVEN")`` at each site.
EARNED_STATUSES: tuple[str, ...] = (*MATCHED_STATUSES, "PROVEN")

# Machine verdicts a failing *tool* produced rather than a byte comparison:
# the compile/extract run errored, the source file is gone, or the VA is not
# addressable.  None of them says the source stopped matching, and all of
# them are transient, so they may not overwrite :data:`EARNED_STATUSES` — a
# missing compiler must not cost a reverser a byte match.  They remain the
# honest verdict over a STUB, NEAR_MATCHING or empty status, where nothing
# earned is at stake.  INTERNAL_ERROR is a crash in the tooling itself:
# verify never persists it as a function status, but it appears in cached
# verify results, so callers that read those must treat it the same way.
INFRASTRUCTURE_STATUSES: tuple[str, ...] = (
    "COMPILE_ERROR",
    "EXTRACT_ERROR",
    "MISSING_FILE",
    "INVALID_VA",
    "INTERNAL_ERROR",
)

# Machine verdicts that only mean "this stub has no real body yet": a
# documented STUB keeps its classification instead of being demoted to one of
# these.  Both the writer's promotion policy
# (``metadata.should_promote_status``) and the status overlay
# (``status.effective_status``) read this, so the two cannot disagree about
# which verdicts count as a placeholder.
STUB_PLACEHOLDER_STATUSES: tuple[str, ...] = ("SIZE_MISMATCH", "MISSING_SIZE")

# Statuses of a function that has a real body whose bytes do not match yet.
# A blocker-documented STUB joins them case by case: it is parked at a wall,
# not unwritten.  ``rebrew prove`` (the entry gate and the batch candidate
# scan) and ``rebrew diagnose near --fix-blocker`` (the classification target
# scan) all read this, so a status added to one and not the other cannot
# leave the two tools disagreeing about which functions are worth work.
NEAR_MATCH_CANDIDATE_STATUSES: tuple[str, ...] = ("NEAR_MATCHING", "SIZE_MISMATCH")

# Statuses whose match percentage is a real fuzzy measure rather than 0 or
# 100: NEAR_MATCHING is a measured partial match, PROVEN is a measured
# equivalence.  ``rebrew coverage report`` (per-unit fuzzy code) and ``rebrew todo``
# (delta fallback when no verify row exists) read this; a byte match is
# :data:`MATCHED_STATUSES` and is excluded.
FUZZY_STATUSES: tuple[str, ...] = ("NEAR_MATCHING", "PROVEN")
