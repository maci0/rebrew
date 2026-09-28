"""Function status vocabulary shared by the coverage consumers.

Owns the canonical STATUS sets so :mod:`rebrew.workspace` stays free of the
metadata writers.  Prefer importing from here (or :mod:`rebrew.workspace`);
:mod:`rebrew.metadata` re-exports the same names only for callers that
already touch the metadata store.  Reportal's portal status set is a
superset: it also carries ``MATCHED``, the aggregate display label, so
portal statuses are not interchangeable with this tuple.
"""

from __future__ import annotations

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
# earned is at stake.
INFRASTRUCTURE_STATUSES: tuple[str, ...] = (
    "COMPILE_ERROR",
    "EXTRACT_ERROR",
    "MISSING_FILE",
    "INVALID_VA",
)

# Machine verdicts that only mean "this stub has no real body yet": a
# documented STUB keeps its classification instead of being demoted to one of
# these.  Both the writer's promotion policy
# (``metadata.should_promote_status``) and the status overlay
# (``status.effective_status``) read this, so the two cannot disagree about
# which verdicts count as a placeholder.
STUB_PLACEHOLDER_STATUSES: tuple[str, ...] = ("SIZE_MISMATCH", "MISSING_SIZE")
