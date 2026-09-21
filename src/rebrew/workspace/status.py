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

# Statuses that count as matched work (byte-identical or proven-equivalent),
# in canonical display order.
MATCHED_STATUSES: tuple[str, ...] = ("EXACT", "RELOC", "PROVEN")
