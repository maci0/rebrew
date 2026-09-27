"""How a status is painted, per surface.

The status *vocabulary* is owned by :mod:`rebrew.workspace.status`.  This
module owns only the presentation of that vocabulary: the Rich colour tag the
terminal tools print, the hex mark the report, dashboard and call graph fill
with, the canonical display order, and the grouping the report stylesheet and
dashboard shell iterate to colour body text.

It is a leaf, importing nothing from rebrew but the vocabulary, so any surface
can read a mark without pulling in the Typer toolkit or the analysis engine
that produced the status.
"""

from __future__ import annotations

from rebrew.workspace.status import MATCHED_STATUSES

# Canonical Rich colour tags for status strings, used across CLI tools for
# consistent output formatting.
STATUS_COLORS: dict[str, str] = {
    "EXACT": "bold green",
    "RELOC": "green",
    "PROVEN": "bold cyan",
    "NEAR_MATCHING": "yellow",
    "SIZE_MISMATCH": "yellow",
    "STUB": "dim",
    "COMPILE_ERROR": "red",
    "EXTRACT_ERROR": "red",
    "MISSING_FILE": "red",
    "MISSING_SIZE": "red",
    "INVALID_VA": "red",
    "INTERNAL_ERROR": "red",
    "SKIP": "dim",
}

# Page and call-graph marks for the same statuses. Text on white (report,
# dashboard) and white on the fill (Mermaid, DOT) both meet WCAG AA.
# STUB is slate, like the dim terminal tag, not an error red. DISPATCH is
# the report header ink: a jump table is structure, not a match status.
# Every KNOWN_STATUS has a mark: the report table, the dashboard cards and
# the call-graph labels all emit ``status-<STATUS>`` for whatever STATUS a
# row carries, so a machine verdict (COMPILE_ERROR, MISSING_SIZE, ...) with
# no entry here renders as unstyled body ink while the terminal paints it
# red (STATUS_COLORS above).  Both tables cover the same vocabulary.
STATUS_HEX: dict[str, str] = {
    "EXACT": "#15803d",
    "RELOC": "#0369a1",
    "PROVEN": "#0e7490",
    "NEAR_MATCHING": "#b45309",
    "SIZE_MISMATCH": "#92400e",
    "STUB": "#475569",
    "COMPILE_ERROR": "#b91c1c",
    "EXTRACT_ERROR": "#b91c1c",
    "MISSING_FILE": "#b91c1c",
    "MISSING_SIZE": "#b91c1c",
    "INVALID_VA": "#b91c1c",
    "INTERNAL_ERROR": "#b91c1c",
    "SKIP": "#556070",
    "UNKNOWN": "#555",
    "DISPATCH": "#1a1a1a",
}

# User-visible classification statuses, in canonical display order: the
# byte-matched ones, then PROVEN (semantically equivalent, bytes differ),
# then the unmatched ones.
DISPLAY_STATUSES: tuple[str, ...] = (*MATCHED_STATUSES, "PROVEN", "NEAR_MATCHING", "STUB")


def status_mark_groups() -> list[tuple[tuple[str, ...], str]]:
    """Return ``STATUS_HEX`` text marks grouped by colour, in table order.

    Each entry is ``(statuses, color)`` listing every status that shares one
    mark.  The report stylesheet, the dashboard shell and their forced-colors
    override all iterate this, so the six machine verdicts on the error red
    cost one rule instead of six.  DISPATCH is left out: it is a graph fill,
    never body text.
    """
    groups: dict[str, list[str]] = {}
    for status, color in STATUS_HEX.items():
        if status == "DISPATCH":
            continue
        groups.setdefault(color, []).append(status)
    return [(tuple(v), k) for k, v in groups.items()]


__all__ = [
    "DISPLAY_STATUSES",
    "STATUS_COLORS",
    "STATUS_HEX",
    "status_mark_groups",
]
