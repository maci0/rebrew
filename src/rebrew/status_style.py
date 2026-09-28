"""How a status is painted, per surface.

The status *vocabulary* is owned by :mod:`rebrew.workspace.status`.  This
module owns only the presentation of that vocabulary: the Rich colour tag the
terminal tools print, the hex mark the report, dashboard and call graph fill
with, the canonical display order, and the grouping the report stylesheet and
dashboard shell iterate to colour body text.

It is a leaf, importing nothing from rebrew but the status vocabulary and the
chrome tokens, so any surface can read a mark without pulling in the Typer
toolkit or the analysis engine that produced the status.
"""

from __future__ import annotations

from rebrew.theme import TOKENS
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
# STUB is a neutral grey, like the dim terminal tag, not an error red.
# DISPATCH is the chrome ink token: a jump table is structure, not a match
# status.
#
# The marks are hand-picked, not a framework ramp. Two decisions carry the
# set, and both follow ``rebrew.theme``:
#
# * Warm, like the chrome neutrals. The mascot is a brass machine in a leather
#   harness under phosphor green, so the amber, the red and the three greys
#   lean warm; a cool slate grey beside ``#f7f4ef`` reads as a different
#   product.
# * No mark in the accent's hue. ``TOKENS["accent"]`` is the one cold value on
#   these surfaces and it is reserved for links and focus rings, so a row
#   painted in that blue reads as clickable and a link reads as a verdict.
#   The two cool marks are teal and a blue-shifted teal, 59 deltaE from the
#   accent and 19 from each other; the loud marks sit 19 or more apart, and
#   STUB/SKIP/UNKNOWN are a deliberate warm ladder (dark to light: a stub is
#   written down, an unknown is not) rather than three unrelated greys.
#
# ``tests/test_theme`` holds every mark to 4.5:1 on both surfaces, and white on
# the fill to 4.5:1 for the graph, so the retune costs no contrast.
#
# Every KNOWN_STATUS has a mark: the report table, the dashboard cards and
# the call-graph labels all emit ``status-<STATUS>`` for whatever STATUS a
# row carries, so a machine verdict (COMPILE_ERROR, MISSING_SIZE, ...) with
# no entry here renders as unstyled body ink while the terminal paints it
# red (STATUS_COLORS above).  Both tables cover the same vocabulary.
STATUS_HEX: dict[str, str] = {
    "EXACT": "#1a6b3c",
    "RELOC": "#0f6a5f",
    "PROVEN": "#146b7d",
    "NEAR_MATCHING": "#a35a06",
    "SIZE_MISMATCH": "#7c3a11",
    "STUB": "#3f3a33",
    "COMPILE_ERROR": "#a3221f",
    "EXTRACT_ERROR": "#a3221f",
    "MISSING_FILE": "#a3221f",
    "MISSING_SIZE": "#a3221f",
    "INVALID_VA": "#a3221f",
    "INTERNAL_ERROR": "#a3221f",
    "SKIP": "#585249",
    "UNKNOWN": "#736d64",
    "DISPATCH": TOKENS["ink"],
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
