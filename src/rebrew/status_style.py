"""How a status is painted, per surface.

The status *vocabulary* is owned by :mod:`rebrew.workspace.status`.  This
module owns only the presentation of that vocabulary: the Rich colour tag the
terminal tools print, the hex mark the report, dashboard and call graph fill
with, the canonical display order, and the grouping the report stylesheet and
dashboard shell iterate to colour body text.

It is a leaf, importing only the status vocabulary, brand colors and the
chrome tokens, so any surface can read a mark without pulling in the Typer
toolkit or the analysis engine that produced the status.
"""

from __future__ import annotations

from rebrew.status_colors import LIGHT, TERMINAL
from rebrew.theme import TOKENS
from rebrew.workspace.status import MATCHED_STATUSES

# Canonical Rich colour tags for status strings, used across CLI tools for
# consistent output formatting.
STATUS_COLORS: dict[str, str] = {
    "LIBRARY": TERMINAL["library"],
    "EXACT": f"bold {TERMINAL['exact']}",
    "RELOC": TERMINAL["reloc"],
    "PROVEN": f"bold {TERMINAL['proven']}",
    "NEAR_MATCHING": TERMINAL["near"],
    "SIZE_MISMATCH": TERMINAL["fail"],
    "STUB": TERMINAL["stub"],
    "COMPILE_ERROR": TERMINAL["fail"],
    "EXTRACT_ERROR": TERMINAL["fail"],
    "MISSING_FILE": TERMINAL["fail"],
    "MISSING_SIZE": TERMINAL["fail"],
    "INVALID_VA": TERMINAL["fail"],
    "INTERNAL_ERROR": TERMINAL["fail"],
    "SKIP": TERMINAL["stub"],
}

# Web words follow the approved brand palette. Graphs use the same words as
# fills with white labels; all marks clear AA on the report's warm surfaces.
# Related green/blue families carry explicit status labels, and links stay
# underlined. LIBRARY is origin attribution, not a comparison status.
STATUS_HEX: dict[str, str] = {
    "LIBRARY": LIGHT["library"],
    "EXACT": LIGHT["exact"],
    "RELOC": LIGHT["reloc"],
    "PROVEN": LIGHT["proven"],
    "NEAR_MATCHING": LIGHT["near"],
    "SIZE_MISMATCH": LIGHT["fail"],
    "STUB": LIGHT["stub"],
    "COMPILE_ERROR": LIGHT["fail"],
    "EXTRACT_ERROR": LIGHT["fail"],
    "MISSING_FILE": LIGHT["fail"],
    "MISSING_SIZE": LIGHT["fail"],
    "INVALID_VA": LIGHT["fail"],
    "INTERNAL_ERROR": LIGHT["fail"],
    "SKIP": "#616873",
    "UNKNOWN": "#636a73",
    "DISPATCH": TOKENS["ink"],
}

# User-visible classification statuses, in canonical display order: the
# byte-matched ones, then PROVEN (semantically equivalent, bytes differ),
# then the unmatched ones.
DISPLAY_STATUSES: tuple[str, ...] = (*MATCHED_STATUSES, "PROVEN", "NEAR_MATCHING", "STUB")

#: One line per status for a reader who has the token in front of them and not
#: the vocabulary behind it.  The report prints these tokens in a summary card
#: and a table cell on every page, where nothing else names them; ``docs/
#: MATCH_TYPES.md`` is the long form, and a static page cannot link a local
#: checkout to it.  Kept to one sentence each, and to the verdict rather than
#: the mechanism: what the token says about the function, not which command
#: wrote it.
STATUS_SUMMARIES: dict[str, str] = {
    "EXACT": "Compiled bytes match the target exactly.",
    "RELOC": "Compiled bytes match after relocation masking.",
    "PROVEN": "Proven semantically equal; the bytes still differ.",
    "NEAR_MATCHING": "60% or more of the bytes match; the structure still differs.",
    "STUB": "A placeholder: no source, or a rewrite is needed.",
    "UNKNOWN": "In the catalog, but no source file exists yet.",
    "SKIP": "Parked on purpose; not expected to match.",
    "SIZE_MISMATCH": "The source compiles to a different length than the target.",
    "COMPILE_ERROR": "The source did not compile.",
    "EXTRACT_ERROR": "The object file could not be read back.",
    "MISSING_SIZE": "No target size is recorded, so no comparison is possible.",
    "MISSING_FILE": "The recorded source file is gone.",
    "INVALID_VA": "The address is not a valid one for this binary.",
}

#: Every status a legend can name, in the order a reader works through them:
#: matched first, then the ones that are close, then the stubs, then the
#: machine verdicts that say nothing about the bytes.
STATUS_LEGEND_ORDER: tuple[str, ...] = (
    *DISPLAY_STATUSES,
    "UNKNOWN",
    "SKIP",
    "SIZE_MISMATCH",
    "COMPILE_ERROR",
    "EXTRACT_ERROR",
    "MISSING_SIZE",
    "MISSING_FILE",
    "INVALID_VA",
)


def status_legend_rows(statuses: set[str]) -> list[tuple[str, str]]:
    """``(status, one-line meaning)`` for the *statuses* that have one.

    Ordered by :data:`STATUS_LEGEND_ORDER`, so two reports list the same
    statuses the same way.  A status with no summary (a hand-edited metadata
    file, a newer tool) is left out rather than given a placeholder, and a
    token the vocabulary does not know keeps its raw spelling in the table
    where the reader met it.
    """
    return [
        (status, STATUS_SUMMARIES[status])
        for status in STATUS_LEGEND_ORDER
        if status in statuses and status in STATUS_SUMMARIES
    ]


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
    "STATUS_LEGEND_ORDER",
    "STATUS_SUMMARIES",
    "status_legend_rows",
    "status_mark_groups",
]
