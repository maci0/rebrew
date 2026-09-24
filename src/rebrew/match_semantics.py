"""match_semantics.py — shared effective-match classification.

The "effective match" rule (reccmp's 100% class: every real delta byte is
register allocation, possibly plus encoding choice — same instructions, not
byte-identical) was classified independently in ``verify`` (structural-diff
summary) and ``near_diag`` (byte-count histogram).  This module is the one
classifier both call: one rule, one note string, no drift.
"""

from __future__ import annotations

#: Shared explanation appended to verify messages / near-diag suggestions.
EFFECTIVE_MATCH_NOTE = (
    "effective match: differs only in register allocation — not "
    "byte-identical; reccmp counts this as 100% (run 'rebrew prove' for "
    "PROVEN, or register-nudging C tweaks for byte-identity)"
)


def is_effective_match(
    *,
    structural: int = 0,
    register: int = 0,
    equivalent: int = 0,
) -> bool:
    """True when the delta is pure register allocation.

    Callers count bytes (or diff rows) per category; anything structural or
    instruction-selection-flavored (`equivalent`) disqualifies the pair.
    """
    return structural == 0 and equivalent == 0 and register > 0
