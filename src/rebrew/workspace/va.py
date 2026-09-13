"""Virtual-address candidate parsing shared by the coverage consumers."""

from __future__ import annotations

import contextlib

#: Upper bound for client-supplied VA integers.  SQLite INTEGER is a SIGNED
#: 64-bit value: anything larger raises OverflowError at execute time, which
#: would surface as an uncaught 500 instead of a clean 4xx/404.  No stored va
#: can exceed this, so rejecting above it can never hide a real match.
VA_MAX = (1 << 63) - 1

_HEX_DIGITS = "abcdef"


def parse_va_candidates(raw: str) -> list[int]:
    """Parse *raw* into deduped candidate lookup ints, order preserved.

    One parser for every surface that resolves a VA spelling.  Hex spellings
    are ``0x``-prefixed or contain ``a-f`` (bare hex valid).  All-digit strings
    are read DECIMAL first, with a bare-hex fallback for legacy callers.
    Candidates beyond SQLite's signed-64-bit range are dropped, since passing
    one raises OverflowError at execute time instead of a clean miss.
    Negatives stay candidates so section-bounds classification can report
    "before section start".
    """
    lowered = raw.lower()
    bases = (
        (16,) if lowered.startswith("0x") or any(c in _HEX_DIGITS for c in lowered) else (10, 16)
    )
    candidates: list[int] = []
    for base in bases:
        with contextlib.suppress(ValueError):
            parsed = int(raw, base)
            if parsed <= VA_MAX and parsed not in candidates:
                candidates.append(parsed)
    return candidates
