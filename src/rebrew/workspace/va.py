"""Virtual-address candidate parsing shared by the coverage consumers."""

from __future__ import annotations

lazy import contextlib

#: Bounds for client-supplied VA integers: the signed 64-bit range the
#: retired SQLite writer enforced and ``coverage_db._SQLITE_INT_MAX`` still
#: clamps to.  No stored va can exceed them, so rejecting outside them can
#: never hide a real match.
VA_MAX = (1 << 63) - 1
VA_MIN = -(1 << 63)

_HEX_DIGITS = "abcdef"


def parse_va_candidates(raw: str) -> list[int]:
    """Parse *raw* into deduped candidate lookup ints, order preserved.

    One parser for every surface that resolves a VA spelling.  Hex spellings
    are ``0x``-prefixed or contain ``a-f`` (bare hex valid).  All-digit strings
    are read DECIMAL first, with a bare-hex fallback for legacy callers.
    Candidates outside the signed-64-bit range are dropped, matching what
    :data:`rebrew.coverage_db._SQLITE_INT_MAX` accepts as a storable va.
    Negatives stay candidates so section-bounds classification can report
    "before section start".  Underscores are rejected, matching
    :func:`rebrew.utils.parse_int_literal`: ``int()`` would read ``"1_0"`` as
    ten, a VA nobody wrote.
    """
    if "_" in raw:
        return []
    # int() also reads Unicode decimal digits (e.g. "١٢" as 12); only ASCII
    # counts, matching _parse_ascii_int in rebrew.utils.
    if not raw.isascii():
        return []
    lowered = raw.lower()
    bases = (
        (16,) if lowered.startswith("0x") or any(c in _HEX_DIGITS for c in lowered) else (10, 16)
    )
    candidates: list[int] = []
    for base in bases:
        with contextlib.suppress(ValueError):
            parsed = int(raw, base)
            if VA_MIN <= parsed <= VA_MAX and parsed not in candidates:
                candidates.append(parsed)
    return candidates
