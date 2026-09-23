"""asm_equiv.py — instruction-equivalence checks beyond register masking.

Adapted from reccmp (isledecomp/reccmp, MIT License)
``compare/asm/fixes.py``.

Detects a flipped ``cmp`` operand order paired with the mirrored
conditional jump, which register normalization does not catch.
``near_diag`` uses it to classify spans as ``equivalent`` instead of
``structural``, so a function whose only delta is a flipped comparison is
reported as an instruction-selection difference, not layout churn.
"""

from __future__ import annotations

# Jump-mnemonic pairs compatible with a swapped cmp operand order.
ALLOWED_JUMP_SWAPS: tuple[tuple[str, str], ...] = (
    ("ja", "jb"),
    ("jae", "jbe"),
    ("jb", "ja"),
    ("jbe", "jae"),
    ("jg", "jl"),
    ("jge", "jle"),
    ("jl", "jg"),
    ("jle", "jge"),
    ("je", "je"),
    ("jne", "jne"),
)


def jump_swap_ok(a: str, b: str) -> bool:
    """True when a, b are both jumps compatible with a swapped cmp operand order."""
    (jmp_a, *_) = a.partition(" ")
    (jmp_b, *_) = b.partition(" ")
    return (jmp_a.lower(), jmp_b.lower()) in ALLOWED_JUMP_SWAPS
