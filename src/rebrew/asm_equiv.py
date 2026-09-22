"""asm_equiv.py — instruction-equivalence checks beyond register masking.

Adapted from reccmp (isledecomp/reccmp, MIT License)
``compare/asm/fixes.py``.

Detects compiler choices that are semantically identical but not caught by
register normalization: a flipped ``cmp`` operand order paired with the
mirrored conditional jump, swapped operands of a ``mov`` + commutative op,
and the ``fld``/``fmul`` source swap.  ``near_diag`` uses these to classify
spans as ``equivalent`` instead of ``structural``, so a function whose only
delta is a flipped comparison is reported as an instruction-selection
difference, not layout churn.
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

_COMMUTATIVE_MNEMONICS = ("add", "and", "or", "xor", "imul")


def _mnemonic(inst: str) -> str:
    """The mnemonic of a ``"mnemonic operands"`` text line."""
    if not inst:
        return ""
    return inst.split(" ", 1)[0].lower()


def _split_operands(inst: str) -> list[str]:
    """Comma-split operand list of a text instruction line."""
    _, _, operand_str = inst.partition(" ")
    return [o.strip() for o in operand_str.split(",") if o.strip()]


def jump_swap_ok(a: str, b: str) -> bool:
    """True when a, b are both jumps compatible with a swapped cmp operand order."""
    (jmp_a, *_) = a.partition(" ")
    (jmp_b, *_) = b.partition(" ")
    return (jmp_a.lower(), jmp_b.lower()) in ALLOWED_JUMP_SWAPS


def is_operand_swap(a: str, b: str) -> bool:
    """True when a and b are the same instruction with operands flipped.

    A cheap text check (reccmp's "hack" to avoid full operand parsing):
    the first operand must differ and both strings must use the exact same
    character multiset — templates and string literals make naive
    comma-splitting unreliable.
    """
    return a.partition(", ")[0] != b.partition(", ")[0] and sorted(a) == sorted(b)


def get_patched_jump(a: str, b: str) -> str:
    """``(mnemonic_a) (operand_b)`` — the jump *b* with *a*'s condition.

    The operand (label/displacement) is kept from *b*: replacing b's
    mnemonic only must not erase a genuine displacement difference.
    """
    mnemonic_a, _, _ = a.partition(" ")
    _, _, operand_b = b.partition(" ")
    return mnemonic_a + " " + operand_b


def patch_cmp_jmp(orig: list[str], recomp: list[str], cmp_instruction: str = "cmp") -> set[int]:
    """Detect the swapped-compare + mirrored-jump pattern.

    ``cmp eax, ebx`` / ``je L`` vs ``cmp ebx, eax`` / ``je L`` (or a
    mirrored ``ja``/``jb``).  Returns the orig line indices explained by
    the swap, or an empty set.
    """
    cmp_index = next((i for i, s in enumerate(orig) if _mnemonic(s) == cmp_instruction), -1)
    if (
        cmp_index in (-1, len(orig) - 1)
        or cmp_index >= len(recomp) - 1
        or _mnemonic(recomp[cmp_index]) != cmp_instruction
        or not jump_swap_ok(orig[cmp_index + 1], recomp[cmp_index + 1])
    ):
        return set()
    if is_operand_swap(orig[cmp_index], recomp[cmp_index]) and orig[cmp_index + 1] == (
        get_patched_jump(orig[cmp_index + 1], recomp[cmp_index + 1])
    ):
        return {cmp_index, cmp_index + 1}
    return set()


def patch_mov_cmp_jmp(orig: list[str], recomp: list[str], cmp_instruction: str = "cmp") -> set[int]:
    """Detect ``mov`` + swapped ``cmp`` + mirrored jump across three lines.

    The register loaded by the mov and the one compared are exchanged as a
    pair (same character multiset across the two lines); the jump is the
    mirrored condition.  Returns orig line indices or an empty set.
    """
    cmp_index = next((i for i, s in enumerate(orig) if _mnemonic(s) == cmp_instruction), -1)
    if (
        cmp_index in (-1, 0, len(orig) - 1)
        or cmp_index >= len(recomp) - 1
        or _mnemonic(recomp[cmp_index]) != cmp_instruction
        or _mnemonic(orig[cmp_index - 1]) != "mov"
        or _mnemonic(recomp[cmp_index - 1]) != "mov"
        or not jump_swap_ok(orig[cmp_index + 1], recomp[cmp_index + 1])
    ):
        return set()
    if sorted(orig[cmp_index - 1] + orig[cmp_index]) == sorted(
        recomp[cmp_index - 1] + recomp[cmp_index]
    ) and orig[cmp_index + 1] == get_patched_jump(orig[cmp_index + 1], recomp[cmp_index + 1]):
        return {0, 1, 2}
    return set()


def patch_mov_commutative(orig: list[str], recomp: list[str]) -> set[int]:
    """Detect swapped sources across ``mov`` + commutative op (add/and/or/xor/imul).

    Both versions write the same destination register; the mov's source and
    the op's second operand are exchanged.  Returns orig line indices or an
    empty set.
    """
    inst_index = next((i for i, s in enumerate(orig) if _mnemonic(s) in _COMMUTATIVE_MNEMONICS), -1)
    if inst_index in (-1, 0) or inst_index >= len(recomp):
        return set()
    if (
        _mnemonic(recomp[inst_index]) != _mnemonic(orig[inst_index])
        or _mnemonic(orig[inst_index - 1]) != "mov"
        or _mnemonic(recomp[inst_index - 1]) != "mov"
    ):
        return set()
    orig_mov_ops = _split_operands(orig[inst_index - 1])
    recomp_mov_ops = _split_operands(recomp[inst_index - 1])
    orig_ops = _split_operands(orig[inst_index])
    recomp_ops = _split_operands(recomp[inst_index])
    if any(len(o) != 2 for o in (orig_mov_ops, recomp_mov_ops, orig_ops, recomp_ops)):
        return set()
    mov_dest = orig_mov_ops[0].lower()
    if mov_dest != recomp_mov_ops[0].lower() or mov_dest not in (
        orig_ops[0].lower(),
        recomp_ops[0].lower(),
    ):
        return set()
    layout_ok = orig_ops[0].lower() == mov_dest and recomp_ops[0].lower() == mov_dest
    swap_ok = orig_ops[1] == recomp_mov_ops[1] and recomp_ops[1] == orig_mov_ops[1]
    return {inst_index - 1, inst_index} if layout_ok and swap_ok else set()


def patch_fld_fmul(orig: list[str], recomp: list[str]) -> set[int]:
    """Detect swapped ``fld``/``fmul`` (or ``fadd``) memory sources.

    ``fld [a]`` + ``fmul [b]`` vs ``fld [b]`` + ``fmul [a]``.  Returns orig
    line indices or an empty set.
    """
    fld_index = next((i for i, s in enumerate(orig) if _mnemonic(s) == "fld"), -1)
    if (
        fld_index in (-1, len(orig) - 1)
        or fld_index >= len(recomp) - 1
        or _mnemonic(recomp[fld_index]) != "fld"
    ):
        return set()
    _, _, orig_op_a = orig[fld_index].partition(" ")
    orig_mnem_b, _, orig_op_b = orig[fld_index + 1].partition(" ")
    _, _, recomp_op_a = recomp[fld_index].partition(" ")
    recomp_mnem_b, _, recomp_op_b = recomp[fld_index + 1].partition(" ")
    if (
        orig_mnem_b in ("fmul", "fadd")
        and orig_mnem_b == recomp_mnem_b
        and orig_op_a == recomp_op_b
        and orig_op_b == recomp_op_a
    ):
        return {fld_index, fld_index + 1}
    return set()
