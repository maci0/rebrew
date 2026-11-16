"""jump_table.py — recognise a jump-table switch dispatch in decoded x86.

Shared by ``rebrew binary switches`` (``rebrew.switch``) and the CFG view
(``rebrew.cfg_ged``): the dispatch ``jmp`` operand form and the bounds check
before it.  Works on capstone instructions; reads no bytes.
"""

from __future__ import annotations

import re
lazy from typing import Any

lazy from rebrew.utils import parse_int_literal

#: Maximum table entries to read (the bounds-check count normally bounds it;
#: this is a safety cap against misreading a data region as a giant table).
MAX_TABLE_ENTRIES = 256

#: Instructions searched back from a dispatch ``jmp`` for its bounds check.
BOUND_WINDOW = 8

#: ``jmp dword ptr [edx*4 + 0x12345678]`` — capstone renders the scaled
#: index before the base for ``[base + index*4]`` operands.  64-bit targets
#: use ``qword ptr [reg*8 + addr]``; 16-bit targets have no SIB byte so the
#: dispatch is ``word ptr [base + addr]`` (index doubled into the base with
#: ``add reg,reg``/``shl reg,1`` beforehand).
_INDIRECT_JMP_RE = re.compile(
    r"(dword|qword) ptr \[([a-z0-9]+)\s*\*\s*([48])\s*\+\s*0x([0-9a-fA-F]+)\]"
)
_INDIRECT_JMP_BASE_RE = re.compile(r"word ptr \[([a-z]+)\s*\+\s*0x([0-9a-fA-F]+)\]")

#: ``cmp ecx, 0xb`` — the bounds check preceding the dispatch.  The right-hand
#: operand must be a numeric literal (`0x...` or decimal); a register operand
#: (`cmp ecx, edx`) is not a bound, and the old `([0-9a-fA-F]+)` read its hex
#: digit prefix as an immediate (`ed` -> 0xed), inflating the table bound and
#: pulling unrelated handler addresses into the case list.
_CMP_IMM_RE = re.compile(r"([a-z0-9]+),\s*(0x[0-9a-fA-F]+|\d+)\s*$")

#: ``and eax, 3`` / ``and rax, 3`` — a register-index mask used as a bounds
#: check by MSVC's memcpy/memmove byte-tail dispatches
#: (``and reg, N; jmp [reg*scale + table]``).  The register is checked
#: against the table index afterwards, so the name is any register, not only
#: the 32-bit set: a 64-bit ``and rax, 3`` is the same bound.
_MASK_RE = re.compile(r"^([a-z0-9]+),\s*(?:0x)?([0-9a-fA-F]+)$")


#: Unsigned below/not-below jumps: after ``cmp reg, N`` either one leaves the
#: dispatch path with ``reg < N`` (``jb`` taken to it, ``jae`` taken away),
#: so the highest index is ``N - 1``; ``ja``/``jbe`` leave ``reg <= N``.
_BELOW_GUARDS = frozenset({"jb", "jc", "jnae", "jae", "jnb", "jnc"})


def _is_index_mask(value: int) -> bool:
    """True when *value* is a power-of-two-minus-1 (1, 3, 7, 15, ...).

    A register index mask bounds a jump-table index; a non-mask ``and reg, N``
    (e.g. a flag test like ``and eax, 0x40``) must not be read as a bound.
    """
    return value >= 1 and (value & (value + 1)) == 0


def dispatch_operand(op_str: str, entry_width: int) -> tuple[str | None, int] | None:
    """``(index register, table VA)`` of a jump-table ``jmp`` operand, else ``None``.

    *entry_width* is the target's table entry size: the scaled form must use
    it as its scale, and the base-only 16-bit form is accepted only at 2.
    """
    m = _INDIRECT_JMP_RE.search(op_str)
    if m is not None:
        if int(m.group(3)) != entry_width:
            return None  # scale does not match the target arch
        return m.group(2), int(m.group(4), 16)
    if entry_width == 2:
        b = _INDIRECT_JMP_BASE_RE.search(op_str)
        if b is not None:
            return b.group(1), int(b.group(2), 16)
    return None


def index_bound(window: list[Any], index_reg: str | None) -> int | None:
    """Highest switch index the instructions in *window* allow, else ``None``.

    *window* is the up to ``BOUND_WINDOW`` instructions before the dispatch.
    The bound is the nearest preceding ``cmp reg, N`` with a small immediate
    (``N - 1`` when ``jb``/``jae`` tests it: the index is below ``N``),
    where the compared register feeds *index_reg* (MSVC copies the index into
    the scaled register between the cmp and the jmp, so the check walks back
    through mov reg-reg copies).  A compare on an unrelated register (an
    address compare, not a switch bound) is rejected, as is a large
    immediate.  MSVC's memcpy/memmove byte-tail dispatches bound the index
    with ``and reg, mask`` instead, so a power-of-two-minus-1 mask on
    *index_reg* is a bound too.  Nearest-first: an earlier compare on the
    index register (a range check before the switch) must not override the
    switch's own bound.
    """
    copies = _index_source_regs(window, index_reg)
    for k in range(len(window) - 1, -1, -1):
        prev = window[k]
        if prev.mnemonic == "cmp":
            cm = _CMP_IMM_RE.search(prev.op_str)
            if cm is None or cm.group(1) not in copies:
                continue
            try:
                value = parse_int_literal(cm.group(2))
            except ValueError:
                continue
            if 0 <= value <= 0xFFFF:
                below = k + 1 < len(window) and window[k + 1].mnemonic in _BELOW_GUARDS
                if below and value == 0:
                    continue
                return value - 1 if below else value
        elif prev.mnemonic == "and":
            am = _MASK_RE.match(prev.op_str)
            if am is None or am.group(1) != index_reg:
                continue
            try:
                value = int(am.group(2), 16)
            except ValueError:
                continue
            if _is_index_mask(value):
                return value
    return None


_MOV_REG_RE = re.compile(r"^([a-z0-9]+),\s*([a-z0-9]+)$")


def _index_source_regs(window: list[Any], index_reg: str | None) -> set[str]:
    """Registers that may hold the switch index at the dispatch.

    Starts from the scaled *index_reg* and walks the window backward
    through plain ``mov dst, src`` copies, so a bounds ``cmp`` on the
    pre-copy register (``cmp ecx, N`` … ``mov edx, ecx`` … ``jmp
    [edx*4+table]``) is accepted while a compare on an unrelated
    register is not.  ``None`` index (16-bit base form) accepts nothing.
    """
    if not index_reg:
        return set()
    sources = {index_reg}
    for prev in reversed(window):
        if prev.mnemonic != "mov":
            continue
        m = _MOV_REG_RE.match(prev.op_str)
        if m is None or m.group(1) not in sources:
            continue
        sources.add(m.group(2))
    return sources
