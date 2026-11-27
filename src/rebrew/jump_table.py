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


def dispatch_operand_insn(insn: Any, entry_width: int) -> tuple[str | None, int] | None:
    """``(index register, table VA)`` of a jump-table ``jmp`` via Capstone detail."""
    from capstone.x86 import X86_OP_MEM, X86_REG_INVALID

    ops = getattr(insn, "operands", None)
    if not ops or len(ops) != 1 or ops[0].type != X86_OP_MEM:
        return dispatch_operand(insn.op_str, entry_width)
    op = ops[0]
    mem = op.mem
    if op.size != entry_width or mem.disp <= 0:
        return None
    if entry_width in (4, 8):
        if (
            mem.base == X86_REG_INVALID
            and mem.index != X86_REG_INVALID
            and mem.scale == entry_width
        ):
            return str(insn.reg_name(mem.index)), int(mem.disp) & ((1 << (entry_width * 8)) - 1)
        return None
    if entry_width == 2 and mem.base != X86_REG_INVALID and mem.index == X86_REG_INVALID:
        return str(insn.reg_name(mem.base)), int(mem.disp) & 0xFFFF
    return None


def _insn_reg_imm(insn: Any) -> tuple[str, int] | None:
    """``(reg_name, imm)`` from Capstone detail operands when available."""
    try:
        ops = insn.operands
    except Exception:
        return None
    from capstone.x86 import X86_OP_IMM, X86_OP_REG

    if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
        return str(insn.reg_name(ops[0].reg)), int(ops[1].imm)
    return None


def _insn_reg_reg(insn: Any) -> tuple[str, str] | None:
    """``(dst_reg, src_reg)`` from Capstone detail operands when available."""
    try:
        ops = insn.operands
    except Exception:
        return None
    from capstone.x86 import X86_OP_REG

    if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
        return str(insn.reg_name(ops[0].reg)), str(insn.reg_name(ops[1].reg))
    return None


def index_bound(window: list[Any], index_reg: str | None) -> int | None:
    """Highest switch index the instructions in *window* allow, else ``None``.

    Uses Capstone ``detail=True`` operands when populated, falling back to
    text parsing for ``disasm_lite``/mock instructions.
    """
    copies = _index_source_regs(window, index_reg)
    for k in range(len(window) - 1, -1, -1):
        prev = window[k]
        if prev.mnemonic == "cmp":
            pair = _insn_reg_imm(prev)
            if pair is not None:
                reg, value = pair
            else:
                cm = _CMP_IMM_RE.search(prev.op_str)
                if cm is None:
                    continue
                try:
                    reg, value = cm.group(1), parse_int_literal(cm.group(2))
                except ValueError:
                    continue
            if reg not in copies:
                continue
            if 0 <= value <= 0xFFFF:
                below = k + 1 < len(window) and window[k + 1].mnemonic in _BELOW_GUARDS
                if below and value == 0:
                    continue
                return value - 1 if below else value
        elif prev.mnemonic == "and":
            pair = _insn_reg_imm(prev)
            if pair is not None:
                reg, value = pair
            else:
                am = _MASK_RE.match(prev.op_str)
                if am is None:
                    continue
                try:
                    reg, value = am.group(1), int(am.group(2), 16)
                except ValueError:
                    continue
            if reg != index_reg:
                continue
            if _is_index_mask(value):
                return value
    return None


_MOV_REG_RE = re.compile(r"^([a-z0-9]+),\s*([a-z0-9]+)$")


def _index_source_regs(window: list[Any], index_reg: str | None) -> set[str]:
    """Registers that may hold the switch index at the dispatch."""
    if not index_reg:
        return set()
    sources = {index_reg}
    for prev in reversed(window):
        if prev.mnemonic != "mov":
            continue
        pair = _insn_reg_reg(prev)
        if pair is not None:
            dst, src = pair
        else:
            m = _MOV_REG_RE.match(prev.op_str)
            if m is None:
                continue
            dst, src = m.group(1), m.group(2)
        if dst in sources:
            sources.add(src)
    return sources
