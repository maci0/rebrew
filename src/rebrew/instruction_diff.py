"""Instruction-level comparison of a function's target bytes and its rebuilt bytes.

Both sides are decoded at the function's VA with the same capstone handle the
``asm`` listing uses, aligned with :class:`rebrew.alignment.AlignedMatcher`
over :func:`rebrew.alignment.normalize_instruction` texts, and each aligned
pair is classified with the relocation masking of the byte verdict: a pair
whose bytes differ only inside the rebuilt side's relocation fields is
``equal`` with ``reloc``.  Operand registers and numbers are marked with
character spans and a ``value`` id shared by both sides.
"""

from __future__ import annotations

import functools
import re
from typing import Any
lazy from collections.abc import Iterable

lazy from rebrew.analysis import Insn
lazy from rebrew.compiler.compile import CompareResult

#: Bytes of each side the comparison decodes; a longer side is cut there and
#: the answer says ``truncated``.
MAX_BYTES = 8192

#: Width of one relocation field: the span ``rebrew test`` masks per offset.
RELOC_FIELD_BYTES = 4

#: Mnemonic of the pseudo-instruction holding bytes that do not decode.
DATA_MNEMONIC = "db"

#: Highest capstone register id probed for register names (every ISA rebrew
#: supports numbers its registers below this).
_MAX_REGISTER_ID = 1024

# A signed number (hex or decimal) or an identifier, as capstone prints operands.
_TOKEN_RE = re.compile(r"-?0x[0-9a-fA-F]+|-?\d+|[A-Za-z_$%][\w.$]*")


@functools.cache
def _register_names(cs_arch: str | int, cs_mode: str | int) -> frozenset[str]:
    from rebrew.analysis import capstone_handle, resolve_capstone

    md = capstone_handle(resolve_capstone(cs_arch), resolve_capstone(cs_mode))
    names = (md.reg_name(reg) for reg in range(1, _MAX_REGISTER_ID))
    return frozenset(name.lower() for name in names if name)


def _decode(code: bytes, va: int, cs_arch: str | int, cs_mode: str | int) -> list[Insn]:
    """Every byte of *code* as instructions; an undecodable tail is one ``db``."""
    from rebrew.analysis import disasm_insns

    insns = disasm_insns(code, va, cs_arch, cs_mode)
    covered = sum(insn.size for insn in insns)
    if covered < len(code):
        tail = code[covered:]
        insns.append(Insn(va + covered, len(tail), DATA_MNEMONIC, tail.hex(" "), tail))
    return insns


def _tokens(insn: Insn, registers: frozenset[str]) -> list[tuple[int, int, str, Any]]:
    """``(start, end, kind, value)`` of each register and number in the operands.

    A ``db`` tail's operands are raw hex bytes, not operands: it has none.
    """
    out: list[tuple[int, int, str, Any]] = []
    if insn.mnemonic == DATA_MNEMONIC:
        return out
    for match in _TOKEN_RE.finditer(insn.op_str):
        text = match.group()
        if text[0] in "-0123456789":
            out.append((match.start(), match.end(), "immediate", int(text, 0)))
        elif text.lstrip("$%").lower() in registers:
            out.append((match.start(), match.end(), "register", text.lstrip("$%").lower()))
    return out


def _masked(raw: bytes, start: int, relocs: set[int]) -> bytes:
    """*raw* (at offset *start* of the rebuilt code) with relocation bytes zeroed."""
    return bytes(0 if start + i in relocs else b for i, b in enumerate(raw))


def instruction_diff(
    target: bytes,
    rebuilt: bytes,
    *,
    va: int,
    cs_arch: str | int,
    cs_mode: str | int,
    reloc_offsets: Iterable[int] = (),
    invalid_reloc_offsets: Iterable[int] = (),
) -> dict[str, Any]:
    """Both instruction lists, their alignment rows and operand spans.

    *reloc_offsets* and *invalid_reloc_offsets* are start offsets in
    *rebuilt* of relocation fields (``CompareResult.reloc_offsets`` and
    ``inv_reloc_offsets``); a pair touching an invalid one is a ``replace``,
    as the byte verdict counts it a mismatch.
    """
    from rebrew.alignment import AlignedMatcher, normalize_instruction

    truncated = len(target) > MAX_BYTES or len(rebuilt) > MAX_BYTES
    left = _decode(target[:MAX_BYTES], va, cs_arch, cs_mode)
    right = _decode(rebuilt[:MAX_BYTES], va, cs_arch, cs_mode)
    relocs = {o + i for o in reloc_offsets for i in range(RELOC_FIELD_BYTES)}
    invalid = {o + i for o in invalid_reloc_offsets for i in range(RELOC_FIELD_BYTES)}

    def pair_row(i: int, j: int) -> dict[str, Any]:
        a, b = left[i], right[j]
        if a.raw == b.raw:
            return {"op": "equal", "left": i, "right": j}
        start = b.va - va
        span = range(start, start + b.size)
        if (
            a.size == b.size
            and not any(o in invalid for o in span)
            and _masked(a.raw, start, relocs) == _masked(b.raw, start, relocs)
        ):
            return {"op": "equal", "left": i, "right": j, "reloc": True}
        return {"op": "replace", "left": i, "right": j}

    rows: list[dict[str, Any]] = []
    matcher = AlignedMatcher(
        a=[normalize_instruction(i) for i in left],
        b=[normalize_instruction(i) for i in right],
        autojunk=False,
    )
    for _tag, i1, i2, j1, j2 in matcher.get_opcodes():
        paired = min(i2 - i1, j2 - j1)
        rows.extend(pair_row(i1 + k, j1 + k) for k in range(paired))
        rows.extend({"op": "delete", "left": i, "right": None} for i in range(i1 + paired, i2))
        rows.extend({"op": "insert", "left": None, "right": j} for j in range(j1 + paired, j2))

    registers = _register_names(cs_arch, cs_mode)
    left_tokens = [_tokens(i, registers) for i in left]
    right_tokens = [_tokens(i, registers) for i in right]
    values: dict[tuple[str, Any], int] = {}
    left_spans: list[list[dict[str, Any]]] = [[] for _ in left]
    right_spans: list[list[dict[str, Any]]] = [[] for _ in right]

    def spans(
        tokens: list[tuple[int, int, str, Any]], other: list[tuple[int, int, str, Any]] | None
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        same_shape = other is not None and [t[2] for t in tokens] == [t[2] for t in other]
        for index, (start, end, kind, value) in enumerate(tokens):
            span: dict[str, Any] = {
                "start": start,
                "end": end,
                "kind": kind,
                "value": values.setdefault((kind, value), len(values)),
            }
            if other is not None and (not same_shape or other[index][3] != value):
                span["changed"] = True
            out.append(span)
        return out

    for row in rows:
        i, j = row["left"], row["right"]
        compared = row["op"] == "replace" or row.get("reloc", False)
        if i is not None:
            left_spans[i] = spans(
                left_tokens[i], right_tokens[j] if compared and j is not None else None
            )
        if j is not None:
            right_spans[j] = spans(
                right_tokens[j], left_tokens[i] if compared and i is not None else None
            )

    def listing(insns: list[Insn], all_spans: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
        return [
            {
                "offset": insn.va - va,
                "bytes": insn.raw.hex(),
                "mnemonic": insn.mnemonic,
                "operands": insn.op_str,
                "spans": insn_spans,
            }
            for insn, insn_spans in zip(insns, all_spans, strict=True)
        ]

    return {
        "max_bytes": MAX_BYTES,
        "truncated": truncated,
        "original": listing(left, left_spans),
        "rebuilt": listing(right, right_spans),
        "rows": rows,
    }


def record_instructions(cfg: Any, result: CompareResult, target: bytes, va: int) -> None:
    """Set ``result.instructions`` unless the rebuild is ``EXACT`` or produced no code.

    An ``EXACT`` rebuild is the original byte for byte: its comparison is the
    original listing against itself, which a reader gets from the target
    alone (the ``rebrew.instruction_listing`` op), so it is not recorded.
    """
    rebuilt = result.full_obj_bytes if result.full_obj_bytes is not None else result.obj_bytes
    if result.status == "EXACT" or not rebuilt:
        return
    result.instructions = instruction_diff(
        target,
        rebuilt,
        va=va,
        cs_arch=cfg.capstone_arch,
        cs_mode=cfg.capstone_mode,
        reloc_offsets=result.reloc_offsets or [],
        invalid_reloc_offsets=result.inv_reloc_offsets,
    )
