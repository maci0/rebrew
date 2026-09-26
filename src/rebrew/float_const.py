"""float_const.py — find floating-point constants referenced from code.

Adapted from reccmp (isledecomp/reccmp, MIT License)
``analysis/float_const.py``.

x87 instructions with a memory operand that falls in the ``D8``-``DF``
two-byte opcode space can reference a constant instead of a variable.
Capstone walks those instructions; a pointer that lands in a read-only
data region is a constant. Complements :mod:`rebrew.inline_strings`
(strings, not floats) for data annotation.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

SINGLE_PRECISION_OPCODES = frozenset(
    [
        (0xD8, 0x05),  # fadd
        (0xD8, 0x0D),  # fmul
        (0xD8, 0x15),  # fcom
        (0xD8, 0x1D),  # fcomp
        (0xD8, 0x25),  # fsub
        (0xD8, 0x2D),  # fsubr
        (0xD8, 0x35),  # fdiv
        (0xD8, 0x3D),  # fdivr
        (0xD9, 0x05),  # fld
    ]
)

DOUBLE_PRECISION_OPCODES = frozenset(
    [
        (0xDC, 0x05),  # fadd
        (0xDC, 0x0D),  # fmul
        (0xDC, 0x15),  # fcom
        (0xDC, 0x1D),  # fcomp
        (0xDC, 0x25),  # fsub
        (0xDC, 0x2D),  # fsubr
        (0xDC, 0x35),  # fdiv
        (0xDC, 0x3D),  # fdivr
        (0xDD, 0x05),  # fld
    ]
)

FLOAT_OPCODES = frozenset([*SINGLE_PRECISION_OPCODES, *DOUBLE_PRECISION_OPCODES])

# Capstone reports a disp32 as a signed value. Image addresses are unsigned.
_DISP32_MASK = 0xFFFFFFFF


@dataclass(frozen=True)
class FloatInstruction:
    """One float instruction referencing an absolute address."""

    address: int  # VA of the instruction
    opcode: tuple[int, int]
    pointer: int  # absolute address of the operand


@dataclass(frozen=True)
class FloatConstant:
    """A constant float value discovered via a code reference."""

    address: int
    size: int  # 4 (single) or 8 (double)
    value: float


def find_float_instructions_in_buffer(buf: bytes, base_addr: int = 0) -> Iterator[FloatInstruction]:
    """Scan *buf* for float instructions with an absolute memory operand.

    Capstone (x86-32) decides which bytes are an instruction. A ``D9 05``
    pattern inside another instruction's immediate is not a reference.
    Undecodable bytes are skipped, so a real instruction later in *buf*
    is still seen. The operand address is the instruction's disp32.
    """
    if not buf:
        return
    from capstone.x86 import X86_OP_MEM, X86_REG_INVALID

    from rebrew.analysis import _capstone

    for insn in _capstone().disasm(buf, base_addr):
        raw = insn.bytes
        if len(raw) < 2:
            continue
        opcode = (raw[0], raw[1])
        if opcode not in FLOAT_OPCODES:
            continue
        for op in insn.operands:
            mem = op.mem
            if op.type != X86_OP_MEM or mem.base != X86_REG_INVALID or mem.index != X86_REG_INVALID:
                continue
            yield FloatInstruction(insn.address, opcode, mem.disp & _DISP32_MASK)
            break


def find_float_consts(
    code_regions: Sequence[tuple[int, bytes]],
    const_regions: Sequence[tuple[int, int]],
    read_at: Callable[[int, int], bytes],
    reloc_sites: set[int] | None = None,
) -> Iterator[FloatConstant]:
    """Yield float constants referenced from code.

    *code_regions* — ``(va, bytes)`` pairs for each executable section.
    *const_regions* — ``(start_va, end_va)`` spans of read-only data; a
    pointer landing in one is a constant, not a variable.
    *read_at* — ``read_at(va, size) -> bytes`` reader over the image (data
    sections live outside the code buffers).
    *reloc_sites* — absolute addresses (VAs) of relocation sites; when
    given, an instruction's operand must sit in one (an immediate that
    happens to look like an address is not a real reference).

    A constant must lie wholly inside one const region, and a short read
    from *read_at* (truncated image) skips it rather than raising.
    """
    seen: set[int] = set()
    for region_va, region_data in code_regions:
        for inst in find_float_instructions_in_buffer(region_data, region_va):
            pointer = inst.pointer
            if pointer in seen:
                continue
            if reloc_sites is not None and inst.address + 2 not in reloc_sites:
                continue
            single = inst.opcode in SINGLE_PRECISION_OPCODES
            size = 4 if single else 8
            if not any(start <= pointer and pointer + size <= end for start, end in const_regions):
                continue
            raw = read_at(pointer, size)
            if len(raw) != size:
                continue
            seen.add(pointer)
            (value,) = struct.unpack("<f" if single else "<d", raw)
            yield FloatConstant(pointer, size, value)
