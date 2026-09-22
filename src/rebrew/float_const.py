"""float_const.py — find floating-point constants referenced from code.

Adapted from reccmp (isledecomp/reccmp, MIT License)
``analysis/float_const.py``.

x87 instructions with a memory operand that falls in the ``D8``-``DF``
two-byte opcode space can reference a constant instead of a variable.
Scanning the code sections for those opcodes and checking each referenced
address against the read-only data regions yields the binary's float
constant pool — complements :mod:`rebrew.inline_strings` (strings, not
floats) for data annotation.
"""

from __future__ import annotations

import re
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

# Superset of the float instructions above (mod-3 low bits of the second
# byte are the ModRM reg field; mod=00 forms are all covered by these
# eight displacement opcodes).  Positive lookahead supports overlapping
# matches so adjacent instructions are not skipped.
_FLOAT_INSTRUCTION_RE = re.compile(
    rb"(?=([\xd8\xd9\xdc\xdd][\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}))", re.S
)


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
    """Scan *buf* for float instructions with an absolute memory operand."""
    for match in _FLOAT_INSTRUCTION_RE.finditer(buf):
        inst = match.group(1)
        opcode = (inst[0], inst[1])
        if opcode in FLOAT_OPCODES:
            (pointer,) = struct.unpack("<I", inst[2:6])
            yield FloatInstruction(base_addr + match.start(), opcode, pointer)


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
    """
    seen: set[int] = set()
    for region_va, region_data in code_regions:
        for inst in find_float_instructions_in_buffer(region_data, region_va):
            pointer = inst.pointer
            if pointer in seen:
                continue
            seen.add(pointer)
            if reloc_sites is not None and inst.address + 2 not in reloc_sites:
                continue
            if not any(start <= pointer < end for start, end in const_regions):
                continue
            if inst.opcode in SINGLE_PRECISION_OPCODES:
                raw = read_at(pointer, 4)
                (value,) = struct.unpack("<f", raw)
                yield FloatConstant(pointer, 4, value)
            else:
                raw = read_at(pointer, 8)
                (value,) = struct.unpack("<d", raw)
                yield FloatConstant(pointer, 8, value)
