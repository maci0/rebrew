"""Property-based fuzz tests for the ``rebrew float_const`` byte scanner.

The scanner runs over raw code buffers taken from a target binary the user
pointed the CLI at, so its instruction bytes, operand displacements, and
section spans are untrusted.  The properties below hold the scanner to its
documented contract: a constant lies wholly inside one read-only region, its
size follows its opcode, a short read from the image reader skips instead of
raising, and each address is yielded once.
"""

from __future__ import annotations

import struct

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.float_const import find_float_consts

#: Bounds that keep the disassembler workload bounded: x86 is variable length,
#: so an unbounded buffer would make the run time a function of the example
#: count rather than of the code under test.
_MAX_BUFFER = 512
_BASE_VA = 0x00401000
_CONST_VA = 0x00402000
_CONST_SPAN = 0x200


#: ``D9 05`` / ``DD 05`` (fld/fld dword [abs]) and the store forms
#: (``D9 15`` / ``DD 15``) — the operand is a disp32 absolute address, which is
#: what the scanner looks for.  Random bytes almost never decode into one, so
#: these are spliced in: without them the harness never leaves the seed corpus.
_FLOAT_OPCODES = (b"\xd9\x05", b"\xd9\x15", b"\xdd\x05", b"\xdd\x15")


@st.composite
def _code_region(draw: st.DrawFn) -> tuple[int, bytes]:
    """A code buffer that sometimes carries a real float reference."""
    noise = draw(st.binary(max_size=_MAX_BUFFER))
    if draw(st.booleans()):
        target = _CONST_VA + draw(st.integers(min_value=0, max_value=_CONST_SPAN - 8))
        insn = draw(st.sampled_from(_FLOAT_OPCODES)) + struct.pack("<I", target)
        noise = insn + noise if draw(st.booleans()) else noise + insn
    return _BASE_VA + draw(st.integers(min_value=0, max_value=0x1000)), noise


@st.composite
def _image(draw: st.DrawFn) -> tuple[list[tuple[int, bytes]], list[tuple[int, int]], bool]:
    """Drawn code regions, const regions, and a short-read toggle."""
    regions = draw(
        st.lists(
            _code_region(),
            max_size=2,
        )
    )
    consts = draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=0x400),
                st.integers(min_value=0, max_value=0x400),
            ),
            max_size=2,
        )
    )
    return regions, consts, draw(st.booleans())


def _reader(short: bool):
    """An image reader that serves a fixed image, optionally truncating."""
    image = bytes(range(256)) * 4

    def read_at(va: int, size: int) -> bytes:
        if va < 0 or size < 0:
            return b""
        offset = va - _CONST_VA
        if offset < 0 or offset >= len(image):
            return b""
        chunk = image[offset : offset + size]
        return chunk[:1] if short and len(chunk) == size else chunk

    return read_at


@settings(max_examples=100, deadline=None)
@given(_image())
def test_find_float_consts_yields_invariants(sample) -> None:
    regions, spans, short = sample
    code_regions = [(_BASE_VA + va, data) for va, data in regions if data]
    const_regions = [(_CONST_VA + start, _CONST_VA + start + length) for start, length in spans]

    consts = list(find_float_consts(code_regions, const_regions, _reader(short)))

    seen: set[int] = set()
    for const in consts:
        assert const.size in (4, 8)
        assert const.address not in seen, "the same constant was yielded twice"
        seen.add(const.address)
        assert any(
            start <= const.address and const.address + const.size <= end
            for start, end in const_regions
        ), "constant outside every const region"
        assert isinstance(const.value, float)
        # A single-precision yield must round-trip through the same <f read.
        expected = struct.unpack(
            "<f" if const.size == 4 else "<d",
            struct.pack("<f" if const.size == 4 else "<d", const.value),
        )[0]
        assert expected == const.value


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=_MAX_BUFFER), st.binary(min_size=1, max_size=8))
def test_find_float_consts_truncated_reader_yields_nothing(code: bytes, image: bytes) -> None:
    """A reader that never returns the full ``size`` yields nothing, never raises."""
    consts = list(
        find_float_consts([(_BASE_VA, code)], [(0, 0x1000)], lambda va, size: image[: size - 1])
    )
    assert consts == []
