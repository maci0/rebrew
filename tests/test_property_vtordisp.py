"""Property-based fuzz tests for ``rebrew.vtordisp`` over untrusted code bytes.

``find_vtordisps`` scans a whole ``.text`` for MI-thunk islands using three
overlapping lookahead regexes, then decodes each hit with ``struct.unpack``.
It runs on bytes lifted straight out of an untrusted target, so the thunk
prefix, both displacement forms and the trailing ``rel32`` are all attacker
controlled, and the three shapes overlap: a 14-byte candidate also contains
an 8-byte one unless the longer form is tried first.

The harnesses below feed it planted thunks at drawn offsets inside drawn
noise, plus raw random bytes, and assert:

* the scan never raises and never yields a thunk whose shape it cannot read
  in full (a match near the end of the buffer must not be decoded);
* every reported thunk is well formed: one of the three sizes, a
  signed-byte ``disp``, an ``addend`` in range, and ``func_addr`` exactly
  ``addr + size + rel32``;
* the scan is ordered, address-shifted by ``base_addr`` alone, and
  deterministic -- the same bytes scanned twice give the same thunks, and
  bytes with no ``sub ecx, imm8`` prefix yield nothing.
"""

from __future__ import annotations

import struct

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.vtordisp import VtordispFunction, find_vtordisps

#: The three shapes the scanner claims to recognize.
_SIZES = (8, 11, 14)


@st.composite
def _thunk(draw: st.DrawFn) -> bytes:
    """One planted thunk: drawn shape, ``this`` adjustment, addend, target."""
    disp = draw(st.integers(min_value=-128, max_value=127))
    shape = draw(st.sampled_from(["vtordisp", "add", "sub"]))
    # the imm8 form only encodes a signed byte
    lo, hi = (-128, 127) if shape == "sub" else (-0x10000, 0x10000)
    addend = draw(st.integers(min_value=lo, max_value=hi))
    rel32 = draw(st.integers(min_value=-(2**31), max_value=2**31 - 1))
    head = b"\x2b\x49" + struct.pack("b", disp)
    jmp = b"\xe9" + struct.pack("<i", rel32)
    if shape == "add":
        return head + b"\x81\xc1" + struct.pack("<i", addend) + jmp
    if shape == "sub":
        return head + b"\x83\xe9" + struct.pack("b", addend) + jmp
    return head + jmp


@st.composite
def _code(draw: st.DrawFn) -> bytes:
    """Random code bytes, optionally with planted thunk shapes."""
    parts: list[bytes] = []
    for _ in range(draw(st.integers(min_value=0, max_value=4))):
        parts.append(draw(st.binary(max_size=64)))
        parts.append(draw(_thunk()))
        parts.append(draw(st.binary(max_size=8)))
    return b"".join(parts) if parts else draw(st.binary(max_size=64))


def _assert_well_formed(thunks: list[VtordispFunction], code: bytes, base: int) -> None:
    prev_end = -1
    for t in thunks:
        assert t.size in _SIZES
        assert -128 <= t.disp <= 127
        assert t.addr >= base
        assert t.addr - base >= prev_end, "thunks overlap or are out of order"
        # the whole shape lies inside the buffer it was read from
        assert t.addr - base + t.size <= len(code)
        # the shape is the one it claims: the fixed prefix, then the jump
        shape = code[t.addr - base : t.addr - base + t.size]
        assert shape[:3] == b"\x2b\x49" + struct.pack("b", t.disp)
        assert shape[-5] == 0xE9  # the jmp rel32 opcode, then its 4-byte target
        rel32 = struct.unpack("<i", shape[-4:])[0]
        assert t.func_addr == t.addr + t.size + rel32
        if t.size == 14:
            assert shape[3:5] == b"\x81\xc1"
            assert t.addend == struct.unpack("<i", shape[5:9])[0]
        elif t.size == 11:
            assert shape[3:5] == b"\x83\xe9"
            assert t.addend == -struct.unpack("b", shape[5:6])[0]
        else:
            assert t.addend == 0
        prev_end = t.addr - base + t.size


@settings(max_examples=300, deadline=None)
@given(_code(), st.integers(min_value=0, max_value=0x1000000))
def test_scan_yields_only_well_formed_thunks(code: bytes, base: int) -> None:
    _assert_well_formed(list(find_vtordisps(code, base)), code, base)


@settings(max_examples=100, deadline=None)
@given(_code(), st.integers(min_value=0, max_value=0x1000000))
def test_base_addr_shifts_by_base_only(code: bytes, base: int) -> None:
    """The scanner is a pure offset map: same bytes, same thunks, shifted."""
    plain = list(find_vtordisps(code, 0))
    shifted = list(find_vtordisps(code, base))
    assert len(plain) == len(shifted)
    for a, b in zip(plain, shifted, strict=True):
        assert b.addr == a.addr + base
        assert b.func_addr == a.func_addr + base
        assert (b.disp, b.addend, b.size) == (a.disp, a.addend, a.size)


@settings(max_examples=100, deadline=None)
@given(_code())
def test_scan_is_deterministic(code: bytes) -> None:
    assert list(find_vtordisps(code)) == list(find_vtordisps(code))


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=256))
def test_bytes_without_the_prefix_yield_nothing(code: bytes) -> None:
    """No ``sub ecx, imm8`` prefix means no thunk, whatever the rest is."""
    if b"\x2b\x49" in code:
        return
    assert list(find_vtordisps(code)) == []


@st.composite
def _code_with_cut(draw: st.DrawFn) -> tuple[bytes, int]:
    """Code bytes plus a truncation point inside them."""
    code = draw(_code())
    return code, draw(st.integers(min_value=0, max_value=len(code)))


@settings(max_examples=100, deadline=None)
@given(_code_with_cut(), st.integers(min_value=0, max_value=0x10000))
def test_truncation_never_invents_a_thunk(drawn: tuple[bytes, int], base: int) -> None:
    """A shape cut short by EOF is dropped, not decoded from a short buffer.

    Every thunk the truncated scan reports was also reported at the same
    address by the full scan, and it lies wholly inside the cut.
    """
    code, cut = drawn
    full = {t.addr: t for t in find_vtordisps(code, base)}
    for t in find_vtordisps(code[:cut], base):
        assert t.addr in full
        assert full[t.addr] == t
        assert t.addr - base + t.size <= cut
