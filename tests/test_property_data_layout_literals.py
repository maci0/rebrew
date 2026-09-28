"""Property-based fuzzing for the C declaration/literal renderer
(``rebrew.data_layout``).

``c_type_size`` / ``estimate_type_size`` size a global and ``typed_array_literal``
turns the target's raw ``.data`` bytes into the initializer written into the
source tree and handed to the compiler.  Their input is a type string out of
``rebrew-functions.toml`` / ``rebrew-data.toml`` and a byte span out of the
target binary, so a mis-sized or mis-formatted result is a wrong VAd entry in
the catalog, a coverage cell that is off by an element, or a source file that
no longer compiles.

The harnesses drive declared type spellings (multi-word qualifiers, pointers,
multi-dimensional and octal/hex array bounds) plus arbitrary type text, in
both byte orders, and assert:

* a size always comes back, and it agrees with what the literal renderer
  reports as an element count (the two models must not drift apart);
* every emitted integer literal re-parses to exactly the bytes it was built
  from, under the same byte order (pair assertion across the render boundary);
* float/double literals round-trip to the exact original bits;
* non-finite floats raise ``ValueError`` instead of emitting an uncompilable
  ``nan``/``inf`` initializer, and every other input renders a brace-balanced
  initializer with the element count the caller will size it by.
"""

import re
import struct
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.data_layout import (
    c_type_size,
    estimate_type_size,
    hex_list,
    typed_array_literal,
)

_SCALARS = [
    "char",
    "unsigned char",
    "signed char",
    "short",
    "unsigned short",
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "DWORD",
    "WORD",
    "BOOL",
    "long long",
    "__int64",
    "LONGLONG",
    "float",
    "double",
    "FLOAT",
    "DOUBLE",
]

#: Types whose emitted literal is a plain C integer expression, so it can be
#: re-parsed and compared against the bytes it came from.
_INT_TYPES = [t for t in _SCALARS if t not in ("float", "double", "FLOAT", "DOUBLE")]

_DECLS = ("static {t} g_x;", "extern {t} g_x;", "const {t} g_x;", "{t} g_x;")
_BOUNDS = ["", "[4]", "[0]", "[010]", "[2][4]", "[0x10]", "[ 3 ]", "[1u]", "[1023]"]
_BYTE_ORDERS = st.sampled_from(["<", ">"])


def _initializer_lits(text: str) -> list[str]:
    """The top-level element literals of a rendered ``{...}`` initializer."""
    body = text.strip()[1:-1].strip()
    return [piece.strip() for piece in body.replace("\n", " ").split(",") if piece.strip()]


@given(st.sampled_from(_DECLS), st.sampled_from(_SCALARS), st.sampled_from(_BOUNDS))
def test_size_and_element_count_agree(decl: str, scalar: str, bound: str) -> None:
    """The sizing model and the literal renderer must not drift: fed exactly
    the bytes the declared extent covers, the renderer emits exactly as many
    elements as the catalog will size the symbol by."""
    ctype = decl.format(t=scalar) + bound
    elemsize = c_type_size(ctype)
    assert elemsize in (1, 2, 4, 8)
    count = estimate_type_size(ctype) // elemsize
    assert count >= 1
    assert estimate_type_size(ctype) == elemsize * count

    data = bytes(range(1, 65))
    text, elems = typed_array_literal(ctype, data)
    if elemsize <= 1:
        assert elems == len(data), "a byte-wide element keeps the raw-byte layout"
    else:
        assert elems == len(data) // elemsize
        # Fed exactly the declared extent, the two models name the same count.
        exact, exact_elems = typed_array_literal(ctype, bytes(count * elemsize))
        assert exact_elems == count
        assert _initializer_lits(exact)


@settings(max_examples=300, deadline=None)
@given(st.sampled_from(_INT_TYPES), st.binary(min_size=0, max_size=64), _BYTE_ORDERS)
def test_integer_literals_reparse_to_the_original_bytes(
    ctype: str, data: bytes, order: str
) -> None:
    """Pair assertion across the render boundary: every emitted integer
    literal is a C integer expression that evaluates back to the exact bytes
    the initializer was built from."""
    text, elems = typed_array_literal(ctype, data, byte_order=order)
    lits = _initializer_lits(text)
    assert len(lits) == elems
    assert all(re.fullmatch(r"-?\d+|0x[0-9a-f]+", lit) for lit in lits)

    size = c_type_size(ctype)
    fmt = f"{order}{'B' if size == 1 else ('H' if size == 2 else ('I' if size == 4 else 'Q'))}"
    for i, lit in enumerate(lits):
        rebuilt = struct.pack(fmt, int(lit, 0))
        assert rebuilt == data[i * size : (i + 1) * size]


@settings(max_examples=300, deadline=None)
@given(
    st.sampled_from(["float", "FLOAT", "double", "DOUBLE"]),
    st.binary(min_size=0, max_size=48),
    _BYTE_ORDERS,
)
def test_float_literals_roundtrip_or_refuse(ctype: str, data: bytes, order: str) -> None:
    """A finite float/double literal reproduces the exact original bits when
    widened; a non-finite one raises ``ValueError`` rather than emitting an
    initializer C89 cannot compile."""
    width = c_type_size(ctype)
    usable = len(data) - len(data) % width
    try:
        text, elems = typed_array_literal(ctype, data, byte_order=order)
    except ValueError as exc:
        # Only a non-finite element may be refused.
        assert "no C89 literal" in str(exc)
        return
    lits = _initializer_lits(text)
    assert len(lits) == elems == usable // width
    for i, lit in enumerate(lits):
        chunk = data[i * width : (i + 1) * width]
        if width == 4:
            assert lit.endswith("f"), "a float literal carries the C suffix"
            value = float(lit[:-1])
            assert value == struct.unpack_from(order + "f", chunk)[0]
            assert struct.pack(order + "f", value) == chunk
        else:
            value = float(lit)
            assert value == struct.unpack_from(order + "d", chunk)[0]
            assert struct.pack(order + "d", value) == chunk


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=48), st.binary(min_size=0, max_size=40), _BYTE_ORDERS)
def test_arbitrary_type_text_always_renders(ctype: str, data: bytes, order: str) -> None:
    """Fuzz: any type text at all yields a size and either a balanced
    initializer or a ``ValueError`` — never a traceback, and never an
    initializer whose element count contradicts its own text."""
    size = c_type_size(ctype)
    assert isinstance(size, int) and size > 0
    assert estimate_type_size(ctype) >= size

    try:
        text, elems = typed_array_literal(ctype, data)
    except ValueError:
        return
    assert isinstance(text, str)
    assert text.startswith("{") and text.endswith("}")
    assert elems >= 0
    if size <= 1:
        assert elems == len(data)
    else:
        assert elems == len(data) // size


@given(st.binary(max_size=64))
def test_hex_list_roundtrips_every_byte(data: bytes) -> None:
    """The byte-wide initializer carries every byte exactly once, in order."""
    text = hex_list(data)
    assert text.startswith("{") and text.endswith("}")
    assert [int(lit, 16) for lit in _initializer_lits(text)] == list(data)


@settings(max_examples=200, deadline=None)
@given(st.sampled_from(_SCALARS), st.binary(min_size=0, max_size=32), _BYTE_ORDERS)
def test_pointer_elements_render_as_void_casts(ctype: str, data: bytes, order: str) -> None:
    """A pointer element is either the null constant or a ``(void*)`` hex
    cast, and every cast re-parses to the original 4-byte slot."""
    ptype = ctype + " *"
    text, elems = typed_array_literal(ptype, data, byte_order=order)
    lits = _initializer_lits(text)
    assert len(lits) == elems == len(data) // 4
    for i, lit in enumerate(lits):
        assert lit == "0" or re.fullmatch(r"\(void\*\) 0x[0-9a-f]{8}", lit)
        value = 0 if lit == "0" else int(lit.rsplit(" ", 1)[1], 16)
        assert struct.pack(order + "I", value) == data[i * 4 : i * 4 + 4]


@pytest.mark.parametrize("bad", [b"\x00\x00\xc0\x7f", b"\x00\x00\x80\x7f"])
def test_non_finite_floats_are_refused(bad: bytes) -> None:
    """C89 has no NaN/Inf literal, so the renderer raises rather than emitting
    a definition that cannot compile."""
    with pytest.raises(ValueError, match="no C89 literal"):
        typed_array_literal("float", bad, byte_order="<")


def test_estimate_type_size_multiplies_every_dimension() -> None:
    """Every ``[N]`` counts, and a flexible ``[0]`` binds one element, so no
    symbol reaches the layout with a zero extent."""
    cases: list[tuple[str, int]] = [
        ("char[2][4]", 8),
        ("int[2][4]", 32),
        ("char[0]", 1),
        ("char[010]", 8),
        ("char[0x10]", 16),
        ("short tbl[3]", 6),
    ]
    for ctype, want in cases:
        got: Any = estimate_type_size(ctype)
        assert got == want, ctype
