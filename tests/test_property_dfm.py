"""Property-based fuzz tests for the hand-written Delphi 1 TPF0 form reader.

``dfm`` walks untrusted bytes embedded in NE images: class/name short
strings, property values dispatched on a wire type byte, counted binary
blobs, terminated identifier sets, and recursively nested components.
These tests draw raw bytes and structure-aware form streams, and check
that decoding either succeeds or raises ``DfmError``, never anything
else, plus the roundtrip invariant across the decode/encode boundary.
"""

from __future__ import annotations

import struct

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.formats.dfm import (
    Binary,
    DfmError,
    Identifier,
    Int8,
    Int16,
    Int32,
    SetOfIdentifiers,
    Str,
    encode,
    parse_form,
    parse_forms,
    roundtrip,
    scan_forms,
)

_MAX_EXAMPLES = 100


@st.composite
def _value(draw: st.DrawFn) -> object:
    """A supported property value, or an unknown type byte's payload."""
    kind = draw(st.integers(0, 8))
    if kind == 0:
        return Int8(draw(st.integers(-128, 127)))
    if kind == 1:
        return Int16(draw(st.integers(-32768, 32767)))
    if kind == 2:
        return Int32(draw(st.integers(-2147483648, 2147483647)))
    if kind in (3, 4):
        text = draw(st.binary(min_size=0, max_size=16)).decode("latin1")
        return Str(text) if kind == 3 else Identifier(text)
    if kind == 5:
        return Binary(draw(st.binary(min_size=0, max_size=32)))
    if kind == 6:
        items = draw(
            st.lists(
                st.binary(min_size=1, max_size=8).map(lambda b: b.decode("latin1")), max_size=3
            )
        )
        return SetOfIdentifiers(items)
    if kind == 7:
        return draw(st.sampled_from([True, False]))
    payload = draw(st.binary(min_size=0, max_size=8))
    return (draw(st.integers(0, 255)), payload)


def _short(text: str) -> bytes:
    raw = text.encode("latin1")
    return bytes([len(raw)]) + raw


@st.composite
def _component(draw: st.DrawFn, depth: int = 0) -> bytes:
    """A component subtree encoded exactly as ``encode`` would write it."""
    cls = draw(st.binary(min_size=1, max_size=8)).decode("latin1")
    name = draw(st.binary(min_size=1, max_size=8)).decode("latin1")
    props = draw(
        st.lists(
            st.tuples(
                st.binary(min_size=1, max_size=8).map(lambda b: b.decode("latin1")), _value()
            ),
            max_size=3,
        )
    )
    out = bytearray(_short(cls) + _short(name))
    for prop, value in props:
        if isinstance(value, tuple):
            type_byte, payload = value
            out += _short(prop)
            out.append(type_byte)
            out += payload
        elif isinstance(value, bool):
            out += _short(prop)
            out.append(0x09 if value else 0x08)
        else:
            out += _short(prop)
            out.append(value.type_byte)  # type: ignore[union-attr]
            out += value.encode()  # type: ignore[union-attr]
    out.append(0)
    if depth < 3:
        for _ in range(draw(st.integers(0, 2))):
            out += draw(_component(depth=depth + 1))
    out.append(0)
    return bytes(out)


@st.composite
def _form_stream(draw: st.DrawFn) -> bytes:
    """A TPF0 stream, optionally truncated, byte-flipped, or deep-nested."""
    style = draw(st.integers(0, 3))
    if style == 0:
        stream = b"TPF0" + draw(_component())
    elif style == 1:
        # Valid-ish prolog with an unsupported/oversized payload.
        cls = draw(st.binary(min_size=1, max_size=4)).decode("latin1")
        size = draw(st.sampled_from([0, 1, 0xFFFFFFFF, draw(st.integers(0, 0x10000))]))
        stream = (
            b"TPF0"
            + _short(cls)
            + _short("M")
            + _short("P")
            + bytes([0x0A])
            + struct.pack("<I", size & 0xFFFFFFFF)
            + draw(st.binary(max_size=16))
        )
    elif style == 2:
        depth = draw(st.integers(0, 140))
        header = b"\x01T\x01x\x00"
        stream = b"TPF0" + header * depth + bytes(depth) + draw(st.binary(max_size=8))
    else:
        stream = b"TPF0" + draw(_component())
        if stream and draw(st.booleans()):
            cut = draw(st.integers(0, len(stream)))
            stream = stream[:cut]
        if stream and draw(st.booleans()):
            i = draw(st.integers(0, len(stream) - 1))
            stream = stream[:i] + bytes([stream[i] ^ draw(st.integers(1, 255))]) + stream[i + 1 :]
    return stream


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(st.binary(max_size=512))
def test_raw_bytes_decode_or_raise_dfmerror(data: bytes) -> None:
    try:
        forms, errors = scan_forms(data)
    except DfmError:
        return
    assert all(0 <= offset < len(data) for offset, _, _ in forms)
    assert all(offset + 4 <= end <= len(data) for offset, _, end in forms)
    assert all(set(error) == {"offset", "error"} for error in errors)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(_form_stream())
def test_form_stream_decode_or_raise_dfmerror(data: bytes) -> None:
    try:
        root, end = parse_form(data)
    except DfmError:
        return
    assert 4 < end <= len(data)
    assert root.cls
    # Pair assertion across the decode/encode boundary.
    assert encode(root) == data[4:end]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(_form_stream())
def test_roundtrip_never_crashes(data: bytes) -> None:
    try:
        count, failures = roundtrip(data)
    except DfmError:
        return
    assert count >= 0
    assert failures == []


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(st.binary(min_size=0, max_size=256), st.integers(0, 0x10000))
def test_parse_form_at_arbitrary_offset(data: bytes, offset: int) -> None:
    try:
        root, end = parse_form(data, offset)
    except DfmError:
        return
    assert offset + 4 < end <= len(data)
    assert encode(root) == data[offset + 4 : end]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(st.binary(max_size=256), st.binary(max_size=256))
def test_scan_concat_never_crashes(a: bytes, b: bytes) -> None:
    try:
        forms = parse_forms(a + b)
    except DfmError:
        return
    assert all(0 <= offset < len(a + b) for offset, _, _ in forms)
