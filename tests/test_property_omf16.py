"""Property-based fuzz tests for the hand-written 16-bit OMF reader.

``omf16`` walks raw ``.obj`` record bytes (LIEF and objconv cannot read the
MSVC 1.52 dialect), so a truncated or crafted object reaches length and
offset arithmetic directly.  These tests draw record streams from the types
the parser dispatches on, plus raw bytes, and check that it either decodes
or raises ``Omf16Error``, never anything else.
"""

from __future__ import annotations

import struct

from hypothesis import given
from hypothesis import strategies as st

from rebrew.omf16 import Omf16Error, Omf16Module, _match_symbol, is_omf16, parse_omf16

_RECORD_TYPES = (0xA0, 0xC2, 0x90, 0x96, 0xCA, 0x80, 0x88, 0x8A)
_NEAR_C2_HEADER = 9


def _record(rtype: int, body: bytes) -> bytes:
    """One OMF record: ``[type][len:2 LE][body][checksum]``."""
    raw = bytes([rtype]) + struct.pack("<H", len(body) + 1) + body
    return raw + bytes([-sum(raw) & 0xFF])


def _name_list(names: list[bytes]) -> bytes:
    return b"".join(bytes([len(n)]) + n for n in names)


_name = st.binary(min_size=1, max_size=12)
_ascii_name = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=12
).map(str.encode)


@st.composite
def _record_body(draw: st.DrawFn, rtype: int) -> bytes:
    """A body shaped like what *rtype* expects, or arbitrary bytes."""
    if draw(st.booleans()):
        return draw(st.binary(max_size=48))
    if rtype == 0xA0:
        return (
            bytes([1])
            + struct.pack("<H", draw(st.integers(0, 0x200)))
            + draw(st.binary(max_size=32))
        )
    if rtype == 0xC2:
        return draw(st.binary(min_size=0, max_size=40))
    if rtype == 0x90:
        pairs = draw(st.lists(st.tuples(_name, st.integers(0, 0xFFFF)), max_size=4))
        return b"".join(bytes([len(n)]) + n + struct.pack("<H", off) for n, off in pairs)
    if rtype == 0x96:
        prefix = draw(st.sampled_from([b"\x00", b""]))
        names = draw(st.lists(st.sampled_from([b"_TEXT", b"SRC_TEXT"]) | _name, max_size=4))
        return prefix + _name_list(names)
    if rtype == 0xCA:
        return _name_list(draw(st.lists(_name, max_size=4)))
    return draw(st.binary(max_size=16))


@st.composite
def _omf_stream(draw: st.DrawFn) -> bytes:
    """A record stream, optionally truncated or with one byte flipped."""
    out = b""
    for rtype in draw(st.lists(st.sampled_from(_RECORD_TYPES), max_size=8)):
        out += _record(rtype, draw(_record_body(rtype)))
    if out and draw(st.booleans()):
        cut = draw(st.integers(0, len(out)))
        out = out[:cut]
    if out and draw(st.booleans()):
        i = draw(st.integers(0, len(out) - 1))
        out = out[:i] + bytes([out[i] ^ draw(st.integers(1, 255))]) + out[i + 1 :]
    return out


def _parse_or_none(data: bytes) -> Omf16Module | None:
    try:
        return parse_omf16(data)
    except Omf16Error:
        return None


class TestParseOmf16Robust:
    @given(st.binary(max_size=256))
    def test_raw_bytes_decode_or_raise_omf16error(self, data: bytes) -> None:
        mod = _parse_or_none(data)
        assert (mod is not None) == is_omf16(data)

    @given(_omf_stream())
    def test_record_stream_decode_or_raise_omf16error(self, data: bytes) -> None:
        mod = _parse_or_none(data)
        assert (mod is not None) == is_omf16(data)
        if mod is None:
            return
        assert all(isinstance(n, str) and n.isascii() for n in mod.names)
        assert all(0 <= off <= 0xFFFF for off in mod.publics.values())
        # 0xC2 code records are concatenated after any 0xA0 code.
        assert mod.code.endswith(b"".join(mod.code_records))

    @given(_omf_stream(), _ascii_name)
    def test_symbol_lookup_never_crashes(self, data: bytes, symbol: bytes) -> None:
        mod = _parse_or_none(data)
        if mod is None:
            return
        for name in [symbol.decode(), *mod.names, *mod.publics]:
            code, relocs = _match_symbol(mod, name)
            if code is None:
                assert relocs == {}
                continue
            assert all(0 <= off < max(len(code), 1) for off in relocs)


class TestParseOmf16Decode:
    @given(
        st.lists(
            st.tuples(_ascii_name, st.binary(min_size=1, max_size=24)), min_size=1, max_size=4
        ),
        st.booleans(),
    )
    def test_optimized_dialect_maps_names_to_code_records(
        self, funcs: list[tuple[bytes, bytes]], far: bool
    ) -> None:
        header_len = 7 if far else _NEAR_C2_HEADER
        seg = b"SRC_TEXT" if far else b"_TEXT"
        data = _record(0x96, b"\x00" + _name_list([seg]))
        data += _record(0x96, _name_list([n for n, _ in funcs]))
        for _, code in funcs:
            data += _record(0xC2, b"\xaa" * header_len + code)
        mod = parse_omf16(data)
        assert mod.names == [n.decode() for n, _ in funcs]
        assert mod.code_records == [code for _, code in funcs]

    @given(st.binary(min_size=1, max_size=32), st.integers(0, 0x100), st.booleans())
    def test_unoptimized_dialect_places_code_at_offset(
        self, code: bytes, off: int, checksummed: bool
    ) -> None:
        body = bytes([1]) + struct.pack("<H", off) + code
        rec = bytes([0xA0]) + struct.pack("<H", len(body) + (1 if checksummed else 0)) + body
        if checksummed:
            rec += bytes([-sum(rec) & 0xFF])
        elif sum(rec) % 256 == 0:
            return  # indistinguishable from a checksummed record
        mod = parse_omf16(rec + _record(0x90, b"\x05_main" + struct.pack("<H", off)))
        assert mod.code[off:] == code
        assert mod.publics == {"_main": off}
