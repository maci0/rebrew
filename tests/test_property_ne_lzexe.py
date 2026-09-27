"""Property-based fuzzing for the NE loader tables and the LZEXE bitstream.

Both modules parse untrusted, attacker-shaped bytes taken straight from a
32-bit target file (a Delphi 1.0 ``.exe``, an LZEXE-packed DOS binary), so
every length, count and offset in the input is forgeable.  The harnesses
below feed structure-aware blobs (valid field layout, arbitrary table bytes)
plus pure-random bytes and assert:

* the public error type is the only failure mode — no ``struct.error``,
  ``IndexError`` or bare ``ValueError`` escapes;
* whatever the parsers return satisfies its own shape invariants;
* the decompressed image is bounded by the caller's budget, and a
  hand-built literal bitstream round-trips to the exact payload (a pair
  assertion across the compression boundary).
"""

import struct
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# rebrew.ne_loader — header, segment, import and export tables
# ---------------------------------------------------------------------------

_NE_HEADER_SIZE = 0x40


@st.composite
def _pascal_string(draw: st.DrawFn) -> str:
    """A length-prefixed-string body: printable ASCII, 1..63 bytes (the NE
    resident-name table rejects anything else, so the valid branch needs it)."""
    return draw(
        st.text(
            alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
            min_size=1,
            max_size=63,
        )
    )


def _put16(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<H", buf, off, value & 0xFFFF)


def _pascal(s: str) -> bytes:
    return bytes([len(s)]) + s.encode("latin-1")


@dataclass(frozen=True)
class NeSpec:
    """The names an :func:`ne_blob` build wrote, for the parser to find again."""

    module_names: tuple[str, ...]
    imported_names: tuple[str, ...]
    exports: tuple[tuple[str, int], ...]


@st.composite
def ne_blob(draw: st.DrawFn) -> tuple[bytes, int, NeSpec]:
    """An MZ-prefixed NE file whose tables are laid out the way a linker emits
    them: resident names, segment table, module reference table, imported
    names, entry table, then the per-module import blocks.

    Every field inside the records stays forgeable (arbitrary sector offsets,
    lengths, flags, by-name/ordinal import mix), so the parsers see the
    successful branches and the plausible-looking corruption that reaches the
    caps in ``parse_segments`` / ``parse_imports``.
    """
    n_segments = draw(st.integers(min_value=0, max_value=4))
    n_modules = draw(st.integers(min_value=0, max_value=4))
    module_names = draw(st.lists(_pascal_string(), min_size=n_modules, max_size=n_modules))
    imported = draw(st.lists(_pascal_string(), min_size=0, max_size=6))
    exports = draw(st.lists(_pascal_string(), min_size=0, max_size=4))
    export_ordinals = draw(
        st.lists(
            st.integers(min_value=0, max_value=0xFFFF),
            min_size=len(exports),
            max_size=len(exports),
        )
    )
    import_mix = draw(
        st.lists(st.booleans(), min_size=0, max_size=12)
    )  # True = by name, False = by ordinal

    # The imported-names blob, plus the offset of every name inside it.
    names = bytearray()
    name_offsets: list[int] = []
    for name in module_names + imported:
        name_offsets.append(len(names))
        names += _pascal(name)
    if draw(st.booleans()):
        names += draw(st.binary(max_size=8))  # trailing garbage inside the table

    exports_blob = bytearray()
    for name, ordinal in zip(exports, export_ordinals, strict=True):
        exports_blob += _pascal(name) + struct.pack("<H", ordinal)
    # A zero length byte closes the resident name table, as the linker writes it.
    exports_blob += b"\x00"

    seg_table = bytearray()
    for _ in range(n_segments):
        seg_table += struct.pack(
            "<HHHH",
            draw(st.integers(min_value=0, max_value=64)),  # sector offset
            draw(st.integers(min_value=0, max_value=0xFFFF)),  # length
            draw(st.integers(min_value=0, max_value=0xFFFF)),  # flags
            draw(st.integers(min_value=0, max_value=0xFFFF)),  # min allocation
        )

    # Offsets are relative to the NE header, so every table lands after it.
    cursor = _NE_HEADER_SIZE
    resident_off = cursor
    cursor += len(exports_blob)
    segment_off = cursor
    cursor += len(seg_table)
    modref_off = cursor
    cursor += 2 * n_modules
    names_off = cursor
    cursor += len(names)
    entry_off = cursor
    entry_len = draw(st.integers(min_value=0, max_value=8))

    modref = bytearray()
    for i in range(n_modules):
        modref += struct.pack("<H", name_offsets[i])

    import_blocks = bytearray()
    mix_at = 0
    for _mod in range(n_modules):
        count = draw(st.integers(min_value=0, max_value=3))
        import_blocks += struct.pack("<H", count)
        for _ in range(count):
            # A by-name entry may only point into the names blob, so it is
            # drawn as an ordinal when no name was written.
            by_name = bool(name_offsets) and (
                import_mix[mix_at % len(import_mix)] if import_mix else True
            )
            mix_at += 1
            if by_name:
                off = draw(
                    st.one_of(
                        st.sampled_from(name_offsets),
                        st.integers(min_value=0, max_value=len(names) - 1),
                    )
                )
                import_blocks += struct.pack("<H", 0x8000 | off)
            else:
                import_blocks += struct.pack("<H", draw(st.integers(min_value=0, max_value=0xFFFE)))
    if draw(st.booleans()):
        # A forged terminator or a count past EOF: the import walk must bail.
        import_blocks += struct.pack("<H", draw(st.sampled_from([0xFFFF, 0x2000, 0x7FFF])))

    header = bytearray(_NE_HEADER_SIZE)
    header[0:2] = b"NE"
    header[0x02] = draw(st.integers(min_value=0, max_value=0xFF))  # linker version
    _put16(header, 0x04, entry_off)
    _put16(header, 0x06, entry_len)
    _put16(header, 0x0C, draw(st.integers(min_value=0, max_value=0xFFFF)))  # flags
    _put16(header, 0x0E, draw(st.integers(min_value=0, max_value=0xFFFF)))  # autodata segment
    _put16(header, 0x1C, n_segments)
    _put16(header, 0x1E, n_modules)
    _put16(header, 0x22, segment_off)
    _put16(header, 0x26, resident_off)
    _put16(header, 0x28, modref_off)
    _put16(header, 0x2A, names_off)
    _put16(header, 0x32, draw(st.integers(min_value=0, max_value=0x10)))  # alignment shift

    mz = draw(st.binary(min_size=0, max_size=16))
    tables = (
        bytes(exports_blob)
        + bytes(seg_table)
        + bytes(modref)
        + bytes(names)
        + draw(st.binary(min_size=0, max_size=entry_len))
        + bytes(import_blocks)
    )
    spec = NeSpec(
        tuple(module_names), tuple(imported), tuple(zip(exports, export_ordinals, strict=True))
    )
    return bytes(mz) + bytes(header) + tables, len(mz), spec


@settings(max_examples=300, deadline=None)
@given(ne_blob())
def test_ne_tables_robust_on_structured_blobs(data: tuple[bytes, int, NeSpec]) -> None:
    """Fuzz: linker-shaped NE tables with forgeable record contents.  Each
    parser either raises :class:`NeParseError` or returns a well-shaped result;
    segments are 1-based and contiguous, absent segments carry no length, and
    every name the parsers report is one that was actually written."""
    from rebrew.ne_loader import (
        NeExport,
        NeParseError,
        NeSegment,
        parse_exports,
        parse_imports,
        parse_ne_header,
        parse_segments,
    )

    blob, ne_offset, spec = data
    header = parse_ne_header(blob, ne_offset)

    try:
        segments = parse_segments(blob, ne_offset, header)
    except NeParseError:
        segments = None
    if segments is not None:
        assert len(segments) == header.segment_count
        for i, seg in enumerate(segments):
            assert isinstance(seg, NeSegment)
            assert seg.index == i + 1
            assert seg.file_offset >= 0
            assert seg.min_allocation > 0
            if not seg.on_disk:
                assert seg.file_offset == 0
                assert seg.length == 0

    modules: list[Any] = []
    with suppress(NeParseError):
        modules = parse_imports(blob, ne_offset, header)
    # The module walk either fails outright or yields every module it was told
    # to read, with the names the builder wrote.
    assert [mod.module for mod in modules] == list(spec.module_names)
    for mod in modules:
        assert isinstance(mod.module, str)
        assert isinstance(mod.imports, list)
        for imp in mod.imports:
            if imp.name is not None:
                assert imp.name in set(spec.imported_names) | set(spec.module_names)
            else:
                assert 0 <= imp.ordinal <= 0xFFFE

    exports = parse_exports(blob, ne_offset, header)
    assert isinstance(exports, list)
    for exp in exports:
        assert isinstance(exp, NeExport)
        assert isinstance(exp.name, str)
        assert (exp.name, exp.ordinal) in spec.exports


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=512), st.integers(min_value=0, max_value=64))
def test_ne_tables_robust_on_random_bytes(blob: bytes, ne_offset: int) -> None:
    """Fuzz: arbitrary bytes at an arbitrary offset.  Anything the loader
    refuses must surface as :class:`NeParseError`, never a traceback."""
    from rebrew.ne_loader import (
        NeParseError,
        parse_exports,
        parse_imports,
        parse_ne_header,
        parse_segments,
    )

    try:
        header = parse_ne_header(blob, ne_offset)
    except NeParseError:
        return
    with suppress(NeParseError):
        parse_segments(blob, ne_offset, header)
    with suppress(NeParseError):
        parse_imports(blob, ne_offset, header)
    with suppress(NeParseError):
        parse_exports(blob, ne_offset, header)


# ---------------------------------------------------------------------------
# rebrew.lzexe — LZEXE 0.90/0.91 bitstream decompressor
# ---------------------------------------------------------------------------

#: End-of-stream token: control bits ``0, 1`` select the word-match path, and
#: ``span=0xFF, lenb=0xF8`` decodes to span 0xFFFF (distance 1, valid for any
#: non-empty output) with ``lenb & 0x07 == 0``, so the trailing zero byte
#: terminates the load module.
_TERMINATOR_BITS = (0, 1)
_TERMINATOR_BYTES = (0xFF, 0xF8, 0x00)


def _literal_stream(payload: bytes) -> bytes:
    """Encode *payload* as an all-literal LZEXE bitstream plus an end token.

    The reader's refills are not aligned with its token bits: a 16-bit control
    word supplies 16 tokens, but the refill that loads the *next* word happens
    while the 16th bit is being consumed, so it lands in the file ahead of the
    literal byte that bit introduces.  The layout is therefore reproduced by
    simulating the same read order (every read advances the same cursor) rather
    than by assuming one control word per 16 payload bytes.
    """
    assert payload
    bits = [1] * len(payload) + list(_TERMINATOR_BITS)
    words = [sum(b << j for j, b in enumerate(bits[i : i + 16])) for i in range(0, len(bits), 16)]
    out = bytearray(words[0].to_bytes(2, "little"))
    word, left, next_word = words[0], 16, 1
    for k, want in enumerate(bits):
        bit = word & 1
        assert bit == want, "encoder disagrees with the reader's bit order"
        if left == 1:
            refill = words[next_word] if next_word < len(words) else 0
            next_word += 1
            out += refill.to_bytes(2, "little")
            word, left = refill, 16
        else:
            word >>= 1
            left -= 1
        if k < len(payload):
            out.append(payload[k])
        elif k == len(bits) - 1:
            # Second header bit completes the word-match token; the reader
            # reads span/lenb/end byte and stops.
            out += bytes(_TERMINATOR_BYTES)
    return bytes(out)


@settings(max_examples=200, deadline=None)
@given(st.binary(min_size=0, max_size=256), st.integers(min_value=0, max_value=256))
def test_decompress_random_bytes_no_crash(blob: bytes, stream_off: int) -> None:
    """Fuzz: arbitrary bytes at an arbitrary stream offset.  The decompressor
    either raises :class:`NotLzexeError` or returns output within the budget —
    never a bare ``struct.error``/``IndexError``, never a decompression bomb."""
    from rebrew.lzexe import NotLzexeError, _decompress

    max_out = 64
    try:
        out = _decompress(blob, stream_off, max_out=max_out)
    except NotLzexeError:
        return
    assert len(out) <= max_out


@settings(max_examples=50, deadline=None)
@given(st.binary(min_size=0, max_size=32))
def test_decompress_derived_budget_is_bounded(blob: bytes) -> None:
    """With the budget derived from the packed size, output can never exceed
    ``16 * len(data) + 64 KiB`` however long the bitstream runs."""
    from rebrew.lzexe import NotLzexeError, _decompress

    data = blob + b"\x00" * 2
    try:
        out = _decompress(data, 0)
    except NotLzexeError:
        return
    assert len(out) <= 16 * len(data) + 0x10000


_literal_payload = st.binary(min_size=1, max_size=1024)


@settings(max_examples=100, deadline=None)
@given(_literal_payload)
def test_decompress_literal_stream_roundtrip(payload: bytes) -> None:
    """Pair assertion across the compression boundary: a literal-only stream
    decodes to exactly the bytes that were written into it."""
    from rebrew.lzexe import _decompress

    assert _decompress(_literal_stream(payload), 0, max_out=len(payload)) == payload


@st.composite
def _payload_and_budget(draw: st.DrawFn) -> tuple[bytes, int]:
    """A literal payload of at least two bytes plus a budget strictly below its
    length, so a literal token is always refused."""
    payload = draw(st.binary(min_size=2, max_size=1024))
    return payload, draw(st.integers(min_value=1, max_value=len(payload) - 1))


@settings(max_examples=50, deadline=None)
@given(_payload_and_budget())
def test_decompress_respects_budget(data: tuple[bytes, int]) -> None:
    """A stream that would decode to the full payload must stop at the budget
    instead of over-producing."""
    payload, max_out = data
    from rebrew.lzexe import NotLzexeError, _decompress

    with pytest.raises(NotLzexeError, match="exceeds"):
        _decompress(_literal_stream(payload), 0, max_out=max_out)


@settings(max_examples=100, deadline=None)
@given(st.binary(min_size=0, max_size=128), st.integers(min_value=0, max_value=0xFFFF))
def test_reloc_tables_robust_on_random_bytes(blob: bytes, offset: int) -> None:
    """Fuzz: the 0.90/0.91 relocation decoders must terminate, report a
    truncated table as :class:`NotLzexeError`, and emit only valid
    offset/segment pairs when they do return."""
    from rebrew.lzexe import NotLzexeError, _reloc_table90, _reloc_table91

    data = blob + b"\x00" * 2
    for decode in (_reloc_table90, _reloc_table91):
        try:
            relocs, end = decode(data, offset)
        except NotLzexeError:
            continue
        assert offset <= end <= len(data)
        for rel_off, rel_seg in relocs:
            assert 0 <= rel_off <= 0xFFFF
            assert 0 <= rel_seg <= 0xFFFF
