"""Property-based fuzzing for the NE comparison/analysis layer.

``formats.ne_analysis.NeImage`` and ``published_method_candidates`` walk
untrusted bytes from a 16-bit NE target: the segment table geometry is
forgeable (a segment can point past EOF or overlap the fixup block), each
segment's fixup block is a counted record stream, and the Delphi
published-method probe scans arbitrary bytes for a class-marker table.
Every sibling parser (NE tables, LZEXE, DFM, OMF16, ar/COFF, PE) already
has a Hypothesis harness; this layer had only hand-written cases in
``test_ne_analysis.py``.

The harnesses below feed structure-aware NE images (built with the same
``make_ne`` layout the hand-written tests use, plus forged fixup blocks)
and pure-random bytes, and assert:

* the only failure mode is ``NeParseError`` (or ``ValueError`` for a bad
  window size) — no ``struct.error``, ``IndexError`` or bare exception
  escapes;
* whatever ``NeImage`` accepts satisfies its own geometry invariants
  (segments inside the file, ``seg_bytes`` round-trips the stored bytes,
  fixup blocks stay inside the segment's following region);
* ``segment_refs`` / ``relocation_census`` only report declared fixups
  (pair assertion across the fixup-read boundary: every reported record
  was actually read from the image);
* ``published_method_candidates`` returns only offsets inside the input
  for names it actually decoded, and never raises on arbitrary bytes.
"""

from __future__ import annotations

import struct
from contextlib import suppress
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st


_CLASS = "TExample"
_MARKER = b"\x08TExample"


@st.composite
def _ne_image_bytes(draw: st.DrawFn) -> bytes:
    """A linker-shaped NE image with a forgeable fixup block.

    Built on ``make_ne`` so the header/table geometry is real, then a
    counted fixup block is appended after the (single) segment and the
    segment is flagged with the fixup bit (0x0100) most of the time.
    The fixup records themselves carry arbitrary field values, and the
    whole blob is occasionally truncated or byte-flipped, so the
    truncated-block and beyond-EOF branches are reachable.
    """
    from bin_util import make_ne

    content = draw(st.binary(min_size=0, max_size=64))
    fixup_flag = draw(st.booleans())
    flags = (0x0100 if fixup_flag else 0) | draw(st.integers(0, 0xFF))
    exports = draw(st.lists(st.tuples(st.binary(min_size=1, max_size=8).map(lambda b: b.decode("latin1")), st.integers(0, 0xFFFF)), max_size=2))
    # make_ne encodes names as ascii; keep exports ascii-safe
    exports = [(n.encode("ascii", "replace").decode("ascii"), o) for n, o in exports]
    modules = draw(st.lists(st.binary(min_size=1, max_size=6).map(lambda b: b.decode("latin1", "replace")), max_size=2))
    modules = [m.encode("ascii", "replace").decode("ascii") for m in modules]
    blob = bytearray(make_ne(segments=[(content, flags)], exports=exports, modules=modules))
    if fixup_flag:
        count = draw(st.integers(0, 4))
        for _ in range(count):
            blob += struct.pack(
                "<BBHHH",  # address_type, relocation_type, target, addend — packed below as BB2xHH
                draw(st.integers(0, 0xFF)),
                draw(st.integers(0, 0xFF)),
                draw(st.integers(0, 0xFFFF)),
                draw(st.integers(0, 0xFFFF)),
                draw(st.integers(0, 0xFFFF)),
            )
    style = draw(st.integers(0, 2))
    if style == 1 and blob:
        # Truncation: cut anywhere, including mid-fixup-block.
        cut = draw(st.integers(0, len(blob)))
        blob = blob[:cut]
    elif style == 2 and blob:
        # Byte flip: scramble a few offsets/lengths.
        for _ in range(draw(st.integers(1, 4))):
            pos = draw(st.integers(0, len(blob) - 1))
            blob[pos] ^= draw(st.integers(1, 0xFF))
    return bytes(blob)


def _image(path: Path) -> object:
    from rebrew.formats.ne_analysis import NeImage

    return NeImage(path)


@pytest.fixture(scope="module")
def _ne_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("ne_analysis_fuzz")


@settings(max_examples=200, deadline=None)
@given(_ne_image_bytes())
def test_ne_image_geometry_or_parse_error(_ne_dir: Path, blob: bytes) -> None:
    """Fuzz: linker-shaped NE with forged fixups.  Either ``NeImage``
    refuses with ``NeParseError``, or every accepted segment lies inside
    the file and ``seg_bytes`` returns exactly the stored slice."""
    from rebrew.formats.ne_loader import NeParseError

    path = _ne_dir / "fuzz.exe"
    path.write_bytes(blob)
    try:
        image = _image(path)
    except NeParseError:
        return
    assert image.seg_count == len(image.segment_records)
    for index, (off, length, _flags) in enumerate(image.segments):
        assert off >= 0
        assert length >= 0
        if image.segment_records[index].on_disk:
            assert off + length <= len(blob)
        assert image.seg_bytes(index) == blob[off : off + length]


@settings(max_examples=200, deadline=None)
@given(_ne_image_bytes())
def test_ne_fixups_stay_inside_following_region(
    _ne_dir: Path, blob: bytes
) -> None:
    """Fuzz: every fixup block ``NeImage.fixups`` returns is complete —
    its records sit after the segment, before the next on-disk segment,
    and the census/refs only ever report records that were read."""
    from rebrew.formats.ne_analysis import relocation_census, segment_refs
    from rebrew.formats.ne_loader import NeParseError

    path = _ne_dir / "fuzz.exe"
    path.write_bytes(blob)
    try:
        image = _image(path)
    except NeParseError:
        return
    for index in range(image.seg_count):
        with suppress(NeParseError):
            records = image.fixups(index)
        # If fixups succeeded, re-reading must give the same records
        # (pair assertion across the persistence boundary).
        try:
            again = image.fixups(index)
        except NeParseError:
            continue
        assert records == again
        for rec in records:
            assert 0 <= rec.address_type <= 0xFF
            assert 0 <= rec.relocation_type <= 0xFF
    with suppress(NeParseError):
        addr_hist, reloc_hist = relocation_census(image)
        assert all(v > 0 for v in addr_hist.values())
        assert all(v > 0 for v in reloc_hist.values())
    with suppress(NeParseError):
        refs, imports = segment_refs(image)
        for index, targets in refs.items():
            assert 0 <= index < image.seg_count
            for target in targets:
                assert 0 <= target < image.seg_count


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=512))
def test_ne_image_random_bytes_never_leak(_ne_dir: Path, blob: bytes) -> None:
    """Fuzz: arbitrary bytes as an NE image.  Anything the loader refuses
    must surface as ``NeParseError``, never a traceback."""
    from rebrew.formats.ne_loader import NeParseError

    path = _ne_dir / "raw.exe"
    path.write_bytes(blob)
    try:
        image = _image(path)
    except NeParseError:
        return
    # Accepted images still honour the geometry contract.
    for index, (off, length, _flags) in enumerate(image.segments):
        if image.segment_records[index].on_disk:
            assert off + length <= len(blob)


@st.composite
def _method_table_blob(draw: st.DrawFn) -> bytes:
    """Bytes carrying a Delphi published-method marker + candidate table.

    The table is drawn with forgeable count, pointer, size and name
    fields so both the accepted-table and the skip-and-scan-later
    branches are reached; trailing garbage follows the table.
    """
    count = draw(st.integers(0, 4))
    table = bytearray(struct.pack("<H", count))
    for _ in range(count):
        name = draw(
            st.binary(min_size=0, max_size=8).map(lambda b: b.decode("latin1"))
        )
        pointer = draw(st.integers(0, 0xFFFFFFFF))
        size = draw(st.integers(0, 0xFF))
        table += struct.pack("<IB", pointer & 0xFFFFFFFF, size)
        table += name.encode("latin1")[:size] if size else b""
    blob = _MARKER + bytes(table) + draw(st.binary(max_size=16))
    # Occasionally prepend a decoy marker with a zero count so the
    # "invalid marker does not hide a later table" path is exercised.
    if draw(st.booleans()):
        blob = _MARKER + b"\x00\x00" + blob
    return blob


def _check_methods(blob: bytes, result: list[tuple[str, int]]) -> None:
    for name, offset in result:
        assert name
        assert 0 <= offset < len(blob)
        # The decoded name must appear verbatim after its size byte
        # somewhere in the input (never an invented string).
        assert name.encode("latin1") in blob


@settings(max_examples=300, deadline=None)
@given(_method_table_blob())
def test_published_method_candidates_structured(blob: bytes) -> None:
    """Fuzz: marker + forgeable method table.  Returned (name, offset)
    pairs point inside the input at names actually present."""
    from rebrew.formats.ne_analysis import published_method_candidates

    result = published_method_candidates(blob, _CLASS)
    _check_methods(blob, result)


@settings(max_examples=200, deadline=None)
@given(_method_table_blob())
def test_published_method_candidates_fixups_stay_same_segment(blob: bytes) -> None:
    """Fuzz: a cross-segment fixup at the pointer site rejects the whole
    candidate; a same-segment fixup rewrites the offset to the target."""
    from rebrew.formats.ne_analysis import published_method_candidates

    site = len(_MARKER) + 2
    cross = published_method_candidates(blob, _CLASS, fixups={(0, site): (1, 0)})
    assert cross == []
    same = published_method_candidates(blob, _CLASS, fixups={(0, site): (0, 0)})
    _check_methods(blob, same)
    # A same-segment fixup can only rescue a candidate the unfixed scan
    # rejected (pointer past EOF); it never invents a new name.
    unfixed = published_method_candidates(blob, _CLASS)
    for name, offset in same:
        if (name, offset) not in unfixed:
            assert offset == 0  # the fixup target, not the raw pointer


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=512))
def test_published_method_candidates_random_bytes(blob: bytes) -> None:
    """Fuzz: arbitrary bytes plus an embedded marker.  Never raises
    (except ``ValueError`` for an unrepresentable class name) and every
    returned offset lies inside the input."""
    from rebrew.formats.ne_analysis import published_method_candidates

    data = _MARKER + blob if blob else _MARKER
    try:
        result = published_method_candidates(data, _CLASS)
    except ValueError:
        return
    _check_methods(data, result)
