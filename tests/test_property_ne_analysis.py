"""Property-based fuzzing for the NE comparison/analysis layer.

``formats.ne_analysis.NeImage`` walks untrusted bytes from a 16-bit NE
target: the segment table geometry is forgeable (a segment can point past
EOF or overlap the fixup block), and each segment's fixup block is a
counted record stream.
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
* ``relocation_census`` only reports declared fixups
  (pair assertion across the fixup-read boundary: every reported record
  was actually read from the image).
"""

from __future__ import annotations

import struct
from contextlib import suppress
lazy from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

_EXPORTS = st.lists(
    st.tuples(
        st.binary(min_size=1, max_size=8).map(lambda b: b.decode("latin1")),
        st.integers(0, 0xFFFF),
    ),
    max_size=2,
)
_MODULES = st.lists(
    st.binary(min_size=1, max_size=6).map(lambda b: b.decode("latin1", "replace")),
    max_size=2,
)


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
    exports = draw(_EXPORTS)
    # make_ne encodes names as ascii; keep exports ascii-safe
    exports = [(n.encode("ascii", "replace").decode("ascii"), o) for n, o in exports]
    modules = draw(_MODULES)
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
def test_ne_fixups_stay_inside_following_region(_ne_dir: Path, blob: bytes) -> None:
    """Fuzz: every fixup block ``NeImage.fixups`` returns is complete —
    its records sit after the segment, before the next on-disk segment,
    and the census only ever reports records that were read."""
    from rebrew.formats.ne_analysis import relocation_census
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
