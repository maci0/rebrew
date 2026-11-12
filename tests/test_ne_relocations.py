"""NE segment relocations applied to a raw slice for the decompiler."""

from __future__ import annotations

import struct

import pytest
from bin_util import make_ne

from rebrew.formats.ne_loader import NeParseError, parse_segments, read_ne_header
from rebrew.formats.ne_relocations import build_ne_slice, read_segment_fixups

CODE_FLAGS = 0x0100
DATA_FLAGS = 0x0001
FAR_CALL = b"\x9a\xff\xff\x00\x00"
#: push bp; mov bp, sp; mov ax, [bp+4]; add ax, [bp+6]; push ax; far call (import); far call
#: (segment 2); near call to 0x20; far call (own segment); pop bp; retf; padding; a second function at 0x20.
CALLER = (
    b"\x55\x8b\xec\x8b\x46\x04\x03\x46\x06\x50"
    + FAR_CALL
    + FAR_CALL
    + b"\xe8\x09\x00"
    + FAR_CALL
    + b"\x5d\xcb"
).ljust(0x20, b"\x90")
CALLEE = b"\x55\x8b\xec\x5d\xcb"
CODE = CALLER + CALLEE
IMPORT_LOCATION = 0x0B
OTHER_SEGMENT_LOCATION = 0x10
OWN_SEGMENT_LOCATION = 0x18
PADDING_LOCATION = 0x1E


def _records(*records: tuple[int, int, int, int, int]) -> bytes:
    """Relocation block: the count, then (source, flags, location, target1, target2) records."""
    return struct.pack("<H", len(records)) + b"".join(
        struct.pack("<BBHHH", *record) for record in records
    )


FIXUPS = _records(
    (3, 1, IMPORT_LOCATION, 1, 176),  # far pointer to KERNEL ordinal 176
    (3, 0, OTHER_SEGMENT_LOCATION, 2, 0x0123),  # far pointer to segment 2, offset 0x123
    (3, 0, OWN_SEGMENT_LOCATION, 1, 0x0020),  # far pointer to segment 1, offset 0x20
)


def _ne(code: bytes = CODE, fixups: bytes = FIXUPS) -> bytes:
    return make_ne(
        segments=[(code, CODE_FLAGS, fixups), (b"\x00" * 0x130, DATA_FLAGS)],
        modules=["KERNEL"],
    )


def test_a_far_call_to_an_import_or_another_segment_targets_a_named_stub() -> None:
    sl = build_ne_slice(_ne(), 1)
    stubs = {name: offset for offset, name in sl.stub_names.items()}
    assert set(stubs) == {"KERNEL_176", "sub_10123"}
    for location, name in ((IMPORT_LOCATION, "KERNEL_176"), (OTHER_SEGMENT_LOCATION, "sub_10123")):
        assert struct.unpack_from("<H", sl.image, location)[0] == stubs[name]
        assert stubs[name] >= len(CODE)
    assert sl.image[stubs["KERNEL_176"] : stubs["KERNEL_176"] + 1] == b"\xcb"
    assert sl.applied == 3
    assert sl.unapplied == {}


def test_a_far_call_inside_the_segment_gets_its_own_offset_and_selector_zero() -> None:
    sl = build_ne_slice(_ne(), 1)
    assert struct.unpack_from("<HH", sl.image, OWN_SEGMENT_LOCATION) == (0x20, 0)
    assert sl.image[: len(CODE)][0x20:] == CALLEE


def test_decompiled_calls_are_named_by_flat_address() -> None:
    sl = build_ne_slice(_ne(), 1)
    stubs = {name: offset for offset, name in sl.stub_names.items()}
    code = (
        f"sub_0();sub_20();sub_{stubs['sub_10123']:x}();sub_{stubs['KERNEL_176']:x}();sub_ffff();"
    )
    assert sl.name_calls(code) == "sub_0000();sub_0020();sub_10123();KERNEL_176();sub_ffff();"
    second = build_ne_slice(_ne(), 2)
    assert second.name_calls("sub_30();") == "sub_10030();"


def test_fixup_chains_are_followed_and_overwritten() -> None:
    code = bytearray(CODE)
    struct.pack_into("<H", code, IMPORT_LOCATION, OWN_SEGMENT_LOCATION)  # link to the next location
    struct.pack_into("<H", code, OWN_SEGMENT_LOCATION, 0xFFFF)
    fixups = _records((3, 0, IMPORT_LOCATION, 1, 0x0020))
    data = _ne(bytes(code), fixups)
    ne_offset, header = read_ne_header(data)
    segment = parse_segments(data, ne_offset, header)[0]
    chain = read_segment_fixups(data, segment, bytes(code))
    assert sorted(chain) == [IMPORT_LOCATION, OWN_SEGMENT_LOCATION]
    sl = build_ne_slice(data, 1)
    assert struct.unpack_from("<HH", sl.image, IMPORT_LOCATION) == (0x20, 0)
    assert struct.unpack_from("<HH", sl.image, OWN_SEGMENT_LOCATION) == (0x20, 0)
    assert sl.applied == 2


def test_fixups_that_cannot_be_applied_are_cleared_and_counted() -> None:
    fixups = _records(
        (5, 1, PADDING_LOCATION, 1, 5),  # an import's offset only: no address to give it
        (3, 3, OTHER_SEGMENT_LOCATION, 1, 0),  # an OS fixup: bytes stay as in the file
        (3, 0, OWN_SEGMENT_LOCATION, 0xFF, 99),  # movable entry 99, not in the (empty) entry table
    )
    code = bytearray(CODE)
    code[PADDING_LOCATION : PADDING_LOCATION + 2] = b"\x34\x12"
    sl = build_ne_slice(_ne(bytes(code), fixups), 1)
    assert sl.image[PADDING_LOCATION : PADDING_LOCATION + 2] == b"\x00\x00"
    assert sl.image[OTHER_SEGMENT_LOCATION : OTHER_SEGMENT_LOCATION + 4] == b"\xff\xff\x00\x00"
    assert sl.image[OWN_SEGMENT_LOCATION : OWN_SEGMENT_LOCATION + 4] == b"\x00\x00\x00\x00"
    assert sl.applied == 0
    assert sl.unapplied == {
        "import offsets and selectors": 1,
        "OS fixups left as in the file": 1,
        "entry ordinals missing from the entry table": 1,
    }
    summary = sl.summary()
    assert "0 relocations applied" in summary
    assert "1 OS fixups left as in the file" in summary


class TestAdditiveByteFixup:
    @pytest.mark.parametrize("trailing", [b"", b"\xa5"])
    @pytest.mark.parametrize(
        ("addend", "target", "expected"), [(0x12, 0x34, 0x46), (0xF0, 0x30, 0x20)]
    )
    def test_one_byte_addend_fits_at_segment_end(
        self, trailing: bytes, addend: int, target: int, expected: int
    ) -> None:
        code = b"\x90" + bytes([addend]) + trailing
        data = _ne(code, _records((0, 4, 1, 1, target)))
        sl = build_ne_slice(data, 1)
        assert sl.image == b"\x90" + bytes([expected]) + trailing
        assert sl.applied == 1
        assert sl.unapplied == {}


class TestFixupSegmentBoundary:
    @pytest.mark.parametrize("crosses_boundary", [False, True])
    def test_fixup_table_stops_at_next_stored_segment(self, crosses_boundary: bool) -> None:
        # Six bytes plus one count and record end exactly at the next sector.
        code = b"\xff\xff\x90\x90\x90\x90"
        records = bytearray(_records((5, 0, 0, 1, 0x20)))
        if crosses_boundary:
            struct.pack_into("<H", records, 0, 2)
        data = _ne(code, bytes(records))
        if crosses_boundary:
            with pytest.raises(NeParseError, match="truncated fixup block"):
                build_ne_slice(data, 1)
        else:
            sl = build_ne_slice(data, 1)
            assert sl.image == b"\x20\x00" + code[2:]
            assert sl.applied == 1
            assert sl.unapplied == {}


def test_a_truncated_relocation_block_is_a_parse_error() -> None:
    data = _ne(CODE, struct.pack("<H", 500))
    with pytest.raises(NeParseError, match="truncated fixup block"):
        build_ne_slice(data[: len(data) - 40], 1)


def test_a_segment_that_is_not_in_the_file_is_refused() -> None:
    with pytest.raises(NeParseError, match="does not exist"):
        build_ne_slice(_ne(), 3)
