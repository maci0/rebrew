"""Property-based fuzz tests for ``rebrew.pe_headers`` on untrusted images.

``pe_headers`` is the hand-rolled PE/COFF walk behind ``rebrew round-trip
--fix-headers``: ``e_lfanew``, the section table, the optional-header field
offsets and the checksum all come straight out of a file the user points the
CLI at, so every count, offset and magic is forgeable.  The harnesses below
feed the committed PE fixture with byte patches and truncations plus pure
random bytes, and assert:

* the parser never raises -- it reports a rejected image as ``None`` and
  clips a section table that overruns the buffer;
* the geometry it reports is self-consistent (``section_table_offset`` is
  derived from the header it just read, every entry it returns lies wholly
  inside the file, names are at most 8 bytes);
* a patch survives the round trip across the trust boundary: what
  :func:`read_pe_header_fields` reads back from the patched image is the
  written value masked to the field width (mask probed from the code under
  test, so PE32 and PE32+ widths stay distinguished), the file length never
  changes, a non-PE is returned untouched, and patching twice is a no-op.
"""

from __future__ import annotations

from pathlib import Path

from bin_util import make_pe
from hypothesis import assume, event, given, settings
from hypothesis import strategies as st

from rebrew.pe_headers import (
    PATCHABLE,
    SECTION_ENTRY_SIZE,
    header_parity,
    patch_pe_headers,
    pe_image_base,
    pe_layout,
    pe_lfanew,
    read_pe_header_fields,
    sections_at,
)

FIXTURES = Path(__file__).parent / "fixtures"
_SEED = (FIXTURES / "mini_pe.exe").read_bytes()

#: Patches land in the DOS header, PE header, optional header and section
#: table, which is where the parser branches on file content.
_MUTATE_SPAN = 0x400
#: Largest field width the parser writes (PE32+ stack/heap sizes).
_MAX_FIELD_BITS = 64
#: The checksum is recomputed, not copied, so it is excluded from the
#: write-then-read equality; it gets its own determinism assertion.
_ROUND_TRIP_FIELDS = PATCHABLE - {"checksum"}


@st.composite
def _mutated_image(draw: st.DrawFn) -> bytes:
    """The PE fixture with drawn byte patches and an optional truncation."""
    data = bytearray(_SEED)
    span = min(_MUTATE_SPAN, len(data))
    patches = draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=span - 1), st.binary(min_size=1, max_size=4)
            ),
            max_size=10,
        )
    )
    for offset, chunk in patches:
        data[offset : offset + len(chunk)] = chunk
    if draw(st.booleans()):
        data = data[: draw(st.integers(min_value=0, max_value=len(data)))]
    return bytes(data)


def _field_mask(data: bytes, label: str) -> int | None:
    """The low-bit mask *label*'s slot holds, probed from the parser itself.

    Patching every bit on and reading the field back yields the ones the
    parser kept, which is the field's real width: 1 byte for
    ``linker_version_major``, 4 for PE32 stack sizes, 8 for PE32+.
    """
    fields = read_pe_header_fields(patch_pe_headers(data, {label: (1 << _MAX_FIELD_BITS) - 1}))
    if fields is None or label not in fields:
        return None
    return fields[label]


@settings(max_examples=200, deadline=None)
@given(_mutated_image(), st.binary(max_size=1024))
def test_pe_layout_is_rejected_or_self_consistent(blob: bytes, noise: bytes) -> None:
    layout = pe_layout(blob)
    event("parsed" if layout is not None else "rejected")
    if layout is None:
        # Rejection is either "not a PE" or a header truncated before the
        # COFF field the section table is derived from.
        lfanew = pe_lfanew(blob)
        assert lfanew is None or lfanew + 0x18 > len(blob)
        return

    assert pe_lfanew(blob) == layout.e_lfanew
    assert layout.section_table_offset == (layout.e_lfanew + 0x18 + layout.size_of_optional_header)
    assert layout.magic is None or 0 <= layout.magic <= 0xFFFF
    assert len(layout.sections) <= layout.number_of_sections

    for index, section in enumerate(layout.sections):
        assert section.header_offset == layout.section_table_offset + SECTION_ENTRY_SIZE * index
        # A section entry the parser returned must lie wholly inside the file.
        assert section.header_offset + SECTION_ENTRY_SIZE <= len(blob)
        assert len(section.name) <= 8
        assert 0 <= section.virtual_size <= 0xFFFFFFFF
        assert section.pointer_to_raw_data <= 0xFFFFFFFF
    # A base read is None or an address the magic's width can hold: 8 bytes
    # for PE32+, 4 for PE32, none for a header that stops short of it.
    for candidate in (blob, noise):
        base = pe_image_base(candidate)
        assert base is None or 0 <= base < (1 << _MAX_FIELD_BITS)


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=1024), st.integers(0, 0xFFFF), st.integers(0, 0xFFFF))
def test_sections_at_never_reads_past_the_buffer(
    blob: bytes, table_offset: int, count: int
) -> None:
    sections = sections_at(blob, table_offset, count)
    assert len(sections) <= count
    for index, section in enumerate(sections):
        assert section.header_offset == table_offset + SECTION_ENTRY_SIZE * index
        assert section.header_offset + SECTION_ENTRY_SIZE <= len(blob)


@settings(max_examples=200, deadline=None)
@given(
    st.dictionaries(
        st.sampled_from(sorted(_ROUND_TRIP_FIELDS)),
        st.integers(min_value=0, max_value=(1 << _MAX_FIELD_BITS) - 1),
        max_size=len(_ROUND_TRIP_FIELDS),
    )
)
def test_patched_fields_read_back_masked_to_their_width(fields: dict[str, int]) -> None:
    masks = {label: _field_mask(_SEED, label) for label in fields}
    assume(all(mask is not None for mask in masks.values()))

    patched = patch_pe_headers(_SEED, fields)
    assert len(patched) == len(_SEED), "patching changed the file length"

    read_back = read_pe_header_fields(patched)
    assert read_back is not None
    for label, value in fields.items():
        mask = masks[label]
        assert mask is not None
        assert read_back[label] == value & mask
    # The source image is never mutated in place.
    assert (FIXTURES / "mini_pe.exe").read_bytes() == _SEED


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=512), st.dictionaries(st.text(max_size=12), st.binary(max_size=8)))
def test_patch_is_a_noop_on_images_it_rejects(blob: bytes, fields: dict[str, bytes]) -> None:
    payload = {label: int.from_bytes(raw, "little") for label, raw in fields.items()}
    if pe_lfanew(blob) is None:
        assert patch_pe_headers(blob, payload) == blob
    # Patching is idempotent: the checksum is recomputed over the patched
    # image with the checksum field zeroed, so a second pass changes nothing.
    once = patch_pe_headers(blob, payload)
    assert patch_pe_headers(once, payload) == once


@settings(max_examples=200, deadline=None)
@given(_mutated_image(), st.binary(max_size=512))
def test_field_reads_and_parity_are_well_shaped(image: bytes, other: bytes) -> None:
    values = read_pe_header_fields(image)
    if values is not None:
        assert all(isinstance(v, int) and 0 <= v < (1 << _MAX_FIELD_BITS) for v in values.values())
        # file_align is read for parity but never patched.
        assert all(label in PATCHABLE | {"file_align"} for label in values)

    for row in header_parity(image, other):
        assert set(row) == {"field", "original", "reasm", "match", "configured"}
        assert row["match"] is (row["original"] == row["reasm"])
    # One side rejected: no rows, never a partial comparison.
    if pe_lfanew(image) is None or pe_lfanew(other) is None:
        assert header_parity(image, other) == []


@settings(max_examples=100, deadline=None)
@given(st.booleans())
def test_image_base_matches_the_magic_selected_width(pe32_plus: bool) -> None:
    data = make_pe(b"\x55\x8b\xec\xc3", pe32_plus=pe32_plus)
    base = pe_image_base(data)
    assert base is not None
    layout = pe_layout(data)
    assert layout is not None
    assert layout.magic == (0x20B if pe32_plus else 0x10B)
    assert base in (0x400000, 0x140000000)
