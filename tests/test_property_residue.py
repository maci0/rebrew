"""Hypothesis fuzz for the residue image parsers (untrusted PE bytes).

``rebrew.residue`` reads the built image and the reference target byte for
byte, so every field it takes from the PE header (section count, raw pointers,
raw sizes, virtual sizes) is attacker-controlled when the input is not the
image the toolchain produced.  These targets assert the invariants that make
the reader safe: a non-PE raises the module's own error, a parsed section
table never claims bytes outside the buffer, and a report is only produced
when there is a ``.text`` extent to compare.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from rebrew.residue import (
    ResidueError,
    _sections,
    layout_map_gate_note,
    residue_report,
)


def _pe_image(sections: list[tuple[str, int, int, int, int]], total: int = 0x400) -> bytes:
    """Build a minimal PE carrying *sections* as (name, va, vsize, raw_size, raw_ptr)."""
    raw = bytearray(total)
    raw[0:2] = b"MZ"
    raw[0x3C:0x40] = struct.pack("<I", 0x80)
    raw[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", raw, 0x80 + 6, len(sections))
    struct.pack_into("<H", raw, 0x80 + 20, 0xE0)
    off = 0x80 + 24 + 0xE0
    for index, (name, va, vsize, raw_size, raw_ptr) in enumerate(sections):
        entry = off + index * 40
        raw[entry : entry + 8] = name.encode("latin1").ljust(8, b"\0")[:8]
        struct.pack_into("<IIII", raw, entry + 8, vsize, va, raw_size, raw_ptr)
    return bytes(raw)


def _text_pe(body: bytes, raw_ptr: int = 0x200, raw_size: int | None = None) -> bytes:
    return _pe_image(
        [
            (".text", 0x1000, len(body), len(body) if raw_size is None else raw_size, raw_ptr),
            (".data", 0x2000, 0, 0, 0),
        ],
        total=max(0x400, raw_ptr + len(body)),
    )


def _mutate(blob: bytes, noise: bytes) -> bytes:
    data = bytearray(blob)
    for index, value in enumerate(noise):
        data[(value * 7 + index * 13) % len(data)] ^= value or 1
    return bytes(data)


@given(st.binary(max_size=512))
@settings(max_examples=300, deadline=None)
def test_sections_rejects_or_bounds_arbitrary_bytes(blob: bytes) -> None:
    """Arbitrary bytes into ``_sections`` raise ``ResidueError`` or return a
    table whose extents lie inside the buffer -- never struct.error,
    IndexError, or a section pointing past the end of the image."""
    try:
        sections = _sections(blob)
    except ResidueError:
        return
    for name, (_va, _vsize, raw_ptr, raw_size) in sections.items():
        assert raw_size > 0, name
        assert 0 <= raw_ptr < len(blob), name
        assert raw_ptr + raw_size <= len(blob), name


@given(
    st.binary(max_size=64),
    st.lists(
        st.tuples(
            st.integers(min_value=-0x10000, max_value=0x10000),
            st.integers(min_value=-0x10000, max_value=0x10000),
        ),
        min_size=1,
        max_size=6,
    ),
)
@settings(max_examples=200, deadline=None)
def test_residue_report_bounds_hostile_section_geometry(
    body: bytes, geometry: list[tuple[int, int]]
) -> None:
    """Section extents that point outside the image (negative, past EOF, huge)
    must be clipped, and the reported text span must stay in bounds."""
    ref_body = body or b"\x01"
    raw_size, raw_ptr = geometry[0]
    reference = _text_pe(ref_body, raw_ptr=0x200, raw_size=raw_size & 0xFFFF)
    built = _text_pe(bytes(reference[0x200 : 0x200 + len(ref_body)]))
    try:
        report = residue_report(built, reference, [], 0)
    except ResidueError:
        return
    assert 0 <= report["text_size"] <= len(ref_body)
    assert report["text_differing"] <= report["text_size"]
    assert 0.0 <= report["text_percent"] <= 100.0
    assert sum(f["bytes"] for f in report["functions"]) == report["text_differing"]


@given(st.binary(max_size=48), st.binary(max_size=48))
@settings(max_examples=150, deadline=None)
def test_residue_report_rejects_malformed_images(ref_body: bytes, built_body: bytes) -> None:
    """Two fuzzed images either both parse and report, or fail loudly with
    ``ResidueError`` -- a truncated or headerless image is never reported as a
    clean zero residue."""
    noise = ref_body + built_body
    reference = _mutate(_text_pe(ref_body or b"\x01"), noise)
    built = _mutate(_text_pe(built_body or b"\x02"), noise)
    assume(reference or built)
    try:
        report = residue_report(built, reference, [], 0)
    except ResidueError:
        return
    assert report["text_size"] >= 0
    assert set(report["sections"])


def test_residue_report_requires_text_on_both_sides() -> None:
    """A PE with no .text is a measurement error, not a zero residue."""
    image = _pe_image([(".data", 0x1000, 0x10, 0x10, 0x200)])
    with pytest.raises(ResidueError):
        residue_report(image, image, [], 0)


def test_sections_clips_extent_past_eof() -> None:
    """A raw size reaching past the end of the file is truncated, not trusted."""
    image = _pe_image([(".text", 0x1000, 0x100, 0x4000, 0x200)], total=0x400)
    sections = _sections(image)
    assert sections[".text"][3] == 0x400 - 0x200


def test_layout_map_gate_reports_unmeasured_for_an_empty_map() -> None:
    """No layout-map entries means alignment was never measured.

    Dividing by the empty denominator used to print "coverage 0.00% below
    gate; output is intermediate, not runnable" — a fabricated measurement
    that contradicts ``postlink.check_text_alignment``, which returns
    silently on the same input.
    """
    note = layout_map_gate_note((0, 0, 0, 0))
    assert note is not None
    assert "not measured" in note
    assert "%" not in note


def test_layout_map_gate_flags_a_real_shortfall_and_passes_a_full_map() -> None:
    """A populated map keeps the percentage gate: 50% warns, 100% is silent."""
    below = layout_map_gate_note((5, 10, 0, 0))
    assert below is not None
    assert "50.00% below gate" in below
    assert layout_map_gate_note((10, 10, 5, 5)) is None
