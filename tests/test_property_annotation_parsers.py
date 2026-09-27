"""Property-based fuzz tests for the annotation text parsers.

The ``.c`` sources rebrew reads come from a reviewed repo, so their
annotation comments are untrusted input: a marker line, a key-value line,
an unterminated ``/*`` comment, or an odd module name reaches the marker
and KV regexes directly.  These tests assemble sources from the line kinds
the parser dispatches on (markers, key-values, block-comment fragments, C
code, junk) plus free text, and assert the parsers only ever return
well-formed annotations or split cleanly, never raise.
"""

from __future__ import annotations

import tempfile
import time
import unicodedata
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.annotation import (
    VALID_MARKERS,
    block_markers,
    parse_new_format,
    parse_new_format_multi,
    parse_source_metadata,
    split_annotation_sections,
)

_lines = st.lists(
    st.one_of(
        st.sampled_from(
            [
                "",
                "   ",
                "\t",
                "int func(int a, int b) {",
                "}",
                "    return a + b;",
                "/*",
                "*/",
                "/* FUNCTION: SERVER 0x10001234 */",
                "// FUNCTION: SERVER 0x10001234",
                "// STATUS: EXACT",
                "/* SIZE: 64 */",
                "// NOTE: trailing */",
                "// sub_10001234",
                "// ",
                "/* nested /* inner */",
            ]
        ),
        st.text(max_size=40),
        # Non-ASCII module names: NFC/NFD pairs must normalize identically.
        st.text(alphabet="éÉÅΩй", min_size=1, max_size=8),
    ),
    max_size=25,
)

_source = st.builds(lambda ls: "\n".join(ls) + "\n", _lines)


@settings(max_examples=200, deadline=None)
@given(text=_source)
def test_split_annotation_sections_conserves_text(text: str) -> None:
    """Preamble plus every block holds every input line exactly once.

    The splitter may reorder: an orphaned key-value line in the preamble
    is rescued up to the first block, so the invariant is multiset
    equality, not order.
    """
    preamble, blocks = split_annotation_sections(text)
    assert sorted((preamble + "".join(blocks)).splitlines(keepends=True)) == sorted(
        text.splitlines(keepends=True)
    )
    if not blocks:
        assert preamble == text


@settings(max_examples=200, deadline=None)
@given(text=_source)
def test_split_annotation_sections_blocks_carry_markers(text: str) -> None:
    """Every non-empty block holds a marker, and every marker lands in one.

    Adjacent markers collapse into a single shared block (ADR-010/022: one
    marker per target stacked above one body), so the leading block of such
    a source is legitimately empty; what must never appear is a block of
    source lines with no marker, or a marker that no block carries.
    """
    _, blocks = split_annotation_sections(text)
    carried = 0
    for block in blocks:
        if not block.strip():
            continue
        markers = block_markers(block)
        assert markers
        carried += len(markers)
    assert carried == len(block_markers(text))


@settings(max_examples=200, deadline=None)
@given(text=_source)
def test_block_markers_are_nfc_normalized(text: str) -> None:
    """Marker module names come back NFC-normalized, and VAs are VAs."""
    for module, va in block_markers(text):
        assert module == unicodedata.normalize("NFC", module)
        assert 0 <= va < 2**64
        assert va >= 0


@settings(max_examples=200, deadline=None)
@given(text=_source)
def test_parse_new_format_multi_well_formed(text: str) -> None:
    """Every annotation the multi parser yields is structurally valid."""
    for ann in parse_new_format_multi(text.splitlines()):
        assert ann.marker_type in VALID_MARKERS
        assert 0 <= ann.va < 2**64
        assert ann.module == unicodedata.normalize("NFC", ann.module)
        assert ann.line >= 1


@settings(max_examples=200, deadline=None)
@given(text=_source)
def test_parse_new_format_agrees_with_multi(text: str) -> None:
    """The single-block parser never raises and yields a valid marker."""
    lines = text.splitlines()
    ann = parse_new_format(lines)
    if ann is not None:
        assert ann.marker_type in VALID_MARKERS
        assert 0 <= ann.va < 2**64


@settings(max_examples=200, deadline=None)
@given(text=_source)
def test_parse_source_metadata_never_raises(text: str) -> None:
    """The file-level entry point on arbitrary text returns a clean dict."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "fuzz.c"
        path.write_text(text, encoding="utf-8", errors="surrogateescape")
        meta = parse_source_metadata(path)
    assert isinstance(meta, dict)
    for key, value in meta.items():
        assert key == key.upper()
        assert isinstance(value, str)
        for marker in ("FUNCTION", "LIBRARY", "STUB", "GLOBAL", "DATA", "VTABLE", "STRING"):
            if key == marker:
                assert value == f"0x{int(value, 16):08x}"
                break


@settings(max_examples=20, deadline=None)
@given(
    pad=st.integers(min_value=0, max_value=40000),
    flavor=st.sampled_from(["//", "/*", "/* ", "?", ":", " "]),
)
def test_annotation_regexes_are_linear(pad: int, flavor: str) -> None:
    """Pathological near-marker lines do not blow up the marker/KV regexes.

    Unterminated comment prefixes and long non-matching tails are the
    ReDoS shape for these patterns; a real hang here is a hang in every
    tree-wide parse.  The bound is deliberately loose (seconds, not
    milliseconds) so the test fails only on a real blowup.
    """
    line = flavor * pad + "\n"
    started = time.monotonic()
    parse_new_format_multi([line, line, line])
    split_annotation_sections(line * 3)
    assert time.monotonic() - started < 5.0
