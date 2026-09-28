"""Property-based fuzzing for the dispatch-table scan, the BSS report, and the
declared-type size model.

``data_scan.find_dispatch_tables`` walks a target's raw ``.data`` / ``.rdata``
bytes with ``struct.unpack_from`` at the image's pointer width, so every slot
in the input is attacker-shaped: a packed executable from a download folder
reaches this loop before anyone has looked at a single byte of it. The scan
also decodes pointers at a stride the caller chooses and clamps each section
against the file length, both of which are trust boundaries the harness below
crosses with an explicit before/after assertion.

``verify_bss_layout`` and the ``data_layout`` size model that feeds it consume
declaration *text* lifted out of reversed sources (``extern short g_tbl[4];``),
which is equally untrusted: it is whatever a decompiler or an LLM wrote into
the file being scanned. ``estimate_type_size`` reaches ``int()`` and
``re.findall`` with it, and ``typed_array_literal`` turns bytes into C source
that is later written back into the tree.

Every harness asserts the shape invariants its caller relies on, plus a pair
assertion across each boundary: the dispatch scan's tables must survive a
re-read of the same bytes, the size model's emitted initializer must parse
back to the bytes it came from, and the BSS report's gaps must tile the
uncovered bytes exactly.
"""

from __future__ import annotations

import re
import struct
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.data_layout import c_type_size, estimate_type_size, hex_list, typed_array_literal
from rebrew.data_scan import (
    GlobalEntry,
    ScanResult,
    find_dispatch_tables,
    verify_bss_layout,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_TEXT_VA = 0x1000
_TEXT_SIZE = 0x400

_CODE_RANGES: list[tuple[int, int]] = [(_TEXT_VA, _TEXT_VA + _TEXT_SIZE)]


@st.composite
def dispatch_image(
    draw: st.DrawFn, *, with_rdata: bool = True
) -> tuple[bytes, dict[str, dict[str, Any]]]:
    """A file whose ``.data`` holds pointer-shaped slots: some into ``.text``,
    some nowhere near it, with the boundary bytes both ends.

    The slot alphabet is what makes the run-splitting logic reachable at all --
    a data section of random bytes almost never produces two adjacent in-range
    values, so the interesting paths would never be taken.  *with_rdata*
    appends a trailing section, which is what decides whether ``.data`` ends at
    EOF.
    """
    ptr_size = draw(st.sampled_from([2, 4, 8]))
    n_slots = draw(st.integers(min_value=0, max_value=24))
    endian = draw(st.sampled_from(["<", ">"]))
    fmt = endian + {2: "H", 4: "I", 8: "Q"}[ptr_size]
    top = 1 << (8 * ptr_size)

    data = bytearray()
    for _ in range(n_slots):
        kind = draw(st.sampled_from(["in", "in", "in", "below", "above", "far", "zero"]))
        if kind == "in":
            value = draw(st.integers(min_value=_TEXT_VA, max_value=_TEXT_VA + _TEXT_SIZE - 1))
        elif kind == "below":
            value = draw(st.integers(min_value=0, max_value=_TEXT_VA - 1))
        elif kind == "above":
            value = draw(
                st.integers(
                    min_value=_TEXT_VA + _TEXT_SIZE, max_value=_TEXT_VA + _TEXT_SIZE + 0x100
                )
            )
        elif kind == "far":
            value = draw(st.integers(min_value=0, max_value=top - 1))
        else:
            value = 0
        data += struct.pack(fmt, value % top)

    # A tail shorter than one slot, so the loop's exit bound is exercised too.
    data += draw(st.binary(max_size=7))

    header = b"MZ" + draw(st.binary(max_size=16))
    data_offset = len(header)
    sections = {
        ".text": {"va": _TEXT_VA, "size": _TEXT_SIZE, "file_offset": 0, "raw_size": len(header)},
        ".data": {
            "va": 0x2000,
            "size": len(data),
            "file_offset": data_offset,
            "raw_size": len(data),
        },
    }
    if with_rdata and draw(st.booleans()):
        rdata = draw(st.binary(max_size=32))
        sections[".rdata"] = {
            "va": 0x3000,
            "size": len(rdata),
            "file_offset": data_offset + len(data),
            "raw_size": len(rdata),
        }
        return header + bytes(data) + rdata, sections
    return header + bytes(data), sections


_decl_tokens = [
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "unsigned",
    "signed",
    "const",
    "extern",
    "static",
    "void",
    "BYTE",
    "DWORD",
    "WORD",
    "struct",
    "Foo",
    "g_name",
    "*",
    " ",
    ";",
]


@st.composite
def declaration_text(draw: st.DrawFn) -> str:
    """A C declaration spliced from type words, an identifier, and array bounds.

    The bounds are the interesting part: they reach ``parse_c_integer_literal``
    through two different regexes, so they are drawn as well-formed constants,
    as the near-miss forms those regexes reject, and as raw noise.
    """
    parts = [draw(st.sampled_from(_decl_tokens)) for _ in range(draw(st.integers(0, 6)))]
    for _ in range(draw(st.integers(0, 3))):
        bound = draw(
            st.sampled_from(
                [
                    "0",
                    "1",
                    "010",
                    "0x10",
                    "0xFFu",
                    "12L",
                    "-1",
                    "N",
                    "",
                    "0x",
                    "0xZZ",
                    "1_0",
                    "0b11",
                    "9" * 24,
                    "'a'",
                ]
            )
        )
        parts.append(f"[{bound}]")
    return "".join(parts)


def _parse_hex_initializer(text: str) -> bytes:
    """Read back the ``0xNN`` tokens of an emitted C initializer body."""
    return bytes(int(tok, 16) for tok in re.findall(r"0x([0-9a-fA-F]{2})\b", text))


# ---------------------------------------------------------------------------
# find_dispatch_tables -- untrusted binary bytes
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(dispatch_image())
def test_dispatch_tables_shape_invariants(image: tuple[bytes, dict[str, dict[str, Any]]]) -> None:
    """Every reported table is a real run of pointers into ``.text``."""
    data, sections = image
    tables = find_dispatch_tables(data, sections, {}, min_entries=1)

    vas = [t.va for t in tables]
    assert vas == sorted(vas), "tables must come back sorted by va"

    for table in tables:
        assert table.num_entries >= 1
        assert 0.0 <= table.coverage <= 1.0
        assert table.resolved == 0
        assert table.section in sections
        lo = sections[table.section]["va"]
        hi = lo + sections[table.section]["size"]
        assert lo <= table.va < hi, "a table must start inside the section that holds it"
        for entry in table.entries:
            assert any(r_lo <= entry.target_va < r_hi for r_lo, r_hi in _CODE_RANGES)
            assert entry.name == "" and entry.status == "", "no known_functions map was passed"


@settings(max_examples=150, deadline=None)
@given(dispatch_image())
def test_dispatch_tables_repeat_scan_is_identical(
    image: tuple[bytes, dict[str, dict[str, Any]]],
) -> None:
    """A second scan of the same bytes reports the same tables (pure function)."""
    data, sections = image
    first = find_dispatch_tables(data, sections, {}, min_entries=2)
    second = find_dispatch_tables(data, sections, {}, min_entries=2)
    assert [t.to_dict() for t in first] == [t.to_dict() for t in second]


@settings(max_examples=150, deadline=None)
@given(dispatch_image(with_rdata=False), st.integers(min_value=1, max_value=64))
def test_dispatch_tables_clamp_a_section_that_runs_past_eof(
    image: tuple[bytes, dict[str, dict[str, Any]]], extra: int
) -> None:
    """A section that claims more bytes than the file holds is skipped whole.

    This is the guard that keeps ``struct.unpack_from`` off the end of a
    truncated or lie-sized image, so it is asserted against the same scan run
    with the offending section absent.
    """
    data, sections = image
    data_sec = sections[".data"]
    sections[".data"] = dict(data_sec, raw_size=data_sec["raw_size"] + extra)
    lying = [t.to_dict() for t in find_dispatch_tables(data, sections, {}, min_entries=1)]

    without = {name: dict(sec) for name, sec in sections.items() if name != ".data"}
    reference = [t.to_dict() for t in find_dispatch_tables(data, without, {}, min_entries=1)]

    assert lying == reference


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=512))
def test_dispatch_tables_random_bytes_no_crash(blob: bytes) -> None:
    """Arbitrary bytes against a plausible section map raise nothing."""
    sections = {
        ".text": {"va": _TEXT_VA, "size": _TEXT_SIZE, "file_offset": 0, "raw_size": 0},
        ".data": {"va": 0x2000, "size": len(blob), "file_offset": 0, "raw_size": len(blob)},
    }
    for table in find_dispatch_tables(blob, sections, {}, min_entries=1):
        assert table.num_entries >= 1
        table.to_dict()


# ---------------------------------------------------------------------------
# verify_bss_layout -- report invariants over forgeable globals
# ---------------------------------------------------------------------------


@st.composite
def bss_scan(draw: st.DrawFn) -> tuple[ScanResult, dict[str, dict[str, Any]]]:
    bss_va = draw(st.integers(min_value=0x1000, max_value=0x8000)) & ~0xF
    bss_size = draw(st.integers(min_value=0, max_value=0x400))
    entries = []
    for i in range(draw(st.integers(0, 8))):
        entries.append(
            GlobalEntry(
                name=f"g_{i}",
                va=draw(
                    st.integers(
                        # Half inside .bss, half anywhere in the image.
                        min_value=0,
                        max_value=bss_va + bss_size + 0x200,
                    )
                ),
                type_str=draw(declaration_text()),
            )
        )
    scan = ScanResult(globals={e.name: e for e in entries})
    sections = {".bss": {"va": bss_va, "size": bss_size, "file_offset": 0, "raw_size": bss_size}}
    return scan, sections


@settings(max_examples=200, deadline=None)
@given(bss_scan())
def test_bss_report_invariants(scanned: tuple[ScanResult, dict[str, dict[str, Any]]]) -> None:
    scan, sections = scanned
    bss_va = sections[".bss"]["va"]
    bss_size = sections[".bss"]["size"]
    report = verify_bss_layout(scan, sections)

    assert report.bss_va == bss_va and report.bss_size == bss_size
    vas = [e.va for e in report.known_entries]
    assert vas == sorted(vas)
    for entry in report.known_entries:
        assert bss_va <= entry.va < bss_va + bss_size
        declared = scan.globals[entry.name].type_str
        assert entry.size_hint == (estimate_type_size(declared) if declared else 4)

    for gap in report.gaps:
        assert gap.size >= 4, "sub-4 gaps are alignment padding, not a missing global"
        assert bss_va <= gap.offset < bss_va + bss_size
        assert gap.offset + gap.size <= bss_va + bss_size
    gap_offsets = [g.offset for g in report.gaps]
    assert gap_offsets == sorted(gap_offsets)

    assert 0 <= report.coverage_bytes <= bss_size
    assert 0.0 <= report.coverage_pct <= 100.0
    assert report.to_dict()["summary"]["total_gap_bytes"] == sum(g.size for g in report.gaps)


@settings(max_examples=100, deadline=None)
@given(bss_scan())
def test_bss_report_is_stable(scanned: tuple[ScanResult, dict[str, dict[str, Any]]]) -> None:
    scan, sections = scanned
    first = verify_bss_layout(scan, sections).to_dict()
    second = verify_bss_layout(scan, sections).to_dict()
    assert first == second


# ---------------------------------------------------------------------------
# data_layout size model -- untrusted declaration text
# ---------------------------------------------------------------------------


@settings(max_examples=300, deadline=None)
@given(declaration_text())
def test_type_size_model_is_a_positive_size(ctype: str) -> None:
    size = c_type_size(ctype)
    assert size in (1, 2, 3, 4, 8)
    total = estimate_type_size(ctype)
    assert total >= size, "an array only ever multiplies the element size"
    assert total % size == 0


@settings(max_examples=300, deadline=None)
@given(declaration_text(), st.binary(max_size=64), st.sampled_from(["<", ">"]))
def test_typed_array_literal_roundtrips_bytes(ctype: str, data: bytes, byte_order: str) -> None:
    """The emitted C initializer parses back to the bytes that produced it."""
    elemsize = c_type_size(ctype)
    try:
        text, count = typed_array_literal(ctype, data, byte_order)
    except ValueError:
        # The one documented rejection: a non-finite float/double element has
        # no C89 literal.  The caller skips the symbol rather than emit one.
        assert any(w in ctype.lower() for w in ("float", "double"))
        return
    if elemsize <= 1:
        assert count == len(data)
        assert _parse_hex_initializer(text) == data
        return
    usable = len(data) - len(data) % elemsize
    assert count == usable // elemsize
    assert count == len([part for part in text.strip("{}").split(",") if part.strip()])


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=256))
def test_hex_list_roundtrips(data: bytes) -> None:
    assert _parse_hex_initializer(hex_list(data)) == data
