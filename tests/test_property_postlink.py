"""Property-based fuzzing for the post-link layout-coverage mapper.

``postlink.map_coverage`` reads a 4-byte value at a ``.text``-relative offset
taken from a layout package — offsets and values that come out of a target
binary and a ``rebrew-layout.toml``, both untrusted.  A forged offset either
lands outside the built image or inside a different instruction, and a forged
section table moves the ``.rdata``/``.data`` spans the reference test compares
against.  ``check_text_alignment`` then turns the ratio into a build break.

The harnesses below pair a built image with a layout package whose every field
is drawable, and assert:

* a forged offset or a truncated image never escapes as ``struct.error`` or
  ``IndexError`` — an unreadable dword is skipped, not fatal;
* the counters are well formed: each is within ``[0, total]``, and the totals
  are exactly the number of layout-map entries handed in;
* every count that lands is explained — an entry past the end of the built
  image cannot be counted, and a call context only validates when the recorded
  two-byte prefix and suffix really sit either side of the dword (a pair
  assertion across the map's read side);
* ``check_text_alignment`` accepts exactly when the coverage it computes is at
  or above the published floor.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from test_postlink import make_full_pe

from rebrew.binary_model import BinaryInfo, SectionInfo
from rebrew.layout_meta import LayoutMetadata, SectionMeta
from rebrew.postlink import FIXER_ORDER as FIXER_NAMES

_u16 = st.integers(min_value=0, max_value=0xFFFF)
_u32 = st.integers(min_value=0, max_value=0xFFFFFFFF)


def _meta_and_info(
    text_off: int,
    text_vs: int,
    operands: dict[int, int],
    calls: dict[int, tuple[int, int, int]],
) -> tuple[LayoutMetadata, BinaryInfo]:
    """A layout package holding only the named layout-map entries, paired with
    a ``BinaryInfo`` whose ``.text`` starts at *text_off* in a built image."""
    sections = [
        SectionMeta(name=".text", va=0, vs=text_vs, raw=text_vs, raw_ptr=text_off, chars=0),
        SectionMeta(name=".rdata", va=0x2000, vs=0, raw=0, raw_ptr=0, chars=0),
        SectionMeta(name=".data", va=0x3000, vs=0, raw=0, raw_ptr=0, chars=0),
    ]
    meta = LayoutMetadata(
        target="fuzz",
        image_base=0,
        link_options=[],
        sections=sections,
        exports=[],
        imports=[],
        header=b"",
        iat=b"",
        prefix=b"",
        bookkeeping=b"",
        data=b"",
        reloc=b"",
        operands=operands,
        calls=calls,
        exp_rva=0,
        export_stamp=(0, 0),
    )
    info = BinaryInfo(path=Path("built"), format="pe")
    info.sections = {
        ".text": SectionInfo(
            name=".text", va=0, size=text_vs, file_offset=text_off, raw_size=text_vs
        )
    }
    return meta, info


@st.composite
def _layout_and_built(draw: st.DrawFn) -> tuple[bytes, LayoutMetadata, BinaryInfo]:
    """A built image, a layout package describing it, and the ``BinaryInfo``
    the mapper reads sections from.

    ``text_off`` puts the built ``.text`` at an arbitrary file offset (often
    past EOF, which the mapper must tolerate), and the operand/call offsets are
    drawn from a range that spans both in-bounds and out-of-bounds positions.
    """
    built = draw(st.binary(min_size=0, max_size=512))
    text_off = draw(st.integers(min_value=0, max_value=len(built) + 8))
    text_vs = draw(st.integers(min_value=0, max_value=max(1, len(built))))
    rdata_va = draw(_u32)
    rdata_vs = draw(st.integers(min_value=0, max_value=0x10000))
    data_va = draw(_u32)
    data_vs = draw(st.integers(min_value=0, max_value=0x10000))
    image_base = draw(st.sampled_from([0, 0x400000, draw(_u32)]))

    sections = [
        SectionMeta(name=".text", va=0, vs=text_vs, raw=text_vs, raw_ptr=text_off, chars=0),
        SectionMeta(name=".rdata", va=rdata_va, vs=rdata_vs, raw=rdata_vs, raw_ptr=0, chars=0),
        SectionMeta(name=".data", va=data_va, vs=data_vs, raw=data_vs, raw_ptr=0, chars=0),
    ]

    n_operands = draw(st.integers(min_value=0, max_value=6))
    n_calls = draw(st.integers(min_value=0, max_value=4))
    operands = {
        draw(st.integers(min_value=0, max_value=max(0, len(built)) + 8)): draw(_u32)
        for _ in range(n_operands)
    }
    calls = {
        draw(st.integers(min_value=0, max_value=max(0, len(built)) + 8)): (
            draw(_u32),
            draw(_u16),
            draw(_u16),
        )
        for _ in range(n_calls)
    }

    meta = LayoutMetadata(
        target="fuzz",
        image_base=image_base,
        link_options=[],
        sections=sections,
        exports=[],
        imports=[],
        header=b"",
        iat=b"",
        prefix=b"",
        bookkeeping=b"",
        data=b"",
        reloc=b"",
        operands=operands,
        calls=calls,
        exp_rva=0,
        export_stamp=(0, 0),
    )
    info = BinaryInfo(path=Path("built"), format="pe", image_base=image_base)
    info.sections = {
        ".text": SectionInfo(
            name=".text",
            va=0,
            size=text_vs,
            file_offset=text_off,
            raw_size=max(0, len(built) - text_off),
        )
    }
    return built, meta, info


@settings(max_examples=300, deadline=None)
@given(_layout_and_built())
def test_map_coverage_counts_are_well_formed(
    data: tuple[bytes, LayoutMetadata, BinaryInfo],
) -> None:
    """Fuzz: a forged layout package against an arbitrary built image.  The
    mapper never raises on a dword it cannot read, and every counter it
    returns is bounded by the number of entries it was asked about."""
    from rebrew.postlink import map_coverage

    built, meta, info = data
    op_ok, op_total, call_ok, call_total = map_coverage(built, meta, info)
    assert op_total == len(meta.operands)
    assert call_total == len(meta.calls)
    assert 0 <= op_ok <= op_total
    assert 0 <= call_ok <= call_total


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=0x400), st.integers(min_value=0, max_value=64))
def test_map_coverage_skips_unreadable_dwords(built_size: int, slack: int) -> None:
    """Every layout-map entry whose dword starts at or past the end of the
    built image is skipped, so a package full of out-of-range offsets scores
    zero rather than raising or counting a read it never made."""
    from rebrew.postlink import map_coverage

    built = bytes(built_size)
    off = built_size + slack
    meta, info = _meta_and_info(off, len(built), {0: 0xDEADBEEF}, {0: (0xDEADBEEF, 0, 0)})
    assert map_coverage(built, meta, info) == (0, 1, 0, 1)


@settings(max_examples=200, deadline=None)
@given(st.binary(min_size=8, max_size=256), _u16, _u16)
def test_map_coverage_validates_a_call_context(built: bytes, pre: int, suf: int) -> None:
    """Pair assertion across the map's read side: a call entry whose dword does
    not hold the reference value still validates when the two-byte context the
    package recorded really sits either side of it, and does not when the
    preceding byte is not a call opcode."""
    from rebrew.postlink import map_coverage

    off = 3
    val = 0xDEADBEEF
    body = bytearray(built)
    body[off : off + 4] = struct.pack("<I", val ^ 0xFFFFFFFF)
    body[off - 3 : off - 1] = pre.to_bytes(2, "big")
    body[off + 4 : off + 6] = suf.to_bytes(2, "big")

    for opcode, expected in ((0xE8, 1), (0x90, 0)):
        body[off - 1] = opcode
        meta, info = _meta_and_info(0, len(bytes(body)), {}, {off: (val, pre, suf)})
        assert map_coverage(bytes(body), meta, info) == (0, 0, expected, 1)


@settings(max_examples=200, deadline=None)
@given(_layout_and_built())
def test_check_text_alignment_agrees_with_coverage(
    data: tuple[bytes, LayoutMetadata, BinaryInfo],
) -> None:
    """``check_text_alignment`` breaks the build on exactly the ratios below the
    published floor, and stays silent on a package with no layout-map entries
    at all."""
    from rebrew.postlink import MIN_LAYOUT_MAP_COVERAGE, check_text_alignment, map_coverage

    built, meta, info = data
    op_ok, op_total, call_ok, call_total = map_coverage(built, meta, info)
    total = op_total + call_total
    aligned = total == 0 or (op_ok + call_ok) / total >= MIN_LAYOUT_MAP_COVERAGE
    if aligned:
        check_text_alignment(built, meta, info)
    else:
        with pytest.raises(ValueError, match="position-aligned"):
            check_text_alignment(built, meta, info)


# ---------------------------------------------------------------------------
# The whole fixer chain over a mutated PE pair
# ---------------------------------------------------------------------------


def _seed_pe() -> bytes:
    """A four-section PE with imports, exports and a relocation block."""
    return make_full_pe(
        imports=[("KERNEL32.dll", ["GetLocalTime", "WriteFile"]), ("USER32.dll", ["MessageBoxA"])],
        timestamp=0x60000000,
        checksum=0x4D328,
    )


#: Patch window: the DOS stub, COFF/optional headers, the section table and the
#: two data directories — the fields every fixer's precondition reads.  Past it
#: lies section content whose corruption only produces ordinary mismatches.
_MUTATE_SPAN = 0x800


@st.composite
def _mutated_pe(draw: st.DrawFn) -> bytes:
    """The seed PE with drawn byte patches and an optional truncation."""
    data = bytearray(_seed_pe())
    span = min(_MUTATE_SPAN, len(data))
    for offset, chunk in draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=span - 1), st.binary(min_size=1, max_size=4)
            ),
            max_size=10,
        )
    ):
        data[offset : offset + len(chunk)] = chunk
    if draw(st.booleans()):
        data = data[: draw(st.integers(min_value=0, max_value=len(data)))]
    return bytes(data)


@settings(max_examples=40, deadline=None)
@given(
    _mutated_pe(),
    _mutated_pe(),
    st.lists(st.sampled_from(FIXER_NAMES), unique=True),
)
def test_run_fixers_reports_only_valueerror(
    built: bytes, reference: bytes, fixer_names: list[str]
) -> None:
    """``ValueError`` is the fixers' whole failure vocabulary.

    ``rebrew build postlink`` catches ``ValueError`` and turns it into an
    ``error_exit``; any other exception reaching the CLI is a traceback.  Both
    inputs are forgeable — the built link and the reference binary the user
    points the command at — and a mutated section table deletes a section name
    outright, so every lookup in the chain must degrade to ``ValueError`` rather
    than a bare ``KeyError`` / ``struct.error`` / ``IndexError``.
    """
    from rebrew.postlink import run_fixers

    with tempfile.TemporaryDirectory() as td:
        built_path = Path(td) / "built.dll"
        ref_path = Path(td) / "ref.dll"
        built_path.write_bytes(built)
        ref_path.write_bytes(reference)
        try:
            patched, reports = run_fixers(built_path, ref_path, fixer_names or None)
        except ValueError:
            return
        # On success the patched image is a byte string and every requested
        # fixer reports exactly once, in FIXER_ORDER order.  An empty
        # selection means "all fixers", which is what run_fixers(None) runs.
        requested = set(fixer_names) if fixer_names else set(FIXER_NAMES)
        assert isinstance(patched, bytes)
        assert reports
        assert [r.name for r in reports] == [n for n in FIXER_NAMES if n in requested]


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=256))
def test_map_coverage_refuses_a_textless_image(blob: bytes) -> None:
    """A built image with no ``.text`` section is a ``ValueError``, not a
    ``KeyError``: the section name comes from the file, so a corrupted table
    removes it, and every caller of the mapper catches ``ValueError``."""
    from rebrew.postlink import map_coverage

    meta, info = _meta_and_info(0, len(blob), {}, {})
    info.sections = {}  # the built image declares no section at all
    with pytest.raises(ValueError, match=r"no \.text section"):
        map_coverage(blob, meta, info)
