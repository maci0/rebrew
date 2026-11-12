"""Tests for rebrew.formats.ne_loader — 16-bit Windows NE parsing.

Builds synthetic NE executables (MZ stub + NE header + segment table) so
the parser is exercised without depending on any real 16-bit binary.
"""

from __future__ import annotations

import struct
import tempfile
from contextlib import suppress
from pathlib import Path

import pytest
from bin_util import make_ne
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.formats.ne_loader import (
    NeFunction,
    NeParseError,
    parse_exports,
    parse_imports,
    parse_ne_header,
    parse_segments,
    probe_is_code,
)

_CODE = bytes.fromhex(
    "55 8b ec 83 ec 02 8b 46 04 30 e4 8b 5e 06 03 d8 89 5e fc 5d c3"  # push bp; mov bp,sp; ... ; pop bp; ret (9 insns)
)
_DATA = b"\x0dHoliday Island\x00\x00\x00\x00"  # Pascal string + padding


class TestParseNeHeader:
    def test_header_fields(self) -> None:
        raw = make_ne(segments=[(_CODE, 0x01)], exports=[("HOLIDAY", 0)])
        hdr = parse_ne_header(raw, 0x100)
        assert hdr.segment_count == 1
        assert hdr.sector_size == 16
        assert hdr.module_reference_count == 0  # no modules in this build

    def test_not_ne_raises(self) -> None:
        from rebrew.formats.ne_loader import NeParseError

        with pytest.raises(NeParseError, match="not an NE executable"):
            parse_ne_header(b"\x00" * 0x40 + b"XX" + b"\x00" * 0x3E, 0x40)

    def test_truncated_header_raises(self) -> None:
        from rebrew.formats.ne_loader import NeParseError

        with pytest.raises(NeParseError, match="NE header truncated"):
            parse_ne_header(b"\x00" * 0x40 + b"NE\x00\x00", 0x40)


class TestParseSegments:
    def test_iterated_flag_bit(self) -> None:
        """NE_SEGFLAGS_ITERATED is 0x0008 (0x0002 is ALLOCATED): the old 0x02
        constant marked allocated segments iterated and missed real ones."""
        raw = make_ne(segments=[(_CODE, 0x0002), (_DATA, 0x0008)])
        hdr = parse_ne_header(raw, 0x100)
        segs = parse_segments(raw, 0x100, hdr)
        assert segs[0].is_iterated is False
        assert segs[1].is_iterated is True

    def test_sector_offsets(self) -> None:
        raw = make_ne(segments=[(_CODE, 0x01), (_DATA, 0x00)])
        hdr = parse_ne_header(raw, 0x100)
        segs = parse_segments(raw, 0x100, hdr)
        assert len(segs) == 2
        # Segment 1's file offset = after headers/tables; both sectors align.
        assert segs[0].file_offset % 16 == 0
        assert segs[1].file_offset % 16 == 0
        assert segs[1].file_offset >= segs[0].file_offset + len(_CODE)


class TestParseExports:
    def test_resident_names(self) -> None:
        raw = make_ne(segments=[(_CODE, 0x01)], exports=[("HOLIDAY", 0), ("InitApp", 7)])
        hdr = parse_ne_header(raw, 0x100)
        exps = parse_exports(raw, 0x100, hdr)
        assert [(e.name, e.ordinal) for e in exps] == [("HOLIDAY", 0), ("InitApp", 7)]


class TestParseImports:
    @pytest.mark.parametrize("remaining", [0, 1, 5])
    def test_truncated_module_name_is_not_reported(self, remaining: int) -> None:
        raw = make_ne(modules=["KERNEL"])
        header = parse_ne_header(raw, 0x100)
        name_start = 0x100 + header.imported_names_offset
        truncated = raw[: name_start + 1 + remaining]
        assert parse_imports(truncated, 0x100, header) == []

    def test_module_names(self) -> None:
        raw = make_ne(segments=[(_CODE, 0x01)], modules=["KERNEL", "USER"])
        hdr = parse_ne_header(raw, 0x100)
        mods = parse_imports(raw, 0x100, hdr)
        assert [m.module for m in mods] == ["KERNEL", "USER"]

    def test_forged_module_count_raises(self) -> None:
        """A module_reference_count past the remaining file bytes must raise
        NeParseError — same contract as the segment_count cap."""
        raw = bytearray(make_ne(segments=[(_CODE, 0x01)], modules=["KERNEL"]))
        # Forge module_reference_count to 0xFFFF at NE+0x1E.
        struct.pack_into("<H", raw, 0x100 + 0x1E, 0xFFFF)
        hdr = parse_ne_header(bytes(raw), 0x100)
        with pytest.raises(NeParseError, match="module reference table"):
            parse_imports(bytes(raw), 0x100, hdr)

    def test_garbage_import_table_degrades_to_modules(self) -> None:
        """Regression: a misplaced/absent import table (MSVC-built NEs like
        the 1991 SkiFree put the non-resident name table where the classic
        import table should be) must not fabricate ordinal garbage — the
        parser degrades to module names only."""
        raw = make_ne(segments=[(_CODE, 0x01)], modules=["KERNEL"])
        hdr = parse_ne_header(raw, 0x100)
        # Give the entry table a nonzero length so the "import table" position
        # lands past the module ref + imported names tables, then overwrite it
        # with a Pascal string ("Ski Free") whose first two bytes 0x08 0x53
        # read as an absurd import count (0x5308).
        blob = bytearray(raw)
        blob[0x106:0x108] = (0x10).to_bytes(2, "little")  # entry table length
        pos = 0x100 + hdr.entry_table_offset + 0x10
        blob[pos : pos + 8] = b"\x08Ski Free"
        mods = parse_imports(bytes(blob), 0x100, hdr)
        assert [m.module for m in mods] == ["KERNEL"]
        assert all(m.imports == [] for m in mods)


class TestLoadNeBinary:
    def test_full_segment_size_sentinel(self, tmp_path: Path) -> None:
        from rebrew.formats.binary_loader import extract_bytes_at_va, load_binary

        content = _CODE + b"\x90" * (0x10000 - len(_CODE) - 1) + b"\xc3"
        path = tmp_path / "full.ne"
        path.write_bytes(make_ne(segments=[(content, 0)]))
        info = load_binary(path)
        assert info.sections["SEG1"].raw_size == 0x10000
        assert info.sections["SEG1"].size == 0x10000
        assert info.text_size == 0x10000
        # zero-based space: segment 1 ends at 0xFFFF, not 0x1FFFF
        assert extract_bytes_at_va(info, info.sections["SEG1"].va + 0xFFFF, 1) == b"\xc3"

    @pytest.mark.parametrize("allocation, expected_size", [(0, 0x10000), (32, 32)])
    def test_zero_filled_segment_size(
        self, tmp_path: Path, allocation: int, expected_size: int
    ) -> None:
        from rebrew.formats.binary_loader import extract_bytes_at_va, load_binary

        raw = bytearray(make_ne(segments=[(_DATA, 1)]))
        struct.pack_into("<HHHH", raw, 0x140, 0, 0, 1, allocation)
        path = tmp_path / "bss.ne"
        path.write_bytes(raw)
        info = load_binary(path)
        assert info.sections["SEG1"].raw_size == 0
        assert info.sections["SEG1"].size == expected_size
        assert info.text_size == 0
        # reads the segment start, which is VA 0 in the zero-based space
        assert extract_bytes_at_va(info, info.sections["SEG1"].va, 1) == b""

    def test_code_after_a_data_prelude_reads_as_code(self, tmp_path: Path) -> None:
        """A segment whose first function starts past the near window is code.

        Borland layout: ``[index\x00]`` marker, then content. The old probe
        looked for an anchor only in the first 128 bytes after the marker and
        only decoded a window of 512, so 700 bytes of data before the first
        `enter` made the whole segment read as data, however many functions
        it held (the real cases: code at offset 0x0997, and a segment whose
        functions start past 0x1700).
        """
        from rebrew.formats.binary_loader import load_binary

        marker = b"\x01\x00"  # Borland segment index marker for SEG1
        prelude = b"\x00" * 700
        function = bytes.fromhex("c8 00 00 00 90 90 90 90 90 90 90 90 c3")
        raw = make_ne(segments=[(marker + prelude + function, 0x01)])
        p = tmp_path / "late.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        assert info.sections["SEG1"].is_code_section

    def test_binary_info_shape(self, tmp_path: Path) -> None:
        from rebrew.formats.binary_loader import load_binary
        from rebrew.formats.binary_model import BinaryInfo

        raw = make_ne(segments=[(_CODE, 0x01), (_DATA, 0x00)], modules=["KERNEL"])
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        assert isinstance(info, BinaryInfo)
        assert info.format == "ne"
        assert set(info.sections) == {"SEG1", "SEG2"}
        # zero-based VA space is canonical: 33 inventory rows sit below
        # 0x10000, which a one-based base cannot address at all
        assert info.sections["SEG1"].va == 0x00000  # segment 1 → 0x00000
        assert info.sections["SEG2"].va == 0x10000
        assert info.ne_segments[0].base_va == 0x00000
        # text_size aggregates code segments (catalog coverage needs it)
        assert info.text_size > 0
        assert info.text_va == info.sections["SEG1"].va

    def test_section_code_flag_follows_the_probe(self, tmp_path: Path) -> None:
        """The probe's verdict has to reach `SectionInfo`, not stop at `text_size`.

        `SectionInfo.is_code_section` resolves a None flag by section name, and
        `SEG<n>` matches no code name, so without the stated flag every NE
        section reads as data and `catalog.inventory.complete_span` refuses
        every repair-extents request with "not a complete file-backed
        executable span".
        """
        from rebrew.formats.binary_loader import load_binary

        path = tmp_path / "code_and_data.ne"
        path.write_bytes(make_ne(segments=[(_CODE, 0x01), (_DATA, 0x00)]))
        info = load_binary(path)
        assert info.sections["SEG1"].is_code_section is True
        assert info.sections["SEG2"].is_code_section is False


class TestProbeIsCode:
    @pytest.mark.parametrize("ret_inside_budget", [False, True])
    def test_deep_probe_stops_decoding_at_instruction_budget(
        self, monkeypatch: pytest.MonkeyPatch, ret_inside_budget: bool
    ) -> None:
        import capstone

        from rebrew.formats.ne_loader import PROBE_DECODE_INSTRUCTIONS

        body = _CODE if ret_inside_budget else b"\x55\x8b\xec" + b"\x90" * 30 + b"\xc3"
        segment = b"\x00" * 512 + body + b"\x90" * 100
        decoded = 0
        real_disasm = capstone.Cs.disasm

        def counting(self: capstone.Cs, code: bytes, offset: int, count: int = 0) -> object:
            nonlocal decoded
            for instruction in real_disasm(self, code, offset, count):
                decoded += 1
                yield instruction

        monkeypatch.setattr(capstone.Cs, "disasm", counting)
        assert probe_is_code(segment, 0, len(segment)) is ret_inside_budget
        assert 8 <= decoded <= PROBE_DECODE_INSTRUCTIONS

    def test_code_segment(self) -> None:
        # Real NE segments carry a 2-byte index marker before their content.
        assert probe_is_code(b"\x01\x00" + _CODE, 0, len(_CODE) + 2) is True

    def test_data_segment(self) -> None:
        assert probe_is_code(b"\x02\x00" + _DATA, 0, len(_DATA) + 2) is False

    def test_markerless_code_segment(self) -> None:
        # MSVC 16-bit NE segments have no [index\x00] marker — code starts
        # directly at offset 0 (e.g. ``push ds/pop ax/nop/inc bp``).
        entry = bytes.fromhex("1e 58 90 45 55 8b ec") + _CODE
        assert probe_is_code(entry, 0, len(entry)) is True

    def test_marker_only_skipped_with_index(self) -> None:
        # With the segment index supplied, the [index\x00] marker is skipped
        # so a data segment that merely resembles the marker is not code.
        assert probe_is_code(b"\x01\x00" + _DATA, 0, len(_DATA) + 2, index=1) is False


class TestEnumerateFunctions:
    def test_finds_function(self, tmp_path: Path) -> None:
        from rebrew.formats.binary_loader import load_binary
        from rebrew.formats.ne_loader import enumerate_ne_functions

        code = (
            b"\x01\x00"  # Borland segment index marker
            + bytes.fromhex(
                "55 8b ec 83 ec 04 8b 46 06 5d c3"  # fn1: push bp; ...; pop bp; ret
                "90 90 90 90"  # padding
                "c8 10 00 00 33 c0 89 46 fc 5d c3"  # fn2: enter 0x10,0; ...; ret
            )
        )
        raw = make_ne(segments=[(code, 0x01)])
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        funcs = enumerate_ne_functions(info)
        assert len(funcs) >= 2
        # Both functions must terminate with a ret epilog.
        import capstone

        from rebrew.formats.binary_loader import extract_bytes_at_va

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        for f in funcs[:2]:
            body = extract_bytes_at_va(info, f.va, f.size, trim_padding=False) or b""
            insns = list(md.disasm(body, f.va))
            assert insns and insns[-1].mnemonic in ("ret", "retf", "retn")

    def test_markerless_segment_entry_recovered(self, tmp_path: Path) -> None:
        # An MSVC-style segment (no Borland marker) starts directly with the
        # entry function, even when it opens with push ds/pop ax/nop/inc bp
        # rather than a push bp prolog.  The entry function must be found.
        from rebrew.formats.binary_loader import load_binary
        from rebrew.formats.ne_loader import enumerate_ne_functions

        entry = bytes.fromhex("1e 58 90 45 55 8b ec 83 ec 02 5d c3")  # entry + ret
        code = entry + bytes.fromhex("90 90 90 90") + _CODE
        raw = make_ne(segments=[(code, 0x01)])
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        funcs = enumerate_ne_functions(info)
        # re-anchored on base_va: the VA number itself is not the claim
        assert any(f.va == info.ne_segments[0].base_va for f in funcs), [hex(f.va) for f in funcs]

    def test_segment_past_eof_clamps_raw_size(self, tmp_path: Path) -> None:
        """Regression: a corrupt segment-table entry pointing past EOF made
        ``min(length, len(data) - file_offset)`` negative, poisoning raw-size
        math downstream.  The loader must clamp to 0 instead."""
        from rebrew.formats.binary_loader import load_binary

        raw = bytearray(make_ne(segments=[(_CODE, 0x01), (_DATA, 0x00)]))
        # Point segment 1 at sector 0xFFFF (file offset 0xFFFF0 — past EOF).
        struct.pack_into("<H", raw, 0x100 + 0x40, 0xFFFF)
        p = tmp_path / "corrupt.ne"
        p.write_bytes(bytes(raw))
        info = load_binary(p)
        assert info.sections["SEG1"].raw_size == 0
        assert info.sections["SEG2"].raw_size == len(_DATA)


class TestSegmentSectorZero:
    def test_sector_offset_zero_is_not_file_content(self, tmp_path: Path) -> None:
        """NE sector offset 0 means "not present in the file" (the segment is
        allocated zero-filled); reading offset 0 reported the MZ/NE header as
        the segment's content."""
        from rebrew.analysis import extract_bytes
        from rebrew.formats.binary_loader import load_binary

        raw = bytearray(make_ne(segments=[(_CODE, 0x01)]))
        struct.pack_into("<H", raw, 0x100 + 0x40, 0)  # segment 1: sector offset 0
        p = tmp_path / "nores.ne"
        p.write_bytes(bytes(raw))
        info = load_binary(p)
        seg_info = info.sections["SEG1"]
        assert seg_info.raw_size == 0
        assert extract_bytes(info, seg_info.va, 0x10) == b""


# ---------------------------------------------------------------------------
# Hypothesis fuzz — NE table parsers on untrusted MZ/NE bytes
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(st.binary(min_size=0, max_size=512), st.integers(min_value=0, max_value=400))
def test_parse_ne_tables_random_bytes_no_crash(blob: bytes, ne_off: int) -> None:
    """Random bytes with an ``NE`` magic poke must load or raise
    ``NeParseError``/``ValueError`` — never IndexError/struct.error."""
    from rebrew.formats.ne_loader import load_ne_binary

    data = bytearray(blob)
    if len(data) < 0x40:
        data.extend(b"\x00" * (0x40 - len(data)))
    off = ne_off % max(len(data) - 1, 1)
    if off + 0x40 > len(data):
        data.extend(b"\x00" * (off + 0x40 - len(data)))
    data[0:2] = b"MZ"
    data[0x3C:0x40] = off.to_bytes(4, "little")
    data[off : off + 2] = b"NE"

    with tempfile.NamedTemporaryFile(suffix=".ne", delete=False) as fh:
        fh.write(bytes(data))
        tmp = Path(fh.name)
    try:
        with suppress(NeParseError, ValueError):
            info = load_ne_binary(tmp)
            assert info.format == "ne"
            assert isinstance(info.sections, dict)
            for sec in info.sections.values():
                assert sec.raw_size >= 0
    finally:
        tmp.unlink(missing_ok=True)


@settings(max_examples=100, deadline=None)
@given(st.binary(min_size=1, max_size=48))
def test_ne_fixture_mutation_no_crash(noise: bytes) -> None:
    """Mutations of a well-formed synthetic NE must load or raise cleanly."""
    from rebrew.formats.binary_loader import load_binary

    base = bytearray(make_ne(segments=[(_CODE, 0x01), (_DATA, 0x00)]))
    for i, b in enumerate(noise):
        base[(b + i * 13) % len(base)] ^= b or 1

    with tempfile.NamedTemporaryFile(suffix=".ne", delete=False) as fh:
        fh.write(bytes(base))
        tmp = Path(fh.name)
    try:
        with suppress(NeParseError, ValueError):
            info = load_binary(tmp)
            assert info.format in ("ne", "mz")
            for sec in info.sections.values():
                assert sec.raw_size >= 0
    finally:
        tmp.unlink(missing_ok=True)


_PROLOG_HEAVY = st.lists(
    st.sampled_from([b"\x55", b"\xc8", b"\x00", b"\x8b\xec"]), max_size=48
).map(b"".join)
_SEGMENT_BODY = st.one_of(
    st.binary(max_size=256),
    _PROLOG_HEAVY,
    st.sampled_from([_CODE, _DATA]),
)


@settings(max_examples=100, deadline=None)
@given(body=_SEGMENT_BODY)
def test_enumerate_ne_functions_invariants(body: bytes) -> None:
    """The linear sweep returns sorted, non-overlapping, in-segment spans.

    Segment bytes are attacker-controlled (a scrambled or data-only code
    segment yields a prolog candidate at nearly every offset), so this
    checks the output contract rather than just the absence of a crash.
    """
    from rebrew.formats.binary_model import BinaryInfo
    from rebrew.formats.ne_loader import NeSegment, enumerate_ne_functions

    segment = body + b"\x55\x8b\xec\xc3"  # ensure at least one real prolog+ret
    info = BinaryInfo(path=Path("fuzz.ne"), format="ne", _data=segment)
    info.ne_segments = [
        NeSegment(
            index=1, file_offset=0, length=len(segment), flags=0, min_allocation=0, is_code=True
        )
    ]

    funcs = enumerate_ne_functions(info)
    previous: NeFunction | None = None
    for func in funcs:
        assert func.name == f"sub_{func.va:05x}"
        assert func.segment == 1
        assert 0 <= func.offset < len(segment)
        assert 3 <= func.size <= len(segment) - func.offset
        # zero-based space: segment 1 contributes no 0x10000 offset
        assert func.va == info.ne_segments[0].base_va + func.offset
        if previous is not None:
            assert func.va >= previous.va + previous.size
        previous = func


@settings(max_examples=20, deadline=None)
@given(fill=st.sampled_from([b"\x55", b"\xc3", b"\x90", b"\x00"]))
def test_enumerate_ne_functions_sweep_is_bounded(fill: bytes) -> None:
    """A ret-free segment must not make the sweep quadratic.

    Every offset is a prolog candidate and none of them reaches a ``ret``,
    so each candidate decodes the rest of the segment.  The decode budget
    caps the bytes fed to the disassembler.  That byte count does not move
    with scheduler load; without the budget a 64 KiB segment takes hours.
    """
    import capstone

    from rebrew.formats.binary_model import BinaryInfo
    from rebrew.formats.ne_loader import SWEEP_DECODE_BUDGET, NeSegment, enumerate_ne_functions

    segment = fill * 4096
    info = BinaryInfo(path=Path("fuzz.ne"), format="ne", _data=segment)
    info.ne_segments = [
        NeSegment(
            index=1, file_offset=0, length=len(segment), flags=0, min_allocation=0, is_code=True
        )
    ]
    fed = 0
    real_disasm = capstone.Cs.disasm

    def counting(self: capstone.Cs, code: bytes, offset: int, count: int = 0) -> object:
        nonlocal fed
        fed += len(code)
        return real_disasm(self, code, offset, count)

    capstone.Cs.disasm = counting
    try:
        assert isinstance(enumerate_ne_functions(info), list)
        # The sweep stops at SWEEP_DECODE_BUDGET. Dedup then disassembles a
        # truncated outer body, which is outside that budget. Twice the budget
        # still rejects an uncapped sweep, whose cost is candidates times length.
        assert fed <= SWEEP_DECODE_BUDGET * 2
    finally:
        capstone.Cs.disasm = real_disasm


def test_enumerate_ne_functions_lists_every_function_of_a_full_segment() -> None:
    """The decode budget is charged the bytes a candidate decodes, not the rest of the segment.

    A 64,000-byte segment of 1,000 small functions decodes about 5 bytes per function.
    Charging each candidate the remaining segment length spent the budget after a few
    dozen functions, and the rest of the segment was never listed.
    """
    from rebrew.formats.binary_model import BinaryInfo
    from rebrew.formats.ne_loader import NeSegment, enumerate_ne_functions

    stride = 64
    count = 1000
    function = b"\x55\x8b\xec\x5d\xc3"  # push bp; mov bp,sp; pop bp; ret
    segment = b"".join(function + b"\x90" * (stride - len(function)) for _ in range(count))
    info = BinaryInfo(path=Path("full.ne"), format="ne", _data=segment)
    info.ne_segments = [
        NeSegment(
            index=1, file_offset=0, length=len(segment), flags=0, min_allocation=0, is_code=True
        )
    ]
    offsets = [f.offset for f in enumerate_ne_functions(info)]
    assert offsets == [i * stride for i in range(count)]


def test_entry_point_and_entry_table_start_functions(tmp_path: Path) -> None:
    """The program entry (CS:IP) is a function even when no prolog opens it, mapped like every other VA."""
    import struct

    from rebrew.formats.ne_loader import enumerate_ne_functions, load_ne_binary

    entry = 0x20
    code = bytearray(b"\x90" * 0x60)
    code[0:4] = b"\x55\x8b\xec\xc3"  # a prolog function at 0
    code[entry : entry + 6] = b"\x90\x90\xb8\x01\x00\xc3"  # no prolog: only the header names it
    data = bytearray(make_ne(segments=[(bytes(code), 0)], exports=[("MAIN", 1)]))
    struct.pack_into("<I", data, 0x100 + 0x14, (1 << 16) | entry)
    path = tmp_path / "entry.exe"
    path.write_bytes(bytes(data))
    functions = {f.va: f for f in enumerate_ne_functions(load_ne_binary(path))}
    assert entry in functions
    assert (functions[entry].segment, functions[entry].offset) == (1, entry)
