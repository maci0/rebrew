"""Unit tests for rebrew.analysis — shared recon primitives.

Uses ``bin_util.make_xref_probe`` to build a synthetic PE whose ``.text``
section contains hand-assembled instructions with known absolute references
plus an appended string blob (ASCII and UTF-16LE).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import PROBE_IMAGE_BASE, PROBE_TEXT_VA, make_pe, make_xref_probe

from rebrew.analysis import (
    Insn,
    Xref,
    data_references,
    disasm_insns,
    extract_bytes,
    is_inside,
    iter_instructions,
    iter_strings,
    scan_references,
    section_range,
    string_refs,
    va_to_file_offset,
)
from rebrew.binary_loader import load_binary

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScanReferences:
    def test_finds_all_abs_refs(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        refs = scan_references(info)
        by_from = {r.from_va: r for r in refs}
        assert by_from[syms["call"]] == Xref("call", syms["call"], syms["call"] + 5 + 0x10)
        assert by_from[syms["push"]].kind == "push"
        assert by_from[syms["push"]].to_va == syms["hello"]
        assert by_from[syms["mov"]].kind == "mov"
        assert by_from[syms["mov"]].to_va == syms["game"]
        assert by_from[syms["iat_call"]].kind == "iat_call"
        assert by_from[syms["iat_call"]].to_va == syms["iat_slot"]
        assert by_from[syms["lea"]].kind == "lea"
        assert by_from[syms["lea"]].to_va == syms["wide"]
        assert by_from[syms["mov_mem"]].kind == "mov_mem"
        assert by_from[syms["mov_mem"]].to_va == syms["wide"]
        assert by_from[syms["and_mem"]].kind == "and_mem"
        assert by_from[syms["and_mem"]].to_va == syms["hello"]

    def test_ne_16bit_refs(self, tmp_path: Path) -> None:
        """16-bit NE scanning: near calls resolve within their segment and
        [imm16] operands resolve against the autodata segment."""
        from test_ne_loader import _build_ne

        # Code: push bp; mov bp,sp; call rel16; les di, [0x1234].
        # autodata = segment 2 (a data segment holding the 0x1234 global).
        code = bytes.fromhex("55 8b ec e8 00 00 c4 3e 34 12 5d c3")
        data = b"\x02\x00" + b"\x00" * 0x2000  # data segment (autodata)
        raw = _build_ne(segments=[(b"\x01\x00" + code, 0x01), (data, 0x00)], autodata=2)
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        refs = scan_references(info)
        by_from = {r.from_va: r for r in refs}
        # Code starts at 0x10002 (after the 2-byte Borland marker):
        # push bp(0x10002); mov bp,sp(0x10003); call 0x10008(0x10005)
        assert by_from[0x10005].kind == "call"
        assert by_from[0x10005].to_va == 0x10008
        # les di, [0x1234] at 0x10008 → autodata seg 2 << 16 | 0x1234
        assert by_from[0x10008].kind == "les_mem"
        assert by_from[0x10008].to_va == (2 << 16) | 0x1234

    def test_target_filter(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        refs = scan_references(info, target_va=syms["wide"])
        kinds = sorted(r.kind for r in refs)
        assert kinds == ["lea", "mov_mem"]
        assert all(r.to_va == syms["wide"] for r in refs)

    def test_sorted_by_from_va(self, tmp_path: Path) -> None:
        path, _ = make_xref_probe(tmp_path)
        info = load_binary(path)
        refs = scan_references(info)
        froms = [r.from_va for r in refs]
        assert froms == sorted(froms)

    def test_register_relative_mem_not_absolute(self, tmp_path: Path) -> None:
        """[esi+0xd] must NOT be treated as an absolute reference."""
        code = b"\x83\x66\x0d\x10\xc3"  # and word ptr [esi+0xd], 0x10; ret
        path = tmp_path / "rel.exe"
        path.write_bytes(make_pe(code))
        info = load_binary(path)
        assert scan_references(info) == []


class TestIterStrings:
    def test_ascii_and_utf16(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        strings = iter_strings(info, min_len=4, section_names=[".text"])
        by_va = {s.va: s for s in strings}
        assert by_va[syms["hello"]].text == "Hello World"
        assert by_va[syms["hello"]].kind == "ascii"
        assert by_va[syms["game"]].text == "Game Boys"
        assert by_va[syms["game"]].kind == "ascii"
        assert by_va[syms["wide"]].text == "Wide"
        assert by_va[syms["wide"]].kind == "utf16"

    def test_min_len_filters(self, tmp_path: Path) -> None:
        code = b"AB\x00" + b"LongEnoughString\x00" + b"\xc3"
        path = tmp_path / "len.exe"
        path.write_bytes(make_pe(code))
        info = load_binary(path)
        strings = iter_strings(info, min_len=5, section_names=[".text"])
        texts = [s.text for s in strings]
        assert "AB" not in texts
        assert "LongEnoughString" in texts

    def test_default_sections_skip_text(self, tmp_path: Path) -> None:
        code = b"HelloInCode\x00\xc3"
        path = tmp_path / "skip.exe"
        path.write_bytes(make_pe(code))
        info = load_binary(path)
        # Probe has only .text; default sections (data-ish) do not include it.
        assert iter_strings(info, min_len=4) == []


class TestStringRefs:
    def test_maps_strings_to_refs(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        strings = iter_strings(info, min_len=4, section_names=[".text"])
        refs = string_refs(info, strings)
        hello_kinds = sorted(r.kind for r in refs[syms["hello"]])
        assert hello_kinds == ["and_mem", "push"]
        assert sorted(r.kind for r in refs[syms["wide"]]) == ["lea", "mov_mem"]


class TestInsnAndBytes:
    def test_iter_instructions(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        insns = iter_instructions(info, syms["call"], 0x29)
        assert insns[0].mnemonic == "call"
        assert insns[0].raw == b"\xe8\x10\x00\x00\x00"
        assert insns[7].mnemonic == "ret"
        assert all(isinstance(i, Insn) for i in insns)

    def test_section_range(self, tmp_path: Path) -> None:
        path, _ = make_xref_probe(tmp_path)
        info = load_binary(path)
        start, size = section_range(info, ".text")
        assert start == PROBE_TEXT_VA
        assert size >= 0x45

    def test_va_to_file_offset_roundtrip(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        offset = va_to_file_offset(info, syms["hello"])
        assert offset >= 0
        raw = info.data
        assert raw[offset : offset + 11] == b"Hello World"

    def test_extract_bytes(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        assert extract_bytes(info, syms["hello"], 11) == b"Hello World"

    def test_is_inside(self, tmp_path: Path) -> None:
        path, _ = make_xref_probe(tmp_path)
        info = load_binary(path)
        assert is_inside(info, PROBE_TEXT_VA + 0x10)
        assert not is_inside(info, PROBE_IMAGE_BASE + 0x9000)


class TestCapstoneHandle:
    def test_cached_per_arch_mode_and_detail(self) -> None:
        import capstone as cs

        from rebrew.analysis import capstone_handle

        handle = capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_32)
        assert capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_32) is handle  # cached
        assert handle.detail is False
        assert capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_32, detail=True) is not handle
        assert capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_64) is not handle

    def test_disassembles(self) -> None:
        import capstone as cs

        from rebrew.analysis import capstone_handle

        md = capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_32)
        insns = list(md.disasm(b"\x55\x8b\xec", 0x1000))
        assert [i.mnemonic for i in insns] == ["push", "mov"]


class TestRipRelativeOperands:
    def test_mov_rip_relative_resolves_to_absolute(self) -> None:
        """x86-64 RIP-relative refs must resolve: target = insn_end + disp."""
        from types import SimpleNamespace

        import capstone

        from rebrew.analysis import _classify_insn

        code = bytes.fromhex("488b0510000000")  # mov rax, [rip+0x10]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        insn = next(md.disasm(code, 0x1000))
        info = SimpleNamespace(format="elf", arch="x86_64")
        kind, _from_va, to_va = _classify_insn(info, insn)
        assert kind == "mov_mem"
        assert to_va == 0x1000 + len(code) + 0x10


class TestExtractBytesRawSizeClamp:
    def _info(self, tmp_path: Path):
        from rebrew.binary_loader import BinaryInfo, SectionInfo

        # `.data` claims 0x2000 mapped bytes but only 0x10 file bytes.
        payload = b"A" * 0x10 + b"B" * 0x40
        f = tmp_path / "t.bin"
        f.write_bytes(payload)
        return BinaryInfo(
            path=f,
            format="pe",
            sections={
                ".data": SectionInfo(
                    name=".data", va=0x1000, size=0x2000, file_offset=0, raw_size=0x10
                )
            },
        )

    def test_past_raw_size_returns_empty(self, tmp_path: Path) -> None:
        """The uninitialized tail of a section has no file bytes; the
        neighbouring data must not be returned as content."""
        from rebrew.analysis import extract_bytes

        assert extract_bytes(self._info(tmp_path), 0x1000 + 0x20, 8) == b""

    def test_clamped_to_raw_size(self, tmp_path: Path) -> None:
        from rebrew.analysis import extract_bytes

        assert extract_bytes(self._info(tmp_path), 0x1000 + 0x8, 16) == b"A" * 8

    def test_zero_virtual_size_clamps_to_raw_size(self, tmp_path: Path) -> None:
        """A section with virtual size 0 maps its raw size (va_to_file_offset
        resolves it); the read must still stop at raw_size, not run into the
        next section's bytes."""
        from rebrew.analysis import extract_bytes
        from rebrew.binary_loader import SectionInfo

        info = self._info(tmp_path)
        info.sections[".data"] = SectionInfo(
            name=".data", va=0x1000, size=0, file_offset=0, raw_size=0x10
        )
        assert extract_bytes(info, 0x1000 + 0x8, 16) == b"A" * 8


class TestScanPascalLongString:
    def test_255_byte_string_found(self) -> None:
        """The scanner capped the length prefix at 63, silently dropping every
        64..255-byte ShortString (Borland's length byte is 1..255)."""
        from rebrew.analysis import _scan_pascal

        body = b"A" * 200
        out = _scan_pascal(bytes([200]) + body, 0x1000, "SEG1", 4)
        assert [(s.va, s.size, s.kind) for s in out] == [(0x1000, 201, "pascal")]


class TestDataReferences:
    def test_refs_are_limited_to_the_extent(self, tmp_path: Path) -> None:
        """The per-function scan stops at the extent: only the caller's own
        instructions contribute references."""
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        refs = data_references(info, syms["call"], 5)
        assert [(r.kind, r.to_va) for r in refs] == [("call", syms["call"] + 5 + 0x10)]
        assert refs[0].from_va == syms["call"]

    def test_sees_refs_after_arbitrary_filler(self, tmp_path: Path) -> None:
        """A function following a non-code blob still contributes its own
        references: only that function's bytes are decoded."""
        filler = bytes(range(256))
        func = b"\xa1" + struct.pack("<I", PROBE_TEXT_VA) + b"\xc3"  # mov eax, [PROBE_TEXT_VA]; ret
        path = tmp_path / "filler.exe"
        path.write_bytes(make_pe(b"\xc3" * 4 + filler + func))
        info = load_binary(path)
        func_va = info.text_va + 4 + len(filler)
        refs = data_references(info, func_va, len(func))
        assert [(r.kind, r.to_va) for r in refs] == [("mov_mem", PROBE_TEXT_VA)]

    def test_out_of_image_targets_are_dropped(self, tmp_path: Path) -> None:
        """A reference to an address outside every section is not a datum."""
        func = b"\xa1" + struct.pack("<I", 0x100) + b"\xc3"  # mov eax, [0x100]; ret
        path = tmp_path / "outside.exe"
        path.write_bytes(make_pe(func))
        info = load_binary(path)
        assert data_references(info, info.text_va, len(func)) == []

    def test_zero_size_yields_nothing(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        info = load_binary(path)
        assert data_references(info, syms["call"], 0) == []


class TestScanUtf16TrailingByte:
    def test_unpaired_trailing_byte_is_not_a_character(self) -> None:
        """The final flush used `raw[start::2]` and `len(raw) - start`, so an odd
        trailing byte became a phantom character (and inflated `size`): raw
        `A\\0B\\0C\\0D\\0E` reported "ABCDE" with size 9."""
        from rebrew.analysis import _scan_utf16

        raw = b"A\x00B\x00C\x00D\x00E"
        out = _scan_utf16(raw, 0x1000, ".rdata", 4)
        assert [(s.text, s.size) for s in out] == [("ABCD", 8)]
        # 4 complete units, so a min_len of 5 yields nothing.
        assert _scan_utf16(raw, 0x1000, ".rdata", 5) == []

    def test_even_length_region_unchanged(self) -> None:
        from rebrew.analysis import _scan_utf16

        out = _scan_utf16(b"A\x00B\x00C\x00D\x00", 0x1000, ".rdata", 4)
        assert [(s.text, s.size) for s in out] == [("ABCD", 8)]


class TestDisasmInsnsCapstoneConstants:
    """disasm_insns must accept BOTH capstone constant-name strings (module
    defaults) and the int constants cfg.capstone_arch/mode return (the config
    property returns ints — a raw getattr(capstone, int) used to crash)."""

    _CODE = bytes.fromhex("558bec83ec08b801000000c9c3")

    def test_string_names(self) -> None:
        insns = disasm_insns(self._CODE, 0x1000, "CS_ARCH_X86", "CS_MODE_32")
        assert len(insns) == 6
        assert [(i.mnemonic, i.op_str) for i in insns] == [
            ("push", "ebp"),
            ("mov", "ebp, esp"),
            ("sub", "esp, 8"),
            ("mov", "eax, 1"),
            ("leave", ""),
            ("ret", ""),
        ]

    def test_int_constants(self) -> None:
        import capstone

        insns = disasm_insns(self._CODE, 0x1000, capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        assert len(insns) == 6
        assert insns[0].mnemonic == "push"
        assert insns[0].op_str == "ebp"
        assert insns[-1].mnemonic == "ret"

    def test_both_forms_equal(self) -> None:
        a = [
            (i.mnemonic, i.op_str)
            for i in disasm_insns(self._CODE, 0x1000, "CS_ARCH_X86", "CS_MODE_32")
        ]
        b = [
            (i.mnemonic, i.op_str)
            for i in disasm_insns(self._CODE, 0x1000, 3, 4)  # CS_ARCH_X86=3, CS_MODE_32=4
        ]
        assert a == b


class TestConcurrentOpConstants:
    def test_concurrent_op_constants_init(self) -> None:
        """Concurrent callers must receive the cached constants without race."""
        import threading

        from rebrew import analysis

        old = analysis._OP_CONSTANTS
        try:
            analysis._OP_CONSTANTS = None
            results: list[tuple[object, ...]] = []
            barrier = threading.Barrier(8)

            def _worker() -> None:
                barrier.wait()
                results.append(analysis._op_constants())

            threads = [threading.Thread(target=_worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(results) == 8
            first = results[0]
            for r in results:
                assert r == first
        finally:
            analysis._OP_CONSTANTS = old
