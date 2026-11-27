"""Unit tests for rebrew.binary.analysis — shared recon primitives.

Uses ``bin_util.make_xref_probe`` to build a synthetic PE whose ``.text``
section contains hand-assembled instructions with known absolute references
plus an appended string blob (ASCII and UTF-16LE).
"""

from __future__ import annotations

import struct
lazy from collections.abc import Callable
lazy from pathlib import Path

import pytest
from bin_util import (
    PROBE_IMAGE_BASE,
    PROBE_TEXT_VA,
    le32,
    make_import_call_pe,
    make_pe,
    make_xref_probe,
)

from rebrew.binary.analysis import (
    Insn,
    Xref,
    data_references,
    disasm_insns,
    extract_bytes,
    instruction_text,
    is_inside,
    iter_instructions,
    iter_strings,
    reachable_code,
    scan_references,
    section_range,
    string_refs,
    va_to_file_offset,
)
from rebrew.formats.binary_loader import load_binary

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _code_image(code: bytes, *, arch: str, endian: str = "little") -> object:
    """A one-section image large enough that an in-section target stays inside."""
    from types import SimpleNamespace

    section = SimpleNamespace(
        name=".text",
        va=0x1000,
        size=len(code),
        file_offset=0,
        raw_size=len(code),
    )
    return SimpleNamespace(
        path=None,
        format="elf",
        arch=arch,
        endian=endian,
        image_base=0x1000,
        text_va=0x1000,
        text_size=len(code),
        text_raw_offset=0,
        sections={".text": section},
        data=code,
        ne_segments=[],
    )


class TestScanReferences:
    def test_pointer_comparisons_reference_immediate_and_memory(self) -> None:
        # cmp ebx, 0x1020; cmp [0x1030], 0x1020; cmp eax, 1; ret
        code = bytes.fromhex("81 fb 20 10 00 00 81 3d 30 10 00 00 20 10 00 00 83 f8 01 c3")
        info = _code_image(code + b"\x90" * 48, arch="x86_32")
        expected = [
            Xref("cmp", 0x1000, 0x1020),
            Xref("cmp", 0x1006, 0x1020),
            Xref("cmp_mem", 0x1006, 0x1030),
        ]
        assert scan_references(info) == expected
        assert data_references(info, 0x1000, len(code)) == expected
        assert reachable_code(info, 0x1000, len(code))[1] == expected
        assert scan_references(info, target_va=0x1030) == [expected[2]]

    def test_x64_pointer_comparison(self) -> None:
        code = bytes.fromhex("48 3d 10 10 00 00 c3") + b"\x90" * 16
        assert scan_references(_code_image(code, arch="x86_64")) == [Xref("cmp", 0x1000, 0x1010)]

    def test_callback_address_stored_through_register(self) -> None:
        code = bytes.fromhex("c7 00 10 10 00 00 c3") + b"\x90" * 32
        info = _code_image(code, arch="x86_32")
        expected = [Xref("mov", 0x1000, 0x1010)]
        assert scan_references(info, target_va=0x1010) == expected
        assert data_references(info, 0x1000, 7) == expected
        assert reachable_code(info, 0x1000, 7)[1] == expected

    def test_absolute_callback_store_references_both_addresses(self) -> None:
        code = bytes.fromhex("c7 05 20 10 00 00 10 10 00 00 c3") + b"\x90" * 32
        info = _code_image(code, arch="x86_32")
        expected = [("mov", 0x1000, 0x1010), ("mov_mem_store", 0x1000, 0x1020)]
        for refs in (
            scan_references(info),
            data_references(info, 0x1000, 11),
            reachable_code(info, 0x1000, 11)[1],
        ):
            assert sorted((r.kind, r.from_va, r.to_va) for r in refs) == expected
        assert scan_references(info, target_va=0x1020) == [Xref("mov_mem_store", 0x1000, 0x1020)]

    def test_scalar_store_is_not_an_address_reference(self) -> None:
        code = bytes.fromhex("c7 00 01 00 00 00 c3")
        info = _code_image(code, arch="x86_32")
        assert scan_references(info) == []
        assert data_references(info, 0x1000, len(code)) == []
        assert reachable_code(info, 0x1000, len(code))[1] == []

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
        from bin_util import make_ne

        # Code: push bp; mov bp,sp; call rel16; les di, [0x1234].
        # autodata = segment 2 (a data segment holding the 0x1234 global).
        code = bytes.fromhex("55 8b ec e8 00 00 c4 3e 34 12 5d c3")
        data = b"\x02\x00" + b"\x00" * 0x2000  # data segment (autodata)
        raw = make_ne(segments=[(b"\x01\x00" + code, 0x01), (data, 0x00)], autodata=2)
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        refs = scan_references(info)
        by_from = {r.from_va: r for r in refs}
        # Code starts at 0x00002 (after the 2-byte Borland marker); the
        # zero-based VA space puts segment 1 at 0x00000:
        # push bp(0x00002); mov bp,sp(0x00003); call 0x00008(0x00005)
        assert by_from[0x00005].kind == "call"
        assert by_from[0x00005].to_va == 0x00008
        # les di, [0x1234] at 0x00008 → autodata segment 2, whose zero-based
        # base is (2 - 1) << 16
        assert by_from[0x00008].kind == "les_mem"
        assert by_from[0x00008].to_va == info.ne_segments[1].base_va | 0x1234

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

    def test_arm_bl_and_b_are_references(self) -> None:
        """ARM BL is a call and ARM B is a jump. Both print the target as ``#0x``."""
        # bl #0x1010 at 0x1000 (imm 2); b #0x1010 at 0x1004 (imm 1). Pad so 0x1010
        # is still inside .text — a target outside every section is dropped.
        code = (
            (0xEB000002).to_bytes(4, "little") + (0xEA000001).to_bytes(4, "little") + b"\x00" * 12
        )
        info = _code_image(code, arch="arm32")
        refs = scan_references(info)
        assert refs == [
            Xref("call", 0x1000, 0x1010),
            Xref("jmp", 0x1004, 0x1010),
        ]

    def test_sh2_bsr_target_is_the_address_not_the_displacement(self) -> None:
        """SH2 BSR's operand type is not an immediate. The address is in the text."""
        # bsr 0x1008 from 0x1000. The displacement field is 2, not the address.
        code = bytes.fromhex("b0020000000000000900")
        info = _code_image(code, arch="sh2", endian="big")
        refs = scan_references(info)
        assert refs == [Xref("call", 0x1000, 0x1008)]

    def test_sh2_register_memory_does_not_abort_the_scan(self) -> None:
        """``mov.l @r1, r0`` is register-relative. Its operand has no x86 base field."""
        info = _code_image(bytes.fromhex("6012"), arch="sh2", endian="big")
        assert scan_references(info) == []


class TestIndexedReferences:
    @pytest.mark.parametrize(
        "encoding",
        [
            "89 0c 85 80 10 00 00",  # mov [eax*4+0x1080], ecx
            "8b 0c 85 80 10 00 00",  # mov ecx, [eax*4+0x1080]
            "8d 0c 85 80 10 00 00",  # lea ecx, [eax*4+0x1080]
            "ff 14 85 80 10 00 00",  # call [eax*4+0x1080], not an exact IAT slot
            "ff 24 85 80 10 00 00",  # jmp [eax*4+0x1080], not an exact IAT slot
            "ff 34 85 80 10 00 00",  # push [eax*4+0x1080]
            "83 04 85 80 10 00 00 01",  # add [eax*4+0x1080], 1
        ],
    )
    def test_indexed_displacements_are_opt_in_candidates(self, encoding: str) -> None:
        code = bytes.fromhex(encoding) + b"\xc3"
        info = _code_image(code + b"\x90" * 256, arch="x86_32")
        expected = [Xref("indexed_mem", 0x1000, 0x1080)]
        assert scan_references(info) == []
        assert data_references(info, 0x1000, len(code)) == []
        assert reachable_code(info, 0x1000, len(code))[1] == []
        assert scan_references(info, include_indexed=True) == expected
        assert data_references(info, 0x1000, len(code), include_indexed=True) == expected
        assert reachable_code(info, 0x1000, len(code), include_indexed=True)[1] == expected
        assert scan_references(info, target_va=0x1080, include_indexed=True) == expected
        assert scan_references(info, target_va=0x1084, include_indexed=True) == []

    @pytest.mark.parametrize("opcode,kind", [("c7 04 85", "mov"), ("81 3c 85", "cmp")])
    def test_indexed_operand_preserves_address_immediate(self, opcode: str, kind: str) -> None:
        code = bytes.fromhex(opcode + " 80 10 00 00 90 10 00 00 c3")
        info = _code_image(code + b"\x90" * 256, arch="x86_32")
        assert scan_references(info, include_indexed=True) == [
            Xref("indexed_mem", 0x1000, 0x1080),
            Xref(kind, 0x1000, 0x1090),
        ]

    def test_x64_absolute_indexed_displacement(self) -> None:
        code = bytes.fromhex("48 8b 0c c5 80 10 00 00 c3")
        info = _code_image(code + b"\x90" * 256, arch="x86_64")
        assert scan_references(info, include_indexed=True) == [Xref("indexed_mem", 0x1000, 0x1080)]

    @pytest.mark.parametrize(
        "encoding",
        [
            "8b 88 80 10 00 00",  # register-relative, despite an image-valued displacement
            "8b 8c 83 80 10 00 00",  # base register plus index, not an absolute base
            "8b 0c 85 20 00 00 00",  # scalar displacement outside the image
        ],
    )
    def test_register_relative_and_scalar_displacements_stay_excluded(self, encoding: str) -> None:
        code = bytes.fromhex(encoding) + b"\xc3"
        info = _code_image(code + b"\x90" * 256, arch="x86_32")
        assert scan_references(info, include_indexed=True) == []


def _import_calls(
    tmp_path: Path, assemble: Callable[[int, int], str]
) -> list[tuple[str, int, str]]:
    """``(kind, code offset, "a" | "b")`` of each IAT reference the scan reports from the code.

    ``a`` and ``b`` name the two import slots *assemble* is given.
    """
    path, slot_a, slot_b = make_import_call_pe(tmp_path, assemble)
    size = len(bytes.fromhex(assemble(0, 0)))
    names = {slot_a: "a", slot_b: "b"}
    return [
        (ref.kind, ref.from_va - PROBE_TEXT_VA, names.get(ref.to_va, hex(ref.to_va)))
        for ref in scan_references(load_binary(path))
        if ref.kind in {"iat_call", "iat_jmp"} and ref.from_va < PROBE_TEXT_VA + size
    ]


class TestRegisterImportCalls:
    """``call reg`` / ``jmp reg`` through a register loaded from an import slot."""

    def test_load_dominating_a_diamond_reaches_both_calls(self, tmp_path: Path) -> None:
        # Win2k notepad 0x1002cf5: one ``mov esi, [lstrlenW]``, a call on one
        # arm of an if, and a second call after the arms merge.
        def assemble(a: int, _b: int) -> str:
            return (
                "55 8bec 837d1400 56"  # 00 push ebp; mov ebp, esp; cmp [ebp+0x14], 0; push esi
                f"8b35{le32(a)}"  # 08 mov esi, [a]
                "57 7409"  # 0e push edi; je 0x1a
                "ff7514 ffd6"  # 11 push [ebp+0x14]; call esi
                "8bf8 eb02"  # 16 mov edi, eax; jmp 0x1c
                "33ff"  # 1a xor edi, edi
                "ff7510 ffd6"  # 1c push [ebp+0x10]; call esi
                "5f 5e 5d c3"  # 21 pop edi; pop esi; pop ebp; ret
            )

        assert _import_calls(tmp_path, assemble) == [
            ("iat_call", 0x14, "a"),
            ("iat_call", 0x1F, "a"),
        ]
        path, slot, _ = make_import_call_pe(tmp_path, assemble)
        to_slot = scan_references(load_binary(path), target_va=slot)
        assert [(ref.kind, ref.from_va - PROBE_TEXT_VA) for ref in to_slot] == [
            ("mov_mem", 0x08),
            ("iat_call", 0x14),
            ("iat_call", 0x1F),
        ]

    def test_callee_saved_register_survives_calls(self, tmp_path: Path) -> None:
        def assemble(a: int, _b: int) -> str:
            # mov esi, [a]; call esi; call 0x10; call esi; ret; (0x10) ret
            return f"8b35{le32(a)} ffd6 e803000000 ffd6 c3 c3"

        assert _import_calls(tmp_path, assemble) == [
            ("iat_call", 0x06, "a"),
            ("iat_call", 0x0D, "a"),
        ]

    def test_caller_saved_register_is_lost_at_a_call(self, tmp_path: Path) -> None:
        def assemble(a: int, _b: int) -> str:
            return f"a1{le32(a)} ffd0 ffd0 c3"  # mov eax, [a]; call eax; call eax; ret

        assert _import_calls(tmp_path, assemble) == [("iat_call", 0x05, "a")]

    @pytest.mark.parametrize(
        "write",
        [
            "33f6",  # xor esi, esi
            "66be0100",  # mov si, 1: a part of esi
            "ad",  # lodsd: an implicit write
            "5e",  # pop esi
            "46",  # inc esi
            "cd2e",  # int 0x2e
        ],
    )
    def test_a_write_after_the_load_gives_no_edge(self, tmp_path: Path, write: str) -> None:
        assert _import_calls(tmp_path, lambda a, _b: f"8b35{le32(a)} {write} ffd6 c3") == []

    def test_a_reload_wins_and_other_registers_do_not_matter(self, tmp_path: Path) -> None:
        def assemble(a: int, b: int) -> str:
            # mov esi, [a]; mov edi, [a]; mov esi, [b]; call esi; ret
            return f"8b35{le32(a)} 8b3d{le32(a)} 8b35{le32(b)} ffd6 c3"

        assert _import_calls(tmp_path, assemble) == [("iat_call", 0x12, "b")]

    def test_paths_holding_different_slots_give_no_edge(self, tmp_path: Path) -> None:
        def assemble(a: int, b: int) -> str:
            # mov esi, [a]; test eax, eax; je 0x10; mov esi, [b]; (0x10) call esi; ret
            return f"8b35{le32(a)} 85c0 7406 8b35{le32(b)} ffd6 c3"

        assert _import_calls(tmp_path, assemble) == []

    def test_paths_loading_the_same_slot_give_the_edge(self, tmp_path: Path) -> None:
        def assemble(a: int, _b: int) -> str:
            # test eax, eax; je 0x0c; mov esi, [a]; jmp 0x12;
            # (0x0c) mov esi, [a]; (0x12) call esi; ret
            return f"85c0 7408 8b35{le32(a)} eb06 8b35{le32(a)} ffd6 c3"

        assert _import_calls(tmp_path, assemble) == [("iat_call", 0x12, "a")]

    def test_a_path_from_the_entry_without_the_load_gives_no_edge(self, tmp_path: Path) -> None:
        def assemble(a: int, _b: int) -> str:
            # test eax, eax; je 0x0a; mov esi, [a]; (0x0a) call esi; ret
            return f"85c0 7406 8b35{le32(a)} ffd6 c3"

        assert _import_calls(tmp_path, assemble) == []

    def test_a_loop_keeps_the_load_across_its_back_edge(self, tmp_path: Path) -> None:
        def assemble(a: int, _b: int) -> str:
            # mov esi, [a]; (0x06) push 0; call esi; dec ebx; jne 0x06; ret
            return f"8b35{le32(a)} 6a00 ffd6 4b 75f9 c3"

        assert _import_calls(tmp_path, assemble) == [("iat_call", 0x08, "a")]

    def test_a_write_on_the_back_edge_gives_no_edge(self, tmp_path: Path) -> None:
        def assemble(a: int, _b: int) -> str:
            # mov esi, [a]; (0x06) call esi; inc esi; jne 0x06; ret
            return f"8b35{le32(a)} ffd6 46 75fb c3"

        assert _import_calls(tmp_path, assemble) == []

    @pytest.mark.parametrize(
        "reference",
        [
            "e8f8ffffff",  # call 0x06: the site's block is also a function entry
            f"68{le32(PROBE_TEXT_VA + 6)}",  # push 0x401006: an address-taken label
        ],
    )
    def test_an_entry_between_load_and_call_gives_no_edge(
        self, tmp_path: Path, reference: str
    ) -> None:
        # mov esi, [a]; (0x06) call esi; ret; (0x09) <reference>; ret
        assert _import_calls(tmp_path, lambda a, _b: f"8b35{le32(a)} ffd6 c3 {reference} c3") == []

    def test_a_switch_dispatch_is_a_known_predecessor(self, tmp_path: Path) -> None:
        table = PROBE_TEXT_VA + 0x14

        def assemble(a: int, _b: int) -> str:
            # mov esi, [a]; test eax, eax; je 0x11; jmp [eax*4 + table];
            # (0x11) call esi; ret; (0x14) table: dd 0x401011
            return (
                f"8b35{le32(a)} 85c0 7407 ff2485{le32(table)} ffd6 c3 {le32(PROBE_TEXT_VA + 0x11)}"
            )

        assert _import_calls(tmp_path, assemble) == [("iat_call", 0x11, "a")]

    def test_a_pointer_table_read_into_a_register_marks_an_unknown_entry(
        self, tmp_path: Path
    ) -> None:
        table = PROBE_TEXT_VA + 0x11

        def assemble(a: int, _b: int) -> str:
            # mov esi, [a]; mov eax, [eax*4 + table]; nop; (0x0e) call esi; ret;
            # (0x11) table: dd 0x40100e.  0x0e follows the nop and is a table entry.
            return f"8b35{le32(a)} 8b0485{le32(table)} 90 ffd6 c3 {le32(PROBE_TEXT_VA + 0x0E)}"

        assert _import_calls(tmp_path, assemble) == []

    def test_a_tail_jump_through_a_held_import(self, tmp_path: Path) -> None:
        def assemble(a: int, _b: int) -> str:
            return f"56 a1{le32(a)} 5e ffe0"  # push esi; mov eax, [a]; pop esi; jmp eax

        assert _import_calls(tmp_path, assemble) == [("iat_jmp", 0x07, "a")]

    def test_a_load_from_a_global_is_no_import(self, tmp_path: Path) -> None:
        def assemble(_a: int, _b: int) -> str:
            return f"8b35{le32(PROBE_TEXT_VA + 8)} ffd6 c3"  # mov esi, [0x401008]; call esi

        assert _import_calls(tmp_path, assemble) == []

    def test_the_walk_gives_up_past_its_limit(self, tmp_path: Path) -> None:
        from rebrew.binary.analysis import _REGISTER_WALK_LIMIT

        # The load and the nops between it and the call are what the walk visits.
        within = _import_calls(
            tmp_path, lambda a, _b: f"8b35{le32(a)} {'90' * (_REGISTER_WALK_LIMIT - 1)} ffd6 c3"
        )
        assert within == [("iat_call", 6 + _REGISTER_WALK_LIMIT - 1, "a")]
        past = _import_calls(
            tmp_path, lambda a, _b: f"8b35{le32(a)} {'90' * _REGISTER_WALK_LIMIT} ffd6 c3"
        )
        assert past == []


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
    def test_instruction_text_joins_mnemonic_and_operands(self) -> None:
        insn = Insn(va=0x1000, size=1, mnemonic="ret", op_str="", raw=b"\xc3")
        assert instruction_text(insn) == "ret"

    def test_instruction_text_keeps_operands(self) -> None:
        insn = Insn(va=0x1000, size=5, mnemonic="call", op_str="0x1234", raw=b"")
        assert instruction_text(insn) == "call 0x1234"

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

        from rebrew.binary.analysis import capstone_handle

        handle = capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_32)
        assert capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_32) is handle  # cached
        assert handle.detail is False
        assert capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_32, detail=True) is not handle
        assert capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_64) is not handle

    def test_disassembles(self) -> None:
        import capstone as cs

        from rebrew.binary.analysis import capstone_handle

        md = capstone_handle(cs.CS_ARCH_X86, cs.CS_MODE_32)
        insns = list(md.disasm(b"\x55\x8b\xec", 0x1000))
        assert [i.mnemonic for i in insns] == ["push", "mov"]


class TestRipRelativeOperands:
    def test_mov_rip_relative_resolves_to_absolute(self) -> None:
        """x86-64 RIP-relative refs must resolve: target = insn_end + disp."""
        from types import SimpleNamespace

        import capstone

        from rebrew.binary.analysis import _classify_insn

        code = bytes.fromhex("488b0510000000")  # mov rax, [rip+0x10]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        insn = next(md.disasm(code, 0x1000))
        info = SimpleNamespace(format="elf", arch="x86_64")
        ((kind, _from_va, to_va),) = _classify_insn(info, insn)
        assert kind == "mov_mem"
        assert to_va == 0x1000 + len(code) + 0x10


class TestExtractBytesRawSizeClamp:
    def _info(self, tmp_path: Path):
        from rebrew.formats.binary_model import BinaryInfo, SectionInfo

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
        from rebrew.binary.analysis import extract_bytes

        assert extract_bytes(self._info(tmp_path), 0x1000 + 0x20, 8) == b""

    def test_clamped_to_raw_size(self, tmp_path: Path) -> None:
        from rebrew.binary.analysis import extract_bytes

        assert extract_bytes(self._info(tmp_path), 0x1000 + 0x8, 16) == b"A" * 8

    def test_zero_virtual_size_clamps_to_raw_size(self, tmp_path: Path) -> None:
        """A section with virtual size 0 maps its raw size (va_to_file_offset
        resolves it); the read must still stop at raw_size, not run into the
        next section's bytes."""
        from rebrew.binary.analysis import extract_bytes
        from rebrew.formats.binary_model import SectionInfo

        info = self._info(tmp_path)
        info.sections[".data"] = SectionInfo(
            name=".data", va=0x1000, size=0, file_offset=0, raw_size=0x10
        )
        assert extract_bytes(info, 0x1000 + 0x8, 16) == b"A" * 8


class TestScanPascalLongString:
    def test_255_byte_string_found(self) -> None:
        """The scanner capped the length prefix at 63, silently dropping every
        64..255-byte ShortString (Borland's length byte is 1..255)."""
        from rebrew.binary.analysis import _scan_pascal

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
        from rebrew.binary.analysis import _scan_utf16

        raw = b"A\x00B\x00C\x00D\x00E"
        out = _scan_utf16(raw, 0x1000, ".rdata", 4)
        assert [(s.text, s.size) for s in out] == [("ABCD", 8)]
        # 4 complete units, so a min_len of 5 yields nothing.
        assert _scan_utf16(raw, 0x1000, ".rdata", 5) == []

    def test_even_length_region_unchanged(self) -> None:
        from rebrew.binary.analysis import _scan_utf16

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

        from thread_util import join_all

        from rebrew.binary import analysis

        old = analysis._OP_CONSTANTS
        try:
            analysis._OP_CONSTANTS = None
            results: list[tuple[object, ...]] = []
            barrier = threading.Barrier(8)

            def _worker() -> None:
                barrier.wait()
                results.append(analysis._op_constants())

            threads = [threading.Thread(target=_worker, daemon=True) for _ in range(8)]
            for t in threads:
                t.start()
            join_all(threads)

            assert len(results) == 8
            first = results[0]
            for r in results:
                assert r == first
        finally:
            analysis._OP_CONSTANTS = old


class TestOperandScreen:
    """x86-32 instructions are decoded only when they print an in-image value."""

    def test_only_an_in_image_hex_value_passes(self) -> None:
        from rebrew.binary.analysis import _prints_image_address

        starts, ends = [0x401000], [0x402000]
        assert _prints_image_address("dword ptr [0x401010]", starts, ends)
        assert _prints_image_address("0x401ffc", starts, ends)
        assert not _prints_image_address("esp, 0xc", starts, ends)
        assert not _prints_image_address("eax, dword ptr [ebp - 8]", starts, ends)
        assert not _prints_image_address("0x402000", starts, ends)

    def test_screening_needs_every_image_address_printed_in_hex(self) -> None:
        from types import SimpleNamespace

        from rebrew.binary.analysis import _screens_operands

        pe = SimpleNamespace(arch="x86_32", format="pe")
        assert _screens_operands(pe, [0x401000])
        # An image range at 0 holds addresses that print in decimal.
        assert not _screens_operands(pe, [0x0, 0x401000])
        assert not _screens_operands(SimpleNamespace(arch="x86_32", format="ne"), [0x10000])
        assert not _screens_operands(SimpleNamespace(arch="x86_64", format="pe"), [0x401000])
