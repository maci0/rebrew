"""Tests for the reccmp-adapted modules: pinned diff, asm equivalence,
vtordisp/float-const scans, and the near_diag wiring (pins + jump-swap
equivalence)."""

import struct

import pytest

from rebrew.analysis import disasm_insns
from rebrew.float_const import find_float_consts, find_float_instructions_in_buffer
from rebrew.near_diag import align_and_classify, jump_swap_ok
from rebrew.pinned_diff import SequenceMatcherWithPins
from rebrew.vtordisp import find_vtordisps

# ---------------------------------------------------------------------------
# pinned_diff
# ---------------------------------------------------------------------------


class TestSequenceMatcherWithPins:
    def test_pin_blocks_cross_alignment(self) -> None:
        # Without the pin, 'ab' in a could align anywhere; the pin forces
        # the X island to stay between the pinned anchors.
        m = SequenceMatcherWithPins("abXcd", "abYcd", [(1, 1), (3, 3)])
        tags = [op.tag for op in m.get_opcodes()]
        assert tags == ["equal", "equal", "replace", "equal"]
        assert m.ratio() == pytest.approx(0.8)

    def test_no_pins_equals_plain_diff(self) -> None:
        import difflib

        a, b = ["x", "y", "z"], ["x", "q", "z"]
        m = SequenceMatcherWithPins(a, b, [])
        plain = difflib.SequenceMatcher(None, a, b, autojunk=False)
        assert [op.tag for op in m.get_opcodes()] == [op[0] for op in plain.get_opcodes()]

    def test_invalid_pins_dropped(self) -> None:
        m = SequenceMatcherWithPins("ab", "ab", [(99, 0), (0, 99), (1, 1)])
        assert all(op.tag == "equal" for op in m.get_opcodes())

    def test_non_monotonic_pins_raise(self) -> None:
        with pytest.raises(ValueError, match="monotonous"):
            SequenceMatcherWithPins("abc", "abc", [(2, 2), (1, 1)])


# ---------------------------------------------------------------------------
# asm_equiv
# ---------------------------------------------------------------------------


class TestAsmEquiv:
    def test_jump_swap_table(self) -> None:
        assert jump_swap_ok("ja 0x10", "jb 0x10")
        assert jump_swap_ok("jge 0x10", "jle 0x10")
        assert jump_swap_ok("je 0x10", "je 0x10")
        assert not jump_swap_ok("ja 0x10", "jg 0x10")
        assert not jump_swap_ok("mov eax, ebx", "jb 0x10")


# ---------------------------------------------------------------------------
# vtordisp
# ---------------------------------------------------------------------------


class TestVtordisp:
    def test_vtordisp_zero_addend(self) -> None:
        # sub ecx, 0x10 ; jmp rel32 (to base+0x100)
        jmp = struct.pack("<i", 0x100 - 8)
        code = b"\x2b\x49\x10" + b"\xe9" + jmp
        found = list(find_vtordisps(code, 0x401000))
        assert len(found) == 1
        t = found[0]
        assert t.addr == 0x401000
        assert t.disp == 0x10
        assert t.addend == 0
        assert t.size == 8
        assert t.func_addr == 0x401100

    def test_vtordisp_add_addend(self) -> None:
        # sub ecx, 4 ; add ecx, 0x20 ; jmp rel32
        code = (
            b"\x2b\x49\x04\x81\xc1"
            + struct.pack("<i", 0x20)
            + b"\xe9"
            + struct.pack("<i", 0x200 - 14)
        )
        (t,) = find_vtordisps(code, 0x401000)
        assert t.addend == 0x20
        assert t.size == 14
        assert t.func_addr == 0x401200

    def test_vtordisp_sub_addend(self) -> None:
        # sub ecx, 4 ; sub ecx, 8 ; jmp rel32
        code = b"\x2b\x49\x04\x83\xe9\x08\xe9" + struct.pack("<i", 0x300 - 11)
        (t,) = find_vtordisps(code, 0x401000)
        assert t.addend == -8
        assert t.size == 11
        assert t.func_addr == 0x401300

    def test_no_thunks_in_plain_code(self) -> None:
        assert list(find_vtordisps(b"\x90" * 32, 0x401000)) == []


# ---------------------------------------------------------------------------
# float_const
# ---------------------------------------------------------------------------


class TestFloatConst:
    def test_find_float_instructions(self) -> None:
        # fld dword ptr [0x00403000]
        code = b"\xd9\x05" + struct.pack("<I", 0x403000) + b"\x90"
        found = list(find_float_instructions_in_buffer(code, 0x401000))
        assert len(found) == 1
        assert found[0].address == 0x401000
        assert found[0].pointer == 0x403000

    def test_find_float_consts(self) -> None:
        image = struct.pack("<f", 3.5)  # the constant at 0x403000
        # fld [0x403000] from code at 0x401000
        code = b"\xd9\x05" + struct.pack("<I", 0x403000)
        consts = list(
            find_float_consts(
                [(0x401000, code)],
                [(0x403000, 0x403100)],
                lambda va, size: image,
            )
        )
        assert len(consts) == 1
        assert consts[0].address == 0x403000
        assert consts[0].size == 4
        assert consts[0].value == pytest.approx(3.5)

    def test_pointer_to_writable_data_ignored(self) -> None:
        code = b"\xd9\x05" + struct.pack("<I", 0x405000)
        assert (
            list(
                find_float_consts(
                    [(0x401000, code)], [(0x403000, 0x403100)], lambda va, size: b"\x00" * size
                )
            )
            == []
        )

    def test_duplicate_pointer_yielded_once(self) -> None:
        code = (b"\xd9\x05" + struct.pack("<I", 0x403000)) * 2
        consts = list(
            find_float_consts([(0x401000, code)], [(0x403000, 0x403100)], lambda va, s: b"\x00" * s)
        )
        assert len(consts) == 1

    def test_double_straddling_region_end_skipped(self) -> None:
        # fld qword ptr [0x4030fc]: 8 bytes would run past .rdata end 0x403100
        code = b"\xdd\x05" + struct.pack("<I", 0x4030FC)
        consts = list(
            find_float_consts([(0x401000, code)], [(0x403000, 0x403100)], lambda va, s: b"\x00" * 4)
        )
        assert consts == []

    def test_unrelocated_hit_does_not_mask_real_reference(self) -> None:
        ref = b"\xd9\x05" + struct.pack("<I", 0x403000)
        code = ref + ref  # first copy is not a reloc site, second is
        consts = list(
            find_float_consts(
                [(0x401000, code)],
                [(0x403000, 0x403100)],
                lambda va, s: b"\x00" * s,
                reloc_sites={0x401000 + len(ref) + 2},
            )
        )
        assert [c.address for c in consts] == [0x403000]


# ---------------------------------------------------------------------------
# near_diag wiring
# ---------------------------------------------------------------------------


class TestNearDiagWiring:
    def test_jump_swap_classified_equivalent(self) -> None:
        # cmp/ja vs cmp/jb with same displacement: mirrored condition pair.
        # ja rel8 (0x77) vs jb rel8 (0x72), same operand.
        target = disasm_insns(b"\x77\x08", 0x401000)
        compiled = disasm_insns(b"\x72\x08", 0x401000)
        counts, _ = align_and_classify(target, compiled, set())
        assert counts["equivalent"] == 2
        assert counts["structural"] == 0

    def test_pins_keep_alignment_across_churn(self) -> None:
        # Shared unique anchor instruction (b8 imm32 = mov eax, imm) on both
        # sides; unique raw pins must produce an equal span at the anchor.
        shared = b"\xb8\xef\xbe\xad\xde"
        target = disasm_insns(b"\x90\x90" + shared, 0x401000)
        compiled = disasm_insns(b"\x90" + shared, 0x401000)
        counts, _ = align_and_classify(target, compiled, set())
        # The anchor's 5 bytes must be classified 'match', not scrambled.
        assert counts["match"] >= 5
