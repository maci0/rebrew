"""Tests for rebrew.matcher.scoring — score_candidate, diff_functions."""

from rebrew.matcher.core import Score, StructuralSimilarity
from rebrew.matcher.scoring import (
    _mask_registers_x86_32,
    _normalize_reloc_x86_32,
    diff_functions,
    score_candidate,
    structural_similarity,
)

# -------------------------------------------------------------------------
# _mask_registers_x86_32
# -------------------------------------------------------------------------


class TestMaskRegisters:
    def test_modrm_masking(self) -> None:
        # mov eax, ebx (8b c3) vs mov edx, ecx (8b d1)
        res1 = _mask_registers_x86_32(b"\x8b\xc3")
        res2 = _mask_registers_x86_32(b"\x8b\xd1")
        assert res1 == b"\x8b\xc0"
        assert res1 == res2

    def test_opcode_masking(self) -> None:
        # push eax (50) vs push ebx (53)
        res1 = _mask_registers_x86_32(b"\x50")
        res2 = _mask_registers_x86_32(b"\x53")
        assert res1 == b"\x50"
        assert res1 == res2

        # mov eax, 0 (b8 00 00 00 00) vs mov ecx, 0 (b9 00 00 00 00)
        res3 = _mask_registers_x86_32(b"\xb8\x00\x00\x00\x00")
        res4 = _mask_registers_x86_32(b"\xb9\x00\x00\x00\x00")
        assert res3 == b"\xb8\x00\x00\x00\x00"
        assert res3 == res4


# -------------------------------------------------------------------------
# _normalize_reloc_x86_32
# -------------------------------------------------------------------------


class TestNormalizeReloc:
    def test_noop_on_empty(self) -> None:
        result = _normalize_reloc_x86_32(b"")
        assert result == b""

    def test_call_rel32_zeroed(self) -> None:
        # E8 xx xx xx xx  (call near)
        code = b"\xe8\xab\xcd\xef\x01"
        result = _normalize_reloc_x86_32(code)
        assert result[0] == 0xE8
        # The 4 displacement bytes should be zeroed
        assert result[1:5] == b"\x00\x00\x00\x00"

    def test_jmp_rel32_zeroed(self) -> None:
        # E9 xx xx xx xx  (jmp near)
        code = b"\xe9\xab\xcd\xef\x01"
        result = _normalize_reloc_x86_32(code)
        assert result[0] == 0xE9
        assert result[1:5] == b"\x00\x00\x00\x00"

    def test_sib_disp32_zeroed(self) -> None:
        # lea ecx, [eax*4 + 0x100358a0] -> 8d 0c 85 a0 58 03 10
        code = b"\x8d\x0c\x85\xa0\x58\x03\x10"
        result = _normalize_reloc_x86_32(code)
        assert result[0:3] == code[0:3]
        assert result[3:7] == b"\x00\x00\x00\x00"

    def test_non_reloc_unchanged(self) -> None:
        # push ebp; mov ebp, esp; sub esp, 10h
        code = b"\x55\x8b\xec\x83\xec\x10"
        result = _normalize_reloc_x86_32(code)
        assert result == code


# -------------------------------------------------------------------------
# score_candidate
# -------------------------------------------------------------------------


class TestScoreCandidate:
    def test_perfect_match(self) -> None:
        # push ebp; mov ebp, esp; sub esp, 10h; ret
        code = b"\x55\x8b\xec\x83\xec\x10\xc3"
        score = score_candidate(code, code)
        assert isinstance(score, Score)
        assert score.length_diff == 0
        assert score.byte_score == 0.0

    def test_different_code(self) -> None:
        target = b"\x55\x8b\xec\x83\xec\x10\xc3"
        cand = b"\x55\x8b\xec\x83\xec\x20\xc3"
        score = score_candidate(target, cand)
        assert score.byte_score > 0.0

    def test_different_length(self) -> None:
        target = b"\x55\x8b\xec\xc3"
        cand = b"\x55\x8b\xec\x83\xec\x10\xc3"
        score = score_candidate(target, cand)
        assert score.length_diff > 0

    def test_with_reloc_offsets(self) -> None:
        # call near with different displacement — should score better with relocs
        target = b"\x55\x8b\xec\xe8\x01\x02\x03\x04\xc3"
        cand = b"\x55\x8b\xec\xe8\xff\xfe\xfd\xfc\xc3"
        score_no_reloc = score_candidate(target, cand)
        score_with_reloc = score_candidate(target, cand, reloc_offsets=[4])
        # With reloc offsets, reloc bytes are excluded; score should differ or be better
        assert score_with_reloc.reloc_score <= score_no_reloc.reloc_score

    def test_empty(self) -> None:
        score = score_candidate(b"", b"")
        assert isinstance(score, Score)
        assert score.length_diff == 0
        assert score.byte_score == 0.0

    def test_prologue_bonus_for_matching_start(self) -> None:
        # First 20 bytes identical → prologue_bonus should be negative (bonus)
        code = b"\x55\x8b\xec\x83\xec\x40\x53\x56\x57\x89\x65\xe8\x89\x45\xfc\x8b\x45\x08\x89\x45\xf8\xc3"
        # Same first 20 bytes, different ending
        cand = b"\x55\x8b\xec\x83\xec\x40\x53\x56\x57\x89\x65\xe8\x89\x45\xfc\x8b\x45\x08\x89\x45\xf8\x90"
        score = score_candidate(code, cand)
        assert score.prologue_bonus < 0  # bonus is negative (reward)

    def test_prologue_penalty_for_different_start(self) -> None:
        # Different first bytes → no prologue bonus
        code = b"\x55\x8b\xec\x83\xec\x10\xc3"
        cand = b"\x56\x8b\xf0\x83\xec\x10\xc3"
        score = score_candidate(code, cand)
        assert score.prologue_bonus == 0.0

    def test_total_is_sum_of_components(self) -> None:
        target = b"\x55\x8b\xec\x83\xec\x10\xc3"
        cand = b"\x55\x8b\xec\x83\xec\x20\xc3"
        score = score_candidate(target, cand)
        expected = (
            score.length_diff * 3.0
            + score.byte_score * 1000.0
            + score.reloc_score * 500.0
            + score.mnemonic_score * 200.0
            + score.prologue_bonus
        )
        assert abs(score.total - expected) < 0.01

    def test_negative_reloc_offsets_ignored(self) -> None:
        code = b"\x55\x8b\xec\xe8\x01\x02\x03\x04\xc3"
        score = score_candidate(code, code, reloc_offsets=[-1, 4])
        assert score.reloc_score == 0.0


# -------------------------------------------------------------------------
# diff_functions
# -------------------------------------------------------------------------


class TestDiffFunctions:
    def test_identical_code(self) -> None:
        code = b"\x55\x8b\xec\xc3"
        result = diff_functions(code, code, as_dict=True)
        assert isinstance(result, dict)
        assert "instructions" in result
        assert "summary" in result
        # All lines should be exact matches
        for line in result["instructions"]:
            assert line["match"] in ("==", "~~"), (
                f"Expected match for identical code, got {line['match']}"
            )
        assert result["summary"]["structural"] == 0

    def test_different_code(self) -> None:
        # sub esp, 0x10 vs sub esp, 0x20 — structural difference (not relocation)
        target = b"\x55\x8b\xec\x83\xec\x10\xc3"
        cand = b"\x55\x8b\xec\x83\xec\x20\xc3"
        result = diff_functions(target, cand, as_dict=True)
        assert isinstance(result, dict)
        matches = [line["match"] for line in result["instructions"]]
        # Must have structural diffs, not just relocation diffs
        assert "**" in matches
        assert result["summary"]["structural"] > 0

    def test_mismatched_length(self) -> None:
        target = b"\x55\x8b\xec\xc3"
        cand = b"\x55\x8b\xec\x83\xec\x10\xc3"
        result = diff_functions(target, cand, as_dict=True)
        assert isinstance(result, dict)
        assert result["target_size"] == 4
        assert result["candidate_size"] == 7

    def test_empty_inputs(self) -> None:
        result = diff_functions(b"", b"", as_dict=True)
        assert isinstance(result, dict)
        assert len(result["instructions"]) == 0

    def test_disp32_zeroed_general(self) -> None:
        # A1 00 00 00 10 is mov eax, dword ptr [0x10000000]
        # This is caught by the specific A0-A3 check, but let's test a general one like 8b 0d
        # mov ecx, dword ptr [0x100358a0] -> 8b 0d a0 58 03 10
        code = b"\x8b\x0d\xa0\x58\x03\x10"
        result = _normalize_reloc_x86_32(code)
        # Should be caught by 8B check:
        assert result[0:2] == code[0:2]
        assert result[2:6] == b"\x00\x00\x00\x00"


# -------------------------------------------------------------------------
# structural_similarity
# -------------------------------------------------------------------------


class TestStructuralSimilarity:
    def test_identical_code(self) -> None:
        code = b"\x55\x8b\xec\x83\xec\x10\xc3"
        sim = structural_similarity(code, code)
        assert isinstance(sim, StructuralSimilarity)
        assert sim.structural == 0
        assert sim.register_only == 0
        assert sim.structural_ratio == 0.0
        assert sim.mnemonic_match_ratio == 1.0
        assert sim.flag_sensitive is False

    def test_structural_diff_detected(self) -> None:
        # sub esp, 0x10 vs sub esp, 0x20 — structural difference
        target = b"\x55\x8b\xec\x83\xec\x10\xc3"
        cand = b"\x55\x8b\xec\x83\xec\x20\xc3"
        sim = structural_similarity(target, cand)
        assert sim.structural > 0
        assert sim.structural_ratio > 0.0
        assert sim.total_insns > 0

    def test_reloc_only_not_structural(self) -> None:
        # call near with different displacement — reloc only
        target = b"\x55\x8b\xec\xe8\x01\x02\x03\x04\xc3"
        cand = b"\x55\x8b\xec\xe8\xff\xfe\xfd\xfc\xc3"
        sim = structural_similarity(target, cand)
        assert sim.reloc_only > 0
        assert sim.structural == 0
        assert sim.flag_sensitive is False

    def test_register_diff_not_structural(self) -> None:
        # push eax; pop eax vs push ebx; pop ebx — register-only difference
        target = b"\x50\x58"
        cand = b"\x53\x5b"
        sim = structural_similarity(target, cand)
        assert sim.register_only > 0
        assert sim.structural == 0
        assert sim.flag_sensitive is False

    def test_empty_inputs(self) -> None:
        sim = structural_similarity(b"", b"")
        assert sim.total_insns == 0
        assert sim.structural_ratio == 0.0
        assert sim.flag_sensitive is False

    def test_flag_sensitive_moderate_structural(self) -> None:
        # 7 identical nops + 3 structurally different: inc eax (40) vs dec eax (48)
        # These have different opcodes AND the register mask groups them differently
        # (0x40-0x47 = inc, 0x48-0x4F = dec), so after masking 0xF8 they differ.
        # inc eax = 40, masked = 40; dec eax = 48, masked = 48 → structural
        target = b"\x90" * 7 + b"\x40\x40\x40"
        cand = b"\x90" * 7 + b"\x48\x48\x48"
        sim = structural_similarity(target, cand)
        assert sim.exact >= 7
        assert sim.structural > 0
        assert sim.total_insns > 0
