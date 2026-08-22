"""Tests for rebrew.matcher.scoring — score_candidate, diff_functions."""

import capstone
import pytest

from rebrew.matcher.core import Score, StructuralSimilarity
from rebrew.matcher.scoring import (
    _mask_registers_x86_32,
    _normalize_reloc_x86_32,
    diff_functions,
    precompute_target,
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

    def test_fast_path_parity_with_detail(self) -> None:
        """The non-detail fast path (_normalize_and_mnems_x86_32) must zero
        EXACTLY the same fields as the detail path (_normalize_reloc_x86_32)
        — including prefixed instructions and the rare SIB/disp32 fallback."""
        from rebrew.matcher.scoring import _normalize_and_mnems_x86_32

        cases = [
            b"\xe8\x00\x00\x00\x00\xc3",  # call rel32
            b"\xa1\x34\x12\x00\x10\xc3",  # mov eax,[abs]
            b"\x68\x78\x56\x34\x10\xc3",  # push imm32
            b"\x0f\x85\x00\x00\x00\x00\xc3",  # jnz rel32
            b"\x64\x8b\x05\x34\x12\x00\x10\xc3",  # mov eax, fs:[abs] (prefixed)
            b"\x8d\x85\x34\x12\x00\x10\xc3",  # lea eax,[ebp+disp32] (fallback)
            b"\x8b\x84\x9d\x34\x12\x00\x10\xc3",  # mov eax,[ebp*4+disp32] (SIB)
            b"\x83\x3d\x34\x12\x00\x10\x01\xc3",  # cmp [abs],1
            b"\xff\x15\x34\x12\x00\x10\xc3",  # call [abs]
            b"\x55\x8b\xec\x83\xec\x10",  # non-reloc unchanged
        ]
        for code in cases:
            detail = _normalize_reloc_x86_32(code)
            fast, mnems = _normalize_and_mnems_x86_32(code)
            assert fast == detail, f"parity mismatch for {code.hex()}"
            assert mnems, f"no mnemonics extracted for {code.hex()}"


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
        assert score.reloc_score == 0.0
        assert score.mnemonic_score == 0.0
        assert score.total <= 0.0  # prologue_bonus can make it negative

    def test_different_code(self) -> None:
        target = b"\x55\x8b\xec\x83\xec\x10\xc3"
        cand = b"\x55\x8b\xec\x83\xec\x20\xc3"
        score = score_candidate(target, cand)
        assert score.byte_score > 0.0

    def test_different_length(self) -> None:
        target = b"\x55\x8b\xec\xc3"  # 4 bytes
        cand = b"\x55\x8b\xec\x83\xec\x10\xc3"  # 7 bytes
        score = score_candidate(target, cand)
        assert score.length_diff == 3
        assert score.total > 0.0  # length penalty must push total positive

    def test_with_reloc_offsets(self) -> None:
        # call near with different displacement — should score better with relocs
        target = b"\x55\x8b\xec\xe8\x01\x02\x03\x04\xc3"
        cand = b"\x55\x8b\xec\xe8\xff\xfe\xfd\xfc\xc3"
        score_no_reloc = score_candidate(target, cand)
        score_with_reloc = score_candidate(target, cand, reloc_offsets=[4])
        # With reloc offsets, reloc bytes are masked; total score should improve
        assert score_with_reloc.total <= score_no_reloc.total, (
            f"reloc masking should not worsen total score: "
            f"with={score_with_reloc.total}, without={score_no_reloc.total}"
        )

    def test_reloc_only_match_scores_zero(self) -> None:
        """A candidate whose ONLY diffs are at known reloc sites must score
        ~0 — the byte score excludes relocation bytes too, not just the
        reloc score.  Previously byte_score counted the 4 reloc bytes raw
        (floor of ~4000) so the GA/flag-sweep `exact: score < 0.1` gate
        never accepted a RELOC match and kept mutating a perfect candidate."""
        target = b"\x55\x8b\xec\xe8\x01\x02\x03\x04\xc3"
        cand = b"\x55\x8b\xec\xe8\xff\xfe\xfd\xfc\xc3"
        score = score_candidate(target, cand, reloc_offsets=[4])
        assert score.byte_score == 0.0
        assert score.reloc_score == 0.0
        assert score.mnemonic_score == 0.0
        assert score.total < 0.1  # the GA/sweep exact gate

    def test_non_reloc_diff_still_counts(self) -> None:
        """Masking must not hide REAL mismatches: a plain byte diff outside
        the reloc sites still raises byte_score."""
        target = b"\x55\x8b\xec\xe8\x01\x02\x03\x04\xc3"
        cand = b"\x55\x8b\xec\xe8\x01\x02\x03\x04\x90"  # ret -> nop
        score = score_candidate(target, cand, reloc_offsets=[4])
        assert score.byte_score > 0.0

    def test_empty(self) -> None:
        score = score_candidate(b"", b"")
        assert isinstance(score, Score)
        assert score.length_diff == 0
        assert score.byte_score == 0.0
        assert score.total <= 0.0

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
        assert score.total == pytest.approx(expected, abs=0.01)

    def test_negative_reloc_offsets_ignored(self) -> None:
        code = b"\x55\x8b\xec\xe8\x01\x02\x03\x04\xc3"
        score = score_candidate(code, code, reloc_offsets=[-1, 4])
        assert score.reloc_score == 0.0

    def test_deletion_not_rewarded(self) -> None:
        """A correct-length candidate with some wrong bytes MUST score better
        than a truncated candidate with no wrong bytes in the overlap.

        This is the core anti-deletion invariant: the GA should never be
        able to improve its score by simply removing valid C code.
        """
        # 100-byte target
        target = b"\x55\x8b\xec" + bytes(range(97))  # 100B
        # Candidate A: correct length, 10 wrong bytes
        cand_a = bytearray(target)
        for i in range(10):
            cand_a[50 + i] ^= 0xFF
        cand_a = bytes(cand_a)
        # Candidate B: only first 50 bytes (perfect match in overlap, but half deleted)
        cand_b = target[:50]

        score_a = score_candidate(target, cand_a)
        score_b = score_candidate(target, cand_b)
        # Full-length with errors MUST beat truncated
        assert score_a.total < score_b.total, (
            f"Deletion rewarded: full({score_a.total:.1f}) >= truncated({score_b.total:.1f})"
        )

    def test_missing_bytes_penalized(self) -> None:
        """byte_score must include penalty for missing bytes (len_diff)."""
        target = b"\x55\x8b\xec\x83\xec\x10\xc3"  # 7 bytes
        cand = target[:4]  # 4 bytes, 3 missing
        score = score_candidate(target, cand)
        # byte_score should be >= 3.0 (at least 3 missing bytes at weight 1.0 each)
        assert score.byte_score >= 3.0

    def test_mnemonic_coverage_penalty(self) -> None:
        """A very short candidate shouldn't get a good mnemonic score
        against a much longer target, even if all its mnemonics match."""
        # Long target: 20 NOPs + ret
        target = b"\x90" * 20 + b"\xc3"
        # Short candidate: 2 NOPs (subset of target mnemonics)
        cand = b"\x90" * 2
        score = score_candidate(target, cand)
        # mnemonic_score should be > 0 despite matching mnemonics, because
        # a very short candidate covers only a small fraction of the target.
        assert score.mnemonic_score > 0.0, (
            f"Short candidate mnemonic_score should be positive: {score.mnemonic_score:.1f}"
        )


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
        assert sim.total_insns >= 4  # push, mov, sub, ret

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


# -------------------------------------------------------------------------
# Fuzzing and Edge Cases
# -------------------------------------------------------------------------


class TestScoringFuzzing:
    def test_fuzz_random_noise(self) -> None:
        """Fuzz with completely random byte sequences of various lengths."""
        import random

        rng = random.Random(42)  # fixed seed for deterministic CI runs
        # 100 iterations of random lengths and bytes
        for _ in range(100):
            len1 = rng.randint(0, 200)
            len2 = rng.randint(0, 200)
            b1 = rng.randbytes(len1)
            b2 = rng.randbytes(len2)

            # Score and similarity must not crash on malformed/random bytes
            score = score_candidate(b1, b2)
            assert isinstance(score, Score)
            assert score.length_diff == abs(len1 - len2)
            assert score.length_diff >= 0
            assert score.byte_score >= 0.0
            assert isinstance(score.total, float)

            sim = structural_similarity(b1, b2)
            assert isinstance(sim, StructuralSimilarity)
            assert sim.total_insns >= 0
            assert 0.0 <= sim.mnemonic_match_ratio <= 1.0
            assert 0.0 <= sim.structural_ratio <= 1.0

    def test_extreme_edge_cases(self) -> None:
        """Test with extreme edge cases (all zeros, all 0xFF, size mismatches)."""
        cases = [
            b"",
            b"\x00" * 100,
            b"\x01" * 100,
            b"\xff" * 100,
            b"\x90" * 50,  # NOPs
            b"\xcc" * 20,  # INT 3
        ]

        for tgt in cases:
            for cand in cases:
                score = score_candidate(tgt, cand)
                assert isinstance(score, Score)
                assert score.length_diff >= 0
                assert score.byte_score >= 0.0
                assert isinstance(score.total, float)

                sim = structural_similarity(tgt, cand)
                assert isinstance(sim, StructuralSimilarity)
                assert sim.total_insns >= 0
                assert 0.0 <= sim.mnemonic_match_ratio <= 1.0
                assert 0.0 <= sim.structural_ratio <= 1.0

                if tgt == cand:
                    assert score.byte_score == 0.0
                    assert sim.structural == 0
                    assert score.length_diff == 0


def test_diff_csv_format_flag_accepted() -> None:
    """Verify --format csv option exists in rebrew diff CLI."""
    from typer.testing import CliRunner

    from rebrew.diff import app

    runner = CliRunner()
    help_output = runner.invoke(app, ["--help"]).stdout
    assert "--format" in help_output


class TestPrecomputedTarget:
    """The GA hot path precomputes target normalization + mnemonics once per
    function; the _pre_* kwargs must produce byte-identical scores."""

    def test_precompute_target_shape(self) -> None:
        code = bytes(range(0x90, 0x90 + 64))  # NOPs + count
        norm, mnems = precompute_target(code)
        assert norm == _normalize_reloc_x86_32(code)
        assert isinstance(mnems, list)
        assert len(mnems) >= 1

    def test_precomputed_equals_fresh_no_relocs(self) -> None:
        target = b"\x55\x8b\xec\x83\xec\x10\xa1\x00\x00\x40\x00\x5d\xc3"
        cand = b"\x55\x8b\xec\x83\xec\x10\xa1\x10\x00\x40\x00\x5d\xc3"
        norm, mnems = precompute_target(target)
        fresh = score_candidate(target, cand, reloc_offsets=None)
        hot = score_candidate(
            target,
            cand,
            reloc_offsets=None,
            _pre_norm_target=norm,
            _pre_target_mnems=mnems,
        )
        assert hot.total == fresh.total
        assert hot.mnemonic_score == fresh.mnemonic_score

    def test_merged_normalize_and_mnems_equals_separate(self) -> None:
        """The hot-path merge (_normalize_and_mnems_x86_32) must produce the
        same bytes as _normalize_reloc_x86_32 and the same mnemonics as a
        plain disassembly — one detail pass replacing two."""
        from rebrew.matcher.scoring import _normalize_and_mnems_x86_32

        # call rel32, mov abs32, push imm32-lookalike, cmp [abs32],imm8
        code = bytes.fromhex("e8 00000000 a1 00004000 68 00100000 833d 00004000 01 c3")
        norm, mnems = _normalize_and_mnems_x86_32(code)
        assert norm == _normalize_reloc_x86_32(code)
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        assert mnems == [i.mnemonic for i in md.disasm(code, 0)]
        assert mnems  # non-empty

    def test_merged_score_matches_precomputed(self) -> None:
        """score_candidate's merged fallback (no relocs, no precompute) must
        score identically to the precomputed hot path."""
        target = bytes.fromhex("558bec83ec10e800000000a1000040005dc3")
        cand = bytes.fromhex("558bec83ec10e805000000a1100040005dc3")
        norm, mnems = precompute_target(target)
        fresh = score_candidate(target, cand, reloc_offsets=None)
        hot = score_candidate(
            target, cand, reloc_offsets=None, _pre_norm_target=norm, _pre_target_mnems=mnems
        )
        assert fresh.total == hot.total
        assert fresh.reloc_score == hot.reloc_score
        assert fresh.mnemonic_score == hot.mnemonic_score

    def test_precomputed_ignored_in_reloc_path(self) -> None:
        """With explicit reloc offsets the _pre_* kwargs are not used."""
        target = b"\x55\x8b\xec\xa1\x00\x00\x40\x00\x5d\xc3"
        cand = b"\x55\x8b\xec\xa1\xff\xff\x40\x00\x5d\xc3"
        relocs = [4]
        norm, mnems = precompute_target(target)
        fresh = score_candidate(target, cand, reloc_offsets=relocs)
        hot = score_candidate(
            target,
            cand,
            reloc_offsets=relocs,
            _pre_norm_target=norm,
            _pre_target_mnems=mnems,
        )
        assert hot.total == fresh.total


class TestScoreFastPaths:
    """Identical-bytes and mnemonic-equality fast paths in score_candidate.

    Both must produce exactly the scores the full computation would — the
    fast paths only skip work, never approximate.
    """

    def test_identical_bytes_zero_metrics_plus_prologue(self) -> None:
        from rebrew.matcher.scoring import _PROLOGUE_BONUS, _PROLOGUE_LEN, Score, score_candidate

        target = b"\x55\x8b\xec" + b"\x90" * 64  # prologue + body
        relocs = {8: "x", 16: "y"}
        s = score_candidate(target, target, relocs)
        assert isinstance(s, Score)
        assert s.length_diff == 0
        assert s.byte_score == 0.0
        assert s.reloc_score == 0.0
        assert s.mnemonic_score == 0.0
        expected_bonus = _PROLOGUE_BONUS if len(target) >= _PROLOGUE_LEN else 0.0
        assert s.prologue_bonus == expected_bonus
        assert s.total == expected_bonus

    def test_identical_bytes_short_function(self) -> None:
        from rebrew.matcher.scoring import score_candidate

        target = b"\x55\x8b\xec\xc3"  # 4 bytes < _PROLOGUE_LEN
        s = score_candidate(target, target, {1: "x"})
        assert s.prologue_bonus == 0.0
        assert s.total == 0.0

    def test_mnemonic_equal_immediates_only(self) -> None:
        """Different immediates → same mnemonics → mnemonic_score must be 0.0,
        exactly what the SequenceMatcher walk yields on equal sequences."""
        import difflib

        from rebrew.matcher.scoring import _get_cs, score_candidate

        # Two functions differing only in immediate bytes.
        a = b"\x55\x8b\xec\xb8\x10\x00\x00\x00\x5d\xc3"  # mov eax, 0x10
        b = b"\x55\x8b\xec\xb8\x20\x00\x00\x00\x5d\xc3"  # mov eax, 0x20
        s = score_candidate(a, b, {})
        assert s.mnemonic_score == 0.0

        # Reference: SequenceMatcher on the mnemonic lists (identical).
        md = _get_cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        mnems_a = [i.mnemonic for i in md.disasm(a, 0x1000)]
        mnems_b = [i.mnemonic for i in md.disasm(b, 0x1000)]
        assert mnems_a == mnems_b
        opcodes = difflib.SequenceMatcher(None, mnems_a, mnems_b).get_opcodes()
        total_diffed = sum(
            max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in opcodes if tag != "equal"
        )
        assert total_diffed == 0

    def test_mnemonic_differing_still_diffed(self) -> None:
        """The fast path must not fire when mnemonics actually differ."""
        from rebrew.matcher.scoring import score_candidate

        a = b"\x55\x8b\xec\xb8\x10\x00\x00\x00\x5d\xc3"  # mov eax, 0x10
        c = b"\x55\x8b\xec\x33\xc0\x5d\xc3"  # xor eax, eax (shorter)
        s = score_candidate(a, c, {})
        assert s.mnemonic_score > 0.0  # real diff still penalized


# -------------------------------------------------------------------------
# code_similarity (optional `resembl` scoring core)
# -------------------------------------------------------------------------


class TestCodeSimilarity:
    """code_similarity delegates to refinements of the `resembl` scoring core.

    Skipped when the optional ``resembl`` dependency (the ``[similarity]``
    extra) is not installed — plain rebrew installs must stay green.
    """

    # mov eax,[ebp+8]; add eax,1 (the base function under test).
    FUNC_A = bytes.fromhex("55 8b ec 8b 45 08 83 c0 01 5d c3")
    # Same logic, registers renamed: mov ecx,[ebp+8]; add ecx,1.
    FUNC_REG = bytes.fromhex("55 8b ec 8b 4d 08 83 c1 01 5d c3")
    # Same logic, immediate changed: add eax,100 (0x64) instead of add eax,1.
    FUNC_IMM = bytes.fromhex("55 8b ec 8b 45 08 83 c0 64 5d c3")
    # Genuinely different function body (no shared prologue/epilogue shape).
    FUNC_UNRELATED = bytes.fromhex("8b 45 08 3d 78 56 34 12 0f 85 05 00 00 00 c3")

    @pytest.fixture(autouse=True)
    def _skip_if_no_resembl(self) -> None:
        import importlib.util

        if importlib.util.find_spec("resembl") is None:
            pytest.skip("optional `resembl` dependency not installed")

    def test_identical_is_100(self) -> None:
        from rebrew.matcher.scoring import code_similarity

        assert code_similarity(TestCodeSimilarity.FUNC_A, TestCodeSimilarity.FUNC_A) == 100.0

    def test_register_insensitive(self) -> None:
        """Register allocation differences must not tank the score."""
        from rebrew.matcher.scoring import code_similarity

        s = code_similarity(TestCodeSimilarity.FUNC_A, TestCodeSimilarity.FUNC_REG)
        assert s >= 85.0

    def test_immediate_insensitive(self) -> None:
        """Immediate-value differences (e.g. different constants) stay high."""
        from rebrew.matcher.scoring import code_similarity

        s = code_similarity(TestCodeSimilarity.FUNC_A, TestCodeSimilarity.FUNC_IMM)
        assert s >= 85.0

    def test_unrelated_is_clearly_lower(self) -> None:
        """Two genuinely different functions score meaningfully below the
        near-identical register/immediate variants."""
        from rebrew.matcher.scoring import code_similarity

        close = code_similarity(TestCodeSimilarity.FUNC_A, TestCodeSimilarity.FUNC_REG)
        far = code_similarity(TestCodeSimilarity.FUNC_A, TestCodeSimilarity.FUNC_UNRELATED)
        assert far < close - 30.0
        assert far < 90.0
