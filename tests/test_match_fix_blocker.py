"""Tests for rebrew.diff classify_blockers and blocker delta calculations."""

from typing import Any

from rebrew.diff import classify_blockers

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_insn(match: str, target_asm: str, cand_asm: str) -> dict[str, Any]:
    return {
        "match": match,
        "target": {"disasm": target_asm, "bytes": ""},
        "candidate": {"disasm": cand_asm, "bytes": ""},
    }


# ---------------------------------------------------------------------------
# classify_blockers — pattern detection
# ---------------------------------------------------------------------------


class TestClassifyBlockers:
    def test_register_allocation(self) -> None:
        summary = {"instructions": [_make_insn("RR", "mov eax, ecx", "mov edx, ecx")]}
        assert "register allocation" in classify_blockers(summary)

    def test_jump_condition_swap(self) -> None:
        summary = {"instructions": [_make_insn("**", "jne 0x1234", "je 0x1234")]}
        assert "jump condition swap" in classify_blockers(summary)

    def test_loop_rotation(self) -> None:
        summary = {"instructions": [_make_insn("**", "jmp 0x1234", "je 0x1234")]}
        assert "loop rotation / branch layout" in classify_blockers(summary)

    def test_zero_extend_pattern(self) -> None:
        summary = {"instructions": [_make_insn("**", "xor eax, eax", "mov eax, 0")]}
        assert "zero-extend pattern (xor vs mov)" in classify_blockers(summary)

    def test_comparison_direction_swap(self) -> None:
        summary = {"instructions": [_make_insn("**", "cmp eax, ecx", "cmp ecx, eax")]}
        assert "comparison direction swap" in classify_blockers(summary)

    def test_stack_frame_choice(self) -> None:
        summary = {"instructions": [_make_insn("**", "push ebp", "sub esp, 4")]}
        assert "stack frame choice (push vs sub esp)" in classify_blockers(summary)

    def test_instruction_folding(self) -> None:
        summary = {"instructions": [_make_insn("**", "lea eax, [ecx+4]", "mov eax, ecx")]}
        assert "instruction folding (lea vs mov)" in classify_blockers(summary)

    def test_exact_match_no_blockers(self) -> None:
        summary = {"instructions": [_make_insn("==", "mov eax, 1", "mov eax, 1")]}
        assert classify_blockers(summary) == []

    def test_empty_summary(self) -> None:
        assert classify_blockers({}) == []
        assert classify_blockers({"instructions": []}) == []

    def test_multiple_blockers_sorted(self) -> None:
        summary = {
            "instructions": [
                _make_insn("RR", "mov eax, ecx", "mov edx, ecx"),
                _make_insn("**", "jne 0x10", "je 0x10"),
            ]
        }
        result = classify_blockers(summary)
        assert len(result) >= 2
        assert result == sorted(result)

    def test_deduplicates_same_type(self) -> None:
        summary = {
            "instructions": [
                _make_insn("RR", "mov eax, ecx", "mov edx, ecx"),
                _make_insn("RR", "add eax, 1", "add edx, 1"),
            ]
        }
        result = classify_blockers(summary)
        assert result.count("register allocation") == 1


# ---------------------------------------------------------------------------
# classify_blockers — edge cases
# ---------------------------------------------------------------------------


class TestClassifyBlockersEdgeCases:
    def test_non_dict_instructions_ignored(self) -> None:
        summary = {"instructions": ["not a dict", 42, None]}
        assert classify_blockers(summary) == []

    def test_non_list_instructions_ignored(self) -> None:
        summary = {"instructions": "not a list"}
        assert classify_blockers(summary) == []

    def test_missing_disasm_fields(self) -> None:
        summary = {
            "instructions": [
                {"match": "**", "target": {}, "candidate": {}},
            ]
        }
        assert classify_blockers(summary) == []

    def test_exact_match_lines_skipped(self) -> None:
        summary = {
            "instructions": [
                _make_insn("==", "mov eax, 1", "mov ecx, 1"),
                _make_insn("RR", "add eax, 1", "add edx, 1"),
            ]
        }
        result = classify_blockers(summary)
        assert "register allocation" in result
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Blocker delta calculation (pure logic, no I/O)
# ---------------------------------------------------------------------------


class TestBlockerDeltaCalculation:
    def test_single_byte_diff(self) -> None:
        target = b"\x55\x8b\xec\x33\xc0\xc3"
        obj = b"\x55\x8b\xec\x31\xc0\xc3"
        delta = sum(1 for a, b in zip(target, obj, strict=False) if a != b) + abs(
            len(target) - len(obj)
        )
        assert delta == 1

    def test_size_difference_adds_to_delta(self) -> None:
        target = b"\x55\x8b\xec\x33\xc0\xc3"
        obj = b"\x55\x8b\xec\xc3"
        delta = sum(1 for a, b in zip(target, obj, strict=False) if a != b) + abs(
            len(target) - len(obj)
        )
        assert delta == 3
