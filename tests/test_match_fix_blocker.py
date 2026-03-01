"""Tests for rebrew.match --fix-blocker annotation writing and classify_blockers."""

from pathlib import Path
from typing import Any

from rebrew.annotation import parse_c_file, update_annotation_key
from rebrew.match import classify_blockers

# ---------------------------------------------------------------------------
# classify_blockers — pattern detection
# ---------------------------------------------------------------------------


def _make_insn(match: str, target_asm: str, cand_asm: str) -> dict[str, Any]:
    return {
        "match": match,
        "target": {"disasm": target_asm, "bytes": ""},
        "candidate": {"disasm": cand_asm, "bytes": ""},
    }


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
# --fix-blocker annotation integration
# ---------------------------------------------------------------------------

_SOURCE_TEMPLATE = """\
// FUNCTION: TARGET 0x{va:08x}
// STATUS: MATCHING
// SYMBOL: _test_func
// SIZE: 10

int test_func(void) {{
    return 0;
}}
"""


def _make_source(tmp_path: Path, va: int = 0x10001000) -> Path:
    src = tmp_path / "test_func.c"
    src.write_text(_SOURCE_TEMPLATE.format(va=va), encoding="utf-8")
    return src


class TestFixBlockerAnnotationWrite:
    def test_writes_blocker_annotation(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        va = 0x10001000
        blocker_text = "register allocation, jump condition swap"
        update_annotation_key(src, va, "BLOCKER", blocker_text)
        update_annotation_key(src, va, "BLOCKER_DELTA", "3")

        anno = parse_c_file(src)
        assert anno is not None
        assert anno.blocker == blocker_text
        assert anno.blocker_delta == 3

    def test_writes_then_clears_blocker(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_annotation_key

        src = _make_source(tmp_path)
        va = 0x10001000
        update_annotation_key(src, va, "BLOCKER", "register allocation")
        update_annotation_key(src, va, "BLOCKER_DELTA", "5")

        anno = parse_c_file(src)
        assert anno is not None
        assert anno.blocker == "register allocation"

        remove_annotation_key(src, va, "BLOCKER")
        remove_annotation_key(src, va, "BLOCKER_DELTA")

        anno2 = parse_c_file(src)
        assert anno2 is not None
        assert not anno2.blocker
        assert anno2.blocker_delta is None

    def test_overwrites_existing_blocker(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        va = 0x10001000
        update_annotation_key(src, va, "BLOCKER", "old blocker text")
        update_annotation_key(
            src, va, "BLOCKER", "register allocation, loop rotation / branch layout"
        )

        anno = parse_c_file(src)
        assert anno is not None
        assert anno.blocker == "register allocation, loop rotation / branch layout"

    def test_delta_calculation(self) -> None:
        target = b"\x55\x8b\xec\x33\xc0\xc3"
        obj = b"\x55\x8b\xec\x31\xc0\xc3"
        delta = sum(1 for a, b in zip(target, obj, strict=False) if a != b) + abs(
            len(target) - len(obj)
        )
        assert delta == 1

    def test_delta_with_size_difference(self) -> None:
        target = b"\x55\x8b\xec\x33\xc0\xc3"
        obj = b"\x55\x8b\xec\xc3"
        delta = sum(1 for a, b in zip(target, obj, strict=False) if a != b) + abs(
            len(target) - len(obj)
        )
        assert delta == 3


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
