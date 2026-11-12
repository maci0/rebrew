"""Cross-target data operand pairing (``rebrew data pair``)."""

import capstone
import pytest

from rebrew.cast_rewrite import declare_externs
from rebrew.data_pair import OperandPair, pair_data_operands, plan_pairs

X86 = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def _in_data(va: int) -> bool:
    return 0x500000 <= va < 0x700000


def _section(_va: int) -> str:
    return ".data"


class TestPairDataOperands:
    @pytest.mark.parametrize("opcode", ["e8", "e9"])
    def test_external_destinations_are_reported(self, opcode: str) -> None:
        a = bytes.fromhex(opcode + "fb1f0000")
        b = bytes.fromhex(opcode + "fb2f0000")
        pairs, calls = pair_data_operands(a, 0x1000, b, 0x2000, _in_data, _in_data, *X86)
        assert pairs == []
        assert calls == [OperandPair(0, 0x3000, 0x5000)]

    def test_changed_internal_branch_is_refused(self) -> None:
        with pytest.raises(ValueError, match="control flow"):
            pair_data_operands(
                bytes.fromhex("75009090"),
                0x1000,
                bytes.fromhex("75019090"),
                0x2000,
                _in_data,
                _in_data,
                *X86,
            )

    def test_absolute_loads_and_stores_pair_by_position(self) -> None:
        # mov eax, [A]; push eax; call rel32; mov dword [A], -1
        a = bytes.fromhex("a170516700 50 e800000000 c70570516700ffffffff".replace(" ", ""))
        b = bytes.fromhex("a1f8105f00 50 e800000000 c705f8105f00ffffffff".replace(" ", ""))
        pairs, calls = pair_data_operands(a, 0x402320, b, 0x401E50, _in_data, _in_data, *X86)
        assert pairs == [OperandPair(0, 0x675170, 0x5F10F8), OperandPair(11, 0x675170, 0x5F10F8)]
        assert calls == []

    def test_one_sided_data_address_is_refused(self) -> None:
        a = bytes.fromhex("a170516700")
        b = bytes.fromhex("a1f8105f00")
        with pytest.raises(ValueError, match="non-data"):
            pair_data_operands(a, 0x1000, b, 0x2000, _in_data, lambda va: False, *X86)

    def test_different_code_is_refused(self) -> None:
        a = bytes.fromhex("a170516700")
        b = bytes.fromhex("8b0df8105f00")
        with pytest.raises(ValueError, match="differ|different"):
            pair_data_operands(a, 0x1000, b, 0x2000, _in_data, _in_data, *X86)


class TestPlanPairs:
    def test_named_side_creates_the_missing_row(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x675170, 0x5F10F8)],
            {},
            {0x5F10F8: {"name": "g_675170", "size": 4, "type": "int", "kind": "GLOBAL"}},
            _section,
            _section,
        )
        assert plan == [
            {
                "offset": 0,
                "a": "0x00675170",
                "b": "0x005f10f8",
                "action": "create-a",
                "name": "g_675170",
                "size": 4,
                "type": "int",
                "kind": "GLOBAL",
                "section": ".data",
                "a_row": "0x00675170",
                "b_row": "0x005f10f8",
            }
        ]

    def test_interior_operand_creates_the_row_at_the_paired_start(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x675178, 0x5F1100)],
            {},
            {0x5F10F8: {"name": "g_table", "size": 16}},
            _section,
            _section,
        )
        assert (plan[0]["action"], plan[0]["a_row"]) == ("create-a", "0x00675170")

    def test_different_names_are_a_conflict(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x675170, 0x5F10F8)],
            {0x675170: {"name": "g_one", "size": 4}},
            {0x5F10F8: {"name": "g_two", "size": 4}},
            _section,
            _section,
        )
        assert plan[0]["action"] == "conflict"

    def test_unnamed_on_both_sides_is_reported(self) -> None:
        plan = plan_pairs([OperandPair(0, 0x675170, 0x5F10F8)], {}, {}, _section, _section)
        assert plan[0]["action"] == "unnamed"


class TestDeclareExterns:
    def test_empty_line_hosts_declarations_without_moving_lines(self) -> None:
        text = '\n#include "x.h"\n\nvoid f(void)\n{\n}\n'
        out, declared = declare_externs(text, ["g_675170"])
        assert declared == ["g_675170"]
        assert out.splitlines()[0] == "extern char g_675170[];"
        assert len(out.splitlines()) == len(text.splitlines())
