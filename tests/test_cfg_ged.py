"""Tests for cfg_ged.py — CFG structural similarity (DecBench GED-inspired)."""

import capstone
import pytest

from rebrew.cfg_ged import build_cfg, build_cfg_view, cfg_similarity

# cmp eax,1; je +7; mov eax,1; jmp +5; mov eax,2; ret  — 3 blocks, 3 edges
IFELSE = bytes.fromhex("83 f8 01 74 07 b8 01 00 00 00 eb 05 b8 02 00 00 00 c3")
# mov ecx,4; dec ecx; jne -3; ret  — loop with a back-edge
LOOP = bytes.fromhex("b9 04 00 00 00 49 75 fd c3")
# mov eax,1; add eax,1; ret  — straight-line flow, 1 block
STRAIGHT = bytes.fromhex("b8 01 00 00 00 83 c0 01 c3")


class TestBuildCfg:
    def test_ifelse_blocks_and_edges(self) -> None:
        cfg = build_cfg(IFELSE, 0x1000)
        assert len(cfg["blocks"]) == 3
        # cmp/je block, mov/jmp block, mov/ret block
        assert cfg["blocks"][0][2] == ["cmp", "je"]
        assert cfg["blocks"][1][2] == ["mov", "jmp"]
        assert cfg["blocks"][2][2] == ["mov", "ret"]
        # je target (0->2), je fallthrough (0->1), jmp target (1->2)
        assert set(cfg["edges"]) == {(0, 2), (0, 1), (1, 2)}

    def test_loop_has_back_edge(self) -> None:
        cfg = build_cfg(LOOP, 0x1000)
        assert len(cfg["blocks"]) == 2
        assert (0, 0) in cfg["edges"]  # back-edge
        assert (0, 1) in cfg["edges"]  # fallthrough to ret

    def test_straight_line_single_block(self) -> None:
        cfg = build_cfg(STRAIGHT, 0x1000)
        assert len(cfg["blocks"]) == 1
        assert cfg["edges"] == []

    def test_empty_code(self) -> None:
        cfg = build_cfg(b"", 0x1000)
        assert cfg == {"blocks": [], "edges": []}

    def test_garbage_does_not_raise(self) -> None:
        cfg = build_cfg(b"\xff\xff\xff\xff\xff", 0x1000)
        assert isinstance(cfg["blocks"], list)
        assert isinstance(cfg["edges"], list)

    def test_jecxz_has_target_and_fallthrough_edges(self) -> None:
        """jecxz/jcxz are conditional: both a branch target and a fallthrough.

        They are block terminators, so if they are not also treated as
        conditional jumps the block yields no edges at all.
        """
        # xor ecx,ecx; jecxz +2 (target offset 7); ret; nop; ret
        code = bytes.fromhex("31 c9 67 e3 02 c3 90 c3")
        cfg = build_cfg(code, 0x1000)
        assert set(cfg["edges"]) == {(0, 1), (0, 2)}

    def test_block_tuple_shape_unchanged(self) -> None:
        """build_cfg keeps (start_offset, insn_count, mnemonics) per block."""
        cfg = build_cfg(IFELSE, 0x1000)
        assert cfg["blocks"][1] == (5, 2, ["mov", "jmp"])
        assert cfg["edges"] == [(0, 2), (0, 1), (1, 2)]


class TestBuildCfgView:
    def test_ifelse_absolute_vas_sizes_and_labels(self) -> None:
        view = build_cfg_view(IFELSE, 0x1000)
        assert view["blocks"] == [
            {
                "va": 0x1000,
                "size": 5,
                "instruction_count": 2,
                "first": "cmp eax, 1",
                "last": "je 0x100c",
            },
            {
                "va": 0x1005,
                "size": 7,
                "instruction_count": 2,
                "first": "mov eax, 1",
                "last": "jmp 0x1011",
            },
            {
                "va": 0x100C,
                "size": 6,
                "instruction_count": 2,
                "first": "mov eax, 2",
                "last": "ret",
            },
        ]
        assert view["edges"] == [
            {"from": 0x1000, "to": 0x100C, "back_edge": False},
            {"from": 0x1000, "to": 0x1005, "back_edge": False},
            {"from": 0x1005, "to": 0x100C, "back_edge": False},
        ]
        assert view["block_count"] == 3
        assert view["block_total"] == 3
        assert view["truncated"] is False
        assert view["note"] is None

    def test_loop_self_edge_is_a_back_edge(self) -> None:
        view = build_cfg_view(LOOP, 0x1000)
        assert [b["va"] for b in view["blocks"]] == [0x1000, 0x1008]
        assert {"from": 0x1000, "to": 0x1000, "back_edge": True} in view["edges"]
        assert {"from": 0x1000, "to": 0x1008, "back_edge": False} in view["edges"]

    def test_straight_line_single_block(self) -> None:
        view = build_cfg_view(STRAIGHT, 0x1000)
        assert len(view["blocks"]) == 1
        assert view["blocks"][0]["instruction_count"] == 3
        assert view["blocks"][0]["size"] == len(STRAIGHT)
        assert view["edges"] == []
        assert view["note"] is None

    def test_empty_code_notes_no_instructions(self) -> None:
        view = build_cfg_view(b"", 0x1000)
        assert view["blocks"] == []
        assert view["edges"] == []
        assert view["note"] == "no decodable instructions"

    def test_garbage_does_not_raise(self) -> None:
        view = build_cfg_view(b"\xff\xff\xff\xff\xff", 0x1000)
        assert view["blocks"] == []
        assert view["note"] == "no decodable instructions"

    def test_block_cap_states_true_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.cfg_ged.MAX_CFG_BLOCKS_PER_FUNCTION", 2)
        view = build_cfg_view(IFELSE, 0x1000)
        assert view["block_cap"] == 2
        assert view["block_total"] == 3
        assert view["block_count"] == 2
        assert view["truncated"] is True
        assert [b["va"] for b in view["blocks"]] == [0x1000, 0x1005]
        # An edge with an endpoint past the cap is dropped: the returned graph
        # never references a block the payload does not contain.
        kept = {b["va"] for b in view["blocks"]}
        assert view["edges"] == [{"from": 0x1000, "to": 0x1005, "back_edge": False}]
        assert all(e["from"] in kept and e["to"] in kept for e in view["edges"])


class TestCfgSimilarity:
    def test_identical_is_100(self) -> None:
        r = cfg_similarity(IFELSE, IFELSE, 0x1000)
        assert r["overall"] == 100.0
        assert r["node_sim"] == 100.0
        assert r["edge_sim"] == 100.0

    def test_different_structures_score_lower(self) -> None:
        same = cfg_similarity(IFELSE, IFELSE, 0x1000)["overall"]
        other = cfg_similarity(IFELSE, LOOP, 0x1000)["overall"]
        assert other < same

    def test_loop_vs_straight_low(self) -> None:
        r = cfg_similarity(LOOP, STRAIGHT, 0x1000)
        assert r["overall"] < 30.0
        assert r["edge_sim"] == 0.0  # the back-edge cannot be matched

    def test_register_swap_preserves_structure(self) -> None:
        # Same structure with different registers (mov eax vs mov ecx in the
        # ifelse bodies) — the CFG shape must still score high.
        variant = bytes.fromhex("83 f8 01 74 07 b9 01 00 00 00 eb 05 b9 02 00 00 00 c3")
        r = cfg_similarity(IFELSE, variant, 0x1000)
        assert r["overall"] == 100.0  # mnemonics identical → node match; edges identical

    def test_degenerate_returns_zero(self) -> None:
        r = cfg_similarity(b"", IFELSE, 0x1000)
        assert r["overall"] == 0.0
        r2 = cfg_similarity(IFELSE, b"\xff\xff", 0x1000)
        assert r2["overall"] == 0.0

    def test_x86_16_mode(self) -> None:
        # 16-bit: push bp; mov bp,sp; cmp ax,1; je +2; mov ax,2; leave; ret
        code16 = bytes.fromhex("55 89 e5 3d 01 00 74 02 b8 02 00 c9 c3")
        r = cfg_similarity(code16, code16, 0x1000, capstone.CS_MODE_16)
        assert r["overall"] == 100.0
