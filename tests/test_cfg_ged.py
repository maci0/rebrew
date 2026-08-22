"""Tests for cfg_ged.py — CFG structural similarity (DecBench GED-inspired)."""

import capstone

from rebrew.cfg_ged import build_cfg, cfg_similarity

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
