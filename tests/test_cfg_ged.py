"""Tests for cfg_ged.py — CFG structural similarity (DecBench GED-inspired)."""

from typing import Any

import capstone
import pytest

from rebrew.binary.cfg_ged import build_cfg, build_cfg_view, cfg_similarity

# cmp eax,1; je +7; mov eax,1; jmp +5 (onto the ret); mov eax,2; ret — 4 blocks, 4 edges
IFELSE = bytes.fromhex("83 f8 01 74 07 b8 01 00 00 00 eb 05 b8 02 00 00 00 c3")
# mov ecx,4; dec ecx; jne -3; ret  — loop with a back-edge; the jne target
# (dec ecx) starts its own block
LOOP = bytes.fromhex("b9 04 00 00 00 49 75 fd c3")
# mov eax,1; add eax,1; ret  — straight-line flow, 1 block
STRAIGHT = bytes.fromhex("b8 01 00 00 00 83 c0 01 c3")

#: zlib 1.1.3's ``inflate`` as MSVC 6 compiled it into guild-rebrew's
#: server.dll (0x100058d0, 1072 bytes; zlib license).  ``switch
#: (z->state->mode)`` is ``cmp ecx, 0xd; ja 0x10005ca0; jmp dword ptr
#: [ecx*4 + 0x10005cc8]``, and the 14-entry table fills the last 56 bytes.
INFLATE_VA = 0x100058D0
INFLATE = bytes.fromhex(
    "5355568b74241085f6570f84c00300008b461c85c00f84b5030000833e000f84"
    "ac0300008b54241833db83fa04bffbffffff0f95c34bbd0500000083e3fb895c"
    "24188b461c8b0883f90d0f8780030000ff248dc85c00108b4e0485c90f846502"
    "00004933d2894e048b4e08418bfb894e088b0e8a118950048b461c8b168b4804"
    "83e10f4280f90889167415c7000d0000008b561cc746188c750210896a04eba2"
    "8b48048b5010c1e90483c1083bca7618c7000d0000008b561cc7461878750210"
    "896a04e97affffffc700010000008b460485c00f84ee0100004833c98946048b"
    "4608408bfb8b5e1c8946088b0633d2bd1f0000008a084089068b4304c1e00803"
    "c1f7f585d27421c7030d0000008b461c8b5c2418bd05000000c7461860750210"
    "896804e91afffffff6c1200f857d010000c703070000008b5c2418bd05000000"
    "e9fdfeffff8b4814575651e820e4ffff8bf883c40c83fffd75188b561cc7020d"
    "0000008b461cc7400400000000e9d0feffff85ff75028bfb83ff010f85460100"
    "008b461c8bfb8b50148d4804515652e8bce2ffff8b461c83c40c8b480c85c974"
    "0bc7000c000000e996feffffc700080000008b460485c00f840a010000488b56"
    "1c8946048b46084033c98946088b068bfb8a08c1e118894a088b064089068b46"
    "1cc700090000008b460485c00f84d50000008b56088b0e48428956088946048b"
    "461c33d28a118bfb8b4808c1e21003ca8948088b064089068b461cc7000a0000"
    "008b460485c00f849b0000008b56088b0e48428956088946048b461c33d28a11"
    "8bfb8b4808c1e20803ca8948088b064089068b461cc7000b0000008b460485c0"
    "74658b56088b0e48428946048b461c89560833d28a118b480803ca8bfb894808"
    "8b064089068b461c8b48048b50083bca0f8444010000c7000d0000008b561cc7"
    "461848750210896a04e994fdffff8b461c8b5c2418bd05000000c70002000000"
    "8b460485c075078bc75f5e5d5bc38b56088b0e484289560833d28946048a118b"
    "461c8bfbc1e2188950088b068b4e1c408906c701030000008b460485c075078b"
    "c75f5e5d5bc38b16488946048b46084033c98946088b461c8a0a8bfb8b5008c1"
    "e11003d18950088b068b561c408906c702040000008b460485c075078bc75f5e"
    "5d5bc38b0e488946048b46084033d28946088b461c8a118bfb8b4808c1e20803"
    "ca8948088b064089068b461c89288b460485c075078bc75f5e5d5bc38b56088b"
    "0e48428946048b461c89560833d28a118b480803ca5f8948088b064089068b46"
    "1c8b4808894e305ec700060000005db8020000005bc38b561cc7020d0000008b"
    "461cc7461838750210c74004000000005f5e5db8feffffff5bc38b4e1cc7010c"
    "0000005f5e5db8010000005bc35f5e5db8fdffffff5bc390275900109e590010"
    "905b0010c85b0010055c00103e5c0010865c0010155a0010825a0010b75a0010"
    "f15a00102b5b0010b35c0010bd5c0010"
)
INFLATE_JMP_VA = 0x10005920
INFLATE_DEFAULT_VA = 0x10005CA0
INFLATE_TABLE_VA = 0x10005CC8
#: The table's entries in case order, read off the bytes at INFLATE_TABLE_VA.
INFLATE_CASES = [
    0x10005927,
    0x1000599E,
    0x10005B90,
    0x10005BC8,
    0x10005C05,
    0x10005C3E,
    0x10005C86,
    0x10005A15,
    0x10005A82,
    0x10005AB7,
    0x10005AF1,
    0x10005B2B,
    0x10005CB3,
    0x10005CBD,
]

#: MSVC 6's two-level switch at 0x1000: ``cmp eax, 5; ja default; xor ecx,
#: ecx; mov cl, byte ptr [eax + 0x1030]; jmp dword ptr [ecx*4 + 0x1024]``,
#: cases at 0x1014 and 0x101a, default at 0x1020, a nop, the 3-entry address
#: table at 0x1024 and the 6-byte index table (0 1 1 2 0 2) at 0x1030.
TWO_LEVEL = bytes.fromhex(
    "83f805 771b 33c9 8a8830100000 ff248d24100000"
    "b801000000c3 b802000000c3 33c0c3 90"
    "14100000 1a100000 20100000 000101020002"
)
#: The same switch loading the index with ``movzx ecx, byte ptr [eax +
#: 0x1030]``: cases at 0x1013 and 0x1019, default at 0x101f, two nops.
TWO_LEVEL_MOVZX = bytes.fromhex(
    "83f805 771a 0fb68830100000 ff248d24100000"
    "b801000000c3 b802000000c3 33c0c3 9090"
    "13100000 19100000 1f100000 000101020002"
)


class TestBuildCfg:
    def test_ifelse_blocks_and_edges(self) -> None:
        cfg = build_cfg(IFELSE, 0x1000)
        assert [b[2] for b in cfg["blocks"]] == [["cmp", "je"], ["mov", "jmp"], ["mov"], ["ret"]]
        # je target (0->2), je fallthrough (0->1), jmp target (1->3), else flows into ret (2->3)
        assert cfg["edges"] == [(0, 2), (0, 1), (1, 3), (2, 3)]

    def test_loop_has_back_edge(self) -> None:
        cfg = build_cfg(LOOP, 0x1000)
        assert [b[2] for b in cfg["blocks"]] == [["mov"], ["dec", "jne"], ["ret"]]
        assert (1, 1) in cfg["edges"]  # back-edge onto the loop head, not the pre-header
        assert (1, 2) in cfg["edges"]  # fallthrough to ret
        assert (0, 1) in cfg["edges"]  # pre-header flows into the loop head

    def test_straight_line_single_block(self) -> None:
        cfg = build_cfg(STRAIGHT, 0x1000)
        assert len(cfg["blocks"]) == 1
        assert cfg["edges"] == []

    def test_empty_code(self) -> None:
        cfg = build_cfg(b"", 0x1000)
        assert cfg == {"blocks": [], "edges": []}

    def test_garbage_does_not_raise(self) -> None:
        cfg = build_cfg(b"\xff\xff\xff\xff\xff", 0x1000)
        assert cfg == {"blocks": [], "edges": []}

    def test_jecxz_has_target_and_fallthrough_edges(self) -> None:
        """jecxz/jcxz are conditional: both a branch target and a fallthrough.

        They are block terminators, so if they are not also treated as
        conditional jumps the block yields no edges at all.
        """
        # xor ecx,ecx; jecxz +2 (target offset 7); ret; nop; ret
        code = bytes.fromhex("31 c9 67 e3 02 c3 90 c3")
        cfg = build_cfg(code, 0x1000)
        assert [b[0] for b in cfg["blocks"]] == [0, 5, 6, 7]
        # jecxz target (0->3) and fallthrough (0->1); nop flows into the target (2->3)
        assert set(cfg["edges"]) == {(0, 3), (0, 1), (2, 3)}

    def test_calls_do_not_split_blocks(self) -> None:
        """A call returns: its target is another function, not a block leader."""
        # mov eax,1; call +0 (the next instruction); add eax,1; ret
        code = bytes.fromhex("b8 01 00 00 00 e8 00 00 00 00 83 c0 01 c3")
        cfg = build_cfg(code, 0x1000)
        assert cfg == {"blocks": [(0, 4, ["mov", "call", "add", "ret"])], "edges": []}

    def test_block_tuple_shape_unchanged(self) -> None:
        """build_cfg keeps (start_offset, insn_count, mnemonics) per block."""
        cfg = build_cfg(IFELSE, 0x1000)
        assert cfg["blocks"][1] == (5, 2, ["mov", "jmp"])


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
                "size": 5,
                "instruction_count": 1,
                "first": "mov eax, 2",
                "last": "mov eax, 2",
            },
            {"va": 0x1011, "size": 1, "instruction_count": 1, "first": "ret", "last": "ret"},
        ]
        assert view["edges"] == [
            {"from": 0x1000, "to": 0x100C, "back_edge": False, "kind": "taken"},
            {"from": 0x1000, "to": 0x1005, "back_edge": False, "kind": "not_taken"},
            {"from": 0x1005, "to": 0x1011, "back_edge": False, "kind": "unconditional"},
            {"from": 0x100C, "to": 0x1011, "back_edge": False, "kind": "unconditional"},
        ]
        assert view["block_count"] == 4
        assert view["block_total"] == 4
        assert view["truncated"] is False
        assert view["note"] is None

    def test_loop_self_edge_is_a_back_edge(self) -> None:
        view = build_cfg_view(LOOP, 0x1000)
        assert [b["va"] for b in view["blocks"]] == [0x1000, 0x1005, 0x1008]
        assert view["edges"] == [
            {"from": 0x1000, "to": 0x1005, "back_edge": False, "kind": "unconditional"},
            {"from": 0x1005, "to": 0x1005, "back_edge": True, "kind": "taken"},
            {"from": 0x1005, "to": 0x1008, "back_edge": False, "kind": "not_taken"},
        ]

    def test_jcc_to_the_next_instruction_keeps_both_kinds(self) -> None:
        """Taken and not-taken reach the same block: two edges, one per kind."""
        code = bytes.fromhex("74 00 c3")  # je +0; ret
        view = build_cfg_view(code, 0x1000)
        assert view["edges"] == [
            {"from": 0x1000, "to": 0x1002, "back_edge": False, "kind": "taken"},
            {"from": 0x1000, "to": 0x1002, "back_edge": False, "kind": "not_taken"},
        ]

    def test_jump_into_an_instruction_gives_no_edge(self) -> None:
        """A target inside an instruction starts no block the view can name."""
        code = bytes.fromhex("eb 01 b8 01 00 00 00 c3")  # jmp into mov's immediate; mov; ret
        view = build_cfg_view(code, 0x1000)
        assert [b["va"] for b in view["blocks"]] == [0x1000, 0x1002]
        assert view["edges"] == []

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
        monkeypatch.setattr("rebrew.binary.cfg_ged.MAX_CFG_BLOCKS_PER_FUNCTION", 2)
        view = build_cfg_view(IFELSE, 0x1000)
        assert view["block_cap"] == 2
        assert view["block_total"] == 4
        assert view["block_count"] == 2
        assert view["truncated"] is True
        assert [b["va"] for b in view["blocks"]] == [0x1000, 0x1005]
        # An edge with an endpoint past the cap is dropped: the returned graph
        # never references a block the payload does not contain.
        kept = {b["va"] for b in view["blocks"]}
        assert view["edges"] == [
            {"from": 0x1000, "to": 0x1005, "back_edge": False, "kind": "not_taken"}
        ]
        assert all(e["from"] in kept and e["to"] in kept for e in view["edges"])


def _switch_targets(view: dict[str, Any], jmp_va: int) -> list[int]:
    """Targets of the ``switch`` edges leaving the block that ends at *jmp_va*."""
    (source,) = [b["va"] for b in view["blocks"] if b["va"] + b["size"] - 7 == jmp_va]
    return [e["to"] for e in view["edges"] if e["from"] == source and e["kind"] == "switch"]


def _with_table(entries: list[int]) -> bytes:
    """INFLATE with its jump table rewritten to *entries*."""
    off = INFLATE_TABLE_VA - INFLATE_VA
    return INFLATE[:off] + b"".join(e.to_bytes(4, "little") for e in entries)


class TestJumpTables:
    def test_inflate_dispatch_has_one_switch_edge_per_case(self) -> None:
        view = build_cfg_view(INFLATE, INFLATE_VA)
        assert _switch_targets(view, INFLATE_JMP_VA) == INFLATE_CASES
        block_vas = {b["va"] for b in view["blocks"]}
        assert set(INFLATE_CASES) <= block_vas
        # The default stays the guard's taken edge.
        (guard,) = [b["va"] for b in view["blocks"] if b["last"] == "ja 0x10005ca0"]
        assert [(e["to"], e["kind"]) for e in view["edges"] if e["from"] == guard] == [
            (INFLATE_DEFAULT_VA, "taken"),
            (INFLATE_JMP_VA, "not_taken"),
        ]

    def test_table_inside_the_extent_is_not_code(self) -> None:
        """MSVC puts the table after the code; its bytes start no block."""
        view = build_cfg_view(INFLATE, INFLATE_VA)
        assert max(b["va"] + b["size"] for b in view["blocks"]) == INFLATE_TABLE_VA
        assert view["blocks"][-1]["last"] == "nop"

    def test_table_past_the_extent_is_read_from_the_image(self) -> None:
        """An extent that stops before the table reads it through *read_image*."""
        code = INFLATE[: INFLATE_TABLE_VA - INFLATE_VA]

        def read_image(va: int, size: int) -> bytes:
            return INFLATE[va - INFLATE_VA : va - INFLATE_VA + size]

        view = build_cfg_view(code, INFLATE_VA, read_image=read_image)
        assert _switch_targets(view, INFLATE_JMP_VA) == INFLATE_CASES

    def test_unreadable_table_gives_no_edge(self) -> None:
        code = INFLATE[: INFLATE_TABLE_VA - INFLATE_VA]
        view = build_cfg_view(code, INFLATE_VA, read_image=lambda va, size: b"")
        assert _switch_targets(view, INFLATE_JMP_VA) == []
        assert _switch_targets(build_cfg_view(code, INFLATE_VA), INFLATE_JMP_VA) == []

    def test_duplicate_targets_give_one_edge(self) -> None:
        entries = [INFLATE_CASES[0]] * 7 + INFLATE_CASES[7:]
        view = build_cfg_view(_with_table(entries), INFLATE_VA)
        assert _switch_targets(view, INFLATE_JMP_VA) == [INFLATE_CASES[0], *INFLATE_CASES[7:]]

    def test_guarded_table_skips_an_entry_outside_the_function(self) -> None:
        entries = [*INFLATE_CASES[:5], 0x20000000, *INFLATE_CASES[6:]]
        view = build_cfg_view(_with_table(entries), INFLATE_VA)
        assert _switch_targets(view, INFLATE_JMP_VA) == [*INFLATE_CASES[:5], *INFLATE_CASES[6:]]

    def test_unguarded_table_stops_at_the_first_entry_outside_the_function(self) -> None:
        entries = [*INFLATE_CASES[:5], 0x20000000, *INFLATE_CASES[6:]]
        code = bytearray(_with_table(entries))
        guard = INFLATE_JMP_VA - 9 - INFLATE_VA  # cmp ecx, 0xd
        assert code[guard : guard + 3] == bytes.fromhex("83f90d")
        code[guard : guard + 3] = b"\x90\x90\x90"
        view = build_cfg_view(bytes(code), INFLATE_VA)
        assert _switch_targets(view, INFLATE_JMP_VA) == INFLATE_CASES[:5]

    def test_masked_table_with_an_unused_first_slot(self) -> None:
        """MSVC memcpy's byte-tail dispatch: ``and eax, 3`` bounds the index,
        slot 0 is never used and overlaps the ``jmp``'s own bytes, so only the
        valid slots are data and the ``jmp`` stays code."""
        code = bytes.fromhex("83e003 ff248508100000 9090 18100000 1a100000 1c100000 c390c390c3")
        view = build_cfg_view(code, 0x1000)
        assert _switch_targets(view, 0x1003) == [0x1018, 0x101A, 0x101C]
        assert [b["va"] for b in view["blocks"]] == [
            0x1000,
            0x100A,
            0x1018,
            0x1019,
            0x101A,
            0x101B,
            0x101C,
        ]

    def test_below_guard_bounds_the_index_below_the_compare(self) -> None:
        """``cmp eax, 3; jae default`` leaves indices 0 to 2: the dword after
        the three entries is code even when it reads as an in-function address."""
        code = bytes.fromhex(
            "83f803 730f ff248518100000 c3c3c3 9090909090 c3 909090"
            "0c100000 0d100000 0e100000 14100000"
        )
        view = build_cfg_view(code, 0x1000)
        assert _switch_targets(view, 0x1005) == [0x100C, 0x100D, 0x100E]
        assert max(b["va"] for b in view["blocks"]) == 0x1024

    def test_negated_index_reads_the_table_below_its_base(self) -> None:
        """MSVC memmove: ``cmp ecx, 3; jb``, ``neg ecx`` and ``jmp [ecx*4 +
        0x101c]`` take slots -2 to 0, the entries at 0x1014 to 0x101c."""
        code = bytes.fromhex(
            "83f903 7202 c3 90 f7d9 ff248d1c100000 c3c3c390 12100000 11100000 10100000"
        )
        view = build_cfg_view(code, 0x1000)
        assert _switch_targets(view, 0x1009) == [0x1012, 0x1011, 0x1010]
        assert max(b["va"] + b["size"] for b in view["blocks"]) == 0x1014

    def test_borrowed_index_reads_the_slots_below_its_base(self) -> None:
        """MSVC memcpy: ``sub ecx, 4; jb tail`` and, at ``tail``, ``jmp [ecx*4
        + 0x102c]`` take slots -4 to -1: the table the masked dispatch
        indexes from 0x101c."""
        code = bytes.fromhex(
            "83e203 83e904 7207 ff24951c100000 ff248d2c100000 9090 c3c3c3c3"
            "18100000 19100000 1a100000 1b100000"
        )
        view = build_cfg_view(code, 0x1000)
        cases = [0x1018, 0x1019, 0x101A, 0x101B]
        assert _switch_targets(view, 0x1008) == cases
        assert _switch_targets(view, 0x100F) == cases

    def test_case_inside_an_instruction_gives_no_edge(self) -> None:
        entries = [INFLATE_CASES[0] + 1, *INFLATE_CASES[1:]]
        view = build_cfg_view(_with_table(entries), INFLATE_VA)
        assert _switch_targets(view, INFLATE_JMP_VA) == INFLATE_CASES[1:]

    @pytest.mark.parametrize(
        ("code", "jmp_va", "cases"),
        [
            (TWO_LEVEL, 0x100D, [0x1014, 0x101A, 0x1020]),
            (TWO_LEVEL_MOVZX, 0x100C, [0x1013, 0x1019, 0x101F]),
        ],
        ids=["mov", "movzx"],
    )
    def test_two_level_byte_index_table(self, code: bytes, jmp_va: int, cases: list[int]) -> None:
        view = build_cfg_view(code, 0x1000)
        assert _switch_targets(view, jmp_va) == cases
        # Neither the address table nor the index table is decoded as code.
        assert max(b["va"] + b["size"] for b in view["blocks"]) <= 0x1024

    def test_two_level_without_guard_reads_the_address_table(self) -> None:
        """No ``cmp``/``ja``: the index table has no bound, the address table
        is read while its entries stay inside the function."""
        code = bytes.fromhex("9090909090") + TWO_LEVEL[5:]
        view = build_cfg_view(code, 0x1000)
        assert _switch_targets(view, 0x100D) == [0x1014, 0x101A, 0x1020]

    def test_similarity_graph_is_unchanged(self) -> None:
        """``build_cfg`` (the GED score) keeps the linear decode: a compiled
        candidate's table holds unrelocated addresses, so resolving only the
        target's would score switch functions lower."""
        graph = build_cfg(INFLATE, INFLATE_VA)
        assert "daa" in graph["blocks"][-1][2]  # the table's first byte, decoded


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
