"""Property-based fuzzing for the CFG segmenter (``rebrew.cfg_ged``).

``build_cfg`` / ``build_cfg_view`` segment a function's raw machine code,
which reaches them straight off a target binary: a stripped, hand-patched,
or simply corrupt ``.text`` decides every block boundary and every edge.  The
segmenter also feeds the GED similarity score, so a byte pattern it mishandles
corrupts a match decision, not just a rendering.

The harnesses below drive structure-aware byte streams (jmp/jcc/ret/loop
terminators at plausible offsets, with forgeable relative displacements) plus
arbitrary bytes, in 16- and 32-bit modes, and assert:

* the block segmentation partitions the decoded instruction stream —
  contiguous, ascending, one mnemonic entry per instruction, every block but
  the last ending at a terminator;
* every edge names two blocks that exist, and no edge is recorded twice
  (the dedup a self-jump chain exercises once per block);
* the capped render view is a faithful prefix of the uncapped one, with
  self-consistent endpoints and truncation flags;
* similarity stays a bounded score for every input pair, never an exception.
"""

import time
from typing import Any

import capstone
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.analysis import capstone_handle
from rebrew.cfg_ged import (
    MAX_CFG_BLOCKS_PER_FUNCTION,
    build_cfg,
    build_cfg_view,
    cfg_similarity,
)

#: Mnemonics that terminate a basic block, restated from the x86 ISA and
#: ``cfg_ged``'s own two sets so the assertion names the property, not the
#: implementation's private constants.
_TERMINATORS = frozenset(
    {
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "je",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
        "jecxz",
        "jcxz",
        "loop",
        "loope",
        "loopne",
        "jmp",
        "ret",
        "retf",
        "iret",
        "hlt",
        "int3",
        "ud2",
    }
)

#: Instruction templates whose presence drives the block segmentation.
_TEMPLATES = [
    b"\x90",  # nop
    b"\x40",  # inc eax
    b"\x55",  # push ebp
    b"\x89\xe5",  # mov ebp, esp
    b"\xc3",  # ret
    b"\xcb",  # retf
    b"\xcc",  # int3
    b"\x0f\x0b",  # ud2
    b"\xf4",  # hlt
    b"\xff",  # indirect call/jmp (modrm only, no displacement of its own)
    b"\xe8",  # call rel32
    b"\xe9",  # jmp rel32
    b"\xeb",  # jmp rel8
    b"\xe2",  # loop rel8
    b"\x74",  # je rel8
    b"\x75",  # jne rel8
    b"\x0f\x84",  # je rel32
    b"\x0f\x85",  # jne rel32
]

#: Templates whose trailing displacement is the single byte after the opcode.
_SHORT_JUMPS = frozenset({b"\xeb", b"\xe2", b"\x74", b"\x75"})


@st.composite
def _control_flow_code(draw: st.DrawFn) -> bytes:
    """A byte stream built from control-flow templates with forgeable
    displacements, so jump targets land inside the buffer, past its end,
    mid-instruction, and on themselves."""
    parts: list[bytes] = []
    for _ in range(draw(st.integers(min_value=0, max_value=24))):
        tmpl = draw(st.sampled_from(_TEMPLATES))
        if tmpl in _SHORT_JUMPS:
            parts.append(tmpl + bytes([draw(st.integers(min_value=0, max_value=0xFF))]))
        elif tmpl[:1] in (b"\xe8", b"\xe9", b"\xff", b"\x0f"):
            parts.append(tmpl + draw(st.binary(min_size=4, max_size=4)))
        else:
            parts.append(tmpl)
    return b"".join(parts)


_modes = st.sampled_from([capstone.CS_MODE_32, capstone.CS_MODE_16])
_bases = st.integers(min_value=0, max_value=0xFFFFFFF0)

Block = tuple[int, int, list[str]]


def _assert_partition(code: bytes, va: int, cs_mode: int, blocks: list[Block]) -> list[int]:
    """The blocks tile the decoded instruction stream exactly once each."""
    insns = list(capstone_handle(capstone.CS_ARCH_X86, cs_mode).disasm(code, va))
    starts = [insn.address - va for insn in insns]
    assert starts == sorted(starts), "capstone must decode in ascending address order"
    if not insns:
        assert blocks == []
        return starts
    assert blocks[0][0] == starts[0]
    assert sum(count for _, count, _ in blocks) == len(insns)
    for idx, (start, count, mnems) in enumerate(blocks):
        assert count == len(mnems) >= 1
        assert start == starts[sum(b[1] for b in blocks[:idx])], "block starts on an instruction"
        if idx + 1 < len(blocks):
            assert mnems[-1] in _TERMINATORS, "only the last block may end without a terminator"
    return starts


@settings(max_examples=250, deadline=None)
@given(_control_flow_code(), _modes, _bases)
def test_build_cfg_partitions_decoded_instructions(code: bytes, cs_mode: int, va: int) -> None:
    """Fuzz: control-flow-shaped code at any base VA.  Blocks tile the decode
    exactly, and every edge names two existing blocks, once."""
    graph = build_cfg(code, va, cs_mode)
    blocks: list[Block] = graph["blocks"]
    edges: list[tuple[int, int]] = graph["edges"]
    _assert_partition(code, va, cs_mode, blocks)

    assert len(edges) == len(set(edges)), "an edge is recorded twice"
    for src, dst in edges:
        assert 0 <= src < len(blocks)
        assert 0 <= dst < len(blocks)


@settings(max_examples=250, deadline=None)
@given(st.binary(min_size=0, max_size=256), _modes, _bases)
def test_build_cfg_partitions_random_bytes(code: bytes, cs_mode: int, va: int) -> None:
    """Fuzz: arbitrary bytes.  Undecodable input yields no blocks; anything
    decodable still partitions the stream and dedups its edges."""
    graph = build_cfg(code, va, cs_mode)
    blocks: list[Block] = graph["blocks"]
    edges: list[tuple[int, int]] = graph["edges"]
    _assert_partition(code, va, cs_mode, blocks)

    assert len(edges) == len(set(edges))
    for src, dst in edges:
        assert 0 <= src < len(blocks)
        assert 0 <= dst < len(blocks)


@settings(max_examples=200, deadline=None)
@given(_control_flow_code(), _control_flow_code(), _modes)
def test_build_cfg_view_is_a_capped_prefix_of_build_cfg(
    left: bytes, right: bytes, cs_mode: int
) -> None:
    """Pair assertion across the cap: the render view describes the same
    segmentation as the uncapped graph, truncated consistently — kept blocks
    are the leading ones, every returned edge names a kept block, and the
    truncation flag agrees with the two counts."""
    va = 0x401000
    full = build_cfg(left, va, cs_mode)
    view = build_cfg_view(left, va, cs_mode)
    kept: list[dict[str, Any]] = view["blocks"]

    assert view["block_cap"] == MAX_CFG_BLOCKS_PER_FUNCTION
    assert 0 <= view["block_count"] <= view["block_cap"]
    assert len(kept) == view["block_count"]
    assert view["block_total"] >= view["block_count"]
    assert view["truncated"] == (view["block_total"] > view["block_count"])
    assert (view["note"] is None) == (view["block_count"] > 0)
    if not kept:
        assert view["block_total"] == 0 or not view["truncated"]

    kept_vas = {b["va"] for b in kept}
    assert kept_vas == {va + start for start, _, _ in full["blocks"][: len(kept)]}
    for block in kept:
        assert block["size"] >= 1
        assert block["instruction_count"] >= 1
        assert isinstance(block["first"], str) and isinstance(block["last"], str)
    for edge in view["edges"]:
        assert edge["from"] in kept_vas and edge["to"] in kept_vas
        assert edge["back_edge"] == (edge["to"] <= edge["from"])

    # A second, independent stream still honours the cap and its own edges.
    other = build_cfg_view(right, va, cs_mode)
    other_vas = {b["va"] for b in other["blocks"]}
    assert len(other["blocks"]) <= MAX_CFG_BLOCKS_PER_FUNCTION
    assert all(e["from"] in other_vas and e["to"] in other_vas for e in other["edges"])


@settings(max_examples=200, deadline=None)
@given(st.binary(min_size=0, max_size=128), st.binary(min_size=0, max_size=128))
def test_cfg_similarity_is_a_bounded_score(left: bytes, right: bytes) -> None:
    """Fuzz: the GED score stays in 0..100 for every pair, degenerate input
    included, and never raises."""
    result = cfg_similarity(left, right, 0x401000, capstone.CS_MODE_32)
    for key in ("node_sim", "edge_sim", "overall"):
        assert 0.0 <= result[key] <= 100.0
    assert result["matched_blocks"] <= min(result["target_blocks"], result["candidate_blocks"])


@pytest.mark.parametrize("count", [1, 16, 4096])
def test_self_jump_chain_segments_one_block_per_jump(count: int) -> None:
    """Regression for the quadratic edge dedup: ``jmp $`` repeated is the
    densest edge case (one block and one edge per two bytes), and segmenting
    a long extent must stay linear in its length."""
    code = b"\xeb\xfe" * count
    started = time.perf_counter()
    graph = build_cfg(code, 0x401000, capstone.CS_MODE_32)
    elapsed = time.perf_counter() - started
    assert len(graph["blocks"]) == count
    assert graph["edges"] == [(i, i) for i in range(count)]
    # Loose bound: the quadratic form spent whole seconds on the largest
    # count, the linear one milliseconds.  Generous so a loaded box cannot flake.
    assert elapsed < 2.0, f"segmenting {count} self-jumps took {elapsed:.3f}s"
