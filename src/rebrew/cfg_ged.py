"""cfg_ged.py — control-flow-graph structural similarity (DecBench GED-inspired).

DecBench scores "structural correctness" as the graph-edit distance between
the source CFG and the decompiled CFG.  rebrew has no source CFG (it has the
target binary and the compiled candidate), so the analogous metric compares
the TARGET function's CFG against the COMPILED function's CFG: a bounded
graph-edit approximation over basic blocks and edges.

- Basic blocks are segmented from the disassembly (blocks end at
  jmp/jcc/ret; edges are fallthrough + jump targets — intra-function only).
- Block matching is greedy best-match by mnemonic-multiset cosine (the
  ``rebrew.similar`` signature machinery), weighted by instruction count.
- Edge similarity is the Jaccard of the successor sets after mapping
  matched blocks.
- ``overall`` = 0.5 * node_sim + 0.5 * edge_sim.

This is a NEW metric (control-flow-aware), complementary to the existing
mnemonic-histogram ``structural_similarity``; it never replaces it.  Pure
capstone, no angr dependency.  Best-effort: garbage/undecodable input yields
0.0, never raises.

``build_cfg_view`` exposes the same segmentation for rendering: absolute
block VAs, byte spans, first/last instruction text and back-edge flags,
capped at ``MAX_CFG_BLOCKS_PER_FUNCTION`` (consumed by ``rebrew asm
--format cfg``).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

import capstone

from rebrew.analysis import capstone_handle

#: Terminators that end a basic block.
_BLOCK_END_MNEMONICS = frozenset(
    {"jmp", "ret", "retf", "iret", "hlt", "int3", "ud2", "jecxz", "jcxz"}
)
#: Conditional jumps (fallthrough + target edges).
_COND_JUMPS = frozenset(
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
    }
)
_JMP_TARGET_RE = re.compile(r"0x([0-9a-fA-F]+)")

#: Cap on the blocks ``build_cfg_view`` returns for one function: a renderable
#: graph, not an unbounded dump of a malformed extent.  The payload carries
#: the true count and this cap.
MAX_CFG_BLOCKS_PER_FUNCTION = 512


def build_cfg(code: bytes, va: int, cs_mode: int = capstone.CS_MODE_32) -> dict[str, Any]:
    """Segment *code* into a basic-block CFG.

    Returns ``{"blocks": [(start_off, insn_count, mnemonics)], "edges":
    [(from_idx, to_idx), ...]}`` — intra-function only (calls are treated as
    plain instructions; their callees are not in this CFG).  *start_off* is
    the byte offset into *code* (address - va).  For the absolute-VA render
    view of the same segmentation, see :func:`build_cfg_view`.
    """
    blocks, edges = _segment_blocks(code, va, cs_mode)
    return {
        "blocks": [(b["start"], b["insn_count"], b["mnems"]) for b in blocks],
        "edges": edges,
    }


def build_cfg_view(code: bytes, va: int, cs_mode: int = capstone.CS_MODE_32) -> dict[str, Any]:
    """Render-facing view of one function's CFG: absolute VAs and labels.

    Returns ``{"blocks": [{"va", "size", "instruction_count", "first",
    "last"}], "edges": [{"from", "to", "back_edge"}], "block_count",
    "block_total", "block_cap", "truncated", "note"}``.

    *va* is the function's start (the same VA :func:`build_cfg` takes) and
    every address here is absolute (``va + byte offset``).  ``size`` is the
    block's byte span; ``first``/``last`` are ``"mnemonic operands"`` text of
    its first and last instruction (equal for a one-instruction block).  An
    edge is ``back_edge`` when it targets a block at or before its source
    (blocks are in address order, so a self-loop counts).

    ``blocks`` is capped at ``MAX_CFG_BLOCKS_PER_FUNCTION``;
    ``block_total``/``block_cap``/``truncated`` state the true count, and
    edges with an endpoint past the cap are dropped so the returned graph
    stays self-consistent.  Undecodable input yields empty ``blocks`` with
    ``note`` set, never an exception.
    """
    blocks, edges = _segment_blocks(code, va, cs_mode)
    total = len(blocks)
    kept = blocks[:MAX_CFG_BLOCKS_PER_FUNCTION]
    kept_idx = set(range(len(kept)))
    return {
        "blocks": [
            {
                "va": va + b["start"],
                "size": b["byte_size"],
                "instruction_count": b["insn_count"],
                "first": b["first"],
                "last": b["last"],
            }
            for b in kept
        ],
        "edges": [
            {
                "from": va + blocks[a]["start"],
                "to": va + blocks[b]["start"],
                "back_edge": b <= a,
            }
            for a, b in edges
            if a in kept_idx and b in kept_idx
        ],
        "block_count": len(kept),
        "block_total": total,
        "block_cap": MAX_CFG_BLOCKS_PER_FUNCTION,
        "truncated": total > len(kept),
        "note": None if kept else "no decodable instructions",
    }


def _segment_blocks(
    code: bytes, va: int, cs_mode: int
) -> tuple[list[dict[str, Any]], list[tuple[int, int]]]:
    """Segment *code* into basic blocks and intra-function edges.

    The single segmenter behind :func:`build_cfg` (offset/index view) and
    :func:`build_cfg_view` (absolute-VA view).  Block records carry the byte
    offset into *code*, the byte span, the instruction count, the mnemonic
    list, first/last instruction text, and the start instruction index.
    """
    md = capstone_handle(capstone.CS_ARCH_X86, cs_mode)
    insns = list(md.disasm(code, va))
    if not insns:
        return [], []

    # Split into blocks at terminators (a block ends at its last terminator).
    # Conditional jumps terminate too — the block ends AT the jcc, whose
    # target + fallthrough edges are added when building the edge list.
    block_starts: list[int] = [0]
    for i, insn in enumerate(insns):
        if (insn.mnemonic in _BLOCK_END_MNEMONICS or insn.mnemonic in _COND_JUMPS) and (
            i + 1 < len(insns)
        ):
            block_starts.append(i + 1)
    block_starts_set = set(block_starts)

    blocks: list[dict[str, Any]] = []
    cur: list[Any] = []
    cur_start_idx = 0
    for i, insn in enumerate(insns):
        if i in block_starts_set and cur:
            blocks.append(_seal(cur, va, cur_start_idx))
            cur = []
            cur_start_idx = i
        cur.append(insn)
    if cur:
        blocks.append(_seal(cur, va, cur_start_idx))

    # Build edges: for each block, its last instruction's targets.  Jump
    # targets resolve to the block CONTAINING the target byte (loop heads
    # often land mid-block after a pre-header); self-edges (back-edges) are
    # meaningful and kept.
    edges: list[tuple[int, int]] = []
    block_idx_of_offset: dict[int, int] = {}
    for idx, b in enumerate(blocks):
        first = insns[b["start_idx"]]
        last = insns[b["start_idx"] + b["insn_count"] - 1]
        start_off = first.address - va
        end_off = last.address + last.size - va
        for off in range(start_off, end_off):
            block_idx_of_offset[off] = idx

    for idx, b in enumerate(blocks):
        count, start_idx = b["insn_count"], b["start_idx"]
        last = insns[start_idx + count - 1]
        mnem = last.mnemonic
        if mnem in _COND_JUMPS:
            target_off = _jump_target_off(last, va)
            if target_off is not None:
                _add_edge(edges, idx, block_idx_of_offset, target_off)
            # fallthrough to the next block
            if start_idx + count < len(insns):
                _add_edge(edges, idx, block_idx_of_offset, insns[start_idx + count].address - va)
        elif mnem == "jmp":
            target_off = _jump_target_off(last, va)
            if target_off is not None:
                _add_edge(edges, idx, block_idx_of_offset, target_off)
        elif mnem not in _BLOCK_END_MNEMONICS:
            # fallthrough
            if start_idx + count < len(insns):
                _add_edge(edges, idx, block_idx_of_offset, insns[start_idx + count].address - va)

    return blocks, edges


def _seal(cur: list[Any], base_va: int, start_idx: int) -> dict[str, Any]:
    """Seal a block: start byte offset (into the code buffer), byte span,
    instruction count, mnemonic list, first/last instruction text, and the
    start instruction index."""
    first, last = cur[0], cur[-1]
    return {
        "start": first.address - base_va,
        "byte_size": last.address + last.size - first.address,
        "insn_count": len(cur),
        "mnems": [insn.mnemonic for insn in cur],
        "first": _insn_text(first),
        "last": _insn_text(last),
        "start_idx": start_idx,
    }


def _insn_text(insn: Any) -> str:
    """One capstone instruction as ``"mnemonic operands"`` text."""
    return f"{insn.mnemonic} {insn.op_str}".strip()


def _jump_target_off(insn: Any, base_va: int) -> int | None:
    """Byte offset (into the code buffer) of a jump's target."""
    m = _JMP_TARGET_RE.search(insn.op_str)
    if not m:
        return None
    return int(m.group(1), 16) - base_va


def _add_edge(
    edges: list[tuple[int, int]],
    from_idx: int,
    block_idx_of_offset: dict[int, int],
    target_off: int,
) -> None:
    to_idx = block_idx_of_offset.get(target_off)
    if to_idx is not None:
        edge = (from_idx, to_idx)
        if edge not in edges:
            edges.append(edge)


def _block_signature(mnems: list[str]) -> Counter[str]:
    return Counter(mnems)


def _cosine(a: Counter[str], b: Counter[str]) -> float:
    keys = set(a) | set(b)
    va = math.sqrt(float(sum(a.get(k, 0) ** 2 for k in keys)))
    vb = math.sqrt(float(sum(b.get(k, 0) ** 2 for k in keys)))
    if va == 0 or vb == 0:
        return 0.0
    dot = 0.0
    for k in keys:
        dot += a.get(k, 0) * b.get(k, 0)
    return dot / (va * vb)


def cfg_similarity(
    target_code: bytes, candidate_code: bytes, va: int = 0, cs_mode: int = capstone.CS_MODE_32
) -> dict[str, float]:
    """CFG structural similarity (0-100) between two functions' byte streams.

    Returns ``{"node_sim", "edge_sim", "overall", "target_blocks",
    "candidate_blocks", "matched_blocks"}``.  Degenerate inputs (either side
    empty/undecodable) return all-zero scores.
    """
    t = build_cfg(target_code, va, cs_mode)
    c = build_cfg(candidate_code, va, cs_mode)
    tb, cb, te, ce = t["blocks"], c["blocks"], t["edges"], c["edges"]

    if not tb or not cb:
        return {
            "node_sim": 0.0,
            "edge_sim": 0.0,
            "overall": 0.0,
            "target_blocks": len(tb),
            "candidate_blocks": len(cb),
            "matched_blocks": 0,
        }

    # Greedy best-match blocks by mnemonic-multiset cosine, weighted by size.
    sigs_t = [_block_signature(m) for _, _, m in tb]
    sigs_c = [_block_signature(m) for _, _, m in cb]
    sizes_t = [s for _, s, _ in tb]
    total_weights = sum(sizes_t)
    matched_t: set[int] = set()
    matched_c: set[int] = set()
    match_map: dict[int, int] = {}
    score_weight = 0.0
    # Order target blocks by size (largest first) for a stable greedy.
    for ti in sorted(range(len(tb)), key=lambda i: -sizes_t[i]):
        best_c, best_score = -1, 0.0
        for ci in range(len(cb)):
            if ci in matched_c:
                continue
            s = _cosine(sigs_t[ti], sigs_c[ci])
            if s > best_score:
                best_score, best_c = s, ci
        if best_c >= 0 and best_score > 0.0:
            matched_t.add(ti)
            matched_c.add(best_c)
            match_map[ti] = best_c
            score_weight += best_score * sizes_t[ti]

    node_sim = score_weight / total_weights if total_weights else 0.0

    # Edge similarity: Jaccard over mapped edges.  A target edge (a,b) matches
    # a candidate edge (c,d) when a→c and b→d are both matched pairs.
    edge_matches = 0
    for a, b in te:
        if a in match_map and b in match_map:
            ce_cand = match_map[b]
            if (match_map[a], ce_cand) in ce:
                edge_matches += 1
    edge_union = len(te) + len(ce) - edge_matches
    edge_sim = edge_matches / edge_union if edge_union else 1.0  # both empty = identical flow

    return {
        "node_sim": round(node_sim * 100.0, 1),
        "edge_sim": round(edge_sim * 100.0, 1),
        "overall": round((0.5 * node_sim + 0.5 * edge_sim) * 100.0, 1),
        "target_blocks": len(tb),
        "candidate_blocks": len(cb),
        "matched_blocks": len(match_map),
    }
