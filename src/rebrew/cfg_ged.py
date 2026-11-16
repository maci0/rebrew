"""cfg_ged.py — control-flow-graph structural similarity (DecBench GED-inspired).

DecBench scores "structural correctness" as the graph-edit distance between
the source CFG and the decompiled CFG.  rebrew has no source CFG (it has the
target binary and the compiled candidate), so the analogous metric compares
the TARGET function's CFG against the COMPILED function's CFG: a bounded
graph-edit approximation over basic blocks and edges.

- Basic blocks are segmented from the disassembly: a block starts at the
  first instruction, after every jmp/jcc/ret, and at every direct jump
  target inside the code; edges are fallthrough + jump targets,
  intra-function only.
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
block VAs, byte spans, first/last instruction text, edge kinds and back-edge flags,
capped at ``MAX_CFG_BLOCKS_PER_FUNCTION`` (consumed by ``rebrew binary asm show
--format cfg``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NamedTuple
lazy import math
lazy from collections import Counter
lazy from collections.abc import Callable
lazy from typing import Any

import capstone

lazy from rebrew.analysis import Insn, capstone_handle, instruction_text
lazy from rebrew.jump_table import BOUND_WINDOW, MAX_TABLE_ENTRIES, dispatch_operand, index_bound

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
# Direct jumps only: op_str is a bare ``0x<addr>``.  An indirect jump's
# ``dword ptr [0x<addr>]`` or ``eax`` operand must not become a direct edge.
_JMP_TARGET_RE = re.compile(r"^0x([0-9a-fA-F]+)$")

#: Edge kinds, read from the source block's last instruction.  A conditional
#: jump gives a ``taken`` edge to its target and a ``not_taken`` edge to the
#: next instruction; a ``jmp``, or a block that ends only because the next
#: instruction is a jump target, gives one ``unconditional`` edge.  In the
#: render view a resolved 32-bit jump-table ``jmp`` gives one ``switch`` edge
#: per distinct case target; other indirect jumps give no edge.
EDGE_TAKEN = "taken"
EDGE_NOT_TAKEN = "not_taken"
EDGE_UNCONDITIONAL = "unconditional"
EDGE_SWITCH = "switch"

#: Jump-table entry size, and the dispatch's index scale, on 32-bit x86.
_TABLE_ENTRY_WIDTH = 4
#: Decode passes that re-find tables after skipping the ones already found
#: (a table can hide a later dispatch behind bytes capstone cannot decode).
_MAX_DECODE_PASSES = 4
#: MSVC's two-level switch loads the address-table slot from a byte index
#: table: ``mov cl, byte ptr [eax + idx]`` or ``movzx ecx, byte ptr [eax + idx]``.
_BYTE_INDEX_RE = re.compile(r"^([a-z]+), byte ptr \[([a-z]+) \+ 0x([0-9a-f]+)\]$")
_FULL_REG = {"al": "eax", "bl": "ebx", "cl": "ecx", "dl": "edx"}
#: Listing mnemonics of a jump-table address entry, a byte index-table entry,
#: and a stretch of bytes that decodes as no instruction.
TABLE_ADDRESS_MNEMONIC = "dd"
TABLE_INDEX_MNEMONIC = "db"
UNDECODED_MNEMONIC = "db"
#: Instructions that name the index register first without writing it.
_COMPARES = frozenset({"cmp", "test"})
#: ``jb`` and its aliases: taken when a ``sub`` borrowed (the index went negative).
_BORROW_JUMPS = frozenset({"jb", "jc", "jnae"})
#: ``sub ecx, 4``: the decrement before a borrow jump to a negative-index dispatch.
_SUB_IMM_RE = re.compile(r"^([a-z0-9]+),\s*(0x[0-9a-fA-F]+|\d+)$")

#: Reads ``size`` image bytes at a VA (fewer, or none, when unmapped).
type ImageReader = Callable[[int, int], bytes]

#: Cap on the blocks ``build_cfg_view`` returns for one function: a renderable
#: graph, not an unbounded dump of a malformed extent.  The payload carries
#: the true count and this cap.
MAX_CFG_BLOCKS_PER_FUNCTION = 512


def build_cfg(code: bytes, va: int, cs_mode: int = capstone.CS_MODE_32) -> dict[str, Any]:
    """Segment *code* into a basic-block CFG.

    Returns ``{"blocks": [(start_off, insn_count, mnemonics)], "edges":
    [(from_idx, to_idx), ...]}`` — each pair once, whatever its kinds;
    intra-function only (calls are treated as
    plain instructions; their callees are not in this CFG).  *start_off* is
    the byte offset into *code* (address - va).  For the absolute-VA render
    view of the same segmentation, see :func:`build_cfg_view`.
    """
    blocks, edges = _segment_blocks(code, va, cs_mode)
    return {
        "blocks": [(b["start"], b["insn_count"], b["mnems"]) for b in blocks],
        "edges": list(dict.fromkeys((a, b) for a, b, _ in edges)),
    }


def build_cfg_view(
    code: bytes,
    va: int,
    cs_mode: int = capstone.CS_MODE_32,
    read_image: ImageReader | None = None,
) -> dict[str, Any]:
    """Render-facing view of one function's CFG: absolute VAs and labels.

    Returns ``{"blocks": [{"va", "size", "instruction_count", "first",
    "last"}], "edges": [{"from", "to", "back_edge", "kind"}], "block_count",
    "block_total", "block_cap", "truncated", "note"}``.

    *va* is the function's start (the same VA :func:`build_cfg` takes) and
    every address here is absolute (``va + byte offset``).  ``size`` is the
    block's byte span; ``first``/``last`` are ``"mnemonic operands"`` text of
    its first and last instruction (equal for a one-instruction block).  An
    edge's ``to`` is always a block start: a jump into the middle of an
    instruction, or out of *code*, gives no edge.  ``kind`` is one of
    ``EDGE_TAKEN``/``EDGE_NOT_TAKEN``/``EDGE_UNCONDITIONAL``/``EDGE_SWITCH``;
    a conditional jump to the next instruction gives two edges between the
    same blocks, one per kind.  An edge is ``back_edge`` when it targets a
    block at or before its source (blocks are in address order, so a
    self-loop counts).

    In 32-bit mode a ``jmp dword ptr [reg*4 + table]`` gets one
    ``EDGE_SWITCH`` edge per distinct case target, in table order, and each
    target starts a block.  The table holds ``N + 1`` entries when a ``cmp
    reg, N`` on the index precedes the ``jmp``, ``N`` when ``jb``/``jae``
    tests it (else up to ``rebrew.jump_table.MAX_TABLE_ENTRIES``).  MSVC
    memcpy/memmove index below the table base: after ``neg reg`` the slots
    run from ``-(N - 1)`` to 0, and a dispatch reached only by ``sub reg, K;
    jb`` reads slots ``-K`` to -1.  An entry outside the function
    (``va`` to ``va + len(code)``) gives no edge; without a bound it ends the
    table, with one the walk goes on, as ``rebrew binary switches`` does: MSVC's
    memcpy byte-tail tables (``and eax, 3`` bound) leave slot 0 unused, its
    bytes overlapping the previous ``jmp``.  Only the span from the first to
    the last valid entry is data.  MSVC's two-level form (``mov cl, byte
    ptr [eax + idx]`` before the ``jmp``) sizes the address table from the
    ``N + 1`` bytes of the index table (no guard: the address table is
    walked unbounded).  Table bytes come from *code* when it holds them,
    else from *read_image* (``(va, size) -> bytes``); an address table read
    short ends early, an index table read short leaves its address table
    unbounded, and an unreadable table gives no edge.  Tables
    inside *code* are data: their bytes start no block.  :func:`build_cfg`
    (the similarity score) decodes linearly and resolves no table.

    ``blocks`` is capped at ``MAX_CFG_BLOCKS_PER_FUNCTION``;
    ``block_total``/``block_cap``/``truncated`` state the true count, and
    edges with an endpoint past the cap are dropped so the returned graph
    stays self-consistent.  Undecodable input yields empty ``blocks`` with
    ``note`` set, never an exception.
    """
    blocks, edges = _segment_blocks(code, va, cs_mode, switches=True, read_image=read_image)
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
                "kind": kind,
            }
            for a, b, kind in edges
            if a in kept_idx and b in kept_idx
        ],
        "block_count": len(kept),
        "block_total": total,
        "block_cap": MAX_CFG_BLOCKS_PER_FUNCTION,
        "truncated": total > len(kept),
        "note": None if kept else "no decodable instructions",
    }


def _segment_blocks(
    code: bytes,
    va: int,
    cs_mode: int,
    *,
    switches: bool = False,
    read_image: ImageReader | None = None,
) -> tuple[list[dict[str, Any]], list[tuple[int, int, str]]]:
    """Segment *code* into basic blocks and intra-function ``(from, to, kind)`` edges.

    The single segmenter behind :func:`build_cfg` (offset/index view) and
    :func:`build_cfg_view` (absolute-VA view).  Block records carry the byte
    offset into *code*, the byte span, the instruction count, the mnemonic
    list, first/last instruction text, and the start instruction index.
    Edges are unique per ``(from, to, kind)``.  With *switches* (32-bit mode
    only) jump tables are resolved as :func:`build_cfg_view` describes.
    """
    if switches:
        layout = jump_table_layout(code, va, cs_mode, read_image)
        insns, tables = layout.insns, layout.tables
    else:
        insns = list(capstone_handle(capstone.CS_ARCH_X86, cs_mode).disasm(code, va))
        tables = {}
    if not insns:
        return [], []
    index_of_offset = {insn.address - va: i for i, insn in enumerate(insns)}

    # Leaders: the first instruction, the one after each terminator or
    # conditional jump or a skipped table, and each direct jump or case
    # target that starts an instruction.  Resolving a target to the block
    # merely containing it put a loop head's edge on its pre-header.
    leaders = {0}
    for i, insn in enumerate(insns):
        if insn.mnemonic in _BLOCK_END_MNEMONICS or insn.mnemonic in _COND_JUMPS:
            leaders.add(i + 1)
            target = index_of_offset.get(_jump_target_off(insn, va))
            if target is not None:
                leaders.add(target)
        elif i + 1 < len(insns) and not _flows_into(insn, insns[i + 1]):
            leaders.add(i + 1)
    for case_vas in tables.values():
        leaders.update(index_of_offset[t - va] for t in case_vas if t - va in index_of_offset)
    starts = sorted(i for i in leaders if i < len(insns))
    ends = [*starts[1:], len(insns)]
    blocks = [_seal(insns[s:e], va, s) for s, e in zip(starts, ends, strict=True)]
    block_of_index = {s: idx for idx, s in enumerate(starts)}

    edges: list[tuple[int, int, str]] = []
    edge_set: set[tuple[int, int, str]] = set()
    for idx, end in enumerate(ends):
        last = insns[end - 1]
        has_next = end < len(insns) and _flows_into(last, insns[end])
        conditional = last.mnemonic in _COND_JUMPS
        if conditional or last.mnemonic == "jmp":
            target = index_of_offset.get(_jump_target_off(last, va))
            if target is not None:
                kind = EDGE_TAKEN if conditional else EDGE_UNCONDITIONAL
                _add_edge(edges, edge_set, (idx, block_of_index[target], kind))
            if conditional and has_next:
                _add_edge(edges, edge_set, (idx, idx + 1, EDGE_NOT_TAKEN))
            for case_va in tables.get(last.address, []):
                case = index_of_offset.get(case_va - va)
                if case is not None:
                    _add_edge(edges, edge_set, (idx, block_of_index[case], EDGE_SWITCH))
        elif last.mnemonic not in _BLOCK_END_MNEMONICS and has_next:
            # The next instruction is a jump target: plain flow into its block.
            _add_edge(edges, edge_set, (idx, idx + 1, EDGE_UNCONDITIONAL))

    return blocks, edges


def _flows_into(insn: Any, nxt: Any) -> bool:
    """True when *nxt* starts where *insn* ends (no skipped table between)."""
    return bool(insn.address + insn.size == nxt.address)


@dataclass(frozen=True)
class TableEntry:
    """One jump-table entry whose bytes lie inside the decoded code.

    ``width`` is 4 for an address-table entry (``value``
    is the case target VA) or 1 for a byte of MSVC's two-level index table
    (``value`` is the address-table slot).  ``first`` marks an entry that
    starts a table.
    """

    va: int
    width: int
    value: int
    first: bool


@dataclass(frozen=True)
class TableLayout:
    """One function's code split into instructions and jump-table data.

    ``insns`` are capstone instructions in address order, decoded around the
    table bytes; ``tables`` maps each resolved dispatch ``jmp`` VA to its
    distinct case target VAs in table order; ``entries`` are the table
    entries inside the code, in address order, never overlapping an
    instruction or each other.  Bytes covered by neither (an undecodable
    stretch) belong to no instruction and no entry.
    """

    insns: list[Any]
    tables: dict[int, list[int]]
    entries: list[TableEntry]


def jump_table_layout(
    code: bytes, va: int, cs_mode: int, read_image: ImageReader | None = None
) -> TableLayout:
    """Decode *code* at *va*, reading the 32-bit jump tables it holds as data.

    The rules are :func:`build_cfg_view`'s; every listing of the function
    renders ``entries`` as data and ``insns`` as code, so the CFG, the
    listings and the instruction diff agree on which bytes are code.  Other
    modes resolve no table: ``insns`` is the linear decode.
    """
    md = capstone_handle(capstone.CS_ARCH_X86, cs_mode)
    insns = list(md.disasm(code, va))
    if cs_mode != capstone.CS_MODE_32:
        return TableLayout(insns, {}, [])
    # Re-decode around the tables found so far until the set settles:
    # table bytes decoded as code can fake or hide a dispatch.
    skip: list[tuple[int, int]] = []
    tables, entries = _jump_tables(insns, code, va, read_image)
    for _ in range(_MAX_DECODE_PASSES):
        data = _entry_ranges(entries, va)
        if data == skip:
            break
        skip = data
        insns = _decode_around(md, code, va, skip)
        tables, entries = _jump_tables(insns, code, va, read_image)
    # A set that has not settled keeps only the entries the decode skipped.
    skipped = {off for start, end in skip for off in range(start, end)}
    entries = [e for e in entries if all(e.va - va + k in skipped for k in range(e.width))]
    return TableLayout(insns, tables, entries)


class Listing(NamedTuple):
    """A function's listing rows (see :func:`listing_items`)."""

    rows: list[Insn]
    #: VAs of the rows that are jump-table entries.
    table_entries: frozenset[int]
    #: VAs of the rows that start a jump table.
    table_starts: frozenset[int]
    #: VAs of the rows holding bytes that decode as no instruction.
    undecoded: frozenset[int]


def listing_items(
    code: bytes,
    va: int,
    cs_arch: str | int,
    cs_mode: str | int,
    read_image: ImageReader | None = None,
    resolved: bytes | None = None,
) -> Listing:
    """*code* as listing rows in address order.

    Every byte is in one row: an instruction, a jump-table entry
    (``TABLE_ADDRESS_MNEMONIC`` with the case target, or
    ``TABLE_INDEX_MNEMONIC`` with the address-table slot, as a ``0x`` number)
    or an undecodable stretch (``UNDECODED_MNEMONIC``, its bytes as
    space-separated hex).  32-bit x86 reads the tables
    :func:`jump_table_layout` resolves; any other ISA decodes linearly.
    *resolved* is *code* with its self-references applied (a compiled
    object's relocations to its own labels): the tables are found in it, and
    rows keep *code*'s bytes and operands.
    """
    from rebrew.analysis import disasm_insns, resolve_capstone

    arch, mode = resolve_capstone(cs_arch), resolve_capstone(cs_mode)
    rows: list[Insn]
    entries: frozenset[int] = frozenset()
    starts: frozenset[int] = frozenset()
    if arch == capstone.CS_ARCH_X86 and mode == capstone.CS_MODE_32:
        layout = jump_table_layout(code if resolved is None else resolved, va, mode, read_image)
        insns = layout.insns
        if resolved is not None:
            insns = _decode_around(
                capstone_handle(arch, mode), code, va, _entry_ranges(layout.entries, va)
            )
        rows = [
            Insn(
                i.address,
                i.size,
                i.mnemonic,
                i.op_str,
                code[i.address - va : i.address - va + i.size],
            )
            for i in insns
        ]
        rows += [
            Insn(
                e.va,
                e.width,
                TABLE_ADDRESS_MNEMONIC if e.width == _TABLE_ENTRY_WIDTH else TABLE_INDEX_MNEMONIC,
                f"0x{e.value:x}",
                code[e.va - va : e.va - va + e.width],
            )
            for e in layout.entries
        ]
        rows.sort(key=lambda row: row.va)
        entries = frozenset(e.va for e in layout.entries)
        starts = frozenset(e.va for e in layout.entries if e.first)
    else:
        rows = disasm_insns(code, va, arch, mode)
    out: list[Insn] = []
    undecoded: set[int] = set()
    pos = va
    for row in [*rows, Insn(va + len(code), 0, "", "", b"")]:
        if row.va > pos:
            gap = code[pos - va : row.va - va]
            out.append(Insn(pos, len(gap), UNDECODED_MNEMONIC, gap.hex(" "), gap))
            undecoded.add(pos)
        if row.size:
            out.append(row)
        pos = max(pos, row.va + row.size)
    return Listing(out, entries, starts, frozenset(undecoded))


def table_label(va: int) -> str:
    """The listing label of the jump table at *va*."""
    return f"jump_table_{va:08X}"


def _decode_around(md: Any, code: bytes, va: int, skip: list[tuple[int, int]]) -> list[Any]:
    """Decode *code* except the sorted, disjoint byte-offset ranges in *skip*.

    Each stretch between two ranges decodes on its own, up to its first
    undecodable byte.
    """
    insns: list[Any] = []
    pos = 0
    for start, end in [*skip, (len(code), len(code))]:
        if start > pos:
            insns.extend(md.disasm(code[pos:start], va + pos))
        pos = max(pos, end)
    return insns


def _jump_tables(
    insns: list[Any], code: bytes, va: int, read_image: ImageReader | None
) -> tuple[dict[int, list[int]], list[TableEntry]]:
    """Resolve the 32-bit jump-table dispatches among *insns*.

    Returns the distinct case target VAs per dispatch ``jmp`` VA, in table
    order, and the table entries (address and byte index) inside *code*.
    The rules are :func:`build_cfg_view`'s.
    """

    end_va = va + len(code)
    tables: dict[int, list[int]] = {}
    entries: list[TableEntry] = []
    for i, insn in enumerate(insns):
        if insn.mnemonic != "jmp":
            continue
        operand = dispatch_operand(insn.op_str, _TABLE_ENTRY_WIDTH)
        if operand is None:
            continue
        index_reg, table_va = operand
        window = insns[max(0, i - BOUND_WINDOW) : i]
        slots = _negative_slots(insns, i, window, index_reg)
        bound: int | None
        if slots is not None:
            first_slot, bound = slots
        else:
            first_slot, bound = 0, index_bound(window, index_reg)
            byte_index = _byte_index_table(window, index_reg)
            if byte_index is not None:
                # The guard bounds the case value, and the index table's bytes
                # bound the address-table slot.
                base_reg, index_va = byte_index
                case_max = index_bound(window, base_reg)
                bound = None
                if case_max is not None:
                    index_bytes = _table_bytes(code, va, read_image, index_va, case_max + 1)
                    if len(index_bytes) == case_max + 1:
                        bound = max(index_bytes)
                        entries.extend(
                            TableEntry(index_va + k, 1, slot, k == 0)
                            for k, slot in enumerate(index_bytes)
                        )
        count = (
            MAX_TABLE_ENTRIES if bound is None else min(bound - first_slot + 1, MAX_TABLE_ENTRIES)
        )
        start_va = table_va + first_slot * _TABLE_ENTRY_WIDTH
        raw = _table_bytes(code, va, read_image, start_va, count * _TABLE_ENTRY_WIDTH)
        targets: list[int] = []
        slot_vas: list[int] = []
        values: dict[int, int] = {}
        for off in range(0, len(raw) - _TABLE_ENTRY_WIDTH + 1, _TABLE_ENTRY_WIDTH):
            target = int.from_bytes(raw[off : off + _TABLE_ENTRY_WIDTH], "little")
            values[start_va + off] = target
            if va <= target < end_va:
                targets.append(target)
                slot_vas.append(start_va + off)
            elif bound is None:
                break
        if targets:
            tables[insn.address] = list(dict.fromkeys(targets))
            entries.extend(
                TableEntry(at, _TABLE_ENTRY_WIDTH, values[at], at == slot_vas[0])
                for at in range(slot_vas[0], slot_vas[-1] + 1, _TABLE_ENTRY_WIDTH)
            )
    return tables, _inside(entries, va, end_va)


def _negative_slots(
    insns: list[Any], i: int, window: list[Any], index_reg: str | None
) -> tuple[int, int] | None:
    """``(first, last)`` table slot of a dispatch whose index is negative, else ``None``.

    MSVC's memcpy and memmove index two tables below their base.  After
    ``cmp ecx, N`` and ``neg ecx`` the index runs from ``-top`` to 0 (``top``
    is :func:`index_bound`'s).  A dispatch no instruction falls into, reached
    by ``sub ecx, K`` then ``jb dispatch``, runs from ``-K`` to -1.
    """
    if not index_reg:
        return None
    for k in range(len(window) - 1, -1, -1):
        prev = window[k]
        if prev.mnemonic in _COMPARES or prev.op_str.split(",")[0].strip() != index_reg:
            continue
        if prev.mnemonic == "neg":
            top = index_bound(window[:k], index_reg)
            return None if top is None else (-top, 0)
        break
    dispatch = insns[i]
    if (
        i > 0
        and _flows_into(insns[i - 1], dispatch)
        and insns[i - 1].mnemonic not in _BLOCK_END_MNEMONICS
    ):
        return None
    for j in range(1, len(insns)):
        jcc = insns[j]
        if jcc.mnemonic not in _BORROW_JUMPS or _jump_target_off(jcc, 0) != dispatch.address:
            continue
        sub = insns[j - 1]
        m = _SUB_IMM_RE.match(sub.op_str)
        if sub.mnemonic == "sub" and m is not None and m.group(1) == index_reg:
            k = int(m.group(2), 0)
            if 0 < k <= MAX_TABLE_ENTRIES:
                return -k, -1
    return None


def _inside(entries: list[TableEntry], va: int, end_va: int) -> list[TableEntry]:
    """*entries* wholly inside ``va..end_va``, in address order, one per byte.

    Tables sharing entries (memcpy's negative-index dispatch reads a table
    another dispatch indexes forward) give each entry once; an entry that
    overlaps an earlier one is dropped.
    """
    first_at: dict[int, bool] = {}
    by_va: dict[int, TableEntry] = {}
    for e in entries:
        if va <= e.va and e.va + e.width <= end_va:
            by_va.setdefault(e.va, e)
            first_at[e.va] = first_at.get(e.va, False) or e.first
    out: list[TableEntry] = []
    for at in sorted(by_va):
        e = by_va[at]
        if out and at < out[-1].va + out[-1].width:
            continue
        out.append(TableEntry(e.va, e.width, e.value, first_at[at]))
    return out


def _entry_ranges(entries: list[TableEntry], va: int) -> list[tuple[int, int]]:
    """The byte-offset ranges *entries* occupy, sorted and merged."""
    merged: list[tuple[int, int]] = []
    for e in entries:
        start, end = e.va - va, e.va - va + e.width
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _byte_index_table(window: list[Any], index_reg: str | None) -> tuple[str, int] | None:
    """``(case register, index table VA)`` when the nearest write to
    *index_reg* in *window* is a byte load ``[reg + table]``, else ``None``."""
    for prev in reversed(window):
        m = _BYTE_INDEX_RE.match(prev.op_str)
        if (
            prev.mnemonic in ("mov", "movzx")
            and m is not None
            and _FULL_REG.get(m.group(1), m.group(1)) == index_reg
        ):
            return m.group(2), int(m.group(3), 16)
    return None


def _table_bytes(code: bytes, va: int, read_image: ImageReader | None, at: int, size: int) -> bytes:
    """Up to *size* bytes at VA *at*: from *code* when it holds them all, else
    from *read_image*, else what *code* holds from *at* on (possibly none)."""
    off = at - va
    in_code = code[off : off + size] if 0 <= off < len(code) else b""
    if len(in_code) == size or read_image is None:
        return in_code
    return read_image(at, size)[:size]


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
        "first": instruction_text(first),
        "last": instruction_text(last),
        "start_idx": start_idx,
    }


def _jump_target_off(insn: Any, base_va: int) -> int | None:
    """Byte offset (into the code buffer) of a direct jump's target, else ``None``."""
    m = _JMP_TARGET_RE.search(insn.op_str)
    if not m:
        return None
    return int(m.group(1), 16) - base_va


def _add_edge(
    edges: list[tuple[int, int, str]],
    edge_set: set[tuple[int, int, str]],
    edge: tuple[int, int, str],
) -> None:
    """Append *edge* to *edges* unless it is already there.

    *edge_set* mirrors *edges* for membership; scanning the list itself made a
    self-jump chain quadratic in the block count (a run of ``jmp $`` is one
    block and one edge per 2 bytes, so a 32 KiB extent spent seconds).
    """
    if edge not in edge_set:
        edge_set.add(edge)
        edges.append(edge)


def _cosine_scaled(a: Counter[str], b: Counter[str], va: float, vb: float) -> float:
    """Cosine of two signatures with norms precomputed (invariant per sweep)."""
    if va == 0 or vb == 0:
        return 0.0
    denom = va * vb
    if not math.isfinite(denom) or denom <= 0.0:
        return 0.0
    raw = sum(a[k] * b[k] for k in a.keys() & b.keys()) / denom
    if not math.isfinite(raw):
        return 0.0
    return min(1.0, max(0.0, raw))


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

    # Greedy best-match blocks by mnemonic-multiset cosine, weighted by instruction count.
    sigs_t = [Counter(m) for _, _, m in tb]
    sigs_c = [Counter(m) for _, _, m in cb]
    norms_t = [math.sqrt(sum(v * v for v in s.values())) for s in sigs_t]
    norms_c = [math.sqrt(sum(v * v for v in s.values())) for s in sigs_c]
    sizes_t = [s for _, s, _ in tb]
    total_weights = sum(sizes_t)
    matched_c: set[int] = set()
    match_map: dict[int, int] = {}
    score_weight = 0.0
    # Order target blocks by size (largest first) for a stable greedy.
    for ti in sorted(range(len(tb)), key=lambda i: -sizes_t[i]):
        best_c, best_score = -1, 0.0
        for ci in range(len(cb)):
            if ci in matched_c:
                continue
            s = _cosine_scaled(sigs_t[ti], sigs_c[ci], norms_t[ti], norms_c[ci])
            if s > best_score:
                best_score, best_c = s, ci
        if best_c >= 0 and best_score > 0.0:
            matched_c.add(best_c)
            match_map[ti] = best_c
            score_weight += best_score * sizes_t[ti]

    node_sim = score_weight / total_weights if total_weights else 0.0

    # Edge similarity: Jaccard over mapped edges.  A target edge (a,b) matches
    # a candidate edge (c,d) when a→c and b→d are both matched pairs.
    edge_matches = 0
    ce_set = set(ce)
    for a, b in te:
        if a in match_map and b in match_map:
            ce_cand = match_map[b]
            if (match_map[a], ce_cand) in ce_set:
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
