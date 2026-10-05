"""near_analysis.py — classify WHY a NEAR_MATCHING function does not match.

Aligns a compiled function against its target bytes and classifies each
mismatching instruction span into a category of compiler choice:

- ``register``      — same instruction, different register allocation
- ``encoding``      — same instruction, same registers, different opcode
                      bytes (e.g. ``mov reg,reg`` as ``89 /r`` vs ``8b /r``)
- ``equivalent``    — semantically equivalent instruction selection (lea/add,
                      movzx/and, xor-zeroing, ...)
- ``reloc``         — span masked by COFF relocations that validated against
                      the target's name→VA catalog (same check as test/verify)
- ``structural``    — genuinely different instruction layout/blocking
- ``match``         — identical bytes

The verdict maps the dominant category to an actionable suggestion
(e.g. "register allocation — likely solvable via C-level tweaks").

The library half of the ``rebrew diagnose near`` command: it holds no Typer app
and writes nothing to a console, so the GA engine, ``probe`` and the command
itself all import it.  ``rebrew.near_diag`` owns the CLI.
"""

from __future__ import annotations

import logging
from typing import Any

import capstone  # module-level: per-call `import capstone` was ~half of analyze() time

from rebrew.analysis import (
    DEFAULT_CS_ARCH,
    DEFAULT_CS_MODE,
    Insn,
    disasm_insns,
    instruction_text,
    normalized_operands,
    resolve_capstone,
)
from rebrew.match_semantics import is_effective_match
from rebrew.pinned_diff import SequenceMatcherWithPins
from rebrew.stack_analysis import analyze_frame, compare_frames
from rebrew.utils import floor_pct

# Jump-equivalence checks — adapted from reccmp (isledecomp/reccmp, MIT
# License) ``compare/asm/fixes.py``: a flipped ``cmp`` operand order paired
# with the mirrored conditional jump, which register normalization does not
# catch.  Such spans are classified as ``equivalent`` instead of
# ``structural``.
#: Jump-mnemonic pairs compatible with a swapped cmp operand order.
ALLOWED_JUMP_SWAPS: tuple[tuple[str, str], ...] = (
    ("ja", "jb"),
    ("jae", "jbe"),
    ("jb", "ja"),
    ("jbe", "jae"),
    ("jg", "jl"),
    ("jge", "jle"),
    ("jl", "jg"),
    ("jle", "jge"),
    ("je", "je"),
    ("jne", "jne"),
)


def jump_swap_ok(a: str, b: str) -> bool:
    """True when a, b are both jumps compatible with a swapped cmp operand order."""
    (jmp_a, *_) = a.partition(" ")
    (jmp_b, *_) = b.partition(" ")
    return (jmp_a.lower(), jmp_b.lower()) in ALLOWED_JUMP_SWAPS


logger = logging.getLogger(__name__)


# Mnemonic families treated as semantically equivalent instruction selection.
_EQUIV_FAMILIES: dict[str, tuple[str, ...]] = {
    "mov": ("mov", "lea"),
    "lea": ("mov", "lea", "add"),
    "add": ("add", "lea", "inc"),
    "inc": ("add", "inc"),
    "sub": ("sub", "dec"),
    "dec": ("sub", "dec"),
    "movzx": ("movzx", "and"),
    "and": ("movzx", "and"),
    "xor": ("xor", "mov"),
    "test": ("test", "cmp"),
    "cmp": ("test", "cmp"),
    "je": ("je", "jz"),
    "jz": ("je", "jz"),
    "jne": ("jne", "jnz"),
    "jnz": ("jne", "jnz"),
}


def _is_x86_16_or_32(cs_arch: str | int, cs_mode: str | int) -> bool:
    """True when (arch, mode) are the x86 16/32-bit disassembly modes.

    Capstone mode values are arch-scoped (``CS_MODE_32 == CS_MODE_MIPS32 ==
    CS_MODE_PPC32 == 4``, ``CS_MODE_16 == CS_MODE_SH2 == 2``), so a mode-only
    check admits mips32/ppc32/sh2 and the x86-only frame/CFG analyzers would
    then disassemble those bytes as x86.
    """
    try:
        arch = resolve_capstone(cs_arch)
        mode = resolve_capstone(cs_mode)
    except (AttributeError, TypeError, ValueError):
        return False
    return arch == capstone.CS_ARCH_X86 and mode in (capstone.CS_MODE_16, capstone.CS_MODE_32)


def classify_pair(target: Insn, compiled: Insn) -> str:
    """Classify one aligned (target, compiled) instruction pair."""
    if target.raw == compiled.raw:
        return "match"
    # Mirrored conditional jump with the same displacement — the compiler
    # flipped the cmp operand order (reccmp's jump-swap equivalence).  Must
    # be checked before the same-mnemonic branch: ja/jb differ by mnemonic.
    if target.op_str == compiled.op_str and jump_swap_ok(
        f"{target.mnemonic} {target.op_str}", f"{compiled.mnemonic} {compiled.op_str}"
    ):
        return "equivalent"
    if target.mnemonic == compiled.mnemonic:
        if target.op_str == compiled.op_str:
            # Identical disassembly, different bytes → the same instruction
            # re-encoded with a different opcode form (mov reg,reg as 89 /r
            # vs 8b /r, add reg,reg as 01 /r vs 03 /r).  Not register churn —
            # register allocation is untouched.
            return "encoding"
        if normalized_operands(target) == normalized_operands(compiled):
            return "register"
        return "structural"
    if compiled.mnemonic in _EQUIV_FAMILIES.get(target.mnemonic, (target.mnemonic,)):
        return "equivalent"
    return "structural"


def _insn_reloc_bytes(insn: Insn, base: int, reloc_offsets: set[int]) -> bool:
    """True if any byte of *insn* (offset relative to *base*) is a reloc site."""
    off = insn.va - base
    return any(o in reloc_offsets for o in range(off, off + insn.size))


def _monotonic_pins(pins: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Drop crossing anchors, keeping *pins* strictly increasing on both sides.

    An instruction-reorder hunk (same instructions, different order) makes
    byte-identical anchors cross.  ``SequenceMatcherWithPins`` slices its
    islands by pin order and rejects crossing pins, so the reorder span
    would abort the whole diagnosis.  Dropping the crossing anchors leaves
    the remaining islands valid and diffable; the matcher's monotonicity
    guard keeps protecting direct callers.
    """
    mono: list[tuple[int, int]] = []
    last_a = last_b = -1
    for ai, bi in pins:
        if ai > last_a and bi > last_b:
            mono.append((ai, bi))
            last_a, last_b = ai, bi
    return mono


def _auto_pins(target_insns: list[Insn], compiled_insns: list[Insn]) -> list[tuple[int, int]]:
    """Anchor pairs for the pinned diff: byte-identical instructions whose
    raw encoding is unique on BOTH sides — reliable landmarks a register or
    encoding churn elsewhere cannot have produced."""
    from collections import Counter

    t_counts = Counter(i.raw for i in target_insns)
    c_counts = Counter(i.raw for i in compiled_insns)
    unique = {raw for raw, n in t_counts.items() if n == 1} & {
        raw for raw, n in c_counts.items() if n == 1
    }
    t_idx = {i.raw: n for n, i in enumerate(target_insns) if i.raw in unique}
    pins = [(t_idx[c.raw], n) for n, c in enumerate(compiled_insns) if c.raw in unique]
    return _monotonic_pins(pins)


def align_and_classify(
    target_insns: list[Insn],
    compiled_insns: list[Insn],
    reloc_offsets: set[int],
) -> tuple[dict[str, int], dict[str, Any] | None]:
    """Align both instruction streams and classify every byte.

    The mnemonic LCS only decides *pairing*; every aligned pair is then
    classified individually (identical bytes → match, same mnemonic with
    different registers → register, semantic-family swap → equivalent,
    mirrored conditional jump → equivalent, anything else → structural).
    Unique byte-identical instructions pin the alignment
    (:class:`~rebrew.pinned_diff.SequenceMatcherWithPins`), so structural
    churn in one island cannot scramble later blocks.  Target bytes at
    relocation sites are neutralised and counted as ``reloc``.  Unpaired
    target instructions (insertion/deletion) count as structural.

    Returns ``(byte_counts, first_mismatch)`` — *first_mismatch* is the
    earliest non-match (dtk ``dol diff``-style decisive diagnosis): the
    ``offset`` of the first differing instruction with its ``category`` and
    the target/compiled text, or ``None`` when everything matches.
    """
    base = target_insns[0].va if target_insns else (compiled_insns[0].va if compiled_insns else 0)
    matcher = SequenceMatcherWithPins(
        a=[i.mnemonic for i in compiled_insns],
        b=[i.mnemonic for i in target_insns],
        pinned_lines=_auto_pins(target_insns, compiled_insns),
    )
    byte_counts: dict[str, int] = {
        "match": 0,
        "register": 0,
        "encoding": 0,
        "equivalent": 0,
        "reloc": 0,
        "structural": 0,
    }
    first_mismatch: dict[str, Any] | None = None

    def _note(offset: int, category: str, target_text: str, compiled_text: str) -> None:
        nonlocal first_mismatch
        if first_mismatch is None:
            first_mismatch = {
                "offset": offset,
                "category": category,
                "target": target_text,
                "compiled": compiled_text,
            }

    for op in matcher.get_opcodes():
        a0, a1, b0, b1 = op.a_start, op.a_end, op.b_start, op.b_end
        comp_span = compiled_insns[a0:a1]
        tgt_span = target_insns[b0:b1]
        if len(tgt_span) == len(comp_span) and tgt_span:
            for t, c in zip(tgt_span, comp_span, strict=True):
                if _insn_reloc_bytes(t, base, reloc_offsets):
                    byte_counts["reloc"] += t.size
                else:
                    cat = classify_pair(t, c)
                    byte_counts[cat] += t.size
                    if cat != "match":
                        _note(t.va, cat, instruction_text(t), instruction_text(c))
        elif tgt_span or comp_span:
            # Insertion/deletion: the longer side's extra bytes are structural.
            if len(tgt_span) > len(comp_span):
                extra = tgt_span
                _note(extra[0].va, "structural", instruction_text(extra[0]), "")
            else:
                extra = comp_span
                _note(extra[0].va, "structural", "", instruction_text(extra[0]))
            byte_counts["structural"] += sum(i.size for i in extra)

    return byte_counts, first_mismatch


#: Per-category actionable suggestion text — module-level so the symptom
#: catalog (:func:`catalog_markdown`) can render it alongside the mutations.
_VERDICT_SUGGESTIONS: dict[str, str] = {
    "register": "Register allocation differs — try reordering expressions, "
    "swapping loop counters, or splitting/merging statements.  Register "
    "gaps are usually PROVEN-able: run 'rebrew prove' to establish "
    "semantic equivalence without byte changes.",
    "encoding": "Encoding choice differs — same instructions, same registers, "
    "different opcode bytes.  Byte-identity needs the original compiler "
    "version's encodings, or 'rebrew prove' for PROVEN equivalence.",
    "equivalent": "Instruction selection differs — try alternative C constructs "
    "(e.g. pointer arithmetic vs indexing, cast-based masking).",
    "reloc": "Difference is confined to relocation sites — the match is RELOC-level.",
    "structural": "Control flow / block layout differs — try restructuring loops "
    "or if/else; may need a compiler-pattern workaround.",
}


def _verdict(counts: dict[str, int], raw_total: int) -> tuple[str, str]:
    """Map byte-count distribution to a verdict (label, suggestion)."""
    if raw_total <= 0:
        return "MATCH", "No instructions to compare."
    non_match = raw_total - counts.get("match", 0)
    if non_match <= 0:
        return "MATCH", "Bytes are identical."
    # ENCODING-ONLY: the strictest near-match class — identical disassembly,
    # only the opcode bytes differ.  No C tweak changes a compiler's encoding
    # preference; only the exact compiler version (or PROVEN) closes this.
    # Effective/encoding-only verdicts take priority over the dominant-
    # category logic below (original near-diag semantics, now expressed via
    # the shared classifier in match_semantics).
    encoding = counts.get("encoding", 0)
    structural = counts.get("structural", 0)
    equivalent = counts.get("equivalent", 0)
    register = counts.get("register", 0)
    if structural == 0 and equivalent == 0 and register == 0 and encoding > 0:
        return (
            "ENCODING-ONLY (same instructions, different opcode bytes)",
            "Every differing byte is the same instruction re-encoded with "
            "a different opcode form — semantically identical, but NOT "
            "byte-identical.  Byte-identity needs the original compiler "
            "version's encodings, or 'rebrew prove' for PROVEN "
            "equivalence.",
        )
    # Effective match (reccmp parity): every real delta byte is register
    # allocation and/or encoding choice — same instructions, no structural
    # churn, no instruction-selection swaps, no invalid relocs (reloc bytes
    # are masked before classification).  reccmp counts this as a 100%
    # effective match; rebrew keeps it a real (non-byte-identical)
    # NEAR_MATCHING with a named cause.  Classification is shared with
    # verify (match_semantics); encoding-only deltas are handled above.
    if is_effective_match(
        structural=structural,
        register=register,
        equivalent=equivalent,
    ):
        return (
            "EFFECTIVE (matches modulo register allocation)",
            "Every differing byte is a register-allocation difference — the "
            "same instructions, different registers.  reccmp counts this as a "
            "100% effective match, but it is NOT byte-identical: 'rebrew "
            "prove' can establish semantic equivalence (PROVEN), or try "
            "register-nudging C tweaks (reorder expressions, swap loop "
            "counters) if byte-identity is required.",
        )
    dominant = max(
        ("register", "equivalent", "reloc", "structural", "encoding"),
        key=lambda k: counts.get(k, 0),
    )
    share = counts[dominant] / non_match
    suggestions = _VERDICT_SUGGESTIONS
    label = f"{dominant.upper()} ({(share * 100):.0f}% of delta)"
    suggestion = suggestions[dominant]
    # A RELOC-dominant verdict is only "RELOC-level" when there are NO real
    # bytes left over — the invalid-reloc sites surface as structural after
    # the DIR32/REL32 catalog validation.  Equivalent/register/encoding bytes
    # are real deltas too (canonical test/verify calls the pair NEAR_MATCHING),
    # so "the match is RELOC-level" must not be claimed for any of them.
    if dominant == "reloc" and non_match > counts["reloc"]:
        # Say which unit this is.  These counts are INSTRUCTION-GRANULAR: a
        # differing instruction contributes its whole size to a category, so
        # the figure does not equal `rebrew test`'s byte delta and can land
        # either side of it (guild-rebrew: 56 vs 28 on one function, 13 vs 15
        # on another).  Readers reconciled those by hand twice before this
        # said so; see guild-rebrew docs/msvc6-c-shapes.md section 108
        # (sibling repo; not shipped under this tree's docs/).
        suggestion = (
            "Most of the delta sits at relocation sites, but "
            f"{non_match - counts['reloc']} real byte(s) differ (instruction-"
            "granular; compare `rebrew test` for the masked byte delta) — the "
            "match is NEAR_MATCHING-level, not RELOC: inspect the structural "
            "spans (likely a wrong call target or global address)."
        )
    # When a secondary category is also significant, mention it too — e.g.
    # structural churn WITH register allocation noise is a different fix
    # than structural churn alone.
    secondary = max(
        (k for k in counts if k not in (dominant, "match")),
        key=lambda k: counts[k],
        default=None,
    )
    if secondary is not None and counts[secondary] / non_match >= 0.25:
        hint = suggestions[secondary].split("—")[0].strip()
        if hint:
            hint = hint[0].lower() + hint[1:]
        suggestion = f"{suggestion} Also: {hint}."
    return label, suggestion


#: Blocker category → the GA mutation operators most likely to fix it.
#: Advisory only — the GA still explores the whole operator set; this tells
#: a human (or an agent) where to start.  Categories in the verdict space
#: must each have at least one suggestion (enforced by test).
MUTATION_SUGGESTIONS: dict[str, list[str]] = {
    "register": [
        "mut_reorder_register_vars",
        "mut_swap_register_keywords",
        "mut_add_register_keyword",
        "mut_toggle_volatile",
        "mut_hoist_repeated_deref",
        "mut_inject_dummy_var",
        "mut_inject_dummy_array",
        "mut_scope_variable",
        "mut_reorder_declarations",
        "mut_swap_adjacent_stmts",
    ],
    "equivalent": [
        "mut_array_to_ptr_arith",
        "mut_ptr_arith_to_array",
        "mut_change_array_index_order",
        "mut_struct_vs_ptr_access",
        "mut_add_cast",
        "mut_remove_cast",
        "mut_toggle_signedness",
        "mut_if_false_to_bitand",
        "mut_fold_constant_add",
        "mut_unfold_constant_add",
        "mut_combine_ptr_arith",
        "mut_decouple_index_math",
    ],
    "structural": [
        "mut_swap_if_else",
        "mut_guard_clause",
        "mut_hoist_return",
        "mut_sink_return",
        "mut_return_to_goto",
        "mut_while_to_dowhile",
        "mut_dowhile_to_while",
        "mut_for_to_while",
        "mut_while_to_for",
        "mut_invert_loop_direction",
        "mut_duplicate_loop_body",
        "mut_hoist_common_tail",
        "mut_sink_common_tail",
        "mut_invert_if_else",
        "mut_if_to_ternary",
        "mut_ternary_to_if",
    ],
    # RELOC-level deltas are already masked by relocations — no mutation helps.
    "reloc": [],
    # Encoding-only deltas are a compiler-version artifact — no C mutation
    # changes the opcode form the compiler picks (same semantics, same
    # registers).  PROVEN or the exact original toolchain is the answer.
    "encoding": [],
}


def mutation_suggestions(dominant_category: str) -> list[str]:
    """The GA operators most likely to fix *dominant_category* (advisory)."""
    return list(MUTATION_SUGGESTIONS.get(dominant_category, []))


def catalog_markdown() -> str:
    """Render the near-diag symptom index (Kuna-style) as Markdown.

    Maps each delta category — the *symptom* a user/agent sees in the
    verdict — to the actionable suggestion and the GA mutation operators
    most likely to fix it.  Generated from the same registry the verdict
    logic uses, so it cannot drift.
    """
    rows: list[str] = []
    for category in ("register", "encoding", "equivalent", "structural", "reloc"):
        suggestion = _VERDICT_SUGGESTIONS.get(category, "")
        ops = mutation_suggestions(category)
        ops_text = ", ".join(f"`{op}`" for op in ops) if ops else "— (no mutation helps)"
        rows.append(f"| `{category}` | {suggestion} | {ops_text} |")
    rows.append(
        "| `effective` | Same instructions, different registers (not "
        "byte-identical) — `rebrew prove` for PROVEN, or register-nudging C "
        "tweaks | " + ", ".join(f"`{op}`" for op in mutation_suggestions("register")) + " |"
    )
    rows.append("| `match` | Bytes are identical — nothing to fix | — |")
    return (
        "# near-diag symptom index\n\n"
        "Generated from the verdict registry (`rebrew diagnose near --catalog`).  "
        "When a function is NEAR_MATCHING, the verdict names the dominant "
        "delta category; the row below gives the actionable suggestion and "
        "the GA mutation operators most likely to close the gap.\n\n"
        "| Symptom (verdict category) | What it means / what to do | GA mutations to try |\n"
        "|---|---|---|\n" + "\n".join(rows) + "\n"
    )


def blocker_text(result: dict[str, Any]) -> str:
    """The BLOCKER metadata text for a non-MATCH verdict.

    ``NEAR_MATCHING — <verdict>: <suggestion>`` — with the top GA mutation
    operators inserted between them when present: the mutations are the
    actionable next step, so they outrank the prose tail of the suggestion
    when the 200-char budget runs out (the full suggestion stays visible in
    near-diag's live output).
    """
    verdict = result.get("verdict", "")
    suggestion = result.get("suggestion", "")
    mutations = result.get("mutations") or []
    text = f"NEAR_MATCHING — {verdict}"
    if mutations:
        text += " — try: " + ", ".join(mutations[:5])
    if suggestion:
        if len(text) + len(suggestion) + 2 <= 200:
            text += f": {suggestion}"
        else:
            # Only the suggestion's first sentence survives a tight budget.
            head = suggestion.split(".")[0].strip() + "."
            if len(text) + len(head) + 2 <= 200:
                text += f": {head}"
    return text[:200]


def analyze(
    target_bytes: bytes,
    compiled_bytes: bytes,
    reloc_offsets: set[int] | None,
    va: int,
    cs_arch: str = DEFAULT_CS_ARCH,
    cs_mode: str = DEFAULT_CS_MODE,
) -> dict[str, Any]:
    """Full classification of a NEAR_MATCHING pair.

    *reloc_offsets* is the set of VALIDATED relocation sites (offsets that
    survived the same DIR32/REL32 address check as ``rebrew test``).
    """
    target_insns = disasm_insns(target_bytes, va, cs_arch, cs_mode)
    compiled_insns = disasm_insns(compiled_bytes, va, cs_arch, cs_mode)
    reloc_set = set(reloc_offsets or {})
    counts, first_mismatch = align_and_classify(target_insns, compiled_insns, reloc_set)
    raw_total = sum(counts.values())
    label, suggestion = _verdict(counts, raw_total)
    # ``raw_total`` is the reported byte count and stays 0 when nothing
    # disassembles.  The percent denominator is a separate value so the
    # divide guard never becomes a reported figure: sharing one variable made
    # a zero-instruction pair report ``bytes: 1``.
    denom = raw_total or 1
    dominant = label.split(" (")[0].lower() if label != "MATCH" else "match"
    if dominant == "effective":
        # The EFFECTIVE verdict IS register allocation — reuse the register
        # category's mutation list (reordering expressions, swapping loop
        # counters) as the actionable next step.
        dominant = "register"
    elif dominant == "encoding-only":
        # ENCODING-ONLY has no fixable mutation list (compiler-version
        # artifact) — the category's empty list is the answer.
        dominant = "encoding"
    mutations = mutation_suggestions(dominant)
    # A significant secondary category (>=15% of the delta, e.g. a register
    # component under a STRUCTURAL verdict) deserves its operators too — the
    # dominant-only list would otherwise miss the register fix entirely.
    non_match = raw_total - counts["match"]
    if non_match > 0:
        secondary = max(
            (k for k in counts if k not in (dominant, "match", "reloc")),
            key=lambda k: counts[k],
            default=None,
        )
        if secondary and counts[secondary] / non_match >= 0.15:
            for op in mutation_suggestions(secondary):
                if op not in mutations:
                    mutations.append(op)
    return {
        "va": f"0x{va:08x}",
        "target_insns": len(target_insns),
        "compiled_insns": len(compiled_insns),
        "bytes": raw_total,
        "categories": {k: {"bytes": v, "percent": floor_pct(v, denom)} for k, v in counts.items()},
        "verdict": label,
        "suggestion": suggestion,
        "mutations": mutations,
        "first_mismatch": first_mismatch,
        "frame": _frame_comparison(target_bytes, compiled_bytes, va, cs_arch, cs_mode),
        "cfg": _cfg_score(target_bytes, compiled_bytes, va, cs_mode, cs_arch),
    }


def _cfg_score(
    target_bytes: bytes,
    compiled_bytes: bytes,
    va: int,
    cs_mode: str | int,
    cs_arch: str | int = DEFAULT_CS_ARCH,
) -> dict[str, Any] | None:
    """CFG structural similarity (cfg_ged) for the pair — best-effort.

    A control-flow-aware complement to the byte classification: identical
    structure with different registers scores high, a loop-vs-linear flow
    mismatch scores low.  ``None`` for non-x86 modes or when disassembly
    fails — never raises.
    """
    try:
        if not _is_x86_16_or_32(cs_arch, cs_mode):
            return None
        mode = resolve_capstone(cs_mode)
        from rebrew.cfg_ged import cfg_similarity

        return cfg_similarity(target_bytes, compiled_bytes, va, mode)
    except Exception:  # cfg info is best-effort
        logger.debug("CFG similarity failed at 0x%08x", va, exc_info=True)
        return None


def _frame_comparison(
    target_bytes: bytes,
    compiled_bytes: bytes,
    va: int,
    cs_arch: str | int,
    cs_mode: str | int,
) -> dict[str, Any] | None:
    """Stack-frame comparison (stack-cmp) for the pair — best-effort.

    Derived from disassembly on both sides (no PDB).  A frame delta is a
    per-function flag symptom (/Oy, /O1 vs /O2, /Gs, calling convention) and
    complements the register/structural byte classification.  ``None`` for
    non-x86 modes or when disassembly fails — never raises.
    """
    try:
        if not _is_x86_16_or_32(cs_arch, cs_mode):
            return None
        mode = resolve_capstone(cs_mode)

        return compare_frames(
            analyze_frame(target_bytes, va, mode),
            analyze_frame(compiled_bytes, va, mode),
        )
    except Exception:  # frame info is best-effort
        logger.debug("frame comparison failed at 0x%08x", va, exc_info=True)
        return None
