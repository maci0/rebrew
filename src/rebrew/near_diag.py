"""near_diag.py — classify WHY a NEAR_MATCHING function does not match.

Compiles the C source, extracts the target bytes, and classifies each
mismatching instruction span into a category of compiler choice:

- ``register``      — same instruction, different register allocation
- ``equivalent``    — semantically equivalent instruction selection (lea/add,
                      movzx/and, xor-zeroing, ...)
- ``reloc``         — span masked by COFF relocations that validated against
                      the target's name→VA catalog (same check as test/verify)
- ``structural``    — genuinely different instruction layout/blocking
- ``match``         — identical bytes

The verdict maps the dominant category to an actionable suggestion
(e.g. "register allocation — likely solvable via C-level tweaks").
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
)

console = Console(stderr=True)

_DEFAULT_CS_ARCH = "CS_ARCH_X86"
_DEFAULT_CS_MODE = "CS_MODE_32"

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

# x86-32 general-purpose register names, collapsed to ``R`` when comparing operands.
_REGISTER_RE = re.compile(
    r"\b(eax|ebx|ecx|edx|esi|edi|ebp|esp|al|bl|cl|dl|ah|bh|ch|dh)\b",
)


class Insn:
    """Minimal instruction view for classification."""

    __slots__ = ("addr", "mnemonic", "op_str", "bytes", "size")

    def __init__(self, addr: int, mnemonic: str, op_str: str, raw: bytes) -> None:
        self.addr = addr
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = raw
        self.size = len(raw)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Insn {self.addr:08x} {self.mnemonic} {self.op_str}>"


def disasm_insns(
    code: bytes,
    va: int,
    cs_arch: str | int = _DEFAULT_CS_ARCH,
    cs_mode: str | int = _DEFAULT_CS_MODE,
) -> list[Insn]:
    """Disassemble *code* into :class:`Insn` records.

    *cs_arch*/*cs_mode* accept capstone constant-name strings (the module
    defaults), the int constants that ``cfg.capstone_arch``/``cfg.capstone_mode``
    return, or a bare numeric string ("3") — both config styles must work.
    """
    import capstone

    def _resolve(value: str | int) -> int:
        if isinstance(value, int):
            return value
        try:
            return int(getattr(capstone, value))
        except (AttributeError, TypeError):
            # A numeric string ("3") is a valid capstone constant.
            return int(value)

    md = capstone.Cs(_resolve(cs_arch), _resolve(cs_mode))
    md.detail = False
    return [Insn(i.address, i.mnemonic, i.op_str, bytes(i.bytes)) for i in md.disasm(code, va)]


def _normalized_operands(insn: Insn) -> str:
    """Operand string with register names stripped — detects register-alloc churn.

    ``mov eax, ebx`` vs ``mov ecx, edx`` both normalise to ``mov R, R``.
    """
    return _REGISTER_RE.sub("R", insn.op_str)


def _equiv_class(mnemonic: str) -> tuple[str, ...]:
    return _EQUIV_FAMILIES.get(mnemonic, (mnemonic,))


def classify_pair(target: Insn, compiled: Insn) -> str:
    """Classify one aligned (target, compiled) instruction pair."""
    if target.bytes == compiled.bytes:
        return "match"
    if target.mnemonic == compiled.mnemonic:
        if _normalized_operands(target) == _normalized_operands(compiled):
            return "register"
        return "structural"
    if compiled.mnemonic in _equiv_class(target.mnemonic):
        return "equivalent"
    return "structural"


def _insn_reloc_bytes(insn: Insn, base: int, reloc_offsets: set[int]) -> bool:
    """True if any byte of *insn* (offset relative to *base*) is a reloc site."""
    off = insn.addr - base
    return any(o in reloc_offsets for o in range(off, off + insn.size))


def align_and_classify(
    target_insns: list[Insn],
    compiled_insns: list[Insn],
    reloc_offsets: set[int],
) -> dict[str, int]:
    """Align both instruction streams and classify every byte.

    The mnemonic LCS only decides *pairing*; every aligned pair is then
    classified individually (identical bytes → match, same mnemonic with
    different registers → register, semantic-family swap → equivalent,
    anything else → structural).  Target bytes at relocation sites are
    neutralised and counted as ``reloc``.  Unpaired target instructions
    (insertion/deletion) count as structural.
    """
    base = target_insns[0].addr if target_insns else 0
    match = difflib.SequenceMatcher(
        a=[i.mnemonic for i in compiled_insns],
        b=[i.mnemonic for i in target_insns],
        autojunk=False,
    )
    byte_counts: dict[str, int] = {
        "match": 0,
        "register": 0,
        "equivalent": 0,
        "reloc": 0,
        "structural": 0,
    }

    for _op, a0, a1, b0, b1 in match.get_opcodes():
        comp_span = compiled_insns[a0:a1]
        tgt_span = target_insns[b0:b1]
        if len(tgt_span) == len(comp_span) and tgt_span:
            for t, c in zip(tgt_span, comp_span, strict=True):
                if _insn_reloc_bytes(t, base, reloc_offsets):
                    byte_counts["reloc"] += t.size
                else:
                    byte_counts[classify_pair(t, c)] += t.size
        elif tgt_span or comp_span:
            # Insertion/deletion: the longer side's extra bytes are structural.
            extra = tgt_span if len(tgt_span) > len(comp_span) else comp_span
            byte_counts["structural"] += sum(i.size for i in extra)

    return byte_counts


def _verdict(counts: dict[str, int], raw_total: int) -> tuple[str, str]:
    """Map byte-count distribution to a verdict (label, suggestion)."""
    if raw_total <= 0:
        return "MATCH", "No instructions to compare."
    non_match = raw_total - counts["match"]
    if non_match <= 0:
        return "MATCH", "Bytes are identical."
    dominant = max(("register", "equivalent", "reloc", "structural"), key=lambda k: counts[k])
    share = counts[dominant] / non_match
    suggestions = {
        "register": "Register allocation differs — try reordering expressions, "
        "swapping loop counters, or splitting/merging statements.  Register "
        "gaps are usually PROVEN-able: run 'rebrew prove' to establish "
        "semantic equivalence without byte changes.",
        "equivalent": "Instruction selection differs — try alternative C constructs "
        "(e.g. pointer arithmetic vs indexing, cast-based masking).",
        "reloc": "Difference is confined to relocation sites — the match is RELOC-level.",
        "structural": "Control flow / block layout differs — try restructuring loops "
        "or if/else; may need a compiler-pattern workaround.",
    }
    label = f"{dominant.upper()} ({(share * 100):.0f}% of delta)"
    suggestion = suggestions[dominant]
    # A RELOC-dominant verdict is only "RELOC-level" when there are NO real
    # bytes left over — the invalid-reloc sites surface as structural after
    # the DIR32/REL32 catalog validation.  Saying "the match is RELOC-level"
    # for a function whose canonical status is NEAR_MATCHING (real bytes
    # differ) misleads; name the real deltas instead.
    if dominant == "reloc" and counts["structural"] > 0:
        suggestion = (
            "Most of the delta sits at relocation sites, but "
            f"{counts['structural']} real byte(s) differ — the match is "
            "NEAR_MATCHING-level, not RELOC: inspect the structural spans "
            "(likely a wrong call target or global address)."
        )
    # When a secondary category is also significant, mention it too — e.g.
    # structural churn WITH register allocation noise is a different fix
    # than structural churn alone.
    secondary = max((k for k in counts if k != dominant and k != "match"), key=lambda k: counts[k])
    if counts[secondary] / non_match >= 0.25:
        hint = suggestions[secondary].split("—")[0].strip()
        if hint:
            hint = hint[0].lower() + hint[1:]
        suggestion = f"{suggestion} Also: {hint}."
    return label, suggestion


#: Blocker category → the GA mutation operators most likely to fix it.
#: Advisory only — the GA still explores the whole operator set; this tells
#: a human (or an agent) where to start.  Categories in the verdict space
#: must each have at least one suggestion (enforced by test).
_MUTATION_SUGGESTIONS: dict[str, list[str]] = {
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
}


def mutation_suggestions(dominant_category: str) -> list[str]:
    """The GA operators most likely to fix *dominant_category* (advisory)."""
    return list(_MUTATION_SUGGESTIONS.get(dominant_category, []))


def _blocker_text(result: dict[str, Any]) -> str:
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
    reloc_offsets: dict[int, str] | set[int] | None,
    va: int,
    cs_arch: str = _DEFAULT_CS_ARCH,
    cs_mode: str = _DEFAULT_CS_MODE,
) -> dict[str, Any]:
    """Full classification of a NEAR_MATCHING pair.

    *reloc_offsets* is the set of VALIDATED relocation sites (offsets that
    survived the same DIR32/REL32 address check as ``rebrew test``); offsets
    may also arrive as the raw ``offset → symbol`` dict for backward compat.
    """
    target_insns = disasm_insns(target_bytes, va, cs_arch, cs_mode)
    compiled_insns = disasm_insns(compiled_bytes, va, cs_arch, cs_mode)
    reloc_set = set(reloc_offsets or {})
    counts = align_and_classify(target_insns, compiled_insns, reloc_set)
    raw_total = sum(counts.values())
    label, suggestion = _verdict(counts, raw_total)
    total = raw_total or 1
    dominant = label.split(" (")[0].lower() if label != "MATCH" else "match"
    mutations = mutation_suggestions(dominant)
    # A significant secondary category (>=15% of the delta, e.g. a register
    # component under a STRUCTURAL verdict) deserves its operators too — the
    # dominant-only list would otherwise miss the register fix entirely.
    non_match = raw_total - counts["match"]
    if non_match > 0:
        secondary = max(
            (k for k in counts if k != dominant and k != "match" and k != "reloc"),
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
        "bytes": total,
        "categories": {
            k: {"bytes": v, "percent": round(v / total * 100, 1)} for k, v in counts.items()
        },
        "verdict": label,
        "suggestion": suggestion,
        "mutations": mutations,
    }


class _DiagnoseError(RuntimeError):
    """Raised when a single function cannot be diagnosed (extract/compile/parse)."""


def _diagnose_one(
    cfg: Any,
    source_path: Path,
    ann: Any,
    va_int: int,
    size_val: int,
    fix_blocker: bool,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Compile and classify ONE function; returns the analysis result.

    The result dict gains a ``blocker_written`` key (bool).  Raises
    :class:`_DiagnoseError` when the target bytes cannot be extracted or the
    source does not compile — single mode turns that into an error_exit,
    batch mode records it per-function and keeps going.
    """
    import tempfile

    from rebrew.binary_loader import extract_raw_bytes
    from rebrew.cli import resolve_cflags
    from rebrew.compile import compile_to_obj
    from rebrew.core import build_iat_region, build_name_to_va, smart_reloc_compare
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size_val)
    if not target_bytes:
        raise _DiagnoseError(f"Failed to extract target bytes at 0x{va_int:08x}")

    cflags = resolve_cflags(cfg, ann.cflags, getattr(ann, "module", ""))
    with tempfile.TemporaryDirectory(prefix="rebrew_near_diag_") as workdir:
        obj_path, err = compile_to_obj(cfg, source_path, cflags.split(), workdir)
        if obj_path is None:
            raise _DiagnoseError(f"Compile error: {err}")
        symbol = ann.symbol or ""
        compiled_bytes, reloc_dict, full_relocs = parse_obj_symbol_and_relocs(obj_path, symbol)
        if compiled_bytes is None:
            raise _DiagnoseError(f"Symbol '{symbol or '(none)'}' not found in compiled .obj")

    # Mask ONLY the relocation sites that survive the same DIR32/REL32 address
    # validation as `rebrew test` / `rebrew verify` — an invalid reloc (wrong
    # call target or global address) is a REAL byte delta, not reloc noise.
    # Without this, near-diag reported "RELOC-level" for functions the
    # canonical status path classifies NEAR_MATCHING (e.g. _CreateListenSocket
    # in guild: 8 real bytes beyond the validated reloc sites).
    reloc_offsets: set[int] = set()
    coff_relocs = full_relocs if full_relocs else reloc_dict
    if coff_relocs:
        name_to_va = build_name_to_va(cfg)
        cmp_obj = compiled_bytes
        cmp_tgt = target_bytes
        if len(cmp_obj) > len(cmp_tgt):
            cmp_obj = cmp_obj[: len(cmp_tgt)]
        else:
            cmp_tgt = cmp_tgt[: len(cmp_obj)]
        if cmp_obj:
            _matched, _mc, _tot, valid_relocs, _invalid = smart_reloc_compare(
                cmp_obj,
                cmp_tgt,
                coff_relocs,
                name_to_va=name_to_va,
                section_va=va_int,
                iat_region=build_iat_region(cfg),
            )
            reloc_offsets = set(valid_relocs)

    result = analyze(
        target_bytes,
        compiled_bytes,
        reloc_offsets,
        va_int,
        cs_arch=getattr(cfg, "capstone_arch", _DEFAULT_CS_ARCH),
        cs_mode=getattr(cfg, "capstone_mode", _DEFAULT_CS_MODE),
    )
    blocker_written = False
    if fix_blocker and not result["verdict"].startswith("MATCH"):
        if dry_run:
            blocker_written = True  # would write, but --dry-run skips it
        else:
            from rebrew.metadata import set_field, update_source_status

            set_field(cfg.metadata_dir, va_int, "blocker", _blocker_text(result), module=ann.module)
            # A blocker note implies NEAR_MATCHING — keep the documented state
            # consistent so status reports count it as documented, not as a
            # bare STUB (previously the status stayed missing/STUB while the
            # blocker said NEAR_MATCHING).
            update_source_status(
                cfg.metadata_dir,
                "NEAR_MATCHING",
                ann.module,
                va_int,
                clear_blockers=False,
            )
            blocker_written = True
    result["blocker_written"] = blocker_written
    return result


def _run_all_batch(cfg: Any, fix_blocker: bool, json_output: bool, dry_run: bool = False) -> None:
    """Classify every NEAR_MATCHING function in the project (--all).

    Mirrors ``prove --all`` collection: iterate sources, keep annotations with
    status NEAR_MATCHING and a known size.  Per-function failures are recorded
    in the results list instead of aborting the batch.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.cli import iter_sources, target_marker

    sources = list(iter_sources(cfg.reversed_dir, cfg))
    tm = target_marker(cfg)
    candidates: list[tuple[Path, Any]] = []
    skipped_files: list[str] = []
    for src in sources:
        try:
            annos = parse_c_file_multi(src, target_name=tm, metadata_dir=cfg.metadata_dir)
        except Exception as exc:  # noqa: BLE001 — one bad file must not kill the batch
            skipped_files.append(f"{src.name}: {exc}")
            continue
        for a in annos:
            if a.status == "NEAR_MATCHING" and a.size:
                candidates.append((src, a))

    if not candidates:
        if json_output:
            json_print(
                {
                    "total": 0,
                    "classified": 0,
                    "failed": 0,
                    "skipped_files": skipped_files,
                    "results": [],
                }
            )
        else:
            console.print("[dim]No NEAR_MATCHING functions found to diagnose.[/dim]")
            for skip in skipped_files:
                console.print(f"[yellow]  skipped: {skip}[/yellow]")
        return

    if not json_output:
        console.print(f"\n[bold]Diagnosing {len(candidates)} NEAR_MATCHING function(s)[/bold]\n")

    classified = 0
    failed = 0
    results: list[dict[str, Any]] = []
    for i, (src, ann) in enumerate(candidates, 1):
        symbol = ann.symbol or src.name
        if not json_output:
            console.print(f"[bold][{i}/{len(candidates)}][/bold] {symbol} (0x{ann.va:08x})")
        entry: dict[str, Any] = {
            "source": str(src),
            "symbol": symbol,
            "va": f"0x{ann.va:08x}",
            "verdict": None,
            "suggestion": None,
            "mutations": [],
            "blocker_written": False,
            "error": None,
        }
        try:
            result = _diagnose_one(cfg, src, ann, ann.va, ann.size, fix_blocker, dry_run)
        except _DiagnoseError as e:
            failed += 1
            if not json_output:
                console.print(f"  [yellow]ERROR:[/yellow] {e}")
            entry["error"] = str(e)
            results.append(entry)
            continue
        classified += 1
        if not json_output:
            console.print(f"  [bold]{result['verdict']}[/bold] — {result['suggestion'][:60]}")
            if result.get("mutations"):
                console.print(
                    "    [dim]GA mutations to try:[/dim] " + ", ".join(result["mutations"])
                )
        entry.update(
            {
                "verdict": result["verdict"],
                "suggestion": result["suggestion"],
                "mutations": result.get("mutations", []),
                "blocker_written": result["blocker_written"],
            }
        )
        results.append(entry)

    if json_output:
        json_print(
            {
                "total": len(candidates),
                "classified": classified,
                "failed": failed,
                "skipped_files": skipped_files,
                "results": results,
            }
        )
        return

    console.print()
    if skipped_files:
        console.print(
            f"[yellow]  {len(skipped_files)} source file(s) skipped (unparseable):[/yellow]"
        )
        for skip in skipped_files[:5]:
            console.print(f"    {skip}")
    console.print("[bold]━━━ near-diag Summary ━━━[/bold]")
    console.print(f"  [bold]{classified}[/bold] classified")
    if failed:
        console.print(f"  [yellow bold]{failed}[/yellow bold] failed")
    if fix_blocker:
        written = sum(1 for r in results if r["blocker_written"])
        verb = "would write" if dry_run else "written"
        console.print(f"  [green bold]{written}[/green bold] BLOCKER metadata {verb}")


app = typer.Typer(
    help="Classify why a NEAR_MATCHING function does not byte-match.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew near-diag src/game/func.c · · · · · Classify the delta\n\n"
        "  rebrew near-diag src/game/func.c --json · · Machine-readable\n\n"
        "  rebrew near-diag --all --fix-blocker · · · Classify + document all NEAR_MATCHING\n\n"
        "[dim]Categories: register (same insn, different regs), equivalent\n"
        "(semantically equal instruction selection), reloc (relocation-masked),\n"
        "structural (different layout). The verdict suggests whether the delta\n"
        "is likely solvable via C-level changes.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(None, help="C source file for the function to diagnose"),
    all_funcs: bool = typer.Option(
        False, "--all", help="Classify every NEAR_MATCHING function in the project"
    ),
    va: str | None = typer.Option(None, "--va", help="Target VA in hex (default: from annotation)"),
    size: int | None = typer.Option(
        None, "--size", help="Target size in bytes (default: from annotation)"
    ),
    fix_blocker: bool = typer.Option(
        False,
        "--fix-blocker",
        help="Write the verdict as BLOCKER metadata for the function (skipped on a match)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compile SOURCE and classify its byte delta against the target function."""
    import re

    from rebrew.annotation import parse_c_file_multi
    from rebrew.cli import target_marker

    cfg = require_config(target=target, json_mode=json_output)

    if all_funcs:
        if source:
            error_exit("A SOURCE argument cannot be combined with --all", json_mode=json_output)
        if va:
            error_exit("--va cannot be combined with --all", json_mode=json_output)
        _run_all_batch(cfg, fix_blocker, json_output, dry_run)
        return

    if not source:
        error_exit(
            "A SOURCE argument is required (or pass --all to classify every "
            "NEAR_MATCHING function)",
            json_mode=json_output,
        )

    from rebrew.cli import resolve_source_arg

    # Accept a hex VA or symbol name in addition to a .c path, like
    # `rebrew diff`/`rebrew prove`/`rebrew test` — a VA resolves to its
    # source file via the catalog.
    raw_source = source  # keep the original positional (may itself be a VA)
    source = str(resolve_source_arg(cfg, source))
    source_path = Path(source).resolve()

    annos = parse_c_file_multi(
        source_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    if not annos:
        error_exit(f"No annotations found in {source}", json_mode=json_output)
    va_from_flag = bool(va)  # explicit --va: user override, annotation optional
    va_int = parse_va(va, json_mode=json_output) if va else None
    if va_int is None and re.match(r"^0[xX][0-9a-fA-F]+$", raw_source):
        # The positional argument itself was a hex VA.
        va_int = parse_va(raw_source, json_mode=json_output)
    if va_int is None:
        va_int = annos[0].va
    # In a multi-function file, pick the annotation matching the requested VA
    # (the first annotation is the wrong function — it has its own VA/size).
    # When the VA was DERIVED (positional/file) and no annotation matches,
    # refuse rather than silently diagnosing the wrong function with its
    # cflags/symbol/size.  An explicit --va is a user override — the file's
    # compile settings are still intended.
    ann = annos[0]
    matched_annotation = False
    for candidate in annos:
        if candidate.va == va_int:
            ann = candidate
            matched_annotation = True
            break
    if not matched_annotation and not va_from_flag:
        error_exit(
            f"No annotation for VA 0x{va_int:08x} in {source_path.name} — "
            "the resolved file covers different functions",
            json_mode=json_output,
        )
    size_val = size or ann.size
    if not va_int or not size_val:
        error_exit(
            "Cannot determine target VA/size — pass --va and --size or add them to the annotation",
            json_mode=json_output,
        )

    try:
        result = _diagnose_one(cfg, source_path, ann, va_int, size_val, fix_blocker, dry_run)
    except _DiagnoseError as e:
        error_exit(str(e), json_mode=json_output)
    blocker_written = result["blocker_written"]

    if json_output:
        json_print(result)
        return

    table = Table(title=f"Delta classification for 0x{va_int:08x}", show_header=True)
    table.add_column("Category", style="bold")
    table.add_column("Bytes", justify="right")
    table.add_column("% of total", justify="right")
    for cat, data in result["categories"].items():
        if data["bytes"]:
            table.add_row(cat, str(data["bytes"]), f"{data['percent']:.1f}")
    console.print(table)
    console.print(f"[bold]{result['verdict']}[/bold]")
    console.print(result["suggestion"])
    if result.get("mutations"):
        console.print("[dim]GA mutations to try:[/dim] " + ", ".join(result["mutations"]))
    if blocker_written:
        console.print(f"[green]Wrote BLOCKER metadata:[/green] {_blocker_text(result)[:80]}...")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
