"""probe.py — measure ONE function after editing its source.

Edit the source, re-run, compare: the fast read-only measurement a source
or flag probe needs.  For *why* two functions differ, use ``rebrew
near-diag``; for *where length drifts*, ``rebrew diagnose gap``.

Unlike ``rebrew test`` this never writes STATUS metadata — it is the
no-side-effect ruler.  Reports the strict masked match, the generous
reloc count (``matched-reloc``, the historical number still quoted in old
headers), the aligned instruction count (the gradient to climb on large
functions), and the COMDAT span vs trimmed code length (two different
rulers — never compare them across tools).

Generalized from guild-rebrew's ``scripts/probe_function.py`` (MSVC6/x86-32
campaign).  Arch-neutral: compile/extract/compare go through the project's
configured toolchain and format handlers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer

from rebrew.binary_loader import extract_raw_bytes, load_binary
from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
    require_positive_size,
    select_annotation,
)
from rebrew.compile import compile_to_obj
from rebrew.utils import floor_pct

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew diagnose probe src/game_dll/my_func.c · · Measure one function, write no metadata\n\n"
    "  rebrew diagnose probe f.c --va 0x10009310 --size 42 · · Override VA and size\n\n"
    '  rebrew diagnose probe f.c --cflags "/O1 /Gd" --json · Machine-readable measurements\n'
)


app = typer.Typer(
    help="Measure one function against the reference without writing metadata.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def matched_reloc_count(ref_raw: bytes, cand: bytes, relocs: set[int], size: int) -> int:
    """Bytes where either side's relocation suffices (the historical count).

    Bounded by the overlap of *size*, *cand* and *ref_raw*: an annotation
    whose SIZE runs past the target section's raw bytes (into the BSS tail)
    or past EOF yields a short *ref_raw*, and indexing it at the candidate's
    offsets raised ``IndexError`` instead of reporting the overlap that does
    exist.
    """
    limit = min(size, len(cand), len(ref_raw))
    return sum(1 for i in range(limit) if (i in relocs or ref_raw[i] == cand[i]))


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file (or VA/symbol) for the function"),
    va: str | None = typer.Option(None, "--va", help="Target VA in hex (default: from annotation)"),
    size: int | None = typer.Option(
        None, "--size", help="Target size in bytes (default: from annotation)"
    ),
    cflags: str | None = typer.Option(
        None, "--cflags", help="Compiler flags (default: from metadata)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compile SOURCE and report matched/aligned against the reference bytes."""
    cfg = require_config(target=target, json_mode=json_output)
    path, sel, va_int = select_annotation(cfg, source, va, json_mode=json_output)
    size_val = size or sel.size
    sym = sel.symbol
    if va_int is None or not size_val or not sym:
        error_exit(
            "Need symbol, VA and SIZE (from the annotation or --va/--size)", json_mode=json_output
        )
    size_val = require_positive_size(size_val, json_mode=json_output)

    from rebrew.analysis import disasm_insns
    from rebrew.coff_reloc import (
        CatalogScanError,
        build_iat_region,
        build_name_to_va,
        smart_reloc_compare,
    )
    from rebrew.compile_overrides import resolve_compile_overrides
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
    from rebrew.near_analysis import align_and_classify

    load_binary(cfg.target_binary)
    try:
        name_to_va = build_name_to_va(cfg)
    except CatalogScanError as exc:
        error_exit(f"Catalog scan failed: {exc}", json_mode=json_output)
    ref_raw = extract_raw_bytes(cfg.target_binary, va_int, size_val)

    # Same fallback chain as test/verify/near-diag so module presets and
    # library overrides cannot make probe disagree with those tools.
    toolchain_name, cflags_str = resolve_compile_overrides(
        cfg,
        path.resolve().parent,
        sel.toolchain,
        cflags or sel.cflags or None,
        sel.module,
    )
    flags = cflags_str.split()
    workdir = Path(cfg.root) / ".rebrew" / "probe"
    workdir.mkdir(parents=True, exist_ok=True)
    obj_path, err = compile_to_obj(
        cfg, path, flags, workdir, use_cache=False, toolchain=toolchain_name
    )
    if obj_path is None:
        error_exit(f"Compile failed: {err}", json_mode=json_output)

    obj_bytes, reloc_dict, full_relocs = parse_obj_symbol_and_relocs(obj_path, sym)
    if obj_bytes is None:
        error_exit(f"EXTRACT_ERROR: Symbol '{sym}' not found in .obj", json_mode=json_output)
    coff_relocs = full_relocs if full_relocs else reloc_dict

    n = size_val
    cb = obj_bytes[:n]
    # Strict: both sides relocate or neither does and bytes agree.
    # Generous (matched-reloc): either side's reloc suffices — historical.
    _, strict_count, _, valid, _ = smart_reloc_compare(
        cb,
        ref_raw[: len(cb)],
        coff_relocs,
        name_to_va=name_to_va,
        section_va=va_int,
        iat_region=build_iat_region(cfg),
    )
    obj_rels = set(valid)
    generous = matched_reloc_count(ref_raw, cb, {r + i for r in valid for i in range(4)}, n)

    ref_insns = disasm_insns(ref_raw, va_int, cfg.capstone_arch, cfg.capstone_mode)
    obj_insns = disasm_insns(cb, va_int, cfg.capstone_arch, cfg.capstone_mode)
    counts, _ = align_and_classify(ref_insns, obj_insns, obj_rels)
    aligned = counts.get("match", 0)
    total_cls = sum(counts.values()) or 1

    span = len(obj_bytes)
    code_len = len(cb.rstrip(b"\x90"))

    payload: dict[str, Any] = {
        "va": hex(va_int),
        "symbol": sym,
        "size": size_val,
        "matched": strict_count,
        "matched_reloc": generous,
        "total": n,
        "percent": floor_pct(strict_count, n),
        "reference_insns": len(ref_insns),
        "compiled_insns": len(obj_insns),
        # align_and_classify reports BYTES per category, not instructions:
        # a 12-instruction function of 42 matching bytes reports 42.
        "aligned_bytes": aligned,
        "aligned_bytes_total": total_cls,
        "comdat_span": span,
        "code_len": code_len,
        "object": obj_path,
    }
    if json_output:
        json_print(payload)
        return
    console.print(
        f"0x{va_int:x} size {size_val}: matched {strict_count}/{n} "
        f"({payload['percent']:.1f}%), matched-reloc {generous}/{n}, "
        f"instructions {len(obj_insns)} vs {len(ref_insns)}, comdat span {span}"
        + (f" (code {code_len})" if code_len != span else "")
    )
    console.print(
        f"  aligned {aligned}/{total_cls} reference bytes ({floor_pct(aligned, total_cls):.1f}%)"
    )
    console.print(f"  object: {obj_path}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
