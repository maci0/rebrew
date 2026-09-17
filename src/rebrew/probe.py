"""probe.py — measure ONE function after editing its source.

Edit the source, re-run, compare: the fast read-only measurement a source
or flag probe needs.  For *why* two functions differ, use ``rebrew
near-diag``; for *where length drifts*, ``rebrew gap-trace``.

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
from rich.console import Console

from rebrew.annotation import parse_c_file_multi
from rebrew.binary_loader import extract_raw_bytes, load_binary
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
    resolve_source_arg,
)
from rebrew.compile import compile_to_obj
from rebrew.sources import target_marker

console = Console(stderr=True)

app = typer.Typer(
    help="Measure one function against the reference without writing metadata.",
    rich_markup_mode="rich",
)


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
    source = str(resolve_source_arg(cfg, source))
    path = Path(source)
    if not path.is_file():
        error_exit(f"Source file not found: {source}", json_mode=json_output)

    annos = parse_c_file_multi(path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir)
    if not annos:
        error_exit("No // FUNCTION annotation found in the source", json_mode=json_output)
    sel = annos[0]
    if va:
        want = parse_va(va, json_mode=json_output)
        sel = next((a for a in annos if a.va == want), sel)
    va_int = parse_va(va, json_mode=json_output) if va else sel.va
    size_val = size or sel.size
    sym = sel.symbol
    if va_int is None or not size_val or not sym:
        error_exit(
            "Need symbol, VA and SIZE (from the annotation or --va/--size)", json_mode=json_output
        )

    from rebrew.coff_reloc import smart_reloc_compare
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
    from rebrew.near_diag import align_and_classify, disasm_insns

    load_binary(cfg.target_binary)
    ref_raw = extract_raw_bytes(cfg.target_binary, va_int, size_val)

    flags = (cflags or getattr(sel, "cflags", None) or cfg.cflags or "").split()
    workdir = Path(cfg.root) / ".rebrew" / "probe"
    workdir.mkdir(parents=True, exist_ok=True)
    obj_path, err = compile_to_obj(cfg, path, flags, workdir, use_cache=False)
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
    _, strict_count, _, valid, _ = smart_reloc_compare(cb, ref_raw[: len(cb)], coff_relocs, None)
    obj_rels = set(valid)
    generous = sum(1 for i in range(n) if i < len(cb) and (i in obj_rels or ref_raw[i] == cb[i]))

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
        "percent": round(100.0 * strict_count / n, 1),
        "reference_insns": len(ref_insns),
        "compiled_insns": len(obj_insns),
        "aligned": aligned,
        "aligned_total": total_cls,
        "comdat_span": span,
        "code_len": code_len,
        "object": obj_path,
    }
    if json_output:
        json_print(payload)
        return
    console.print(
        f"0x{va_int:x} size {size_val}: matched {strict_count}/{n} "
        f"({100.0 * strict_count / n:.1f}%), matched-reloc {generous}/{n}, "
        f"instructions {len(obj_insns)} vs {len(ref_insns)}, comdat span {span}"
        + (f" (code {code_len})" if code_len != span else "")
    )
    console.print(
        f"  aligned {aligned}/{total_cls} reference instructions "
        f"({100.0 * aligned / max(1, total_cls):.1f}%)"
    )
    console.print(f"  object: {obj_path}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
