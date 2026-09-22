"""qual_sweep.py — sweep declaration qualifiers/types for one function.

``rebrew climb`` moves whole statements.  Functions that converge there do
so because their residue is register *naming* rather than order: the target
keeps a loop counter in ``ebx`` where we keep it in ``edi``, the same
instruction kinds in the same sequence.  The allocator is driven by live
ranges, so the cheap way to perturb it without changing what the code does
is to change a local's qualifying type.

This runs that idea over every declaration in a function, one at a time,
keeping only moves that improve the score.  It complements the GA's random
``mut_toggle_volatile`` (``rebrew match``): this is the exhaustive,
deterministic, one-variable-at-a-time sweep for when the GA stalls on an
allocator wall.

Generalized from guild-rebrew's ``scripts/qualsweep.py`` (MSVC6/x86-32
campaign).  Scoring goes through ``rebrew.compile.compile_and_compare``
so flags, toolchain, and reloc masking resolve per project.
"""

from __future__ import annotations

import concurrent.futures as cf
import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    require_config,
    select_annotation,
)
from rebrew.climb import _function_span as climb_function_span
from rebrew.compile import compile_and_compare
from rebrew.utils import atomic_write_text, read_source_text

console = Console(stderr=True)

app = typer.Typer(
    help="Sweep declaration qualifiers over one function, keeping winners.",
    rich_markup_mode="rich",
)

#: (label, pattern, replacement) — each must keep the declaration legal and
#: the function semantically identical.
QUALIFIERS: list[tuple[str, str, str]] = [
    ("volatile", r"^(\s*)(?!(?:.*\bvolatile\b))", r"\1volatile "),
]


def _strip_literals(text: str) -> str:
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)


def variants(decl: str) -> list[tuple[str, str]]:
    """Candidate rewrites of one declaration, as (label, text)."""
    body = _strip_literals(decl).strip()
    out = []
    for label, pat, repl in QUALIFIERS:
        new = re.sub(pat, repl, decl, count=1, flags=re.M)
        if _strip_literals(new).strip() != body:
            out.append((label, new))
    return out


def _function_span(lines: list[str], symbol: str) -> tuple[int, int]:
    """Half-open line range of *symbol*'s definition, closing brace included.

    Raises:
        ValueError: when no definition or no matching closing brace is found.
    """
    lo, last = climb_function_span(lines, symbol)
    return lo, last + 1


def _is_decl(unit: str) -> bool:
    s = _strip_literals(unit).strip()
    return bool(
        re.match(
            r"^(?:volatile\s+|const\s+|static\s+|register\s+)?(?:\w[\w\s\*]*?)\s+\w+\s*(?:\[[^\]]*\])?\s*(?:=[^;]*)?;",
            s,
        )
    )


def score_fn(cfg: Any, path: Path, va: int, size: int, symbol: str) -> tuple[float, int]:
    """(match_percent, obj_len) via the project's compile-and-compare path."""
    from rebrew.binary_loader import extract_raw_bytes

    target_bytes = extract_raw_bytes(cfg.target_binary, va, size)
    res = compile_and_compare(cfg, path, symbol, target_bytes, cfg.cflags or "")
    obj_len = len(res.obj_bytes) if res.obj_bytes else -1
    if res.full_obj_size is not None:
        obj_len = res.full_obj_size
    return res.match_percent, obj_len


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file (or VA/symbol) for the function"),
    va: str | None = typer.Option(None, "--va", help="Target VA in hex (default: from annotation)"),
    symbol: str | None = typer.Option(
        None, "--symbol", help="COFF symbol (default: from annotation)"
    ),
    rounds: int = typer.Option(4, "--rounds", help="Sweep rounds (stops early on convergence)"),
    jobs: int = typer.Option(4, "--jobs", help="Parallel compile workers"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Sweep one qualifier at a time over every declaration; keep winners."""
    cfg = require_config(target=target, json_mode=json_output)
    path, sel, va_int = select_annotation(cfg, source, va, json_mode=json_output)
    sym = symbol or sel.symbol
    size = sel.size
    if va_int is None or not sym or not size:
        error_exit(
            "Need symbol, VA and SIZE (from the annotation or --va/--symbol)", json_mode=json_output
        )

    original, encoding = read_source_text(path)
    lines = original.splitlines(keepends=True)
    try:
        lo, hi = _function_span(lines, sym)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    head, body_lines, tail = lines[:lo], lines[lo:hi], lines[hi:]
    # Split body into top-level `;`-terminated units (declarations live there).
    units: list[str] = []
    depth = 0
    cur: list[str] = []
    for ln in body_lines:
        cur.append(ln)
        depth += ln.count("{") - ln.count("}")
        if depth == 0 and ";" in ln:
            units.append("".join(cur))
            cur = []
    if cur:
        units.append("".join(cur))
    decls = [k for k, u in enumerate(units) if _is_decl(u)]
    console.print(f"{sym}: {len(units)} statements, {len(decls)} declarations")

    if dry_run:
        candidates = [
            (k, lab, _strip_literals(new).strip()) for k in decls for lab, new in variants(units[k])
        ]
        if json_output:
            json_print(
                {
                    "source": str(path),
                    "symbol": sym,
                    "va": hex(va_int),
                    "candidates": [
                        {"index": k, "qualifier": lab, "text": text} for k, lab, text in candidates
                    ],
                }
            )
            return
        for k, lab, text in candidates:
            console.print(f"  [{k:3d}] {lab}: {text[:70]}")
        return

    base = score_fn(cfg, path, va_int, size, sym)
    baseline = base
    console.print(f"baseline {base[0]} matched, object size {base[1]} vs target {size}")
    moves: list[dict[str, Any]] = []

    for rnd in range(rounds):
        cands = [(k, lab, new) for k in decls for lab, new in variants(units[k])]
        tmpdir = Path(cfg.root) / ".rebrew" / "qualsweep"
        tmpdir.mkdir(parents=True, exist_ok=True)

        def submit(
            c: tuple[int, str, str], _tmpdir: Path = tmpdir
        ) -> tuple[tuple[int, str, str], tuple[float, int]]:
            k, lab, new = c
            alt = units[:]
            alt[k] = new
            # Compile a copy: parallel candidates must not share one path.
            tmp = _tmpdir / f"{sym}_{k}_{lab}.c"
            tmp.write_text("".join(head) + "".join(alt) + "".join(tail), encoding=encoding)
            return (k, lab, new), score_fn(cfg, tmp, va_int, size, sym)

        with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
            results = list(ex.map(submit, cands))

        best, best_c = base, None
        for (_k, _lab, _new), sc in results:
            if sc[0] > best[0] and sc[1] >= size:
                best, best_c = sc, (_k, _lab, _new)
        if best_c is None:
            console.print(
                f"round {rnd}: no improving qualifier among {len(cands)}; converged at {base[0]}"
            )
            break
        k, lab, new = best_c
        units[k] = new
        base = best
        atomic_write_text(path, "".join(head) + "".join(units) + "".join(tail), encoding=encoding)
        moves.append({"round": rnd, "index": k, "qualifier": lab, "matched": base[0]})
        console.print(f"round {rnd}: {lab} on [{k}] -> {base[0]} matched (object {base[1]})")

    payload = {
        "source": str(path),
        "symbol": sym,
        "va": hex(va_int),
        "baseline_matched": baseline[0],
        "best_matched": base[0],
        "moves": moves,
    }
    if json_output:
        json_print(payload)
        return
    console.print(f"{sym}: final {base[0]} matched, object size {base[1]} ({len(moves)} move(s))")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
