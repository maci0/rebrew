"""Binary similarity search — rank functions by structural similarity.

Finds functions in the target binary that are structurally similar to a query
function: same opcode mix, similar call/branch density.  Useful for
prioritising which STUBs to tackle next — structurally similar functions are
likely to share the same optimisation approach (and often the same source).

Pure local analysis: capstone for disassembly, numpy for the histogram cosine.
No external service.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import TargetOption, json_print, parse_va, require_config
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig

console = Console(stderr=True)

_DEFAULT_CS_ARCH = "CS_ARCH_X86"
_DEFAULT_CS_MODE = "CS_MODE_32"


def _disasm_signature(
    code: bytes, va: int, cs_arch: int | str, cs_mode: int | str
) -> dict[str, Any] | None:
    """Disassemble *code* and build a structural signature.

    Signature: mnemonic histogram plus call/branch counts.  Returns ``None``
    when nothing disassembles (empty or undecodable input).
    """
    import capstone

    # cfg.capstone_arch/capstone_mode return ints; the defaults are the
    # constant-name strings.  Accept either form.
    def _resolve(value: int | str) -> int:
        return value if isinstance(value, int) else int(getattr(capstone, value))

    md = capstone.Cs(_resolve(cs_arch), _resolve(cs_mode))
    mnemonics: dict[str, int] = {}
    calls = 0
    branches = 0
    for insn in md.disasm(code, va):
        mnemonic = insn.mnemonic
        mnemonics[mnemonic] = mnemonics.get(mnemonic, 0) + 1
        if mnemonic.startswith("call"):
            calls += 1
        elif mnemonic == "jmp" or mnemonic.startswith("j"):
            branches += 1
    if not mnemonics:
        return None
    return {"histogram": mnemonics, "calls": calls, "branches": branches}


def _cosine(hist_a: dict[str, int], hist_b: dict[str, int]) -> float:
    """Cosine similarity between two mnemonic histograms (0.0-1.0)."""
    keys = set(hist_a) | set(hist_b)
    vec_a = np.array([hist_a.get(k, 0) for k in keys], dtype=float)
    vec_b = np.array([hist_b.get(k, 0) for k in keys], dtype=float)
    denom = float(np.linalg.norm(vec_a) * np.linalg.norm(vec_b))
    if denom == 0.0:
        return 0.0
    return float(np.dot(vec_a, vec_b) / denom)


def _ratio(a: int, b: int) -> float:
    """1.0 when equal, min/max when both non-zero, 0.0 when one side is zero."""
    if a == b:
        return 1.0
    if a == 0 or b == 0:
        return 0.0
    return min(a, b) / max(a, b)


def similarity_score(sig_a: dict[str, Any] | None, sig_b: dict[str, Any] | None) -> float:
    """Structural similarity of two signatures as a 0-100 score.

    Weights: 60% mnemonic-histogram cosine, 20% call-count agreement,
    20% branch-count agreement.
    """
    if sig_a is None or sig_b is None:
        return 0.0
    hist = _cosine(sig_a["histogram"], sig_b["histogram"]) * 100.0
    calls = _ratio(sig_a["calls"], sig_b["calls"]) * 100.0
    branches = _ratio(sig_a["branches"], sig_b["branches"]) * 100.0
    return round(0.6 * hist + 0.2 * calls + 0.2 * branches, 1)


def find_similar(
    cfg: ProjectConfig,
    query_va: int,
    size: int | None = None,
    top: int = 10,
    min_score: float = 0.0,
) -> list[dict[str, Any]]:
    """Rank functions in the target binary by similarity to *query_va*.

    Function set and sizes come from the catalog registry (function list +
    Ghidra structure JSON); bytes are extracted from the target binary and
    compared structurally.  Returns the top *top* results (excluding the query
    itself), each as ``{va, size, name, score}``.
    """
    from rebrew.binary_loader import extract_raw_bytes
    from rebrew.catalog.loaders import parse_function_list
    from rebrew.catalog.registry import build_function_registry

    cs_arch = getattr(cfg, "capstone_arch", _DEFAULT_CS_ARCH)
    cs_mode = getattr(cfg, "capstone_mode", _DEFAULT_CS_MODE)

    funcs = parse_function_list(cfg.function_list)
    registry = build_function_registry(
        funcs,
        cfg,
        cfg.reversed_dir / FUNCTION_STRUCTURE_JSON,
        cfg.target_binary,
    )

    entry = registry.get(query_va)
    query_size = size or (entry["canonical_size"] if entry else 0)
    if not query_size:
        return []
    query_bytes = extract_raw_bytes(cfg.target_binary, query_va, query_size)
    query_sig = _disasm_signature(query_bytes, query_va, cs_arch, cs_mode)
    if query_sig is None:
        return []

    results: list[dict[str, Any]] = []
    for va, cand in registry.items():
        if va == query_va:
            continue
        cand_size = cand["canonical_size"]
        if not cand_size:
            continue
        cand_bytes = extract_raw_bytes(cfg.target_binary, va, cand_size)
        sig = _disasm_signature(cand_bytes, va, cs_arch, cs_mode)
        if sig is None:
            continue
        score = similarity_score(query_sig, sig)
        if score >= min_score:
            name = cand.get("list_name") or cand.get("ghidra_name") or ""
            results.append({"va": f"0x{va:08x}", "size": cand_size, "name": name, "score": score})

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top]


app = typer.Typer(
    help="Find structurally similar functions in the target binary.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew similar 0x10001000 · · · · · · · · · Top 10 structural matches\n\n"
        "  rebrew similar 0x10001000 --top 5 --min-score 50 · · Raise the bar\n\n"
        "  rebrew similar 0x10001000 --json · · · · · · · Machine-readable output\n\n"
        "[dim]Scores: 0-100 blend of mnemonic histogram (60%), call count (20%),\n"
        "branch count (20%). Use it to find which STUBs likely share the same\n"
        "source and optimisation approach as a solved function.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    va: str = typer.Argument(..., help="Query function VA in hex (e.g. 0x10001000)"),
    size: int | None = typer.Option(
        None, "--size", help="Query function size in bytes (defaults to catalog size)"
    ),
    top: int = typer.Option(10, "--top", help="Number of results to show"),
    min_score: float = typer.Option(
        0.0, "--min-score", help="Minimum similarity score (0-100) to include"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Find functions structurally similar to the one at VA."""
    cfg = require_config(target=target, json_mode=json_output)
    query_va = parse_va(va, json_mode=json_output)
    results = find_similar(cfg, query_va, size=size, top=top, min_score=min_score)

    if json_output:
        json_print({"query_va": va, "results": results})
        return

    if not results:
        console.print("[yellow]No similar functions found.[/yellow]")
        return

    table = Table(title=f"Functions similar to {va}", show_header=True)
    table.add_column("Rank", justify="right")
    table.add_column("VA")
    table.add_column("Score", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Name")
    for i, r in enumerate(results, 1):
        table.add_row(str(i), r["va"], f"{r['score']:.1f}", str(r["size"]), r["name"])
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
