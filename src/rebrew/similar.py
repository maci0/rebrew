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

from rebrew.cli import TargetOption, error_exit, json_print, parse_va, require_config
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.instruction_clones import (
    MIN_RUN_INSTRUCTIONS,
    cluster_units,
    find_common_runs,
    function_unit,
    load_function_units,
)

console = Console(stderr=True)

DEFAULT_CS_ARCH = "CS_ARCH_X86"
DEFAULT_CS_MODE = "CS_MODE_32"

#: Smallest duplicate group ``rebrew similar --cluster`` reports.
MIN_CLUSTER_SIZE = 2


def disasm_signature(
    code: bytes, va: int, cs_arch: int | str, cs_mode: int | str
) -> dict[str, Any] | None:
    """Disassemble *code* and build a structural signature.

    Signature: mnemonic histogram, call/branch counts and the byte length.
    The length is part of the signature so :func:`similarity_score` can
    penalise a size difference on its own: without it a 40-byte function
    whose opcode mix sits inside a 400-byte function scored in the high 90s
    against it (cross-import then offered that one source for dozens of
    unrelated destinations).  Returns ``None`` when nothing disassembles
    (empty or undecodable input).
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
    return {"histogram": mnemonics, "calls": calls, "branches": branches, "size": len(code)}


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
    """1.0 when equal (including both zero), min/max otherwise, 0.0 when exactly one side is zero."""
    if a == b:
        return 1.0
    if a == 0 or b == 0:
        return 0.0
    return min(a, b) / max(a, b)


def similarity_score(
    sig_a: dict[str, Any] | None,
    sig_b: dict[str, Any] | None,
    size_a: int | None = None,
    size_b: int | None = None,
) -> float:
    """Structural similarity of two signatures as a 0-100 score.

    Weights: 50% mnemonic-histogram cosine, 15% call-count agreement,
    15% branch-count agreement, 20% size agreement (a 10B thunk must not
    score ~100 against a 1000B function with the same opcode mix).  An
    explicit *size_a*/*size_b* wins; otherwise the signature's own ``size``
    (its byte length) is used, so the gate applies even when the caller has
    no size to hand.
    """
    if sig_a is None or sig_b is None:
        return 0.0
    size_a = size_a or int(sig_a.get("size") or 0)
    size_b = size_b or int(sig_b.get("size") or 0)
    hist = _cosine(sig_a["histogram"], sig_b["histogram"]) * 100.0
    calls = _ratio(sig_a["calls"], sig_b["calls"]) * 100.0
    branches = _ratio(sig_a["branches"], sig_b["branches"]) * 100.0
    if size_a and size_b:
        size = _ratio(size_a, size_b) * 100.0
        return round(0.5 * hist + 0.15 * calls + 0.15 * branches + 0.2 * size, 1)
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
    from rebrew.catalog import build_function_registry, parse_function_list

    cs_arch = getattr(cfg, "capstone_arch", DEFAULT_CS_ARCH)
    cs_mode = getattr(cfg, "capstone_mode", DEFAULT_CS_MODE)

    funcs = parse_function_list(cfg.function_list)
    registry = build_function_registry(
        funcs,
        cfg,
        cfg.reversed_dir / FUNCTION_STRUCTURE_JSON,
        cfg.target_binary,
    )

    entry = registry.get(query_va)
    if entry is None:
        raise ValueError(f"No function found at VA 0x{query_va:08x}")
    query_size = size or entry["canonical_size"]
    if not query_size:
        return []
    query_bytes = extract_raw_bytes(cfg.target_binary, query_va, query_size)
    query_sig = disasm_signature(query_bytes, query_va, cs_arch, cs_mode)
    if query_sig is None:
        return []

    # One signature per candidate VA: repeated queries against the same
    # binary re-disassemble unchanged bytes, so memoize within the call.
    sig_cache: dict[int, dict[str, Any] | None] = {}

    def _cached_sig(va: int, cand_bytes: bytes) -> dict[str, Any] | None:
        if va not in sig_cache:
            sig_cache[va] = disasm_signature(cand_bytes, va, cs_arch, cs_mode)
        return sig_cache[va]

    results: list[dict[str, Any]] = []
    for va, cand in registry.items():
        if va == query_va:
            continue
        cand_size = cand["canonical_size"]
        if not cand_size:
            continue
        cand_bytes = extract_raw_bytes(cfg.target_binary, va, cand_size)
        sig = _cached_sig(va, cand_bytes)
        if sig is None:
            continue
        score = similarity_score(query_sig, sig, query_size, cand_size)
        if score >= min_score:
            name = cand.get("list_name") or cand.get("ghidra_name") or ""
            results.append({"va": f"0x{va:08x}", "size": cand_size, "name": name, "score": score})

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top]


def submatch_report(
    cfg: ProjectConfig, left_va: int, right_va: int, min_run: int
) -> dict[str, Any]:
    """Common instruction runs between the functions at *left_va* and *right_va*.

    Returns ``{left_va, right_va, min_run, left_instructions,
    right_instructions, runs}``; ``runs`` is empty when the two functions
    share no run of at least *min_run* instructions.
    """
    left = function_unit(cfg, left_va)
    if left is None:
        raise ValueError(f"No function found at VA 0x{left_va:08x}")
    right = function_unit(cfg, right_va)
    if right is None:
        raise ValueError(f"No function found at VA 0x{right_va:08x}")

    runs = find_common_runs(left.instructions, right.instructions, min_run=min_run)
    return {
        "left_va": f"0x{left_va:08x}",
        "right_va": f"0x{right_va:08x}",
        "left_name": left.name,
        "right_name": right.name,
        "left_instructions": len(left.instructions),
        "right_instructions": len(right.instructions),
        "min_run": min_run,
        "runs": [
            {
                "left_va": f"0x{run.left_va:08x}",
                "right_va": f"0x{run.right_va:08x}",
                "length": run.length,
                "instructions": run.instructions,
            }
            for run in runs
        ],
    }


def cluster_report(
    cfg: ProjectConfig, min_size: int, query_va: int | None = None
) -> dict[str, Any]:
    """Groups of functions with identical normalized instruction sequences.

    The query function's own group (when *query_va* is given) is marked by
    ``query_group`` so a caller of ``rebrew similar <VA> --cluster`` can see
    which of the identical functions it asked about.
    """
    units, skipped = load_function_units(cfg)
    clusters = cluster_units(units, min_size=min_size)

    groups: list[dict[str, Any]] = []
    query_group: int | None = None
    for index, cluster in enumerate(clusters):
        if query_va is not None and query_va in cluster.members:
            query_group = index
        groups.append(
            {
                "size": cluster.size,
                "signature": cluster.signature,
                "instructions": cluster.instruction_count,
                "members": [
                    {
                        "va": f"0x{va:08x}",
                        "name": name,
                        "size": next(u.size for u in units if u.va == va),
                    }
                    for va, name in zip(cluster.members, cluster.names, strict=True)
                ],
            }
        )

    return {
        "total_functions": len(units),
        "skipped": skipped,
        "min_size": min_size,
        "duplicate_groups": len(groups),
        "duplicate_functions": sum(g["size"] for g in groups),
        "query_group": query_group,
        "clusters": groups,
    }


app = typer.Typer(
    help="Find structurally similar functions in the target binary.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew similar 0x10001000 · · · · · · · · · Top 10 structural matches\n\n"
        "  rebrew similar 0x10001000 --top 5 --min-score 50 · · Raise the bar\n\n"
        "  rebrew similar 0x10001000 --submatch --other 0x10002000 · Common instruction runs\n\n"
        "  rebrew similar --cluster · · · · · · · · · · Groups of identical functions\n\n"
        "  rebrew similar 0x10001000 --json · · · · · · · Machine-readable output\n\n"
        "[dim]Scores: 0-100 blend of mnemonic histogram (50%), call count (15%),\n"
        "branch count (15%), size agreement (20%). Use it to find which STUBs likely share the same\n"
        "source and optimisation approach as a solved function.[/dim]\n\n"
        "[bold]Similar or identical?[/bold]\n"
        "Ranking similarity is what this command does by default, and what the sibling\n"
        "`resembl` project does across a persisted corpus (MinHash + LSH, fragment queries,\n"
        "cross-project duplicates).  --submatch and --cluster report structure instead, and\n"
        "answer the two questions a resemblance score cannot: --submatch names WHERE inside\n"
        "two functions the common instructions are (offsets + text), --cluster names WHICH\n"
        "functions of one target are identical after normalization.  In-process, exact, one\n"
        "target, no index: for cross-project or near-duplicate work use resembl."
    ),
)


@app.callback(invoke_without_command=True)
def main(
    va: str | None = typer.Argument(
        None, help="Query function VA in hex (e.g. 0x10001000); omitted with --cluster"
    ),
    size: int | None = typer.Option(
        None, "--size", help="Query function size in bytes (defaults to catalog size)"
    ),
    top: int = typer.Option(10, "--top", help="Number of results to show"),
    min_score: float = typer.Option(
        0.0, "--min-score", help="Minimum similarity score (0-100) to include"
    ),
    submatch: bool = typer.Option(
        False,
        "--submatch",
        help=(
            "Report WHERE two functions correspond (common instruction runs, with offsets and "
            "text) instead of ranking their similarity"
        ),
    ),
    other: str | None = typer.Option(
        None, "--other", help="Second function VA for --submatch (e.g. 0x10002000)"
    ),
    min_run: int = typer.Option(
        MIN_RUN_INSTRUCTIONS,
        "--min-run",
        help="Shortest common instruction run --submatch reports",
    ),
    cluster: bool = typer.Option(
        False,
        "--cluster",
        help=(
            "Group the functions of THIS target whose normalized instruction sequence is "
            "identical (exact duplicates; cross-project or near-duplicate clustering is the "
            "resembl project's job)"
        ),
    ),
    min_cluster_size: int = typer.Option(
        MIN_CLUSTER_SIZE, "--min-cluster-size", help="Smallest group --cluster reports"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Find functions structurally similar to the one at VA."""
    cfg = require_config(target=target, json_mode=json_output)
    query_va = parse_va(va, json_mode=json_output) if va is not None else None

    if cluster:
        try:
            report = cluster_report(cfg, min_cluster_size, query_va=query_va)
        except ValueError as e:
            error_exit(str(e), json_mode=json_output)
        if json_output:
            json_print(report)
            return
        _print_clusters(report)
        return

    if query_va is None:
        error_exit(
            "Provide a query VA, or use --cluster to group identical functions",
            json_mode=json_output,
        )

    if submatch:
        if other is None:
            error_exit("--submatch needs --other <VA>", json_mode=json_output)
        other_va = parse_va(other, json_mode=json_output)
        try:
            report = submatch_report(cfg, query_va, other_va, min_run)
        except ValueError as e:
            error_exit(str(e), json_mode=json_output)
        if json_output:
            json_print(report)
            return
        _print_submatch(report)
        return

    try:
        results = find_similar(cfg, query_va, size=size, top=top, min_score=min_score)
    except ValueError as e:
        error_exit(str(e), json_mode=json_output)

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


def _print_submatch(report: dict[str, Any]) -> None:
    """Render a submatch report as a table of common runs."""
    runs = report["runs"]
    console.print(
        f"\n[bold]Common instruction runs[/bold]  "
        f"{report['left_va']} ({report['left_instructions']} insns) vs "
        f"{report['right_va']} ({report['right_instructions']} insns), "
        f"min run {report['min_run']}\n"
    )
    if not runs:
        console.print("[yellow]No common run at or above the minimum length.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Left")
    table.add_column("Right")
    table.add_column("Insns", justify="right")
    table.add_column("Matched")
    for run in runs:
        preview = " ; ".join(run["instructions"][:3])
        if run["length"] > 3:
            preview += " ; ..."
        table.add_row(run["left_va"], run["right_va"], str(run["length"]), preview)
    console.print(table)


def _print_clusters(report: dict[str, Any]) -> None:
    """Render a duplicate-cluster report, largest group first."""
    console.print(
        f"\n[bold]Identical instruction sequences[/bold]  "
        f"({report['duplicate_functions']} of {report['total_functions']} functions "
        f"in {report['duplicate_groups']} group(s), min size {report['min_size']})\n"
    )
    if report["skipped"]:
        console.print(f"[yellow]{report['skipped']} function(s) beyond the scan limit[/yellow]")
    if not report["clusters"]:
        console.print("[yellow]No duplicate groups found.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Group", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Insns", justify="right")
    table.add_column("Signature", style="dim")
    table.add_column("Representative")
    for index, group in enumerate(report["clusters"]):
        first = group["members"][0]
        table.add_row(
            str(index),
            str(group["size"]),
            str(group["instructions"]),
            group["signature"],
            f"{first['va']} {first['name']}".strip(),
        )
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
