"""binary_similarity.py — whole-binary structural similarity between two binaries.

The binary-level analog of the per-function diff metrics: instead of scoring
ONE function against the target (``rebrew similar``, ``near-diag``, ``diff``),
this aggregates the per-function structural signatures across EVERY function
of two binaries — the current project target vs another binary (a different
game version, or a DLL+EXE pair sharing code).

For each function in binary A, the best-matching function in binary B is
found by the same structural signature ``rebrew similar``/``cross-import``
use (mnemonic-histogram cosine + call/branch agreement, 0-100), then the
per-function scores are aggregated:

- ``overall`` — byte-weighted mean of the best-match scores (what fraction of
  A's code is replicated in B)
- ``mean`` / ``median`` — unweighted per-function stats
- threshold buckets (>=95 near-identical, 85-95, 60-85, <60) with byte shares
- the lowest-scoring functions — the "what changed between versions" list

Matching is one-to-many best-per-A-function (a duplicated function in A may
both match the same B function) — a similarity metric, not an alignment.
Pairwise scoring is vectorised (numpy), so two ~2000-function binaries
compare in seconds.

Usage::

    rebrew binary-similarity ../v2/server.dll --other-list ../v2/functions.txt
    rebrew binary-similarity --other-target CLIENT --json
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    require_config,
)
from rebrew.similar import _DEFAULT_CS_ARCH, _DEFAULT_CS_MODE, _disasm_signature

console = Console(stderr=True)


def _pair_ratio(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Element-wise min/max ratio matching :func:`rebrew.similar._ratio`.

    ``a`` is ``(N, 1)``, ``b`` is ``(1, M)``.  Equal values (including both
    zero) → 1.0; one side zero → 0.0; otherwise min/max.
    """
    denom = np.maximum(a, b)
    out = np.divide(np.minimum(a, b), denom, out=np.zeros_like(denom), where=denom > 0)
    return np.where(a == b, 1.0, out)


def score_matrix(sigs_a: list[dict[str, Any]], sigs_b: list[dict[str, Any]]) -> np.ndarray:
    """The full N×M similarity score matrix (0-100) between two signature lists.

    Each signature is ``{"histogram": {mnemonic: count}, "calls": int,
    "branches": int}``.  Scores mirror :func:`rebrew.similar.similarity_score`
    (60% histogram cosine + 20% call agreement + 20% branch agreement) but
    computed vectorised: one shared mnemonic vocabulary, normalised histogram
    rows, and a single matrix product for all cosine pairs.
    """
    if not sigs_a or not sigs_b:
        return np.zeros((len(sigs_a), len(sigs_b)), dtype=float)

    vocab = sorted(
        {m for s in sigs_a for m in s["histogram"]} | {m for s in sigs_b for m in s["histogram"]}
    )
    vmap = {m: i for i, m in enumerate(vocab)}

    def _hist_rows(sigs: list[dict[str, Any]]) -> np.ndarray:
        rows = np.zeros((len(sigs), len(vocab)), dtype=float)
        for i, s in enumerate(sigs):
            for m, c in s["histogram"].items():
                rows[i, vmap[m]] = c
        return rows

    ha, hb = _hist_rows(sigs_a), _hist_rows(sigs_b)
    na = np.linalg.norm(ha, axis=1)
    nb = np.linalg.norm(hb, axis=1)
    cos = np.divide(
        ha @ hb.T,
        na[:, None] * nb[None, :],
        out=np.zeros((len(sigs_a), len(sigs_b)), dtype=float),
        where=(na[:, None] > 0) & (nb[None, :] > 0),
    )

    ca = np.array([s["calls"] for s in sigs_a], dtype=float)[:, None]
    cb = np.array([s["calls"] for s in sigs_b], dtype=float)[None, :]
    ba = np.array([s["branches"] for s in sigs_a], dtype=float)[:, None]
    bb = np.array([s["branches"] for s in sigs_b], dtype=float)[None, :]

    scores: np.ndarray = np.round(
        0.6 * cos * 100.0 + 0.2 * _pair_ratio(ca, cb) * 100.0 + 0.2 * _pair_ratio(ba, bb) * 100.0, 1
    )
    return scores


def aggregate_similarity(
    funcs_a: list[dict[str, Any]],
    funcs_b: list[dict[str, Any]],
    *,
    low_count: int = 10,
) -> dict[str, Any]:
    """Aggregate per-function best matches into the binary-level report.

    *funcs_a* / *funcs_b* are lists of ``{"va", "size", "name", "signature"}``
    records (signature may be ``None`` for undecodable functions, which are
    skipped).  Returns the aggregate dict (``overall`` byte-weighted 0-100,
    ``mean``/``median``, threshold buckets with byte shares, and the
    *low_count* lowest-scoring A functions with their B match).
    """
    sig_a: list[dict[str, Any]] = []
    meta_a: list[tuple[int, int, str]] = []  # (va, size, name)
    for f in funcs_a:
        if f.get("signature") is not None:
            sig_a.append(f["signature"])
            meta_a.append((f["va"], f["size"], f["name"]))
    sig_b = [f["signature"] for f in funcs_b if f.get("signature") is not None]
    meta_b: list[tuple[int, int, str]] = [
        (f["va"], f["size"], f["name"]) for f in funcs_b if f.get("signature") is not None
    ]

    n_a, n_b = len(sig_a), len(sig_b)
    if n_a == 0 or n_b == 0:
        return {
            "functions_a": n_a,
            "functions_b": n_b,
            "overall": 0.0,
            "mean": 0.0,
            "median": 0.0,
            "buckets": [],
            "low": [],
        }

    scores = score_matrix(sig_a, sig_b)
    best_idx = np.argmax(scores, axis=1)
    best_scores = scores[np.arange(n_a), best_idx]

    weights = np.array([s for _, s, _ in meta_a], dtype=float)
    wsum = weights.sum()
    overall = float((best_scores * weights).sum() / wsum) if wsum > 0 else 0.0
    mean = float(best_scores.mean())
    median = float(np.median(best_scores))

    bucket_defs = (
        (95.0, float("inf"), ">= 95 (near-identical)"),
        (85.0, 95.0, "85 - 95 (structurally close)"),
        (60.0, 85.0, "60 - 85 (related)"),
        (0.0, 60.0, "< 60 (diverged)"),
    )
    buckets: list[dict[str, Any]] = []
    for lo, hi, label in bucket_defs:
        mask = (best_scores >= lo) & (best_scores < hi)
        bsum = float(weights[mask].sum()) if mask.any() else 0.0
        buckets.append(
            {
                "label": label,
                "count": int(mask.sum()),
                "bytes": int(bsum),
                "percent": round(100.0 * bsum / wsum, 1) if wsum > 0 else 0.0,
            }
        )

    low: list[dict[str, Any]] = []
    order = np.argsort(best_scores)
    for i in order[:low_count]:
        j = int(best_idx[i])
        va, size, name = meta_a[i]
        bva, bsize, bname = meta_b[j]
        low.append(
            {
                "va": f"0x{va:08x}",
                "size": size,
                "name": name,
                "score": float(best_scores[i]),
                "matches": {"va": f"0x{bva:08x}", "size": bsize, "name": bname},
            }
        )

    return {
        "functions_a": n_a,
        "functions_b": n_b,
        "overall": round(overall, 1),
        "mean": round(mean, 1),
        "median": round(median, 1),
        "buckets": buckets,
        "low": low,
    }


def _load_side(
    cfg: Any,
    binary: Path,
    func_list: Path | None,
    cs_arch: str | int,
    cs_mode: str | int,
) -> list[dict[str, Any]]:
    """Load ``{va, size, name, signature}`` records for one binary."""
    from rebrew.binary_loader import extract_raw_bytes
    from rebrew.catalog import parse_function_list

    funcs = parse_function_list(func_list) if func_list and func_list.exists() else []
    out: list[dict[str, Any]] = []
    for f in funcs:
        va = int(f.get("va", 0))
        size = int(f.get("size", 0) or 0)
        if va <= 0 or size <= 0:
            continue
        try:
            code = extract_raw_bytes(binary, va, size)
        except Exception:  # one bad function must not kill the report
            continue
        if not code:
            continue
        sig = _disasm_signature(code, va, cs_arch, cs_mode)
        out.append({"va": va, "size": size, "name": str(f.get("name", "")), "signature": sig})
    return out


def run_binary_similarity(
    other_binary: Path,
    other_list: Path | None,
    json_output: bool,
    low_count: int,
    target: str | None,
) -> None:
    """Compute the binary-level similarity between the target and *other_binary*."""
    cfg = require_config(target=target, json_mode=json_output)
    if not other_binary.exists():
        error_exit(f"other binary not found: {other_binary}", json_mode=json_output)
    if other_list is not None and not other_list.exists():
        error_exit(f"other function list not found: {other_list}", json_mode=json_output)
    if other_list is None:
        error_exit(
            "a function list for the other binary is required — pass --other-list "
            "(functions.txt format: VA SIZE NAME) or use --other-target to pick a "
            "configured target",
            json_mode=json_output,
        )

    cs_arch = getattr(cfg, "capstone_arch", _DEFAULT_CS_ARCH)
    cs_mode = getattr(cfg, "capstone_mode", _DEFAULT_CS_MODE)

    funcs_a = _load_side(cfg, cfg.target_binary, cfg.function_list, cs_arch, cs_mode)
    funcs_b = _load_side(cfg, other_binary, other_list, cs_arch, cs_mode)

    result = aggregate_similarity(funcs_a, funcs_b, low_count=low_count)
    result["binary_a"] = str(cfg.target_binary)
    result["binary_b"] = str(other_binary)

    if json_output:
        json_print(result)
        return

    console.print(
        f"[bold]Binary similarity:[/bold] {Path(cfg.target_binary).name} → {other_binary.name}"
    )
    console.print(
        f"  functions: {result['functions_a']} vs {result['functions_b']} "
        f"(scored {result['functions_a']})"
    )
    console.print(
        f"  [bold]overall (byte-weighted): {result['overall']:.1f}%[/bold]  "
        f"mean {result['mean']:.1f} · median {result['median']:.1f}"
    )
    table = Table(show_header=True, header_style="bold", pad_edge=False)
    table.add_column("Bucket")
    table.add_column("Count", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("% of A", justify="right")
    for b in result["buckets"]:
        table.add_row(
            b["label"],
            str(b["count"]),
            f"0x{b['bytes']:x}",
            f"{b['percent']:.1f}",
        )
    console.print(table)
    if result["low"]:
        console.print("[dim]Lowest-similarity functions (the version deltas):[/dim]")
        for item in result["low"]:
            m = item["matches"]
            console.print(
                f"  {item['score']:6.1f}  {item['va']} {item['name'] or '?'} "
                f"({item['size']}B) → {m['va']} {m['name'] or '?'}"
            )


app = typer.Typer(
    help="Whole-binary structural similarity between the target and another binary.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binary-similarity ../v2/server.dll --other-list ../v2/functions.txt\n\n"
        "  rebrew binary-similarity --other-target CLIENT --json\n\n"
        "  rebrew binary-similarity other.dll --other-list other.txt --low 20\n\n"
        "[dim]Matches every function of the current target against the other "
        "binary's function list by structural signature (mnemonic histogram + "
        "call/branch agreement) and aggregates the best matches into a "
        "byte-weighted binary similarity.  The lowest-scoring functions are "
        "the version deltas.  Same-arch binaries only.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    other_binary: Path | None = typer.Argument(
        None, help="Path to the other binary (omit with --other-target)"
    ),
    other_list: Path | None = typer.Option(
        None,
        "--other-list",
        help="Function list for the other binary (functions.txt format: VA SIZE NAME)",
    ),
    other_target: str | None = typer.Option(
        None,
        "--other-target",
        help="Resolve the other binary + function list from a configured target",
    ),
    low: int = typer.Option(10, "--low", help="How many lowest-scoring functions to list"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Report binary-level structural similarity against another binary."""
    if other_target and other_binary:
        error_exit(
            "--other-target cannot be combined with a positional binary",
            json_mode=json_output,
        )
    if other_target and other_list:
        error_exit(
            "--other-target cannot be combined with --other-list",
            json_mode=json_output,
        )

    if other_target:
        from rebrew.config import load_config

        try:
            other_cfg = load_config(target=other_target)
        except Exception as exc:  # report the config error
            error_exit(f"cannot load target {other_target!r}: {exc}", json_mode=json_output)
        run_binary_similarity(
            other_cfg.target_binary, other_cfg.function_list, json_output, low, target
        )
        return

    if other_binary is None:
        error_exit(
            "a positional OTHER_BINARY (or --other-target) is required",
            json_mode=json_output,
        )
    run_binary_similarity(other_binary, other_list, json_output, low, target)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
