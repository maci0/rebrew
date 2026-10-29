"""binary_similarity.py — whole-binary structural similarity between two binaries.

The binary-level analog of the per-function diff metrics: instead of scoring
ONE function against the target (``rebrew similarity function``, ``near-diag``, ``diff``),
this aggregates the per-function structural signatures across EVERY function
of two binaries — the current project target vs another binary (a different
game version, or a DLL+EXE pair sharing code).

For each function in binary A, the best-matching function in binary B is
found by the same structural signature ``rebrew similarity function``/``cross-import``
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

    rebrew similarity binary ../v2/server.dll --other-list ../v2/src/SERVER/function_structure.json
    rebrew similarity binary --other-target CLIENT --json
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
lazy from pathlib import Path

import typer
lazy from rich.table import Table

if TYPE_CHECKING:
    import numpy as np

from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
    require_non_negative,
)
lazy from rebrew.analysis import DEFAULT_CS_ARCH, DEFAULT_CS_MODE
lazy from rebrew.config import inventory_path_for
lazy from rebrew.similar import disasm_signature

log = logging.getLogger(__name__)

#: Decimal places :func:`score_matrix` rounds to.  Deep enough to erase the
#: float noise of the weighted sum, far above the 1 decimal shown in reports.
_SCORE_NOISE_DECIMALS = 6

#: :func:`_count_agreement` gathers from a table of distinct count pairs only
#: when the matrix has at least this many cells and each table cell serves at
#: least ``_COUNT_TABLE_MIN_REUSE`` matrix cells (measured: with mostly distinct
#: counts the table plus the gather is slower than the direct ratio).
_COUNT_TABLE_MIN_CELLS = 10_000
_COUNT_TABLE_MIN_REUSE = 8


def _pair_ratio(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Element-wise min/max ratio matching :func:`rebrew.similar._ratio`.

    ``a`` is ``(N, 1)``, ``b`` is ``(1, M)``.  Equal values (including both
    zero) → 1.0; one side zero → 0.0; otherwise min/max.
    """
    import numpy as np  # deferred: ~60 ms of startup for non-similarity commands

    denom = np.maximum(a, b)
    out = np.divide(np.minimum(a, b), denom, out=np.zeros_like(denom), where=denom > 0)
    return np.where(a == b, 1.0, out)


def score_matrix(sigs_a: list[dict[str, Any]], sigs_b: list[dict[str, Any]]) -> np.ndarray:
    """The full N×M similarity score matrix (0-100) between two signature lists.

    Each signature is ``{"histogram": {mnemonic: count}, "calls": int,
    "branches": int}``.  Scores mirror the size-less branch of
    :func:`rebrew.similar.similarity_score` (60% histogram cosine + 20% call
    agreement + 20% branch agreement; that function adds a 20% size term when
    both sizes are known, which this matrix cannot — it takes no sizes).  The
    arithmetic is the same; only the layout differs: computed vectorised with
    one shared mnemonic vocabulary, normalised histogram rows, and a single
    matrix product for all cosine pairs.
    """
    import numpy as np  # deferred: ~60 ms of startup for non-similarity commands

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
    # In place from here: each N×M temporary is megabytes at ~2000 functions.
    # Rows with a zero norm have an all-zero product row, so skipping their
    # division leaves the 0.0 cosine the masked divide used to write.
    cos = ha @ hb.T
    norms = np.multiply.outer(na, nb)
    np.divide(cos, norms, out=cos, where=norms > 0)
    np.clip(cos, 0.0, 1.0, out=cos)

    # Rounded only far enough to drop the float noise of the weighted sum
    # (an identical pair weighs 99.99999999999999).  The caller picks the
    # argmax and applies exact threshold buckets, so rounding to display
    # precision here would tie near-equal candidates and move a score across
    # a bucket edge: a true 94.96 becomes 95.0 and reports as
    # ">= 95 (near-identical)".  Display rounds at the JSON/console layer.
    # The operation order matches 0.6 * cos * 100 + 0.2 * r_calls * 100 +
    # 0.2 * r_branches * 100 exactly, so the floats are unchanged.
    cos *= 0.6
    cos *= 100.0
    for key in ("calls", "branches"):
        cos += _count_agreement(
            np.array([s[key] for s in sigs_a], dtype=float),
            np.array([s[key] for s in sigs_b], dtype=float),
        )
    scores: np.ndarray = np.round(cos, _SCORE_NOISE_DECIMALS, out=cos)
    return scores


def _count_agreement(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """The N×M ``0.2 * ratio * 100`` term of two count vectors.

    Counts repeat heavily (a handful of distinct call and branch counts per
    binary), so for a large matrix with few distinct pairs the ratio is
    computed once per pair and gathered.  Small matrices and mostly-distinct
    counts take the direct form, where the lookup would cost more than it saves.
    """
    import numpy as np  # deferred: ~60 ms of startup for non-similarity commands

    if a.size * b.size >= _COUNT_TABLE_MIN_CELLS:
        ua, ia = np.unique(a, return_inverse=True)
        ub, ib = np.unique(b, return_inverse=True)
        if ua.size * ub.size * _COUNT_TABLE_MIN_REUSE <= a.size * b.size:
            table = 0.2 * _pair_ratio(ua[:, None], ub[None, :]) * 100.0
            return table[ia[:, None], ib[None, :]]
    return 0.2 * _pair_ratio(a[:, None], b[None, :]) * 100.0


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
    import numpy as np  # deferred: ~60 ms of startup for non-similarity commands

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
                "score": round(float(best_scores[i]), 1),
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
    binary: Path,
    func_list: Path | None,
    cs_arch: str | int,
    cs_mode: str | int,
) -> list[dict[str, Any]]:
    """Load ``{va, size, name, signature}`` records for one binary."""
    from rebrew.catalog import load_function_structure
    from rebrew.formats.binary_loader import extract_raw_bytes

    funcs: list[dict[str, Any]] = (
        [
            {"va": e.va, "size": e.size, "name": e.name or e.tool_name}
            for e in load_function_structure(func_list)
        ]
        if func_list and func_list.exists()
        else []
    )
    out: list[dict[str, Any]] = []
    skipped: list[int] = []
    for f in funcs:
        va = f.get("va")
        size = int(f.get("size", 0) or 0)
        # VA 0 is a real address on 16-bit targets; only a missing or negative
        # VA means the row is unusable.
        if not isinstance(va, int) or va < 0 or size <= 0:
            continue
        try:
            code = extract_raw_bytes(binary, va, size)
        except Exception as exc:  # one bad function must not kill the report
            skipped.append(va)
            log.debug("skipped function at %#x: %s", va, exc)
            continue
        if not code:
            continue
        sig = disasm_signature(code, va, cs_arch, cs_mode)
        out.append({"va": va, "size": size, "name": str(f.get("name", "")), "signature": sig})
    if skipped:
        # A truncated scan reads as a complete one, and every skipped function
        # is a candidate the report silently dropped.
        log.warning(
            "%d of %d functions could not be read from %s and are absent from the report: %s",
            len(skipped),
            len(funcs),
            binary,
            ", ".join(f"{va:#x}" for va in skipped[:10]) + (" ..." if len(skipped) > 10 else ""),
        )
    return out


def run_binary_similarity(
    other_binary: Path,
    *,
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
            "a function inventory for the other binary is required — pass --other-list "
            "(function_structure.json: [{va, size, name}]) or use --other-target to pick a "
            "configured target",
            json_mode=json_output,
        )

    cs_arch = getattr(cfg, "capstone_arch", DEFAULT_CS_ARCH)
    cs_mode = getattr(cfg, "capstone_mode", DEFAULT_CS_MODE)

    funcs_a = _load_side(
        cfg.target_binary, inventory_path_for(cfg.reversed_dir, cfg), cs_arch, cs_mode
    )
    funcs_b = _load_side(other_binary, other_list, cs_arch, cs_mode)

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
        "  rebrew similarity binary other.exe --other-list functions.json\n\n"
        "  rebrew similarity binary --other-target CLIENT --json\n\n"
        "  rebrew similarity binary other.dll --other-list other.json --limit 20\n\n"
        "[dim]Matches every function of the current target against the other binary's function list by structural signature (mnemonic histogram + call/branch agreement) and aggregates the best matches into a byte-weighted binary similarity.  The lowest-scoring functions are the version deltas.  Same-arch binaries only.[/dim]"
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
        help="Function inventory for the other binary (function_structure.json); excludes --other-target",
    ),
    other_target: str | None = typer.Option(
        None,
        "--other-target",
        help="Use a configured target instead of OTHER_BINARY and --other-list",
    ),
    low: int = typer.Option(
        10, "--limit", help="Maximum lowest-scoring functions to list (0 = no rows)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Report binary-level structural similarity against another binary."""
    low = require_non_negative(option_default(low, 10), "--limit", json_mode=json_output)
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
            other_cfg.target_binary,
            other_list=inventory_path_for(other_cfg.reversed_dir, other_cfg),
            json_output=json_output,
            low_count=low,
            target=target,
        )
        return

    if other_binary is None:
        error_exit(
            "a positional OTHER_BINARY (or --other-target) is required",
            json_mode=json_output,
        )
    run_binary_similarity(
        other_binary, other_list=other_list, json_output=json_output, low_count=low, target=target
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
