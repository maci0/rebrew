"""verify-placement — post-edit check: compare .data symbol VAs vs the metadata.

The linked ``.data`` section is the concatenation of per-TU contributions in
link order.  After editing sources, this command walks the link's object
files (objdump on each obj, in link order), computes every symbol's current
``.data`` VA, and compares it against the data metadata
(``src/rebrew-data.toml``).  Misplaced symbols mean the object order or a
TU's own layout drifted — the reccmp "0 aligned" symptom.

Usage:
    rebrew build check-data-placement [--data-metadata src/rebrew-data.toml] [--json]
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer

from rebrew.binary_loader import load_binary
from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
    require_non_negative,
    untrusted_ident,
)
from rebrew.data_layout import built_data_va

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew build check-data-placement · · · · · · Compare .data symbol VAs against the metadata\n\n"
    "  rebrew build check-data-placement --cut 0x100273e0 · · · Veto a size edit at this VA\n\n"
    "  rebrew build check-data-placement --target win16 --json · Machine-readable result\n"
)


def data_shift_scores(
    reference: bytes, built: bytes, *, step: int, shifts: int
) -> list[dict[str, int]]:
    """Matching bytes after each candidate shift of *built* against *reference*.

    A size edit moves every byte after its cut. Score each shift on the tail
    and let the caller decide whether shift 0 already wins.
    """
    if step < 1:
        raise ValueError("step must be positive")
    width = len(reference)
    scores = []
    for delta in range(-shifts * step, shifts * step + 1, step):
        if delta < 0:
            ref = reference[-delta:]
            cand = built[: width + delta]
        else:
            ref = reference[: width - delta]
            cand = built[delta : delta + len(ref)]
        limit = min(len(ref), len(cand))
        scores.append({"shift": delta, "matches": sum(ref[i] == cand[i] for i in range(limit))})
    return scores


app = typer.Typer(
    help="Compare .data symbol VAs of the current build against the data metadata.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    data_metadata: Path = typer.Option(
        Path("src/rebrew-data.toml"), "--data-metadata", help="Data metadata toml path"
    ),
    built: Path | None = typer.Option(
        None,
        "--built",
        help="Built binary to inspect (default: build/<target>)",
    ),
    limit: int = typer.Option(15, "--limit", help="Max misplaced symbols to print"),
    cut: str | None = typer.Option(
        None, "--cut", help="VA of a .data cut. Score size shifts of the bytes after it"
    ),
    shift_step: int = typer.Option(8, "--shift-step", help="Bytes between candidate size shifts"),
    shifts: int = typer.Option(4, "--shifts", help="Candidate shifts to try on each side of zero"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Build-then-compare: .data symbol VAs of the current build vs the metadata."""
    limit = require_non_negative(option_default(limit, 15), "--limit", json_mode=json_output)
    cfg = require_config(target=target, json_mode=json_output)
    root = Path(cfg.root)
    metadata = data_metadata if data_metadata.is_absolute() else root / data_metadata
    if not metadata.exists():
        error_exit(f"data metadata not found: {metadata}", json_mode=json_output)
    built = option_default(built, None)
    if built is None:
        # The ACTIVE target's build output — one project serves several
        # binaries and each keeps its own build/<target> file.  text-audit
        # resolves the same default the same way.
        built = Path("build") / cfg.target_name
    dll = built if built.is_absolute() else root / built
    if not dll.exists():
        error_exit(
            f"{dll} not found — build the project first (or pass --built <path>)",
            json_mode=json_output,
        )
    from rebrew.data_layout import data_symbols, link_objects, obj_data_symbol_offsets

    data_va = built_data_va(dll)
    expected = data_symbols(metadata)

    here: dict[str, int] = {}
    tot = 0
    # Per-object drift tallies (reccmp `roadmap`-style placement statistics):
    # which linked object contributes how many misplaced .data symbols and
    # how far off the whole object sits — one drifted TU shifts everything
    # after it by the same delta.
    per_object: dict[str, dict[str, int]] = {}
    try:
        for obj in link_objects(root):
            dsize, syms = obj_data_symbol_offsets(obj)
            obj_stats = per_object.setdefault(
                str(obj), {"symbols": 0, "misplaced": 0, "delta_sum": 0}
            )
            for sym, off in syms.items():
                va = data_va + tot + off
                here.setdefault(sym, va)
                if sym in expected:
                    obj_stats["symbols"] += 1
                    if va != expected[sym]:
                        obj_stats["misplaced"] += 1
                        obj_stats["delta_sum"] += va - expected[sym]
            tot += dsize
    except (RuntimeError, OSError) as exc:
        error_exit(f"cannot inventory build objects: {exc}", json_mode=json_output)

    good = bad = 0
    bads: list[tuple[str, int, int]] = []
    for sym, addr in here.items():
        if sym in expected:
            if addr == expected[sym]:
                good += 1
            else:
                bad += 1
                bads.append((sym, expected[sym], addr))
    bads.sort(key=lambda t: -abs(t[1] - t[2]))

    shift_report = _shift_report(cfg, dll, cut, shift_step, shifts, json_output)

    # Only objects with at least one misplaced symbol, worst delta first.
    drifted: list[dict[str, Any]] = sorted(
        (
            # Two decimals: round() with no digits returns an int and banks
            # rounds, so a mean byte delta of 1/2 read as 0 and the sort put
            # the drifted object last.
            {
                "object": obj,
                **stats,
                "mean_delta": round(stats["delta_sum"] / stats["misplaced"], 2),
            }
            for obj, stats in per_object.items()
            if stats["misplaced"]
        ),
        key=lambda s: -abs(s["mean_delta"]),
    )

    if json_output:
        json_print(
            {
                "symbols": len(here),
                "matched": good + bad,
                "correct": good,
                "misplaced": bad,
                "misplaced_list": [
                    {"symbol": s, "expected": f"0x{e:x}", "actual": f"0x{a:x}", "delta": a - e}
                    for s, e, a in bads[:limit]
                ],
                "per_object": drifted,
                "shift": shift_report,
            }
        )
    else:
        console.print(
            f"symbols: {len(here)}  toml-matched: {good + bad}  correct-VA: {good}  misplaced: {bad}"
        )
        for sym, exp, act in bads[:limit]:
            console.print(
                f"  {untrusted_ident(sym):32} exp {exp:#010x}  our {act:#010x}  d {act - exp:+#x}"
            )
        if shift_report is not None:
            best = shift_report["best_shift"]
            verdict = (
                "size edit can only lose" if best == 0 else f"tail matches best at shift {best:+d}"
            )
            console.print(f"  shift veto at {shift_report['cut']}: {verdict}")
            for row in shift_report["scores"]:
                mark = "  <-- current" if row["shift"] == 0 else ""
                console.print(f"    shift {row['shift']:+d}  {row['matches']} matches{mark}")
        if drifted:
            console.print("  [dim]placement drift by object (roadmap-style):[/dim]")
            for stats in drifted[:limit]:
                console.print(
                    f"    {untrusted_ident(Path(stats['object']).name):32} "
                    f"{stats['misplaced']}/{stats['symbols']} misplaced  "
                    f"mean delta {stats['mean_delta']:+.2f}B"
                )
    if bad:
        raise typer.Exit(code=EXIT_MISMATCH)


def _shift_report(
    cfg: Any, dll: Path, cut: str | None, step: int, shifts: int, json_output: bool
) -> dict[str, Any] | None:
    """Score the `.data` tail after *cut*. None when the caller did not ask."""
    if cut is None:
        return None
    from rebrew.cli import parse_va

    step = require_non_negative(option_default(step, 8), "--shift-step", json_mode=json_output)
    shifts = require_non_negative(option_default(shifts, 4), "--shifts", json_mode=json_output)
    if step < 1 or shifts < 1:
        error_exit("--shift-step and --shifts must be positive", json_mode=json_output)
        return None
    cut_va = parse_va(cut, json_mode=json_output)
    ref = load_binary(Path(cfg.target_binary))
    built = load_binary(dll)
    ref_data = ref.sections.get(".data")
    built_data = built.sections.get(".data")
    if ref_data is None or built_data is None:
        error_exit("reference or build has no .data section", json_mode=json_output)
        return None
    if not ref_data.va <= cut_va < ref_data.va + ref_data.raw_size:
        error_exit(f"--cut {cut} is outside the reference .data section", json_mode=json_output)
    ref_off = ref_data.file_offset + (cut_va - ref_data.va)
    built_off = built_data.file_offset + (cut_va - ref_data.va)
    ref_tail = ref.data[ref_off : ref_data.file_offset + ref_data.raw_size]
    built_tail = built.data[built_off : built_data.file_offset + built_data.raw_size]
    scores = data_shift_scores(ref_tail, built_tail, step=step, shifts=shifts)
    best = max(scores, key=lambda row: (row["matches"], -abs(row["shift"])))
    return {"cut": hex(cut_va), "best_shift": best["shift"], "scores": scores}


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
