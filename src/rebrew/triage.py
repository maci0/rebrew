#!/usr/bin/env python3
"""Cold-start triage: combine FLIRT scan, coverage stats, and recommendations.

Produces a single JSON report suitable for an agent's first action in a session.

Usage:
    rebrew-triage                  Human-readable summary
    rebrew-triage --json           Machine-readable JSON report
"""

import contextlib
import json
from typing import Any

import typer

from rebrew.cli import TargetOption, get_config
from rebrew.next import (
    detect_origin,
    detect_unmatchable,
    estimate_difficulty,
    ignored_symbols,
    load_data,
    parse_byte_delta,
)

app = typer.Typer(
    help="Cold-start triage report for agent sessions.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]
  rebrew-triage               Human-readable summary
  rebrew-triage --json        Full JSON report for agents

[bold]What it includes:[/bold]
  - Coverage statistics (total, covered, by status)
  - Unmatchable function count
  - MATCHING near-miss functions (sorted by byte delta)
  - Top recommendations for new functions
  - FLIRT library match count (if signatures available)

[dim]Combines rebrew-next --stats, --improving, and rebrew-flirt
into a single command for cold-start agent sessions.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    count: int = typer.Option(10, "-n", help="Number of recommendations to include"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate a cold-start triage report."""
    from rebrew.binary_loader import BinaryInfo, load_binary
    from rebrew.skeleton import find_neighbor_file, make_filename

    cfg = get_config(target=target)
    ghidra_funcs, existing, covered_vas = load_data(cfg)
    ignored = ignored_symbols(cfg)
    iat_thunks = getattr(cfg, "iat_thunks", None)
    iat_set: set[int] = set(iat_thunks) if iat_thunks else set()

    # Load binary
    binary_info: BinaryInfo | None = None
    bin_path = cfg.target_binary
    if bin_path and bin_path.exists():
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            binary_info = load_binary(bin_path)

    # --- Coverage stats ---
    total = len(ghidra_funcs)
    covered = len(existing)
    by_status: dict[str, int] = {}
    by_origin: dict[str, int] = {}
    for info in existing.values():
        by_status[info["status"]] = by_status.get(info["status"], 0) + 1
        by_origin[info["origin"]] = by_origin.get(info["origin"], 0) + 1

    exact = by_status.get("EXACT", 0)
    reloc = by_status.get("RELOC", 0)
    matching = by_status.get("MATCHING", 0) + by_status.get("MATCHING_RELOC", 0)
    stub = by_status.get("STUB", 0)

    # --- Unmatchable count ---
    unmatchable_count = 0
    for func in ghidra_funcs:
        fva = func["va"]
        if fva in existing:
            continue
        name = func.get("ghidra_name", "")
        fsize = func.get("size", 0)
        if detect_unmatchable(fva, fsize, binary_info, iat_set, ignored, name):
            unmatchable_count += 1

    actionable = total - covered - unmatchable_count

    # --- Near-miss MATCHING functions ---
    size_by_va: dict[int, int] = {f["va"]: f["size"] for f in ghidra_funcs}
    near_miss: list[dict[str, Any]] = []
    for imp_va, info in sorted(existing.items()):
        if info["status"] in ("MATCHING", "MATCHING_RELOC"):
            imp_size = size_by_va.get(imp_va, 0)
            raw_bd = info.get("blocker_delta", "")
            try:
                delta = int(raw_bd) if raw_bd else parse_byte_delta(info.get("blocker", ""))
            except ValueError:
                delta = parse_byte_delta(info.get("blocker", ""))
            near_miss.append(
                {
                    "va": f"0x{imp_va:08x}",
                    "size": imp_size,
                    "byte_delta": delta,
                    "filename": info["filename"],
                    "blocker": info.get("blocker", ""),
                }
            )
    near_miss.sort(
        key=lambda x: (x["byte_delta"] if x["byte_delta"] is not None else 9999, x["size"])
    )

    # --- Recommendations ---
    sorted_covered = sorted(covered_vas)
    recommendations: list[dict[str, Any]] = []
    for func in ghidra_funcs:
        va = func["va"]
        size = func["size"]
        name = func.get("ghidra_name", f"FUN_{va:08x}")
        if va in existing or va in iat_set or name in ignored:
            continue
        if detect_unmatchable(va, size, binary_info, iat_set, ignored, name):
            continue
        if size < 10:
            continue
        origin = detect_origin(va, name, cfg)
        difficulty, reason = estimate_difficulty(size, name, origin, ignored, cfg=cfg)
        if difficulty == 0:
            continue
        neighbor = find_neighbor_file(va, covered_vas, _sorted_keys=sorted_covered)
        if neighbor:
            suggested_file = f"{cfg.reversed_dir.name}/{neighbor}"
            suggested_action = "append"
        else:
            fname = make_filename(va, name, origin, cfg=cfg)
            suggested_file = f"{cfg.reversed_dir.name}/{fname}"
            suggested_action = "create"
        recommendations.append(
            {
                "va": f"0x{va:08x}",
                "size": size,
                "difficulty": difficulty,
                "origin": origin,
                "name": name,
                "reason": reason,
                "suggested_file": suggested_file,
                "suggested_action": suggested_action,
            }
        )
    recommendations.sort(key=lambda x: (x["difficulty"], x["size"]))
    recommendations = recommendations[:count]

    # --- FLIRT scan (best-effort, requires binary) ---
    flirt_count: int | None = None
    if binary_info is not None:
        try:
            import flirt as flirt_mod

            from rebrew.flirt import find_func_size, load_signatures

            sig_dir = cfg.root / "flirt_sigs"
            if sig_dir.exists():
                sigs = load_signatures(str(sig_dir), json_output=True)
                if sigs:
                    matcher = flirt_mod.compile(sigs)
                    text_name = ".text" if ".text" in binary_info.sections else "__text"
                    if text_name in binary_info.sections:
                        text_sec = binary_info.sections[text_name]
                        code = binary_info.data[
                            text_sec.file_offset : text_sec.file_offset + text_sec.raw_size
                        ]
                        flirt_count = 0
                        for offset in range(0, len(code) - 32, 16):
                            func_size = find_func_size(code, offset)
                            if func_size < 16:
                                continue
                            matches = matcher.match(code[offset : offset + 1024])
                            if matches:
                                names: list[str] = []
                                for m in matches:
                                    for n in m.names:
                                        label = n[0] if isinstance(n, tuple) else str(n)
                                        if label and label not in names:
                                            names.append(label)
                                if names and len(names) <= 3:
                                    flirt_count += 1
        except (ImportError, OSError, KeyError, ValueError):
            pass

    # --- Output ---
    pct = 100 * covered / total if total else 0.0

    if json_output:
        report: dict[str, Any] = {
            "coverage": {
                "total": total,
                "covered": covered,
                "coverage_pct": round(pct, 1),
                "exact": exact,
                "reloc": reloc,
                "matching": matching,
                "stub": stub,
                "unmatchable": unmatchable_count,
                "actionable": actionable,
            },
            "near_miss": near_miss[:count],
            "near_miss_total": len(near_miss),
            "recommendations": recommendations,
        }
        if flirt_count is not None:
            report["flirt_matches"] = flirt_count
        print(json.dumps(report, indent=2))
    else:
        print("=" * 60)
        print("REBREW TRIAGE REPORT")
        print("=" * 60)
        print()
        print(f"Coverage: {covered}/{total} ({pct:.1f}%)")
        print(f"  EXACT: {exact}  RELOC: {reloc}  MATCHING: {matching}  STUB: {stub}")
        print(f"  Unmatchable: {unmatchable_count}  Actionable: ~{actionable}")
        if flirt_count is not None:
            print(f"  FLIRT library matches: {flirt_count}")
        print()

        if near_miss:
            print(
                f"Near-miss functions ({len(near_miss)} total, showing top {min(count, len(near_miss))}):"
            )
            for nm in near_miss[:count]:
                delta_str = f"{nm['byte_delta']}B" if nm["byte_delta"] is not None else "?"
                print(f"  {nm['va']}  {nm['size']:4d}B  Δ{delta_str:>5s}  {nm['filename']}")
            print()

        if recommendations:
            print(f"Recommendations (top {len(recommendations)}):")
            for r in recommendations:
                stars = "*" * r["difficulty"]
                print(f"  {r['va']}  {r['size']:4d}B  {stars:5s}  {r['origin']:>6s}  {r['name']}")
            print()


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
