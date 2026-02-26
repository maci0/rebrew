#!/usr/bin/env python3
"""next.py - Show what to work on next in the rebrew RE project.

Analyzes the current state of reverse engineering progress and recommends
the next functions to work on, sorted by estimated difficulty and priority.
Supports neighbor-file detection (suggesting append targets for multi-function
files) and grouping adjacent uncovered functions by address proximity.

Usage:
    rebrew-next                     # Show top 20 recommendations
    rebrew-next --count 50          # Show top 50
    rebrew-next --origin GAME       # Only GAME functions
    rebrew-next --improving         # Show MATCHING functions to improve
    rebrew-next --stats             # Show overall progress statistics
    rebrew-next --group             # Group adjacent uncovered functions
"""

import contextlib
import json
import sys
from typing import Any

import typer

from rebrew.binary_loader import BinaryInfo, load_binary
from rebrew.cli import TargetOption, get_config
from rebrew.naming import (
    UncoveredItem,
    detect_origin,
    detect_unmatchable,
    estimate_difficulty,
    find_neighbor_file,
    group_uncovered,
    ignored_symbols,
    load_data,
    make_filename,
    parse_byte_delta,
)

_EPILOG = """\
[bold]Examples:[/bold]
  rebrew-next                          Top 20 recommendations (easiest first)
  rebrew-next --count 50               Show top 50
  rebrew-next --origin GAME            Only GAME-origin functions
  rebrew-next --improving              Show MATCHING functions to improve
  rebrew-next --stats                  Overall progress statistics
  rebrew-next --commands               Include rebrew-test commands for each
  rebrew-next --unmatchable            Show detected unmatchable functions
  rebrew-next --min-size 50 --max-size 200   Filter by function size
  rebrew-next --group                  Group adjacent functions by proximity
  rebrew-next --group --group-gap 8192 Custom grouping distance (bytes)
  rebrew-next --group --commands       Show batch skeleton commands per group
  rebrew-next --json                  Machine-readable JSON output
  rebrew-next --stats --json          JSON progress statistics

[bold]Difficulty ratings:[/bold]
  *      Tiny function (< 80B), likely getter/setter
  **     Small function (< 150B), straightforward
  ***    Medium function (< 250B), branches/loops
  ****   Large function (< 400B), complex control flow
  *****  Very large function, significant effort

[dim]Reads function list from ghidra_functions.json and existing .c files.
Auto-skips IAT thunks, single-byte stubs, and ignored symbols.[/dim]"""

app = typer.Typer(
    help="Show what to work on next in the rebrew RE project.",
    rich_markup_mode="rich",
)


@app.command(epilog=_EPILOG)
def main(
    count: int = typer.Option(20, "--count", "-n", help="Number of recommendations"),
    origin_filter: str | None = typer.Option(
        None, "--origin", help="Filter by origin (GAME, MSVCRT, ZLIB)"
    ),
    improving: bool = typer.Option(False, help="Show MATCHING functions to improve"),
    stats: bool = typer.Option(False, help="Show overall progress statistics"),
    max_size: int = typer.Option(9999, help="Max function size"),
    min_size: int = typer.Option(10, help="Min function size"),
    commands: bool = typer.Option(False, help="Print test commands for each"),
    show_unmatchable: bool = typer.Option(
        False, "--unmatchable", help="Show detected unmatchable functions"
    ),
    group: bool = typer.Option(False, help="Group adjacent uncovered functions"),
    group_gap: int = typer.Option(0x1000, help="Max address gap for grouping"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Show what to work on next in the rebrew RE project."""
    try:
        cfg = get_config(target=target)
    except (FileNotFoundError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise typer.Exit(code=1) from None
    ghidra_funcs, existing, covered_vas = load_data(cfg)
    ignored = ignored_symbols(cfg)
    iat_thunks = getattr(cfg, "iat_thunks", None)
    iat_set: set[int] = set(iat_thunks) if iat_thunks else set()

    # Load binary for byte-pattern detection
    binary_info: BinaryInfo | None = None
    bin_path = cfg.target_binary
    if bin_path and bin_path.exists():
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            binary_info = load_binary(bin_path)

    # --stats mode
    if stats:
        total = len(ghidra_funcs)
        covered = len(existing)
        uncovered_count = total - covered

        # Count by status
        by_status: dict[str, int] = {}
        by_origin: dict[str, int] = {}
        for info in existing.values():
            s = info["status"]
            o = info["origin"]
            by_status[s] = by_status.get(s, 0) + 1
            by_origin[o] = by_origin.get(o, 0) + 1

        exact = by_status.get("EXACT", 0)
        reloc = by_status.get("RELOC", 0)
        matching = by_status.get("MATCHING", 0) + by_status.get("MATCHING_RELOC", 0)
        stub = by_status.get("STUB", 0)
        perfect = exact + reloc

        # Count unmatchable via byte patterns
        unmatchable_count = 0
        unmatchable_reasons: dict[str, int] = {}
        for func in ghidra_funcs:
            fva = func["va"]
            if fva in existing:
                continue
            name = func.get("ghidra_name", "")
            fsize = func.get("size", 0)
            reason = detect_unmatchable(fva, fsize, binary_info, iat_set, ignored, name)
            if reason:
                unmatchable_count += 1
                key = reason.split(":")[0].strip()
                unmatchable_reasons[key] = unmatchable_reasons.get(key, 0) + 1

        actionable = uncovered_count - unmatchable_count
        pct = 100 * covered / total if total else 0.0

        if json_output:
            print(
                json.dumps(
                    {
                        "mode": "stats",
                        "total": total,
                        "covered": covered,
                        "coverage_pct": round(pct, 1),
                        "by_status": by_status,
                        "by_origin": by_origin,
                        "unmatchable": unmatchable_count,
                        "actionable": actionable,
                    },
                    indent=2,
                )
            )
            return

        print("=" * 60)
        print("REBREW REVERSE ENGINEERING PROGRESS")
        print("=" * 60)
        print()
        print(f"Total functions (Ghidra):  {total}")
        print(f"Covered (.c files):        {covered} ({pct:.1f}%)")
        print(f"  EXACT match:             {exact}")
        print(f"  RELOC match:             {reloc}")
        print(f"  MATCHING (near-miss):    {matching}")
        print(f"  STUB (placeholder):      {stub}")
        perfect_pct = 100 * perfect / total if total else 0.0
        print(f"  Perfect (EXACT+RELOC):   {perfect} ({perfect_pct:.1f}%)")
        print()
        print(f"Uncovered (no .c file):    {uncovered_count}")
        print(f"  Auto-detected unmatchable: {unmatchable_count}")
        for r, c in sorted(unmatchable_reasons.items(), key=lambda x: -x[1]):
            print(f"    {r}: {c}")
        print(f"  Actionable remaining:    ~{actionable}")
        print()

        if matching > 0:
            print(f"MATCHING functions that could be improved to EXACT/RELOC: {matching}")
            print("  Run: rebrew-next --improving")
        return

    # --improving mode
    if improving:
        size_by_va: dict[int, int] = {f["va"]: f["size"] for f in ghidra_funcs}
        matching_items: list[tuple[int, int, int | None, dict[str, str]]] = []
        for imp_va, info in sorted(existing.items()):
            if info["status"] in ("MATCHING", "MATCHING_RELOC"):
                imp_size = size_by_va.get(imp_va, 0)
                # Use structured BLOCKER_DELTA if available, else parse from text
                raw_bd = info.get("blocker_delta", "")
                try:
                    delta = int(raw_bd) if raw_bd else parse_byte_delta(info.get("blocker", ""))
                except ValueError:
                    delta = parse_byte_delta(info.get("blocker", ""))
                matching_items.append((imp_va, imp_size, delta, info))

        if not matching_items:
            if json_output:
                print(
                    json.dumps({"mode": "improving", "total": 0, "count": 0, "items": []}, indent=2)
                )
            else:
                print("No MATCHING functions found.")
            return

        # Sort by delta ascending (smallest diff = easiest to fix), then by size
        matching_items.sort(key=lambda x: (x[2] if x[2] is not None else 9999, x[1]))

        if json_output:
            items = []
            for imp_va, imp_size, delta, info in matching_items[:count]:
                items.append(
                    {
                        "va": f"0x{imp_va:08x}",
                        "size": imp_size,
                        "byte_delta": delta,
                        "origin": info["origin"],
                        "filename": info["filename"],
                        "blocker": info.get("blocker", ""),
                    }
                )
            print(
                json.dumps(
                    {
                        "mode": "improving",
                        "total": len(matching_items),
                        "count": len(items),
                        "items": items,
                    },
                    indent=2,
                )
            )
            return

        print(f"MATCHING functions to improve ({len(matching_items)} total):")
        print(
            f"{'VA':>12s}  {'Size':>5s}  {'Delta':>5s}  {'Origin':>6s}  {'File':30s}  {'Blocker'}"
        )
        print(f"{'---':>12s}  {'---':>5s}  {'---':>5s}  {'---':>6s}  {'---':30s}  {'---'}")
        for imp_va, imp_size, delta, info in matching_items[:count]:
            delta_str = f"{delta}B" if delta is not None else "?"
            print(
                f"  0x{imp_va:08x}  {imp_size:4d}B  {delta_str:>5s}  {info['origin']:>6s}  {info['filename']:30s}  {info.get('blocker', '')}"
            )

            if commands:
                symbol = info.get("symbol") or f"_func_{imp_va:08x}"
                imp_cflags = (getattr(cfg, "cflags_presets", None) or {}).get(
                    info["origin"], "/O2 /Gd"
                )
                rel_path = f"{cfg.reversed_dir.name}/{info['filename']}"
                print(
                    f'    TEST: rebrew-test {rel_path} {symbol} --va 0x{imp_va:08x} --size {imp_size} --cflags "{imp_cflags}"'
                )
        return

    # --unmatchable mode: show detected unmatchable functions
    if show_unmatchable:
        unmatchable_list: list[tuple[int, int, str, str]] = []
        for func in ghidra_funcs:
            um_va = func["va"]
            um_size = func["size"]
            um_name = func.get("ghidra_name", f"FUN_{um_va:08x}")
            if um_va in existing:
                continue
            reason = detect_unmatchable(um_va, um_size, binary_info, iat_set, ignored, um_name)
            if reason:
                unmatchable_list.append((um_va, um_size, um_name, reason))

        if json_output:
            items = [
                {"va": f"0x{uva:08x}", "size": usz, "name": un, "reason": ur}
                for uva, usz, un, ur in unmatchable_list[:count]
            ]
            print(
                json.dumps(
                    {
                        "mode": "unmatchable",
                        "total": len(unmatchable_list),
                        "count": len(items),
                        "items": items,
                    },
                    indent=2,
                )
            )
            return

        if not unmatchable_list:
            print("No unmatchable functions detected.")
            return

        print(f"Detected unmatchable functions ({len(unmatchable_list)} total):")
        print(f"{'VA':>12s}  {'Size':>5s}  {'Name':30s}  {'Reason'}")
        print(f"{'---':>12s}  {'---':>5s}  {'---':30s}  {'---'}")
        for um_va, um_size, um_name, reason in unmatchable_list[:count]:
            print(f"  0x{um_va:08x}  {um_size:4d}B  {um_name:30s}  {reason}")
        return

    # Default: recommend next functions to work on
    sorted_covered = sorted(covered_vas)  # pre-sort for O(log n) neighbor lookups
    uncovered: list[UncoveredItem] = []
    for func in ghidra_funcs:
        va = func["va"]
        size = func["size"]
        name = func.get("ghidra_name", f"FUN_{va:08x}")

        if va in existing or va in iat_set:
            continue
        if name in ignored:
            continue

        # Auto-detect unmatchable
        reason = detect_unmatchable(va, size, binary_info, iat_set, ignored, name)
        if reason:
            continue  # skip unmatchable

        if size < min_size or size > max_size:
            continue

        origin = detect_origin(va, name, cfg)
        if origin_filter and origin != origin_filter:
            continue

        difficulty, reason = estimate_difficulty(size, name, origin, ignored, cfg=cfg)
        if difficulty == 0:
            continue  # Skip ignored symbols

        neighbor = find_neighbor_file(va, covered_vas, _sorted_keys=sorted_covered)
        uncovered.append((difficulty, size, va, name, origin, reason, neighbor))

    # Sort by difficulty then size
    uncovered.sort(key=lambda x: (x[0], x[1]))

    if not uncovered:
        if json_output:
            print(
                json.dumps(
                    {"mode": "recommendations", "total_uncovered": 0, "count": 0, "items": []},
                    indent=2,
                )
            )
        else:
            print("No uncovered functions found matching criteria. Great progress!")
        return

    # --group mode: cluster adjacent uncovered functions
    if group:
        groups = group_uncovered(uncovered, max_gap=group_gap)
        multi_groups = [g for g in groups if len(g) > 1]
        single_count = sum(1 for g in groups if len(g) == 1)

        if json_output:
            json_groups: list[dict[str, Any]] = []
            for gi, grp in enumerate(multi_groups[:count], 1):
                grp_total = sum(item[1] for item in grp)
                grp_va_lo = min(item[2] for item in grp)
                grp_va_hi = max(item[2] for item in grp)
                grp_neighbor = None
                for item in grp:
                    if item[6]:
                        grp_neighbor = item[6]
                        break
                funcs = [
                    {
                        "va": f"0x{fva:08x}",
                        "size": fsz,
                        "difficulty": fdiff,
                        "origin": forg,
                        "name": fname,
                    }
                    for fdiff, fsz, fva, fname, forg, _, _ in grp
                ]
                json_groups.append(
                    {
                        "group_id": gi,
                        "function_count": len(grp),
                        "total_size": grp_total,
                        "va_range": [f"0x{grp_va_lo:08x}", f"0x{grp_va_hi:08x}"],
                        "neighbor_file": grp_neighbor,
                        "functions": funcs,
                    }
                )
            print(
                json.dumps(
                    {
                        "mode": "groups",
                        "group_count": len(multi_groups),
                        "singleton_count": single_count,
                        "groups": json_groups,
                    },
                    indent=2,
                )
            )
            return

        print(f"Function groups ({len(multi_groups)} groups, {single_count} singletons):")
        print()

        for gi, grp in enumerate(multi_groups[:count], 1):
            total_size = sum(item[1] for item in grp)
            va_lo = min(item[2] for item in grp)
            va_hi = max(item[2] for item in grp)
            # Check if any member has a neighbor file
            neighbor = None
            for item in grp:
                if item[6]:
                    neighbor = item[6]
                    break

            header = (
                f"Group {gi}: {len(grp)} functions, {total_size}B total "
                f"(0x{va_lo:08x}\u20130x{va_hi:08x})"
            )
            if neighbor:
                header += f"  [\u2192 {neighbor}]"
            print(header)

            for diff, grp_size, grp_va, grp_name, grp_origin, _reason, _ in grp:
                stars = "*" * diff
                print(
                    f"    0x{grp_va:08x}  {grp_size:4d}B  {stars:4s}  {grp_origin:>6s}  {grp_name}"
                )

            if commands:
                if neighbor:
                    for item in grp:
                        print(f"    GEN: rebrew-skeleton 0x{item[2]:08x} --append {neighbor}")
                else:
                    first = grp[0]
                    print(f"    GEN: rebrew-skeleton 0x{first[2]:08x}")
                    fname = make_filename(first[2], first[3], first[4])
                    for item in grp[1:]:
                        print(f"    GEN: rebrew-skeleton 0x{item[2]:08x} --append {fname}")
            print()

        return

    if json_output:
        items = []
        for i, (diff, rec_size, rec_va, rec_name, rec_origin, rec_reason, neighbor) in enumerate(
            uncovered[:count], 1
        ):
            if neighbor:
                suggested_file = f"{cfg.reversed_dir.name}/{neighbor}"
                suggested_action = "append"
            else:
                fname = make_filename(rec_va, rec_name, rec_origin, cfg=cfg)
                suggested_file = f"{cfg.reversed_dir.name}/{fname}"
                suggested_action = "create"
            items.append(
                {
                    "rank": i,
                    "va": f"0x{rec_va:08x}",
                    "size": rec_size,
                    "difficulty": diff,
                    "origin": rec_origin,
                    "name": rec_name,
                    "reason": rec_reason,
                    "neighbor_file": neighbor,
                    "suggested_file": suggested_file,
                    "suggested_action": suggested_action,
                }
            )
        print(
            json.dumps(
                {
                    "mode": "recommendations",
                    "total_uncovered": len(uncovered),
                    "count": count,
                    "items": items,
                },
                indent=2,
            )
        )
        return

    print(f"Next {count} functions to work on (of {len(uncovered)} remaining):")
    print()
    print(
        f"{'#':>3s}  {'VA':>12s}  {'Size':>5s}  {'Diff':>4s}  {'Origin':>6s}  {'Name':30s}  {'Reason'}"
    )
    print(f"{'---':>3s}  {'---':>12s}  {'---':>5s}  {'---':>4s}  {'---':>6s}  {'---':30s}  {'---'}")

    for i, (diff, rec_size, rec_va, rec_name, rec_origin, rec_reason, neighbor) in enumerate(
        uncovered[:count], 1
    ):
        stars = "*" * diff
        line = f"{i:3d}  0x{rec_va:08x}  {rec_size:4d}B  {stars:4s}  {rec_origin:>6s}  {rec_name:30s}  {rec_reason}"
        if neighbor:
            line += f"  [\u2192 {neighbor}]"
        print(line)

        if commands:
            rec_cflags = (getattr(cfg, "cflags_presets", None) or {}).get(rec_origin, "/O2 /Gd")
            if neighbor:
                print(f"     GEN: rebrew-skeleton 0x{rec_va:08x} --append {neighbor}")
            else:
                print(f"     GEN: rebrew-skeleton 0x{rec_va:08x}")
            print(
                f'     TEST: rebrew-test {cfg.reversed_dir.name}/... _... --va 0x{rec_va:08x} --size {rec_size} --cflags "{rec_cflags}"'
            )

    print()
    print("To generate a skeleton: rebrew-skeleton 0x<VA>")
    print("To generate a batch:    rebrew-skeleton --batch 10 --origin GAME")


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
