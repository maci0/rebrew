"""next.py - Show what to work on next in the rebrew RE project.

Analyzes the current state of reverse engineering progress and recommends
the next functions to work on, sorted by estimated difficulty and priority.
Supports neighbor-file detection (suggesting append targets for multi-function
files) and grouping adjacent uncovered functions by address proximity.

Usage:
    rebrew next                     # Show top 20 recommendations
    rebrew next --count 50          # Show top 50
    rebrew next --origin GAME       # Only GAME functions
    rebrew next --improving         # Show MATCHING functions to improve
    rebrew next --stats             # Show overall progress statistics
    rebrew next --group             # Group adjacent uncovered functions
"""

import bisect
import contextlib
import difflib
from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from rebrew.binary_loader import BinaryInfo, load_binary
from rebrew.cli import TargetOption, json_print, require_config
from rebrew.naming import (
    UncoveredItem,
    detect_unmatchable,
    estimate_difficulty,
    find_neighbor_file,
    group_uncovered,
    ignored_symbols,
    load_data,
    make_filename,
    parse_byte_delta,
)

console = Console(stderr=True)

_EPILOG = """\
[bold]Examples:[/bold]

rebrew next                          Top 20 recommendations (easiest first)

rebrew next --count 50               Show top 50

rebrew next --origin GAME            Only GAME-origin functions

rebrew next --improving              Show MATCHING functions to improve

rebrew next --stats                  Overall progress statistics

rebrew next --commands               Include rebrew test commands for each

rebrew next --unmatchable            Show detected unmatchable functions

rebrew next --min-size 50 --max-size 200   Filter by function size

rebrew next --group                  Group adjacent functions by proximity

rebrew next --group --group-gap 8192 Custom grouping distance (bytes)

rebrew next --group --commands       Show batch skeleton commands per group

rebrew next --json                  Machine-readable JSON output

rebrew next --stats --json          JSON progress statistics

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
    epilog=_EPILOG,
)


# ---------------------------------------------------------------------------
# Mode helpers
# ---------------------------------------------------------------------------


def _show_stats(
    ghidra_funcs: list[Any],
    existing: dict[int, dict[str, str]],
    binary_info: BinaryInfo | None,
    iat_set: set[int],
    ignored: set[str],
    json_output: bool,
) -> None:
    """Show overall progress statistics (--stats)."""
    total = len(ghidra_funcs)
    covered = len(existing)
    uncovered_count = total - covered

    by_status: dict[str, int] = {}
    for info in existing.values():
        s = info["status"]
        by_status[s] = by_status.get(s, 0) + 1

    exact = by_status.get("EXACT", 0)
    reloc = by_status.get("RELOC", 0)
    matching = by_status.get("MATCHING", 0) + by_status.get("MATCHING_RELOC", 0)
    stub = by_status.get("STUB", 0)
    perfect = exact + reloc

    unmatchable_count = 0
    unmatchable_reasons: dict[str, int] = {}
    for func in ghidra_funcs:
        fva = func.va
        if fva in existing:
            continue
        name = func.name
        fsize = func.size
        reason = detect_unmatchable(fva, fsize, binary_info, iat_set, ignored, name)
        if reason:
            unmatchable_count += 1
            key = reason.split(":")[0].strip()
            unmatchable_reasons[key] = unmatchable_reasons.get(key, 0) + 1

    actionable = uncovered_count - unmatchable_count
    pct = 100 * covered / total if total else 0.0

    if json_output:
        json_print(
            {
                "mode": "stats",
                "total": total,
                "covered": covered,
                "coverage_pct": round(pct, 1),
                "by_status": by_status,
                "unmatchable": unmatchable_count,
                "actionable": actionable,
            }
        )
        return

    table = Table(title="REBREW REVERSE ENGINEERING PROGRESS", show_header=False)
    table.add_column("Category", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total functions (Ghidra)", str(total))
    table.add_row("Covered (.c files)", f"{covered} ({pct:.1f}%)")
    table.add_row("  EXACT match", f"[green]{exact}[/]")
    table.add_row("  RELOC match", f"[green]{reloc}[/]")
    table.add_row("  MATCHING (near-miss)", f"[yellow]{matching}[/]")
    table.add_row("  STUB (placeholder)", f"[red]{stub}[/]")
    perfect_pct = 100 * perfect / total if total else 0.0
    table.add_row("  Perfect (EXACT+RELOC)", f"[bold green]{perfect} ({perfect_pct:.1f}%)[/]")
    table.add_row("", "")
    table.add_row("Uncovered (no .c file)", str(uncovered_count))
    table.add_row("  Auto-detected unmatchable", str(unmatchable_count))
    for r, c in sorted(unmatchable_reasons.items(), key=lambda x: -x[1]):
        table.add_row(f"    {r}", str(c))
    table.add_row("  Actionable remaining", f"~{actionable}")
    console.print(table)

    if matching > 0:
        console.print(f"\n[bold]MATCHING functions that could be improved:[/] {matching}")
        console.print("  Run: [cyan]rebrew next --improving[/]")


def _show_improving(
    ghidra_funcs: list[Any],
    existing: dict[int, dict[str, str]],
    cfg: Any,
    count: int,
    commands: bool,
    json_output: bool,
) -> None:
    """Show MATCHING functions to improve (--improving)."""
    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    matching_items: list[tuple[int, int, int | None, dict[str, str]]] = []
    for imp_va, info in sorted(existing.items()):
        if info["status"] in ("MATCHING", "MATCHING_RELOC"):
            imp_size = size_by_va.get(imp_va) or int(info.get("size", 0))
            raw_bd = info.get("blocker_delta", "")
            try:
                delta = int(raw_bd) if raw_bd else parse_byte_delta(info.get("blocker", ""))
            except ValueError:
                delta = parse_byte_delta(info.get("blocker", ""))
            matching_items.append((imp_va, imp_size, delta, info))

    if not matching_items:
        if json_output:
            json_print({"mode": "improving", "total": 0, "count": 0, "items": []})
        else:
            console.print("No MATCHING functions found.")
        return

    matching_items.sort(key=lambda x: (x[2] if x[2] is not None else 9999, x[1]))

    if json_output:
        items = []
        for imp_va, imp_size, delta, info in matching_items[:count]:
            items.append(
                {
                    "va": f"0x{imp_va:08x}",
                    "size": imp_size,
                    "byte_delta": delta,
                    "filename": info["filename"],
                    "symbol": info.get("symbol", ""),
                    "blocker": info.get("blocker", ""),
                }
            )
        json_print(
            {
                "mode": "improving",
                "total": len(matching_items),
                "count": len(items),
                "items": items,
            }
        )
        return

    table = Table(title=f"MATCHING Functions to Improve ({len(matching_items)} total)")
    table.add_column("VA", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Delta", justify="right")
    table.add_column("File", style="magenta")
    table.add_column("Blocker")

    for imp_va, imp_size, delta, info in matching_items[:count]:
        delta_str = f"{delta}B" if delta is not None else "?"
        delta_style = (
            "green"
            if delta is not None and delta <= 5
            else "yellow"
            if delta is not None and delta <= 20
            else ""
        )
        table.add_row(
            f"0x{imp_va:08x}",
            f"{imp_size}B",
            Text(delta_str, style=delta_style),
            info["filename"],
            info.get("blocker", ""),
        )

    console.print(table)

    if commands:
        console.print()
        for imp_va, imp_size, _delta, info in matching_items[:count]:
            symbol = info.get("symbol") or f"_func_{imp_va:08x}"
            imp_cflags = cfg.base_cflags or "/O2 /Gd"
            rel_path = f"{cfg.reversed_dir.name}/{info['filename']}"
            if info.get("symbol"):
                console.print(
                    f'  [dim]TEST:[/] rebrew test {rel_path} {symbol} --cflags "{imp_cflags}"'
                )
            else:
                console.print(
                    f'  [dim]TEST:[/] rebrew test {rel_path} {symbol} --va 0x{imp_va:08x} --size {imp_size} --cflags "{imp_cflags}"'
                )


def _show_unmatchable(
    ghidra_funcs: list[Any],
    existing: dict[int, dict[str, str]],
    binary_info: BinaryInfo | None,
    iat_set: set[int],
    ignored: set[str],
    count: int,
    json_output: bool,
) -> None:
    """Show detected unmatchable functions (--unmatchable)."""
    unmatchable_list: list[tuple[int, int, str, str]] = []
    for func in ghidra_funcs:
        um_va = func.va
        um_size = func.size
        um_name = func.name or f"FUN_{um_va:08x}"
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
        json_print(
            {
                "mode": "unmatchable",
                "total": len(unmatchable_list),
                "count": len(items),
                "items": items,
            }
        )
        return

    if not unmatchable_list:
        console.print("No unmatchable functions detected.")
        return

    table = Table(title=f"Detected Unmatchable Functions ({len(unmatchable_list)} total)")
    table.add_column("VA", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Name", style="magenta")
    table.add_column("Reason", style="yellow")

    for um_va, um_size, um_name, reason in unmatchable_list[:count]:
        table.add_row(f"0x{um_va:08x}", f"{um_size}B", um_name, reason)

    console.print(table)


def _build_recommendations(
    ghidra_funcs: list[Any],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
    binary_info: BinaryInfo | None,
    iat_set: set[int],
    ignored: set[str],
    cfg: Any,
    min_size: int,
    max_size: int,
) -> list[UncoveredItem]:
    """Build and return sorted list of recommended uncovered functions."""
    # Build index of already-matched function bytes for similarity comparison
    matched_funcs: list[tuple[int, bytes]] = []
    if binary_info:
        from rebrew.binary_loader import extract_bytes_at_va

        for m_va, info in existing.items():
            if info.get("status") in ("EXACT", "RELOC"):
                m_size_val = info.get("size")
                if not m_size_val:
                    for f in ghidra_funcs:
                        if f.va == m_va:
                            m_size_val = str(f.size)
                            break
                if m_size_val:
                    parsed_m_size = int(m_size_val)
                    if parsed_m_size > 0:
                        try:
                            m_bytes = extract_bytes_at_va(binary_info, m_va, parsed_m_size)
                            if m_bytes:
                                matched_funcs.append((parsed_m_size, m_bytes))
                        except (OSError, ValueError, KeyError):
                            pass

    matched_funcs.sort(key=lambda x: x[0])

    sorted_covered = sorted(covered_vas)
    uncovered: list[UncoveredItem] = []
    for func in ghidra_funcs:
        va = func.va
        size = func.size
        name = func.name or f"FUN_{va:08x}"

        if va in existing or va in iat_set:
            continue
        if name in ignored:
            continue

        reason = detect_unmatchable(va, size, binary_info, iat_set, ignored, name)
        if reason:
            continue

        if size < min_size or size > max_size:
            continue

        difficulty, reason = estimate_difficulty(size, name, ignored=ignored, cfg=cfg)
        if difficulty == 0:
            continue

        neighbor = find_neighbor_file(va, covered_vas, _sorted_keys=sorted_covered)

        similarity = 0.0
        if matched_funcs and binary_info and size > 20:
            try:
                from rebrew.binary_loader import extract_bytes_at_va

                u_bytes = extract_bytes_at_va(binary_info, va, size)
                if u_bytes:
                    best_sim = 0.0
                    min_s = int(size * 0.75)
                    max_s = int(size * 1.25)
                    start_idx = bisect.bisect_left(matched_funcs, (min_s, b""))
                    end_idx = bisect.bisect_right(matched_funcs, (max_s, b"\xff"))

                    for cand_size, cand_bytes in matched_funcs[start_idx:end_idx]:
                        if u_bytes[:4] == cand_bytes[:4] or size == cand_size:
                            sm = difflib.SequenceMatcher(None, u_bytes, cand_bytes)
                            if sm.quick_ratio() > best_sim:
                                sim_ratio = sm.ratio()
                                if sim_ratio > best_sim:
                                    best_sim = sim_ratio

                    similarity = best_sim
            except (OSError, ValueError, KeyError, MemoryError):
                pass

        uncovered.append((difficulty, size, va, name, reason, neighbor, similarity))

    uncovered.sort(key=lambda x: (-x[6], x[0], x[1]))
    return uncovered


def _display_groups(
    uncovered: list[UncoveredItem],
    cfg: Any,
    count: int,
    group_gap: int,
    commands: bool,
    json_output: bool,
) -> None:
    """Display grouped adjacent uncovered functions (--group)."""
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
                if item[5]:
                    grp_neighbor = item[5]
                    break
            funcs = [
                {
                    "va": f"0x{fva:08x}",
                    "size": fsz,
                    "difficulty": fdiff,
                    "name": fname,
                    "similarity": fsim,
                }
                for fdiff, fsz, fva, fname, _, _, fsim in grp
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
        json_print(
            {
                "mode": "groups",
                "group_count": len(multi_groups),
                "singleton_count": single_count,
                "groups": json_groups,
            }
        )
        return

    console.print(
        f"\n[bold]Function groups[/] ({len(multi_groups)} groups, {single_count} singletons)\n"
    )

    for gi, grp in enumerate(multi_groups[:count], 1):
        total_size = sum(item[1] for item in grp)
        va_lo = min(item[2] for item in grp)
        va_hi = max(item[2] for item in grp)
        neighbor = None
        for item in grp:
            if item[5]:
                neighbor = item[5]
                break

        title = (
            f"Group {gi}: {len(grp)} functions, {total_size}B (0x{va_lo:08x}\u20130x{va_hi:08x})"
        )
        if neighbor:
            title += f"  \u2192 {neighbor}"

        table = Table(title=title, show_edge=False)
        table.add_column("VA", style="cyan")
        table.add_column("Size", justify="right")
        table.add_column("Diff")
        table.add_column("Name", style="magenta")

        for diff, grp_size, grp_va, grp_name, _reason, _, _sim in grp:
            stars = "*" * diff
            table.add_row(f"0x{grp_va:08x}", f"{grp_size}B", stars, grp_name)

        console.print(table)

        if commands:
            if neighbor:
                for item in grp:
                    console.print(
                        f"  [dim]GEN:[/] rebrew skeleton 0x{item[2]:08x} --append {neighbor}"
                    )
            else:
                first = grp[0]
                console.print(f"  [dim]GEN:[/] rebrew skeleton 0x{first[2]:08x}")
                fname = make_filename(first[2], first[3])
                for item in grp[1:]:
                    console.print(
                        f"  [dim]GEN:[/] rebrew skeleton 0x{item[2]:08x} --append {fname}"
                    )
        console.print()


def _display_recommendations(
    uncovered: list[UncoveredItem],
    cfg: Any,
    count: int,
    commands: bool,
    json_output: bool,
) -> None:
    """Display the default recommendation list."""
    if not uncovered:
        if json_output:
            json_print({"mode": "recommendations", "total_uncovered": 0, "count": 0, "items": []})
        else:
            console.print("No uncovered functions found matching criteria. Great progress!")
        return

    if json_output:
        items = []
        for i, (
            diff,
            rec_size,
            rec_va,
            rec_name,
            rec_reason,
            neighbor,
            sim,
        ) in enumerate(uncovered[:count], 1):
            if neighbor:
                suggested_file = f"{cfg.reversed_dir.name}/{neighbor}"
                suggested_action = "append"
            else:
                fname = make_filename(rec_va, rec_name, cfg=cfg)
                suggested_file = f"{cfg.reversed_dir.name}/{fname}"
                suggested_action = "create"
            items.append(
                {
                    "rank": i,
                    "va": f"0x{rec_va:08x}",
                    "size": rec_size,
                    "difficulty": diff,
                    "similarity": sim,
                    "name": rec_name,
                    "reason": rec_reason,
                    "neighbor_file": neighbor,
                    "suggested_file": suggested_file,
                    "suggested_action": suggested_action,
                }
            )
        json_print(
            {
                "mode": "recommendations",
                "total_uncovered": len(uncovered),
                "count": count,
                "items": items,
            }
        )
        return

    table = Table(title=f"Next {count} Functions to Work On (of {len(uncovered)} remaining)")
    table.add_column("#", justify="right", style="bold")
    table.add_column("VA", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Diff")
    table.add_column("Sim", justify="right")
    table.add_column("Name", style="magenta")
    table.add_column("Reason")
    table.add_column("Target", style="dim")

    for i, (diff, rec_size, rec_va, rec_name, rec_reason, neighbor, sim) in enumerate(
        uncovered[:count], 1
    ):
        stars = "*" * diff
        sim_str = f"{int(sim * 100)}%" if sim > 0 else ""
        target = f"\u2192 {neighbor}" if neighbor else ""
        table.add_row(
            str(i),
            f"0x{rec_va:08x}",
            f"{rec_size}B",
            stars,
            sim_str,
            rec_name,
            rec_reason,
            target,
        )

    console.print(table)

    if commands:
        console.print()
        for (
            _diff,
            _rec_size,
            rec_va,
            _rec_name,
            _rec_origin,
            _rec_reason,
            neighbor,
            _sim,
        ) in uncovered[:count]:
            if neighbor:
                console.print(f"  [dim]GEN:[/] rebrew skeleton 0x{rec_va:08x} --append {neighbor}")
            else:
                console.print(f"  [dim]GEN:[/] rebrew skeleton 0x{rec_va:08x}")

    console.print()
    console.print("To generate a skeleton: [cyan]rebrew skeleton 0x<VA>[/]")
    console.print("To generate a batch:    [cyan]rebrew skeleton --batch 10[/]")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    count: int = typer.Option(20, "--count", "-n", help="Number of recommendations"),
    improving: bool = typer.Option(
        False, "--improving", "-i", help="Show MATCHING functions to improve"
    ),
    stats: bool = typer.Option(
        False, "--stats", "-s", help="Show overall progress statistics (see also: rebrew status)"
    ),
    max_size: int = typer.Option(9999, help="Max function size"),
    min_size: int = typer.Option(10, help="Min function size"),
    commands: bool = typer.Option(False, "--commands", "-c", help="Print test commands for each"),
    show_unmatchable: bool = typer.Option(
        False, "--unmatchable", help="Show detected unmatchable functions"
    ),
    group: bool = typer.Option(False, help="Group adjacent uncovered functions"),
    group_gap: int = typer.Option(0x1000, help="Max address gap for grouping"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Show what to work on next in the rebrew RE project."""
    cfg = require_config(target=target, json_mode=json_output)
    ghidra_funcs, existing, covered_vas = load_data(cfg)
    ignored = ignored_symbols(cfg)
    iat_thunks = cfg.iat_thunks
    iat_set: set[int] = set(iat_thunks) if iat_thunks else set()

    # Load binary for byte-pattern detection
    binary_info: BinaryInfo | None = None
    bin_path = cfg.target_binary
    if bin_path and bin_path.exists():
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            binary_info = load_binary(bin_path)

    if stats:
        _show_stats(ghidra_funcs, existing, binary_info, iat_set, ignored, json_output)
        return

    if improving:
        _show_improving(ghidra_funcs, existing, cfg, count, commands, json_output)
        return

    if show_unmatchable:
        _show_unmatchable(ghidra_funcs, existing, binary_info, iat_set, ignored, count, json_output)
        return

    # Default: recommend next functions
    uncovered = _build_recommendations(
        ghidra_funcs,
        existing,
        covered_vas,
        binary_info,
        iat_set,
        ignored,
        cfg,
        min_size,
        max_size,
    )

    if group:
        _display_groups(uncovered, cfg, count, group_gap, commands, json_output)
        return

    _display_recommendations(uncovered, cfg, count, commands, json_output)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
