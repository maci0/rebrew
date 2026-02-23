#!/usr/bin/env python3
"""next.py - Show what to work on next in the rebrew RE project.

Analyzes the current state of reverse engineering progress and recommends
the next functions to work on, sorted by estimated difficulty and priority.

Usage:
    rebrew-next                     # Show top 20 recommendations
    rebrew-next --count 50          # Show top 50
    rebrew-next --origin GAME       # Only GAME functions
    rebrew-next --improving         # Show MATCHING functions to improve
    rebrew-next --stats             # Show overall progress statistics
"""

import json
import os
import re
from pathlib import Path

import typer

from rebrew.annotation import parse_c_file
from rebrew.cli import TargetOption, get_config
from rebrew.verify import load_ghidra_functions

# Known ASM builtins - cannot be matched from C source
ASM_BUILTINS = {
    "memset",
    "strcmp",
    "strstr",
    "strchr",
    "strlen",
    "strncpy",
    "strpbrk",
    "strcspn",
    "__local_unwind2",
    "__aulldiv",
    "__aullrem",
    "__alloca_probe",
    "_chkstk",
    "__except_handler3",
}

def detect_origin(va: int, name: str, cfg) -> str:
    if cfg.game_range_end and va >= cfg.game_range_end:
        return "MSVCRT"
    if name.startswith("__") or name.startswith("_crt"):
        return "MSVCRT"
    return "GAME"


def load_data(cfg):
    """Load all project data."""
    src_dir = Path(cfg.reversed_dir)
    ghidra_json = src_dir / "ghidra_functions.json"

    # Ghidra functions
    ghidra_funcs = load_ghidra_functions(ghidra_json)

    # Existing .c files
    existing = {}  # va -> {filename, status, origin, blocker}
    for cfile in sorted(src_dir.glob("*.c")):
        entry = parse_c_file(cfile)
        if entry is not None:
            existing[entry.va] = {
                "filename": Path(entry.filepath).name,
                "status": entry.status,
                "origin": entry.origin,
                "blocker": entry.blocker,
                "symbol": entry.symbol,
            }

    return ghidra_funcs, existing


def estimate_difficulty(size: int, name: str, origin: str) -> tuple[int, str]:
    """Estimate difficulty (1-5) and reason."""
    if name in ASM_BUILTINS:
        return 0, "ASM builtin (skip)"

    if origin == "ZLIB":
        return 1, "zlib source available at references/zlib-1.1.3/"
    if origin == "MSVCRT":
        if size < 100:
            return 2, "small CRT function, check CRT/SRC/"
        return 3, "CRT function, may need shihyu/learn_c source"

    # GAME functions
    if size < 80:
        return 1, "tiny function, likely simple getter/setter"
    if size < 150:
        return 2, "small function, straightforward logic"
    if size < 250:
        return 3, "medium function, may have branches/loops"
    if size < 400:
        return 4, "large function, complex control flow"
    return 5, "very large function, expect significant effort"


app = typer.Typer(help="Show what to work on next in the rebrew RE project.")


@app.command()
def main(
    count: int = typer.Option(20, "--count", "-n", help="Number of recommendations"),
    origin_filter: str = typer.Option(None, "--origin", help="Filter by origin (GAME, MSVCRT, ZLIB)"),
    improving: bool = typer.Option(False, help="Show MATCHING functions to improve"),
    stats: bool = typer.Option(False, help="Show overall progress statistics"),
    max_size: int = typer.Option(9999, help="Max function size"),
    min_size: int = typer.Option(10, help="Min function size"),
    commands: bool = typer.Option(False, help="Print test commands for each"),
    target: str | None = TargetOption,
):
    """Show what to work on next in the rebrew RE project."""
    cfg = get_config(target=target)
    ghidra_funcs, existing = load_data(cfg)

    # --stats mode
    if stats:
        total = len(ghidra_funcs)
        covered = len(existing)
        uncovered = total - covered

        # Count by status
        by_status = {}
        by_origin = {}
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

        print("=" * 60)
        print("REBREW REVERSE ENGINEERING PROGRESS")
        print("=" * 60)
        print()
        print(f"Total functions (Ghidra):  {total}")
        print(f"  IAT thunks (skip):       {len(cfg.iat_thunks)}")
        print(f"  ASM builtins (skip):     ~{len(ASM_BUILTINS)}")
        print(
            f"  Actionable:              ~{total - len(cfg.iat_thunks) - len(ASM_BUILTINS)}"
        )
        print()
        print(f"Covered (.c files):        {covered} ({100 * covered / total:.1f}%)")
        print(f"  EXACT match:             {exact}")
        print(f"  RELOC match:             {reloc}")
        print(f"  MATCHING (near-miss):    {matching}")
        print(f"  STUB (placeholder):      {stub}")
        print(f"  Perfect (EXACT+RELOC):   {perfect} ({100 * perfect / total:.1f}%)")
        print()
        print(f"Uncovered (no .c file):    {uncovered}")
        print()

        # Uncovered by estimated origin
        unc_game = unc_crt = unc_zlib = 0
        for func in ghidra_funcs:
            va = func["va"]
            if va in existing or va in cfg.iat_thunks:
                continue
            name = func.get("ghidra_name", "")
            if name in ASM_BUILTINS:
                continue
            origin = detect_origin(va, name, cfg)
            if origin == "GAME":
                unc_game += 1
            elif origin == "MSVCRT":
                unc_crt += 1
            elif origin == "ZLIB":
                unc_zlib += 1

        print("Uncovered by origin:")
        print(f"  GAME:   {unc_game}")
        print(f"  MSVCRT: {unc_crt}")
        print(f"  ZLIB:   {unc_zlib}")
        print()

        if matching > 0:
            print(
                f"MATCHING functions that could be improved to EXACT/RELOC: {matching}"
            )
            print("  Run: rebrew-next --improving")
        return

    # --improving mode
    if improving:
        matching = []
        for va, info in sorted(existing.items()):
            if info["status"] in ("MATCHING", "MATCHING_RELOC"):
                # Find size from ghidra
                size = 0
                for func in ghidra_funcs:
                    if func["va"] == va:
                        size = func["size"]
                        break
                matching.append((va, size, info))

        if not matching:
            print("No MATCHING functions found.")
            return

        matching.sort(key=lambda x: x[1])  # Sort by size (easiest first)
        print(f"MATCHING functions to improve ({len(matching)} total):")
        print(f"{'VA':>12s}  {'Size':>5s}  {'Origin':>6s}  {'File':30s}  {'Blocker'}")
        print(f"{'---':>12s}  {'---':>5s}  {'---':>6s}  {'---':30s}  {'---'}")
        for va, size, info in matching[: count]:
            print(
                f"  0x{va:08x}  {size:4d}B  {info['origin']:>6s}  {info['filename']:30s}  {info['blocker']}"
            )

            if commands:
                symbol = info.get("symbol") or f"_func_{va:08x}"
                cflags = cfg.cflags_presets.get(info["origin"], "/O2 /Gd")
                rel_path = f"{cfg.reversed_dir.name}/{info['filename']}"
                print(
                    f'    TEST: rebrew-test {rel_path} {symbol} --va 0x{va:08x} --size {size} --cflags "{cflags}"'
                )
        return

    # Default: recommend next functions to work on
    uncovered = []
    for func in ghidra_funcs:
        va = func["va"]
        size = func["size"]
        name = func.get("ghidra_name", f"FUN_{va:08x}")

        if va in existing or va in cfg.iat_thunks:
            continue
        if name in ASM_BUILTINS:
            continue
        if size < min_size or size > max_size:
            continue

        origin = detect_origin(va, name, cfg)
        if origin_filter and origin != origin_filter:
            continue

        difficulty, reason = estimate_difficulty(size, name, origin)
        if difficulty == 0:
            continue  # Skip ASM builtins

        uncovered.append((difficulty, size, va, name, origin, reason))

    # Sort by difficulty then size
    uncovered.sort(key=lambda x: (x[0], x[1]))

    if not uncovered:
        print("No uncovered functions found matching criteria. Great progress!")
        return

    count = min(count, len(uncovered))
    print(f"Next {count} functions to work on (of {len(uncovered)} remaining):")
    print()
    print(
        f"{'#':>3s}  {'VA':>12s}  {'Size':>5s}  {'Diff':>4s}  {'Origin':>6s}  {'Name':30s}  {'Reason'}"
    )
    print(
        f"{'---':>3s}  {'---':>12s}  {'---':>5s}  {'---':>4s}  {'---':>6s}  {'---':30s}  {'---'}"
    )

    for i, (diff, size, va, name, origin, reason) in enumerate(uncovered[:count], 1):
        stars = "*" * diff
        print(
            f"{i:3d}  0x{va:08x}  {size:4d}B  {stars:4s}  {origin:>6s}  {name:30s}  {reason}"
        )

        if commands:
            cflags = cfg.cflags_presets.get(origin, "/O2 /Gd")
            print(f"     GEN: rebrew-skeleton 0x{va:08x}")
            print(
                f'     TEST: rebrew-test {cfg.reversed_dir.name}/... _... --va 0x{va:08x} --size {size} --cflags "{cflags}"'
            )

    print()
    print("To generate a skeleton: rebrew-skeleton 0x<VA>")
    print(
        "To generate a batch:    rebrew-skeleton --batch 10 --origin GAME"
    )


def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
