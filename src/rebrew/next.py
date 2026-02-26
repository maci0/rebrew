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
import re
import sys
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import parse_c_file_multi
from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
from rebrew.catalog import load_ghidra_functions
from rebrew.cli import TargetOption, get_config

# 7-tuple: (difficulty, size, va, name, origin, reason, neighbor_file)
UncoveredItem = tuple[int, int, int, str, str, str, str | None]

# ---------------------------------------------------------------------------
# Unmatchable function detection
# ---------------------------------------------------------------------------

# x86 IAT thunk: FF 25 xx xx xx xx  (jmp [addr])
_IAT_JMP = bytes([0xFF, 0x25])

# Single-byte ret: C3 or CC (int3 padding)
_RET = 0xC3
_INT3 = 0xCC
_NOP = 0x90

# SEH prologue using fs segment: 64 A1 00 00 00 00 (mov eax, fs:[0])
_SEH_FS = bytes([0x64, 0xA1, 0x00, 0x00, 0x00, 0x00])


def detect_unmatchable(
    va: int,
    size: int,
    binary_info: BinaryInfo | None,
    iat_thunks: set[int] | None = None,
    ignored_symbols: set[str] | None = None,
    name: str = "",
) -> str | None:
    """Check if a function is unmatchable from C source.

    Returns a reason string if unmatchable, or None if it appears normal.
    """
    # 1. Explicit IAT thunk list from config
    if iat_thunks and va in iat_thunks:
        return "IAT thunk (config)"

    # 2. Known ignored symbols (ASM builtins)
    if ignored_symbols and name in ignored_symbols:
        return f"ignored symbol: {name}"

    # 3. Byte-pattern detection (requires binary)
    if binary_info is None:
        return None

    raw = extract_bytes_at_va(binary_info, va, max(size, 8), padding_bytes=())
    if raw is None or len(raw) == 0:
        return None

    # 3a. Tiny functions: single ret or int3/nop padding
    if size <= 2:
        if raw[0] == _RET:
            return "single-byte RET stub"
        if raw[0] == _INT3:
            return "INT3 padding"
        if raw[0] == _NOP:
            return "NOP padding"

    # 3b. IAT jmp [addr] thunk (6 bytes: FF 25 xx xx xx xx)
    if size <= 8 and len(raw) >= 2 and raw[:2] == _IAT_JMP:
        return "IAT jmp [addr] thunk"

    # 3c. SEH handler manipulating fs:[0] directly (ASM-only patterns)
    if len(raw) >= 6 and raw[:6] == _SEH_FS:
        return "SEH handler (fs:[0] access)"

    return None


def ignored_symbols(cfg: Any) -> set[str]:
    """Return the set of symbols to skip (ASM builtins, etc.).

    Reads from ``cfg.ignored_symbols`` (populated from ``rebrew.toml``).
    """
    syms = getattr(cfg, "ignored_symbols", None)
    return set(syms) if syms else set()


# Patterns for extracting byte delta from BLOCKER annotations
# Matches: "2B diff", "24B diff:", "1B diff:", "(2B diff)"
_DELTA_PATTERN_DIFF = re.compile(r"(\d+)\s*B?\s*(?:byte[s]?)?\s*diff", re.IGNORECASE)
# Matches: "XB vs YB" → delta = abs(X - Y)
_DELTA_PATTERN_VS = re.compile(r"(\d+)\s*B\s*vs\s*(\d+)\s*B", re.IGNORECASE)


def parse_byte_delta(blocker: str) -> int | None:
    """Extract byte delta from a BLOCKER annotation string.

    Tries several patterns seen in practice:
    - ``(2B diff)`` → 2
    - ``24B diff:`` → 24
    - ``229B vs 205B`` → 24 (abs difference)

    Returns None if no delta can be parsed.
    """
    if not blocker:
        return None

    # Try explicit "XB diff" pattern first
    m = _DELTA_PATTERN_DIFF.search(blocker)
    if m:
        return int(m.group(1))

    # Try "XB vs YB" pattern
    m = _DELTA_PATTERN_VS.search(blocker)
    if m:
        return abs(int(m.group(1)) - int(m.group(2)))

    return None


def detect_origin(va: int, name: str, cfg: Any) -> str:
    """Detect function origin based on VA, name, and config rules.

    Uses project-specific heuristics (zlib_vas, game_range_end) for known
    origins, then falls back to cfg.default_origin or the first configured origin.
    """
    zlib_vas = set(getattr(cfg, "zlib_vas", None) or [])
    if va in zlib_vas:
        return "ZLIB"
    game_range_end = getattr(cfg, "game_range_end", None)
    if game_range_end and va >= game_range_end:
        return "MSVCRT"
    if name.startswith("__") or name.startswith("_crt"):
        return "MSVCRT"
    default = getattr(cfg, "default_origin", "") or ""
    if default:
        return default
    origins = getattr(cfg, "origins", None) or []
    return origins[0] if origins else "GAME"


def load_data(
    cfg: Any,
) -> tuple[list[dict[str, Any]], dict[int, dict[str, str]], dict[int, str]]:
    """Load all project data.

    Returns (ghidra_funcs, existing, covered_vas) where:
    - ghidra_funcs: list of function dicts from ghidra_functions.json
    - existing: dict mapping VA -> {filename, status, origin, blocker, symbol}
    - covered_vas: dict mapping VA -> filename (for find_neighbor_file)
    """
    src_dir = Path(cfg.reversed_dir)
    ghidra_json = src_dir / "ghidra_functions.json"

    # Ghidra functions
    ghidra_funcs = load_ghidra_functions(ghidra_json)

    # Existing source files — use parse_c_file_multi to capture all VAs in
    # multi-function files (not just the first annotation).
    from rebrew.cli import source_glob

    existing: dict[int, dict[str, str]] = {}
    covered_vas: dict[int, str] = {}
    for cfile in sorted(src_dir.glob(source_glob(cfg))):
        entries = parse_c_file_multi(cfile)
        for entry in entries:
            if entry.marker_type in ("GLOBAL", "DATA"):
                continue
            if entry.va < 0x1000:
                continue
            filename = Path(entry.filepath).name
            existing[entry.va] = {
                "filename": filename,
                "status": entry.status,
                "origin": entry.origin,
                "blocker": entry.blocker,
                "blocker_delta": str(entry.blocker_delta)
                if entry.blocker_delta is not None
                else "",
                "symbol": entry.symbol,
            }
            covered_vas[entry.va] = filename

    return ghidra_funcs, existing, covered_vas


def estimate_difficulty(
    size: int,
    name: str,
    origin: str,
    ignored: set[str] | None = None,
    cfg: Any = None,
) -> tuple[int, str]:
    """Estimate difficulty (1-5) and reason."""
    if ignored and name in ignored:
        return 0, "ASM builtin / ignored symbol (skip)"

    lib_origins = getattr(cfg, "library_origins", None) if cfg else None
    if lib_origins is None:
        lib_origins = {"ZLIB", "MSVCRT"}
    if origin in lib_origins:
        if size < 100:
            return 2, f"small {origin} function, reference source available"
        return 3, f"{origin} function, check reference sources"

    # Primary origin (GAME or equivalent)
    if size < 80:
        return 1, "tiny function, likely simple getter/setter"
    if size < 150:
        return 2, "small function, straightforward logic"
    if size < 250:
        return 3, "medium function, may have branches/loops"
    if size < 400:
        return 4, "large function, complex control flow"
    return 5, "very large function, expect significant effort"


def group_uncovered(
    uncovered: list[UncoveredItem],
    max_gap: int = 0x1000,
) -> list[list[UncoveredItem]]:
    """Group uncovered functions by address proximity.

    Adjacent functions are grouped when the gap from the *end* of one function
    to the *start* of the next is within *max_gap* bytes.  This accounts for
    function body size, not just VA distance.  Groups are sorted by total size
    (smallest first — easiest batch to tackle).
    """
    if not uncovered:
        return []

    # Sort by VA (index 2) for contiguity detection
    by_va = sorted(uncovered, key=lambda x: x[2])

    groups: list[list[UncoveredItem]] = []
    current_group = [by_va[0]]

    for item in by_va[1:]:
        prev_va = current_group[-1][2]
        prev_size = current_group[-1][1]
        curr_va = item[2]

        # Gap from end of previous function to start of current
        gap = curr_va - (prev_va + prev_size)
        if gap <= max_gap:
            current_group.append(item)
        else:
            groups.append(current_group)
            current_group = [item]

    groups.append(current_group)

    # Sort groups by total size (smallest first)
    groups.sort(key=lambda g: sum(item[1] for item in g))

    return groups


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
    from rebrew.skeleton import find_neighbor_file, make_filename

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
