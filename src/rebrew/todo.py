"""todo.py – Prioritized action dashboard for rebrew projects.

Synthesizes verify results, coverage data, and function catalog into a single
ranked list of "what to work on next" with ROI scoring.

Usage::

    rebrew todo                     Top 20 actions by ROI
    rebrew todo --count 50          Show top 50
    rebrew todo -c fix-near-miss    Filter by category
    rebrew todo --stats             Show coverage stats header
    rebrew todo --json              Machine-readable output
"""

import contextlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.catalog.models import FunctionEntry
    from rebrew.verify import VerifyCacheEntry

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rebrew.cli import NEAR_MATCH_THRESHOLD, TargetOption, error_exit, json_print, require_config
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.naming import (
    detect_unmatchable,
    estimate_difficulty,
    find_neighbor_file,
    ignored_symbols,
    load_data,
    parse_byte_delta,
)

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Category constants
# ---------------------------------------------------------------------------

CAT_SETUP = "setup"
CAT_COMPILE_ERROR = "compile-error"
CAT_FIX_DELTA = "fix-delta"
CAT_IMPROVE_MATCH = "improve-match"
CAT_START_FUNCTION = "start-function"
CAT_MISSING_ANNOTATION = "missing-annotation"
CAT_IDENTIFY_LIBRARY = "identify-library"
CAT_RUN_PROVER = "run-prover"

_CATEGORY_COLORS = {
    CAT_SETUP: "bold white",
    CAT_COMPILE_ERROR: "red",
    CAT_FIX_DELTA: "green",
    CAT_IMPROVE_MATCH: "yellow",
    CAT_START_FUNCTION: "cyan",
    CAT_MISSING_ANNOTATION: "dim",
    CAT_IDENTIFY_LIBRARY: "blue",
    CAT_RUN_PROVER: "cyan",
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TodoItem:
    """A single prioritized action item."""

    category: str
    roi_score: float
    va: int
    name: str
    size: int
    filename: str
    description: str
    command: str
    byte_delta: int | None = None
    difficulty: int = 0
    status: str = ""
    match_percent: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        d: dict[str, Any] = {
            "category": self.category,
            "roi_score": round(self.roi_score, 1),
            "va": f"0x{self.va:08x}",
            "name": self.name,
            "size": self.size,
            "filename": self.filename,
            "description": self.description,
            "command": self.command,
        }
        if self.byte_delta is not None:
            d["byte_delta"] = self.byte_delta
        if self.difficulty:
            d["difficulty"] = self.difficulty
        if self.status:
            d["status"] = self.status
        if self.match_percent is not None:
            d["match_percent"] = self.match_percent
        return d


# ---------------------------------------------------------------------------
# Unified Continuous Scoring
# ---------------------------------------------------------------------------


def calculate_roi(size: int, match_pct: float | None, delta: int | None, status: str) -> float:
    """Calculate a continuous ROI score (0-100).

    User Workflow Heuristic: Higher match percentage is often HARDER to finish
    because it implies fighting the compiler (register allocation, instruction scheduling).
    Therefore, rewrite tasks (low match) are prioritized over near-match tasks,
    unless the near-match task has a small, actionable byte delta.
    """
    if match_pct is None:
        match_pct = 0.0

    # Invert the score: 0% match = 65 base, 100% match = 25 base
    base_score = 65.0 - (match_pct * 0.4)

    modifier = 0.0

    # 1. Delta Boosts (Small explicit byte differences are quick wins)
    if delta is not None:
        if delta <= 4:
            modifier += 25.0
        elif delta <= 20:
            modifier += 15.0

    # 2. Size Modifiers (Smaller functions are easier to cognitively load and rewrite)
    if size < 50:
        modifier += 15.0
    elif size < 150:
        modifier += 10.0
    elif size < 300:
        modifier += 5.0
    elif size > 1000:
        modifier -= 15.0
    elif size > 500:
        modifier -= 5.0

    # 3. Stubborn Diff Penalty (High match >= 90%, no explicit small delta)
    if match_pct >= 90.0 and (delta is None or delta > 20):
        modifier -= 15.0

    final_score = base_score + modifier
    return min(89.0, max(1.0, final_score))


# ---------------------------------------------------------------------------
# Collector functions
# ---------------------------------------------------------------------------


def _collect_setup_steps(
    cfg: ProjectConfig,
    ghidra_funcs: list["FunctionEntry"],
    existing: dict[int, dict[str, str]],
) -> list[TodoItem]:
    """Detect missing project setup steps for fresh/incomplete projects.

    Returns high-priority setup items that guide the user through initial
    project configuration. Scored 90-99 so they always appear first.
    """
    items: list[TodoItem] = []
    step = 0

    # 1. Check doctor health
    src_dir = Path(cfg.reversed_dir)
    ghidra_json = src_dir / FUNCTION_STRUCTURE_JSON

    # 2. No function list → need to generate it
    if not ghidra_json.exists():
        func_list = cfg.function_list
        if func_list.exists():
            step += 1
            items.append(
                TodoItem(
                    category=CAT_SETUP,
                    roi_score=99.0 - step,
                    va=0,
                    name="",
                    size=0,
                    filename="",
                    description="Build function catalog from Ghidra or function list",
                    command="rebrew catalog",
                )
            )
        else:
            step += 1
            items.append(
                TodoItem(
                    category=CAT_SETUP,
                    roi_score=99.0 - step,
                    va=0,
                    name="",
                    size=0,
                    filename="",
                    description="Export function list from Ghidra/r2/rizin",
                    command="rebrew doctor",
                )
            )
        return items  # Can't do much more without function list

    # 3. Have function list but no source files → run triage + skeleton
    if not ghidra_funcs:
        return items  # Shouldn't happen if ghidra_json exists, but be safe

    if not existing:
        step += 1
        items.append(
            TodoItem(
                category=CAT_SETUP,
                roi_score=99.0 - step,
                va=0,
                name="",
                size=0,
                filename="",
                description=f"Run todo to survey {len(ghidra_funcs)} functions",
                command="rebrew todo --json",
            )
        )
        step += 1
        items.append(
            TodoItem(
                category=CAT_SETUP,
                roi_score=99.0 - step,
                va=0,
                name="",
                size=0,
                filename="",
                description="Generate first skeleton files to start reversing",
                command="rebrew skeleton --batch 5",
            )
        )

    # 4. Have source files but never verified
    elif not (cfg.root / ".rebrew" / "verify_cache.json").exists() and existing:
        step += 1
        items.append(
            TodoItem(
                category=CAT_SETUP,
                roi_score=90.0 - step,
                va=0,
                name="",
                size=0,
                filename="",
                description=f"Run first verify on {len(existing)} functions",
                command="rebrew verify",
            )
        )

    return items


def _collect_active_functions(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    name_by_va: dict[int, str],
    verify_entries: dict[str, "VerifyCacheEntry"],
) -> list[TodoItem]:
    """Collect and score all incomplete functions currently tracked in the project.

    This unifies previously separate categories (compile errors, near misses, stubs,
    verify failures) into a single pass that calculates a continuous ROI score.
    """
    items: list[TodoItem] = []

    # 1. Gather all unique VAs between metadata and verify cache
    metadata_vas = set(existing.keys())
    verify_vas = set()
    for va_str in verify_entries:
        try:
            v = int(va_str, 16) if va_str.startswith("0x") else int(va_str)
            verify_vas.add(v)
        except (ValueError, TypeError):
            pass

    all_vas = metadata_vas | verify_vas

    for va in all_vas:
        info = existing.get(va, {})
        status = info.get("status", "STUB")

        # Skip finished functions
        if status in ("EXACT", "RELOC", "PROVEN"):
            continue

        size = size_by_va.get(va) or int(info.get("size", 0))
        name = info.get("symbol") or name_by_va.get(va) or f"FUN_{va:08x}"
        filename = info.get("filename", "")

        # Get verify cache data if available
        va_key = f"0x{va:08x}"
        v_entry = verify_entries.get(va_key)
        v_status = v_entry.result.status if v_entry else None
        v_match = v_entry.result.match_percent if v_entry else None
        v_delta = v_entry.result.delta if v_entry else None

        # If verify says it compiled and size changed, or we don't have verify, fallback to metadata parsing
        calc_delta = v_delta
        if calc_delta is None and status == "NEAR_MATCHING":
            raw_bd = info.get("blocker_delta", "")
            try:
                calc_delta = int(raw_bd) if raw_bd else parse_byte_delta(info.get("blocker", ""))
            except ValueError:
                calc_delta = parse_byte_delta(info.get("blocker", ""))

        cmd = f"rebrew test {filename}" if filename else f"rebrew test 0x{va:08x}"

        # Determine category and specific description
        if v_status == "COMPILE_ERROR":
            category = CAT_COMPILE_ERROR
            desc = "Compile error — fix syntax/includes"
            score = 200.0  # High priority blocker

        elif not name or name.startswith("FUN_"):
            category = CAT_MISSING_ANNOTATION
            desc = "Missing C function definition (needs skeleton)"
            score = calculate_roi(size, v_match, calc_delta, status)
            cmd = f"rebrew skeleton 0x{va:08x}"

        elif calc_delta is not None and calc_delta <= 20:
            category = CAT_FIX_DELTA
            desc = f"{calc_delta}B diff — try flag sweep, GA, or padding adjustments"
            score = calculate_roi(size, v_match, calc_delta, status)
            if calc_delta <= 4:
                cmd = f"rebrew diff {filename}" if filename else f"rebrew diff 0x{va:08x}"
            else:
                cmd = (
                    f"rebrew match --flag-sweep-only {filename}"
                    if filename
                    else f"rebrew match --flag-sweep-only 0x{va:08x}"
                )

        else:
            category = CAT_IMPROVE_MATCH
            desc = "Needs implementation/fixing"
            score = calculate_roi(size, v_match, calc_delta, status)

            blocker = info.get("blocker", "")
            if blocker:
                desc += f" — Blocked: {blocker[:50]}"

            cmd = f"rebrew diff {filename}" if filename else f"rebrew diff 0x{va:08x}"

        items.append(
            TodoItem(
                category=category,
                roi_score=score,
                va=va,
                name=name,
                size=size,
                filename=filename,
                description=desc,
                command=cmd,
                byte_delta=calc_delta,
                status=v_status or status,
                match_percent=v_match,
            )
        )

    return items


def _collect_prover_candidates(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    verify_entries: dict[str, Any],
) -> list[TodoItem]:
    """Collect functions suitable for symbolic equivalence proving."""
    # Check if angr is importable
    angr_available = False
    with contextlib.suppress(ImportError):
        import angr  # noqa: F401

        angr_available = True

    if not angr_available:
        return []

    items: list[TodoItem] = []
    for va, info in existing.items():
        ann_status = info.get("status", "STUB")
        # PROVEN is a post-verify promotion that wins over verify cache
        if ann_status in ("EXACT", "RELOC", "PROVEN"):
            continue
        va_key = f"0x{va:08x}"
        cached = verify_entries.get(va_key)
        effective_status = cached.result.status if cached else ann_status
        if effective_status != "NEAR_MATCHING":
            continue
        size = size_by_va.get(va) or int(info.get("size", 0))
        if size > 500 or size == 0:
            continue

        filename = info.get("filename", "")
        match_pct = cached.result.match_percent if cached else None
        byte_delta = cached.result.delta if cached else None

        items.append(
            TodoItem(
                category=CAT_RUN_PROVER,
                # Prover is most useful at high match% (few diffs to prove).
                # Give it a bonus so it wins dedup over improve-match/fix-delta.
                roi_score=calculate_roi(size, match_pct, None, "NEAR_MATCHING")
                + (10.0 if match_pct and match_pct >= NEAR_MATCH_THRESHOLD * 100 else -10.0),
                va=va,
                name=info.get("symbol", ""),
                size=size,
                filename=filename,
                description="NEAR_MATCHING + small — prove semantic equivalence",
                command=f"rebrew prove {filename}" if filename else f"rebrew prove 0x{va:08x}",
                status=effective_status,
                match_percent=match_pct,
                byte_delta=byte_delta,
            )
        )
    return items


def _load_verify_entries(cfg: ProjectConfig) -> dict[str, "VerifyCacheEntry"]:
    """Load verify cache entries, returning {} on missing/corrupt cache."""
    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    if not cache_path.exists():
        return {}
    try:
        from rebrew.verify import VerifyCache

        data = VerifyCache.from_dict(json.loads(cache_path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError, ValueError, AttributeError, ImportError):
        return {}
    return data.entries


def _collect_new_functions(
    ghidra_funcs: list["FunctionEntry"],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
    cfg: ProjectConfig,
    max_candidates: int = 50,
) -> list[TodoItem]:
    """Collect uncovered functions as start-function candidates."""
    ignored = ignored_symbols(cfg)
    iat_set: set[int] = set(getattr(cfg, "iat_thunks", None) or [])
    sorted_covered = sorted(covered_vas)

    # Load binary for unmatchable detection
    binary_info = None
    bin_path = cfg.target_binary
    if bin_path and bin_path.exists():
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            from rebrew.binary_loader import load_binary

            binary_info = load_binary(bin_path)

    items: list[TodoItem] = []
    for func in ghidra_funcs:
        if len(items) >= max_candidates:
            break
        va = func.va
        size = func.size
        name = func.name or f"FUN_{va:08x}"

        if va in existing or va in iat_set or name in ignored:
            continue
        if size < 10:
            continue

        reason = detect_unmatchable(
            va,
            size,
            binary_info,
            iat_set,
            ignored,
            name,
            cs_arch=getattr(cfg, "capstone_arch", None),
            cs_mode=getattr(cfg, "capstone_mode", None),
        )
        if reason:
            continue

        difficulty, desc = estimate_difficulty(size, name, ignored=ignored, cfg=cfg)
        if difficulty == 0:
            continue

        neighbor = find_neighbor_file(va, covered_vas, _sorted_keys=sorted_covered)
        if neighbor:
            cmd = f"rebrew skeleton 0x{va:08x} --append {neighbor}"
        else:
            cmd = f"rebrew skeleton 0x{va:08x}"

        items.append(
            TodoItem(
                category=CAT_START_FUNCTION,
                roi_score=max(10.0, calculate_roi(size, 0.0, None, "MISSING") - difficulty * 2),
                va=va,
                name=name,
                size=size,
                filename=neighbor or "",
                description=desc,
                command=cmd,
                difficulty=difficulty,
            )
        )

    return items


def _collect_library_candidates(
    ghidra_funcs: list["FunctionEntry"],
    existing: dict[int, dict[str, str]],
    cfg: ProjectConfig,
) -> list[TodoItem]:
    """Collect uncovered functions with library module for identification."""
    lib_modules = set(cfg.library_modules) if cfg.library_modules else {"ZLIB", "MSVCRT"}
    items: list[TodoItem] = []
    for func in ghidra_funcs:
        va = func.va
        if va in existing:
            continue
        size = func.size
        name = func.name or f"FUN_{va:08x}"
        module = func.module if hasattr(func, "module") else ""
        if module not in lib_modules:
            continue

        items.append(
            TodoItem(
                category=CAT_IDENTIFY_LIBRARY,
                roi_score=max(10.0, calculate_roi(size, 0.0, None, "MISSING") - 10.0),
                va=va,
                name=name,
                size=size,
                filename="",
                description=f"{module or 'library'} function — check reference sources or FLIRT",
                command=f"rebrew flirt --va 0x{va:08x}",
            )
        )
    return items


# ---------------------------------------------------------------------------
# Main collection + ranking
# ---------------------------------------------------------------------------


def collect_all(
    cfg: ProjectConfig,
    ghidra_funcs: list["FunctionEntry"],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
) -> list[TodoItem]:
    """Collect and rank all todo items by ROI score (descending)."""
    items: list[TodoItem] = []

    # Setup steps for fresh/incomplete projects (scored highest)
    items.extend(_collect_setup_steps(cfg, ghidra_funcs, existing))

    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    name_by_va: dict[int, str] = {f.va: f.name or "" for f in ghidra_funcs}
    verify_entries = _load_verify_entries(cfg)

    # 1. Collect all active functions tracked in the project
    items.extend(_collect_active_functions(existing, size_by_va, name_by_va, verify_entries))

    # 2. Collect specialized candidates
    items.extend(_collect_prover_candidates(existing, size_by_va, verify_entries))
    items.extend(_collect_new_functions(ghidra_funcs, existing, covered_vas, cfg))
    items.extend(_collect_library_candidates(ghidra_funcs, existing, cfg))

    # Deduplicate by VA — keep only the highest-ROI item per function.
    # Setup items (va=0) are category-level, not per-function, so they skip dedup.
    best: dict[int, TodoItem] = {}
    non_va_items: list[TodoItem] = []
    for item in items:
        if item.va == 0:
            non_va_items.append(item)
            continue
        prev = best.get(item.va)
        if prev is None or item.roi_score > prev.roi_score:
            best[item.va] = item
    items = non_va_items + list(best.values())

    # Sort by ROI descending
    items.sort(key=lambda x: (-x.roi_score, x.va))
    return items


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew todo · · · · · · · · · · Top 20 actions by ROI (size + similarity to target)\n\n"
    "  rebrew todo --count 50 · · · · · Show top 50\n\n"
    "  rebrew todo -c fix-delta · · · · Filter to quick-win near-misses (<= 20B diff)\n\n"
    "  rebrew todo -c improve-match · · Filter to functions needing general work\n\n"
    "  rebrew todo --json · · · · · · · Machine-readable JSON output\n\n"
    "[bold]Categories (interleaved globally by continuous ROI score):[/bold]\n\n"
    "  setup · · · · · · · · · Project setup steps (fresh projects)\n\n"
    "  compile-error · · · · · Failed verify syntax/includes\n\n"
    "  fix-delta · · · · · · · Known tiny byte diffs (<= 20B) — flag sweeps, padding, GA\n\n"
    "  improve-match · · · · · Functions in-progress without a known small delta\n\n"
    "  start-function · · · · · Uncovered functions, ranked by difficulty\n\n"
    "  missing-annotation · · · Found in Ghidra but missing C body\n\n"
    "  identify-library · · · · Uncovered library-origin functions\n\n"
    "  run-prover · · · · · · · Small nearly-matching functions (angr equivalence)\n\n"
    "[dim]Reads from ghidra_functions.json, source files, and .rebrew/verify_cache.json.[/dim]"
)

app = typer.Typer(
    help="Prioritized action list: what to work on next for highest ROI.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    count: int = typer.Option(20, "--count", "-n", help="Number of items to show"),
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (fix-near-miss, flag-sweep, start-function, ...)",
    ),
    stats: bool = typer.Option(False, "--stats", "-s", help="Show coverage stats header"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Show prioritized actions ranked by ROI."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        ghidra_funcs, existing, covered_vas = load_data(cfg)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        error_exit(f"Failed to load project data: {exc}", json_mode=json_output)
    all_items = collect_all(cfg, ghidra_funcs, existing, covered_vas)

    # Coverage stats (always computed for JSON, optional for terminal)
    # Overlay verify cache on annotation statuses (same logic as status.py)
    verify_statuses: dict[int, str] = {}
    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    if cache_path.exists():
        try:
            cache_raw = json.loads(cache_path.read_text(encoding="utf-8"))
            for va_key, entry_data in cache_raw.get("entries", {}).items():
                result = entry_data.get("result", {})
                s = result.get("status", "")
                if s:
                    try:
                        va_int = int(va_key, 16) if va_key.startswith("0x") else int(va_key)
                        verify_statuses[va_int] = s
                    except (ValueError, TypeError):
                        pass
        except (json.JSONDecodeError, OSError):
            pass

    status_counts: dict[str, int] = {}
    for va_int, info in existing.items():
        ann_status = info.get("status", "STUB")
        # PROVEN is a post-verify promotion that wins over verify cache
        s = "PROVEN" if ann_status == "PROVEN" else verify_statuses.get(va_int, ann_status)
        status_counts[s] = status_counts.get(s, 0) + 1
    total_funcs = len(ghidra_funcs)
    covered = len(covered_vas)
    exact = status_counts.get("EXACT", 0)
    reloc = status_counts.get("RELOC", 0)
    proven = status_counts.get("PROVEN", 0)
    matching = status_counts.get("NEAR_MATCHING", 0)
    stub = status_counts.get("STUB", 0)
    pct = round(100.0 * (exact + reloc + proven) / total_funcs, 1) if total_funcs else 0.0

    if category:
        all_items = [i for i in all_items if i.category == category]

    display_items = all_items[:count]

    if json_output:
        cat_summary: dict[str, int] = {}
        for item in all_items:
            cat_summary[item.category] = cat_summary.get(item.category, 0) + 1
        json_print(
            {
                "coverage": {
                    "total": total_funcs,
                    "covered": covered,
                    "exact": exact,
                    "reloc": reloc,
                    "proven": proven,
                    "matching": matching,
                    "stub": stub,
                    "pct_matched": pct,
                },
                "total_items": len(all_items),
                "count": len(display_items),
                "summary": cat_summary,
                "items": [i.to_dict() for i in display_items],
            }
        )
        return

    if stats or not display_items:
        # Show coverage stats header
        console.print(
            f"  [bold]Coverage[/bold]: {covered}/{total_funcs} functions"
            f"  [green]EXACT: {exact}[/green]"
            f"  [cyan]RELOC: {reloc}[/cyan]"
            f"  [magenta]PROVEN: {proven}[/magenta]"
            f"  [yellow]NEAR_MATCHING: {matching}[/yellow]"
            f"  [dim]STUB: {stub}[/dim]"
            f"  → [bold]{pct}%[/bold] matched"
        )

    if not display_items:
        console.print("No action items found. Great progress!")
        return

    table = Table(show_header=True, header_style="bold", pad_edge=False, expand=True)
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Cat", width=14)
    table.add_column("VA", width=12)
    table.add_column("Sz", width=5, justify="right")
    table.add_column("Name", width=26, no_wrap=True, overflow="ellipsis")
    table.add_column("Match %", width=8, justify="right")
    table.add_column("Δ Bytes", width=8, justify="right")
    table.add_column("Description", no_wrap=True, overflow="ellipsis")

    for i, item in enumerate(display_items, 1):
        color = _CATEGORY_COLORS.get(item.category, "white")
        cat_label = item.category.replace("-", "\u2011")  # non-breaking hyphen for display
        match_str = f"{item.match_percent:.0f}%" if item.match_percent is not None else ""
        delta_str = f"{item.byte_delta}B" if item.byte_delta is not None else ""
        table.add_row(
            str(i),
            f"[{color}]{cat_label}[/{color}]",
            f"0x{item.va:08x}" if item.va else "",
            f"{item.size}B" if item.size else "",
            item.name,
            match_str,
            delta_str,
            item.description,
        )

    # Category summary subtitle
    cat_parts: dict[str, int] = {}
    for item in all_items:
        cat_parts[item.category] = cat_parts.get(item.category, 0) + 1
    subtitle = "  ".join(
        f"[{_CATEGORY_COLORS.get(cat, 'white')}]{cat}: {cnt}[/{_CATEGORY_COLORS.get(cat, 'white')}]"
        for cat, cnt in sorted(cat_parts.items(), key=lambda x: -x[1])
    )

    panel = Panel(
        table,
        title=f"[bold]Rebrew TODO[/bold] — {len(all_items)} actions"
        f"  [green]{exact}E[/green] [cyan]{reloc}R[/cyan]"
        f" [magenta]{proven}P[/magenta] [yellow]{matching}M[/yellow]"
        f" [dim]{stub}S[/dim] ({pct}%)",
        subtitle=subtitle,
        border_style="blue",
    )
    console.print(panel)
    console.print(f"  Showing top {len(display_items)} of {len(all_items)} items")
    console.print(
        "  Tip: use [bold]rebrew todo -c <category>[/bold] to filter  |  [bold]rebrew todo -s[/bold] for stats"
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
