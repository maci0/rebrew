"""todo.py – Prioritized action dashboard for rebrew projects.

Synthesizes signals from multiple analysis tools (verify, next, triage, status)
into a single ranked list of "what to work on next" with ROI scoring and
suggested commands.

Usage::

    rebrew todo                     Top 20 actions by ROI
    rebrew todo --count 50          Show top 50
    rebrew todo -c fix-near-miss    Filter by category
    rebrew todo --json              Machine-readable output
"""

import contextlib
import json
import math
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

from rebrew.cli import TargetOption, error_exit, json_print, require_config
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
CAT_FIX_NEAR_MISS = "fix-near-miss"
CAT_FLAG_SWEEP = "flag-sweep"
CAT_IMPROVE_MATCHING = "improve-matching"
CAT_RUN_PROVER = "run-prover"
CAT_FIX_COMPILE_ERROR = "fix-compile-error"
CAT_FIX_VERIFY_FAIL = "fix-verify-fail"
CAT_FINISH_STUB = "finish-stub"
CAT_START_FUNCTION = "start-function"
CAT_ADD_ANNOTATIONS = "add-annotations"
CAT_IDENTIFY_LIBRARY = "identify-library"

_CATEGORY_COLORS = {
    CAT_SETUP: "bold white",
    CAT_FIX_NEAR_MISS: "green",
    CAT_FLAG_SWEEP: "yellow",
    CAT_IMPROVE_MATCHING: "yellow",
    CAT_RUN_PROVER: "cyan",
    CAT_FIX_COMPILE_ERROR: "red",
    CAT_FIX_VERIFY_FAIL: "red",
    CAT_FINISH_STUB: "magenta",
    CAT_START_FUNCTION: "cyan",
    CAT_ADD_ANNOTATIONS: "dim",
    CAT_IDENTIFY_LIBRARY: "blue",
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
        return d


# ---------------------------------------------------------------------------
# Size-tier scoring table: (small<100, medium<300, large) score bounds
# ---------------------------------------------------------------------------

_SCORE_TIERS: dict[str, tuple[float, float, float]] = {
    CAT_FIX_COMPILE_ERROR: (95.0, 90.0, 85.0),
    CAT_FINISH_STUB: (75.0, 70.0, 60.0),
    CAT_IMPROVE_MATCHING: (55.0, 50.0, 45.0),
    CAT_RUN_PROVER: (40.0, 35.0, 30.0),
    CAT_ADD_ANNOTATIONS: (40.0, 35.0, 30.0),
    CAT_IDENTIFY_LIBRARY: (25.0, 20.0, 15.0),
}


def _score_by_size(category: str, size: int) -> float:
    """Score a category using simple size-tier lookup."""
    small, medium, large = _SCORE_TIERS[category]
    if size < 100:
        return small
    if size < 300:
        return medium
    return large


# ---------------------------------------------------------------------------
# Scoring functions with non-trivial logic (kept as standalone)
# ---------------------------------------------------------------------------


def _score_near_miss(delta: int | None, size: int) -> float:
    """Score a near-miss fix (delta <= 4B). Higher = easier to fix."""
    if delta is None:
        return 70.0
    # delta=1 → ~85, delta=4 → ~75, logarithmic falloff
    score = 85.0 - 5.0 * math.log2(max(delta, 1))
    # Boost small functions slightly
    if size < 100:
        score += 2.0
    return min(85.0, max(70.0, score))


def _score_flag_sweep(delta: int | None, size: int) -> float:
    """Score a flag-sweep candidate (delta 5-20B)."""
    base = 45.0
    if delta is not None:
        # Smaller delta = higher score
        base -= (delta - 5) * 0.5
    if size < 200:
        base += 3.0
    return min(55.0, max(25.0, base))


def _score_verify_fail(delta: int | None, match_pct: float | None, size: int = 0) -> float:
    """Score a verify failure. Best ROI is moderate match% on small functions.

    ROI tiers by match%:
    - >=95%: negligible gain (stubborn structural diff) → ~44
    - 80-94%: decent, worth fixing → ~53-58
    - 60-79%: sweet spot; meaningful gain, achievable → ~58-62
    - 30-59%: significant work, moderate gain → ~47-50
    - <30%:   effectively a full rewrite; scores BELOW start-function (< 45)
              so these don't crowd out more productive work

    Capped at 62. Min 36 (below add-annotations floor for large low-match items).
    """
    if match_pct is None:
        # Unknown — treat conservatively, don't crowd out start-function
        base = 46.0
    elif match_pct >= 95.0:
        # Negligible gain, last 1% often a stubborn structural diff.
        # Flat score below start-function min (45) so it never crowds them out.
        return 43.0
    elif match_pct >= 80.0:
        base = 55.0
    elif match_pct >= 60.0:
        base = 59.0  # sweet spot
    elif match_pct >= 30.0:
        base = 48.0
    else:
        # Full regression territory — score BELOW start-function (~45)
        base = 40.0

    # Size modifiers — only meaningful for mid-range items
    if match_pct is not None and match_pct >= 30.0:
        if 0 < size < 100:
            base += 3.0
        elif size > 500:
            base -= 5.0
    elif match_pct is not None and match_pct < 30.0 and size > 300:
        # Low-match, large function: even harder to fix
        base -= 3.0

    return min(62.0, max(36.0, base))


def _score_start_function(difficulty: int, size: int) -> float:
    """Score a new function to start working on."""
    score = 65.0 - (difficulty * 5)
    return min(65.0, max(45.0, score))


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


def _collect_near_misses(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
) -> tuple[list[TodoItem], set[int]]:
    """Collect fix-near-miss (delta <= 4B) and flag-sweep (delta 5-20B) items.

    Returns (items, has_delta_vas) where has_delta_vas tracks VAs with known deltas
    so _collect_improve_matching can skip them.
    """
    items: list[TodoItem] = []
    has_delta: set[int] = set()
    for va, info in existing.items():
        if info["status"] not in ("MATCHING", "MATCHING_RELOC"):
            continue
        raw_bd = info.get("blocker_delta", "")
        try:
            delta = int(raw_bd) if raw_bd else parse_byte_delta(info.get("blocker", ""))
        except ValueError:
            delta = parse_byte_delta(info.get("blocker", ""))
        if delta is None:
            continue
        has_delta.add(va)

        size = size_by_va.get(va) or int(info.get("size", 0))
        filename = info.get("filename", "")

        if delta <= 4:
            items.append(
                TodoItem(
                    category=CAT_FIX_NEAR_MISS,
                    roi_score=_score_near_miss(delta, size),
                    va=va,
                    name=info.get("symbol", ""),
                    size=size,
                    filename=filename,
                    description=f"{delta}B diff — tweak code or adjust padding",
                    command=f"rebrew diff {filename}" if filename else f"rebrew diff 0x{va:08x}",
                    byte_delta=delta,
                    status=info["status"],
                )
            )
        elif delta <= 20:
            items.append(
                TodoItem(
                    category=CAT_FLAG_SWEEP,
                    roi_score=_score_flag_sweep(delta, size),
                    va=va,
                    name=info.get("symbol", ""),
                    size=size,
                    filename=filename,
                    description=f"{delta}B diff — try flag sweep or GA",
                    command=f"rebrew match --flag-sweep-only {filename}"
                    if filename
                    else f"rebrew match --flag-sweep-only 0x{va:08x}",
                    byte_delta=delta,
                    status=info["status"],
                )
            )
    return items, has_delta


def _collect_improve_matching(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    has_delta: set[int],
) -> list[TodoItem]:
    """Collect MATCHING functions without parseable delta (need investigation)."""
    items: list[TodoItem] = []
    for va, info in existing.items():
        if info["status"] not in ("MATCHING", "MATCHING_RELOC"):
            continue
        if va in has_delta:
            continue  # Already captured by near-miss or flag-sweep

        size = size_by_va.get(va) or int(info.get("size", 0))
        filename = info.get("filename", "")
        blocker = info.get("blocker", "")
        desc = "MATCHING — run diff to find delta"
        if blocker:
            desc = f"MATCHING — {blocker[:50]}"

        items.append(
            TodoItem(
                category=CAT_IMPROVE_MATCHING,
                roi_score=_score_by_size(CAT_IMPROVE_MATCHING, size),
                va=va,
                name=info.get("symbol", ""),
                size=size,
                filename=filename,
                description=desc,
                command=f"rebrew diff {filename}" if filename else f"rebrew diff 0x{va:08x}",
                status=info["status"],
            )
        )
    return items


def _collect_prover_candidates(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
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
        if info["status"] not in ("MATCHING", "MATCHING_RELOC"):
            continue
        size = size_by_va.get(va) or int(info.get("size", 0))
        if size > 500 or size == 0:
            continue
        filename = info.get("filename", "")
        items.append(
            TodoItem(
                category=CAT_RUN_PROVER,
                roi_score=_score_by_size(CAT_RUN_PROVER, size),
                va=va,
                name=info.get("symbol", ""),
                size=size,
                filename=filename,
                description="MATCHING + small — prove semantic equivalence",
                command=f"rebrew prove {filename}" if filename else f"rebrew prove 0x{va:08x}",
                status=info["status"],
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


def _collect_compile_errors(
    entries: dict[str, "VerifyCacheEntry"],
) -> list[TodoItem]:
    """Collect functions with compile errors from verify cache entries."""
    items: list[TodoItem] = []
    for _va_key, entry in entries.items():
        result = entry.result
        if result.status != "COMPILE_ERROR":
            continue
        va_str = str(result.va)
        try:
            va = int(va_str, 16) if va_str.startswith("0x") else int(va_str)
        except (ValueError, TypeError):
            continue
        size = result.size
        filepath = result.filepath
        items.append(
            TodoItem(
                category=CAT_FIX_COMPILE_ERROR,
                roi_score=_score_by_size(CAT_FIX_COMPILE_ERROR, size),
                va=va,
                name=result.symbol,
                size=size,
                filename=filepath,
                description="Compile error — fix syntax/includes",
                command=f"rebrew test {filepath}" if filepath else "rebrew verify",
                status="COMPILE_ERROR",
            )
        )
    return items


def _collect_verify_failures(
    entries: dict[str, "VerifyCacheEntry"],
) -> list[TodoItem]:
    """Collect verify MISMATCH/MISSING_FILE failures from verify cache entries."""
    items: list[TodoItem] = []
    for _va_key, entry in entries.items():
        result = entry.result
        status = result.status
        if status not in ("MISMATCH", "MISSING_FILE"):
            continue
        va_str = str(result.va)
        try:
            va = int(va_str, 16) if va_str.startswith("0x") else int(va_str)
        except (ValueError, TypeError):
            continue
        size = result.size
        filepath = result.filepath
        delta = result.delta
        match_pct = result.match_percent

        if status == "MISSING_FILE":
            desc = "Source file missing — recreate or remove annotation"
        elif match_pct is not None:
            desc = f"Verify mismatch ({match_pct:.0f}% match)"
        else:
            desc = "Verify mismatch — check diff"

        items.append(
            TodoItem(
                category=CAT_FIX_VERIFY_FAIL,
                roi_score=_score_verify_fail(delta, match_pct, size),
                va=va,
                name=result.name,
                size=size,
                filename=filepath,
                description=desc,
                command=f"rebrew test {filepath}" if filepath else "rebrew verify",
                byte_delta=delta,
                status=status,
            )
        )
    return items


def _collect_stubs(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
) -> list[TodoItem]:
    """Collect STUB functions that need implementation."""
    items: list[TodoItem] = []
    for va, info in existing.items():
        if info["status"] != "STUB":
            continue
        size = size_by_va.get(va) or int(info.get("size", 0))
        filename = info.get("filename", "")
        items.append(
            TodoItem(
                category=CAT_FINISH_STUB,
                roi_score=_score_by_size(CAT_FINISH_STUB, size),
                va=va,
                name=info.get("symbol", ""),
                size=size,
                filename=filename,
                description=f"STUB ({size}B) — implement function body",
                command=f"rebrew test {filename}" if filename else f"rebrew test 0x{va:08x}",
                status="STUB",
            )
        )
    return items


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

        reason = detect_unmatchable(va, size, binary_info, iat_set, ignored, name)
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
                roi_score=_score_start_function(difficulty, size),
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


def _collect_missing_annotations(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
) -> list[TodoItem]:
    """Collect files with missing symbol (no C function definition to derive from)."""
    items: list[TodoItem] = []
    for va, info in existing.items():
        symbol = info.get("symbol", "")
        if symbol:
            continue

        size = size_by_va.get(va) or int(info.get("size", 0))
        filename = info.get("filename", "")
        items.append(
            TodoItem(
                category=CAT_ADD_ANNOTATIONS,
                roi_score=_score_by_size(CAT_ADD_ANNOTATIONS, size),
                va=va,
                name=f"FUN_{va:08x}",
                size=size,
                filename=filename,
                description="Missing: symbol (add C function definition)",
                command=f"rebrew lint {filename}" if filename else "rebrew lint",
                status=info.get("status", ""),
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
                roi_score=_score_by_size(CAT_IDENTIFY_LIBRARY, size),
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

    # Near-misses + flag-sweep (returns set of VAs with known deltas)
    near_miss_items, has_delta = _collect_near_misses(existing, size_by_va)

    items.extend(near_miss_items)
    items.extend(_collect_improve_matching(existing, size_by_va, has_delta))
    items.extend(_collect_prover_candidates(existing, size_by_va))
    verify_entries = _load_verify_entries(cfg)
    items.extend(_collect_compile_errors(verify_entries))
    items.extend(_collect_verify_failures(verify_entries))
    items.extend(_collect_stubs(existing, size_by_va))
    items.extend(_collect_new_functions(ghidra_funcs, existing, covered_vas, cfg))
    items.extend(_collect_missing_annotations(existing, size_by_va))
    items.extend(_collect_library_candidates(ghidra_funcs, existing, cfg))

    # Sort by ROI descending
    items.sort(key=lambda x: (-x.roi_score, x.va))
    return items


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = """\
[bold]Examples:[/bold]

rebrew todo                          Top 20 actions by ROI

rebrew todo --count 50               Show top 50

rebrew todo -c fix-near-miss         Filter to near-miss fixes only

rebrew todo -c flag-sweep            Filter to flag-sweep candidates

rebrew todo --json                   Machine-readable JSON output

[bold]Categories (highest ROI first):[/bold]

setup              Project setup steps (fresh projects)

fix-near-miss      MATCHING with ≤4B diff — tweak code or padding

flag-sweep         MATCHING with 5-20B diff — try compiler flags

improve-matching   MATCHING without known delta — investigate diff

run-prover         MATCHING + small — prove equivalence via angr

fix-compile-error  Compile errors from verify cache

fix-verify-fail    Verify mismatches — regression or missing files

finish-stub        STUB functions that need implementation

start-function     Uncovered functions, ranked by difficulty

add-annotations    Missing symbol (no C function definition)

identify-library   Uncovered library-origin functions

[dim]Reads from ghidra_functions.json, source files, and .rebrew/verify_cache.json.[/dim]"""

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
    max_per_cat: int = typer.Option(
        5,
        "--max-per-cat",
        "-m",
        help="Max items per category in default view (0 = unlimited)",
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
    status_counts: dict[str, int] = {}
    for info in existing.values():
        s = info.get("status", "STUB")
        status_counts[s] = status_counts.get(s, 0) + 1
    total_funcs = len(ghidra_funcs)
    covered = len(covered_vas)
    exact = status_counts.get("EXACT", 0)
    reloc = status_counts.get("RELOC", 0)
    matching = status_counts.get("MATCHING", 0) + status_counts.get("MATCHING_RELOC", 0)
    stub = status_counts.get("STUB", 0)
    pct = round(100.0 * (exact + reloc) / total_funcs, 1) if total_funcs else 0.0

    if category:
        all_items = [i for i in all_items if i.category == category]

    # Per-category cap: prevent any single category from flooding the default view.
    # Applied only when not filtering by category. Use -m 0 to disable.
    if not category and max_per_cat > 0:
        cat_counts: dict[str, int] = {}
        capped: list[TodoItem] = []
        for item in all_items:
            n = cat_counts.get(item.category, 0)
            if n < max_per_cat:
                capped.append(item)
                cat_counts[item.category] = n + 1
        display_items = capped[:count]
    else:
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
            f"  [yellow]MATCHING: {matching}[/yellow]"
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
    table.add_column("Description", no_wrap=True, overflow="ellipsis")

    for i, item in enumerate(display_items, 1):
        color = _CATEGORY_COLORS.get(item.category, "white")
        cat_label = item.category.replace("-", "\u2011")  # non-breaking hyphen for display
        table.add_row(
            str(i),
            f"[{color}]{cat_label}[/{color}]",
            f"0x{item.va:08x}" if item.va else "",
            f"{item.size}B" if item.size else "",
            item.name,
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
        f" [yellow]{matching}M[/yellow] [dim]{stub}S[/dim]"
        f" ({pct}%)",
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
