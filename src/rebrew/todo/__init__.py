"""Prioritized action dashboard for rebrew projects.

Synthesizes verify results, coverage data, and function catalog into a single
ranked list of "what to work on next" by affected extent, then estimated effort.

Usage::

    rebrew todo                     Top 20 actions by overall impact
    rebrew todo --limit 50          Show top 50
    rebrew todo --category fix-delta        Filter by category
    rebrew todo --stats             Show coverage stats header
    rebrew todo --json              Machine-readable output
"""

from typing import TYPE_CHECKING, Any
lazy import json
lazy from collections.abc import Sequence
lazy from pathlib import Path

if TYPE_CHECKING:
    from rebrew.catalog import FunctionEntry
    from rebrew.config import ProjectConfig

import typer

from rebrew.cli import (
    AllTargetsOption,
    TargetOption,
    all_targets_run,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
    require_non_negative,
)
from rebrew.todo.collectors import (
    collect_active_functions,
    collect_data_drift,
    collect_library_candidates,
    collect_missing_bindings,
    collect_new_functions,
    collect_postlink_rewritten,
    collect_prover_candidates,
    collect_setup_steps,
    collect_start_data,
    zero_fill_tail_checker,
)
from rebrew.todo.collectors import (
    collect_all as _collect_all_impl,
)
from rebrew.todo.models import (
    CAT_COMPILE_ERROR as CAT_COMPILE_ERROR,
)
from rebrew.todo.models import (
    CAT_DATA_DRIFT as CAT_DATA_DRIFT,
)
from rebrew.todo.models import (
    CAT_DOCUMENTED as CAT_DOCUMENTED,
)
from rebrew.todo.models import (
    CAT_EXACT_ONLY as CAT_EXACT_ONLY,
)
from rebrew.todo.models import (
    CAT_EXTRACT_ERROR as CAT_EXTRACT_ERROR,
)
from rebrew.todo.models import (
    CAT_FIX_DELTA as CAT_FIX_DELTA,
)
from rebrew.todo.models import (
    CAT_IDENTIFY_LIBRARY as CAT_IDENTIFY_LIBRARY,
)
from rebrew.todo.models import (
    CAT_IMPROVE_MATCH as CAT_IMPROVE_MATCH,
)
from rebrew.todo.models import (
    CAT_MISSING_ANNOTATION as CAT_MISSING_ANNOTATION,
)
from rebrew.todo.models import (
    CAT_NAKED as CAT_NAKED,
)
from rebrew.todo.models import (
    CAT_POSTLINK as CAT_POSTLINK,
)
from rebrew.todo.models import (
    CAT_RUN_PROVER as CAT_RUN_PROVER,
)
from rebrew.todo.models import (
    CAT_SETUP as CAT_SETUP,
)
from rebrew.todo.models import (
    CAT_START_DATA as CAT_START_DATA,
)
from rebrew.todo.models import (
    CAT_START_FUNCTION as CAT_START_FUNCTION,
)
from rebrew.todo.models import (
    DATA_CATEGORIES,
    EXTERN_CACHE,
    EXTERN_CACHE_LOCK,
    EXTERN_CACHE_MAX,
    EXTERN_CACHE_VERSION,
    NON_TARGET_MARKERS,
    PROVE_MAX_DIFF_BYTES,
    PROVE_MAX_FUNC_BYTES,
    TODO_FIELDS,
    begin_extern_cache,
    caller_boost,
    caller_counts,
    caller_suffix,
    display_path,
    extern_cache_dir,
    extern_cache_remember,
    extern_entry,
    extern_path_key,
    extern_source_stamp,
    flush_extern_cache,
    item_domain,
    rank_by_impact,
    select_item_fields,
)
from rebrew.todo.models import (
    TodoItem as TodoItem,
)
from rebrew.todo.models import (
    calculate_roi as calculate_roi,
)
from rebrew.todo.models import (
    load_verify_entries as load_verify_entries,
)
from rebrew.todo.render import (
    CATEGORY_COLORS,
    LETTER_STATUSES,
    coverage_status_markup,
    render_stats_header,
    render_todo_panel,
)
from rebrew.todo.render import (
    render_matched_headline as _render_matched_headline_impl,
)
lazy from rebrew.config import ProjectConfig as ProjectConfig
lazy from rebrew.naming import (
    detect_unmatchable,
    external_vas,
    inside_annotated_vas,
    load_data,
    scope_to_target,
)
lazy from rebrew.utils import atomic_write_text, floor_pct

# ---------------------------------------------------------------------------
# Local module-private aliases preserved for existing tests and benchmarks
# ---------------------------------------------------------------------------

_PROVE_MAX_DIFF_BYTES = PROVE_MAX_DIFF_BYTES
_PROVE_MAX_FUNC_BYTES = PROVE_MAX_FUNC_BYTES
_NON_TARGET_MARKERS = NON_TARGET_MARKERS
_CATEGORY_COLORS = CATEGORY_COLORS
_DATA_CATEGORIES = DATA_CATEGORIES
_TODO_FIELDS = TODO_FIELDS
_LETTER_STATUSES = LETTER_STATUSES

_EXTERN_CACHE = EXTERN_CACHE
_EXTERN_CACHE_MAX = EXTERN_CACHE_MAX
_EXTERN_CACHE_LOCK = EXTERN_CACHE_LOCK
_EXTERN_CACHE_VERSION = EXTERN_CACHE_VERSION

_select_item_fields = select_item_fields
_item_domain = item_domain
_rank_by_impact = rank_by_impact
_extern_path_key = extern_path_key
_display_path = display_path
_extern_source_stamp = extern_source_stamp
_extern_cache_dir = extern_cache_dir
_extern_entry = extern_entry
_begin_extern_cache = begin_extern_cache
_extern_cache_remember = extern_cache_remember
_caller_counts = caller_counts
_caller_boost = caller_boost
_caller_suffix = caller_suffix
_collect_setup_steps = collect_setup_steps
_collect_start_data = collect_start_data
_zero_fill_tail_checker = zero_fill_tail_checker
_collect_missing_bindings = collect_missing_bindings
_coverage_status_markup = coverage_status_markup


def _effective_status(ann_status: str, cached: str | None) -> str:
    from rebrew.status import effective_status

    return effective_status(ann_status, cached)


def _angr_available() -> bool:
    from rebrew.matching.prove import angr_available

    return angr_available()


def _infer_module(name: str, default: str) -> str:
    from rebrew.library.identify import infer_module

    return infer_module(name, default)


def _stock_lib_fns() -> tuple[Any, Any, Any, Any]:
    from rebrew.library.match import index_library, match_bytes, stock_lib_cache, stock_lib_valid

    return stock_lib_cache, stock_lib_valid, index_library, match_bytes


def _copied_ranges(cfg: ProjectConfig) -> list[tuple[int, int]]:
    from rebrew.status import postlink_copied_ranges

    return postlink_copied_ranges(cfg)


def _span_is_copied(va: int, size: int, copied: list[tuple[int, int]]) -> bool:
    from rebrew.status import span_is_copied

    return span_is_copied(va, size, copied)


def _find_built_image(root: Path, target_name: str, raw_link: Path | None = None) -> Path | None:
    from rebrew.status import find_built_image

    return find_built_image(root, target_name, raw_link)


def _flush_extern_cache(cache: dict[str, Any]) -> None:
    flush_extern_cache(cache, write_text=atomic_write_text)


def _collect_active_functions(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    name_by_va: dict[int, str],
    verify_entries: dict[str, Any],
    caller_counts_map: dict[str, int] | None = None,
) -> list[TodoItem]:
    return collect_active_functions(
        existing,
        size_by_va,
        name_by_va,
        verify_entries,
        caller_counts_map,
        effective_status_fn=_effective_status,
        prover_available_fn=_angr_available,
    )


def _collect_prover_candidates(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    verify_entries: dict[str, Any],
) -> list[TodoItem]:
    return collect_prover_candidates(
        existing,
        size_by_va,
        verify_entries,
        effective_status_fn=_effective_status,
        prover_available_fn=_angr_available,
    )


def _collect_new_functions(
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
    cfg: ProjectConfig,
    skip_vas: frozenset[int] | set[int] = frozenset(),
) -> list[TodoItem]:
    return collect_new_functions(
        ghidra_funcs,
        existing,
        covered_vas,
        cfg,
        skip_vas,
        unmatchable_detector=detect_unmatchable,
        infer_module_fn=_infer_module,
        stock_lib_fns=_stock_lib_fns(),
        out_console=console,
    )


def _collect_library_candidates(
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
    cfg: ProjectConfig,
) -> list[TodoItem]:
    return collect_library_candidates(
        ghidra_funcs,
        existing,
        cfg,
        unmatchable_detector=detect_unmatchable,
        infer_module_fn=_infer_module,
        out_console=console,
    )


def _collect_data_drift(
    cfg: ProjectConfig,
    data_entries: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> list[TodoItem]:
    return collect_data_drift(
        cfg,
        data_entries,
        copied_ranges_fn=_copied_ranges,
        span_is_copied_fn=_span_is_copied,
    )


def _collect_postlink_rewritten(
    cfg: ProjectConfig,
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
) -> list[TodoItem]:
    return collect_postlink_rewritten(
        cfg,
        existing,
        size_by_va,
        find_built_image_fn=_find_built_image,
    )


def collect_all(
    cfg: ProjectConfig,
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
    exclude_vas: set[int] | None = None,
    *,
    scanned: Sequence[Path] | None = None,
) -> list[TodoItem]:
    """Collect and rank actions by affected bytes, using effort to break ties."""
    return _collect_all_impl(
        cfg,
        ghidra_funcs,
        existing,
        covered_vas,
        exclude_vas,
        scanned=scanned,
        verify_entries_loader=load_verify_entries,
        unmatchable_detector=detect_unmatchable,
        effective_status_fn=_effective_status,
        prover_available_fn=_angr_available,
        infer_module_fn=_infer_module,
        stock_lib_fns=_stock_lib_fns(),
        copied_ranges_fn=_copied_ranges,
        span_is_copied_fn=_span_is_copied,
        find_built_image_fn=_find_built_image,
        out_console=console,
    )


def render_matched_headline(
    matched: int,
    total: int,
    *,
    accounted_bytes: int = 0,
    text_bytes: int = 0,
) -> None:
    """Print the same progress line ``rebrew status`` prints."""
    from rebrew.status import CODE_ACCOUNT_CAPTION, code_account_headline

    _render_matched_headline_impl(
        matched,
        total,
        accounted_bytes=accounted_bytes,
        text_bytes=text_bytes,
        out_console=console,
        code_account_caption=CODE_ACCOUNT_CAPTION,
        code_account_headline_fn=code_account_headline,
    )


def _requested_item_fields(fields: str | None, *, json_mode: bool) -> list[str] | None:
    """Validate ``--fields`` before any project work and preserve request order."""
    if fields is None:
        return None
    selected = [name.strip() for name in fields.split(",") if name.strip()]
    unknown = sorted(set(selected) - set(TODO_FIELDS))
    if unknown:
        error_exit(
            f"unknown --fields value(s): {', '.join(unknown)}; "
            f"choose from: {', '.join(TODO_FIELDS)}",
            json_mode=json_mode,
            kind="usage",
        )
    return selected


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew todo  # Top 20 actions by affected extent, then estimated effort\n\n"
    "  rebrew todo --limit 50  # Show top 50\n\n"
    "  # Filter to quick-win near-misses (<= 20B diff)\n"
    "  rebrew todo --category fix-delta\n\n"
    "  # Filter to functions needing general work\n"
    "  rebrew todo --category improve-match\n\n"
    "  rebrew todo --json  # Machine-readable JSON output\n\n"
    "  rebrew todo --json --fields category,va,command  # Select item fields\n\n"
    "[bold]Categories (ranked by affected bytes, then estimated effort):[/bold]\n\n"
    "  setup · · · · · · · · · Project setup steps (fresh projects)\n\n"
    "  compile-error · · · · · Failed verify syntax/includes\n\n"
    "  extract-error · · · · · Symbol not found in .obj: binding/symbol/implementation issue\n\n"
    "  fix-delta · · · · · · · Known tiny byte diffs (<= 20B): flag sweeps, padding, GA\n\n"
    "  improve-match · · · · · Functions in-progress without a known small delta\n\n"
    "  start-function · · · ·  Uncovered functions, ranked by affected extent\n\n"
    "  missing-annotation · ·  Found in Ghidra but missing C body or SIZE metadata\n\n"
    "  identify-library · · ·  Uncovered library-origin functions\n\n"
    "  run-prover · · · · · ·  Small nearly-matching functions (angr equivalence)\n\n"
    "  documented · · · · · ·  IAT thunks / non-reproducible code. Audit only, hidden from the default list\n\n"
    "  data-drift · · · · · ·  Data symbol differs from reference bytes. Run `rebrew verify --data`\n\n"
    "  start-data · · · · · ·  Data symbol never verified. Run `rebrew verify --data`\n\n"
    "  exact-only · · · · · ·  RELOC matches: identical only with relocations masked, not straight out of the toolchain\n\n"
    "  postlink-mangled · · ·  Functions whose shipped bytes a postlink fixer rewrote (needs `raw_link` configured)\n\n"
    "[dim]Reads from function_structure.json, source files, and the selected verify cache "
    "(.rebrew/verify_cache.toml, or its per-target file under .rebrew/targets/).[/dim]"
)


app = typer.Typer(
    help="Prioritized actions by overall impact, then estimated effort.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    count: int = typer.Option(20, "--limit", "-n", help="Number of items to show (0 = none)"),
    offset: int = typer.Option(0, "--offset", help="Skip this many items before listing"),
    fields: str | None = typer.Option(
        None,
        "--fields",
        help="Comma-separated JSON item fields (envelope fields are always included)",
    ),
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help=f"Filter by category ({', '.join(CATEGORY_COLORS)})",
    ),
    stats: bool = typer.Option(False, "--stats", "-s", help="Show coverage stats header"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
) -> None:
    """Show prioritized actions ranked by affected extent, then estimated effort."""
    category = option_default(category, None)
    fields = option_default(fields, None)
    selected_fields = _requested_item_fields(fields, json_mode=option_default(json_output, False))
    count = require_non_negative(
        option_default(count, 20), "--limit", json_mode=option_default(json_output, False)
    )
    offset = require_non_negative(
        option_default(offset, 0), "--offset", json_mode=option_default(json_output, False)
    )
    if category is not None and category not in CATEGORY_COLORS:
        error_exit(
            f"Unknown category {category!r}; choose one of: {', '.join(CATEGORY_COLORS)}",
            json_mode=json_output,
        )
    all_targets = option_default(all_targets, False)
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda n: main(
            count=count,
            offset=offset,
            fields=fields,
            category=category,
            stats=stats,
            json_output=json_output,
            target=n,
            all_targets=False,
        ),
    ):
        return
    cfg = require_config(target=target, json_mode=json_output)
    from rebrew.source.discovery import scan_files

    tree = scan_files(cfg.reversed_dir)
    try:
        loaded = load_data(cfg, tree=tree)
        ghidra_funcs, existing, covered_vas = loaded
        # Before scoping: external .lib rows carry library modules
        # (D3DX8, MSVCRT, …) and leave the denominator as identified
        # external code whatever the module — the flag is
        # `targets.<name>.external_libs` (same rule as `rebrew status`).
        library_vas = external_vas(existing, getattr(cfg, "external_libs", None))
        existing = scope_to_target(existing, cfg)
        # Switch arms and split bodies inside an annotated function (library
        # rows included) are not functions: the rule `rebrew status` uses.
        pseudo_vas = inside_annotated_vas(ghidra_funcs, existing)
        # Library rows are NOT work: their bytes come from the linked archive,
        # so "improve-match / needs implementation" is a false action item.
        # The server's `library_msvc.h` alone contributed 11 of the top 20
        # items before this filter (`_ftell`, `__ftell_lk`, `_realloc`, …
        # all correctly attributed, all unrunnable).
        existing = {va: info for va, info in existing.items() if va not in library_vas}
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        error_exit(f"Failed to load project data: {exc}", json_mode=json_output)
    all_items = collect_all(
        cfg,
        ghidra_funcs,
        existing,
        covered_vas,
        exclude_vas=library_vas | pseudo_vas,
        scanned=tree,
    )

    # Coverage stats (always computed for JSON, optional for terminal)
    # Overlay verify cache on annotation statuses (same logic + target guard
    # as status.py — a different target's cache must not leak into this
    # project's coverage stats).
    from rebrew.status import collect_status, effective_status, load_verify_statuses

    verify_statuses = load_verify_statuses(cfg)

    from rebrew.metadata.functions import canonical_status

    status_counts: dict[str, int] = {}
    documented = 0
    for va_int, info in existing.items():
        # External .lib attributions count for nothing (same rule as
        # `rebrew status`): identifications, not bodies to match.
        if va_int in library_vas:
            continue
        ann_status = info.get("status", "STUB")
        s = effective_status(ann_status, verify_statuses.get(va_int))
        # Documented non-targets stay STUB, the bucket `rebrew status` uses.
        # `documented` is how many of those STUB rows carry the marker, not
        # a seventh bucket and not the NO_SOURCE remainder.
        if (
            s == "STUB"
            and canonical_status(ann_status or "") == "STUB"
            and any(m in info.get("blocker", "") for m in NON_TARGET_MARKERS)
        ):
            documented += 1
        status_counts[s] = status_counts.get(s, 0) + 1
    function_vas = {va for va in existing if va not in library_vas}
    ghidra_vas = {f.va for f in ghidra_funcs}
    total_funcs = len(function_vas | (ghidra_vas - library_vas - pseudo_vas))
    covered = len(function_vas)
    # Denominator mirrors `rebrew status` exactly (the two must not
    # disagree): covered FUNCTION rows plus the ghidra inventory MINUS
    # identified library code (CRT/zlib/static libs — "never reverse"
    # attributions, not pending work).  The older shapes both lied:
    # `ghidra_funcs` alone went over 100% (library rows outside the
    # inventory), and `ghidra ∪ covered` counted library attributions as
    # unfinished functions (28% where status said 42% for the same tree).
    # When the target binary is on disk, the live status report replaces
    # these counts so a second loop cannot drift from it.
    text_bytes = 0
    accounted_bytes = 0
    byte_coverage_pct: float | None = None
    binary = Path(getattr(cfg, "target_binary", "") or "")
    if binary.is_file():
        try:
            progress = collect_status(cfg, tree=tree, data=loaded)
        except OSError, ValueError, KeyError:
            progress = None
        else:
            if progress is not None and progress.load_error:
                progress = None
        if progress is not None:
            status_counts = dict(progress.status_counts)
            total_funcs = progress.total_functions
            covered = progress.covered_functions
            if progress.total_text_bytes > 0:
                text_bytes = progress.total_text_bytes
                accounted_bytes = progress.accounted_text_bytes
                byte_coverage_pct = progress.byte_coverage_pct
    exact = status_counts.get("EXACT", 0)
    reloc = status_counts.get("RELOC", 0)
    proven = status_counts.get("PROVEN", 0)
    matching = status_counts.get("NEAR_MATCHING", 0)
    stub = status_counts.get("STUB", 0)
    denominator = total_funcs
    # Function ratio. PROVEN bytes still differ from the target. This is
    # `StatusReport.matched_pct`, not the code account.
    pct = floor_pct(exact + reloc, denominator)
    if byte_coverage_pct is not None:
        pct_label = f"{byte_coverage_pct}% of .text"
    else:
        pct_label = f"{pct}% of functions"

    if category:
        all_items = [i for i in all_items if i.category == category]
    else:
        # Documented non-targets are audit info, not work — hide them from the
        # default actionable list (still visible via `-c documented` and the
        # coverage stats below).
        all_items = [i for i in all_items if i.category != CAT_DOCUMENTED]

    page = all_items[offset:]
    display_items = page[:count]
    truncated = len(page) > count

    if json_output:
        cat_summary: dict[str, int] = {}
        for item in all_items:
            cat_summary[item.category] = cat_summary.get(item.category, 0) + 1
        json_print(
            {
                "coverage": {
                    "ghidra_funcs": total_funcs,
                    "covered": covered,
                    "exact": exact,
                    "reloc": reloc,
                    "proven": proven,
                    "matching": matching,
                    "stub": stub,
                    "documented": documented,
                    "pct_matched": pct,
                    "byte_coverage_pct": byte_coverage_pct,
                    "statuses": status_counts,
                },
                "total_items": len(all_items),
                "count": len(display_items),
                "offset": offset,
                "limit": count,
                "truncated": truncated,
                "summary": cat_summary,
                "items": select_item_fields(display_items, selected_fields),
            }
        )
        return

    if denominator > 0 or text_bytes > 0:
        # One bar. With a known .text it is the code account; otherwise the
        # function ratio, labeled as functions. Per-row Match % is neither.
        render_matched_headline(
            exact + reloc,
            denominator,
            accounted_bytes=accounted_bytes,
            text_bytes=text_bytes,
        )

    if stats or not display_items:
        render_stats_header(
            status_counts,
            covered=covered,
            total_funcs=total_funcs,
            exact=exact,
            reloc=reloc,
            proven=proven,
            matching=matching,
            stub=stub,
            documented=documented,
            denominator=denominator,
            out_console=console,
        )

    if not display_items:
        console.print("No action items found.")
        return

    render_todo_panel(
        display_items,
        all_items,
        status_counts,
        pct_label,
        offset,
        out_console=console,
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()


__all__ = [
    "CATEGORY_COLORS",
    "CAT_COMPILE_ERROR",
    "CAT_DATA_DRIFT",
    "CAT_DOCUMENTED",
    "CAT_EXACT_ONLY",
    "CAT_EXTRACT_ERROR",
    "CAT_FIX_DELTA",
    "CAT_IDENTIFY_LIBRARY",
    "CAT_IMPROVE_MATCH",
    "CAT_MISSING_ANNOTATION",
    "CAT_NAKED",
    "CAT_POSTLINK",
    "CAT_RUN_PROVER",
    "CAT_SETUP",
    "CAT_START_DATA",
    "CAT_START_FUNCTION",
    "DATA_CATEGORIES",
    "EXTERN_CACHE",
    "EXTERN_CACHE_LOCK",
    "EXTERN_CACHE_MAX",
    "EXTERN_CACHE_VERSION",
    "LETTER_STATUSES",
    "NON_TARGET_MARKERS",
    "PROVE_MAX_DIFF_BYTES",
    "PROVE_MAX_FUNC_BYTES",
    "TODO_FIELDS",
    "TodoItem",
    "app",
    "begin_extern_cache",
    "calculate_roi",
    "caller_boost",
    "caller_counts",
    "caller_suffix",
    "collect_all",
    "coverage_status_markup",
    "display_path",
    "extern_cache_dir",
    "extern_cache_remember",
    "extern_entry",
    "extern_path_key",
    "extern_source_stamp",
    "flush_extern_cache",
    "item_domain",
    "load_verify_entries",
    "main",
    "main_entry",
    "rank_by_impact",
    "render_matched_headline",
    "select_item_fields",
]
