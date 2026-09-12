#!/usr/bin/env python3
"""Genetic Algorithm engine for binary matching — single-function and batch modes.

Compile C source, compare object bytes against a target function, and
iteratively mutate to find a byte-perfect or relocation-normalized match.

Single-function usage:
    rebrew match <source.c> [--generations N --pop-size N]
    rebrew match <source.c> --flag-sweep-only

Batch usage (``rebrew match --all``)::
    rebrew match --all                       Run GA on all STUB functions
    rebrew match --all --improve             GA on all NEAR_MATCHING functions
    rebrew match --all --near-miss           Near-miss NEAR_MATCHING functions
    rebrew match --all --flag-sweep          Batch flag sweep on NEAR_MATCHING
    rebrew match --all --dry-run             List targets without running
"""

from __future__ import annotations

import logging
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    TargetOption,
    error_exit,
    json_print,
    require_config,
    resolve_source_arg,
)
from rebrew.match_ga import (
    _MUTATION_FOCUS_WEIGHT,
    _live_mutation_weights,
    _mutation_focus_weights,
)
from rebrew.match_run import (
    _run_all,
    _run_single_ga,
    _show_ga_history,
)
from rebrew.match_sweep import (
    _run_single_flag_sweep,
    _run_single_toolchain_flag_sweep,
    _run_single_toolchain_sweep,
    resolve_build_params,
)

log = logging.getLogger(__name__)

console = Console(stderr=True)


# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[dim]Auto-reads VA and SIZE from source markers, CFLAGS from metadata. "
    "Symbol is derived from the C function definition. "
    "Requires rebrew-project.toml with valid compiler paths.[/dim]\n\n"
    "[bold]Batch mode (--all):[/bold]\n\n"
    "  rebrew match --all · · · · · · · · · GA on all STUB functions\n\n"
    "  rebrew match --all --improve · · · · · GA on all NEAR_MATCHING functions\n\n"
    "  rebrew match --all --near-miss · · · · GA on near-miss NEAR_MATCHING (Δ ≤ threshold)\n\n"
    "  rebrew match --all --flag-sweep · · · · Batch flag sweep on NEAR_MATCHING functions\n\n"
    "  rebrew match --all --dry-run · · · · · List targets without running\n\n"
    "[bold]Exit codes:[/bold]\n\n"
    "  0   Match found (EXACT or RELOC)\n\n"
    "  1   No match found (structural diffs remain)\n\n"
    "  2   Build or config error"
)

app = typer.Typer(
    help="GA matching engine — single file or batch (--all).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    seed_c: str | None = typer.Argument(None, help="Seed source file (.c) — omit for --all mode"),
    # Single-function options
    cl: str | None = typer.Option(
        None,
        help="CL.EXE command (auto from rebrew-project.toml)",
        rich_help_panel="Single-Function",
    ),
    inc: str | None = typer.Option(
        None, help="Include dir (auto from rebrew-project.toml)", rich_help_panel="Single-Function"
    ),
    cflags: str | None = typer.Option(
        None, help="Compiler flags (auto from source)", rich_help_panel="Single-Function"
    ),
    symbol: str | None = typer.Option(
        None,
        "--symbol",
        help="Symbol to match (auto from source)",
        rich_help_panel="Single-Function",
    ),
    target_va: str | None = typer.Option(
        None, "--va", help="Target VA hex (auto from source)", rich_help_panel="Single-Function"
    ),
    target_size: int | None = typer.Option(
        None, "--size", help="Target size (auto from source)", rich_help_panel="Single-Function"
    ),
    out_dir: str = typer.Option(
        "output/ga_runs", help="Output dir", rich_help_panel="Single-Function"
    ),
    compare_obj: bool = typer.Option(
        True, help="Use object comparison instead of full link", rich_help_panel="Single-Function"
    ),
    lib: str | None = typer.Option(
        None, "--lib", help="Lib dir", rich_help_panel="Single-Function"
    ),
    link: str | None = typer.Option(
        None,
        "--link",
        help="Linker command (auto from rebrew-project.toml)",
        rich_help_panel="Single-Function",
    ),
    ldflags: str | None = typer.Option(
        None, help="Linker flags", rich_help_panel="Single-Function"
    ),
    flag_sweep_only: bool = typer.Option(
        False,
        "--flag-sweep-only",
        help="Run MSVC compiler flag sweep instead of GA (tries flag combos to find exact match)",
        rich_help_panel="Single-Function",
    ),
    tier: str = typer.Option(
        "targeted",
        help="Flag sweep tier: quick, targeted, normal, thorough, or full",
        rich_help_panel="Single-Function",
    ),
    ignore_lint: bool = typer.Option(
        False,
        "--ignore-lint",
        help="Continue even if source marker lint errors exist",
        rich_help_panel="Single-Function",
    ),
    seed: int | None = typer.Option(
        None, "--seed", help="RNG seed for reproducible GA runs", rich_help_panel="GA Tuning"
    ),
    extra_seed: list[str] | None = typer.Option(
        None,
        "--seed-file",
        help="Extra .c file(s) to seed GA population from solved functions. Ignored if --no-seeds is also passed.",
        rich_help_panel="Single-Function",
    ),
    no_seed: bool = typer.Option(
        False,
        "--no-seeds",
        help="Disable cross-function solution seeding (takes precedence over --seed-file)",
        rich_help_panel="Single-Function",
    ),
    mutation_focus: str | None = typer.Option(
        None,
        "--mutation-focus",
        help=(
            "Bias GA mutation selection toward a near-diag category: "
            "register | equivalent | structural, or auto (read the function's "
            "BLOCKER metadata). Suggested operators get 6x selection weight."
        ),
        rich_help_panel="GA Tuning",
    ),
    # GA tuning (shared single/batch)
    generations: int = typer.Option(
        100, "--generations", "-g", help="Number of GA generations", rich_help_panel="GA Tuning"
    ),
    pop_size: int = typer.Option(
        64, "--pop-size", "-p", help="Population size per generation", rich_help_panel="GA Tuning"
    ),
    jobs: int | None = typer.Option(
        None,
        "--jobs",
        "-j",
        help="Parallel jobs (default: from config)",
        rich_help_panel="GA Tuning",
    ),
    # Batch-only options
    all_mode: bool = typer.Option(
        False,
        "--all",
        help="Batch mode: run GA on all STUB functions (use --near-miss for NEAR_MATCHING)",
        rich_help_panel="Batch Mode",
    ),
    all_targets: bool = typer.Option(
        False,
        "--all-targets",
        help="Batch mode: run GA across STUB functions in EVERY configured target",
        rich_help_panel="Batch Mode",
    ),
    flag_sweep_toolchains: bool = typer.Option(
        False,
        "--flag-sweep-toolchains",
        help="Try each vendored MSVC toolchain (SP versions) instead of GA and report the best; combine with --flag-sweep-only to flag-sweep with each toolchain",
        rich_help_panel="Single-Function",
    ),
    sweep_toolchains: str = typer.Option(
        "",
        "--sweep-toolchains",
        "--toolchain",
        help="Sweep only these toolchains (comma-separated profile names or version prefixes, e.g. msvc-6.0,6.0,win16; a Y2K binary likely rules out 2.0/4.x — exclude them with --sweep-exclude-toolchains 2.0,4.0)",
        rich_help_panel="Single-Function",
    ),
    sweep_exclude_toolchains: str = typer.Option(
        "",
        "--sweep-exclude-toolchains",
        help="Skip these toolchains in the sweep (comma-separated profile names or version prefixes, e.g. 2.0,4.0,win16)",
        rich_help_panel="Single-Function",
    ),
    flag_sweep_then_ga: bool = typer.Option(
        False,
        "--flag-sweep-then-ga",
        help="Batch: flag-sweep each stub first, then run the GA with the best flags",
        rich_help_panel="Batch Mode",
    ),
    skip_recent_hours: int = typer.Option(
        0,
        "--skip-recent",
        help="Batch: skip stubs with a GA run record within the last N hours",
        rich_help_panel="Batch Mode",
    ),
    seed_solutions: Path | None = typer.Option(
        None,
        "--seed-solutions-file",
        help=(
            "Batch: extra solutions.json to seed from (cross-project cflags/"
            "source transfer).  E.g. ../makehm-rebrew/.rebrew/solutions.json"
        ),
        rich_help_panel="Batch Mode",
    ),
    llm_seed: bool = typer.Option(
        False,
        "--seed-llm",
        help=(
            "Ask a configured LLM endpoint for alternative C implementations "
            "and inject them into the GA's initial population (see [llm] "
            "config / REBREW_LLM_ENDPOINT)."
        ),
        rich_help_panel="Single-Function",
    ),
    kuna_seed: bool = typer.Option(
        False,
        "--seed-kuna",
        help=(
            "Seed the GA's initial population with Kuna's decompilation of "
            "the target function (github.com/Noelo-Lab/kuna — requires the "
            "`kuna` binary on PATH).  The output is compilability-fixed "
            "(rebrew fix) before injection."
        ),
        rich_help_panel="Single-Function",
    ),
    resume: bool = typer.Option(
        False,
        "--resume",
        help="Batch: resume interrupted GA runs from their per-function checkpoints.",
        rich_help_panel="Batch Mode",
    ),
    near_miss: bool = typer.Option(
        False,
        "--near-miss",
        help="--all: target NEAR_MATCHING near-misses instead of STUBs",
        rich_help_panel="Batch Mode",
    ),
    improve: bool = typer.Option(
        False,
        "--improve",
        help="--all: target all NEAR_MATCHING functions (no delta threshold)",
        rich_help_panel="Batch Mode",
    ),
    size_mismatch: bool = typer.Option(
        False,
        "--size-mismatch",
        help="--all: target SIZE_MISMATCH functions (length differs) with the GA",
        rich_help_panel="Batch Mode",
    ),
    threshold: int = typer.Option(
        10,
        "--threshold",
        help="--all: max byte delta for --near-miss mode",
        rich_help_panel="Batch Mode",
    ),
    flag_sweep: bool = typer.Option(
        False,
        "--flag-sweep",
        help="--all: batch flag sweep on NEAR_MATCHING functions (finds optimal CFLAGS)",
        rich_help_panel="Batch Mode",
    ),
    fix_cflags: bool = typer.Option(
        False,
        "--fix-cflags",
        help="--all --flag-sweep: auto-update CFLAGS metadata on exact match",
        rich_help_panel="Batch Mode",
    ),
    max_stubs: int = typer.Option(
        0,
        "--max-stubs",
        help="--all: max functions to process (0=all)",
        rich_help_panel="Batch Mode",
    ),
    min_size: int = typer.Option(
        10,
        "--min-size",
        help="--all: min target size to attempt",
        rich_help_panel="Batch Mode",
    ),
    max_size: int = typer.Option(
        9999,
        "--max-size",
        help="--all: max target size to attempt",
        rich_help_panel="Batch Mode",
    ),
    filter_str: str = typer.Option(
        "",
        "--filter",
        help="--all: only process functions matching substring",
        rich_help_panel="Batch Mode",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview changes without writing",
        rich_help_panel="Batch Mode",
    ),
    timeout_min: int = typer.Option(
        30,
        "--timeout-min",
        help="--all: per-function GA timeout (minutes)",
        rich_help_panel="Batch Mode",
    ),
    ga_history: bool = typer.Option(
        False,
        "--ga-history",
        help="Show GA run history summary (from .rebrew/ga_runs.jsonl)",
        rich_help_panel="Batch Mode",
    ),
    seed_from_solved: bool = typer.Option(
        True,
        "--seed-solved/--no-seed-solved",
        help="Seed GA population from similar solved functions",
        rich_help_panel="Batch Mode",
    ),
    collect_pairs: str | None = typer.Option(
        None,
        "--collect-pairs",
        help="Save source-binary pairs to JSONL file for ML training",
        rich_help_panel="Batch Mode",
    ),
    watch: bool = typer.Option(
        False, "--watch", help="Watch the seed source and re-run the GA on every change"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """GA matching engine — single file or batch (--all)."""
    cfg = require_config(target=target, json_mode=json_output)

    if ga_history:
        _show_ga_history(cfg, json_output, target=getattr(cfg, "target_name", ""))
        return

    if jobs is None:
        jobs = int(getattr(cfg, "default_jobs", 4))

    # Validate --tier up front: generate_flag_combinations raises a bare
    # ValueError that would otherwise escape as a traceback mid-sweep.
    # Checked unconditionally — `rebrew match f.c --tier nonsense` silently
    # succeeded before (tier is only consulted in sweep paths, so the typo
    # went unnoticed instead of erroring at invocation time).
    from rebrew.matcher import MSVC_SWEEP_TIERS

    if tier not in MSVC_SWEEP_TIERS:
        error_exit(
            f"Unknown sweep tier {tier!r}, valid: {', '.join(MSVC_SWEEP_TIERS)}",
            json_mode=json_output,
            code=EXIT_ERROR,
        )

    if watch and all_mode:
        error_exit("--watch cannot be combined with --all", json_mode=json_output)
    if all_targets and all_mode:
        error_exit("--all-targets cannot be combined with --all", json_mode=json_output)
    if watch and all_targets:
        error_exit("--watch cannot be combined with --all-targets", json_mode=json_output)
    if (all_mode or all_targets) and out_dir != "output/ga_runs":
        # Batch mode hardcodes cfg.root/output/ga_runs — reject a silent no-op.
        error_exit("--out-dir only applies to single-function mode", json_mode=json_output)

    # --mutation-focus in batch mode applies one explicit category to every
    # stub ("auto" is per-function — the BLOCKER lives in the stub's metadata).
    if mutation_focus == "auto" and (all_mode or all_targets):
        error_exit(
            "--mutation-focus auto is single-function only (the BLOCKER is "
            "per-function); pass an explicit category in batch mode "
            "(register | equivalent | structural)",
            json_mode=json_output,
        )
    batch_mutation_weights = (
        _mutation_focus_weights(mutation_focus) if (all_mode or all_targets) else None
    )
    if (
        batch_mutation_weights is None
        and mutation_focus
        and (all_mode or all_targets)
        and not json_output
    ):
        console.print(
            f"[yellow]warning:[/yellow] --mutation-focus {mutation_focus} has "
            "no suggested operators — sampling mutations uniformly"
        )

    if all_mode:
        matched, failed = _run_all(
            cfg=cfg,
            jobs=jobs,
            generations=generations,
            pop_size=pop_size,
            timeout_min=timeout_min,
            dry_run=dry_run,
            min_size=min_size,
            max_size=max_size,
            filter_str=filter_str,
            near_miss=near_miss,
            improve=improve,
            size_mismatch=size_mismatch,
            threshold=threshold,
            flag_sweep=flag_sweep,
            fix_cflags=fix_cflags,
            max_stubs=max_stubs,
            seed_from_solved=seed_from_solved,
            json_output=json_output,
            tier=tier,
            flag_sweep_then_ga=flag_sweep_then_ga,
            skip_recent_hours=skip_recent_hours,
            seed=seed,
            seed_solutions_path=seed_solutions,
            resume=resume,
            mutation_weights=batch_mutation_weights,
            collect_pairs=collect_pairs,
        )
        # Documented exit contract (epilog): 1 = no match found.  A batch
        # with any failed stub is not a success for CI gates — mirror
        # `rebrew test --all`'s failed>0 → EXIT_MISMATCH.
        if failed > 0 and not dry_run:
            raise typer.Exit(code=EXIT_MISMATCH)
        return

    if all_targets:
        from rebrew.config import load_config

        names = list(getattr(cfg, "all_targets", []) or [])
        if not names:
            names = [getattr(cfg, "target_name", "main")]
        total_matched = 0
        total_failed = 0

        def _run_target(name: str) -> tuple[int, int]:
            # One broken target (unresolvable config, unexpected error) must
            # not discard the other targets' completed GA runs: in parallel
            # mode every future has already been submitted, so letting the
            # exception escape would drop results of targets that ran to
            # completion after it.  Count the failure and keep aggregating
            # (same contract as _run_stub: failed>0 → EXIT_MISMATCH).
            try:
                target_cfg = load_config(cfg.root, target=name) if len(names) > 1 else cfg
                if not json_output:
                    console.print(f"\n[bold cyan]=== Target {name} ===[/]")
                # Per-target detail stays on stderr (console); stdout gets one
                # aggregate JSON document when --json is active.
                return _run_all(
                    cfg=target_cfg,
                    jobs=per_target_jobs,
                    generations=generations,
                    pop_size=pop_size,
                    timeout_min=timeout_min,
                    dry_run=dry_run,
                    min_size=min_size,
                    max_size=max_size,
                    filter_str=filter_str,
                    near_miss=near_miss,
                    improve=improve,
                    size_mismatch=size_mismatch,
                    threshold=threshold,
                    flag_sweep=flag_sweep,
                    fix_cflags=fix_cflags,
                    max_stubs=max_stubs,
                    seed_from_solved=seed_from_solved,
                    json_output=False,
                    tier=tier,
                    flag_sweep_then_ga=flag_sweep_then_ga,
                    skip_recent_hours=skip_recent_hours,
                    seed=seed,
                    seed_solutions_path=seed_solutions,
                    resume=resume,
                    mutation_weights=batch_mutation_weights,
                    collect_pairs=collect_pairs,
                )
            except Exception as exc:
                log.warning("Target %s failed — counted as failed", name, exc_info=True)
                console.print(
                    f"  [yellow]warning:[/yellow] target {name} failed: {type(exc).__name__}: {exc}"
                )
                return 0, 1

        # Parallel targets: split --jobs across targets so total wine
        # concurrency stays bounded (~jobs).  Determinism is preserved — the
        # GA is seeded per-stub from (--seed, va), and the metadata/solutions
        # locks serialize cross-target writes.  Falls back to serial when
        # jobs cannot be shared or there is a single target.
        parallel = len(names) > 1 and jobs > 1
        per_target_jobs = max(1, jobs // len(names)) if parallel else jobs
        if parallel:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=len(names)) as executor:
                for m, f in executor.map(_run_target, names):  # order preserved
                    total_matched += m
                    total_failed += f
        else:
            for name in names:
                m, f = _run_target(name)
                total_matched += m
                total_failed += f
        if json_output:
            json_print(
                {
                    "mode": "all-targets",
                    "targets": names,
                    "matched": total_matched,
                    "failed": total_failed,
                    "total": total_matched + total_failed,
                }
            )
        else:
            console.print(
                f"\n[bold]All targets: {total_matched} matched, {total_failed} failed "
                f"across {len(names)} target(s)[/]"
            )
        # Same exit contract as --all: 1 = no match found (any failed stub).
        if total_failed > 0 and not dry_run:
            raise typer.Exit(code=EXIT_MISMATCH)
        return

    # Single-function mode requires seed_c
    if seed_c is None:
        error_exit(
            "Provide a source file (rebrew match <file.c>) or use --all for batch mode.",
            json_mode=json_output,
        )

    if dry_run and not llm_seed:
        error_exit(
            "--dry-run is batch mode only — 'rebrew match --all --dry-run' lists "
            "candidates without running. Single-function match always runs the GA.",
            json_mode=json_output,
            code=EXIT_ERROR,
        )

    # Accept a hex VA or symbol name in addition to a .c path, like
    # `rebrew diff`/`rebrew prove` (resolve_source_arg returns the argument
    # unchanged when nothing matches, so the original error path is kept).
    va_arg = seed_c.strip().lower().startswith("0x")
    seed_c_orig = seed_c
    seed_c = str(resolve_source_arg(cfg, seed_c))

    # A bare-VA positional must target THAT annotation in a multi-function
    # file — thread it through so resolve_build_params does not fall back to
    # the first annotation (wrong function).
    if va_arg and target_va is None:
        target_va = seed_c_orig

    params = resolve_build_params(
        cfg, seed_c, cl, inc, cflags, symbol, target_va, target_size, ignore_lint, json_output
    )

    # --mutation-focus: bias GA mutation selection toward a near-diag category.
    # "auto" reads the function's BLOCKER metadata (written by
    # near-diag --fix-blocker) to derive the category; with no verdict blocker
    # it falls back to classifying the CURRENT implementation live (see
    # _live_mutation_weights).
    mutation_weights: dict[str, float] | None = None
    if mutation_focus:
        blocker_text = ""
        if mutation_focus == "auto":
            from rebrew.metadata import load_metadata

            for (_module, va), entry in load_metadata(cfg.metadata_dir).items():
                if va == params.va_int and entry.get("blocker"):
                    blocker_text = entry["blocker"]
                    break
        mutation_weights = _mutation_focus_weights(mutation_focus, blocker_text)
        if mutation_weights is None and mutation_focus == "auto" and not blocker_text:
            mutation_weights = _live_mutation_weights(params)
        if mutation_weights and not json_output:
            console.print(
                f"[dim]mutation focus:[/dim] {len(mutation_weights)} operator(s) "
                f"weighted {_MUTATION_FOCUS_WEIGHT}x"
            )
        elif mutation_weights is None and not json_output:
            # An explicit focus that yields no operators (e.g. "reloc" — its
            # delta is relocation-masked) must not silently no-op.
            console.print(
                f"[yellow]warning:[/yellow] --mutation-focus {mutation_focus} has "
                "no suggested operators — sampling mutations uniformly"
            )

    if watch:
        from rebrew.utils import watch_files

        seed_path = Path(seed_c).resolve()

        def _retest() -> None:
            # Re-run the full single-function match path; --watch must not nest.
            main(
                seed_c=seed_c,
                cl=cl,
                inc=inc,
                cflags=cflags,
                symbol=symbol,
                target_va=target_va,
                target_size=target_size,
                out_dir=out_dir,
                compare_obj=compare_obj,
                lib=lib,
                link=link,
                ldflags=ldflags,
                flag_sweep_only=flag_sweep_only,
                tier=tier,
                flag_sweep_toolchains=flag_sweep_toolchains,
                flag_sweep_then_ga=flag_sweep_then_ga,
                skip_recent_hours=skip_recent_hours,
                seed_solutions=seed_solutions,
                llm_seed=llm_seed,
                kuna_seed=kuna_seed,
                resume=resume,
                ignore_lint=ignore_lint,
                seed=seed,
                extra_seed=extra_seed,
                no_seed=no_seed,
                generations=generations,
                pop_size=pop_size,
                jobs=jobs,
                all_mode=False,
                all_targets=False,  # never nest multi-target batch in watch mode
                near_miss=near_miss,
                improve=improve,
                size_mismatch=size_mismatch,
                threshold=threshold,
                flag_sweep=flag_sweep,
                fix_cflags=fix_cflags,
                max_stubs=max_stubs,
                min_size=min_size,
                max_size=max_size,
                filter_str=filter_str,
                dry_run=dry_run,
                timeout_min=timeout_min,
                ga_history=False,
                seed_from_solved=seed_from_solved,
                collect_pairs=collect_pairs,
                watch=False,
                json_output=json_output,
                target=target,
            )

        watch_files([seed_path], _retest)
        return

    if flag_sweep_only and flag_sweep_toolchains:
        # Both dimensions at once: flag-sweep with each vendored MSVC version.
        _run_single_toolchain_flag_sweep(
            params, tier, jobs, json_output, sweep_toolchains, sweep_exclude_toolchains
        )
        return

    if flag_sweep_only:
        _run_single_flag_sweep(params, tier, jobs, json_output)
        return

    if flag_sweep_toolchains:
        _run_single_toolchain_sweep(params, json_output, sweep_toolchains, sweep_exclude_toolchains)
        return

    _run_single_ga(
        params,
        out_dir,
        generations,
        pop_size,
        jobs,
        compare_obj,
        lib,
        ldflags,
        seed,
        json_output,
        extra_seed,
        no_seed,
        collect_pairs,
        llm_seed=llm_seed,
        kuna_seed=kuna_seed,
        dry_run=dry_run,
        mutation_weights=mutation_weights,
        link=link,
    )


# ---------------------------------------------------------------------------
# Build parameter resolution
# ---------------------------------------------------------------------------


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
