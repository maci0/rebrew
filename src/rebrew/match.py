"""Genetic Algorithm engine for binary matching — single-function and batch modes.

Compile C source, compare object bytes against a target function, and
iteratively mutate to find a byte-perfect or relocation-normalized match.

Single-function usage:
    rebrew match run <source.c> [--generations N --pop-size N]
    rebrew match flags <source.c>

Batch usage (``rebrew match batch``)::
    rebrew match batch Run GA on all STUB functions
    rebrew match batch --improve GA on all NEAR_MATCHING functions
    rebrew match batch --near-miss Near-miss NEAR_MATCHING functions
    rebrew match batch Batch flag sweep on NEAR_MATCHING --algorithm flags
    rebrew match batch --dry-run List targets without running
"""

from __future__ import annotations

import logging
lazy import functools
lazy from pathlib import Path
lazy from typing import Literal

import typer
from typer.models import TyperPath

from rebrew.cli import (
    CFLAGS_HELP,
    EXIT_ERROR,
    EXIT_MISMATCH,
    JOBS_HELP,
    SIZE_HELP,
    SOURCE_HELP,
    TIER_HELP,
    WATCH_FILE_HELP,
    AllTargetsOption,
    TargetOption,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
    resolve_source_arg,
)
from rebrew.limits import NO_MAX_SIZE
lazy from rebrew.match_ga import (
    MUTATION_FOCUS_WEIGHT,
    live_mutation_weights,
    mutation_focus_weights,
)
lazy from rebrew.match_run import (
    run_all,
    run_single_ga,
    show_ga_history,
)
lazy from rebrew.match_sweep import (
    resolve_build_params,
    run_single_flag_sweep,
    run_single_toolchain_flag_sweep,
    run_single_toolchain_sweep,
)
lazy from rebrew.utils import interruptible_pool, preset_module_key, untrusted_ident

log = logging.getLogger(__name__)


# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew match run src/f.c\n\n"
    "  rebrew match batch --dry-run\n\n"
    "  rebrew match batch --improve\n\n"
    "  rebrew match flags src/f.c\n\n"
    "  rebrew match toolchains src/f.c\n\n"
    "[dim]run searches source mutations; flags searches compiler options; toolchains compares compiler profiles. batch selects project functions and can use --algorithm flags. Identity, size, and flags resolve from the C definition and dedicated metadata/configuration. Searches compile with the configured toolchain.[/dim]\n\n"
    "Exit codes: 0 success; 1 search found no match where applicable; "
    "2 usage/config/build error; 130 interrupted; 141 output pipe closed.\n\n"
)

app = typer.Typer(
    help="Search source mutations, compiler flags, and toolchains for byte matches.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def execute_search(
    seed_c: str | None = None,
    cl: str | None = None,
    inc: str | None = None,
    cflags: str | None = None,
    symbol: str | None = None,
    target_va: str | None = None,
    target_size: int | None = None,
    out_dir: str = "output/ga_runs",
    compare_obj: bool = True,
    lib: str | None = None,
    link: str | None = None,
    ldflags: str | None = None,
    flag_sweep_only: bool = False,
    tier: str = "targeted",
    ignore_lint: bool = False,
    seed: int | None = None,
    extra_seed: list[str] | None = None,
    no_seed: bool = False,
    mutation_focus: str | None = None,
    generations: int = 100,
    pop_size: int = 64,
    jobs: int | None = None,
    all_mode: bool = False,
    all_targets: bool = False,
    flag_sweep_toolchains: bool = False,
    sweep_toolchains: str = "",
    sweep_exclude_toolchains: str = "",
    flag_sweep_then_ga: bool = False,
    skip_recent_hours: int = 0,
    seed_solutions: Path | None = None,
    llm_seed: bool = False,
    kuna_seed: bool = False,
    resume: bool = False,
    near_miss: bool = False,
    improve: bool = False,
    size_mismatch: bool = False,
    threshold: int = 10,
    flag_sweep: bool = False,
    fix_cflags: bool = False,
    max_stubs: int = 0,
    min_size: int = 10,
    max_size: int = NO_MAX_SIZE,
    filter_str: str = "",
    timeout_min: int = 30,
    ga_history: bool = False,
    seed_from_solved: bool = True,
    collect_pairs: str | None = None,
    watch: bool = False,
    dry_run: bool = False,
    json_output: bool = False,
    target: str | None = None,
) -> None:
    """Search source mutations, compiler flags, and toolchains for byte matches."""
    if option_default(watch, False) and option_default(json_output, False):
        error_exit("--watch is terminal-only; omit --json", json_mode=True)
    all_targets = option_default(all_targets, False)
    all_mode = option_default(all_mode, False)
    watch = option_default(watch, False)
    dry_run = option_default(dry_run, False)
    json_output = option_default(json_output, False)
    ga_history = option_default(ga_history, False)

    if all_targets and target is not None:
        error_exit(
            "--all-targets and --target are mutually exclusive — pick one target or sweep them all",
            json_mode=json_output,
        )

    cfg = require_config(target=target, json_mode=json_output)

    if ga_history:
        show_ga_history(cfg, json_output, target=getattr(cfg, "target_name", ""))
        return

    if jobs is None:
        jobs = int(getattr(cfg, "default_jobs", 4))
    # The -j flag bypasses config's _positive_int validation, so `-j 0` (or a
    # negative) reached ThreadPoolExecutor(max_workers=...) verbatim and raised
    # ValueError. Clamp once here: every pool this command drives (the GA, the
    # flag sweep, the per-stub batch, --all-targets) inherits the bound.
    jobs = max(1, jobs)

    # Validate --tier up front: generate_flag_combinations raises a bare
    # ValueError that would otherwise escape as a traceback mid-sweep.
    # Checked unconditionally — `rebrew match run f.c --tier nonsense` silently
    # succeeded before (tier is only consulted in sweep paths, so the typo
    # went unnoticed instead of erroring at invocation time).
    from rebrew.flag_data import MSVC_SWEEP_TIERS

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
        error_exit("--output only applies to single-function mode", json_mode=json_output)
    if llm_seed and (all_mode or all_targets):
        # Batch mode seeds from the run log and extra files only, so the flag
        # would be dropped without a word.  An operator who asked for a paid
        # LLM call and got a silent no-op has no way to tell the two apart from
        # "the endpoint returned nothing usable".
        error_exit(
            "--seed-llm is single-function only; use rebrew match run for one target",
            json_mode=json_output,
        )

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
        mutation_focus_weights(mutation_focus) if (all_mode or all_targets) else None
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

    # Batch knobs shared by --all and --all-targets; callers supply cfg, jobs, json_output.
    run_all_batch = functools.partial(
        run_all,
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
        tier=tier,
        flag_sweep_then_ga=flag_sweep_then_ga,
        skip_recent_hours=skip_recent_hours,
        seed=seed,
        seed_solutions_path=seed_solutions,
        resume=resume,
        mutation_weights=batch_mutation_weights,
        collect_pairs=collect_pairs,
    )

    if all_mode:
        matched, failed = run_all_batch(cfg=cfg, jobs=jobs, json_output=json_output)
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

        def _run_target(name: str) -> tuple[int, int, bool]:
            # One broken target (unresolvable config, compiler exception) must
            # not discard the other targets' completed runs. The exception is
            # an infrastructure failure, not a mismatch count.
            try:
                target_cfg = load_config(cfg.root, target=name) if len(names) > 1 else cfg
                if not json_output:
                    console.print(f"\n[bold cyan]=== Target {untrusted_ident(name)} ===[/]")
                # Per-target detail stays on stderr (console); stdout gets one
                # aggregate JSON document when --json is active.
                matched, failed = run_all_batch(
                    cfg=target_cfg, jobs=per_target_jobs, json_output=False
                )
                return matched, failed, False
            except typer.Exit:
                raise
            except Exception as exc:
                log.warning("Target %s failed", name, exc_info=True)
                console.print(
                    f"  [yellow]warning:[/yellow] target {untrusted_ident(name)} failed: "
                    f"{type(exc).__name__}: {exc}"
                )
                return 0, 0, True

        # Parallel targets: split --jobs across targets so total wine
        # concurrency stays bounded (~jobs).  Cap concurrent targets at
        # *jobs* — when len(names) > jobs, ``jobs // len(names)`` underflows
        # to 0→1 and ``max_workers=len(names)`` would run every target at
        # once (one wine/docker compile each).  Determinism is preserved —
        # the GA is seeded per-stub from (--seed, va), and the
        # metadata/solutions locks serialize cross-target writes.  Falls
        # back to serial when jobs cannot be shared or there is a single
        # target.
        parallel = len(names) > 1 and jobs > 1
        n_parallel = min(len(names), jobs) if parallel else 1
        per_target_jobs = max(1, jobs // n_parallel) if parallel else jobs
        infra_errors = 0
        if parallel:
            with interruptible_pool(n_parallel) as executor:
                for m, f, infra in executor.map(_run_target, names):  # order preserved
                    total_matched += m
                    total_failed += f
                    if infra:
                        infra_errors += 1
        else:
            for name in names:
                m, f, infra = _run_target(name)
                total_matched += m
                total_failed += f
                if infra:
                    infra_errors += 1
        if json_output:
            json_print(
                {
                    "mode": "all-targets",
                    "targets": names,
                    "matched": total_matched,
                    "failed": total_failed,
                    "errors": infra_errors,
                    "total": total_matched + total_failed,
                }
            )
        else:
            console.print(
                f"\n[bold]All targets: {total_matched} matched, {total_failed} failed "
                f"across {len(names)} target(s)[/]"
            )
        # A compiler or config exception is infrastructure, including previews.
        # Mismatch counts stay exit 1, and a dry run does not hide them as success
        # when the run itself failed to start.
        if infra_errors:
            raise typer.Exit(code=EXIT_ERROR)
        # Same exit contract as Batch: 1 = no match found (any failed stub).
        if total_failed > 0 and not dry_run:
            raise typer.Exit(code=EXIT_MISMATCH)
        return

    # Single-function mode requires seed_c
    if seed_c is None:
        error_exit(
            "Provide a source file, symbol, or VA; use rebrew match batch for project selection.",
            json_mode=json_output,
        )

    if dry_run and not llm_seed:
        error_exit(
            "--dry-run requires --seed-llm; use rebrew match batch --dry-run to list candidates.",
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

    if not va_arg and symbol is None and not Path(seed_c_orig).exists():
        symbol = seed_c_orig

    params = resolve_build_params(
        cfg, seed_c, cl, inc, cflags, symbol, target_va, target_size, ignore_lint, json_output
    )

    # --mutation-focus: bias GA mutation selection toward a near-diag category.
    # "auto" reads the function's BLOCKER metadata (written by
    # near-diag --fix-blocker) to derive the category; with no verdict blocker
    # it falls back to classifying the CURRENT implementation live (see
    # live_mutation_weights).
    mutation_weights: dict[str, float] | None = None
    if mutation_focus:
        blocker_text = ""
        if mutation_focus == "auto":
            from rebrew.metadata.functions import load_metadata

            # Metadata keys are qualified (module, va); VA-only lookup picks
            # the first hit and can weight mutations from a sibling target
            # that shares the address (SERVER vs CLIENT at the same VA).
            want_module = preset_module_key(params.module or "")
            for (_module, va), entry in load_metadata(cfg.metadata_dir, deepcopy=False).items():
                if va != params.va_int or not entry.get("blocker"):
                    continue
                if want_module and preset_module_key(_module) != want_module:
                    continue
                blocker_text = entry["blocker"]
                break
        mutation_weights = mutation_focus_weights(mutation_focus, blocker_text)
        if mutation_weights is None and mutation_focus == "auto" and not blocker_text:
            mutation_weights = live_mutation_weights(params)
        if mutation_weights and not json_output:
            console.print(
                f"[dim]mutation focus:[/dim] {len(mutation_weights)} operator(s) "
                f"weighted {MUTATION_FOCUS_WEIGHT}x"
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
            # Forward every CLI param — an omitted one leaks as a truthy
            # OptionInfo on direct main() re-entry (see docs/DEVELOPMENT.md).
            execute_search(
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
                sweep_toolchains=sweep_toolchains,
                sweep_exclude_toolchains=sweep_exclude_toolchains,
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
                mutation_focus=mutation_focus,
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
        run_single_toolchain_flag_sweep(
            params, tier, jobs, json_output, sweep_toolchains, sweep_exclude_toolchains
        )
        return

    if flag_sweep_only:
        run_single_flag_sweep(params, tier, jobs, json_output, timeout_min=timeout_min)
        return

    # `--toolchains` / `--exclude-toolchains` name the profiles to
    # sweep and to skip, so naming one IS the opt-in: each selects the sweep
    # exactly as `--flag-sweep-toolchains` does, just filtered.  Both were
    # checked only alongside that unrelated flag, so
    # `rebrew match toolchains f.c --toolchains msvc-6.0` parsed, filtered nothing and ran
    # the plain GA — a silently ignored filter, on the long spelling every
    # other command uses to pin a compiler.
    if flag_sweep_toolchains or sweep_toolchains or sweep_exclude_toolchains:
        run_single_toolchain_sweep(params, json_output, sweep_toolchains, sweep_exclude_toolchains)
        return

    run_single_ga(
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


@app.command(
    "run",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew match run src/game/f.c --seed 7 --json\n\n"
        "Searches compile with the configured toolchain. --seed-llm --dry-run previews the seed request."
    ),
)
def run(
    seed_c: str | None = typer.Argument(..., metavar="source", help=SOURCE_HELP),
    cl: str | None = typer.Option(
        None,
        help="Compiler command override (default: project config)",
        rich_help_panel="Build inputs",
    ),
    inc: str | None = typer.Option(
        None,
        help="Include dir (auto from project config)",
        rich_help_panel="Build inputs",
        click_type=TyperPath(path_type=str),
    ),
    cflags: str | None = typer.Option(
        None,
        help=CFLAGS_HELP,
        rich_help_panel="Build inputs",
    ),
    symbol: str | None = typer.Option(
        None,
        "--symbol",
        help="Symbol to match (default: C definition or metadata)",
        rich_help_panel="Build inputs",
    ),
    target_va: str | None = typer.Option(
        None,
        "--va",
        help="Target VA in hex (default: from metadata)",
        rich_help_panel="Build inputs",
    ),
    target_size: int | None = typer.Option(
        None, "--size", help=SIZE_HELP, rich_help_panel="Build inputs"
    ),
    out_dir: str = typer.Option(
        "output/ga_runs",
        "--output",
        "-o",
        help="Directory for search results",
        rich_help_panel="Output options",
        click_type=TyperPath(path_type=str),
    ),
    compare_obj: bool = typer.Option(
        True, help="Use object comparison instead of full link", rich_help_panel="Build inputs"
    ),
    lib: str | None = typer.Option(
        None,
        "--lib",
        help="Lib dir",
        rich_help_panel="Build inputs",
        click_type=TyperPath(path_type=str),
    ),
    link: str | None = typer.Option(
        None,
        "--link",
        help="Linker command (auto from project config)",
        rich_help_panel="Build inputs",
    ),
    ldflags: str | None = typer.Option(None, help="Linker flags", rich_help_panel="Build inputs"),
    jobs: int | None = typer.Option(
        None,
        "--jobs",
        "-j",
        help=JOBS_HELP,
        rich_help_panel="GA Tuning",
    ),
    ignore_lint: bool = typer.Option(
        False,
        "--ignore-lint",
        help="Continue even if source binding lint errors exist",
        rich_help_panel="Build inputs",
    ),
    seed: int | None = typer.Option(
        None, "--seed", help="RNG seed for reproducible GA runs", rich_help_panel="GA Tuning"
    ),
    extra_seed: list[str] | None = typer.Option(
        None,
        "--seed-file",
        help="Extra .c file(s) to seed GA population from solved functions. Ignored if --no-seeds is also passed",
        rich_help_panel="Seeding",
        click_type=TyperPath(path_type=str),
    ),
    no_seed: bool = typer.Option(
        False,
        "--no-seeds",
        help="Disable cross-function solution seeding (takes precedence over --seed-file)",
        rich_help_panel="Seeding",
    ),
    mutation_focus: Literal["auto", "register", "equivalent", "structural"] | None = typer.Option(
        None,
        "--mutation-focus",
        help=(
            "Bias GA mutation selection toward a near-diag category: register | equivalent | structural, or auto (read the function's BLOCKER metadata). Suggested operators get 6x selection weight"
        ),
        rich_help_panel="GA Tuning",
        metavar="FOCUS",
    ),
    generations: int = typer.Option(
        100, "--generations", "-g", help="Number of GA generations", rich_help_panel="GA Tuning"
    ),
    pop_size: int = typer.Option(
        64, "--pop-size", "-p", help="Population size per generation", rich_help_panel="GA Tuning"
    ),
    llm_seed: bool = typer.Option(
        False,
        "--seed-llm",
        help=("Seed one function from the configured LLM endpoint; required with --dry-run"),
        rich_help_panel="Seeding",
    ),
    kuna_seed: bool = typer.Option(
        False,
        "--seed-kuna",
        help=(
            "Seed the GA's initial population with Kuna's decompilation of the target function (github.com/Noelo-Lab/kuna, requires the `kuna` binary on PATH). The output is compilability-fixed (rebrew source fix) before injection"
        ),
        rich_help_panel="Seeding",
    ),
    collect_pairs: str | None = typer.Option(
        None,
        "--collect-pairs",
        help="Append source/binary training pairs to a JSONL file",
        rich_help_panel="Output options",
        click_type=TyperPath(path_type=str),
    ),
    watch: bool = typer.Option(
        False,
        "--watch",
        help=WATCH_FILE_HELP,
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Run genetic matching for one source function."""
    execute_search(
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
        jobs=jobs,
        ignore_lint=ignore_lint,
        seed=seed,
        extra_seed=extra_seed,
        no_seed=no_seed,
        mutation_focus=mutation_focus,
        generations=generations,
        pop_size=pop_size,
        llm_seed=llm_seed,
        kuna_seed=kuna_seed,
        collect_pairs=collect_pairs,
        watch=watch,
        dry_run=dry_run,
        json_output=json_output,
        target=target,
    )


@app.command(
    "batch",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew match batch --dry-run --json\n\n"
        "--dry-run lists selected functions without compiling or writing."
    ),
)
def batch(
    algorithm: Literal["ga", "flags", "flags-then-ga"] = typer.Option(
        "ga", "--algorithm", help="Search: ga, flags, flags-then-ga", metavar="ALGORITHM"
    ),
    tier: Literal["quick", "targeted", "normal", "thorough", "full"] = typer.Option(
        "targeted",
        "--tier",
        help=TIER_HELP,
        rich_help_panel="Search",
        metavar="TIER",
    ),
    seed: int | None = typer.Option(
        None, "--seed", help="RNG seed for reproducible GA runs", rich_help_panel="GA Tuning"
    ),
    mutation_focus: Literal["register", "equivalent", "structural"] | None = typer.Option(
        None,
        "--mutation-focus",
        help=(
            "Bias every selected function toward register, equivalent, or structural mutations. Suggested operators get 6x selection weight"
        ),
        rich_help_panel="GA Tuning",
        metavar="FOCUS",
    ),
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
        help=JOBS_HELP,
        rich_help_panel="GA Tuning",
    ),
    skip_recent_hours: int = typer.Option(
        0,
        "--skip-recent",
        help="Skip stubs with a GA run record within the last N hours",
        rich_help_panel="Selection",
    ),
    seed_solutions: Path | None = typer.Option(
        None,
        "--seed-solutions-file",
        help="Additional GA run log for cross-project seeds (e.g. runs.jsonl)",
        rich_help_panel="Saved runs",
    ),
    resume: bool = typer.Option(
        False,
        "--resume",
        help="Resume interrupted GA runs from their per-function checkpoints",
        rich_help_panel="Saved runs",
    ),
    near_miss: bool = typer.Option(
        False,
        "--near-miss",
        help="Target NEAR_MATCHING near-misses instead of STUBs",
        rich_help_panel="Selection",
    ),
    improve: bool = typer.Option(
        False,
        "--improve",
        help="Target all NEAR_MATCHING functions (no delta threshold)",
        rich_help_panel="Selection",
    ),
    size_mismatch: bool = typer.Option(
        False,
        "--size-mismatch",
        help="Target SIZE_MISMATCH functions (length differs) with the GA",
        rich_help_panel="Selection",
    ),
    threshold: int = typer.Option(
        10,
        "--threshold",
        help="Max byte delta for --near-miss mode",
        rich_help_panel="Selection",
    ),
    fix_cflags: bool = typer.Option(
        False,
        "--fix-cflags",
        help="With --algorithm flags: auto-update CFLAGS metadata on exact match",
        rich_help_panel="Selection",
    ),
    max_stubs: int = typer.Option(
        0,
        "--max-stubs",
        help="Maximum functions to process (0 means all)",
        min=0,
        rich_help_panel="Selection",
    ),
    min_size: int = typer.Option(
        10,
        "--min-size",
        help="Min target size to attempt",
        rich_help_panel="Selection",
    ),
    max_size: int = typer.Option(
        NO_MAX_SIZE,
        "--max-size",
        help="Max target size to attempt",
        rich_help_panel="Selection",
    ),
    filter_str: str = typer.Option(
        "",
        "--filter",
        help="Only process functions matching substring",
        rich_help_panel="Selection",
    ),
    timeout_min: int = typer.Option(
        30,
        "--timeout-min",
        help="Per-function GA timeout (minutes)",
        rich_help_panel="Selection",
    ),
    seed_from_solved: bool = typer.Option(
        True,
        "--seed-solved/--no-seed-solved",
        help="Seed GA population from similar solved functions",
        rich_help_panel="Seeding",
    ),
    collect_pairs: str | None = typer.Option(
        None,
        "--collect-pairs",
        help="Append source/binary training pairs to a JSONL file",
        rich_help_panel="Output options",
        click_type=TyperPath(path_type=str),
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
) -> None:
    """Run matching over selected project functions."""
    if algorithm not in ("ga", "flags", "flags-then-ga"):
        error_exit("--algorithm must be ga, flags or flags-then-ga", json_mode=json_output)
    execute_search(
        tier=tier,
        seed=seed,
        mutation_focus=mutation_focus,
        generations=generations,
        pop_size=pop_size,
        jobs=jobs,
        skip_recent_hours=skip_recent_hours,
        seed_solutions=seed_solutions,
        resume=resume,
        near_miss=near_miss,
        improve=improve,
        size_mismatch=size_mismatch,
        threshold=threshold,
        flag_sweep=algorithm == "flags",
        flag_sweep_then_ga=algorithm == "flags-then-ga",
        fix_cflags=fix_cflags,
        max_stubs=max_stubs,
        min_size=min_size,
        max_size=max_size,
        filter_str=filter_str,
        timeout_min=timeout_min,
        seed_from_solved=seed_from_solved,
        collect_pairs=collect_pairs,
        dry_run=dry_run,
        json_output=json_output,
        target=target,
        all_targets=all_targets,
        all_mode=not all_targets,
    )


@app.command(
    "flags",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew match flags src/game/f.c --tier quick --json\n\n"
        "Compares compiler flag combinations using object bytes."
    ),
)
def flags(
    seed_c: str | None = typer.Argument(..., metavar="source", help=SOURCE_HELP),
    cl: str | None = typer.Option(
        None,
        help="Compiler command override (default: project config)",
        rich_help_panel="Build inputs",
    ),
    inc: str | None = typer.Option(
        None,
        help="Include dir (auto from project config)",
        rich_help_panel="Build inputs",
        click_type=TyperPath(path_type=str),
    ),
    cflags: str | None = typer.Option(
        None,
        help=CFLAGS_HELP,
        rich_help_panel="Build inputs",
    ),
    symbol: str | None = typer.Option(
        None,
        "--symbol",
        help="Symbol to match (default: C definition or metadata)",
        rich_help_panel="Build inputs",
    ),
    target_va: str | None = typer.Option(
        None,
        "--va",
        help="Target VA in hex (default: from metadata)",
        rich_help_panel="Build inputs",
    ),
    target_size: int | None = typer.Option(
        None, "--size", help=SIZE_HELP, rich_help_panel="Build inputs"
    ),
    jobs: int | None = typer.Option(
        None,
        "--jobs",
        "-j",
        help=JOBS_HELP,
        rich_help_panel="Search",
    ),
    tier: Literal["quick", "targeted", "normal", "thorough", "full"] = typer.Option(
        "targeted",
        "--tier",
        help=TIER_HELP,
        rich_help_panel="Search",
        metavar="TIER",
    ),
    ignore_lint: bool = typer.Option(
        False,
        "--ignore-lint",
        help="Continue even if source binding lint errors exist",
        rich_help_panel="Build inputs",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Search compiler flags for one source function."""
    execute_search(
        seed_c=seed_c,
        cl=cl,
        inc=inc,
        cflags=cflags,
        symbol=symbol,
        target_va=target_va,
        target_size=target_size,
        jobs=jobs,
        tier=tier,
        ignore_lint=ignore_lint,
        json_output=json_output,
        target=target,
        flag_sweep_only=True,
    )


@app.command(
    "toolchains",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew match toolchains src/game/f.c --toolchains msvc-6.0,msvc-7.0 --json\n\n"
        "Compares object bytes for each profile; --flags also searches compiler options."
    ),
)
def toolchains(
    seed_c: str | None = typer.Argument(..., metavar="source", help=SOURCE_HELP),
    cflags: str | None = typer.Option(
        None,
        help=CFLAGS_HELP,
        rich_help_panel="Build inputs",
    ),
    symbol: str | None = typer.Option(
        None,
        "--symbol",
        help="Symbol to match (default: C definition or metadata)",
        rich_help_panel="Build inputs",
    ),
    target_va: str | None = typer.Option(
        None,
        "--va",
        help="Target VA in hex (default: from metadata)",
        rich_help_panel="Build inputs",
    ),
    target_size: int | None = typer.Option(
        None, "--size", help=SIZE_HELP, rich_help_panel="Build inputs"
    ),
    jobs: int | None = typer.Option(
        None,
        "--jobs",
        "-j",
        help=f"{JOBS_HELP}. Requires --flags",
        rich_help_panel="Search",
    ),
    tier: Literal["quick", "targeted", "normal", "thorough", "full"] = typer.Option(
        "targeted",
        "--tier",
        help=f"{TIER_HELP}. Requires --flags",
        rich_help_panel="Search",
        metavar="TIER",
    ),
    with_flags: bool = typer.Option(
        False, "--flags", help="Search flags for each compiler profile"
    ),
    sweep_toolchains: str = typer.Option(
        "",
        "--toolchains",
        help="Comma-separated profiles or version prefixes to compare (e.g. msvc-6.0,7.0)",
        rich_help_panel="Search",
    ),
    sweep_exclude_toolchains: str = typer.Option(
        "",
        "--exclude-toolchains",
        help="Comma-separated profiles or version prefixes to exclude",
        rich_help_panel="Search",
    ),
    ignore_lint: bool = typer.Option(
        False,
        "--ignore-lint",
        help="Continue even if source binding lint errors exist",
        rich_help_panel="Build inputs",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compare compiler profiles, optionally searching flags per profile."""
    if jobs is not None and not with_flags:
        error_exit("--jobs requires --flags", json_mode=json_output)
    if tier != "targeted" and not with_flags:
        error_exit("--tier requires --flags", json_mode=json_output)
    execute_search(
        seed_c=seed_c,
        cflags=cflags,
        symbol=symbol,
        target_va=target_va,
        target_size=target_size,
        jobs=jobs,
        tier=tier,
        flag_sweep_toolchains=True,
        flag_sweep_only=with_flags,
        sweep_toolchains=sweep_toolchains,
        sweep_exclude_toolchains=sweep_exclude_toolchains,
        ignore_lint=ignore_lint,
        json_output=json_output,
        target=target,
    )


@app.command(
    "history",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew match history --json\n\n"
        "Reads saved GA results without compiling."
    ),
)
def history(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Show recorded GA run history without compiling."""
    execute_search(json_output=json_output, target=target, ga_history=True)


# ---------------------------------------------------------------------------
# Build parameter resolution
# ---------------------------------------------------------------------------


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
