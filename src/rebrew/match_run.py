"""match_run.py — the batch GA and flag-sweep run drivers.

Drives single-function and batch GA runs, solution persistence, the
recently-run filter, and the batch flag sweep.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi
from rebrew.binary_loader import capstone_mode_for_arch, extract_raw_bytes
from rebrew.cli import EXIT_MISMATCH, json_print
from rebrew.compile import resolve_compiler_env
from rebrew.config import ProjectConfig
from rebrew.match_batch import (
    StubInfo,
    find_all_matching,
    find_all_stubs,
    find_near_miss,
    find_size_mismatch,
    update_cflags_annotation,
    update_stub_to_matched,
)
from rebrew.match_ga import (
    _MUTATION_FOCUS_WEIGHT,
    BinaryMatchingGA,
    _ga_runs_dir,
    read_ga_checkpoint,
)
from rebrew.match_sweep import (
    _BuildParams,
    _compile_cflags,
    _select_annotation,
    run_flag_sweep,
)
from rebrew.matcher import GACheckpoint, SolutionEntry, load_ga_runs
from rebrew.utils import metadata_write_lock, read_source_text

log = logging.getLogger(__name__)
console = Console(stderr=True)


def _run_single_ga(
    p: _BuildParams,
    out_dir: str,
    generations: int,
    pop_size: int,
    jobs: int,
    compare_obj: bool,
    lib: str | None,
    ldflags: str | None,
    seed: int | None,
    json_output: bool,
    extra_seed: list[str] | None,
    no_seed: bool,
    collect_pairs: str | None = None,
    llm_seed: bool = False,
    kuna_seed: bool = False,
    dry_run: bool = False,
    mutation_weights: dict[str, float] | None = None,
    link: str | None = None,
) -> None:
    """Run the full GA matching engine for a single source file."""
    out_dir_path = Path(out_dir)
    if not out_dir_path.is_absolute():
        # Resolve relative to the project root, not the CWD — running
        # `rebrew match` from anywhere must write into the project's
        # output/ga_runs (consistent with the batch path).
        out_dir_path = getattr(p.cfg, "root", Path.cwd()) / out_dir_path
    out_dir_path.mkdir(parents=True, exist_ok=True)

    loaded_seeds: list[str] = []
    if not no_seed and extra_seed:
        for extra_path in extra_seed:
            ep = Path(extra_path)
            if ep.exists():
                text, _ = read_source_text(ep)
                loaded_seeds.append(text)

    # Optional LLM-assisted seeding: ask the configured endpoint for
    # alternative C implementations of the current source.  Off by default;
    # degrades to a warning when no endpoint is configured.
    if llm_seed and not no_seed:
        from rebrew.llm_seed import build_prompt, llm_config, request_seeds

        if llm_config(p.cfg) is None:
            console.print(
                "[yellow]warning:[/yellow] --llm-seed set but no LLM endpoint configured "
                "(set \\[llm] endpoint or REBREW_LLM_ENDPOINT) — running without LLM seeds"
            )
            # --dry-run promised "preview, no GA" — without an endpoint there
            # is nothing to preview and the GA must NOT run (it used to fall
            # through here and burn hours of Wine compiles despite --dry-run).
            if dry_run:
                console.print(
                    "\n[bold]Dry run:[/bold] --llm-seed with no LLM endpoint — "
                    "nothing to preview; skipping the GA run."
                )
                return
        else:
            llm_snippets = request_seeds(p.cfg, p.seed_src)
            if llm_snippets:
                console.print(
                    f"[dim]LLM seeding:[/dim] {len(llm_snippets)} valid alternative "
                    "implementation(s) added to the initial population"
                )
                loaded_seeds.extend(llm_snippets)
            if dry_run:
                # Preview the exact prompt + what would be seeded, no GA run.
                console.print("\n[bold]LLM seed prompt (dry-run):[/bold]\n")
                console.print(build_prompt(p.seed_src))
                console.print(
                    f"\n[dim]{len(llm_snippets)} validated seed(s) would be added "
                    "to the initial population.[/dim]"
                )
                return

    # Optional Kuna-assisted seeding: decompile the target function with the
    # Kuna decompiler (agent-first Ghidra port), fix it up so it compiles
    # (rebrew fix), and inject it into the GA's initial population.  Off by
    # default; degrades to a warning when kuna is unavailable.
    if kuna_seed and not no_seed:
        from rebrew.decompiler import kuna_seed_source

        kuna_snippet = kuna_seed_source(p.cfg.target_binary, p.va_int, p.cfg.root)
        if kuna_snippet is None:
            console.print(
                "[yellow]warning:[/yellow] --kuna-seed set but kuna produced no "
                "compilable C (install the kuna binary — "
                "github.com/Noelo-Lab/kuna); running without the kuna seed"
            )
            if dry_run:
                console.print(
                    "\n[bold]Dry run:[/bold] no kuna seed available — "
                    "nothing to preview; skipping the GA run."
                )
                return
        else:
            console.print("[dim]Kuna seeding:[/dim] decompilation added to the initial population")
            loaded_seeds.append(kuna_snippet)
        if dry_run:
            console.print("\n[bold]Kuna seed (dry-run):[/bold]\n")
            console.print(kuna_snippet)
            return

    ga = BinaryMatchingGA(
        p.seed_src,
        p.target_bytes,
        p.cl,
        p.inc,
        p.cflags,
        p.symbol,
        out_dir_path,
        pop_size=pop_size,
        num_generations=generations,
        num_jobs=jobs,
        compare_obj=compare_obj,
        lib_dir=lib,
        link_cmd=link,
        ldflags=ldflags,
        env=p.msvc_env,
        rng_seed=seed,
        compile_cache=p.cc,
        compile_timeout=p.cfg.compile_timeout,
        verbose=0 if json_output else 1,
        extra_seeds=loaded_seeds or None,
        collect_pairs_path=Path(collect_pairs) if collect_pairs else None,
        extra_include_dirs=[str(p.seed_c.parent.resolve())],
        posix_style=getattr(p.cfg, "posix_style", False),
        mutation_weights=mutation_weights,
        profile=getattr(p.cfg, "compiler_profile", ""),
        cs_mode=capstone_mode_for_arch(getattr(p.cfg, "arch", "")),
        cfg=p.cfg,
    )
    ceiling_blocker: str | None = None
    try:
        best_src, best_score = ga.run()
        # GA exhausted without a match: if the champion's residual delta is
        # register-only (effective match), document the ceiling (needs the
        # warm build cache, so run before ga.close()).
        if best_src is not None and best_score >= 0.1:
            try:
                annos = parse_c_file_multi(p.seed_c, metadata_dir=p.cfg.metadata_dir)
            except Exception:
                annos = []
            ann = _select_annotation(annos, p.symbol) or (annos[0] if annos else None)
            module = ann.module if ann is not None else ""
            if module:
                ceiling_blocker = _maybe_document_ga_ceiling(
                    p.cfg,
                    module,
                    p.va_int,
                    p.target_bytes,
                    ga,
                    best_src,
                    best_score,
                    generations,
                )
    finally:
        ga.close()

    if collect_pairs and ga._pairs_count > 0:
        console.print(
            f"[bold green]Collected {ga._pairs_count} source-binary pairs[/] → {collect_pairs}"
        )

    if json_output:
        ga_payload: dict[str, Any] = {
            "source": str(p.seed_c),
            "symbol": p.symbol,
            "mode": "ga",
            "generations": generations,
            "pop_size": pop_size,
            "best_score": round(best_score, 2),
            "exact": best_score < 0.1,
            "elapsed_sec": round(ga.elapsed_sec, 2),
            "stagnant_gens": ga.stagnant_gens,
        }
        if best_src is not None:
            best_path = out_dir_path / "best.c"
            ga_payload["best_source_path"] = str(best_path)
        json_print(ga_payload)
    else:
        console.print(f"\nDone. Best score: {best_score:.2f}")
        if best_score < 0.1:
            console.print("[bold green]EXACT MATCH[/]")

    if best_score < 0.1:
        _save_solution(
            p.cfg,
            p.symbol,
            p.cflags,
            p.target_size,
            str(p.seed_c),
            best_score,
            generations,
            mutations=tuple(sorted(getattr(ga, "applied_mutations", ()))),
        )
    else:
        # Documented exit-code contract: 0 = match, 1 = no match, 2 = build
        # or config error.
        console.print(
            "\n[yellow]No match found.[/yellow] If the delta is register/structural "
            "class, `rebrew prove` can often establish semantic equivalence "
            "(smygb: 7/7 NEAR_MATCHING promoted) — or run "
            "`rebrew near-diag --fix-blocker` to classify + document."
        )
        if ceiling_blocker:
            console.print(
                "[dim]Documented GA ceiling (register-only delta) — further GA "
                "runs on this function will be skipped; `rebrew prove` is the "
                "sanctioned next step.[/dim]"
            )
        raise typer.Exit(code=EXIT_MISMATCH)


def _save_solution(
    cfg: Any,
    symbol: str,
    cflags: str,
    target_size: int,
    source_file: str,
    score: float,
    generations: int,
    *,
    mutations: tuple[str, ...] = (),
    collect_out: list[SolutionEntry] | None = None,
) -> None:
    """Save an exact-match solution to the solutions database.

    *mutations* are the ``mut_*`` operators the winning GA run applied (see
    ``SolutionEntry.mutations``) — the cross-function learning signal.

    With *collect_out* set, the entry is appended to that list instead of
    written — the batch GA driver collects one entry per matched stub and
    flushes via ``save_solutions`` once, so N matches cost one whole-file
    read-modify-write instead of N (the flag-sweep batch already does this).
    """
    try:
        from rebrew.matcher import SolutionEntry, save_solution

        entry = SolutionEntry(
            symbol=symbol,
            cflags=cflags,
            size=target_size or 0,
            source_file=source_file,
            target=getattr(cfg, "target_name", ""),
            score=score,
            generations=generations,
            mutations=mutations,
        )
        if collect_out is not None:
            collect_out.append(entry)
            return
        save_solution(cfg.root, entry)
    except Exception:
        # A failed save silently breaks --seed-from-solved / find_similar for
        # this function; visible at WARNING, not swallowed at DEBUG.
        log.warning("Solution save failed for %s", symbol, exc_info=True)


# ---------------------------------------------------------------------------
# Batch: in-process GA runner
# ---------------------------------------------------------------------------


def _run_one_stub_ga(
    stub: StubInfo,
    cfg: ProjectConfig,
    generations: int,
    pop: int,
    jobs: int,
    timeout_min: int,
    extra_seed_paths: list[str] | None = None,
    cflags_override: str | None = None,
    rng_seed: int | None = None,
    resume_from: GACheckpoint | None = None,
    mutation_weights: dict[str, float] | None = None,
    solutions_out: list[SolutionEntry] | None = None,
    collect_pairs_path: Path | None = None,
) -> tuple[bool, str, float, int]:
    """Run one GA pass for a single stub in-process.

    Returns ``(matched, summary, best_score, generations)`` — ``generations``
    is what the run actually executed (resume-aware), not the requested
    budget, so the batch driver records the truth in ``ga_runs.jsonl``.

    *cflags_override* replaces ``stub.cflags`` (used by ``--sweep-then-ga``
    to seed the GA with the flag-sweep's best variant).  *resume_from* is a
    validated :class:`GACheckpoint` (batch ``--resume``).  *solutions_out*
    collects SolutionEntry for the batch driver's single end-of-batch flush
    (see ``_save_solution``); when None the entry is written immediately.
    """
    filepath = stub.filepath
    try:
        rel = filepath.relative_to(cfg.root)
    except ValueError:
        rel = Path(filepath.stem)
    out_dir = _ga_runs_dir(cfg, rel)
    out_dir.mkdir(parents=True, exist_ok=True)

    va_int = int(stub.va, 16)
    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, stub.size)
    if not target_bytes:
        return False, "Could not extract target bytes", float("inf"), 0

    cl_cmd, inc_dir, msvc_env, cc = resolve_compiler_env(cfg)

    # Per-function / per-library overrides resolve exactly like the
    # single-function path (resolve_compile_overrides is the shared chain:
    # metadata TOOLCHAIN/CFLAGS → nearest rebrew-libraries.toml → project).
    # Without this a library built with another compiler was recompiled with
    # the project default and could never match (docs/TOOLCHAIN.md).
    from rebrew.cli import resolve_compile_overrides

    toolchain_name, resolved_cflags = resolve_compile_overrides(
        cfg,
        filepath.parent,
        getattr(stub, "toolchain", "") or None,
        cflags_override if cflags_override is not None else (stub.cflags or None),
        getattr(stub, "module", ""),
    )
    cflags = _compile_cflags(
        resolved_cflags,
        getattr(cfg, "base_cflags", "") or "",
        posix_style=bool(getattr(cfg, "posix_style", False)),
    )

    seed_src, _ = read_source_text(filepath)

    loaded_extra: list[str] = []
    if extra_seed_paths:
        for sp in extra_seed_paths:
            p = Path(sp)
            if p.exists():
                text, _ = read_source_text(p)
                loaded_extra.append(text)

    ga = BinaryMatchingGA(
        seed_src,
        target_bytes,
        cl_cmd,
        inc_dir,
        cflags,
        stub.symbol,
        out_dir,
        num_generations=generations,
        pop_size=pop,
        num_jobs=jobs,
        compile_cache=cc,
        env=msvc_env,
        compile_timeout=getattr(cfg, "compile_timeout", 60),
        verbose=0,
        extra_seeds=loaded_extra or None,
        rng_seed=rng_seed,
        posix_style=getattr(cfg, "posix_style", False),
        resume_from=resume_from,
        mutation_weights=mutation_weights,
        cs_mode=capstone_mode_for_arch(getattr(cfg, "arch", "")),
        profile=str(toolchain_name or getattr(cfg, "compiler_profile", "") or ""),
        cfg=cfg,
        collect_pairs_path=collect_pairs_path,
    )

    matched = False
    output_summary = ""
    # Cooperative deadline (thread-safe; SIGALRM only fires in the main
    # thread and would break parallel batch runs).  Compile subprocesses
    # are individually bounded by compile_timeout, so the worst-case
    # overshoot past the deadline is one in-flight compile.
    deadline = time.monotonic() + timeout_min * 60 + 60
    try:
        best_src, best_score = ga.run(deadline=deadline)
        matched = best_score < 0.1
        output_summary = f"best_score={best_score:.2f}"

        if matched and best_src is not None:
            best_c = out_dir / "best.c"
            # Persist the RAW user-facing flags (swept override or the stub's
            # own metadata) — never the base-prefixed compile string.  The
            # metadata convention stores user-facing flags only; compile_to_obj
            # prepends base_cflags itself, and embedding the prefix would
            # break later base_cflags changes (duplicate /MT etc.).
            persist_cflags = cflags_override if cflags_override is not None else stub.cflags
            # Authoritative validation before splicing/promoting: the GA
            # scores with score_candidate, which masks every reloc slot —
            # a candidate differing ONLY in a call/mov displacement scores
            # 0.0 without checking the reloc TARGET against the catalog, so
            # a wrong-callee source would be spliced and promoted RELOC that
            # the next test/verify immediately demotes (functionality-review
            # F3).  Confirm with the same predicate test/verify use.
            confirmed = False
            try:
                from rebrew.coff_reloc import build_name_to_va
                from rebrew.compile import compile_and_compare

                n2v = build_name_to_va(cfg)
                if n2v and best_c.exists():
                    # The GA ran with _compile_cflags(resolved_cflags, base);
                    # pass the raw resolved user-facing flags
                    # (compile_and_compare prepends base itself) and the same
                    # toolchain, or the confirmation validates a different
                    # compile than the GA scored.
                    cmp_res = compile_and_compare(
                        cfg,
                        best_c,
                        stub.symbol,
                        target_bytes,
                        resolved_cflags,
                        name_to_va=n2v,
                        section_va=va_int,
                        toolchain=toolchain_name,
                    )
                    confirmed = cmp_res.matched
                    if not confirmed:
                        log.warning(
                            "GA match for %s not confirmed by reloc validation "
                            "(%s: %s) — not promoting",
                            stub.symbol,
                            cmp_res.status,
                            cmp_res.message[:120],
                        )
            except Exception as exc:  # validation is best-effort
                log.warning("GA match validation failed for %s: %s", stub.symbol, exc)
            if not confirmed:
                matched = False
                output_summary = f"best_score={best_score:.2f} (reloc-masked only, not confirmed)"
            spliced_ok = False
            # Only splice a CONFIRMED champion: ``update_stub_to_matched``
            # promotes STATUS to RELOC, and an unconfirmed (reloc-masked-only)
            # candidate would claim a match the next test/verify demotes.  The
            # flag-sweep path gates identically; the two must agree.
            if confirmed and best_c.exists():
                try:
                    with metadata_write_lock(cfg.metadata_dir, "rebrew-functions.toml"):
                        spliced_ok = update_stub_to_matched(
                            filepath, best_src, stub, metadata_dir=cfg.metadata_dir
                        )
                        if matched and not spliced_ok:
                            # Distinguish "not confirmed" (reloc validation
                            # rejected it) from "splice failed": a confirmed
                            # match that could not be spliced would otherwise
                            # vanish from the report as a bare "No match".
                            log.warning(
                                "GA match for %s not spliced: the stub's function "
                                "definition could not be located (unrecognized "
                                "return type or no marker) — the .c still holds a stub",
                                stub.symbol,
                            )
                        # Under --sweep-then-ga the GA ran with swept flags that
                        # differ from stub.cflags — persist them or the next
                        # test/verify (which compiles with metadata CFLAGS)
                        # demotes the match immediately.
                        if spliced_ok and cflags_override is not None:
                            update_cflags_annotation(
                                filepath, persist_cflags, metadata_dir=cfg.metadata_dir
                            )
                        # Keep status/todo in sync: the verify cache may still
                        # hold a STUB entry from the last full verify — without
                        # this patch, `rebrew status` reads the stale cached
                        # STUB over the fresh RELOC metadata until the next
                        # verify (functionality-review F4).  Best-effort: a
                        # failed cache write must not undo the splice.
                        if spliced_ok:
                            try:
                                from rebrew.verify_cache import patch_verify_cache_entries

                                patch_verify_cache_entries(
                                    cfg,
                                    [
                                        {
                                            "va": int(stub.va, 16),
                                            "status": "RELOC",
                                            "match_count": stub.size or 0,
                                            "total": stub.size or 0,
                                            "delta": 0,
                                        }
                                    ],
                                )
                            except Exception:  # cache patch is best-effort
                                log.warning(
                                    "Verify-cache patch failed for %s (status may be stale)",
                                    stub.symbol,
                                    exc_info=True,
                                )
                except (RuntimeError, OSError) as e:
                    console.print(
                        f"  [yellow]warning:[/yellow] GA matched but failed to update source: {e}"
                    )
            if spliced_ok:
                with metadata_write_lock(cfg.metadata_dir, "rebrew-functions.toml"):
                    _save_solution(
                        cfg,
                        stub.symbol,
                        # find_similar cross-function seeding filters on this field,
                        # so it must be the raw user-facing flags (matching the
                        # stub.cflags spelling), not the base-prefixed compile string.
                        persist_cflags,
                        stub.size,
                        str(filepath),
                        best_score,
                        generations,
                        mutations=tuple(sorted(getattr(ga, "applied_mutations", ()))),
                        collect_out=solutions_out,
                    )
            # Only claim a match when the source was actually updated — a
            # stub whose block could not be spliced is still a stub, and
            # must not pollute ga_runs/solutions with a false "solved".
            matched = spliced_ok

        # GA exhausted without a match: if the champion's residual delta is
        # register-only (effective match), document the ceiling so later
        # --improve/--flag-sweep runs skip this function and `rebrew prove`
        # is the sanctioned next step.  Runs before ga.close() so the warm
        # build cache can serve the champion compile.
        if not matched and best_src is not None:
            ceiling = _maybe_document_ga_ceiling(
                cfg,
                stub.module,
                va_int,
                target_bytes,
                ga,
                best_src,
                best_score,
                generations,
            )
            if ceiling:
                output_summary += " [GA ceiling documented]"
    finally:
        ga.close()

    # Score and executed generations ride back to the batch driver so its
    # .rebrew/ga_runs.jsonl record carries them (`--ga-history` averages the
    # scores; without them every past run reports null).
    return matched, output_summary, best_score, ga.generation


# ---------------------------------------------------------------------------
# GA ceiling documentation
# ---------------------------------------------------------------------------


#: Blocker prefix marking a function whose residual byte delta is
#: register-only ("effective match") — the GA ceiling, not reproducible
#: from portable C (register allocation is a compiler-internal decision).
#: Ceiling entries keep their NEAR_MATCHING/SIZE_MISMATCH status (so
#: `rebrew prove --all` still targets them) but are excluded from further
#: GA batch runs (--improve / --flag-sweep / --near-miss / --size-mismatch)
#: — see `_parse_annotations`.
def _classify_register_only(
    ga: BinaryMatchingGA,
    best_src: str,
    target_bytes: bytes,
    va_int: int,
) -> bool:
    """True when the GA champion's residual delta is register-only.

    Compiles the champion once (warm-cached — it was just scored) and runs
    the near-diag classifier on the extracted code.  A register-only delta
    with zero structural bytes is the effective-match case: byte-exact is not
    reachable from portable C, so further GA search cannot succeed.

    ``BuildResult.obj_bytes`` is the extracted FUNCTION CODE (not a COFF
    object), so it is classified in memory.  The previous version wrote it to
    a ``.obj`` and re-parsed it with LIEF, which failed every time — the
    ceiling was never documented.
    """
    try:
        res = ga._compile_source(best_src)
        if not res.ok or not res.obj_bytes:
            return False

        from rebrew.near_diag import analyze

        diag = analyze(
            target_bytes,
            res.obj_bytes,
            set(res.reloc_offsets or {}),
            va_int,
            cs_mode=getattr(ga, "cs_mode", "CS_MODE_32"),
        )
        if diag.get("verdict") == "MATCH":
            return False
        cats = diag.get("categories", {}) or {}
        reg = int((cats.get("register") or {}).get("bytes", 0))
        struct = int((cats.get("structural") or {}).get("bytes", 0))
        return reg > 0 and struct == 0
    except Exception:
        # Best-effort: a classification failure must not crash the run or
        # write a bogus ceiling marker.
        return False


def _maybe_document_ga_ceiling(
    cfg: Any,
    module: str,
    va_int: int,
    target_bytes: bytes,
    ga: BinaryMatchingGA,
    best_src: str,
    best_score: float,
    generations: int,
) -> str | None:
    """Write a ``GA_CEILING`` blocker when the champion is register-only.

    Called after the GA exhausts its budget without a match.  Never clobbers
    an existing blocker; writes nothing when the champion is not cleanly
    register-only.  Returns the blocker text written, or ``None``.
    """
    if not best_src:
        return None
    from rebrew.metadata import GA_CEILING_PREFIX, get_entry, update_field

    meta_root = cfg.metadata_dir
    existing = (get_entry(meta_root, va_int, module) or {}).get("blocker")
    if existing:
        return None
    if not _classify_register_only(ga, best_src, target_bytes, va_int):
        return None
    text = (
        f"{GA_CEILING_PREFIX} register-only byte delta (effective match) — not "
        "byte-reproducible from portable C (compiler register allocation); GA "
        f"exhausted {generations} generations at best score {best_score:.2f}; "
        "run `rebrew prove` for PROVEN"
    )
    update_field(meta_root, va_int, "blocker", text, module=module)
    return text


# ---------------------------------------------------------------------------
# Batch: --all entry point
# ---------------------------------------------------------------------------


def _show_ga_history(cfg: ProjectConfig, json_output: bool, *, target: str = "") -> None:
    """Summarize past GA runs (``.rebrew/ga_runs.jsonl``) for at-a-glance
    effectiveness triage: how many attempts, how many converged, score trends.
    """

    records = load_ga_runs(cfg.root, target=target, limit=100000)
    total = len(records)
    matched = sum(1 for r in records if r.get("matched"))
    scored = [r["score"] for r in records if isinstance(r.get("score"), (int, float))]
    summary: dict[str, Any] = {
        "total": total,
        "matched": matched,
        "matched_pct": round(100.0 * matched / total, 1) if total else 0.0,
        "avg_score": round(sum(scored) / len(scored), 2) if scored else None,
        "best_score": round(min(scored), 2) if scored else None,
        "recent": records[:10],
    }
    if json_output:
        json_print(summary)
        return
    console.print(f"[bold]GA run history[/bold] ({target or 'all targets'}):")
    console.print(f"  Total runs: {total}   Matched: {matched} ({summary['matched_pct']:.1f}%)")
    if scored:
        console.print(
            f"  Score (0 = exact): avg {summary['avg_score']:.2f}, best {summary['best_score']:.2f}"
        )
    for rec in records[:10]:
        mark = "[green]MATCH[/green]" if rec.get("matched") else "[dim]no match[/dim]"
        score = f" score={rec['score']}" if rec.get("score") is not None else ""
        console.print(f"  {mark}  {rec.get('ts', '')[:19]}  {rec.get('symbol', '?')}{score}")


def _filter_recently_run(
    stubs: list[StubInfo],
    cfg: ProjectConfig,
    hours: int,
    json_output: bool,
) -> list[StubInfo]:
    """Drop stubs that already have a GA run record within the last *hours*.

    Lets long batch runs resume without re-attempting recently-processed
    stubs (see ``--skip-recent``).
    """
    from datetime import UTC, datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    records = load_ga_runs(cfg.root, target=getattr(cfg, "target_name", ""), limit=100000)
    recent_vas: set[str] = set()
    for rec in records:
        ts = rec.get("ts", "")
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            if dt >= cutoff:
                recent_vas.add(str(rec.get("va")))
        except (ValueError, TypeError):
            continue
    if not recent_vas:
        return stubs
    kept = [s for s in stubs if s.va not in recent_vas]
    skipped = len(stubs) - len(kept)
    if skipped and not json_output:
        console.print(f"[dim]Skipping {skipped} stub(s) run in the last {hours}h[/dim]")
    return kept


def _run_all(
    cfg: ProjectConfig,
    jobs: int,
    generations: int,
    pop_size: int,
    timeout_min: int,
    dry_run: bool,
    min_size: int,
    max_size: int,
    filter_str: str,
    near_miss: bool,
    improve: bool,
    threshold: int,
    flag_sweep: bool,
    fix_cflags: bool,
    max_stubs: int,
    seed_from_solved: bool,
    json_output: bool,
    tier: str,
    flag_sweep_then_ga: bool = False,
    skip_recent_hours: int = 0,
    seed: int | None = None,
    size_mismatch: bool = False,
    seed_solutions_path: Path | None = None,
    resume: bool = False,
    mutation_weights: dict[str, float] | None = None,
    collect_pairs: str | None = None,
) -> tuple[int, int]:
    """Batch driver: run GA or flag sweep across all discovered functions.

    Returns ``(matched_count, failed_count)``; ``(0, 0)`` on the dry-run
    and flag-sweep early paths.
    """
    reversed_dir = cfg.reversed_dir
    ignored = set(cfg.ignored_symbols or [])

    if flag_sweep:
        stubs = find_all_matching(
            reversed_dir,
            ignored=ignored,
            cfg=cfg,
            warn_duplicates=not json_output,
            min_size=min_size,
        )
        mode_label = "NEAR_MATCHING (flag-sweep)"
    elif improve:
        stubs = find_all_matching(
            reversed_dir,
            ignored=ignored,
            cfg=cfg,
            warn_duplicates=not json_output,
            min_size=min_size,
        )
        mode_label = "NEAR_MATCHING (improve)"
    elif size_mismatch:
        stubs = find_size_mismatch(
            reversed_dir,
            ignored=ignored,
            cfg=cfg,
            warn_duplicates=not json_output,
            min_size=min_size,
        )
        mode_label = "SIZE_MISMATCH (GA)"
    elif near_miss:
        stubs = find_near_miss(
            reversed_dir,
            ignored=ignored,
            max_delta=threshold,
            cfg=cfg,
            warn_duplicates=not json_output,
            min_size=min_size,
        )
        mode_label = "NEAR_MATCHING (near-miss)"
    else:
        stubs = find_all_stubs(
            reversed_dir,
            ignored=ignored,
            cfg=cfg,
            warn_duplicates=not json_output,
            min_size=min_size,
        )
        mode_label = "STUB"

    if max_size < 9999:
        stubs = [s for s in stubs if s.size <= max_size]
    if filter_str:
        stubs = [s for s in stubs if filter_str in str(s.filepath)]
    # Skip recently-run stubs BEFORE capping by max_stubs so --skip-recent
    # and --max-stubs compose sensibly (skip first, then limit).
    if skip_recent_hours:
        stubs = _filter_recently_run(stubs, cfg, skip_recent_hours, json_output)

    if max_stubs > 0:
        stubs = stubs[:max_stubs]

    from rebrew.utils import rel_display_path

    if not json_output:
        console.print(f"\nFound [bold]{len(stubs)}[/] {mode_label} function(s) to process:\n")
        for i, stub in enumerate(stubs, 1):
            delta_str = f"  Δ{stub.delta}B" if stub.delta != 9999 else ""
            display = rel_display_path(stub.filepath, reversed_dir)
            console.print(
                f"  {i:3d}. [magenta]{display:45s}[/]  {stub.size:4d}B  "
                f"[cyan]{stub.va}[/]  {stub.symbol:30s}  [dim]{stub.cflags}{delta_str}[/]"
            )
        console.print()

    if dry_run:
        if json_output:
            items = []
            for stub in stubs:
                item: dict[str, Any] = {
                    "file": str(stub.filepath),
                    "va": stub.va,
                    "size": stub.size,
                    "symbol": stub.symbol,
                    "cflags": stub.cflags,
                }
                if stub.delta != 9999:
                    item["delta"] = stub.delta
                items.append(item)
            json_print({"mode": mode_label, "dry_run": True, "count": len(stubs), "items": items})
        else:
            console.print("Dry run — exiting.")
        return 0, 0

    if flag_sweep:
        from rebrew.coff_reloc import build_name_to_va

        # Shared relocation-validation catalog (same as test/verify): the
        # sweep's reloc-masked score alone cannot certify a match — a
        # candidate differing only in a call/mov displacement scores 0.0
        # without checking the reloc TARGET, so a wrong-callee source could
        # be promoted EXACT/RELOC and demoted by the next test/verify
        # (functionality-review F3).  Validate every sweep "exact" against
        # the catalog before promoting.
        name_to_va = build_name_to_va(cfg)
        matched, failed = _run_batch_flag_sweep(
            stubs, cfg, tier, jobs, fix_cflags, json_output, mode_label, name_to_va=name_to_va
        )
        return matched, failed

    _ga_runs_dir(cfg).mkdir(parents=True, exist_ok=True)

    matched_count = 0
    failed_count = 0
    ga_results: list[dict[str, Any]] = []

    # Print the run header for every stub up front (deterministic order).
    for i, stub in enumerate(stubs, 1):
        display = rel_display_path(stub.filepath, reversed_dir)
        if not json_output:
            console.print(f"\n[bold]{'=' * 60}[/]")
            console.print(
                f"\\[{i}/{len(stubs)}] [magenta]{display}[/] ({stub.size}B) symbol={stub.symbol}"
            )
            console.print(f"[bold]{'=' * 60}[/]")
        else:
            console.print(f"\\[{i}/{len(stubs)}] {display} ({stub.size}B)")

    # Precompute cross-function seeding (read-only; main thread, so the
    # dim "Seeding from solved" lines stay deterministic).  Load the
    # solutions list once — find_similar re-reads the whole file per stub
    # otherwise (N file reads + parses for N stubs).
    seed_solutions: list[Any] = []
    if seed_from_solved:
        try:
            from rebrew.matcher import load_solutions, load_solutions_file

            seed_solutions = load_solutions(cfg.root)
            if seed_solutions_path is not None:
                # Cross-project seeding: merge another project's solutions,
                # deduped by (target, symbol) — local entries win.
                extra = load_solutions_file(seed_solutions_path)
                seen = {(s.target, s.symbol) for s in seed_solutions}
                for sol in extra:
                    if (sol.target, sol.symbol) not in seen:
                        seen.add((sol.target, sol.symbol))
                        seed_solutions.append(sol)
                if extra and not json_output:
                    console.print(
                        f"  [dim]Cross-project seeding:[/] {len(extra)} solutions "
                        f"from {seed_solutions_path}"
                    )
        except Exception:
            # Seeding is a batch-time enhancement, but a failed load silently
            # disables --seed-from-solved for the whole batch — warn at
            # WARNING so the user knows the run was not seed-informed.
            log.warning("Solution list load failed — cross-project seeding disabled", exc_info=True)

    stub_seeds: list[list[str]] = []
    stub_seed_cflags: list[str | None] = []
    stub_seed_mutations: list[tuple[str, ...]] = []
    for stub in stubs:
        extra_ga_paths: list[str] = []
        seed_cflags: str | None = None
        seed_mutations: tuple[str, ...] = ()
        if seed_from_solved:
            try:
                from rebrew.matcher import find_similar

                similar = find_similar(
                    cfg.root,
                    size=stub.size,
                    cflags=stub.cflags,
                    target=getattr(cfg, "target_name", ""),
                    top_k=3,
                    entries=seed_solutions,
                )
                for sol in similar:
                    sol_path = cfg.root / sol.source_file
                    if sol_path.exists():
                        extra_ga_paths.append(str(sol_path))
                        if not json_output:
                            console.print(
                                f"  [dim]Seeding from solved:[/] {sol.symbol} ({sol.size}B)"
                            )
                    elif seed_cflags is None and sol.cflags:
                        # Cross-project: the source file lives in another
                        # project, but the winning cflags are transferable —
                        # same size + same compiler often means same flags.
                        seed_cflags = sol.cflags
                        if not json_output:
                            console.print(
                                f"  [dim]Seeding cflags from solved:[/] {sol.symbol} "
                                f"({sol.size}B, {sol.cflags})"
                            )
                    # The winning run's mutation operators transfer too: bias
                    # this GA toward what solved the lookalike.  First usable
                    # seed's mutations win (batch --mutation-focus overrides
                    # per-stub weights — see _run_stub).
                    if not seed_mutations and sol.mutations:
                        seed_mutations = tuple(sol.mutations)
            except Exception:
                # Per-stub seed lookup failure — warn so a stub that would
                # otherwise have been seed-informed is not silently run from
                # its bare seed.
                log.warning("Solution lookup failed for %s", stub.symbol, exc_info=True)
        stub_seeds.append(extra_ga_paths)
        stub_seed_cflags.append(seed_cflags)
        stub_seed_mutations.append(seed_mutations)

    # Parallel stubs: one worker per stub, intra-GA compiles serialized so
    # total concurrency stays at ~jobs (MSVC under wine is not cheap).
    # The cooperative deadline (no SIGALRM) keeps this thread-safe.
    intra_jobs = 1 if jobs > 1 else jobs

    # Collect solution entries across all stubs and flush ONCE at the end —
    # _save_solution per matched stub re-read and rewrote the whole
    # solutions file per match (O(matches × file size)).
    solutions_out: list[SolutionEntry] = []

    def _run_stub(
        stub: StubInfo,
        seeds: list[str],
        seed_cflags: str | None,
        seed_mutations: tuple[str, ...] = (),
    ) -> tuple[StubInfo, bool, str]:
        # A batch --mutation-focus overrides the per-stub transfer from the
        # seeded solution; without one, the seed's winning operators bias
        # this GA the same way a verdict blocker would.
        stub_weights: dict[str, float] | None = mutation_weights
        if stub_weights is None and seed_mutations:
            stub_weights = dict.fromkeys(seed_mutations, _MUTATION_FOCUS_WEIGHT)
        # Deterministic per-stub sub-seed: same --seed + same VA ⇒ same GA.
        # (VA collisions are impossible within one batch; across batches the
        # VA is stable, so runs stay reproducible.)
        stub_seed = None if seed is None else seed + int(stub.va, 16)
        sweep_flags: str | None = None
        if flag_sweep_then_ga:
            try:
                _s, best_flags, _all = run_flag_sweep(stub, cfg, tier=tier, jobs=intra_jobs)
                if best_flags and _s < float("inf"):
                    sweep_flags = best_flags
                    if not json_output:
                        console.print(
                            f"  [dim]Flag sweep:[/] {stub.symbol} best flags {best_flags}"
                        )
            except Exception:  # sweep failure falls back to stub flags
                # A sweep failure silently degrades the GA to the stub's own
                # cflags — visible at WARNING (batch workflow default hides
                # DEBUG), so the user can tell the result was not
                # sweep-informed.
                log.warning(
                    "Flag sweep failed for %s — GA will run with stub cflags",
                    stub.symbol,
                    exc_info=True,
                )

        # --resume: continue from the stub's last checkpoint (the GA
        # constructor re-validates args_hash — a stale one restarts fresh).
        resume_from: GACheckpoint | None = None
        if resume:
            try:
                rel = stub.filepath.relative_to(cfg.root)
            except ValueError:
                rel = Path(stub.filepath.stem)
            stub_out_dir = _ga_runs_dir(cfg, rel)
            resume_from = read_ga_checkpoint(stub_out_dir, stub.symbol)
            if resume_from is not None and not json_output:
                console.print(
                    f"  [dim]Resuming {stub.symbol} from generation {resume_from.generation}[/dim]"
                )
        try:
            matched, output_summary, best_score, generations_run = _run_one_stub_ga(
                stub,
                cfg,
                generations,
                pop_size,
                intra_jobs,
                timeout_min,
                seeds or None,
                cflags_override=sweep_flags or seed_cflags,
                rng_seed=stub_seed,
                resume_from=resume_from,
                mutation_weights=stub_weights,
                solutions_out=solutions_out,
                collect_pairs_path=Path(collect_pairs) if collect_pairs else None,
            )
        except Exception as exc:  # one bad stub must not abort the batch
            log.debug("GA run failed for %s", stub.symbol, exc_info=True)
            console.print(
                f"  [yellow]warning:[/yellow] GA run failed for {stub.symbol}: "
                f"{exc.__class__.__name__}: {exc}"
            )
            return stub, False, f"error: {exc.__class__.__name__}: {exc}"
        # Persist the outcome for cross-run progress tracking (append-only
        # log; O_APPEND small-line writes are atomic across threads).
        try:
            from rebrew.matcher import record_ga_run

            record_ga_run(
                cfg.root,
                target=getattr(cfg, "target_name", ""),
                va=stub.va,
                symbol=stub.symbol,
                matched=matched,
                score=best_score,
                generations=generations_run,
            )
        except Exception:
            # A failed record makes --skip-recent re-run this stub next batch
            # (hours of GA).  Visible at WARNING, not swallowed at DEBUG.
            log.warning("GA run record failed for %s", stub.symbol, exc_info=True)
        return stub, matched, output_summary

    if jobs > 1 and len(stubs) > 1:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            outcomes = list(
                executor.map(
                    _run_stub, stubs, stub_seeds, stub_seed_cflags, stub_seed_mutations
                )  # order preserved
            )
    else:
        outcomes = [
            _run_stub(s, seeds, scf, sm)
            for s, seeds, scf, sm in zip(
                stubs, stub_seeds, stub_seed_cflags, stub_seed_mutations, strict=False
            )
        ]

    for stub, matched, output_summary in outcomes:
        result_entry: dict[str, Any] = {
            "file": str(stub.filepath),
            "va": stub.va,
            "size": stub.size,
            "symbol": stub.symbol,
            "matched": matched,
        }
        if stub.delta != 9999:
            result_entry["delta"] = stub.delta

        if matched:
            matched_count += 1
            if not json_output:
                console.print(f"  [bold green]MATCHED![/] ({matched_count} total matches)")
        else:
            failed_count += 1
            if not json_output:
                console.print(f"  [red]No match.[/] {output_summary}")

        ga_results.append(result_entry)

    if json_output:
        json_print(
            {
                "mode": mode_label,
                "matched": matched_count,
                "failed": failed_count,
                "total": len(stubs),
                "seeded_cflags": sum(1 for c in stub_seed_cflags if c),
                "results": ga_results,
            }
        )
    else:
        console.print(f"\n[bold]{'=' * 60}[/]")
        console.print(
            f"Results: [green]{matched_count} matched[/], [red]{failed_count} failed[/], {len(stubs)} total"
        )
        console.print(f"[bold]{'=' * 60}[/]")

    # Flush all collected solutions in one read-modify-write (see
    # solutions_out) — mirrors the batch flag-sweep path.
    if solutions_out:
        try:
            from rebrew.matcher import save_solutions

            save_solutions(cfg.root, solutions_out)
        except Exception:
            log.warning("Batch solution save failed", exc_info=True)
    return matched_count, failed_count


def _run_batch_flag_sweep(
    stubs: list[StubInfo],
    cfg: ProjectConfig,
    tier: str,
    jobs: int,
    fix_cflags: bool,
    json_output: bool,
    mode_label: str,
    name_to_va: dict[str, int] | None = None,
) -> tuple[int, int]:
    """Execute batch flag sweep across all discovered NEAR_MATCHING functions.

    Returns ``(exact_count, not_exact_count)`` so ``--all-targets``
    aggregation reports real numbers instead of a hardcoded ``(0, 0)``.
    """
    from rebrew.annotation import module_for_va
    from rebrew.matcher import SolutionEntry, save_solutions
    from rebrew.metadata import update_source_status
    from rebrew.utils import rel_display_path

    reversed_dir = cfg.reversed_dir
    # Collect solved entries and flush ONCE at the end — save_solution per
    # exact match re-read and rewrote the whole solutions file (O(N²)).
    solved_entries: list[SolutionEntry] = []
    console.print(
        f"\n[bold green]Running {mode_label} flag sweep for {len(stubs)} NEAR_MATCHING functions with {jobs} workers...[/bold green]"
    )
    improved_count = 0
    exact_count = 0
    sweep_results: list[dict[str, Any]] = []

    for i, stub in enumerate(stubs, 1):
        display = rel_display_path(stub.filepath, reversed_dir)
        if not json_output:
            console.print(f"\n[bold]{'=' * 60}[/]")
            console.print(
                f"\\[{i}/{len(stubs)}] [magenta]{display}[/] ({stub.size}B) symbol={stub.symbol}"
            )
            console.print(f"  Current flags: [dim]{stub.cflags}[/]")
            console.print(f"[bold]{'=' * 60}[/]")
        else:
            console.print(f"\\[{i}/{len(stubs)}] {display} ({stub.size}B)")

        best_score, best_flags, all_results = run_flag_sweep(stub, cfg, tier=tier, jobs=jobs)

        is_exact = best_score < 0.1
        # Whether the authoritative re-verify below can run at all.  It needs
        # --fix-cflags, a winning flag combo, and the catalog used to validate
        # reloc targets.
        validation_ran = bool(is_exact and fix_cflags and best_flags and name_to_va)
        if is_exact and not validation_ran:
            # No authoritative predicate is available (typically a
            # --flag-sweep-only run without --fix-cflags): the JSON row
            # reports `exact: true`, so the batch count and exit code must
            # agree instead of reporting `exact: 0` and exiting 1 (a false red
            # for CI).  When validation DID run, only a confirmed match counts
            # (the sweep score alone masks reloc targets).
            exact_count += 1
        result_entry: dict[str, Any] = {
            "file": str(stub.filepath),
            "va": stub.va,
            "size": stub.size,
            "symbol": stub.symbol,
            "best_score": round(best_score, 2) if best_score < float("inf") else None,
            "best_flags": best_flags or None,
            "exact": is_exact,
        }
        if stub.delta != 9999:
            result_entry["delta"] = stub.delta

        cflags_updated = False
        confirmed = False
        resolved = ""
        if is_exact and fix_cflags and best_flags and name_to_va:
            # The sweep's reloc-masked score alone cannot certify a match:
            # score_candidate masks every reloc slot, so a candidate that
            # differs ONLY in a call/mov displacement scores 0.0 without
            # checking the reloc TARGET — promoting it would write
            # EXACT/RELOC that the next test/verify (which validates reloc
            # targets against the catalog) immediately demotes
            # (functionality-review F3).  Re-verify with the authoritative
            # predicate before touching STATUS.
            try:
                from rebrew.binary_loader import extract_raw_bytes
                from rebrew.cli import resolve_compile_overrides
                from rebrew.compile import compile_and_compare

                target_bytes = extract_raw_bytes(cfg.target_binary, int(stub.va, 16), stub.size)
                if target_bytes:
                    # Same effective flags AND toolchain the sweep used:
                    # resolved stub overrides (per-function → library →
                    # preset → compiler.cflags) PLUS the winning combo.
                    # compile_and_compare prepends cfg.base_cflags itself, so
                    # pass the raw resolved set — bare best_flags would drop
                    # the stub's own cflags and validate a DIFFERENT compile
                    # than the sweep scored.
                    resolved_tc, resolved = resolve_compile_overrides(
                        cfg,
                        stub.filepath.parent,
                        getattr(stub, "toolchain", "") or None,
                        stub.cflags or None,
                        getattr(stub, "module", ""),
                    )
                    cmp_res = compile_and_compare(
                        cfg,
                        stub.filepath,
                        stub.symbol,
                        target_bytes,
                        f"{resolved} {best_flags}".strip(),
                        name_to_va=name_to_va,
                        section_va=int(stub.va, 16),
                        toolchain=resolved_tc,
                    )
                    confirmed = cmp_res.matched
                    if not confirmed and not json_output:
                        console.print(
                            f"  [yellow]sweep exact not confirmed:[/] {stub.symbol} "
                            f"({cmp_res.status}: {cmp_res.message[:80]}) — not promoting"
                        )
            except Exception as exc:  # validation is best-effort
                log.warning(
                    "Match validation failed for %s — not promoting: %s",
                    stub.symbol,
                    exc,
                )
        # The report's `exact` field is the sweep's score-based finding and is
        # NEVER downgraded — the console marks every score<0.1 row EXACT, so
        # the JSON must agree.  Promotion is the separate, gated action below.
        result_entry["promoted"] = bool(confirmed)
        if confirmed:
            # Validated exact: the authoritative compare agreed with the
            # sweep's reloc-masked score.
            exact_count += 1
            # Persist the FULL effective flag set the sweep validated — bare
            # best_flags would drop the stub's own non-axis cflags (/GX, /Zp)
            # and the next test/verify would compile different flags and
            # demote the match.
            cflags_updated = update_cflags_annotation(
                stub.filepath,
                f"{resolved} {best_flags}".strip(),
                metadata_dir=cfg.metadata_dir,
            )
            result_entry["cflags_updated"] = cflags_updated
            update_source_status(
                cfg.metadata_dir,
                "EXACT",
                module=module_for_va(stub.filepath, int(stub.va, 16)),
                va=int(stub.va, 16),
                clear_blockers=True,
                updated_by="match",
            )
            # Keep status/todo in sync with the fresh EXACT metadata (the
            # verify cache may hold a stale NEAR_MATCHING entry).
            try:
                from rebrew.verify_cache import patch_verify_cache_entries

                patch_verify_cache_entries(
                    cfg,
                    [
                        {
                            "va": int(stub.va, 16),
                            "status": "EXACT",
                            "match_count": stub.size or 0,
                            "total": stub.size or 0,
                            "delta": 0,
                        }
                    ],
                )
            except Exception:  # cache patch is best-effort
                log.warning(
                    "Verify-cache patch failed for %s (status may be stale)",
                    stub.symbol,
                    exc_info=True,
                )
            solved_entries.append(
                SolutionEntry(
                    symbol=stub.symbol,
                    cflags=best_flags,
                    size=stub.size,
                    source_file=str(stub.filepath),
                    target=cfg.target_name,
                    score=0.0,
                    generations=1,
                )
            )

        if best_score < float("inf"):
            improved_count += 1

        if not json_output:
            if not all_results:
                console.print("  No compilable results.")
            else:
                top_n = min(5, len(all_results))
                for score, flags_str in all_results[:top_n]:
                    marker = " ← [bold green]EXACT[/]" if score < 0.1 else ""
                    console.print(f"  {score:8.2f}: [dim]{flags_str}[/]{marker}")
                if is_exact:
                    console.print(f"  [bold green]EXACT MATCH[/] with flags: {best_flags}")
                    if cflags_updated:
                        console.print(f"  [bold]Updated CFLAGS → {best_flags}[/]")
                    elif confirmed:
                        console.print("  [dim](flags unchanged — already exact)[/dim]")
                    else:
                        console.print(
                            "  [dim](not promoted — unconfirmed or --fix-cflags not set)[/dim]"
                        )

        sweep_results.append(result_entry)

    # Flush all solved entries in one read-modify-write (see solved_entries).
    if solved_entries:
        save_solutions(cfg.root, solved_entries)

    if json_output:
        json_print(
            {
                "mode": mode_label,
                "tier": tier,
                "exact": exact_count,
                "compilable": improved_count,
                "total": len(stubs),
                "results": sweep_results,
            }
        )
    else:
        console.print(f"\n[bold]{'=' * 60}[/]")
        console.print(
            f"Flag sweep results: [green]{exact_count} exact[/], "
            f"{improved_count} compilable, {len(stubs)} total (tier={tier})"
        )
        console.print(f"[bold]{'=' * 60}[/]")

    return exact_count, len(stubs) - exact_count
