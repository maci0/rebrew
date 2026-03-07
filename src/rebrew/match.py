#!/usr/bin/env python3
"""Genetic Algorithm engine for binary matching.

Compile C source, compare object bytes against a target function, and
iteratively mutate to find a byte-perfect or relocation-normalized match.

For a byte diff of the current state, use ``rebrew diff src/f.c``.

Usage:
    rebrew match <source.c> [--flag-sweep-only --tier TIER]
    rebrew match <source.c> [--generations N --pop-size N]
"""

import hashlib
import logging
import random
import shlex
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi, parse_source_metadata
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import TargetOption, error_exit, json_print, parse_va, require_config, target_marker
from rebrew.compile import resolve_cl_command
from rebrew.compile_cache import CompileCache, get_compile_cache
from rebrew.core import msvc_env_from_config
from rebrew.matcher import (
    BuildCache,
    BuildResult,
    StructuralSimilarity,
    build_candidate,
    build_candidate_obj_only,
    compute_population_diversity,
    crossover,
    flag_sweep,
    mutate_code,
    score_candidate,
    structural_similarity,
)
from rebrew.matcher.mutator import quick_validate
from rebrew.utils import atomic_write_text

log = logging.getLogger(__name__)
console = Console(stderr=True)


def _print_structural_similarity(sim: StructuralSimilarity) -> None:
    verdict = "flag sweep MAY help" if sim.flag_sensitive else "flags unlikely to help"
    console.print(f"\nStructural similarity ({verdict}):")
    console.print(
        f"  Instructions: {sim.exact} exact, {sim.reloc_only} reloc, "
        f"{sim.register_only} register, {sim.structural} structural "
        f"(of {sim.total_insns} total)"
    )
    console.print(
        f"  Mnemonic match: {sim.mnemonic_match_ratio:.1%}  |  "
        f"Structural ratio: {sim.structural_ratio:.1%}"
    )


class BinaryMatchingGA:
    """Genetic algorithm engine for finding byte-identical C source matches."""

    def __init__(
        self,
        seed_source: str,
        target_bytes: bytes,
        cl_cmd: str,
        inc_dir: str,
        cflags: str,
        symbol: str,
        out_dir: Path,
        pop_size: int = 32,
        num_generations: int = 100,
        mutation_prob: float = 0.3,
        crossover_prob: float = 0.7,
        elitism: int = 4,
        num_jobs: int = 4,
        mutation_weights: dict[str, float] | None = None,
        stagnation_limit: int = 20,
        verbose: int = 1,
        rng_seed: int | None = None,
        compare_obj: bool = True,
        link_cmd: str | None = None,
        lib_dir: str | None = None,
        ldflags: str | None = None,
        env: dict[str, str] | None = None,
        compile_cache: CompileCache | None = None,
        compile_timeout: int = 60,
        extra_seeds: list[str] | None = None,
    ) -> None:
        """Initialize the genetic algorithm matching engine.

        Args:
            seed_source: Initial C source code.
            target_bytes: The target byte sequence.
            cl_cmd: Compiler path or command.
            inc_dir: Base include directory.
            cflags: Compiler flags.
            symbol: Target symbol name.
            out_dir: Output directory for matched source.
            pop_size: Population size.
            num_generations: Maximum generations to run.
            mutation_prob: Mutation probability.
            crossover_prob: Crossover probability.
            elitism: Number of elite individuals to keep.
            num_jobs: Thread count for parallel compilation.
            mutation_weights: Custom weights for mutators.
            stagnation_limit: Generations without improvement before stop.
            verbose: Verbosity level.
            rng_seed: Random seed.
            compare_obj: If True, compare object files instead of full link.
            link_cmd: Linker command.
            lib_dir: Library directory.
            ldflags: Linker flags.
            env: Optional MSVC environment variables.
            compile_cache: Persistent compiler cache.
            compile_timeout: Subprocess timeout for compilations.
            extra_seeds: Additional C sources for initial population.

        """
        self.seed_source = seed_source
        self.target_bytes = target_bytes
        self.cl_cmd = cl_cmd
        self.inc_dir = inc_dir
        self.cflags = cflags
        self.symbol = symbol
        self.out_dir = Path(out_dir)
        self.pop_size = pop_size
        self.num_generations = num_generations
        self.mutation_prob = mutation_prob
        self.crossover_prob = crossover_prob
        self.elitism = elitism
        self.num_jobs = num_jobs
        self.stagnation_limit = stagnation_limit
        self.verbose = verbose
        self.rng_seed = rng_seed
        self.compare_obj = compare_obj
        self.link_cmd = link_cmd
        self.lib_dir = lib_dir
        self.ldflags = ldflags
        self.env = env
        self.compile_timeout = compile_timeout

        self.rng = random.Random(rng_seed)
        self.mutation_weights = mutation_weights or {}

        self.population: list[str] = []
        self.best_source: str | None = None
        self.best_score: float = float("inf")
        self.stagnant_gens: int = 0
        self.elapsed_sec: float = 0.0

        self.cache = BuildCache(str(self.out_dir / "build_cache.db"))
        self.compile_cache = compile_cache
        self.extra_seeds = extra_seeds or []

        self._init_population()

    def _init_population(self) -> None:
        self.population = [self.seed_source]
        # Inject solved sources as extra seeds (cross-function transfer)
        for seed_src in self.extra_seeds:
            if seed_src not in self.population:
                self.population.append(seed_src)
                # Also add a mutated variant
                if len(self.population) < self.pop_size:
                    mutated = mutate_code(
                        seed_src, self.rng, mutation_weights=self.mutation_weights
                    )
                    self.population.append(mutated)
        while len(self.population) < self.pop_size:
            src = self.seed_source
            for _ in range(self.rng.randint(1, 4)):
                src = mutate_code(src, self.rng, mutation_weights=self.mutation_weights)
            self.population.append(src)

    def _compile_source(self, src: str) -> BuildResult:
        src_hash = hashlib.sha256(src.encode()).hexdigest()[:16]
        res = self.cache.get(src_hash)
        if res:
            return res

        if self.compare_obj:
            res = build_candidate_obj_only(
                src,
                self.cl_cmd,
                self.inc_dir,
                self.cflags,
                self.symbol,
                env=self.env,
                cache=self.compile_cache,
                timeout=self.compile_timeout,
            )
        else:
            if not self.lib_dir or not self.ldflags:
                raise ValueError("lib dir and ldflags must be set when compare_obj is False")
            res = build_candidate(
                src,
                self.cl_cmd,
                self.inc_dir,
                self.lib_dir,
                self.cflags,
                self.ldflags,
                self.symbol,
                env=self.env,
                timeout=self.compile_timeout * 2,
            )

        self.cache.put(src_hash, res)
        return res

    def _compute_fitness(self, res: BuildResult, src_hash: str) -> float:
        if not res.ok or res.obj_bytes is None:
            console.print(f"[{src_hash}] Error during compilation/parsing: {res.error_msg}")
            return 10000000.0
        obj_bytes = res.obj_bytes
        if len(obj_bytes) > len(self.target_bytes):
            console.print(
                f"[{src_hash}] Candidate {len(obj_bytes)}B > target {len(self.target_bytes)}B, truncating"
            )
            obj_bytes = obj_bytes[: len(self.target_bytes)]
        sc = score_candidate(self.target_bytes, obj_bytes, res.reloc_offsets)
        console.print(f"[{src_hash}] SUCCESS. Score={sc.total} (len_bytes={len(obj_bytes)})")
        return sc.total

    def run(self) -> tuple[str | None, float]:
        """Run the GA and return ``(best_source, best_score)``."""
        for gen in range(self.num_generations):
            gen_start = time.time()
            scored_pop = []
            with ThreadPoolExecutor(max_workers=self.num_jobs) as executor:
                futures = {
                    executor.submit(self._compile_source, src): src for src in self.population
                }
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                    except (
                        FileNotFoundError,
                        OSError,
                        ValueError,
                        RuntimeError,
                        subprocess.SubprocessError,
                    ) as exc:
                        res = BuildResult(
                            ok=False, error_msg=f"exception during compilation: {exc}"
                        )
                    src_hash = hashlib.sha256(futures[fut].encode()).hexdigest()[:8]
                    scored_pop.append((self._compute_fitness(res, src_hash), futures[fut]))

            scored_pop.sort(key=lambda x: x[0])
            best_score, best_src = scored_pop[0]
            diversity = compute_population_diversity(self.population)

            if best_score < self.best_score:
                self.best_score = best_score
                self.best_source = best_src
                self.stagnant_gens = 0
                atomic_write_text(self.out_dir / "best.c", best_src, encoding="utf-8")
            else:
                self.stagnant_gens += 1

            self.elapsed_sec += time.time() - gen_start
            if self.verbose:
                console.print(
                    f"gen={gen:03d} best={best_score:.2f} div={diversity:.2f} stag={self.stagnant_gens}"
                )

            if best_score < 0.1 or self.stagnant_gens >= self.stagnation_limit:
                break

            elite = [s[1] for s in scored_pop[: self.elitism]]
            next_pop = elite.copy()
            max_attempts = self.pop_size * 10
            attempts = 0
            while len(next_pop) < self.pop_size and attempts < max_attempts:
                attempts += 1
                p1 = self.rng.choice(elite)
                if self.rng.random() < self.crossover_prob:
                    p2 = self.rng.choice(elite)
                    child = crossover(p1, p2, self.rng)
                else:
                    child = p1

                if self.rng.random() < self.mutation_prob:
                    child = mutate_code(child, self.rng, mutation_weights=self.mutation_weights)

                if quick_validate(child):
                    next_pop.append(child)

            # Pad with elite copies if mutations failed validation
            while len(next_pop) < self.pop_size:
                next_pop.append(self.rng.choice(elite))

            self.population = next_pop

        return self.best_source, self.best_score


_EPILOG = """\
[bold]Modes:[/bold]

rebrew match src/f.c --flag-sweep-only          Find best compiler flags

rebrew match src/f.c                            Full GA matching run

[bold]Examples:[/bold]

rebrew match src/game/my_func.c --flag-sweep-only --tier targeted

rebrew match src/game/my_func.c --generations 200 --pop-size 48 -j 8

rebrew match src/game/my_func.c --seed 42       Reproducible GA run

rebrew match src/f.c --flag-sweep-only --json   JSON flag sweep results

rebrew match src/f.c --json                     JSON GA results

[bold]Byte diff:[/bold]

Use [bold]rebrew diff src/f.c[/bold] to show a byte diff before running the GA.

[bold]Flag sweep tiers:[/bold]

quick      ~192 combos     Fast iteration

targeted   ~1.1K combos    Codegen-altering flags only (/Oy, /Op)

normal     ~21K combos     Default sweep

thorough   ~1M combos      Deep search

full       ~8.3M combos    Exhaustive (needs sampling)

[dim]Auto-reads VA, SIZE, and CFLAGS from source annotations.
Symbol is derived from the C function definition.
Requires rebrew-project.toml with valid compiler paths.[/dim]"""

app = typer.Typer(
    help="GA engine for binary matching (diff, flag-sweep, GA).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    seed_c: str = typer.Argument(..., help="Seed source file (.c)"),
    cl: str | None = typer.Option(None, help="CL.EXE command (auto from rebrew-project.toml)"),
    inc: str | None = typer.Option(None, help="Include dir (auto from rebrew-project.toml)"),
    cflags: str | None = typer.Option(None, help="Compiler flags (auto from source)"),
    symbol: str | None = typer.Option(None, "-s", help="Symbol to match (auto from source)"),
    target_va: str | None = typer.Option(None, help="Target VA hex (auto from source)"),
    target_size: int | None = typer.Option(None, help="Target size (auto from source)"),
    out_dir: str = typer.Option("output/ga_run", help="Output dir"),
    generations: int = typer.Option(100, "-g", help="Number of GA generations"),
    pop_size: int = typer.Option(32, "-p", help="Population size per generation"),
    jobs: int = typer.Option(4, "-j", help="Number of parallel compile jobs"),
    compare_obj: bool = typer.Option(True, help="Use object comparison instead of full link"),
    link: str | None = typer.Option(None, help="LINK.EXE command"),
    lib: str | None = typer.Option(None, help="Lib dir"),
    ldflags: str | None = typer.Option(None, help="Linker flags"),
    flag_sweep_only: bool = typer.Option(
        False, "--flag-sweep-only", "-S", help="Run compiler flag sweep instead of GA"
    ),
    tier: str = typer.Option(
        "targeted",
        help="Flag sweep tier: quick (~192), targeted (~1.1K), normal (~21K), thorough (~258K), full.",
    ),
    force: bool = typer.Option(
        False, "--force", help="Continue even if annotation lint errors exist"
    ),
    seed: int | None = typer.Option(None, "--seed", help="RNG seed for reproducible GA runs"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    extra_seed: list[str] | None = typer.Option(
        None, "--extra-seed", help="Extra .c file(s) to seed GA population from solved functions"
    ),
    no_seed: bool = typer.Option(
        False, "--no-seed", help="Disable cross-function solution seeding"
    ),
    target: str | None = TargetOption,
) -> None:
    """Genetic Algorithm engine for binary matching (flag sweep or GA)."""
    cfg = require_config(target=target, json_mode=json_output)
    params = _resolve_build_params(
        cfg, seed_c, cl, inc, cflags, symbol, target_va, target_size, force, json_output
    )

    if flag_sweep_only:
        _run_flag_sweep(params, tier, jobs, json_output)
        return

    # Default: GA run
    _run_ga(
        params,
        out_dir,
        generations,
        pop_size,
        jobs,
        compare_obj,
        link,
        lib,
        ldflags,
        seed,
        json_output,
        extra_seed,
        no_seed,
    )


# ---------------------------------------------------------------------------
# Build parameter resolution
# ---------------------------------------------------------------------------


@dataclass
class _BuildParams:
    """Resolved build parameters shared across all modes."""

    cfg: Any
    seed_c: str
    seed_src: str
    cl: str
    inc: str
    cflags: str
    symbol: str
    target_bytes: bytes
    va_int: int
    target_size: int
    msvc_env: dict[str, str] | None
    cc: Any  # CompileCache | None


def _resolve_build_params(
    cfg: Any,
    seed_c: str,
    cl: str | None,
    inc: str | None,
    cflags: str | None,
    symbol: str | None,
    target_va: str | None,
    target_size: int | None,
    force: bool,
    json_output: bool,
) -> _BuildParams:
    """Resolve config, annotations, compiler, and target bytes into build params."""
    try:
        cc = get_compile_cache(cfg.root)
    except OSError:
        cc = None

    # Build name -> VA map for relocation validation
    name_to_va: dict[str, int] = {}
    try:
        from rebrew.data import scan_globals

        scan = scan_globals(cfg.reversed_dir, cfg)
        for entry in scan.data_annotations:
            name = entry.get("name", "")
            va_int = entry.get("va")
            if isinstance(name, str) and isinstance(va_int, int) and name:
                name_to_va[name] = va_int
        for name, glob in scan.globals.items():
            if glob.va:
                name_to_va[name] = glob.va
    except (OSError, AttributeError, KeyError, ValueError):
        pass

    annos = parse_c_file_multi(
        Path(seed_c), target_name=target_marker(cfg), sidecar_dir=Path(seed_c).parent
    )
    anno = annos[0] if annos else None
    if anno:
        eval_errs, eval_warns = anno.validate()
        if not json_output:
            for e in eval_errs:
                console.print(f"[bold red]LINT ERROR:[/bold red] {e}")
            for w in eval_warns:
                console.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")
        if eval_errs and not force:
            if json_output:
                error_exit("Annotation lint errors", json_mode=True)
            else:
                error_exit(
                    "Aborting due to annotation errors. Fix them or use --force to override."
                )

    meta = parse_source_metadata(seed_c)
    compile_cfg = cfg
    msvc_env = msvc_env_from_config(compile_cfg)
    if cl is None or (compile_cfg.compiler_runner and cl == compile_cfg.compiler_command):
        cl = " ".join(resolve_cl_command(compile_cfg))
    inc = inc or str(compile_cfg.compiler_includes)

    try:
        cl_parts = shlex.split(cl)
    except ValueError:
        cl_parts = cl.split()
    cl_resolved = []
    for part in cl_parts:
        p = cfg.root / part
        cl_resolved.append(str(p) if p.exists() else part)
    cl = " ".join(cl_resolved)

    inc_path = cfg.root / inc
    if inc_path.exists():
        inc = str(inc_path)

    if not symbol and anno:
        symbol = anno.symbol
    if not symbol:
        error_exit(
            "--symbol required (could not derive from C function definition)", json_mode=json_output
        )

    if not cflags:
        cflags = meta.get("CFLAGS", "/O2 /Gd")
    if "/c" not in cflags:
        cflags = "/nologo /c " + cflags

    if not target_va:
        for marker_key in ("FUNCTION", "LIBRARY", "STUB"):
            func_meta = meta.get(marker_key)
            if func_meta and "0x" in func_meta:
                after_hex = func_meta.split("0x")[1].split()
                if after_hex:
                    target_va = "0x" + after_hex[0]
                    break

    if target_size is None and "SIZE" in meta:
        try:
            target_size = int(meta["SIZE"])
        except ValueError:
            error_exit(f"Invalid SIZE annotation: {meta['SIZE']!r}")

    if target_va and target_size:
        va_int = parse_va(target_va, json_mode=json_output)
        target_bytes = extract_raw_bytes(cfg.target_binary, va_int, target_size)
    else:
        error_exit("Need VA and SIZE (from source annotations or CLI)", json_mode=json_output)

    if not target_bytes:
        error_exit("Could not extract target bytes", json_mode=json_output)

    seed_src = Path(seed_c).read_text(encoding="utf-8")

    return _BuildParams(
        cfg=cfg,
        seed_c=seed_c,
        seed_src=seed_src,
        cl=cl,
        inc=inc,
        cflags=cflags,
        symbol=symbol,
        target_bytes=target_bytes,
        va_int=va_int,
        target_size=target_size,
        msvc_env=msvc_env,
        cc=cc,
    )


# ---------------------------------------------------------------------------
# Mode: --flag-sweep-only
# ---------------------------------------------------------------------------


def _run_flag_sweep(
    p: _BuildParams,
    tier: str,
    jobs: int,
    json_output: bool,
) -> None:
    """Run compiler flag sweep and report results."""
    results = flag_sweep(
        p.seed_src,
        p.target_bytes,
        p.cl,
        p.inc,
        p.cflags,
        p.symbol,
        jobs,
        tier=tier,
        env=p.msvc_env,
        cache=p.cc,
        timeout=p.cfg.compile_timeout,
    )

    sim_res = None
    res = build_candidate_obj_only(
        p.seed_src,
        p.cl,
        p.inc,
        p.cflags,
        p.symbol,
        env=p.msvc_env,
        cache=p.cc,
        timeout=p.cfg.compile_timeout,
    )
    if res.ok and res.obj_bytes:
        obj_bytes = res.obj_bytes
        if len(obj_bytes) > len(p.target_bytes):
            obj_bytes = obj_bytes[: len(p.target_bytes)]
        sim_res = structural_similarity(p.target_bytes, obj_bytes, res.reloc_offsets)

    best_score = results[0][0] if results else float("inf")

    if json_output:
        sweep_items = [{"score": round(s, 2), "flags": f} for s, f in results[:20]]
        payload: dict[str, Any] = {
            "source": p.seed_c,
            "symbol": p.symbol,
            "mode": "flag_sweep",
            "tier": tier,
            "best_score": round(best_score, 2) if best_score < float("inf") else None,
            "best_flags": results[0][1] if results else None,
            "exact": best_score < 0.1,
            "results": sweep_items,
        }
        if sim_res is not None:
            payload["structural_similarity"] = {
                "total_insns": sim_res.total_insns,
                "exact": sim_res.exact,
                "reloc_only": sim_res.reloc_only,
                "register_only": sim_res.register_only,
                "structural": sim_res.structural,
                "mnemonic_match_ratio": sim_res.mnemonic_match_ratio,
                "structural_ratio": sim_res.structural_ratio,
                "flag_sensitive": sim_res.flag_sensitive,
            }
        json_print(payload)
    else:
        for score, flags in results[:10]:
            console.print(f"{score:.2f}: {flags}")
        if sim_res is not None:
            _print_structural_similarity(sim_res)

    if best_score < 0.1:
        return
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Mode: GA run (default)
# ---------------------------------------------------------------------------


def _run_ga(
    p: _BuildParams,
    out_dir: str,
    generations: int,
    pop_size: int,
    jobs: int,
    compare_obj: bool,
    link: str | None,
    lib: str | None,
    ldflags: str | None,
    seed: int | None,
    json_output: bool,
    extra_seed: list[str] | None,
    no_seed: bool,
) -> None:
    """Run the full GA matching engine."""
    out_dir_path = Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)

    loaded_seeds: list[str] = []
    if not no_seed and extra_seed:
        for extra_path in extra_seed:
            ep = Path(extra_path)
            if ep.exists():
                loaded_seeds.append(ep.read_text(encoding="utf-8", errors="replace"))

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
        link_cmd=link,
        lib_dir=lib,
        ldflags=ldflags,
        env=p.msvc_env,
        rng_seed=seed,
        compile_cache=p.cc,
        compile_timeout=p.cfg.compile_timeout,
        verbose=0 if json_output else 1,
        extra_seeds=loaded_seeds or None,
    )
    best_src, best_score = ga.run()

    if json_output:
        ga_payload: dict[str, Any] = {
            "source": p.seed_c,
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
        typer.echo(f"\nDone. Best score: {best_score:.2f}", err=True)
        if best_score < 0.1:
            typer.echo("EXACT MATCH", err=True)

    # Save solution on exact match
    if best_score < 0.1:
        try:
            from rebrew.solutions import SolutionEntry, save_solution

            entry = SolutionEntry(
                symbol=p.symbol,
                cflags=p.cflags,
                size=p.target_size or 0,
                source_file=p.seed_c,
                score=best_score,
                generations=generations,
            )
            save_solution(p.cfg.root, entry)
        except Exception:  # noqa: BLE001
            log.debug("Solution save failed", exc_info=True)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
