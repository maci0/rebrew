#!/usr/bin/env python3
"""Genetic Algorithm engine for binary matching.

Compile C source, compare object bytes against a target function, and
iteratively mutate to find a byte-perfect or relocation-normalized match.

Usage:
    rebrew-match <source.c> [--diff-only] [--flag-sweep-only --tier TIER]
"""

import hashlib
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rebrew.matcher import (
    BuildCache,
    BuildResult,
    _quick_validate,
    build_candidate,
    build_candidate_obj_only,
    compute_population_diversity,
    crossover,
    diff_functions,
    flag_sweep,
    mutate_code,
    score_candidate,
)


class BinaryMatchingGA:
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
        num_parents_mating: int = 8,
        mutation_prob: float = 0.3,
        crossover_prob: float = 0.7,
        elitism: int = 4,
        num_jobs: int = 4,
        training_output: Path | None = None,
        mutation_weights: dict[str, float] | None = None,
        stagnation_limit: int = 20,
        adaptive_mutation: bool = False,
        checkpoint_every: int = 5,
        verbose: int = 1,
        rng_seed: int | None = None,
        compare_obj: bool = True,
        link_cmd: str | None = None,
        lib_dir: str | None = None,
        ldflags: str | None = None,
    ):
        self.seed_source = seed_source
        self.target_bytes = target_bytes
        self.cl_cmd = cl_cmd
        self.inc_dir = inc_dir
        self.cflags = cflags
        self.symbol = symbol
        self.out_dir = Path(out_dir)
        self.pop_size = pop_size
        self.num_generations = num_generations
        self.num_parents_mating = num_parents_mating
        self.mutation_prob = mutation_prob
        self.crossover_prob = crossover_prob
        self.elitism = elitism
        self.num_jobs = num_jobs
        self.stagnation_limit = stagnation_limit
        self.adaptive_mutation = adaptive_mutation
        self.checkpoint_every = checkpoint_every
        self.verbose = verbose
        self.rng_seed = rng_seed
        self.compare_obj = compare_obj
        self.link_cmd = link_cmd
        self.lib_dir = lib_dir
        self.ldflags = ldflags

        self.rng = random.Random(rng_seed)
        self.mutation_weights = mutation_weights or {}

        self.population: list[str] = []
        self.best_source: str | None = None
        self.best_score: float = float("inf")
        self.generation_stats: list[dict] = []
        self.stagnant_gens: int = 0
        self.elapsed_sec: float = 0.0

        self.cache = BuildCache(str(self.out_dir / "build_cache.db"))
        self.lock = threading.Lock()

        self._init_population()

    def _init_population(self):
        self.population = [self.seed_source]
        while len(self.population) < self.pop_size:
            src = self.seed_source
            for _ in range(self.rng.randint(1, 4)):
                src = mutate_code(src, self.rng, mutation_weights=self.mutation_weights)
            self.population.append(src)

    def _compile_source(self, src: str) -> BuildResult:
        src_hash = hashlib.sha256(src.encode()).hexdigest()[:16]
        res = self.cache.get(src_hash)
        if res: return res

        if self.compare_obj:
            res = build_candidate_obj_only(src, self.cl_cmd, self.inc_dir, self.cflags, self.symbol)
        else:
            res = build_candidate(src, self.cl_cmd, self.link_cmd, self.inc_dir, self.lib_dir, self.cflags, self.ldflags, self.symbol)

        self.cache.put(src_hash, res)
        return res

    def _compute_fitness(self, res: BuildResult) -> float:
        if not res.ok or res.obj_bytes is None: return 10000.0
        obj_bytes = res.obj_bytes
        if len(obj_bytes) > len(self.target_bytes):
            obj_bytes = obj_bytes[:len(self.target_bytes)]
        sc = score_candidate(self.target_bytes, obj_bytes, res.reloc_offsets)
        return sc.total

    def run(self) -> tuple[str | None, float]:
        start_time = time.time()
        for gen in range(self.num_generations):
            gen_start = time.time()
            scored_pop = []
            with ThreadPoolExecutor(max_workers=self.num_jobs) as executor:
                futures = {executor.submit(self._compile_source, src): src for src in self.population}
                for fut in as_completed(futures):
                    res = fut.result()
                    scored_pop.append((self._compute_fitness(res), futures[fut]))

            scored_pop.sort(key=lambda x: x[0])
            best_score, best_src = scored_pop[0]
            diversity = compute_population_diversity(self.population)

            if best_score < self.best_score:
                self.best_score = best_score
                self.best_source = best_src
                self.stagnant_gens = 0
                (self.out_dir / "best.c").write_text(best_src)
            else:
                self.stagnant_gens += 1

            self.elapsed_sec += time.time() - gen_start
            if self.verbose:
                print(f"gen={gen:03d} best={best_score:.2f} div={diversity:.2f} stag={self.stagnant_gens}")

            if best_score < 0.1 or self.stagnant_gens >= self.stagnation_limit: break

            elite = [s[1] for s in scored_pop[:self.elitism]]
            next_pop = elite.copy()
            while len(next_pop) < self.pop_size:
                p1 = self.rng.choice(elite)
                if self.rng.random() < self.crossover_prob:
                    p2 = self.rng.choice(elite)
                    child = crossover(p1, p2, self.rng)
                else:
                    child = p1

                if self.rng.random() < self.mutation_prob:
                    child = mutate_code(child, self.rng, mutation_weights=self.mutation_weights)

                if _quick_validate(child): next_pop.append(child)

            self.population = next_pop

        return self.best_source, self.best_score

import typer
import rich

from pathlib import Path
from rebrew.cli import TargetOption, get_config
from rebrew.test import parse_source_metadata
from rebrew.annotation import parse_c_file

app = typer.Typer(help="GA engine for binary matching (diff, flag-sweep, GA).")


@app.command()
def main(
    seed_c: str = typer.Argument(..., help="Seed source file (.c)"),
    cl: str | None = typer.Option(None, help="CL.EXE command (auto from rebrew.toml)"),
    inc: str | None = typer.Option(None, help="Include dir (auto from rebrew.toml)"),
    cflags: str | None = typer.Option(None, help="Compiler flags (auto from source)"),
    symbol: str | None = typer.Option(None, help="Symbol to match (auto from source)"),
    target_exe: str | None = typer.Option(None, help="Target EXE (auto from rebrew.toml)"),
    target_va: str | None = typer.Option(None, help="Target VA hex (auto from source)"),
    target_size: int | None = typer.Option(None, help="Target size (auto from source)"),
    target: str | None = TargetOption,
    out_dir: str = typer.Option("output/ga_run", help="Output dir"),
    generations: int = typer.Option(100),
    pop_size: int = typer.Option(32),
    jobs: int = typer.Option(4, "-j"),
    compare_obj: bool = typer.Option(True, help="Use object comparison instead of full link"),
    link: str | None = typer.Option(None, help="LINK.EXE command"),
    lib: str | None = typer.Option(None, help="Lib dir"),
    ldflags: str | None = typer.Option(None, help="Linker flags"),

    diff_only: bool = typer.Option(False, "--diff-only", help="Show diff for seed file, don't run GA"),
    flag_sweep_only: bool = typer.Option(False),
    tier: str = typer.Option("quick", help="Flag sweep tier: quick, normal, thorough, full"),
):
    """Genetic Algorithm engine for binary matching."""
    # Auto-fill from rebrew.toml config
    cfg = get_config(target=target)
    msvc_env = cfg.msvc_env()
    cl = cl or cfg.compiler_command
    inc = inc or str(cfg.compiler_includes)

    # Resolve relative paths to absolute using project root so they work
    # from temp directories used by build_candidate_obj_only
    cl_parts = cl.split()
    cl_resolved = []
    for part in cl_parts:
        p = (cfg.root / part)
        cl_resolved.append(str(p) if p.exists() else part)
    cl = " ".join(cl_resolved)

    inc_path = cfg.root / inc
    if inc_path.exists():
        inc = str(inc_path)

    # Optional: lint the file first to catch basic annotation errors
    anno = parse_c_file(Path(seed_c))
    if anno:
        eval_errs, eval_warns = anno.validate()
        for e in eval_errs:
            rich.print(f"[bold red]LINT ERROR:[/bold red] {e}")
        for w in eval_warns:
            rich.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")

    # Auto-fill from source file metadata
    meta = parse_source_metadata(seed_c)

    if not symbol:
        symbol = meta.get("SYMBOL")
    if not symbol:
        print("ERROR: --symbol required (not found in source annotations)")
        raise typer.Exit(code=1)

    if not cflags:
        cflags = meta.get("CFLAGS", "/O2 /Gd")
    # Ensure compile-only flags are present
    if "/c" not in cflags:
        cflags = "/nologo /c " + cflags

    if not target_va:
        for marker_key in ("FUNCTION", "LIBRARY", "STUB"):
            func_meta = meta.get(marker_key)
            if func_meta and "0x" in func_meta:
                target_va = "0x" + func_meta.split("0x")[1].split()[0]
                break

    if target_size is None and "SIZE" in meta:
        target_size = int(meta["SIZE"])

    # Extract target bytes from offset in the configured binary
    if target_va and target_size:
        va_int = int(target_va, 16)
        target_bytes = cfg.extract_dll_bytes(va_int, target_size)
    else:
        print("ERROR: Need VA and SIZE (from source annotations or CLI)")
        raise typer.Exit(code=1)

    if not target_bytes:
        print("Error: Could not extract target bytes")
        raise typer.Exit(code=1)

    seed_src = Path(seed_c).read_text()
    out_dir_path = Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)

    if diff_only:
        res = build_candidate_obj_only(seed_src, cl, inc, cflags, symbol, env=msvc_env)
        if res.ok and res.obj_bytes:
            obj_bytes = res.obj_bytes
            if len(obj_bytes) > len(target_bytes):
                obj_bytes = obj_bytes[:len(target_bytes)]
            diff_functions(target_bytes, obj_bytes, res.reloc_offsets)
        else:
            print(f"Build failed: {res.error_msg}")
        raise typer.Exit(code=0)

    if flag_sweep_only:
        results = flag_sweep(seed_src, target_bytes, cl, inc, cflags, symbol, jobs, tier=tier)
        for score, flags in results[:10]:
            print(f"{score:.2f}: {flags}")
        raise typer.Exit(code=0)

    ga = BinaryMatchingGA(seed_src, target_bytes, cl, inc, cflags, symbol, out_dir_path,
                          pop_size=pop_size, num_generations=generations, num_jobs=jobs,
                          compare_obj=compare_obj, link_cmd=link, lib_dir=lib, ldflags=ldflags)
    best_src, best_score = ga.run()
    print(f"\nDone. Best score: {best_score:.2f}")

def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
