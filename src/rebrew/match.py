#!/usr/bin/env python3
"""Genetic Algorithm engine for binary matching.

Compile C source, compare object bytes against a target function, and
iteratively mutate to find a byte-perfect or relocation-normalized match.

Usage:
    rebrew match <source.c> [--diff-only] [--flag-sweep-only --tier TIER]
"""

import hashlib
import json
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import rich
import typer

from rebrew.annotation import parse_c_file, parse_source_metadata
from rebrew.cli import TargetOption, get_config
from rebrew.matcher import (
    BuildCache,
    BuildResult,
    build_candidate,
    build_candidate_obj_only,
    compute_population_diversity,
    crossover,
    diff_functions,
    flag_sweep,
    mutate_code,
    score_candidate,
)
from rebrew.matcher.mutator import quick_validate


def classify_blockers(diff_summary: dict[str, Any]) -> list[str]:
    """Auto-classify MATCHING blockers from structural diffs.

    Looks for patterns in mismatched (** / RR) lines to identify systemic
    compiler differences like register allocation, loop rotation, etc.
    """
    blockers = set()
    insns = diff_summary.get("instructions", [])

    for row in insns:
        match_char = row.get("match")
        if match_char not in ("**", "RR"):
            continue

        t = row.get("target") or {}
        c = row.get("candidate") or {}
        t_asm = t.get("disasm", "")
        c_asm = c.get("disasm", "")

        # Register allocation
        if match_char == "RR":
            blockers.add("register allocation")
            continue

        t_mnem = t_asm.split()[0] if t_asm else ""
        c_mnem = c_asm.split()[0] if c_asm else ""

        # Loop rotation / jump conditions
        if (t_mnem.startswith("j") and c_mnem.startswith("j")) and t_mnem != c_mnem:
            if t_mnem != "jmp" and c_mnem != "jmp":
                blockers.add("jump condition swap")
            else:
                blockers.add("loop rotation / branch layout")

        # Zero-extend patterns
        if ("xor" in t_mnem and "mov" in c_mnem) or ("mov" in t_mnem and "xor" in c_mnem):
            blockers.add("zero-extend pattern (xor vs mov)")

        # Comparison direction swap
        if t_mnem == "cmp" and c_mnem == "cmp" and t_asm != c_asm:
            blockers.add("comparison direction swap")

        # Stack frame choice
        if ("push" in t_mnem and "sub esp" in c_asm) or ("sub esp" in t_asm and "push" in c_mnem):
            blockers.add("stack frame choice (push vs sub esp)")

        # Instruction folding (lea vs mov)
        if ("lea" in t_mnem and "mov" in c_mnem) or ("mov" in t_mnem and "lea" in c_mnem):
            blockers.add("instruction folding (lea vs mov)")

    return sorted(list(blockers))


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
    ) -> None:
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

        self.rng = random.Random(rng_seed)
        self.mutation_weights = mutation_weights or {}

        self.population: list[str] = []
        self.best_source: str | None = None
        self.best_score: float = float("inf")
        self.stagnant_gens: int = 0
        self.elapsed_sec: float = 0.0

        self.cache = BuildCache(str(self.out_dir / "build_cache.db"))

        self._init_population()

    def _init_population(self) -> None:
        self.population = [self.seed_source]
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
                src, self.cl_cmd, self.inc_dir, self.cflags, self.symbol, env=self.env
            )
        else:
            res = build_candidate(
                src,
                self.cl_cmd,
                self.link_cmd,
                self.inc_dir,
                self.lib_dir,
                self.cflags,
                self.ldflags,
                self.symbol,
                env=self.env,
            )

        self.cache.put(src_hash, res)
        return res

    def _compute_fitness(self, res: BuildResult, src_hash: str) -> float:
        if not res.ok or res.obj_bytes is None:
            print(f"[{src_hash}] Error during compilation/parsing: {res.error_msg}")
            return 10000000.0
        obj_bytes = res.obj_bytes
        if len(obj_bytes) > len(self.target_bytes):
            print(
                f"[{src_hash}] Candidate {len(obj_bytes)}B > target {len(self.target_bytes)}B, truncating"
            )
            obj_bytes = obj_bytes[: len(self.target_bytes)]
        sc = score_candidate(self.target_bytes, obj_bytes, res.reloc_offsets)
        print(f"[{src_hash}] SUCCESS. Score={sc.total} (len_bytes={len(obj_bytes)})")
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
                (self.out_dir / "best.c").write_text(best_src, encoding="utf-8")
            else:
                self.stagnant_gens += 1

            self.elapsed_sec += time.time() - gen_start
            if self.verbose:
                print(
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
  rebrew match src/f.c --diff-only               Show byte diff vs target
  rebrew match src/f.c --diff-only --mm          Show only structural diffs (**)
  rebrew match src/f.c --flag-sweep-only          Find best compiler flags
  rebrew match src/f.c                            Full GA matching run

[bold]Examples:[/bold]
  rebrew match src/game/my_func.c --diff-only
  rebrew match src/game/my_func.c --flag-sweep-only --tier quick
  rebrew match src/game/my_func.c --generations 200 --pop-size 48 -j 8
  rebrew match src/game/my_func.c --seed 42       Reproducible GA run
  rebrew match src/f.c --diff-only --json          JSON structured diff

[bold]Flag sweep tiers:[/bold]
  quick      ~192 combos     Fast iteration
  normal     ~21K combos     Default sweep
  thorough   ~1M combos      Deep search
  full       ~8.3M combos    Exhaustive (needs sampling)

[dim]Auto-reads VA, SIZE, SYMBOL, and CFLAGS from source annotations.
Requires rebrew.toml with valid compiler paths.[/dim]"""

app = typer.Typer(
    help="GA engine for binary matching (diff, flag-sweep, GA).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    seed_c: str = typer.Argument(..., help="Seed source file (.c)"),
    cl: str | None = typer.Option(None, help="CL.EXE command (auto from rebrew.toml)"),
    inc: str | None = typer.Option(None, help="Include dir (auto from rebrew.toml)"),
    cflags: str | None = typer.Option(None, help="Compiler flags (auto from source)"),
    symbol: str | None = typer.Option(None, help="Symbol to match (auto from source)"),
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
    diff_only: bool = typer.Option(
        False, "--diff-only", help="Show diff for seed file, don't run GA"
    ),
    mismatches_only: bool = typer.Option(
        False,
        "--mismatches-only",
        "--mm",
        help="With --diff-only, show only ** (structural diff) lines",
    ),
    register_aware: bool = typer.Option(
        False,
        "--register-aware",
        "--rr",
        help="With --diff-only, normalize register encodings and mark differences as RR",
    ),
    flag_sweep_only: bool = typer.Option(False),
    tier: str = typer.Option(
        "quick",
        help="Flag sweep tier: quick, normal, thorough, full. Note: 'thorough' produces 258k+ combinations. Consider using 'quick' or 'normal' tier, or use sampling.",
    ),
    force: bool = typer.Option(
        False, "--force", help="Continue even if annotation lint errors exist"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON (only with --diff-only)"
    ),
    seed: int | None = typer.Option(None, "--seed", help="RNG seed for reproducible GA runs"),
) -> None:
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
        p = cfg.root / part
        cl_resolved.append(str(p) if p.exists() else part)
    cl = " ".join(cl_resolved)

    inc_path = cfg.root / inc
    if inc_path.exists():
        inc = str(inc_path)

    # Lint gate: validate annotations before proceeding
    anno = parse_c_file(Path(seed_c))
    if anno:
        eval_errs, eval_warns = anno.validate()
        if not json_output:
            for e in eval_errs:
                rich.print(f"[bold red]LINT ERROR:[/bold red] {e}")
            for w in eval_warns:
                rich.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")
        if eval_errs and not force:
            if json_output:
                print(
                    json.dumps({"error": "Annotation lint errors", "details": eval_errs}, indent=2)
                )
            else:
                rich.print(
                    "\n[bold red]Aborting due to annotation errors. "
                    "Fix them or use --force to override.[/bold red]"
                )
            raise typer.Exit(code=1)

    # Auto-fill from source file metadata
    meta = parse_source_metadata(seed_c)

    if not symbol:
        symbol = meta.get("SYMBOL")
    if not symbol:
        if json_output:
            print(
                json.dumps(
                    {"error": "--symbol required (not found in source annotations)"}, indent=2
                )
            )
        else:
            print("ERROR: --symbol required (not found in source annotations)", file=sys.stderr)
        raise typer.Exit(code=1)

    if not cflags:
        # Fallback default — should be set via annotation or config cflags_presets.
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
        try:
            target_size = int(meta["SIZE"])
        except ValueError:
            print(f"ERROR: Invalid SIZE annotation: {meta['SIZE']!r}", file=sys.stderr)
            raise typer.Exit(code=1)

    # Extract target bytes from offset in the configured binary
    if target_va and target_size:
        va_int = int(target_va, 16)
        target_bytes = cfg.extract_dll_bytes(va_int, target_size)
    else:
        if json_output:
            print(
                json.dumps({"error": "Need VA and SIZE (from source annotations or CLI)"}, indent=2)
            )
        else:
            print("ERROR: Need VA and SIZE (from source annotations or CLI)", file=sys.stderr)
        raise typer.Exit(code=1)

    if not target_bytes:
        if json_output:
            print(json.dumps({"error": "Could not extract target bytes"}, indent=2))
        else:
            print("Error: Could not extract target bytes", file=sys.stderr)
        raise typer.Exit(code=1)

    seed_src = Path(seed_c).read_text(encoding="utf-8")
    out_dir_path = Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)

    if diff_only:
        res = build_candidate_obj_only(seed_src, cl, inc, cflags, symbol, env=msvc_env)
        if res.ok and res.obj_bytes:
            obj_bytes = res.obj_bytes
            if len(obj_bytes) > len(target_bytes):
                obj_bytes = obj_bytes[: len(target_bytes)]
            summary = diff_functions(
                target_bytes,
                obj_bytes,
                res.reloc_offsets,
                mismatches_only=mismatches_only,
                register_aware=register_aware,
                as_dict=True,
            )
            if json_output:
                print(json.dumps(summary, indent=2))
            else:
                # Print human-readable diff
                diff_functions(
                    target_bytes,
                    obj_bytes,
                    res.reloc_offsets,
                    mismatches_only=mismatches_only,
                    register_aware=register_aware,
                )

            has_structural = False
            if summary:
                blockers = classify_blockers(summary)
                if not json_output and blockers:
                    print("\nAuto-classified blockers:")
                    for b in blockers:
                        print(f"  - {b}")
                elif json_output:
                    pass
                has_structural = summary["summary"]["structural"] > 0
            if has_structural:
                raise typer.Exit(code=1)
            return
        else:
            if json_output:
                print(json.dumps({"error": f"Build failed: {res.error_msg}"}, indent=2))
            else:
                print(f"Build failed: {res.error_msg}")
            raise typer.Exit(code=2)

    if flag_sweep_only:
        results = flag_sweep(
            seed_src, target_bytes, cl, inc, cflags, symbol, jobs, tier=tier, env=msvc_env
        )
        for score, flags in results[:10]:
            print(f"{score:.2f}: {flags}")
        best_score = results[0][0] if results else float("inf")
        if best_score < 0.1:
            return
        raise typer.Exit(code=1)

    ga = BinaryMatchingGA(
        seed_src,
        target_bytes,
        cl,
        inc,
        cflags,
        symbol,
        out_dir_path,
        pop_size=pop_size,
        num_generations=generations,
        num_jobs=jobs,
        compare_obj=compare_obj,
        link_cmd=link,
        lib_dir=lib,
        ldflags=ldflags,
        env=msvc_env,
        rng_seed=seed,
    )
    _, best_score = ga.run()
    print(f"\nDone. Best score: {best_score:.2f}", file=sys.stderr)
    if best_score < 0.1:
        print("EXACT MATCH", file=sys.stderr)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
