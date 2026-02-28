#!/usr/bin/env python3
"""Genetic Algorithm engine for binary matching.

Compile C source, compare object bytes against a target function, and
iteratively mutate to find a byte-perfect or relocation-normalized match.

Usage:
    rebrew match <source.c> [--diff-only] [--flag-sweep-only --tier TIER]
"""

import hashlib
import random
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import rich
import typer

from rebrew.annotation import parse_c_file, parse_source_metadata
from rebrew.cli import TargetOption, error_exit, get_config, json_print, parse_va
from rebrew.compile import resolve_cl_command
from rebrew.matcher import (
    BuildCache,
    BuildResult,
    StructuralSimilarity,
    build_candidate,
    build_candidate_obj_only,
    compute_population_diversity,
    crossover,
    diff_functions,
    flag_sweep,
    mutate_code,
    score_candidate,
    structural_similarity,
)
from rebrew.matcher.mutator import quick_validate
from rebrew.utils import atomic_write_text


def _print_structural_similarity(sim: StructuralSimilarity) -> None:
    verdict = "flag sweep MAY help" if sim.flag_sensitive else "flags unlikely to help"
    print(f"\nStructural similarity ({verdict}):")
    print(
        f"  Instructions: {sim.exact} exact, {sim.reloc_only} reloc, "
        f"{sim.register_only} register, {sim.structural} structural "
        f"(of {sim.total_insns} total)"
    )
    print(
        f"  Mnemonic match: {sim.mnemonic_match_ratio:.1%}  |  "
        f"Structural ratio: {sim.structural_ratio:.1%}"
    )


def classify_blockers(diff_summary: dict[str, object]) -> list[str]:
    """Auto-classify MATCHING blockers from structural diffs.

    Looks for patterns in mismatched (** / RR) lines to identify systemic
    compiler differences like register allocation, loop rotation, etc.
    """
    blockers = set()
    insns_raw = diff_summary.get("instructions", [])
    insns = insns_raw if isinstance(insns_raw, list) else []

    for row in insns:
        if not isinstance(row, dict):
            continue
        match_char = row.get("match")
        if match_char not in ("**", "RR"):
            continue

        t_obj = row.get("target") or {}
        c_obj = row.get("candidate") or {}
        t = t_obj if isinstance(t_obj, dict) else {}
        c = c_obj if isinstance(c_obj, dict) else {}
        t_asm = t.get("disasm", "")
        c_asm = c.get("disasm", "")

        # Register allocation
        if match_char == "RR":
            blockers.add("register allocation")
            continue

        t_parts = t_asm.split()
        c_parts = c_asm.split()
        t_mnem = t_parts[0] if t_parts else ""
        c_mnem = c_parts[0] if c_parts else ""

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
        """Initialize the GA engine with seed source, target bytes, and compiler settings."""
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
                atomic_write_text(self.out_dir / "best.c", best_src, encoding="utf-8")
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

targeted   ~1.1K combos    Codegen-altering flags only (/Oy, /Op)

normal     ~21K combos     Default sweep

thorough   ~1M combos      Deep search

full       ~8.3M combos    Exhaustive (needs sampling)

[dim]Auto-reads VA, SIZE, SYMBOL, and CFLAGS from source annotations.
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
    diff_format: str = typer.Option(
        "terminal",
        "--diff-format",
        help="Output format for --diff-only: terminal, json, csv",
    ),
    seed: int | None = typer.Option(None, "--seed", help="RNG seed for reproducible GA runs"),
) -> None:
    """Genetic Algorithm engine for binary matching."""
    if diff_format not in ("terminal", "json", "csv"):
        error_exit("--diff-format must be 'terminal', 'json', or 'csv'")

    json_output = diff_format == "json"
    csv_output = diff_format == "csv"

    # Auto-fill from rebrew-project.toml config
    cfg = get_config(target=target)

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
    anno = parse_c_file(Path(seed_c), target_name=cfg.marker if cfg else None)
    if anno:
        eval_errs, eval_warns = anno.validate()
        if not json_output:
            for e in eval_errs:
                rich.print(f"[bold red]LINT ERROR:[/bold red] {e}")
            for w in eval_warns:
                rich.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")
        if eval_errs and not force:
            if json_output:
                error_exit("Annotation lint errors", json_mode=True)
            else:
                error_exit(
                    "Aborting due to annotation errors. Fix them or use --force to override."
                )

    meta = parse_source_metadata(seed_c)

    origin = meta.get("ORIGIN", "")
    compile_cfg = cfg.for_origin(origin)
    msvc_env = compile_cfg.msvc_env()
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

    if not symbol:
        symbol = meta.get("SYMBOL")
    if not symbol:
        error_exit("--symbol required (not found in source annotations)", json_mode=json_output)

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
            error_exit(f"Invalid SIZE annotation: {meta['SIZE']!r}")

    # Extract target bytes from offset in the configured binary
    if target_va and target_size:
        va_int = parse_va(target_va, json_mode=json_output)
        target_bytes = cfg.extract_dll_bytes(va_int, target_size)
    else:
        error_exit("Need VA and SIZE (from source annotations or CLI)", json_mode=json_output)

    if not target_bytes:
        error_exit("Could not extract target bytes", json_mode=json_output)

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
            if not json_output and not csv_output:
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
                sim = structural_similarity(target_bytes, obj_bytes, res.reloc_offsets)

                if json_output:
                    summary["structural_similarity"] = {
                        "total_insns": sim.total_insns,
                        "exact": sim.exact,
                        "reloc_only": sim.reloc_only,
                        "register_only": sim.register_only,
                        "structural": sim.structural,
                        "mnemonic_match_ratio": sim.mnemonic_match_ratio,
                        "structural_ratio": sim.structural_ratio,
                        "flag_sensitive": sim.flag_sensitive,
                    }
                    if blockers:
                        summary["blockers"] = blockers
                    json_print(summary)
                elif csv_output:
                    import csv

                    writer = csv.writer(sys.stdout)
                    writer.writerow(
                        [
                            "Index",
                            "Match",
                            "Target_Bytes",
                            "Target_Disasm",
                            "Cand_Bytes",
                            "Cand_Disasm",
                        ]
                    )
                    instructions_obj = summary.get("instructions", [])
                    instructions = instructions_obj if isinstance(instructions_obj, list) else []
                    for row in instructions:
                        if not isinstance(row, dict):
                            continue
                        m_char = row.get("match") or ""
                        if mismatches_only and m_char != "**":
                            continue
                        t_obj = row.get("target") or {}
                        c_obj = row.get("candidate") or {}
                        t_data = t_obj if isinstance(t_obj, dict) else {}
                        c_data = c_obj if isinstance(c_obj, dict) else {}
                        writer.writerow(
                            [
                                row.get("index", ""),
                                m_char,
                                t_data.get("bytes", ""),
                                t_data.get("disasm", ""),
                                c_data.get("bytes", ""),
                                c_data.get("disasm", ""),
                            ]
                        )
                else:
                    if blockers:
                        print("\nAuto-classified blockers:")
                        for b in blockers:
                            print(f"  - {b}")
                    _print_structural_similarity(sim)

                summary_obj = summary.get("summary", {})
                structural_obj = (
                    summary_obj.get("structural", 0) if isinstance(summary_obj, dict) else 0
                )
                has_structural = isinstance(structural_obj, int | float) and structural_obj > 0
            if has_structural:
                raise typer.Exit(code=1)
            return
        else:
            if json_output:
                error_exit(f"Build failed: {res.error_msg}", json_mode=True)
            print(f"Build failed: {res.error_msg}")
            raise typer.Exit(code=2)

    if flag_sweep_only:
        results = flag_sweep(
            seed_src, target_bytes, cl, inc, cflags, symbol, jobs, tier=tier, env=msvc_env
        )
        for score, flags in results[:10]:
            print(f"{score:.2f}: {flags}")

        res = build_candidate_obj_only(seed_src, cl, inc, cflags, symbol, env=msvc_env)
        if res.ok and res.obj_bytes:
            obj_bytes = res.obj_bytes
            if len(obj_bytes) > len(target_bytes):
                obj_bytes = obj_bytes[: len(target_bytes)]
            sim = structural_similarity(target_bytes, obj_bytes, res.reloc_offsets)
            _print_structural_similarity(sim)

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
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
