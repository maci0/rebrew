#!/usr/bin/env python3
"""
PyGAD-based Genetic Algorithm for binary matching.
Modularized implementation using the matcher package.
"""

import argparse
import hashlib
import json
import os
import pickle
import random
import shutil
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, cast

import numpy as np
import pygad

# Import from matcher package
from rebrew.matcher import (
    Score, BuildResult, BuildCache, GACheckpoint, save_checkpoint, load_checkpoint, compute_args_hash,
    _normalize_reloc_x86_32, score_candidate, diff_functions,
    parse_coff_obj_symbol_bytes, list_coff_obj_symbols, extract_function_from_pe, extract_function_from_lib,
    build_candidate, build_candidate_obj_only, flag_sweep, generate_flag_combinations, MSVC6_FLAG_AXES,
    _split_preamble_body, _quick_validate, crossover, compute_population_diversity, mutate_code
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
        training_output: Optional[Path] = None,
        mutation_weights: Optional[Dict[str, float]] = None,
        stagnation_limit: int = 20,
        adaptive_mutation: bool = False,
        checkpoint_every: int = 5,
        verbose: int = 1,
        rng_seed: Optional[int] = None,
        compare_obj: bool = True,
        link_cmd: Optional[str] = None,
        lib_dir: Optional[str] = None,
        ldflags: Optional[str] = None,
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

        self.population: List[str] = []
        self.best_source: Optional[str] = None
        self.best_score: float = float("inf")
        self.generation_stats: List[dict] = []
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
        sc = score_candidate(self.target_bytes, res.obj_bytes, res.reloc_offsets)
        return sc.total

    def run(self) -> Tuple[Optional[str], float]:
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

def main():
    ap = argparse.ArgumentParser(description="Converged Binary Matching engine")
    ap.add_argument("--cl", required=True, help="CL.EXE command")
    ap.add_argument("--inc", required=True, help="Include dir")
    ap.add_argument("--cflags", required=True, help="Compiler flags")
    ap.add_argument("--symbol", required=True, help="Symbol to match")
    ap.add_argument("--seed-c", required=True, help="Seed source")
    ap.add_argument("--target-exe", help="Target EXE")
    ap.add_argument("--target-va", help="Target VA (hex)")
    ap.add_argument("--target-size", type=int, help="Target size")
    ap.add_argument("--out-dir", default="output/ga_run", help="Output dir")
    ap.add_argument("--generations", type=int, default=100)
    ap.add_argument("--pop-size", type=int, default=32)
    ap.add_argument("--jobs", "-j", type=int, default=4)
    ap.add_argument("--compare-obj", action="store_true", default=True)
    ap.add_argument("--full-link", action="store_false", dest="compare_obj")
    ap.add_argument("--link", help="LINK.EXE command")
    ap.add_argument("--lib", help="Lib dir")
    ap.add_argument("--ldflags", help="Linker flags")
    ap.add_argument("--diff", action="store_true")
    ap.add_argument("--diff-only", help="Diff specific file")
    ap.add_argument("--flag-sweep-only", action="store_true")
    
    args = ap.parse_args()
    seed_src = Path(args.seed_c).read_text()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    target_bytes = extract_function_from_pe(Path(args.target_exe), int(args.target_va, 16), args.target_size)
    if not target_bytes:
        print("Error: Could not extract target bytes")
        return 1

    if args.diff_only:
        res = build_candidate_obj_only(Path(args.diff_only).read_text(), args.cl, args.inc, args.cflags, args.symbol)
        if res.ok and res.obj_bytes:
            diff_functions(target_bytes, res.obj_bytes, res.reloc_offsets)
        return 0

    if args.flag_sweep_only:
        results = flag_sweep(seed_src, target_bytes, args.cl, args.inc, args.cflags, args.symbol, args.jobs)
        for score, flags in results[:10]:
            print(f"{score:.2f}: {flags}")
        return 0

    ga = BinaryMatchingGA(seed_src, target_bytes, args.cl, args.inc, args.cflags, args.symbol, out_dir, 
                          pop_size=args.pop_size, num_generations=args.generations, num_jobs=args.jobs, 
                          compare_obj=args.compare_obj, link_cmd=args.link, lib_dir=args.lib, ldflags=args.ldflags)
    best_src, best_score = ga.run()
    print(f"\nDone. Best score: {best_score:.2f}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
