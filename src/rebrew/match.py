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

import hashlib
import json
import logging
import random
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import capstone
import typer
from rich.console import Console

from rebrew.annotation import (
    Annotation,
    has_skip_annotation,
    min_valid_va_for,
    parse_c_file_multi,
    parse_source_metadata,
    resolve_symbol,
)
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
    resolve_source_arg,
)
from rebrew.compile import resolve_compiler_env
from rebrew.compile_cache import CompileCache, _source_digest
from rebrew.config import ProjectConfig
from rebrew.core import build_iat_region, smart_reloc_compare
from rebrew.matcher import (
    BuildCache,
    BuildResult,
    GACheckpoint,
    SolutionEntry,
    build_candidate,
    build_candidate_obj_only,
    compute_population_diversity,
    crossover,
    flag_sweep,
    mutate_code,
    quick_validate,
    score_candidate,
    structural_similarity,
)
from rebrew.sources import (
    target_marker,
)
from rebrew.utils import atomic_write_text, read_source_text

log = logging.getLogger(__name__)

# Serializes metadata/solutions writes across parallel batch GA workers
# (read-modify-write of rebrew-function.toml is not otherwise thread-safe).
_metadata_lock = threading.Lock()
console = Console(stderr=True)


def print_structural_similarity(sim: Any) -> None:
    """Print a :class:`StructuralSimilarity` result to the console."""
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


def _ga_runs_dir(cfg: ProjectConfig, rel: Path | None = None) -> Path:
    """Resolve the GA run output directory, honoring ``[project].output_dir``.

    ``cfg.output_dir`` defaults to ``output`` (config.py), so the default
    path is unchanged — but a project setting ``output_dir = "artifacts"``
    must route GA runs there too.  The old code hardcoded ``cfg.root /
    "output"`` while ``rebrew report`` used the config value, so the same
    documented option behaved differently per tool (config-review F4).
    """
    base = getattr(cfg, "output_dir", None) or (cfg.root / "output")
    if rel is None:
        return base / "ga_runs"
    return base / "ga_runs" / rel.with_suffix("")


def _compile_cflags(cflags: str, base_cf: str, posix_style: bool = False) -> str:
    """Build the effective compile flags: base_cflags first (when it carries
    ``/c``), else the ``/nologo /c`` glue.  ONE definition shared by the
    single-function, flag-sweep, and batch-GA paths — a divergent copy in the
    sweep path silently dropped ``base_cflags`` (e.g. ``/MT``), so a
    sweep-reported exact could demote on the next test/verify.

    For POSIX-style compilers (gcc-pe/mingw, clang) the ``/nologo /c`` glue
    is omitted — ``-c`` is added by the compile command builders.

    A ``base_cf`` WITHOUT ``/c`` (e.g. a bare ``/MT``) is preserved AND gets
    the glue inserted: the old code dropped it entirely in that branch — the
    same silent flag-loss regression class this function consolidates.
    """
    if posix_style:
        return f"{base_cf} {cflags}".strip() if base_cf else cflags
    if base_cf and "/c" in base_cf:
        return f"{base_cf} {cflags}".strip()
    if "/c" not in cflags:
        if base_cf:
            return f"/nologo /c {base_cf} {cflags}".strip()
        return f"/nologo /c {cflags}".strip()
    return cflags


#: --mutation-focus category → selection weight for its suggested operators
#: (everything else keeps the default 1.0).
_MUTATION_FOCUS_CATEGORIES = ("register", "equivalent", "structural")
_MUTATION_FOCUS_WEIGHT = 6.0

#: Generations between full-population checkpoint writes (an interrupted run
#: redoes at most this many generations of deterministic work).
_CHECKPOINT_INTERVAL = 5


def _mutation_focus_weights(
    focus: str | None, blocker: str | None = None
) -> dict[str, float] | None:
    """GA mutation selection weights biased toward a near-diag category.

    *focus* is a near-diag category (``register``/``equivalent``/``structural``)
    or ``"auto"``, which derives the category from *blocker* — the function's
    BLOCKER metadata written by ``near-diag --fix-blocker`` (verdict text like
    ``NEAR_MATCHING — REGISTER (57% of delta) — try: ...``).  The category's
    suggested operators (``rebrew.near_diag._MUTATION_SUGGESTIONS``) get
    ``_MUTATION_FOCUS_WEIGHT``; unlisted operators keep weight 1.0.

    Returns None when there is nothing to bias (no focus, ``reloc`` — whose
    delta is relocation-masked, or ``auto`` with no derivable verdict) — the
    GA then samples mutations uniformly.
    """
    from rebrew.near_diag import _MUTATION_SUGGESTIONS

    if focus == "auto":
        if not blocker:
            return None
        m = re.search(r"NEAR_MATCHING — (REGISTER|EQUIVALENT|STRUCTURAL) \(", blocker)
        focus = m.group(1).lower() if m else None
    if focus not in _MUTATION_FOCUS_CATEGORIES:
        return None
    ops = _MUTATION_SUGGESTIONS.get(focus) or []
    if not ops:
        return None
    return {op: _MUTATION_FOCUS_WEIGHT for op in ops}


def _find_function_range(source: str, symbol: str) -> tuple[int, int] | None:
    """Byte range of the function matching *symbol* in *source*, or None.

    Used to scope GA mutation queries to the target function (only its
    compiled bytes are scored).  Matches the first ``function_definition``
    whose declarator name equals the symbol with or without a leading
    underscore (the MSVC decoration).  Returns None when the symbol cannot
    be located — the caller then leaves mutations unscoped.
    """
    try:
        from rebrew.matcher import parse_c_ast
    except Exception:  # tree-sitter unavailable: no scoping
        return None
    try:
        tree = parse_c_ast(source.encode("utf-8"))
        wanted = symbol.lstrip("_")
        for node in tree.root_node.children:
            if node.type != "function_definition":
                continue
            declarator = node.child_by_field_name("declarator")
            if declarator is None:
                continue
            name_node: Any = declarator
            # function_declarator -> declarator -> identifier
            while name_node is not None and name_node.type != "identifier":
                name_node = name_node.child_by_field_name("declarator") or name_node.named_child(0)
            if (
                name_node is not None
                and name_node.type == "identifier"
                and (name_node.text or b"").decode("utf-8", "replace").lstrip("_") == wanted
                and name_node.start_byte != name_node.end_byte
            ):
                return node.start_byte, node.end_byte
    except Exception:  # parse failure: no scoping
        return None
    return None


# ---------------------------------------------------------------------------
# GA engine
# ---------------------------------------------------------------------------


def _ga_cache_key(
    src: str,
    cflags: str,
    cl_cmd: str,
    inc_dir: str,
    extra_include_dirs: list[str] | None = None,
    defines: list[str] | None = None,
) -> str:
    """Cache key for a GA compile result.

    Must cover everything that changes the produced .obj: the source text,
    the compiler flags, the compiler command, the include directory, the
    extra include dirs (different headers → different codegen), and the
    per-target defines (a version switch changes ``#ifdef``-driven codegen).
    The build cache persists across runs
    (``output/ga_runs/<rel>/build_cache.db``), so a sweep-then-GA or
    CFLAGS-metadata change must not reuse an .obj compiled under different
    flags.
    """
    # Incremental hashing — the old code built a full material buffer per
    # candidate (src.encode() + joins), and the source hash was recomputed
    # every call despite being constant within a GA run (perf-review F3).
    h = hashlib.sha256()
    h.update(_source_digest(src).encode())
    h.update(b"\x00cflags=" + cflags.encode())
    h.update(b"\x00cmd=" + cl_cmd.encode())
    h.update(b"\x00inc=" + inc_dir.encode())
    for d in sorted(extra_include_dirs or []):
        h.update(b"\x00" + d.encode())
    for d in sorted(defines or []):
        h.update(b"\x00defines=" + d.encode())
    return h.hexdigest()[:16]


class BinaryMatchingGA:
    """Genetic algorithm engine for finding byte-identical or relocation-equivalent C source matches."""

    def __init__(
        self,
        seed_source: str,
        target_bytes: bytes,
        cl_cmd: str,
        inc_dir: str,
        cflags: str,
        symbol: str,
        out_dir: Path,
        pop_size: int = 64,
        num_generations: int = 100,
        mutation_prob: float = 0.85,
        crossover_prob: float = 0.7,
        elitism: int = 4,
        num_jobs: int = 4,
        mutation_weights: dict[str, float] | None = None,
        stagnation_limit: int = 40,
        verbose: int = 1,
        rng_seed: int | None = None,
        compare_obj: bool = True,
        lib_dir: str | None = None,
        link_cmd: str | None = None,
        ldflags: str | None = None,
        env: dict[str, str] | None = None,
        compile_cache: CompileCache | None = None,
        compile_timeout: int = 60,
        extra_seeds: list[str] | None = None,
        collect_pairs_path: Path | None = None,
        extra_include_dirs: list[str] | None = None,
        posix_style: bool = False,
        resume_from: GACheckpoint | None = None,
        cs_mode: int | None = None,
        profile: str = "",
        cfg: Any = None,
    ) -> None:
        """Initialize the genetic algorithm matching engine.

        *resume_from* (a :class:`GACheckpoint` with a matching ``args_hash``)
        restores the population, best result, and RNG state instead of
        starting fresh from the seed source.
        """
        self.posix_style = posix_style
        # 16-bit DOS/NE targets disassemble in 16-bit mode for structural
        # scoring; None keeps the 32-bit default for PE/ELF targets.
        self.cs_mode = cs_mode if cs_mode is not None else capstone.CS_MODE_32
        # Toolchain-backed profiles (tc16/tc20/watcom16/...) route GA
        # compiles through compile_to_obj (DOSBox); without these the GA
        # ran the DOS compiler binary natively.
        self.profile = profile
        self.cfg = cfg
        self.seed_source = seed_source
        self.target_bytes = target_bytes
        self.cl_cmd = cl_cmd
        self.inc_dir = inc_dir
        self.extra_include_dirs = extra_include_dirs or []
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
        self.lib_dir = lib_dir
        self.link_cmd = link_cmd
        self.ldflags = ldflags
        self.env = env
        self.compile_timeout = compile_timeout
        self.collect_pairs_path = collect_pairs_path
        self._pairs_count = 0
        # Lazily hexed target bytes — every pair record repeats them, and
        # re-hexing per candidate dominated --collect-pairs overhead.
        self._target_hex: str | None = None

        self.rng = random.Random(rng_seed)
        self.mutation_weights = mutation_weights or {}
        # One-shot flag: _save_checkpoint warns once per run on failure
        # (per-generation repetition would flood a long batch's log).
        self._checkpoint_warned = False

        self.population: list[str] = []
        self.best_source: str | None = None
        self.best_score: float = float("inf")
        self.stagnant_gens: int = 0
        self.elapsed_sec: float = 0.0

        self.cache = BuildCache(str(self.out_dir / "build_cache.db"))
        self.compile_cache = compile_cache
        self.extra_seeds = extra_seeds or []

        # Process-local fitness memo keyed by source hash.  The disk-backed
        # BuildCache stores BuildResult objects WITHOUT the fitness field
        # (it is populated after scoring, and put() already ran in
        # _compile_source), so a cache.get() always returns a fresh
        # unpickled object whose getattr(res, "fitness", None) is None —
        # the warm-scoring fast path in _compute_fitness could never fire.
        # Elite sources persist across generations unchanged, so a dict
        # here (no extra disk write) captures the real win.
        self._fitness_memo: dict[str, float] = {}

        # Scope mutation queries to the target function's byte range — only
        # that function's compiled bytes are scored, so mutating siblings in
        # a multi-function file is pure waste (whole-file query cost was
        # ~270x higher on large seeds).  The thread-local is set INSIDE
        # run() (and cleared in its finally) so a GA instance that is never
        # run cannot leak the scope into other code.
        self._target_range: tuple[int, int] | None = _find_function_range(seed_source, symbol)

        # Pre-compute target normalization and mnemonics once for scoring hot path
        from rebrew.matcher import precompute_target

        self._pre_norm_target, self._pre_target_mnems = precompute_target(target_bytes)

        # Stable fingerprint of the GA parameters — rejects stale checkpoints.
        self.args_hash = _ga_args_hash(
            seed_source, target_bytes, symbol, cflags, pop_size, num_generations, rng_seed
        )
        self._start_generation = 0

        # Resume restores population/best/RNG instead of a fresh start.
        if resume_from is not None and resume_from.args_hash == self.args_hash:
            self.population = list(resume_from.population)
            self.best_source = resume_from.best_source
            self.best_score = float(resume_from.best_score)
            if resume_from.rng_state:
                self.rng.setstate(resume_from.rng_state)
            self._start_generation = resume_from.generation
        else:
            self._init_population()

    def _init_population(self) -> None:
        self.population = [self.seed_source]
        for seed_src in self.extra_seeds:
            if seed_src not in self.population:
                self.population.append(seed_src)
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
        # The cache persists across runs (output/ga_runs/<rel>/build_cache.db),
        # so the key must cover everything that changes the .obj — not just
        # the source.  A sweep-then-GA or CFLAGS-metadata change used to
        # reuse the previous flag combination's .obj.
        src_hash = _ga_cache_key(
            src,
            self.cflags,
            str(self.cl_cmd),
            self.inc_dir,
            self.extra_include_dirs,
            getattr(self.cfg, "defines", None) or [],
        )
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
                extra_include_dirs=self.extra_include_dirs,
                posix_style=getattr(self, "posix_style", False),
                profile=self.profile,
                cfg=self.cfg,
            )
        else:
            if not self.lib_dir or not self.ldflags:
                raise ValueError("lib dir and ldflags must be set when compare_obj is False")
            # The linked-exe GA path uses a host subprocess (wine) — execution
            # is docker-only for Windows/DOS toolchains, so this mode is only
            # available for native Linux compilers (gcc-pe).
            if self.profile:
                from rebrew.toolchain import TOOLCHAINS

                _spec = TOOLCHAINS.get(self.profile)
                if _spec is not None and _spec.image is not None:
                    raise ValueError(
                        f"linked-exe GA ({self.profile}) needs host wine — execution is "
                        "docker-only; use object comparison (default) instead"
                    )
            res = build_candidate(
                src,
                self.cl_cmd,
                self.inc_dir,
                self.lib_dir,
                self.cflags,
                self.ldflags,
                self.symbol,
                link_cmd=self.link_cmd,
                env=self.env,
                timeout=self.compile_timeout * 2,
            )

        self.cache.put(src_hash, res)
        return res

    def _compute_fitness(self, res: BuildResult, src_hash: str, src: str) -> float:
        # Per-candidate prints are gated behind self.verbose: in batch mode
        # (verbose=0, -j N workers) an unconditional Rich print per candidate
        # serialized all workers on the Console lock and flooded stderr with
        # pop_size × generations × stubs formatted lines.
        def _log(line: str) -> None:
            if self.verbose:
                console.print(line)

        # Warm-scoring fast path: a source hash already scored in this
        # process (same stub, same flags → same obj bytes → same score)
        # skips re-disassembly + re-scoring entirely.  Perf-review F6:
        # ~2.8s per 300k-candidate warm batch of elite/unchanged sources
        # that persist across generations.
        memoized = self._fitness_memo.get(src_hash)
        if memoized is not None:
            return memoized
        cached_fitness = getattr(res, "fitness", None)
        if res.ok and cached_fitness is not None:
            self._fitness_memo[src_hash] = float(cached_fitness)
            return float(cached_fitness)

        if not res.ok or res.obj_bytes is None:
            _log(f"[{src_hash[:8]}] Error during compilation/parsing: {res.error_msg}")
            return 10000000.0
        obj_bytes = res.obj_bytes

        # Size-ratio floor: reject candidates that are far too small.
        # The GA sometimes "optimizes" by deleting large code blocks;
        # this guard prevents it from exploring that neighbourhood.
        target_len = len(self.target_bytes)
        if target_len > 0 and len(obj_bytes) < target_len * 0.5:
            _log(f"[{src_hash[:8]}] Too small: {len(obj_bytes)}B < 50% of target {target_len}B")
            return 5000000.0

        # Proportional penalty for oversized candidates instead of silent
        # truncation.  Score the overlapping region normally but add a
        # penalty proportional to the excess — teaches the GA to avoid bloat.
        excess = max(0, len(obj_bytes) - target_len)
        if excess > 0:
            _log(
                f"[{src_hash[:8]}] Candidate {len(obj_bytes)}B > target {target_len}B (+{excess}B excess)"
            )
        score_bytes = obj_bytes[:target_len]
        sc = score_candidate(
            self.target_bytes,
            score_bytes,
            res.reloc_offsets,
            _pre_norm_target=self._pre_norm_target,
            _pre_target_mnems=self._pre_target_mnems,
            cs_mode=self.cs_mode,
        )
        excess_penalty = excess * 1500.0  # per-byte penalty comparable to byte_score weight
        total = sc.total + excess_penalty
        # Memoize the fitness on the BuildResult so a warm-cache rerun (same
        # stub, same source hash → same obj bytes → same score) skips the
        # re-disassembly + re-scoring entirely (perf-review F6: ~2.8s per
        # 300k-candidate warm batch).  getattr guards pickles written before
        # the field existed.
        res.fitness = total
        self._fitness_memo[src_hash] = total
        _log(
            f"[{src_hash[:8]}] SUCCESS. Score={total:.2f} (len_bytes={len(obj_bytes)}, excess={excess})"
        )

        # Collect source-binary pair for ML training if enabled
        if self.collect_pairs_path is not None:
            self._write_pair(src, obj_bytes, total)

        return total

    def _write_pair(self, src: str, obj_bytes: bytes, score: float) -> None:
        """Append a source-binary pair to the JSONL collection file.

        The caller guards ``collect_pairs_path is not None`` before calling,
        so no in-function re-check is needed (the old one sat AFTER the
        record was built, i.e. unreachable).
        """
        if self._target_hex is None:
            self._target_hex = self.target_bytes.hex()
        record = {
            "source": src,
            "compiled_bytes": obj_bytes.hex(),
            "target_bytes": self._target_hex,
            "score": round(score, 4),
            "cflags": self.cflags,
            "symbol": self.symbol,
        }
        with open(self.collect_pairs_path, "a", encoding="utf-8") as f:  # type: ignore[arg-type]
            f.write(json.dumps(record) + "\n")
        self._pairs_count += 1

    def run(self, deadline: float | None = None) -> tuple[str | None, float]:
        """Run the GA and return ``(best_source, best_score)``.

        *deadline* is a ``time.monotonic()`` timestamp; when reached, the
        loop stops between generations and returns the best result so far.
        This is a cooperative, thread-safe timeout (unlike SIGALRM, which
        only fires in the main thread) — it exists so parallel batch runs
        can bound each stub without signals.
        """
        from rebrew.matcher import set_target_range

        if self._target_range is not None:
            set_target_range(*self._target_range)
        try:
            return self._run_inner(deadline)
        finally:
            set_target_range(None, None)

    def _run_inner(self, deadline: float | None = None) -> tuple[str | None, float]:
        """Run the GA and return ``(best_source, best_score)``."""
        last_generation = self._start_generation
        for gen in range(self._start_generation, self.num_generations):
            if deadline is not None and time.monotonic() > deadline:
                break
            gen_start = time.monotonic()
            scored_pop = []
            with ThreadPoolExecutor(max_workers=self.num_jobs) as executor:
                # Perf-review F5: consult the in-process fitness memo BEFORE
                # submitting — elite/unchanged sources keep their score across
                # generations, so skipping _compile_source entirely avoids the
                # disk BuildCache round-trip (sqlite read + unpickle) per
                # generation for every surviving member.  Key on the full
                # SHA-256 hex, not the old 32-bit [:8] truncation: at ~300k
                # unique sources the birthday bound gives ~10 collision pairs,
                # silently mixing scores of different sources.
                futures: dict[Future[BuildResult], tuple[str, str]] = {}
                for src in self.population:
                    src_hash = _source_digest(src)
                    memoized = self._fitness_memo.get(src_hash)
                    if memoized is not None:
                        scored_pop.append((memoized, src))
                        continue
                    futures[executor.submit(self._compile_source, src)] = (src, src_hash)
                for fut in as_completed(futures):
                    src, src_hash = futures[fut]
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
                    scored_pop.append((self._compute_fitness(res, src_hash, src), src))

            scored_pop.sort(key=lambda x: x[0])
            if not scored_pop:
                continue
            best_score, best_src = scored_pop[0]
            diversity = compute_population_diversity(self.population)

            if best_score < self.best_score:
                self.best_score = best_score
                self.best_source = best_src
                self.stagnant_gens = 0
                atomic_write_text(self.out_dir / "best.c", best_src, encoding="utf-8")
            else:
                self.stagnant_gens += 1

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
                    # Multi-mutation: 35% chance of chaining 2-3 mutations for
                    # bigger jumps in the search space.
                    n_muts = 1
                    if self.rng.random() < 0.35:
                        n_muts = self.rng.randint(2, 3)
                    for _ in range(n_muts):
                        child = mutate_code(child, self.rng, mutation_weights=self.mutation_weights)

                if quick_validate(child):
                    next_pop.append(child)

            while len(next_pop) < self.pop_size:
                next_pop.append(self.rng.choice(elite))

            self.population = next_pop

            # Accumulate the FULL generation time (scoring + mutation +
            # crossover) — stopping at the break above under-reported GA
            # time by ~99% on cache-warm runs (mutation dominates).
            self.elapsed_sec += time.monotonic() - gen_start

            # Persist a checkpoint every _CHECKPOINT_INTERVAL generations so
            # an interrupted batch resumes from here instead of restarting
            # the stub.  The full-population JSON write is not free; an
            # interrupted run only redoes the skipped generations' work.
            if (gen + 1) % _CHECKPOINT_INTERVAL == 0:
                self._save_checkpoint(gen + 1)
            last_generation = gen + 1

        # Always leave a fresh checkpoint on orderly exit (converged,
        # stagnant, deadline, or completed) so resume sees final state.
        if last_generation > self._start_generation:
            self._save_checkpoint(last_generation)

        return self.best_source, self.best_score

    def _save_checkpoint(self, next_generation: int) -> None:
        """Write the current GA state as a JSON checkpoint (best-effort)."""
        try:
            checkpoint = GACheckpoint(
                generation=next_generation,
                best_score=self.best_score,
                best_source=self.best_source,
                population=list(self.population),
                rng_state=self.rng.getstate(),
                args_hash=self.args_hash,
            )
            ckpt_dir = self.out_dir / "checkpoints"
            ckpt_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_text(
                ckpt_dir / f"{self.symbol}.json",
                json.dumps(checkpoint.to_dict(), indent=1),
                encoding="utf-8",
            )
        except (OSError, TypeError, ValueError):
            # Best-effort, but a persistent failure silently disables
            # --resume for this run (hours of GA lost on interruption) —
            # warn once so the user knows resume will restart from scratch.
            if not self._checkpoint_warned:
                self._checkpoint_warned = True
                log.warning("Checkpoint save failed for %s — --resume unavailable", self.symbol)

    def close(self) -> None:
        """Close the build cache (releases SQLite connection)."""
        from rebrew.matcher import set_target_range

        set_target_range(None, None)  # safety: ensure no scope leaks
        self.cache.close()

    def __enter__(self) -> BinaryMatchingGA:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _ga_args_hash(
    seed_source: str,
    target_bytes: bytes,
    symbol: str,
    cflags: str,
    pop_size: int,
    num_generations: int,
    rng_seed: int | None,
) -> str:
    """Stable fingerprint of the GA parameters — invalidates stale checkpoints."""
    h = hashlib.sha256()
    h.update(seed_source.encode("utf-8", errors="replace"))
    h.update(target_bytes)
    h.update(symbol.encode())
    h.update(cflags.encode())
    h.update(str((pop_size, num_generations, rng_seed)).encode())
    return h.hexdigest()


def load_ga_checkpoint(out_dir: Path, symbol: str, args_hash: str) -> GACheckpoint | None:
    """Load + validate the checkpoint for *symbol*; None when missing/stale.

    A checkpoint whose ``args_hash`` differs (source/params changed) is
    rejected — resume must never continue from incompatible state.
    """
    checkpoint = read_ga_checkpoint(out_dir, symbol)
    if checkpoint is None or checkpoint.args_hash != args_hash:
        return None
    return checkpoint


def read_ga_checkpoint(out_dir: Path, symbol: str) -> GACheckpoint | None:
    """Parse the checkpoint for *symbol* without hash validation.

    The GA constructor validates ``args_hash`` itself; this raw reader is
    for the batch path where the final cflags are only known inside the GA.

    A checkpoint that exists but cannot be parsed (truncated write, corrupt
    JSON) is reported at WARNING: resume would silently restart from
    scratch, discarding all prior generations for this stub.
    """
    ckpt = Path(out_dir) / "checkpoints" / f"{symbol}.json"
    if not ckpt.is_file():
        return None
    try:
        data = json.loads(ckpt.read_text(encoding="utf-8"))
        return GACheckpoint.from_dict(data)
    except (OSError, ValueError, TypeError, KeyError):
        log.warning(
            "Checkpoint %s is unreadable — GA restarts %s from scratch",
            ckpt,
            symbol,
        )
        return None


# ---------------------------------------------------------------------------
# Batch annotation types and finders
# ---------------------------------------------------------------------------


@dataclass
class StubInfo:
    """Parsed annotation fields for a STUB or near-miss NEAR_MATCHING function."""

    filepath: Path
    va: str
    size: int
    symbol: str
    cflags: str
    status: str
    module: str
    delta: int = 9999


_FUNC_START_RE = re.compile(
    r"^(?:BOOL|int|void|char|short|long|unsigned|signed|float|double|"
    r"DWORD|HANDLE|LPVOID|LPCSTR|LPSTR|HRESULT|UINT|ULONG|BYTE|WORD|"
    r"SIZE_T|WPARAM|LPARAM|LRESULT|"
    r"static|__declspec|extern|struct|enum|union)\s",
    re.MULTILINE,
)


def _parse_annotations(
    filepath: Path,
    *,
    status_filter: set[str],
    max_delta: int | None = None,
    ignored: set[str] | None = None,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
) -> list[StubInfo]:
    """Parse annotations with configurable status and delta filters.

    *metadata_dir* defaults to ``filepath.parent`` (the legacy inline-layout
    assumption); batch callers pass ``cfg.metadata_dir`` so functions whose
    SIZE/STATUS live in ``rebrew-function.toml`` at the reversed_dir parent
    are found.
    """
    if ignored is None:
        ignored = set()
    meta_dir = metadata_dir if metadata_dir is not None else filepath.parent

    entries = parse_c_file_multi(filepath, metadata_dir=meta_dir)
    if not entries:
        return []

    if has_skip_annotation(filepath, metadata_dir=meta_dir):
        return []

    stubs: list[StubInfo] = []
    for ann in entries:
        parsed_status = ann.status
        if parsed_status not in status_filter:
            continue

        if ann.va < min_va:
            continue

        symbol = resolve_symbol(ann, filepath)
        if symbol in ignored or symbol.lstrip("_") in ignored:
            continue

        if ann.size < 10:
            continue

        # Pass STUB and PROVEN directly.
        # NEAR_MATCHING functions need delta checks:
        if parsed_status in ("NEAR_MATCHING",):
            d = ann.blocker_delta or 9999
            if max_delta is not None and d > max_delta:
                continue
            delta = d
        else:
            delta = 9999

        stubs.append(
            StubInfo(
                filepath=filepath,
                va=f"0x{ann.va:x}",
                size=ann.size,
                symbol=symbol,
                cflags=ann.cflags,
                status=parsed_status,
                module=ann.module,
                delta=delta,
            )
        )
    return stubs


def parse_stub_info(
    filepath: Path,
    ignored: set[str] | None = None,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
) -> list[StubInfo]:
    """Extract STUB annotation fields from a reversed .c file."""
    return _parse_annotations(
        filepath,
        status_filter={"STUB"},
        ignored=ignored,
        metadata_dir=metadata_dir,
        min_va=min_va,
    )


def parse_matching_info(
    filepath: Path,
    ignored: set[str] | None = None,
    max_delta: int = 10,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
) -> list[StubInfo]:
    """Extract NEAR_MATCHING annotation fields with byte delta <= max_delta."""
    return _parse_annotations(
        filepath,
        status_filter={"NEAR_MATCHING"},
        max_delta=max_delta,
        ignored=ignored,
        metadata_dir=metadata_dir,
        min_va=min_va,
    )


def parse_matching_all(
    filepath: Path,
    ignored: set[str] | None = None,
    metadata_dir: Path | None = None,
    min_va: int = 0x1000,
) -> list[StubInfo]:
    """Extract all NEAR_MATCHING annotations (no delta filter)."""
    return _parse_annotations(
        filepath,
        status_filter={"NEAR_MATCHING"},
        ignored=ignored,
        metadata_dir=metadata_dir,
        min_va=min_va,
    )


def parse_size_mismatch_all(
    filepath: Path,
    ignored: set[str] | None = None,
    metadata_dir: Path | None = None,
) -> list[StubInfo]:
    """Extract all SIZE_MISMATCH annotations (no delta filter)."""
    return _parse_annotations(
        filepath, status_filter={"SIZE_MISMATCH"}, ignored=ignored, metadata_dir=metadata_dir
    )


def _collect_with_dedup(
    reversed_dir: Path,
    cfg: ProjectConfig | None,
    parser_fn: Callable[[Path], list[StubInfo]],
    sort_key: Callable[[StubInfo], Any],
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Collect StubInfo entries from source files, deduplicating by VA."""
    from rebrew.sources import iter_sources
    from rebrew.utils import rel_display_path

    results: list[StubInfo] = []
    seen_vas: dict[str, str] = {}
    dup_warnings: list[str] = []

    if not reversed_dir.exists():
        return results

    for cfile in iter_sources(reversed_dir, cfg):
        infos = parser_fn(cfile)
        rel_name = rel_display_path(cfile, reversed_dir)
        for info in infos:
            va_str = info.va
            if va_str in seen_vas:
                if warn_duplicates:
                    dup_warnings.append(
                        f"  [yellow]warning:[/yellow] Duplicate VA {va_str} found in {rel_name} "
                        f"(already in {seen_vas[va_str]}), skipping"
                    )
                continue
            seen_vas[va_str] = rel_name
            results.append(info)

    for w in dup_warnings:
        console.print(w)

    results.sort(key=sort_key)
    return results


def find_all_stubs(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find all STUB files in reversed/ and return sorted by size."""
    md = cfg.metadata_dir if cfg is not None else None
    min_va = min_valid_va_for(cfg) if cfg is not None else 0x1000
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_stub_info(cfile, ignored=ignored, metadata_dir=md, min_va=min_va),
        sort_key=lambda x: x.size,
        warn_duplicates=warn_duplicates,
    )


def find_near_miss(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    max_delta: int = 10,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find NEAR_MATCHING functions with small byte deltas, sorted by delta ascending."""
    md = cfg.metadata_dir if cfg is not None else None
    min_va = min_valid_va_for(cfg) if cfg is not None else 0x1000
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_matching_info(
            cfile,
            ignored=ignored,
            max_delta=max_delta,
            metadata_dir=md,
            min_va=min_va,
        ),
        sort_key=lambda x: (x.delta, x.size),
        warn_duplicates=warn_duplicates,
    )


def find_all_matching(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find all NEAR_MATCHING functions, sorted by byte delta then size."""
    md = cfg.metadata_dir if cfg is not None else None
    min_va = min_valid_va_for(cfg) if cfg is not None else 0x1000
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_matching_all(cfile, ignored=ignored, metadata_dir=md, min_va=min_va),
        sort_key=lambda x: (x.delta, x.size),
        warn_duplicates=warn_duplicates,
    )


def find_size_mismatch(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find all SIZE_MISMATCH functions (bytes differ in length, not just
    content), sorted by size.  Batch GA previously could not target these —
    ``--all`` matches STUBs, ``--improve``/``--near-miss`` NEAR_MATCHING —
    leaving SIZE_MISMATCH functions unreachable by any batch mode."""
    md = cfg.metadata_dir if cfg is not None else None
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_size_mismatch_all(cfile, ignored=ignored, metadata_dir=md),
        sort_key=lambda x: x.size,
        warn_duplicates=warn_duplicates,
    )


# ---------------------------------------------------------------------------
# Source update helpers
# ---------------------------------------------------------------------------


def update_cflags_annotation(
    filepath: Path, new_cflags: str, metadata_dir: Path | None = None
) -> bool:
    """Update the ``cflags`` for a function — writes to the metadata.

    Returns True if the metadata was updated, False on failure.
    """
    from rebrew.metadata import get_entry, update_field

    try:
        text, _ = read_source_text(filepath)
    except OSError:
        return False

    m = re.search(
        r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*(\S+)\s+(0x[0-9a-fA-F]+)",
        text,
    )
    if m is None:
        return False

    module = m.group(1)
    va_int = int(m.group(2), 16)

    meta_root = metadata_dir or filepath.parent
    entry = get_entry(meta_root, va_int, module=module)
    if entry.get("cflags", "") == new_cflags:
        return False

    update_field(meta_root, va_int, "cflags", new_cflags, module=module)
    return True


def update_stub_to_matched(
    filepath: Path, best_src: str, stub: StubInfo, metadata_dir: Path | None = None
) -> bool:
    """Replace STUB source with matched source and update STATUS.

    Validates the transformed content before writing, then uses
    ``atomic_write_text`` with a .bak backup to prevent data loss.

    STATUS promotion happens only after the body splice succeeded AND the
    post-write parse validation passed — a failed splice or a validation
    error must not claim RELOC on a file whose body is still a stub.

    Returns True when the splice landed, the file was rewritten, and STATUS
    was promoted; False when the stub's own block could not be located (the
    file is left untouched).
    """
    bak_path = filepath.with_suffix(".c.bak")

    original, encoding = read_source_text(filepath)

    m = re.search(
        # Trailing lookahead: without it, stub.va="0x401000" would also match
        # a marker "0x4010000" (hex-prefix collision), splicing the wrong
        # function and writing STATUS/CFLAGS to the wrong module.
        r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*(\S+)\s+"
        + re.escape(stub.va)
        + r"(?![0-9a-fA-F])",
        original,
        re.IGNORECASE,
    )
    module = m.group(1) if m else None
    va_int = int(stub.va, 16) if m else None

    # NOTE: STATUS is metadata-owned (update_source_status above); the old
    # whole-file inline `// STATUS: RELOC` rewrite is gone — it hit the file's
    # FIRST block regardless of stub.va (clobbering sibling functions in
    # multi-function files and tripping lint W019).
    updated = original

    # Splice the matched body into the STUB's OWN block — search for the
    # function definition AFTER the stub's marker, not the file's first one.
    body_start = _FUNC_START_RE.search(updated, m.end() if m else 0)
    best_body = _FUNC_START_RE.search(best_src)
    spliced = bool(body_start and best_body)

    if body_start and best_body:
        # The stub's span ends at the NEXT function marker comment (or EOF) —
        # the splice must not drop sibling functions that follow this stub's
        # block in a multi-function file.
        next_fn = re.compile(
            r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*\S+\s+0x[0-9a-fA-F]+"
        ).search(updated, body_start.end())
        body_end = next_fn.start() if next_fn else len(updated)
        header = updated[: body_start.start()]
        tail = updated[body_end:]
        new_body = best_src[best_body.start() :]
        updated = header + new_body + tail

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".c",
        dir=filepath.parent,
        delete=False,
        encoding=encoding,
    ) as tmp:
        tmp.write(updated)
        tmp_path = Path(tmp.name)

    try:
        annos = parse_c_file_multi(tmp_path)
        if not annos:
            raise RuntimeError(
                f"Post-write validation failed: {filepath} would not re-parse after stub update"
            )
    finally:
        tmp_path.unlink(missing_ok=True)

    # Fail closed: if the stub's own block could not be located (no marker, or
    # a return type _FUNC_START_RE does not recognise), do NOT write, backup,
    # promote, or claim a match — the .c still holds a stub.
    if not (spliced and module is not None and va_int is not None):
        return False

    # Promote only when the splice actually landed, the file re-parses, AND
    # the write succeeded — otherwise the metadata would claim RELOC on an
    # unchanged stub body (a failed atomic_write_text — disk full, read-only
    # dir — must not leave rebrew-function.toml saying RELOC while the .c
    # still holds the stub).  The promotion therefore runs AFTER the write.
    from rebrew.metadata import update_source_status

    shutil.copy2(filepath, bak_path)
    atomic_write_text(filepath, updated, encoding=encoding)

    meta_root = metadata_dir or filepath.parent
    update_source_status(meta_root, "RELOC", module, va_int)

    from rebrew.utils import rel_display_path

    display = rel_display_path(filepath, filepath.parent.parent)
    console.print(f"  [bold green]Updated[/] {display}: STUB → RELOC (backup: {bak_path.name})")
    return True


# ---------------------------------------------------------------------------
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
        "--extra-seed",
        help="Extra .c file(s) to seed GA population from solved functions. Ignored if --no-seed is also passed.",
        rich_help_panel="Single-Function",
    ),
    no_seed: bool = typer.Option(
        False,
        "--no-seed",
        help="Disable cross-function solution seeding (takes precedence over --extra-seed)",
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
    sweep_toolchain: bool = typer.Option(
        False,
        "--sweep-toolchain",
        help="Try each vendored MSVC toolchain (SP versions) instead of GA and report the best; combine with --flag-sweep-only to flag-sweep with each toolchain",
        rich_help_panel="Single-Function",
    ),
    sweep_only: str = typer.Option(
        "",
        "--sweep-only",
        help="Sweep only these toolchains (comma-separated profile names or version prefixes, e.g. msvc6,6.0,win16; a Y2K binary likely rules out 2.0/4.x — exclude them with --sweep-exclude 2.0,4.0)",
        rich_help_panel="Single-Function",
    ),
    sweep_exclude: str = typer.Option(
        "",
        "--sweep-exclude",
        help="Skip these toolchains in the sweep (comma-separated profile names or version prefixes, e.g. 2.0,4.0,win16)",
        rich_help_panel="Single-Function",
    ),
    sweep_then_ga: bool = typer.Option(
        False,
        "--sweep-then-ga",
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
        "--seed-solutions",
        help=(
            "Batch: extra solutions.json to seed from (cross-project cflags/"
            "source transfer).  E.g. ../makehm-rebrew/.rebrew/solutions.json"
        ),
        rich_help_panel="Batch Mode",
    ),
    llm_seed: bool = typer.Option(
        False,
        "--llm-seed",
        help=(
            "Ask a configured LLM endpoint for alternative C implementations "
            "and inject them into the GA's initial population (see [llm] "
            "config / REBREW_LLM_ENDPOINT)."
        ),
        rich_help_panel="Single-Function",
    ),
    kuna_seed: bool = typer.Option(
        False,
        "--kuna-seed",
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
        "--seed-from-solved/--no-seed-from-solved",
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
            sweep_then_ga=sweep_then_ga,
            skip_recent_hours=skip_recent_hours,
            seed=seed,
            seed_solutions_path=seed_solutions,
            resume=resume,
            mutation_weights=batch_mutation_weights,
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
                sweep_then_ga=sweep_then_ga,
                skip_recent_hours=skip_recent_hours,
                seed=seed,
                seed_solutions_path=seed_solutions,
                resume=resume,
                mutation_weights=batch_mutation_weights,
            )

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
    # near-diag --fix-blocker) to derive the category.
    mutation_weights: dict[str, float] | None = None
    if mutation_focus:
        blocker_text = ""
        if mutation_focus == "auto":
            from rebrew.metadata import load_metadata

            for (_module, va), entry in load_metadata(cfg.metadata_dir).items():
                if va == params.va_int and entry.get("blocker"):
                    blocker_text = entry["blocker"]
                    break
            if not blocker_text and not json_output:
                console.print(
                    "[dim]--mutation-focus auto: no BLOCKER metadata for "
                    f"0x{params.va_int:08x} — sampling uniformly.[/dim]"
                )
        mutation_weights = _mutation_focus_weights(mutation_focus, blocker_text)
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
                sweep_toolchain=sweep_toolchain,
                sweep_then_ga=sweep_then_ga,
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

    if flag_sweep_only and sweep_toolchain:
        # Both dimensions at once: flag-sweep with each vendored MSVC version.
        _run_single_toolchain_flag_sweep(params, tier, jobs, json_output, sweep_only, sweep_exclude)
        return

    if flag_sweep_only:
        _run_single_flag_sweep(params, tier, jobs, json_output)
        return

    if sweep_toolchain:
        _run_single_toolchain_sweep(params, json_output, sweep_only, sweep_exclude)
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


@dataclass
class _BuildParams:
    """Resolved build parameters shared across all modes."""

    cfg: Any
    seed_c: Path
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


def _select_annotation(annos: list[Annotation], symbol: str | None) -> Annotation | None:
    """Pick the annotation whose symbol or name matches *symbol*.

    ``rebrew match`` on a multi-function file with ``--symbol`` must target
    THAT function; falling back to the first annotation silently compares
    the wrong bytes (false EXACT + wrong solution records).
    """
    if not symbol:
        return None
    want = symbol.strip().lstrip("_").lower()
    for a in annos:
        for candidate in (a.symbol or "", a.name or ""):
            if candidate.strip().lstrip("_").lower() == want:
                return a
    return None


def resolve_build_params(
    cfg: Any,
    seed_c: str,
    cl: str | None,
    inc: str | None,
    cflags: str | None,
    symbol: str | None,
    target_va: str | None,
    target_size: int | None,
    ignore_lint: bool,
    json_output: bool,
) -> _BuildParams:
    """Resolve config, annotations, compiler, and target bytes into build params."""
    seed_c_path = Path(seed_c)
    if not seed_c_path.exists():
        # Run the existence check unconditionally — with an explicit --symbol
        # the old guard below was skipped and read_source_text raised a raw
        # FileNotFoundError traceback.
        error_exit(f"Source not found: {seed_c}", json_mode=json_output)
    annos = parse_c_file_multi(
        seed_c_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    # Prefer the VA-matched annotation when a VA is given (diff/match/prove
    # invoked as `rebrew diff 0x<va>` on a multi-function file must target
    # THAT function — the old first-annotation fallback silently diffed a
    # different function and reported a false match).
    anno = _select_annotation(annos, symbol)
    if anno is None and target_va:
        # target_va is validated by the parse below before bytes are
        # extracted, so it is safe to parse here for the VA match.
        want_va = parse_va(target_va, json_mode=json_output)
        anno = next((a for a in annos if a.va == want_va), None)
    if anno is None:
        if target_va and not symbol:
            # A requested VA that the resolved file does not annotate must not
            # silently fall back to the first annotation — that compiles the
            # WRONG function's symbol and diffs it against the requested
            # address (the `rebrew diff 0x<va>` false-match regression class,
            # same rule as test/prove/near-diag).  An explicit --symbol is a
            # deliberate override and still allowed.
            error_exit(
                f"No annotation for VA {target_va} in {seed_c} — the resolved "
                "file covers different functions (pass --symbol to override)",
                json_mode=json_output,
            )
        anno = annos[0] if annos else None
    if anno:
        eval_errs, eval_warns = anno.validate(min_va=min_valid_va_for(cfg))
        if not json_output:
            for e in eval_errs:
                console.print(f"[bold red]LINT ERROR:[/bold red] {e}")
            for w in eval_warns:
                console.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")
        if eval_errs and not ignore_lint:
            error_exit(
                "Aborting due to annotation errors. Fix them or use --ignore-lint to override.",
                json_mode=json_output,
            )

    meta = parse_source_metadata(seed_c, metadata_dir=cfg.metadata_dir)
    compile_cfg = cfg

    # Use shared helper for compiler env resolution — the returned msvc_env
    # IS msvc_env_from_config(cfg) (the old code computed it a second time
    # and discarded the helper's copy).
    cl_resolved, inc_resolved, msvc_env, cc = resolve_compiler_env(cfg)
    # Per-library / per-function toolchain override: the nearest
    # rebrew-library.toml (walk-up from the source dir) or the function's
    # own TOOLCHAIN metadata selects the docker image.  Every compile runs
    # through docker images — there is no host wine/wibo path.
    from rebrew.cli import resolve_compile_overrides

    toolchain_name, _lib_cflags = resolve_compile_overrides(
        cfg,
        Path(seed_c).resolve().parent,
        meta.get("TOOLCHAIN"),
        meta.get("CFLAGS"),
        getattr(anno, "module", "") if anno else "",
    )
    if toolchain_name:
        from rebrew.toolchain import TOOLCHAINS

        tc_spec = TOOLCHAINS.get(toolchain_name)
        if tc_spec is None or tc_spec.image is None:
            error_exit(
                f"metadata TOOLCHAIN {toolchain_name!r} has no docker image — "
                "every compile runs through its docker image; "
                f"run `rebrew toolchain build {toolchain_name}` first",
                json_mode=json_output,
            )
        # Route the GA compile through the overridden toolchain by pointing
        # the compile config at its profile (compile_to_obj resolves the
        # image from the profile).  The cl/inc/env fields stay as resolved
        # for the default profile; image-backed compiles ignore them.
        from types import SimpleNamespace

        compile_cfg = SimpleNamespace(**vars(compile_cfg))
        compile_cfg.compiler_profile = toolchain_name
    if cl is not None:
        # Caller override: resolve paths relative to root
        try:
            cl_parts = shlex.split(cl)
        except ValueError:
            cl_parts = cl.split()
        cl_parts_res = []
        for part in cl_parts:
            p = cfg.root / part
            cl_parts_res.append(str(p) if p.exists() else part)
        cl_resolved = " ".join(cl_parts_res)
    if inc is not None:
        inc_path = cfg.root / inc
        inc_resolved = str(inc_path) if inc_path.exists() else inc

    if not symbol and anno:
        symbol = anno.symbol
    if not symbol:
        if not Path(seed_c).exists():
            error_exit(f"Source not found: {seed_c}", json_mode=json_output)
        error_exit(
            "--symbol required (could not derive from C function definition)", json_mode=json_output
        )

    if not cflags:
        # Single source of truth: per-function CFLAGS → per-library
        # rebrew-library.toml → cflags_presets → [compiler].cflags →
        # "/O2 /Gd" (shared with verify/test/prove so every tool compiles
        # the same function with the same flags).
        cflags = _lib_cflags
    cflags = _compile_cflags(
        cflags,
        getattr(compile_cfg, "base_cflags", "") or "",
        posix_style=bool(getattr(compile_cfg, "posix_style", False)),
    )

    if not target_va:
        if anno and anno.va:
            target_va = f"0x{anno.va:08x}"
        else:
            for marker_key in ("FUNCTION", "LIBRARY", "STUB"):
                func_meta = meta.get(marker_key)
                if func_meta and "0x" in func_meta:
                    after_hex = func_meta.split("0x")[1].split()
                    if after_hex:
                        target_va = "0x" + after_hex[0]
                        break

    if target_size is None:
        if anno and anno.size:
            target_size = anno.size
        elif "SIZE" in meta:
            try:
                target_size = int(meta["SIZE"])
            except ValueError:
                error_exit(f"Invalid SIZE metadata: {meta['SIZE']!r}", json_mode=json_output)

    if target_va and target_size:
        va_int = parse_va(target_va, json_mode=json_output)
        target_bytes = extract_raw_bytes(cfg.target_binary, va_int, target_size)
    else:
        error_exit("Need VA and SIZE (from source metadata or CLI)", json_mode=json_output)

    if not target_bytes:
        error_exit("Could not extract target bytes", json_mode=json_output)

    seed_src, _ = read_source_text(seed_c_path)

    return _BuildParams(
        cfg=compile_cfg,
        seed_c=seed_c_path,
        seed_src=seed_src,
        cl=cl_resolved,
        inc=inc_resolved,
        cflags=cflags,
        symbol=symbol,
        target_bytes=target_bytes,
        va_int=va_int,
        target_size=target_size,
        msvc_env=msvc_env,
        cc=cc,
    )


# ---------------------------------------------------------------------------
# Single-function: flag sweep
# ---------------------------------------------------------------------------


def _run_single_flag_sweep(
    p: _BuildParams,
    tier: str,
    jobs: int,
    json_output: bool,
) -> None:
    """Run compiler flag sweep on one function and report results."""
    try:
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
            extra_include_dirs=[str(p.seed_c.parent.resolve())],
            posix_style=getattr(p.cfg, "posix_style", False),
            profile=getattr(p.cfg, "compiler_profile", ""),
            cfg=p.cfg,
        )
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)

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
        posix_style=getattr(p.cfg, "posix_style", False),
        profile=getattr(p.cfg, "compiler_profile", ""),
        cfg=p.cfg,
    )
    if res.ok and res.obj_bytes:
        obj_bytes = res.obj_bytes
        if len(obj_bytes) > len(p.target_bytes):
            obj_bytes = obj_bytes[: len(p.target_bytes)]
        import capstone

        sim_cs_mode = (
            capstone.CS_MODE_16 if getattr(p.cfg, "arch", "") == "x86_16" else capstone.CS_MODE_32
        )
        sim_res = structural_similarity(
            p.target_bytes, obj_bytes, res.reloc_offsets, cs_mode=sim_cs_mode
        )

    best_score = results[0][0] if results else float("inf")

    if json_output:
        sweep_items = [
            {"score": round(s, 2), "flags": f, "exact": s < 0.1} for s, f in results[:20]
        ]
        payload: dict[str, Any] = {
            "source": str(p.seed_c),
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
        for score, flags_str in results[:10]:
            console.print(f"{score:.2f}: {flags_str}")
        if sim_res is not None:
            print_structural_similarity(sim_res)

    if best_score < 0.1:
        return
    raise typer.Exit(code=EXIT_MISMATCH)


def run_flag_sweep(
    stub: StubInfo,
    cfg: ProjectConfig,
    tier: str = "targeted",
    jobs: int = 4,
) -> tuple[float, str, list[tuple[float, str]]]:
    """Run a compiler flag sweep on a single StubInfo in-process.

    Returns ``(best_score, best_flags, all_results)``.
    """

    filepath = stub.filepath
    va_int = int(stub.va, 16)
    size = stub.size
    symbol = stub.symbol
    from rebrew.cli import resolve_cflags

    cflags = resolve_cflags(cfg, stub.cflags, getattr(stub, "module", ""))

    source, _ = read_source_text(filepath)
    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size)
    if not target_bytes:
        return float("inf"), "", []

    cl_cmd, inc_dir, msvc_env, cc = resolve_compiler_env(cfg)

    if "/c" not in cflags:
        cflags = _compile_cflags(
            cflags,
            getattr(cfg, "base_cflags", "") or "",
            posix_style=bool(getattr(cfg, "posix_style", False)),
        )

    # NOTE: no redirect_stdout here — mutating process-global stdout is not
    # thread-safe under --sweep-then-ga batch (-j N) and silently loses later
    # prints (incl. the --json report).  flag_sweep logs via logging, not stdout.
    try:
        results = flag_sweep(
            source,
            target_bytes,
            cl_cmd,
            inc_dir,
            cflags,
            symbol,
            n_jobs=jobs,
            tier=tier,
            env=msvc_env,
            cache=cc,
            extra_include_dirs=[str(filepath.parent.resolve())],
            timeout=cfg.compile_timeout,
            posix_style=bool(getattr(cfg, "posix_style", False)),
            profile=getattr(cfg, "compiler_profile", ""),
            cfg=cfg,
        )
    except ValueError as exc:
        # The flag sweep is MSVC-only — a posix project must not silently
        # waste compiles; surface it as a per-function failure.
        return float("inf"), str(exc), []

    if not results:
        return float("inf"), "", []

    best_score, best_flags = results[0]
    return best_score, best_flags, results


# ---------------------------------------------------------------------------
# Single-function: GA run
# ---------------------------------------------------------------------------


def _sweep_filter_matches(name: str, verarch: str, filters: list[str]) -> bool:
    """True when *name* (profile id, e.g. msvc600sp6) matches a sweep filter.

    A filter matches when it is the profile name itself ("msvc6"), a prefix
    of the profile id ("msvc2" -> msvc200), or a substring of the version-arch
    ("6.0" -> every 6.0 line incl. SPs; "win16" -> all 16-bit DOSBox
    toolchains).  This is what lets a Y2K binary exclude the pre-5.0 line
    with --sweep-exclude 2.0,4.0."""
    n = name.lower()
    va = verarch.lower()
    for f in filters:
        f = f.strip().lower()
        if not f:
            continue
        if f == n or n.startswith(f) or f in va:
            return True
    return False


def _vendored_msvc_toolchains(
    cfg: Any,
    baseline_cl: str,
    baseline_inc: str,
    only: str = "",
    exclude: str = "",
) -> list[tuple[str, str, str]]:
    """Return (profile, cl_cmd, inc_dir) for every image-backed MSVC toolchain.

    Execution is docker-only: the cl_cmd/inc_dir are inert for image-backed
    profiles (the image bakes the compiler + includes), so they are returned
    empty and only the profile names matter — the sweep routes each compile
    through that profile's image.  *only* / *exclude* are comma-separated
    profile-name or version-prefix filters (see :func:`_sweep_filter_matches`);
    the configured profile's own compiler is always included as a baseline.
    """
    from rebrew.toolchain import TOOLCHAINS

    only_f = [f for f in (only or "").split(",") if f.strip()]
    excl_f = [f for f in (exclude or "").split(",") if f.strip()]

    out: list[tuple[str, str, str]] = []
    for name, spec in sorted(TOOLCHAINS.items()):
        if spec.image is not None and spec.family == "msvc" and spec.binary == "cl":
            verarch = spec.image.rsplit(":", 1)[-1] if spec.image else ""
            if only_f and not _sweep_filter_matches(name, verarch, only_f):
                continue
            if _sweep_filter_matches(name, verarch, excl_f):
                continue
            out.append((name, "", ""))
    # Always include the configured profile's own compiler as a baseline.
    out.insert(0, (getattr(cfg, "compiler_profile", "") or "msvc6", "", ""))
    return out


def _run_single_toolchain_sweep(
    p: _BuildParams, json_output: bool, only: str = "", exclude: str = ""
) -> None:
    """Compile the seed with each vendored MSVC toolchain and report the best."""
    toolchains = _vendored_msvc_toolchains(p.cfg, p.cl, p.inc, only, exclude)
    # Catalog + IAT region are constant across toolchains — computed once,
    # not per iteration (the old code called build_iat_region inside the
    # loop and passed name_to_va via a getattr that never existed, so reloc
    # targets were never validated: a wrong-callee source could tag "EXACT").
    from rebrew.core import build_name_to_va

    name_to_va = build_name_to_va(p.cfg)
    iat_region = build_iat_region(p.cfg)
    results: list[tuple[float, bool, int, int, str]] = []
    for profile, cl_cmd, inc_dir in toolchains:
        res = build_candidate_obj_only(
            p.seed_src,
            cl_cmd,
            inc_dir,
            p.cflags,
            p.symbol,
            env=p.msvc_env,
            cache=p.cc,
            timeout=p.cfg.compile_timeout,
            extra_include_dirs=[str(p.seed_c.parent.resolve())],
            profile=profile,
            cfg=p.cfg,
        )
        if not (res.ok and res.obj_bytes):
            results.append((float("inf"), False, 0, 0, profile))
            continue
        obj = res.obj_bytes
        score = score_candidate(p.target_bytes, obj, res.reloc_offsets)
        score_val: float = score.total
        matched, count, total, _relocs, _inv = smart_reloc_compare(
            obj[: len(p.target_bytes)],
            p.target_bytes,
            res.reloc_offsets,
            name_to_va=name_to_va,
            section_va=p.va_int,
            iat_region=iat_region,
        )
        results.append((score_val, matched, count, total, profile))

    results.sort(key=lambda r: r[0])
    if json_output:
        json_print(
            {
                "sweep": "toolchain",
                "symbol": p.symbol,
                "results": [
                    {
                        "toolchain": profile,
                        "score": score,
                        "matched": matched,
                        "bytes": f"{count}/{total}",
                    }
                    for score, matched, count, total, profile in results
                ],
                "best": results[0][4] if results else None,
            }
        )
        return

    console.print("[bold]Toolchain sweep:[/bold]")
    for score_val, matched, count, total, profile in results:
        tag = "[green]EXACT[/green]" if matched and count == total else ""
        console.print(f"  {profile:10s} score={score_val:9.2f}  {count}/{total} bytes {tag}")
    if results:
        best = results[0]
        if best[1] and best[2] == best[3]:
            console.print(
                f"[green]Full match with {best[4]} — switch the project profile or set per-function CFLAGS.[/green]"
            )


def _run_single_toolchain_flag_sweep(
    p: _BuildParams,
    tier: str,
    jobs: int,
    json_output: bool,
    only: str = "",
    exclude: str = "",
) -> None:
    """Flag-sweep with each vendored MSVC toolchain; report per-toolchain best.

    Answers "which MSVC version AND which flags built this function" in one
    run — the two-dimension question a decompiler faces when the configured
    profile does not byte-match (``--sweep-toolchain`` alone only tries the
    project's cflags; ``--flag-sweep`` alone only tries the project's
    compiler).
    """
    toolchains = _vendored_msvc_toolchains(p.cfg, p.cl, p.inc, only, exclude)
    rows: list[dict[str, Any]] = []
    for profile, cl_cmd, inc_dir in toolchains:
        results = flag_sweep(
            p.seed_src,
            p.target_bytes,
            cl_cmd,
            inc_dir,
            p.cflags,
            p.symbol,
            jobs,
            tier=tier,
            env=p.msvc_env,
            cache=p.cc,
            timeout=p.cfg.compile_timeout,
            extra_include_dirs=[str(p.seed_c.parent.resolve())],
            profile=profile,
            cfg=p.cfg,
        )
        best_score, best_flags = results[0] if results else (float("inf"), "")
        rows.append(
            {
                "toolchain": profile,
                "best_score": best_score if best_score < float("inf") else None,
                "flags": best_flags,
                "exact": best_score < 0.1,
            }
        )

    rows.sort(
        key=lambda r: (
            r["best_score"] is None,
            r["best_score"] if r["best_score"] is not None else float("inf"),
        )
    )
    if json_output:
        json_print(
            {
                "sweep": "toolchain+flags",
                "results": rows,
                "best": rows[0]["toolchain"] if rows else None,
            }
        )
        return

    console.print("[bold]Toolchain + flag sweep:[/bold]")
    for r in rows:
        tag = "[green]EXACT[/green]" if r["exact"] else ""
        score = f"{r['best_score']:.2f}" if r["best_score"] is not None else "    n/a"
        console.print(
            f"  {r['toolchain']:10s} best={score:>9s}  {r['flags'] or '(no flags)'} {tag}"
        )
    if rows and rows[0]["exact"]:
        console.print(
            f"[green]Full match with {rows[0]['toolchain']} — switch the project profile "
            "or set per-function CFLAGS.[/green]"
        )


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
        cfg=p.cfg,
    )
    try:
        best_src, best_score = ga.run()
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
            p.cfg, p.symbol, p.cflags, p.target_size, str(p.seed_c), best_score, generations
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
    collect_out: list[SolutionEntry] | None = None,
) -> None:
    """Save an exact-match solution to the solutions database.

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
) -> tuple[bool, str]:
    """Run one GA pass for a single stub in-process. Returns (matched, summary).

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
        return False, "Could not extract target bytes"

    cl_cmd, inc_dir, msvc_env, cc = resolve_compiler_env(cfg)

    if cflags_override is not None:
        cflags = cflags_override
    else:
        from rebrew.cli import resolve_cflags

        cflags = resolve_cflags(cfg, stub.cflags, getattr(stub, "module", ""))
    cflags = _compile_cflags(
        cflags,
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
        cs_mode=(
            capstone.CS_MODE_16 if getattr(cfg, "arch", "") == "x86_16" else capstone.CS_MODE_32
        ),
        profile=getattr(cfg, "compiler_profile", ""),
        cfg=cfg,
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
                from rebrew.cli import resolve_cflags
                from rebrew.compile import compile_and_compare
                from rebrew.core import build_name_to_va

                n2v = build_name_to_va(cfg)
                if n2v and best_c.exists():
                    # The GA ran with _compile_cflags(this, base); pass the
                    # resolved user-facing flags (compile_and_compare prepends
                    # base itself) to reproduce the same compile — NOT the
                    # already-prefixed `cflags` variable, which would
                    # double-apply base_cflags.
                    resolved = (
                        cflags_override
                        if cflags_override is not None
                        else resolve_cflags(cfg, stub.cflags, getattr(stub, "module", ""))
                    )
                    cmp_res = compile_and_compare(
                        cfg,
                        best_c,
                        stub.symbol,
                        target_bytes,
                        resolved,
                        name_to_va=n2v,
                        section_va=va_int,
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
            if best_c.exists():
                try:
                    with _metadata_lock:
                        spliced_ok = update_stub_to_matched(
                            filepath, best_src, stub, metadata_dir=cfg.metadata_dir
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
                                from rebrew.verify import patch_verify_cache_entries

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
                with _metadata_lock:
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
                        collect_out=solutions_out,
                    )
            # Only claim a match when the source was actually updated — a
            # stub whose block could not be spliced is still a stub, and
            # must not pollute ga_runs/solutions with a false "solved".
            matched = spliced_ok
    finally:
        ga.close()

    return matched, output_summary


# ---------------------------------------------------------------------------
# Batch: --all entry point
# ---------------------------------------------------------------------------


def _show_ga_history(cfg: ProjectConfig, json_output: bool, *, target: str = "") -> None:
    """Summarize past GA runs (``.rebrew/ga_runs.jsonl``) for at-a-glance
    effectiveness triage: how many attempts, how many converged, score trends.
    """
    from rebrew.matcher import load_ga_runs

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

    from rebrew.matcher import load_ga_runs

    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    records = load_ga_runs(cfg.root, target=getattr(cfg, "target_name", ""), limit=100000)
    recent_vas: set[str] = set()
    for rec in records:
        ts = rec.get("ts", "")
        try:
            if datetime.fromisoformat(ts) >= cutoff:
                recent_vas.add(str(rec.get("va")))
        except ValueError:
            continue
        except TypeError:
            # Naive timestamp (no offset) can't compare against the aware UTC
            # cutoff; treat like any other unparseable line instead of
            # aborting the batch filter.
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
    sweep_then_ga: bool = False,
    skip_recent_hours: int = 0,
    seed: int | None = None,
    size_mismatch: bool = False,
    seed_solutions_path: Path | None = None,
    resume: bool = False,
    mutation_weights: dict[str, float] | None = None,
) -> tuple[int, int]:
    """Batch driver: run GA or flag sweep across all discovered functions.

    Returns ``(matched_count, failed_count)``; ``(0, 0)`` on the dry-run
    and flag-sweep early paths.
    """
    reversed_dir = cfg.reversed_dir
    ignored = set(cfg.ignored_symbols or [])

    if flag_sweep:
        stubs = find_all_matching(
            reversed_dir, ignored=ignored, cfg=cfg, warn_duplicates=not json_output
        )
        mode_label = "NEAR_MATCHING (flag-sweep)"
    elif improve:
        stubs = find_all_matching(
            reversed_dir, ignored=ignored, cfg=cfg, warn_duplicates=not json_output
        )
        mode_label = "NEAR_MATCHING (improve)"
    elif size_mismatch:
        stubs = find_size_mismatch(
            reversed_dir, ignored=ignored, cfg=cfg, warn_duplicates=not json_output
        )
        mode_label = "SIZE_MISMATCH (GA)"
    elif near_miss:
        stubs = find_near_miss(
            reversed_dir,
            ignored=ignored,
            max_delta=threshold,
            cfg=cfg,
            warn_duplicates=not json_output,
        )
        mode_label = "NEAR_MATCHING (near-miss)"
    else:
        stubs = find_all_stubs(
            reversed_dir, ignored=ignored, cfg=cfg, warn_duplicates=not json_output
        )
        mode_label = "STUB"

    if min_size > 0:
        stubs = [s for s in stubs if s.size >= min_size]
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
        from rebrew.core import build_name_to_va

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
    for stub in stubs:
        extra_ga_paths: list[str] = []
        seed_cflags: str | None = None
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
            except Exception:
                # Per-stub seed lookup failure — warn so a stub that would
                # otherwise have been seed-informed is not silently run from
                # its bare seed.
                log.warning("Solution lookup failed for %s", stub.symbol, exc_info=True)
        stub_seeds.append(extra_ga_paths)
        stub_seed_cflags.append(seed_cflags)

    # Parallel stubs: one worker per stub, intra-GA compiles serialized so
    # total concurrency stays at ~jobs (MSVC under wine is not cheap).
    # The cooperative deadline (no SIGALRM) keeps this thread-safe.
    intra_jobs = 1 if jobs > 1 else jobs

    # Collect solution entries across all stubs and flush ONCE at the end —
    # _save_solution per matched stub re-read and rewrote the whole
    # solutions file per match (O(matches × file size)).
    solutions_out: list[SolutionEntry] = []

    def _run_stub(
        stub: StubInfo, seeds: list[str], seed_cflags: str | None
    ) -> tuple[StubInfo, bool, str]:
        # Deterministic per-stub sub-seed: same --seed + same VA ⇒ same GA.
        # (VA collisions are impossible within one batch; across batches the
        # VA is stable, so runs stay reproducible.)
        stub_seed = None if seed is None else seed + int(stub.va, 16)
        sweep_flags: str | None = None
        if sweep_then_ga:
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
            matched, output_summary = _run_one_stub_ga(
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
                mutation_weights=mutation_weights,
                solutions_out=solutions_out,
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
            )
        except Exception:
            # A failed record makes --skip-recent re-run this stub next batch
            # (hours of GA).  Visible at WARNING, not swallowed at DEBUG.
            log.warning("GA run record failed for %s", stub.symbol, exc_info=True)
        return stub, matched, output_summary

    if jobs > 1 and len(stubs) > 1:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            outcomes = list(
                executor.map(_run_stub, stubs, stub_seeds, stub_seed_cflags)  # order preserved
            )
    else:
        outcomes = [
            _run_stub(s, seeds, scf)
            for s, seeds, scf in zip(stubs, stub_seeds, stub_seed_cflags, strict=False)
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
        if is_exact:
            # The sweep's reloc-masked score alone cannot certify a match:
            # score_candidate masks every reloc slot, so a candidate that
            # differs ONLY in a call/mov displacement scores 0.0 without
            # checking the reloc TARGET — promoting it would write
            # EXACT/RELOC that the next test/verify (which validates reloc
            # targets against the catalog) immediately demotes
            # (functionality-review F3).  Re-verify with the authoritative
            # predicate before touching STATUS.
            confirmed = False
            if fix_cflags and best_flags and name_to_va:
                try:
                    from rebrew.binary_loader import extract_raw_bytes
                    from rebrew.cli import resolve_cflags
                    from rebrew.compile import compile_and_compare

                    target_bytes = extract_raw_bytes(cfg.target_binary, int(stub.va, 16), stub.size)
                    if target_bytes:
                        # Same effective flags the sweep used: resolved stub
                        # cflags (per-function → preset → compiler.cflags)
                        # PLUS the winning combo.  compile_and_compare prepends
                        # cfg.base_cflags itself, so pass the raw resolved set —
                        # bare best_flags would drop the stub's own cflags and
                        # validate a DIFFERENT compile than the sweep scored.
                        resolved = resolve_cflags(cfg, stub.cflags, getattr(stub, "module", ""))
                        cmp_res = compile_and_compare(
                            cfg,
                            stub.filepath,
                            stub.symbol,
                            target_bytes,
                            f"{resolved} {best_flags}".strip(),
                            name_to_va=name_to_va,
                            section_va=int(stub.va, 16),
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
            if not confirmed:
                # Not promoted: the reported exact flag was reloc-masked only.
                result_entry["exact"] = False
                is_exact = False
            else:
                exact_count += 1
                cflags_updated = update_cflags_annotation(
                    stub.filepath, best_flags, metadata_dir=cfg.metadata_dir
                )
                result_entry["cflags_updated"] = cflags_updated
                update_source_status(
                    cfg.metadata_dir,
                    "EXACT",
                    module=module_for_va(stub.filepath, int(stub.va, 16)),
                    va=int(stub.va, 16),
                    clear_blockers=True,
                )
                # Keep status/todo in sync with the fresh EXACT metadata (the
                # verify cache may hold a stale NEAR_MATCHING entry).
                try:
                    from rebrew.verify import patch_verify_cache_entries

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


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
