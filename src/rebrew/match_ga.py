"""match_ga.py — the genetic-algorithm matching engine.

The BinaryMatchingGA engine, its mutation-focus weighting, the GA cache key
and argument hash, and the checkpoint reader.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import subprocess
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import capstone
from rich.console import Console

from rebrew.compile_cache import CacheBackend, source_digest
from rebrew.config import ProjectConfig
from rebrew.match_sweep import _BuildParams
from rebrew.matcher import (
    BuildCache,
    BuildResult,
    GACheckpoint,
    build_candidate,
    build_candidate_obj_only,
    compute_population_diversity,
    crossover,
    mutate_code,
    quick_validate,
    score_candidate,
)
from rebrew.utils import atomic_write_text

log = logging.getLogger(__name__)
console = Console(stderr=True)


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


_MUTATION_FOCUS_CATEGORIES = ("register", "equivalent", "structural")
_MUTATION_FOCUS_WEIGHT = 6.0

#: Generations between full-population checkpoint writes (an interrupted run
#: redoes at most this many generations of deterministic work).
_CHECKPOINT_INTERVAL = 5

#: Default floor (bytes) for a function considered by a batch GA/sweep run.


def _mutation_focus_weights(
    focus: str | None, blocker: str | None = None
) -> dict[str, float] | None:
    """GA mutation selection weights biased toward a near-diag category.

    *focus* is a near-diag category (``register``/``equivalent``/``structural``)
    or ``"auto"``, which derives the category from *blocker* — the function's
    BLOCKER metadata written by ``near-diag --fix-blocker`` (verdict text like
    ``NEAR_MATCHING — REGISTER (57% of delta) — try: ...``).  The category's
    suggested operators (``rebrew.near_diag.MUTATION_SUGGESTIONS``) get
    ``_MUTATION_FOCUS_WEIGHT``; unlisted operators keep weight 1.0.

    Returns None when there is nothing to bias (no focus, ``reloc`` — whose
    delta is relocation-masked, or ``auto`` with no derivable verdict) — the
    GA then samples mutations uniformly.
    """
    from rebrew.near_diag import MUTATION_SUGGESTIONS

    if focus == "auto":
        if not blocker:
            return None
        m = re.search(r"NEAR_MATCHING — (REGISTER|EQUIVALENT|STRUCTURAL) \(", blocker)
        focus = m.group(1).lower() if m else None
    if focus not in _MUTATION_FOCUS_CATEGORIES:
        return None
    ops = MUTATION_SUGGESTIONS.get(focus) or []
    if not ops:
        return None
    return dict.fromkeys(ops, _MUTATION_FOCUS_WEIGHT)


def _live_mutation_weights(params: _BuildParams) -> dict[str, float] | None:
    """Near-diag category of the CURRENT implementation, for auto focus.

    ``--mutation-focus auto`` normally derives its category from a verdict
    BLOCKER (written by ``near-diag --fix-blocker``); when none exists, this
    compiles the seed once and classifies it against the target live, so the
    GA's first generations already sample the category's operators.  Returns
    None (uniform sampling) when the seed does not compile or the delta is
    not cleanly classifiable (reloc-masked, compiler-version encoding).
    """
    if not params.seed_src:
        return None
    try:
        from rebrew.matcher import build_candidate_obj_only
        from rebrew.near_diag import analyze

        res = build_candidate_obj_only(
            params.seed_src,
            params.cl,
            params.inc,
            params.cflags,
            params.symbol,
            env=params.msvc_env,
            cache=params.cc,
            timeout=getattr(params.cfg, "compile_timeout", 60),
            extra_include_dirs=[str(params.seed_c.parent.resolve())],
            posix_style=getattr(params.cfg, "posix_style", False),
            profile=getattr(params.cfg, "compiler_profile", ""),
            cfg=params.cfg,
        )
        if not res.ok or not res.obj_bytes:
            return None
        diag = analyze(
            params.target_bytes,
            res.obj_bytes,
            set(res.reloc_offsets or {}),
            params.va_int,
        )
        mutations = diag.get("mutations") or []
        if not mutations:
            return None
        return dict.fromkeys(mutations, _MUTATION_FOCUS_WEIGHT)
    except Exception:
        # Best-effort: a live classification failure degrades to uniform.
        return None


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
            # function_declarator -> declarator -> identifier (guard against cycles)
            visited: set[int] = set()
            while name_node is not None and name_node.type != "identifier":
                nid = id(name_node)
                if nid in visited:
                    break
                visited.add(nid)
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
    symbol: str = "",
    profile: str = "",
) -> str:
    """Cache key for a GA compile result.

    Must cover everything that changes the produced .obj: the source text,
    the compiler flags, the compiler command, the include directory, the
    extra include dirs (different headers → different codegen), the
    per-target defines (a version switch changes ``#ifdef``-driven codegen),
    the extracted symbol (stubs share one cache DB, and the same source
    compiled for different symbols yields different bytes), and the toolchain
    profile.  The build cache persists across runs
    (``output/ga_runs/<rel>/build_cache.db``), so a sweep-then-GA or
    CFLAGS-metadata change must not reuse an .obj compiled under different
    flags.  The profile matters because every image-backed toolchain compiles
    through docker: ``cl_cmd`` is empty and ``inc_dir`` is the same default
    for all of them, so without the profile an msvc6 object is reused for a
    borlandc55 or tc16 run on the same source.
    """
    # Incremental hashing — the old code built a full material buffer per
    # candidate (src.encode() + joins), and the source hash was recomputed
    # every call despite being constant within a GA run (perf-review F3).
    h = hashlib.sha256()
    h.update(source_digest(src).encode())
    h.update(b"\x00cflags=" + cflags.encode())
    h.update(b"\x00cmd=" + cl_cmd.encode())
    h.update(b"\x00inc=" + inc_dir.encode())
    h.update(b"\x00sym=" + symbol.encode())
    h.update(b"\x00profile=" + profile.encode())
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
        compile_cache: CacheBackend | None = None,
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
        #: Mutation operators applied during this run (tracked for solution
        #: provenance — see SolutionEntry.mutations).  Filled by _mutate().
        self.applied_mutations: set[str] = set()

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

        # Score in the SAME disassembly mode as the candidate: a 16-bit
        # target precomputed in 32-bit mode has instruction boundaries and
        # mnemonics that differ from the candidate's 16-bit disassembly.
        self._pre_norm_target, self._pre_target_mnems = precompute_target(
            target_bytes, cs_mode=self.cs_mode
        )

        # Stable fingerprint of the GA parameters — rejects stale checkpoints.
        self.args_hash = _ga_args_hash(
            seed_source,
            target_bytes,
            symbol,
            cflags,
            pop_size,
            num_generations,
            rng_seed,
            mutation_weights=mutation_weights,
            mutation_prob=mutation_prob,
            crossover_prob=crossover_prob,
            elitism=elitism,
            num_jobs=num_jobs,
            stagnation_limit=stagnation_limit,
        )
        self._start_generation = 0
        # Generations actually executed by the last run() (resume-aware), read
        # by the batch driver to record the run in .rebrew/ga_runs.jsonl.
        self.generation = 0

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

    def _mutate(self, src: str) -> str:
        """Apply one weighted mutation, recording the operator for solution
        provenance (SolutionEntry.mutations — see match.py win sites)."""
        out = mutate_code(
            src, self.rng, mutation_weights=self.mutation_weights, track_mutation=True
        )
        if isinstance(out, tuple):
            new_src, mut_name = out
            if mut_name:
                self.applied_mutations.add(mut_name)
            return new_src
        return out

    def _init_population(self) -> None:
        self.population = [self.seed_source]
        for seed_src in self.extra_seeds:
            if seed_src not in self.population:
                self.population.append(seed_src)
                if len(self.population) < self.pop_size:
                    mutated = self._mutate(seed_src)
                    self.population.append(mutated)
        while len(self.population) < self.pop_size:
            src = self.seed_source
            for _ in range(self.rng.randint(1, 4)):
                src = self._mutate(src)
            self.population.append(src)

    def _cache_key(self, src: str) -> str:
        """Disk-cache key for *src* under this run's compile configuration.

        Single source of truth: ``_compile_source`` reads with it and
        ``_compute_fitness`` stores with it.  They used to disagree (the
        scoring store keyed on the bare source digest, which nothing reads),
        so a successful build was never reused across processes.
        """
        return _ga_cache_key(
            src,
            self.cflags,
            str(self.cl_cmd),
            self.inc_dir,
            self.extra_include_dirs,
            getattr(self.cfg, "defines", None) or [],
            self.symbol,
            self.profile,
        )

    def _compile_source(self, src: str) -> BuildResult:
        # The cache persists across runs (output/ga_runs/<rel>/build_cache.db),
        # so the key must cover everything that changes the .obj — not just
        # the source.  A sweep-then-GA or CFLAGS-metadata change used to
        # reuse the previous flag combination's .obj.
        src_hash = self._cache_key(src)
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

        # No disk write for successes here: the result carries no fitness yet,
        # and _compute_fitness stores the scored result with one put —
        # writing now would double every candidate's disk-cache writes.
        # Failures never reach that put (they return early there), so they
        # are stored here instead: one write per candidate either way.
        if not res.ok:
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
            # 16-bit targets carry 2-byte reloc slots (omf16 rel16/disp16) —
            # the 4-byte default would mask the bytes after every slot.
            pointer_size=getattr(self.cfg, "pointer_size", 4) if self.cfg else 4,
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
        # One disk write per candidate: _compile_source skipped the store on
        # a miss (it defers to the scored result here), so this put persists
        # both the .obj and the fitness — a later process loads fitness set
        # and takes the warm-cache skip.  Keyed on the compile configuration
        # (``_cache_key``), NOT the ``src_hash`` argument: the caller passes
        # the bare source digest for memoization, and a digest-keyed entry is
        # never read by ``_compile_source``.
        self.cache.put(self._cache_key(src), res)
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
        # One executor for the whole run: the old code built and tore down a
        # pool per generation (thread create/join churn × num_generations).
        with ThreadPoolExecutor(max_workers=self.num_jobs) as executor:
            for gen in range(self._start_generation, self.num_generations):
                if deadline is not None and time.monotonic() > deadline:
                    break
                gen_start = time.monotonic()
                scored_pop = []
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
                    src_hash = source_digest(src)
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
                            child = self._mutate(child)

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

        self.generation = last_generation
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
    mutation_weights: dict[str, float] | None = None,
    mutation_prob: float = 0.85,
    crossover_prob: float = 0.7,
    elitism: int = 4,
    num_jobs: int = 4,
    stagnation_limit: int = 40,
) -> str:
    """Stable fingerprint of the GA parameters — invalidates stale checkpoints.

    Every tuning parameter that shapes the search is folded in: resuming
    after changing --mutation-focus / --generations / --elitism etc. must
    reject the old checkpoint instead of silently continuing the previous
    population with stale RNG state.

    The params tuple is JSON-encoded with sorted keys and compact separators:
    the old ``str(tuple_with_dict)`` inherited dict insertion order and
    CPython's ``', '`` separators, so equal ``mutation_weights`` mappings
    built in different orders hashed differently (and any repr change across
    versions silently invalidated every checkpoint)."""
    h = hashlib.sha256()
    h.update(seed_source.encode("utf-8", errors="replace"))
    h.update(target_bytes)
    h.update(symbol.encode())
    h.update(cflags.encode())
    h.update(
        json.dumps(
            {
                "pop_size": pop_size,
                "num_generations": num_generations,
                "rng_seed": rng_seed,
                "mutation_weights": mutation_weights,
                "mutation_prob": mutation_prob,
                "crossover_prob": crossover_prob,
                "elitism": elitism,
                "num_jobs": num_jobs,
                "stagnation_limit": stagnation_limit,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    return h.hexdigest()


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
