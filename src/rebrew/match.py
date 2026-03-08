#!/usr/bin/env python3
"""Genetic Algorithm engine for binary matching — single-function and batch modes.

Compile C source, compare object bytes against a target function, and
iteratively mutate to find a byte-perfect or relocation-normalized match.

Single-function usage:
    rebrew match <source.c> [--generations N --pop-size N]
    rebrew match <source.c> --flag-sweep-only

Batch usage (``rebrew match --all``)::
    rebrew match --all                       Run GA on all STUB functions
    rebrew match --all --near-miss           Near-miss MATCHING functions
    rebrew match --all --flag-sweep          Batch flag sweep on MATCHING
    rebrew match --all --dry-run             List targets without running
"""

import hashlib
import logging
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import typer
from rich.console import Console

from rebrew.annotation import (
    has_skip_annotation,
    parse_c_file_multi,
    parse_source_metadata,
    resolve_symbol,
)
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import TargetOption, error_exit, json_print, parse_va, require_config, target_marker
from rebrew.compile import resolve_compiler_env
from rebrew.compile_cache import CompileCache
from rebrew.config import ProjectConfig
from rebrew.core import msvc_env_from_config
from rebrew.diff import _print_structural_similarity
from rebrew.matcher import (
    BuildCache,
    BuildResult,
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


# ---------------------------------------------------------------------------
# GA engine
# ---------------------------------------------------------------------------


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
        """Initialize the genetic algorithm matching engine."""
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

            while len(next_pop) < self.pop_size:
                next_pop.append(self.rng.choice(elite))

            self.population = next_pop

        return self.best_source, self.best_score


# ---------------------------------------------------------------------------
# Batch annotation types and finders
# ---------------------------------------------------------------------------


class StubInfo(TypedDict):
    """Parsed annotation fields for a STUB or near-miss MATCHING function."""

    filepath: Path
    va: str
    size: int
    symbol: str
    cflags: str
    delta: NotRequired[int]


# Match function definition start: return type at start of line.
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
) -> list[StubInfo]:
    """Parse annotations with configurable status and delta filters."""
    from rebrew.naming import parse_byte_delta

    if ignored is None:
        ignored = set()

    entries = parse_c_file_multi(filepath, sidecar_dir=filepath.parent)
    if not entries:
        return []

    if has_skip_annotation(filepath):
        return []

    results: list[StubInfo] = []
    for entry in entries:
        status = entry["status"]
        if status not in status_filter:
            continue

        if entry.va < 0x1000:
            continue

        symbol = resolve_symbol(entry, filepath)
        if symbol in ignored or symbol.lstrip("_") in ignored:
            continue

        size = entry["size"]
        if size < 10:
            continue

        blocker = entry.get("blocker") or ""
        delta = parse_byte_delta(blocker) if blocker else None

        if max_delta is not None and (delta is None or delta > max_delta):
            continue

        cflags = entry["cflags"] or "/O2 /Gd"

        info: StubInfo = {
            "filepath": filepath,
            "va": f"0x{entry['va']:08X}",
            "size": size,
            "symbol": symbol,
            "cflags": cflags,
        }
        if delta is not None:
            info["delta"] = delta
        results.append(info)
    return results


def parse_stub_info(filepath: Path, ignored: set[str] | None = None) -> list[StubInfo]:
    """Extract STUB annotation fields from a reversed .c file."""
    return _parse_annotations(filepath, status_filter={"STUB"}, ignored=ignored)


def parse_matching_info(
    filepath: Path, ignored: set[str] | None = None, max_delta: int = 10
) -> list[StubInfo]:
    """Extract MATCHING annotation fields with byte delta <= max_delta."""
    return _parse_annotations(
        filepath, status_filter={"MATCHING"}, max_delta=max_delta, ignored=ignored
    )


def parse_matching_all(filepath: Path, ignored: set[str] | None = None) -> list[StubInfo]:
    """Extract all MATCHING annotations (no delta filter)."""
    return _parse_annotations(filepath, status_filter={"MATCHING"}, ignored=ignored)


def _collect_with_dedup(
    reversed_dir: Path,
    cfg: ProjectConfig | None,
    parser_fn: "Callable[[Path], list[StubInfo]]",
    sort_key: "Callable[[StubInfo], Any]",
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Collect StubInfo dicts from source files, deduplicating by VA."""
    from rebrew.cli import iter_sources, rel_display_path

    results: list[StubInfo] = []
    seen_vas: dict[str, str] = {}

    if not reversed_dir.exists():
        return results

    for cfile in iter_sources(reversed_dir, cfg):
        infos = parser_fn(cfile)
        rel_name = rel_display_path(cfile, reversed_dir)
        for info in infos:
            va_str = info["va"]
            if va_str in seen_vas:
                if warn_duplicates:
                    typer.echo(
                        f"  WARNING: Duplicate VA {va_str} found in {rel_name} "
                        f"(already in {seen_vas[va_str]}), skipping",
                        err=True,
                    )
                continue
            seen_vas[va_str] = rel_name
            results.append(info)

    results.sort(key=sort_key)
    return results


def find_all_stubs(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find all STUB files in reversed/ and return sorted by size."""
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_stub_info(cfile, ignored=ignored),
        sort_key=lambda x: x["size"],
        warn_duplicates=warn_duplicates,
    )


def find_near_miss(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    max_delta: int = 10,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find MATCHING functions with small byte deltas, sorted by delta ascending."""
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_matching_info(cfile, ignored=ignored, max_delta=max_delta),
        sort_key=lambda x: (x["delta"], x["size"]),
        warn_duplicates=warn_duplicates,
    )


def find_all_matching(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find all MATCHING functions, sorted by byte delta then size."""
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_matching_all(cfile, ignored=ignored),
        sort_key=lambda x: (x.get("delta", 9999), x["size"]),
        warn_duplicates=warn_duplicates,
    )


# ---------------------------------------------------------------------------
# Source update helpers
# ---------------------------------------------------------------------------


def update_cflags_annotation(filepath: Path, new_cflags: str) -> bool:
    """Update the ``cflags`` for a function — writes to the sidecar.

    Returns True if the sidecar was updated, False on failure.
    """
    from rebrew.sidecar import get_entry, set_field

    try:
        text = filepath.read_text(encoding="utf-8")
    except OSError:
        return False

    m = re.search(
        r"(?://|/\*)\\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\\s*(\\S+)\\s+(0x[0-9a-fA-F]+)",
        text,
    )
    if m is None:
        # Try without the escaped form (real regex)
        m = re.search(
            r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*(\S+)\s+(0x[0-9a-fA-F]+)",
            text,
        )
    if m is None:
        return False

    module = m.group(1)
    va_int = int(m.group(2), 16)

    entry = get_entry(filepath.parent, va_int, module=module)
    if entry.get("cflags", "") == new_cflags:
        return False

    set_field(filepath.parent, va_int, "cflags", new_cflags, module=module)
    return True


def update_stub_to_matched(filepath: Path, best_src: str, stub: StubInfo) -> None:
    """Replace STUB source with matched source and update STATUS.

    Validates the transformed content before writing, then uses
    ``atomic_write_text`` with a .bak backup to prevent data loss.
    """
    bak_path = filepath.with_suffix(".c.bak")

    original = filepath.read_text(encoding="utf-8", errors="replace")

    updated = re.sub(
        r"^(//\s*)STATUS:\s*(STUB|MATCHING(?:_RELOC)?)",
        r"\1STATUS: RELOC",
        original,
        count=1,
        flags=re.MULTILINE,
    )
    if "BLOCKER:" in updated:
        updated = re.sub(r"//\s*BLOCKER:[^\n]*\n?", "", updated, count=1)
        updated = re.sub(r"/\*\s*BLOCKER:.*?\*/[ \t]*\n?", "", updated, count=1)

    body_start = _FUNC_START_RE.search(updated)
    best_body = _FUNC_START_RE.search(best_src)

    if body_start and best_body:
        header = updated[: body_start.start()]
        new_body = best_src[best_body.start() :]
        updated = header + new_body

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".c",
        dir=filepath.parent,
        delete=False,
        encoding="utf-8",
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

    shutil.copy2(filepath, bak_path)
    atomic_write_text(filepath, updated)

    from rebrew.cli import rel_display_path

    display = rel_display_path(filepath, filepath.parent.parent)
    console.print(f"  [bold green]Updated[/] {display}: STUB → RELOC (backup: {bak_path.name})")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = """\
[dim]Auto-reads VA, SIZE, and CFLAGS from source annotations.
Symbol is derived from the C function definition.
Requires rebrew-project.toml with valid compiler paths.

[bold]Batch mode (--all):[/bold]
  rebrew match --all               GA on all STUB functions
  rebrew match --all --near-miss   GA on near-miss MATCHING functions
  rebrew match --all --flag-sweep  Batch flag sweep on MATCHING functions
  rebrew match --all --dry-run     List targets without running[/dim]"""

app = typer.Typer(
    help="GA matching engine — single file or batch (--all).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    seed_c: str | None = typer.Argument(None, help="Seed source file (.c) — omit for --all mode"),
    # Single-function options
    cl: str | None = typer.Option(None, help="CL.EXE command (auto from rebrew-project.toml)"),
    inc: str | None = typer.Option(None, help="Include dir (auto from rebrew-project.toml)"),
    cflags: str | None = typer.Option(None, help="Compiler flags (auto from source)"),
    symbol: str | None = typer.Option(None, "-s", help="Symbol to match (auto from source)"),
    target_va: str | None = typer.Option(None, help="Target VA hex (auto from source)"),
    target_size: int | None = typer.Option(None, help="Target size (auto from source)"),
    out_dir: str = typer.Option("output/ga_run", help="Output dir"),
    compare_obj: bool = typer.Option(True, help="Use object comparison instead of full link"),
    link: str | None = typer.Option(None, help="LINK.EXE command"),
    lib: str | None = typer.Option(None, help="Lib dir"),
    ldflags: str | None = typer.Option(None, help="Linker flags"),
    flag_sweep_only: bool = typer.Option(
        False,
        "--flag-sweep-only",
        "-S",
        help="Run MSVC compiler flag sweep instead of GA (tries flag combos to find exact match)",
    ),
    tier: str = typer.Option(
        "targeted",
        help="Flag sweep tier: targeted (common flags) or exhaustive (all combos)",
    ),
    force: bool = typer.Option(
        False, "--force", help="Continue even if annotation lint errors exist"
    ),
    seed: int | None = typer.Option(None, "--seed", help="RNG seed for reproducible GA runs"),
    extra_seed: list[str] | None = typer.Option(
        None, "--extra-seed", help="Extra .c file(s) to seed GA population from solved functions"
    ),
    no_seed: bool = typer.Option(
        False, "--no-seed", help="Disable cross-function solution seeding"
    ),
    # GA tuning (shared single/batch)
    generations: int = typer.Option(100, "-g", "--generations", help="Number of GA generations"),
    pop_size: int = typer.Option(32, "-p", "--pop-size", help="Population size per generation"),
    jobs: int | None = typer.Option(
        None, "-j", "--jobs", help="Parallel jobs (default: from config)"
    ),
    # Batch-only options
    all_mode: bool = typer.Option(False, "--all", help="Batch mode: run GA on all STUB functions"),
    near_miss: bool = typer.Option(
        False, "--near-miss", help="--all: target MATCHING near-misses instead of STUBs"
    ),
    threshold: int = typer.Option(
        10, "--threshold", help="--all: max byte delta for --near-miss mode"
    ),
    flag_sweep: bool = typer.Option(
        False,
        "--flag-sweep",
        help="--all: batch flag sweep on MATCHING functions (finds optimal CFLAGS)",
    ),
    fix_cflags: bool = typer.Option(
        False,
        "--fix-cflags",
        help="--all --flag-sweep: auto-update CFLAGS annotation on exact match",
    ),
    max_stubs: int = typer.Option(0, "--max-stubs", help="--all: max functions to process (0=all)"),
    min_size: int = typer.Option(10, "--min-size", help="--all: min target size to attempt"),
    max_size: int = typer.Option(9999, "--max-size", help="--all: max target size to attempt"),
    filter_str: str = typer.Option(
        "", "--filter", help="--all: only process functions matching substring"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    timeout_min: int = typer.Option(
        30, "--timeout-min", help="--all: per-function GA timeout (minutes)"
    ),
    seed_from_solved: bool = typer.Option(
        True,
        "--seed-from-solved/--no-solved",
        help="Seed GA population from similar solved functions",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """GA matching engine — single file or batch (--all)."""
    cfg = require_config(target=target, json_mode=json_output)

    if jobs is None:
        jobs = int(getattr(cfg, "default_jobs", 4))

    if all_mode:
        _run_all(
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
            threshold=threshold,
            flag_sweep=flag_sweep,
            fix_cflags=fix_cflags,
            max_stubs=max_stubs,
            seed_from_solved=seed_from_solved,
            json_output=json_output,
            tier=tier,
        )
        return

    # Single-function mode requires seed_c
    if seed_c is None:
        error_exit(
            "Provide a source file (rebrew match <file.c>) or use --all for batch mode.",
            json_mode=json_output,
        )

    params = resolve_build_params(
        cfg, seed_c, cl, inc, cflags, symbol, target_va, target_size, force, json_output
    )

    if flag_sweep_only:
        _run_single_flag_sweep(params, tier, jobs, json_output)
        return

    _run_single_ga(
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


def resolve_build_params(
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

    # Use shared helper for compiler env resolution
    cl_resolved, inc_resolved, _, cc = resolve_compiler_env(cfg)
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
        error_exit(
            "--symbol required (could not derive from C function definition)", json_mode=json_output
        )

    if not cflags:
        cflags = meta.get("CFLAGS", getattr(compile_cfg, "cflags", "/O2 /Gd") or "/O2 /Gd")
    base_cf = getattr(compile_cfg, "base_cflags", "") or ""
    if base_cf and "/c" in base_cf:
        cflags = f"{base_cf} {cflags}".strip()
    elif "/c" not in cflags:
        cflags = f"/nologo /c {cflags}".strip()

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
        for score, flags_str in results[:10]:
            console.print(f"{score:.2f}: {flags_str}")
        if sim_res is not None:
            _print_structural_similarity(sim_res)

    if best_score < 0.1:
        return
    raise typer.Exit(code=1)


def run_flag_sweep(
    stub: StubInfo,
    cfg: ProjectConfig,
    tier: str = "targeted",
    jobs: int = 4,
) -> tuple[float, str, list[tuple[float, str]]]:
    """Run a compiler flag sweep on a single StubInfo in-process.

    Returns ``(best_score, best_flags, all_results)``.
    """
    import contextlib
    import io

    filepath = stub["filepath"]
    va_int = int(stub["va"], 16)
    size = stub["size"]
    symbol = stub["symbol"]
    cflags = stub["cflags"]

    source = filepath.read_text(encoding="utf-8")
    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size)
    if not target_bytes:
        return float("inf"), "", []

    cl_cmd, inc_dir, msvc_env, cc = resolve_compiler_env(cfg)

    if "/c" not in cflags:
        cflags = "/nologo /c " + cflags

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
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
            timeout=cfg.compile_timeout,
        )

    if not results:
        return float("inf"), "", []

    best_score, best_flags = results[0]
    return best_score, best_flags, results


# ---------------------------------------------------------------------------
# Single-function: GA run
# ---------------------------------------------------------------------------


def _run_single_ga(
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
    """Run the full GA matching engine for a single source file."""
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

    if best_score < 0.1:
        _save_solution(p.cfg, p.symbol, p.cflags, p.target_size, p.seed_c, best_score, generations)


def _save_solution(
    cfg: Any,
    symbol: str,
    cflags: str,
    target_size: int,
    source_file: str,
    score: float,
    generations: int,
) -> None:
    """Save an exact-match solution to the solutions database."""
    try:
        from rebrew.solutions import SolutionEntry, save_solution

        entry = SolutionEntry(
            symbol=symbol,
            cflags=cflags,
            size=target_size or 0,
            source_file=source_file,
            score=score,
            generations=generations,
        )
        save_solution(cfg.root, entry)
    except Exception:  # noqa: BLE001
        log.debug("Solution save failed", exc_info=True)


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
) -> tuple[bool, str]:
    """Run one GA pass for a single stub in-process. Returns (matched, summary)."""
    filepath = stub["filepath"]
    try:
        rel = filepath.relative_to(cfg.root)
    except ValueError:
        rel = Path(filepath.stem)
    out_dir = cfg.root / "output" / "ga_runs" / rel.with_suffix("")
    out_dir.mkdir(parents=True, exist_ok=True)

    va_int = int(stub["va"], 16)
    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, stub["size"])
    if not target_bytes:
        return False, "Could not extract target bytes"

    cl_cmd, inc_dir, msvc_env, cc = resolve_compiler_env(cfg)

    cflags = stub["cflags"]
    base_cf = getattr(cfg, "base_cflags", "") or ""
    if base_cf and "/c" in base_cf:
        cflags = f"{base_cf} {cflags}".strip()
    elif "/c" not in cflags:
        cflags = f"/nologo /c {cflags}".strip()

    seed_src = filepath.read_text(encoding="utf-8", errors="replace")

    loaded_extra: list[str] = []
    if extra_seed_paths:
        for sp in extra_seed_paths:
            p = Path(sp)
            if p.exists():
                loaded_extra.append(p.read_text(encoding="utf-8", errors="replace"))

    ga = BinaryMatchingGA(
        seed_src,
        target_bytes,
        cl_cmd,
        inc_dir,
        cflags,
        stub["symbol"],
        out_dir,
        num_generations=generations,
        pop_size=pop,
        num_jobs=jobs,
        compile_cache=cc,
        env=msvc_env,
        compile_timeout=getattr(cfg, "compile_timeout", 60),
        verbose=0,
        extra_seeds=loaded_extra or None,
    )

    import signal

    matched = False
    output_summary = ""

    def _timeout_handler(signum: int, frame: Any) -> None:
        raise TimeoutError

    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout_min * 60 + 60)
    try:
        best_src, best_score = ga.run()
        matched = best_score < 0.1
        output_summary = f"best_score={best_score:.2f}"

        if matched and best_src is not None:
            best_c = out_dir / "best.c"
            if best_c.exists():
                try:
                    update_stub_to_matched(filepath, best_src, stub)
                except (RuntimeError, OSError) as e:
                    console.print(
                        f"  [yellow]WARNING:[/yellow] GA matched but failed to update source: {e}"
                    )
            _save_solution(
                cfg,
                stub["symbol"],
                stub["cflags"],
                stub["size"],
                str(filepath),
                best_score,
                generations,
            )
    except TimeoutError:
        return False, "TIMEOUT"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    return matched, output_summary


# ---------------------------------------------------------------------------
# Batch: --all entry point
# ---------------------------------------------------------------------------


def _run_all(  # noqa: PLR0913
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
    threshold: int,
    flag_sweep: bool,
    fix_cflags: bool,
    max_stubs: int,
    seed_from_solved: bool,
    json_output: bool,
    tier: str,
) -> None:
    """Batch driver: run GA or flag sweep across all discovered functions."""
    import json as json_mod

    reversed_dir = cfg.reversed_dir
    ignored = set(cfg.ignored_symbols or [])

    if flag_sweep:
        stubs = find_all_matching(
            reversed_dir, ignored=ignored, cfg=cfg, warn_duplicates=not json_output
        )
        mode_label = "MATCHING (flag-sweep)"
    elif near_miss:
        stubs = find_near_miss(
            reversed_dir,
            ignored=ignored,
            max_delta=threshold,
            cfg=cfg,
            warn_duplicates=not json_output,
        )
        mode_label = "MATCHING (near-miss)"
    else:
        stubs = find_all_stubs(
            reversed_dir, ignored=ignored, cfg=cfg, warn_duplicates=not json_output
        )
        mode_label = "STUB"

    if min_size > 0:
        stubs = [s for s in stubs if s["size"] >= min_size]
    if max_size < 9999:
        stubs = [s for s in stubs if s["size"] <= max_size]
    if filter_str:
        stubs = [s for s in stubs if filter_str in str(s["filepath"])]
    if max_stubs > 0:
        stubs = stubs[:max_stubs]

    from rebrew.cli import rel_display_path

    if not json_output:
        console.print(f"\nFound [bold]{len(stubs)}[/] {mode_label} function(s) to process:\n")
        for i, stub in enumerate(stubs, 1):
            delta_str = f"  Δ{stub['delta']}B" if "delta" in stub else ""
            display = rel_display_path(stub["filepath"], reversed_dir)
            console.print(
                f"  {i:3d}. [magenta]{display:45s}[/]  {stub['size']:4d}B  "
                f"[cyan]{stub['va']}[/]  {stub['symbol']:30s}  [dim]{stub['cflags']}{delta_str}[/]"
            )
        console.print()

    if dry_run:
        if json_output:
            items = []
            for stub in stubs:
                item: dict[str, Any] = {
                    "file": str(stub["filepath"]),
                    "va": stub["va"],
                    "size": stub["size"],
                    "symbol": stub["symbol"],
                    "cflags": stub["cflags"],
                }
                if "delta" in stub:
                    item["delta"] = stub["delta"]
                items.append(item)
            print(
                json_mod.dumps(
                    {"mode": mode_label, "dry_run": True, "count": len(stubs), "items": items},
                    indent=2,
                )
            )
        else:
            console.print("Dry run — exiting.")
        return

    if flag_sweep:
        _run_batch_flag_sweep(stubs, cfg, tier, jobs, fix_cflags, json_output, mode_label)
        return

    Path("output/ga_runs").mkdir(parents=True, exist_ok=True)

    matched_count = 0
    failed_count = 0
    ga_results: list[dict[str, Any]] = []

    for i, stub in enumerate(stubs, 1):
        display = rel_display_path(stub["filepath"], reversed_dir)
        if not json_output:
            console.print(f"\n[bold]{'=' * 60}[/]")
            console.print(
                f"\\[{i}/{len(stubs)}] [magenta]{display}[/] ({stub['size']}B) symbol={stub['symbol']}"
            )
            console.print(f"[bold]{'=' * 60}[/]")
        else:
            print(f"[{i}/{len(stubs)}] {display} ({stub['size']}B)", file=sys.stderr)

        extra_ga_paths: list[str] = []
        if seed_from_solved:
            try:
                from rebrew.solutions import find_similar

                similar = find_similar(cfg.root, size=stub["size"], cflags=stub["cflags"], top_k=3)
                for sol in similar:
                    sol_path = cfg.root / sol.source_file
                    if sol_path.exists():
                        extra_ga_paths.append(str(sol_path))
                        if not json_output:
                            console.print(
                                f"  [dim]Seeding from solved:[/] {sol.symbol} ({sol.size}B)"
                            )
            except Exception:  # noqa: BLE001
                log.debug("Solution lookup failed", exc_info=True)

        matched, output_summary = _run_one_stub_ga(
            stub, cfg, generations, pop_size, jobs, timeout_min, extra_ga_paths or None
        )

        result_entry: dict[str, Any] = {
            "file": str(stub["filepath"]),
            "va": stub["va"],
            "size": stub["size"],
            "symbol": stub["symbol"],
            "matched": matched,
        }
        if "delta" in stub:
            result_entry["delta"] = stub["delta"]

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
        print(
            json_mod.dumps(
                {
                    "mode": mode_label,
                    "matched": matched_count,
                    "failed": failed_count,
                    "total": len(stubs),
                    "results": ga_results,
                },
                indent=2,
            )
        )
    else:
        console.print(f"\n[bold]{'=' * 60}[/]")
        console.print(
            f"Results: [green]{matched_count} matched[/], [red]{failed_count} failed[/], {len(stubs)} total"
        )
        console.print(f"[bold]{'=' * 60}[/]")


def _run_batch_flag_sweep(
    stubs: list[StubInfo],
    cfg: ProjectConfig,
    tier: str,
    jobs: int,
    fix_cflags: bool,
    json_output: bool,
    mode_label: str,
) -> None:
    """Execute batch flag sweep across all discovered MATCHING functions."""
    import json as json_mod

    from rebrew.cli import rel_display_path

    reversed_dir = cfg.reversed_dir
    improved_count = 0
    exact_count = 0
    sweep_results: list[dict[str, Any]] = []

    for i, stub in enumerate(stubs, 1):
        display = rel_display_path(stub["filepath"], reversed_dir)
        if not json_output:
            console.print(f"\n[bold]{'=' * 60}[/]")
            console.print(
                f"\\[{i}/{len(stubs)}] [magenta]{display}[/] ({stub['size']}B) symbol={stub['symbol']}"
            )
            console.print(f"  Current flags: [dim]{stub['cflags']}[/]")
            console.print(f"[bold]{'=' * 60}[/]")
        else:
            print(f"[{i}/{len(stubs)}] {display} ({stub['size']}B)", file=sys.stderr)

        best_score, best_flags, all_results = run_flag_sweep(stub, cfg, tier=tier, jobs=jobs)

        is_exact = best_score < 0.1
        result_entry: dict[str, Any] = {
            "file": str(stub["filepath"]),
            "va": stub["va"],
            "size": stub["size"],
            "symbol": stub["symbol"],
            "best_score": round(best_score, 2) if best_score < float("inf") else None,
            "best_flags": best_flags or None,
            "exact": is_exact,
        }
        if "delta" in stub:
            result_entry["delta"] = stub["delta"]

        cflags_updated = False
        if is_exact:
            exact_count += 1
            if fix_cflags and best_flags:
                cflags_updated = update_cflags_annotation(stub["filepath"], best_flags)
                result_entry["cflags_updated"] = cflags_updated

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
                        console.print(f"  [bold]Updated CFLAGS annotation → {best_flags}[/]")

        sweep_results.append(result_entry)

    if json_output:
        print(
            json_mod.dumps(
                {
                    "mode": mode_label,
                    "tier": tier,
                    "exact": exact_count,
                    "compilable": improved_count,
                    "total": len(stubs),
                    "results": sweep_results,
                },
                indent=2,
            )
        )
    else:
        console.print(f"\n[bold]{'=' * 60}[/]")
        console.print(
            f"Flag sweep results: [green]{exact_count} exact[/], "
            f"{improved_count} compilable, {len(stubs)} total (tier={tier})"
        )
        console.print(f"[bold]{'=' * 60}[/]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
