"""Batch GA runner and flag sweep for STUB and MATCHING functions.

Parses all .c files in the reversed directory for STUB annotations (default),
MATCHING annotations with a small byte delta (--near-miss), or all MATCHING
annotations (--flag-sweep), then runs rebrew match GA or compiler flag sweep
on each one to attempt automatic byte-perfect matching.

Usage:
    rebrew ga [--max-stubs N] [--generations G] [-j JOBS] [--dry-run]
    rebrew ga --near-miss --threshold 10
    rebrew ga --flag-sweep [--tier TIER] [--fix-cflags]
"""

import contextlib
import io
import json
import logging
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import typer
from rich.console import Console

from rebrew.annotation import has_skip_annotation, parse_c_file_multi, resolve_symbol
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import TargetOption, require_config
from rebrew.config import ProjectConfig
from rebrew.core import msvc_env_from_config
from rebrew.utils import atomic_write_text

log = logging.getLogger(__name__)
console = Console(stderr=True)


class StubInfo(TypedDict):
    """Parsed annotation fields for a STUB or near-miss MATCHING function.

    All fields are required except ``delta``, which is only present for
    near-miss MATCHING functions (populated by ``parse_matching_info``).
    """

    filepath: Path
    va: str
    size: int
    symbol: str
    cflags: str
    origin: str
    delta: NotRequired[int]


# Match function definition start: return type at start of line.
# Covers standard C types, Win32 types, and modifiers.
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
    """Generic annotation parser with configurable status and delta filters.

    Shared implementation for parse_stub_info, parse_matching_info, and
    parse_matching_all.  Reads annotations via the canonical multi-function
    parser, then applies filtering by status, ignored symbols, min VA, min
    size, and optional byte-delta threshold.

    Args:
        filepath: Path to the .c source file.
        status_filter: Set of status strings to include (e.g. {"STUB"}).
        max_delta: If set, only include entries whose BLOCKER byte-delta
                   is <= this value.  None means no delta filtering.
        ignored: Set of symbol names to skip (from cfg.ignored_symbols).
    """
    from rebrew.naming import parse_byte_delta

    if ignored is None:
        ignored = set()

    entries = parse_c_file_multi(filepath)
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

        # Parse byte delta from BLOCKER annotation (for MATCHING functions)
        blocker = entry.get("blocker") or ""
        delta = parse_byte_delta(blocker) if blocker else None

        # Apply delta filter if requested
        if max_delta is not None and (delta is None or delta > max_delta):
            continue

        # Fallback defaults — used only when annotation lacks CFLAGS/ORIGIN.
        cflags = entry["cflags"] or "/O2 /Gd"
        origin = entry["origin"] or "GAME"

        info: StubInfo = {
            "filepath": filepath,
            "va": f"0x{entry['va']:08X}",
            "size": size,
            "symbol": symbol,
            "cflags": cflags,
            "origin": origin,
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


def find_near_miss(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    max_delta: int = 10,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find MATCHING functions with small byte deltas, sorted by delta ascending.

    Args:
        reversed_dir: Directory containing reversed .c files.
        ignored: Set of symbol names to skip.
        max_delta: Maximum byte delta to include.
        cfg: Optional config for source extension.
    """
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_matching_info(cfile, ignored=ignored, max_delta=max_delta),
        sort_key=lambda x: (x["delta"], x["size"]),
        warn_duplicates=warn_duplicates,
    )


def find_all_stubs(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find all STUB files in reversed/ and return sorted by size.

    Detects and warns about duplicate VAs across files, keeping only the first.

    Args:
        reversed_dir: Directory containing reversed .c files.
        ignored: Set of symbol names to skip (from cfg.ignored_symbols).
        cfg: Optional config for source extension.
    """
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_stub_info(cfile, ignored=ignored),
        sort_key=lambda x: x["size"],
        warn_duplicates=warn_duplicates,
    )


def _collect_with_dedup(
    reversed_dir: Path,
    cfg: ProjectConfig | None,
    parser_fn: "Callable[[Path], list[StubInfo]]",
    sort_key: "Callable[[StubInfo], Any]",
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Collect StubInfo dicts from source files, deduplicating by VA.

    Shared implementation for find_near_miss, find_all_stubs, and
    find_all_matching.  The *parser_fn* is called on each source file and
    should return a list of StubInfo dicts.  Results are deduplicated by
    VA (first occurrence wins) and sorted by *sort_key*.
    """
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


def parse_matching_all(filepath: Path, ignored: set[str] | None = None) -> list[StubInfo]:
    """Extract all MATCHING annotations (no delta filter).

    Unlike ``parse_matching_info``, this accepts all MATCHING functions regardless
    of whether they have a BLOCKER annotation or byte delta.  Used by the batch
    flag sweep mode which targets every MATCHING function.
    """
    return _parse_annotations(filepath, status_filter={"MATCHING"}, ignored=ignored)


def find_all_matching(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
    warn_duplicates: bool = True,
) -> list[StubInfo]:
    """Find all MATCHING functions, sorted by byte delta then size.

    Used by ``--flag-sweep`` mode to sweep compiler flags across every
    MATCHING function.  Functions with known byte deltas are processed
    first (smallest delta = closest to match).
    """
    return _collect_with_dedup(
        reversed_dir,
        cfg,
        lambda cfile: parse_matching_all(cfile, ignored=ignored),
        sort_key=lambda x: (x.get("delta", 9999), x["size"]),
        warn_duplicates=warn_duplicates,
    )


def run_flag_sweep(
    stub: StubInfo,
    cfg: ProjectConfig,
    tier: str = "targeted",
    jobs: int = 4,
) -> tuple[float, str, list[tuple[float, str]]]:
    """Run a compiler flag sweep on a single function in-process.

    Reads source and target bytes, then calls ``flag_sweep()`` from the
    matcher engine.  Returns ``(best_score, best_flags, all_results)``.
    """
    from rebrew.compile_cache import get_compile_cache
    from rebrew.matcher import flag_sweep

    filepath = stub["filepath"]
    va_int = int(stub["va"], 16)
    size = stub["size"]
    symbol = stub["symbol"]
    cflags = stub["cflags"]

    source = filepath.read_text(encoding="utf-8")
    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size)
    if not target_bytes:
        return float("inf"), "", []

    compile_cfg = cfg.for_origin(stub.get("origin", ""))
    msvc_env = msvc_env_from_config(compile_cfg)
    cl_cmd = compile_cfg.compiler_command
    inc_dir = str(compile_cfg.compiler_includes)

    # Resolve paths relative to project root
    cl_parts = cl_cmd.split()
    cl_resolved = []
    for part in cl_parts:
        p = cfg.root / part
        cl_resolved.append(str(p) if p.exists() else part)
    cl_cmd = " ".join(cl_resolved)

    inc_path = cfg.root / inc_dir
    if inc_path.exists():
        inc_dir = str(inc_path)

    # Ensure compile-only flags
    if "/c" not in cflags:
        cflags = "/nologo /c " + cflags

    try:
        cc = get_compile_cache(cfg.root)
    except OSError:
        cc = None

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


def update_cflags_annotation(filepath: Path, new_cflags: str) -> bool:
    """Update the ``// CFLAGS:`` annotation in a source file.

    Returns True if the file was modified, False if the annotation
    was not found or already had the same value.
    """
    content = filepath.read_text(encoding="utf-8")
    pattern = r"^(//\s*)CFLAGS:\s*(.+)$"
    match = re.search(pattern, content, flags=re.MULTILINE)
    if match is None:
        return False

    old_cflags = match.group(2).strip()
    if old_cflags == new_cflags:
        return False

    updated = re.sub(
        pattern,
        rf"\g<1>CFLAGS: {new_cflags}",
        content,
        count=1,
        flags=re.MULTILINE,
    )
    atomic_write_text(filepath, updated, encoding="utf-8")
    return True


def run_ga(
    stub: StubInfo,
    compiler_command: str,
    inc_dir: Path,
    project_root: Path,
    generations: int = 200,
    pop: int = 48,
    jobs: int = 16,
    timeout_min: int = 30,
    extra_flags: list[str] | None = None,
) -> tuple[bool, str]:
    """Execute one GA matching run for a single parsed function target.

    The command shells out to ``python -m rebrew.match`` with source,
    symbol, VA/size, compile environment, and GA tuning parameters. Output
    is captured and scanned for an exact-match marker. On success, the helper
    attempts to apply ``best.c`` back into the original source file and update
    status annotations atomically.

    Args:
        stub: Parsed target metadata from annotation discovery.
        compiler_command: Compiler executable/command used by ``rebrew match``.
        inc_dir: Include directory passed to the matcher.
        project_root: Root directory used for output layout and subprocess cwd.
        generations: GA generation count.
        pop: GA population size.
        jobs: Parallel worker count.
        timeout_min: Timeout budget in minutes for this target.
        extra_flags: Optional extra CLI flags appended to matcher invocation.

    Returns:
        Tuple ``(matched, output)`` where ``matched`` is True for exact matches
        and ``output`` contains combined stdout/stderr (or ``TIMEOUT``).
    """
    filepath = stub["filepath"]
    # Use relative path with suffix stripped to avoid collisions when nested
    # dirs contain files with the same stem (e.g. game/init.c vs network/init.c).
    try:
        rel = filepath.relative_to(project_root)
    except ValueError:
        rel = Path(filepath.stem)
    out_dir = project_root / "output" / "ga_runs" / rel.with_suffix("")

    base_cflags = stub["cflags"]

    # Build the rebrew match CLI command.  seed_c is a positional argument.
    cmd = [
        sys.executable,
        "-m",
        "rebrew.match",
        str(filepath.resolve()),  # seed_c (positional)
        "--cl",
        compiler_command,
        "--inc",
        str(inc_dir.resolve()),
        "--cflags",
        base_cflags,
        "--compare-obj",
        "--target-va",
        stub["va"],
        "--target-size",
        str(stub["size"]),
        "--symbol",
        stub["symbol"],
        "--out-dir",
        str(out_dir),
        "--generations",
        str(generations),
        "--pop-size",
        str(pop),
        "-j",
        str(jobs),
    ]
    if extra_flags:
        cmd.extend(extra_flags)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_min * 60 + 60,
            cwd=str(project_root),
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"

    if result.returncode != 0 and "EXACT MATCH" not in output:
        return False, f"SUBPROCESS_ERROR (exit {result.returncode}): {output[-500:]}"

    matched = "EXACT MATCH" in output

    if matched:
        best_c = out_dir / "best.c"
        if best_c.exists():
            best_src = best_c.read_text(encoding="utf-8", errors="replace")
            try:
                update_stub_to_matched(filepath, best_src, stub)
            except (RuntimeError, OSError) as e:
                typer.echo(f"  WARNING: GA matched but failed to update source: {e}", err=True)

        # Record the solution for cross-function seeding
        try:
            from rebrew.solutions import SolutionEntry, save_solution

            entry = SolutionEntry(
                symbol=stub["symbol"],
                cflags=stub["cflags"],
                origin=stub.get("origin", ""),
                size=stub["size"],
                source_file=str(filepath.relative_to(project_root)),
                score=0.0,
                generations=generations,
            )
            save_solution(project_root, entry)
        except Exception:  # noqa: BLE001
            log.debug("Solution save failed", exc_info=True)

    return matched, output


def update_stub_to_matched(filepath: Path, best_src: str, stub: StubInfo) -> None:
    """Replace STUB source with matched source and update STATUS.

    Validates the transformed content before writing, then uses
    ``atomic_write_text`` (write-to-tmp + ``os.replace``) with a .bak
    backup to prevent data loss from crashes or invalid writes.
    """
    import tempfile

    bak_path = filepath.with_suffix(".c.bak")

    original = filepath.read_text(encoding="utf-8", errors="replace")

    # Handle both STUB and MATCHING status (near-miss mode uses MATCHING)
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
    # else: header already had STATUS: STUB replaced on line above

    # Validate the transformed content re-parses correctly *before* touching
    # the original file.  Write to a true temp file in the same directory so
    # parse_c_file_multi sees it on the same filesystem.
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

    # Backup original, then atomically replace
    shutil.copy2(filepath, bak_path)
    atomic_write_text(filepath, updated)

    # Show relative path for clarity in nested directory layouts.
    from rebrew.cli import rel_display_path

    display = rel_display_path(filepath, filepath.parent.parent)
    console.print(f"  [bold green]Updated[/] {display}: STUB → RELOC (backup: {bak_path.name})")


app = typer.Typer(
    help="Batch GA runner and flag sweep for STUB and MATCHING functions.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew ga                                     Run GA on all STUB functions

rebrew ga --dry-run                           List targets without running GA

rebrew ga --max-stubs 5                       Process at most 5 functions

rebrew ga --near-miss --threshold 10          Target MATCHING funcs within 10B

rebrew ga --flag-sweep                        Batch flag sweep on all MATCHING

rebrew ga --flag-sweep --tier targeted        Use targeted tier (~1.1K combos)

rebrew ga --flag-sweep --fix-cflags           Auto-update CFLAGS on exact match

rebrew ga --min-size 20 --max-size 200        Filter by function size

rebrew ga --filter my_func                    Only functions matching substring

rebrew ga -j 16 --generations 300 --pop-size 64  Tune GA parameters

[bold]Modes:[/bold]

[default]  GA on STUB functions (sorted by size, smallest first)

--near-miss  GA on MATCHING functions with small byte deltas

--flag-sweep  Compiler flag sweep on all MATCHING functions (no GA mutations)

[dim]Functions are processed smallest/easiest first. Duplicate VAs are
detected and skipped. Ignored symbols from rebrew-project.toml are excluded.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    max_stubs: int = typer.Option(0, help="Max functions to process (0=all)"),
    generations: int = typer.Option(200, help="GA generations per function"),
    pop_size: int = typer.Option(48, "--pop-size", help="GA population size"),
    jobs: int | None = typer.Option(
        None, "-j", "--jobs", help="Parallel jobs (default: from [project].jobs)"
    ),
    timeout_min: int = typer.Option(30, help="Per-function GA timeout in minutes"),
    dry_run: bool = typer.Option(False, help="List targets without running GA/sweep"),
    min_size: int = typer.Option(10, help="Min target size to attempt"),
    max_size: int = typer.Option(9999, help="Max target size to attempt"),
    filter_str: str = typer.Option(
        "", "--filter", help="Only process functions matching this substring"
    ),
    near_miss: bool = typer.Option(
        False, "--near-miss", help="Target MATCHING functions instead of STUBs"
    ),
    threshold: int = typer.Option(10, "--threshold", help="Max byte delta for --near-miss mode"),
    flag_sweep: bool = typer.Option(
        False, "--flag-sweep", help="Batch flag sweep on all MATCHING functions (no GA mutations)"
    ),
    tier: str = typer.Option(
        "targeted",
        "--tier",
        help="Flag sweep tier: quick (~192), targeted (~1.1K), normal (~21K), thorough (~1M). Default: targeted.",
    ),
    fix_cflags: bool = typer.Option(
        False,
        "--fix-cflags",
        help="Auto-update CFLAGS annotation when flag sweep finds exact match",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    seed_from_solved: bool = typer.Option(
        True,
        "--seed-from-solved/--no-seed",
        help="Seed GA population from similar solved functions (default: on)",
    ),
    target: str | None = TargetOption,
) -> None:
    """Run GA or batch flag sweep across STUB/MATCHING functions."""
    cfg = require_config(target=target)
    if jobs is None:
        jobs = int(cfg.default_jobs)

    reversed_dir = cfg.reversed_dir
    ignored = set(cfg.ignored_symbols or [])

    if flag_sweep:
        stubs = find_all_matching(
            reversed_dir,
            ignored=ignored,
            cfg=cfg,
            warn_duplicates=not json_output,
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
            reversed_dir,
            ignored=ignored,
            cfg=cfg,
            warn_duplicates=not json_output,
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
                json.dumps(
                    {
                        "mode": mode_label,
                        "dry_run": True,
                        "count": len(stubs),
                        "items": items,
                    },
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
            print(
                f"[{i}/{len(stubs)}] {display} ({stub['size']}B)",
                file=sys.stderr,
            )

        ga_cfg = cfg.for_origin(stub.get("origin", ""))

        # Look up similar solved functions to seed the GA
        extra_ga_flags: list[str] = []
        if seed_from_solved:
            try:
                from rebrew.solutions import find_similar

                similar = find_similar(
                    cfg.root,
                    origin=stub.get("origin", ""),
                    size=stub["size"],
                    cflags=stub["cflags"],
                    top_k=3,
                )
                for sol in similar:
                    sol_path = cfg.root / sol.source_file
                    if sol_path.exists():
                        extra_ga_flags.extend(["--extra-seed", str(sol_path)])
                        if not json_output:
                            console.print(
                                f"  [dim]Seeding from solved:[/] {sol.symbol} ({sol.size}B)"
                            )
            except Exception:  # noqa: BLE001
                logging.debug("Solution lookup failed", exc_info=True)

        matched, output = run_ga(
            stub,
            compiler_command=ga_cfg.compiler_command,
            inc_dir=ga_cfg.compiler_includes,
            project_root=cfg.root,
            generations=generations,
            pop=pop_size,
            jobs=jobs,
            timeout_min=timeout_min,
            extra_flags=extra_ga_flags or None,
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
                last_lines = output.strip().split("\n")[-5:]
                console.print("  [red]No match.[/] Last output:")
                for line in last_lines:
                    console.print(f"    [dim]{line}[/]")

        ga_results.append(result_entry)

    if json_output:
        print(
            json.dumps(
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
            print(
                f"[{i}/{len(stubs)}] {display} ({stub['size']}B)",
                file=sys.stderr,
            )

        best_score, best_flags, all_results = run_flag_sweep(
            stub,
            cfg,
            tier=tier,
            jobs=jobs,
        )

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
                for score, flags in all_results[:top_n]:
                    marker = " ← [bold green]EXACT[/]" if score < 0.1 else ""
                    console.print(f"  {score:8.2f}: [dim]{flags}[/]{marker}")
                if is_exact:
                    console.print(f"  [bold green]EXACT MATCH[/] with flags: {best_flags}")
                    if cflags_updated:
                        console.print(f"  [bold]Updated CFLAGS annotation → {best_flags}[/]")

        sweep_results.append(result_entry)

    if json_output:
        print(
            json.dumps(
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
