#!/usr/bin/env python3
"""Batch GA runner for STUB and near-miss MATCHING functions.

Parses all .c files in the reversed directory for STUB annotations (default)
or MATCHING annotations with a small byte delta (--near-miss), then runs
rebrew-match GA on each one (sorted by target size, smallest first) to attempt
automatic byte-perfect matching.

Usage:
    rebrew-ga [--max-stubs N] [--generations G] [-j JOBS] [--dry-run]
    rebrew-ga --near-miss --threshold 10
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import typer

from rebrew.annotation import has_skip_annotation, parse_c_file, resolve_symbol
from rebrew.cli import TargetOption, get_config


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


def parse_stub_info(filepath: Path, ignored: set[str] | None = None) -> StubInfo | None:
    """Extract STUB annotation fields from a reversed .c file.

    Uses the canonical parser from rebrew.annotation, then applies
    STUB-specific filtering (SKIP, ignored symbols, min size).

    Args:
        filepath: Path to the .c source file.
        ignored: Set of symbol names to skip (from cfg.ignored_symbols).
    """
    if ignored is None:
        ignored = set()
    entry = parse_c_file(filepath)
    if entry is None:
        return None

    status = entry["status"]
    if status != "STUB":
        return None

    if has_skip_annotation(filepath):
        return None

    symbol = resolve_symbol(entry, filepath)
    if symbol in ignored or symbol.lstrip("_") in ignored:
        return None

    if entry.va < 0x1000:
        return None

    size = entry["size"]
    if size < 10:
        return None

    # Fallback defaults — used only when annotation lacks CFLAGS/ORIGIN.
    # Config-driven values should be set upstream in the annotation itself.
    cflags = entry["cflags"] or "/O2 /Gd"
    origin = entry["origin"] or "GAME"

    return {
        "filepath": filepath,
        "va": f"0x{entry['va']:08X}",
        "size": size,
        "symbol": symbol,
        "cflags": cflags,
        "origin": origin,
    }


def parse_matching_info(
    filepath: Path, ignored: set[str] | None = None, max_delta: int = 10
) -> StubInfo | None:
    """Extract MATCHING annotation fields from a reversed .c file.

    Like parse_stub_info but for MATCHING functions with small byte deltas.
    Only returns functions whose BLOCKER byte-delta is <= max_delta.

    Args:
        filepath: Path to the .c source file.
        ignored: Set of symbol names to skip.
        max_delta: Maximum byte delta to include.
    """
    from rebrew.next import parse_byte_delta

    if ignored is None:
        ignored = set()
    entry = parse_c_file(filepath)
    if entry is None:
        return None

    status = entry["status"]
    if status != "MATCHING":
        return None

    if entry.va < 0x1000:
        return None

    if has_skip_annotation(filepath):
        return None

    symbol = resolve_symbol(entry, filepath)
    if symbol in ignored or symbol.lstrip("_") in ignored:
        return None

    size = entry["size"]
    if size < 10:
        return None

    # Parse byte delta from BLOCKER annotation
    blocker = entry.get("blocker") or ""
    delta = parse_byte_delta(blocker) if blocker else None
    if delta is None or delta > max_delta:
        return None

    cflags = entry["cflags"] or "/O2 /Gd"
    origin = entry["origin"] or "GAME"

    return {
        "filepath": filepath,
        "va": f"0x{entry['va']:08X}",
        "size": size,
        "symbol": symbol,
        "cflags": cflags,
        "origin": origin,
        "delta": delta,
    }


def find_near_miss(
    reversed_dir: Path,
    ignored: set[str] | None = None,
    max_delta: int = 10,
    cfg: Any = None,
) -> list[StubInfo]:
    """Find MATCHING functions with small byte deltas, sorted by delta ascending.

    Args:
        reversed_dir: Directory containing reversed .c files.
        ignored: Set of symbol names to skip.
        max_delta: Maximum byte delta to include.
        cfg: Optional config for source extension.
    """
    from rebrew.cli import iter_sources, rel_display_path

    results = []
    seen_vas: dict[str, str] = {}

    if not reversed_dir.exists():
        return results

    for cfile in iter_sources(reversed_dir, cfg):
        info = parse_matching_info(cfile, ignored=ignored, max_delta=max_delta)
        if info is not None:
            va_str = info["va"]
            rel_name = rel_display_path(cfile, reversed_dir)
            if va_str in seen_vas:
                print(
                    f"  WARNING: Duplicate VA {va_str} found in {rel_name} "
                    f"(already in {seen_vas[va_str]}), skipping"
                )
                continue
            seen_vas[va_str] = rel_name
            results.append(info)

    # Sort by delta (smallest first = easiest to match)
    results.sort(key=lambda x: (x["delta"], x["size"]))
    return results


def find_all_stubs(
    reversed_dir: Path, ignored: set[str] | None = None, cfg: Any = None
) -> list[StubInfo]:
    """Find all STUB files in reversed/ and return sorted by size.

    Detects and warns about duplicate VAs across files, keeping only the first.

    Args:
        reversed_dir: Directory containing reversed .c files.
        ignored: Set of symbol names to skip (from cfg.ignored_symbols).
        cfg: Optional config for source extension.
    """
    from rebrew.cli import iter_sources, rel_display_path

    stubs = []
    seen_vas: dict[str, str] = {}  # va_str -> rel_path

    if not reversed_dir.exists():
        return stubs

    for cfile in iter_sources(reversed_dir, cfg):
        info = parse_stub_info(cfile, ignored=ignored)
        if info is not None:
            va_str = info["va"]
            rel_name = rel_display_path(cfile, reversed_dir)
            if va_str in seen_vas:
                print(
                    f"  WARNING: Duplicate VA {va_str} found in {rel_name} "
                    f"(already in {seen_vas[va_str]}), skipping"
                )
                continue
            seen_vas[va_str] = rel_name
            stubs.append(info)
    stubs.sort(key=lambda x: x["size"])
    return stubs


def run_ga(
    stub: StubInfo,
    target_binary: Path,
    compiler_command: str,
    inc_dir: Path,
    project_root: Path,
    generations: int = 200,
    pop: int = 48,
    jobs: int = 16,
    timeout_min: int = 30,
    extra_flags: list[str] | None = None,
) -> tuple[bool, str]:
    """Run rebrew-match GA on a single STUB. Returns (matched, output)."""
    filepath = stub["filepath"]
    # Use relative path with suffix stripped to avoid collisions when nested
    # dirs contain files with the same stem (e.g. game/init.c vs network/init.c).
    try:
        rel = filepath.relative_to(project_root)
    except ValueError:
        rel = Path(filepath.stem)
    out_dir = project_root / "output" / "ga_runs" / rel.with_suffix("")

    base_cflags = stub["cflags"]

    # Build the rebrew-match CLI command.  seed_c is a positional argument.
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

    matched = "EXACT MATCH" in output

    if matched:
        best_c = out_dir / "best.c"
        if best_c.exists():
            best_src = best_c.read_text(encoding="utf-8", errors="replace")
            try:
                update_stub_to_matched(filepath, best_src, stub)
            except (RuntimeError, OSError) as e:
                print(f"  WARNING: GA matched but failed to update source: {e}")

    return matched, output


def update_stub_to_matched(filepath: Path, best_src: str, stub: StubInfo) -> None:
    """Replace STUB source with matched source and update STATUS.

    Uses atomic write (write to .tmp, validate, rename) with .bak backup
    to prevent data loss from crashes or invalid writes.
    """
    tmp_path = filepath.with_suffix(".c.tmp")
    bak_path = filepath.with_suffix(".c.bak")

    original = filepath.read_text(encoding="utf-8", errors="replace")

    # Handle both STUB and MATCHING status (near-miss mode uses MATCHING)
    updated = re.sub(
        r"^(//\s*)STATUS:\s*(STUB|MATCHING(?:_RELOC)?)",
        r"\1STATUS: RELOC",
        original,
        flags=re.MULTILINE,
    )
    if "BLOCKER:" in updated:
        updated = re.sub(r"//\s*BLOCKER:[^\n]*\n?", "", updated)
        updated = re.sub(r"/\*\s*BLOCKER:.*?\*/[ \t]*\n?", "", updated)

    body_start = _FUNC_START_RE.search(updated)
    best_body = _FUNC_START_RE.search(best_src)

    if body_start and best_body:
        header = updated[: body_start.start()]
        new_body = best_src[best_body.start() :]
        updated = header + new_body
    # else: header already had STATUS: STUB replaced on line above

    # Write to temp file first
    tmp_path.write_text(updated, encoding="utf-8")

    # Validate the written file re-parses correctly
    anno = parse_c_file(tmp_path)
    if anno is None:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"Post-write validation failed: {filepath} would not re-parse after stub update"
        )

    # Atomic swap: backup original, rename tmp to source
    shutil.copy2(filepath, bak_path)
    tmp_path.rename(filepath)
    # Show relative path for clarity in nested directory layouts.
    from rebrew.cli import rel_display_path

    display = rel_display_path(filepath, filepath.parent.parent)
    print(f"  Updated {display}: STUB -> RELOC (backup: {bak_path.name})")


app = typer.Typer(
    help="Batch GA runner for STUB and near-miss MATCHING functions.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]
  rebrew-ga                                     Run GA on all STUB functions
  rebrew-ga --dry-run                           List targets without running GA
  rebrew-ga --max-stubs 5                       Process at most 5 functions
  rebrew-ga --near-miss --threshold 10          Target MATCHING funcs within 10B
  rebrew-ga --min-size 20 --max-size 200        Filter by function size
  rebrew-ga --filter my_func                    Only functions matching substring
  rebrew-ga -j 16 --generations 300 --pop 64    Tune GA parameters

[bold]How it works:[/bold]
  Scans reversed_dir for STUB (or near-miss MATCHING) annotations, sorts by
  size (smallest first), and runs rebrew-match GA on each one. On match,
  auto-updates the .c file from STUB → RELOC with the matched source.

[dim]Functions are processed smallest-first for quick wins. Duplicate VAs are
detected and skipped. Ignored symbols from rebrew.toml are excluded.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    max_stubs: int = typer.Option(0, help="Max functions to process (0=all)"),
    generations: int = typer.Option(200),
    pop: int = typer.Option(48),
    jobs: int | None = typer.Option(
        None, "-j", "--jobs", help="Parallel jobs (default: from [project].jobs)"
    ),
    timeout_min: int = typer.Option(30, help="Per-function GA timeout in minutes"),
    dry_run: bool = typer.Option(False, help="List targets without running GA"),
    min_size: int = typer.Option(0, help="Min target size to attempt"),
    max_size: int = typer.Option(9999, help="Max target size to attempt"),
    filter_str: str = typer.Option(
        "", "--filter", help="Only process functions matching this substring"
    ),
    near_miss: bool = typer.Option(
        False, "--near-miss", help="Target MATCHING functions instead of STUBs"
    ),
    threshold: int = typer.Option(10, "--threshold", help="Max byte delta for --near-miss mode"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Batch GA runner for STUB and near-miss MATCHING functions."""
    cfg = get_config(target=target)
    if jobs is None:
        jobs = int(getattr(cfg, "default_jobs", 4))

    reversed_dir = cfg.reversed_dir
    target_binary = cfg.target_binary

    # Build ignored symbols set from config
    ignored = set(getattr(cfg, "ignored_symbols", None) or [])

    if near_miss:
        stubs = find_near_miss(reversed_dir, ignored=ignored, max_delta=threshold, cfg=cfg)
        mode_label = "MATCHING (near-miss)"
    else:
        stubs = find_all_stubs(reversed_dir, ignored=ignored, cfg=cfg)
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
        print(f"Found {len(stubs)} {mode_label} function(s) to process:\n")
        for i, stub in enumerate(stubs, 1):
            delta_str = f"  Δ{stub['delta']}B" if "delta" in stub else ""
            display = rel_display_path(stub["filepath"], reversed_dir)
            print(
                f"  {i:3d}. {display:45s}  {stub['size']:4d}B  "
                f"{stub['va']}  {stub['symbol']:30s}  {stub['cflags']}{delta_str}"
            )
        print()

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
            print("Dry run — exiting.")
        return

    Path("output/ga_runs").mkdir(parents=True, exist_ok=True)

    matched_count = 0
    failed_count = 0
    ga_results: list[dict[str, Any]] = []

    for i, stub in enumerate(stubs, 1):
        display = rel_display_path(stub["filepath"], reversed_dir)
        if not json_output:
            print(f"\n{'=' * 60}")
            print(f"[{i}/{len(stubs)}] {display} ({stub['size']}B) symbol={stub['symbol']}")
            print(f"{'=' * 60}")
        else:
            print(
                f"[{i}/{len(stubs)}] {display} ({stub['size']}B)",
                file=sys.stderr,
            )

        matched, output = run_ga(
            stub,
            target_binary=target_binary,
            compiler_command=cfg.compiler_command,
            inc_dir=cfg.compiler_includes,
            project_root=cfg.root,
            generations=generations,
            pop=pop,
            jobs=jobs,
            timeout_min=timeout_min,
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
                print(f"  MATCHED! ({matched_count} total matches)")
        else:
            failed_count += 1
            if not json_output:
                last_lines = output.strip().split("\n")[-5:]
                print("  No match. Last output:")
                for line in last_lines:
                    print(f"    {line}")

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
        print(f"\n{'=' * 60}")
        print(f"Results: {matched_count} matched, {failed_count} failed, {len(stubs)} total")
        print(f"{'=' * 60}")


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
