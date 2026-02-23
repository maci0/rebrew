#!/usr/bin/env python3
"""Batch GA runner for STUB functions.

Parses all .c files in the reversed directory for STUB annotations, then runs
rebrew-match GA on each one (sorted by target size, smallest first) to attempt
automatic byte-perfect matching.

Usage:
    rebrew-ga [--max-stubs N] [--generations G] [-j JOBS] [--dry-run]
"""

import re
import subprocess
import sys
from pathlib import Path

import typer

from rebrew.annotation import parse_c_file
from rebrew.cli import TargetOption, get_config

# ga.py invokes rebrew-match as a subprocess for each STUB function.

NON_MATCHABLE_SYMBOLS = frozenset(
    [
        "_strlen",
        "_strcmp",
        "_memset",
        "_strstr",
        "_strchr",
        "_strncpy",
        "__aulldiv",
        "__aullrem",
        "__local_unwind2",
    ]
)


def parse_stub_info(filepath: Path) -> dict | None:
    """Extract STUB annotation fields from a reversed .c file.

    Uses the canonical parser from rebrew.annotation, then applies
    STUB-specific filtering (SKIP, NON_MATCHABLE_SYMBOLS, min size).
    """
    entry = parse_c_file(filepath)
    if entry is None:
        return None

    status = entry["status"]
    if status != "STUB":
        return None

    # Read raw text to check for SKIP key (not always in canonical parser)
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.split("\n")[:20]:
        stripped = line.strip()
        if stripped.upper().startswith("// SKIP:") or stripped.upper().startswith("/* SKIP:"):
            return None

    symbol = entry["symbol"]
    if symbol == "?" or not symbol:
        func_name = filepath.stem
        symbol = "_" + func_name
    if symbol.lstrip("_") in NON_MATCHABLE_SYMBOLS or symbol in NON_MATCHABLE_SYMBOLS:
        return None

    size = entry["size"]
    if size < 10:
        return None

    cflags = entry["cflags"] or "/O2 /Gd"
    origin = entry["origin"] or "GAME"

    return {
        "filepath": filepath,
        "va": f"0x{entry['va']:08X}" if isinstance(entry['va'], int) else entry['va'],
        "size": size,
        "symbol": symbol,
        "cflags": cflags,
        "origin": origin,
    }


def find_all_stubs(reversed_dir: Path) -> list[dict]:
    """Find all STUB files in reversed/ and return sorted by size."""
    stubs = []
    if not reversed_dir.exists():
        return stubs

    for cfile in sorted(reversed_dir.glob("*.c")):
        info = parse_stub_info(cfile)
        if info is not None:
            stubs.append(info)
    stubs.sort(key=lambda x: x["size"])
    return stubs


def run_ga(
    stub: dict,
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
    out_dir = project_root / "output" / "ga_runs" / filepath.stem

    base_cflags = "/nologo /c /MT " + stub["cflags"]

    # Build the rebrew-match CLI command.  seed_c is a positional argument.
    cmd = [
        sys.executable, "-m", "rebrew.match",
        str(filepath.resolve()),       # seed_c (positional)
        "--cl", compiler_command,
        "--inc", str(inc_dir.resolve()),
        "--cflags", base_cflags,
        "--compare-obj",
        "--target-va", stub["va"],
        "--target-size", str(stub["size"]),
        "--symbol", stub["symbol"],
        "--out-dir", str(out_dir),
        "--generations", str(generations),
        "--pop-size", str(pop),
        "-j", str(jobs),
    ]
    if extra_flags:
        cmd.extend(extra_flags)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_min * 60 + 60,
            cwd=str(project_root),
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"

    matched = "EXACT MATCH" in output or "score = 0.0" in output.lower()

    if matched:
        best_c = out_dir / "best.c"
        if best_c.exists():
            best_src = best_c.read_text(encoding="utf-8", errors="replace")
            update_stub_to_matched(filepath, best_src, stub)

    return matched, output


def update_stub_to_matched(filepath: Path, best_src: str, stub: dict) -> None:
    """Replace STUB source with matched source and update STATUS."""
    original = filepath.read_text(encoding="utf-8", errors="replace")

    updated = original.replace("STATUS: STUB", "STATUS: RELOC")
    if "BLOCKER:" in updated:
        updated = re.sub(r"//\s*BLOCKER:.*\n?", "", updated)
        updated = re.sub(r"/\*\s*BLOCKER:.*?\*/\s*\n?", "", updated)

    body_start = re.search(
        r"^(?:BOOL|int|void|char|short|long|unsigned|DWORD|HANDLE|LPVOID|static|__declspec)\s",
        original,
        re.MULTILINE,
    )
    best_body = re.search(
        r"^(?:BOOL|int|void|char|short|long|unsigned|DWORD|HANDLE|LPVOID|static|__declspec)\s",
        best_src,
        re.MULTILINE,
    )

    if body_start and best_body:
        header = updated[: body_start.start()]
        new_body = best_src[best_body.start() :]
        updated = header + new_body
    else:
        updated = updated.replace("STATUS: STUB", "STATUS: RELOC")

    filepath.write_text(updated, encoding="utf-8")
    print(f"  Updated {filepath.name}: STUB -> RELOC")




app = typer.Typer(help="Batch GA runner for STUB functions")

@app.callback(invoke_without_command=True)
def main(
    max_stubs: int = typer.Option(0, help="Max stubs to process (0=all)"),
    generations: int = typer.Option(200),
    pop: int = typer.Option(48),
    jobs: int = typer.Option(16, "-j", "--jobs"),
    timeout_min: int = typer.Option(30, help="Per-stub GA timeout in minutes"),
    dry_run: bool = typer.Option(False, help="List stubs without running GA"),
    min_size: int = typer.Option(0, help="Min target size to attempt"),
    max_size: int = typer.Option(9999, help="Max target size to attempt"),
    filter_str: str = typer.Option("", "--filter", help="Only process stubs matching this substring"),
    target: str | None = TargetOption,
):
    """Batch GA runner for STUB functions."""
    cfg = get_config(target=target)

    reversed_dir = cfg.reversed_dir
    target_binary = cfg.target_binary

    stubs = find_all_stubs(reversed_dir)

    if min_size > 0:
        stubs = [s for s in stubs if s["size"] >= min_size]
    if max_size < 9999:
        stubs = [s for s in stubs if s["size"] <= max_size]
    if filter_str:
        stubs = [s for s in stubs if filter_str in str(s["filepath"])]
    if max_stubs > 0:
        stubs = stubs[: max_stubs]

    print(f"Found {len(stubs)} STUB(s) to process:\n")
    for i, stub in enumerate(stubs, 1):
        print(
            f"  {i:3d}. {stub['filepath'].name:45s}  {stub['size']:4d}B  "
            f"{stub['va']}  {stub['symbol']:30s}  {stub['cflags']}"
        )
    print()

    if dry_run:
        print("Dry run — exiting.")
        return

    Path("output/ga_runs").mkdir(parents=True, exist_ok=True)

    matched_count = 0
    failed_count = 0

    for i, stub in enumerate(stubs, 1):
        print(f"\n{'=' * 60}")
        print(
            f"[{i}/{len(stubs)}] {stub['filepath'].name} ({stub['size']}B) "
            f"symbol={stub['symbol']}"
        )
        print(f"{'=' * 60}")

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

        if matched:
            matched_count += 1
            print(f"  MATCHED! ({matched_count} total matches)")
        else:
            failed_count += 1
            last_lines = output.strip().split("\n")[-5:]
            print("  No match. Last output:")
            for line in last_lines:
                print(f"    {line}")

    print(f"\n{'=' * 60}")
    print(
        f"Results: {matched_count} matched, {failed_count} failed, {len(stubs)} total"
    )
    print(f"{'=' * 60}")


def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
