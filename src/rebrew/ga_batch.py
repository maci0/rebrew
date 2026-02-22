#!/usr/bin/env python3
"""Batch GA runner for STUB functions.

Parses all server_dll/*.c files for STUB annotations, then runs matcher.py
GA on each one (sorted by target size, smallest first) to attempt automatic
byte-perfect matching.

Usage:
    uv run python ga_batch.py [--max-stubs N] [--generations G] [-j JOBS] [--dry-run]
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

# PROJECT_ROOT removed — use cfg.root
MATCHER_PY = Path(__file__).parent / "matcher.py"

try:
    from rebrew.config import cfg as _cfg
    REVERSED_DIR = _cfg.reversed_dir
    SERVER_DLL = _cfg.target_binary
    TOOLS_DIR = Path(__file__).parent / "MSVC600" / "VC98"
    CL_EXE = TOOLS_DIR / "Bin" / "CL.EXE"
    INC_DIR = _cfg.compiler_includes
except Exception:
    REVERSED_DIR = PROJECT_ROOT / "src" / "server_dll"
    SERVER_DLL = PROJECT_ROOT / "original" / "Server" / "server.dll"
    TOOLS_DIR = Path(__file__).parent / "MSVC600" / "VC98"
    CL_EXE = TOOLS_DIR / "Bin" / "CL.EXE"
    INC_DIR = TOOLS_DIR / "Include"

_MARKER_RE = re.compile(
    r"//\s*(?:FUNCTION|LIBRARY|STUB):\s*SERVER\s+(0x[0-9a-fA-F]+)"
    r"|/\*\s*(?:FUNCTION|LIBRARY|STUB):\s*SERVER\s+(0x[0-9a-fA-F]+)\s*\*/"
)
_KV_RE = re.compile(
    r"//\s*(\w+):\s*(.*)"
    r"|/\*\s*(\w+):\s*(.*?)\s*\*/"
)

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


def parse_stub_info(filepath: Path) -> Optional[dict]:
    """Extract STUB annotation fields from a reversed .c file."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    lines = text.split("\n")
    header_lines = lines[:20]

    va = None
    kv = {}

    for line in header_lines:
        m = _MARKER_RE.match(line.strip())
        if m:
            va = m.group(1) or m.group(2)
            continue
        m2 = _KV_RE.match(line.strip())
        if m2:
            key = (m2.group(1) or m2.group(3)).upper()
            val = (m2.group(2) or m2.group(4)).strip()
            kv[key] = val

    if va is None:
        return None

    status = kv.get("STATUS", "")
    if status != "STUB":
        return None

    skip = kv.get("SKIP", "")
    if skip:
        return None

    symbol = kv.get("SYMBOL", "")
    if symbol == "?" or not symbol:
        func_name = filepath.stem
        symbol = "_" + func_name
    if symbol.lstrip("_") in NON_MATCHABLE_SYMBOLS or symbol in NON_MATCHABLE_SYMBOLS:
        return None

    size_str = kv.get("SIZE", "0")
    try:
        size = int(size_str)
    except ValueError:
        size = 0
    if size < 10:
        return None

    cflags = kv.get("CFLAGS", "/O2 /Gd")
    origin = kv.get("ORIGIN", "GAME")

    return {
        "filepath": filepath,
        "va": va,
        "size": size,
        "symbol": symbol,
        "cflags": cflags,
        "origin": origin,
    }


def find_all_stubs() -> List[dict]:
    """Find all STUB files in reversed/ and return sorted by size."""
    stubs = []
    for cfile in sorted(REVERSED_DIR.glob("*.c")):
        info = parse_stub_info(cfile)
        if info is not None:
            stubs.append(info)
    stubs.sort(key=lambda x: x["size"])
    return stubs


def run_ga(
    stub: dict,
    generations: int = 200,
    pop: int = 48,
    jobs: int = 16,
    timeout_min: int = 30,
    extra_flags: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Run matcher.py GA on a single STUB. Returns (matched, output)."""
    filepath = stub["filepath"]
    out_dir = Path("output/ga_runs") / filepath.stem

    base_cflags = "/nologo /c /MT " + stub["cflags"]

    cmd = [
        sys.executable,
        str(MATCHER_PY),
        "--cl",
        "wine " + str(CL_EXE.resolve()),
        "--inc",
        str(INC_DIR.resolve()),
        "--cflags",
        base_cflags,
        "--compare-obj",
        "--target-exe",
        str(SERVER_DLL.resolve()),
        "--target-va",
        stub["va"],
        "--target-size",
        str(stub["size"]),
        "--symbol",
        stub["symbol"],
        "--seed-c",
        str(filepath.resolve()),
        "--out-dir",
        str(out_dir),
        "--generations",
        str(generations),
        "--pop",
        str(pop),
        "-j",
        str(jobs),
        "--timeout-min",
        str(timeout_min),
        "--diff",
    ]
    if extra_flags:
        cmd.extend(extra_flags)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_min * 60 + 60,
            cwd=str(PROJECT_ROOT),
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


def main():
    parser = argparse.ArgumentParser(description="Batch GA runner for STUB functions")
    parser.add_argument(
        "--max-stubs", type=int, default=0, help="Max stubs to process (0=all)"
    )
    parser.add_argument("--generations", type=int, default=200)
    parser.add_argument("--pop", type=int, default=48)
    parser.add_argument("-j", "--jobs", type=int, default=16)
    parser.add_argument(
        "--timeout-min", type=int, default=30, help="Per-stub GA timeout in minutes"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="List stubs without running GA"
    )
    parser.add_argument(
        "--min-size", type=int, default=0, help="Min target size to attempt"
    )
    parser.add_argument(
        "--max-size", type=int, default=9999, help="Max target size to attempt"
    )
    parser.add_argument(
        "--filter",
        type=str,
        default="",
        help="Only process stubs matching this substring",
    )
    args = parser.parse_args()

    stubs = find_all_stubs()

    if args.min_size > 0:
        stubs = [s for s in stubs if s["size"] >= args.min_size]
    if args.max_size < 9999:
        stubs = [s for s in stubs if s["size"] <= args.max_size]
    if args.filter:
        stubs = [s for s in stubs if args.filter in str(s["filepath"])]
    if args.max_stubs > 0:
        stubs = stubs[: args.max_stubs]

    print(f"Found {len(stubs)} STUB(s) to process:\n")
    for i, stub in enumerate(stubs, 1):
        print(
            f"  {i:3d}. {stub['filepath'].name:45s}  {stub['size']:4d}B  "
            f"{stub['va']}  {stub['symbol']:30s}  {stub['cflags']}"
        )
    print()

    if args.dry_run:
        print("Dry run — exiting.")
        return

    os.makedirs("output/ga_runs", exist_ok=True)

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
            generations=args.generations,
            pop=args.pop,
            jobs=args.jobs,
            timeout_min=args.timeout_min,
        )

        if matched:
            matched_count += 1
            print(f"  MATCHED! ({matched_count} total matches)")
        else:
            failed_count += 1
            last_lines = output.strip().split("\n")[-5:]
            print(f"  No match. Last output:")
            for line in last_lines:
                print(f"    {line}")

    print(f"\n{'=' * 60}")
    print(
        f"Results: {matched_count} matched, {failed_count} failed, {len(stubs)} total"
    )
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
