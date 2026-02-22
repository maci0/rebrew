#!/usr/bin/env python3
"""
extract_target.py — Compile a C file with MSVC6 (via Wine), then extract
a named function's bytes from the resulting EXE using the MAP file.

Saves:
  <out-dir>/target.exe
  <out-dir>/target.map
  <out-dir>/<symbol>.bin

Usage:
  python3 extract_target.py \
    --cl "wine /path/to/CL.EXE" \
    --link "wine /path/to/LINK.EXE" \
    --inc "/path/to/Include" \
    --lib "/path/to/Lib" \
    --cflags "/nologo /c /O2 /MT /Gd" \
    --ldflags "/nologo /SUBSYSTEM:CONSOLE" \
    --source target.c \
    --symbol _add \
    --out-dir target/
"""

import argparse
import sys
from pathlib import Path

# Reuse functions from matcher.py
from rebrew.matcher import (
    build_candidate,
    extract_candidate_symbol_bytes,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract target function bytes from a C source file")
    ap.add_argument("--cl", required=True, help="CL.EXE command (e.g. 'wine /path/CL.EXE')")
    ap.add_argument("--link", required=True, help="LINK.EXE command")
    ap.add_argument("--inc", required=True, help="MSVC Include directory")
    ap.add_argument("--lib", required=True, help="MSVC Lib directory")
    ap.add_argument("--cflags", required=True, help="Compiler flags")
    ap.add_argument("--ldflags", required=True, help="Linker flags")
    ap.add_argument("--source", required=True, help="C source file to compile")
    ap.add_argument("--symbol", required=True, help="Symbol name to extract (e.g. _add)")
    ap.add_argument("--out-dir", default="target", help="Output directory")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    source_text = Path(args.source).read_text(encoding="utf-8", errors="ignore")

    print(f"Compiling {args.source}...")
    ok, exe_path, map_path, log = build_candidate(
        workdir=out_dir,
        cl_cmd=args.cl,
        link_cmd=args.link,
        inc_dir=args.inc,
        lib_dir=args.lib,
        cflags=args.cflags,
        ldflags=args.ldflags,
        c_source_text=source_text,
        exe_name="target.exe",
        map_name="target.map",
        verbose=True,
    )

    if not ok or exe_path is None or map_path is None:
        print(f"Build failed:\n{log}", file=sys.stderr)
        return 1

    print(f"Build OK: {exe_path}")

    func_bytes = extract_candidate_symbol_bytes(exe_path, map_path, args.symbol)
    if func_bytes is None:
        print(f"Could not extract symbol '{args.symbol}' from MAP.", file=sys.stderr)
        return 1

    bin_path = out_dir / f"{args.symbol}.bin"
    bin_path.write_bytes(func_bytes)
    print(f"Extracted {len(func_bytes)} bytes for '{args.symbol}' -> {bin_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
