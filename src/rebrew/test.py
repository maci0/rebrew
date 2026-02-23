#!/usr/bin/env python3
"""Quick compile-and-compare for reversed functions.

Usage:
    rebrew-test <source.c> [symbol] [--va 0xHEX --size N] [--cflags ...]
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import typer
import rich

from rebrew.cli import TargetOption, get_config
from rebrew.matcher.parsers import list_obj_symbols, parse_coff_symbol_bytes
from rebrew.annotation import parse_c_file


def compile_obj(cfg, source_path, cflags, workdir):
    """Compile .c to .obj using MSVC6 under Wine."""
    # Copy source to workdir for Wine compatibility
    src_name = os.path.basename(source_path)
    local_src = os.path.join(workdir, src_name)
    shutil.copy2(source_path, local_src)

    obj_name = os.path.splitext(src_name)[0] + ".obj"
    cmd_parts = cfg.compiler_command.split()
    if len(cmd_parts) > 1 and cmd_parts[0] == "wine":
        # Handle "wine path/to/cl.exe"
        cl_rel = Path(cmd_parts[1])
        cl_abs = str(cfg.root / cl_rel) if not cl_rel.is_absolute() else str(cl_rel)
        cmd = ["wine", cl_abs, "/nologo", "/c"]
    else:
        # Handle "cl.exe" or "path/to/cl.exe"
        cl_rel = Path(cfg.compiler_command)
        cl_abs = str(cfg.root / cl_rel) if not cl_rel.is_absolute() else str(cl_rel)
        cmd = [cl_abs, "/nologo", "/c"]

    inc_path = str(cfg.compiler_includes)

    cmd = (
        cmd
        + cflags
        + [f"/I{inc_path}", f"/Fo{obj_name}", src_name]
    )
    r = subprocess.run(
        cmd, capture_output=True, cwd=workdir, env=cfg.msvc_env()
    )
    obj_path = os.path.join(workdir, obj_name)
    if r.returncode != 0 or not os.path.exists(obj_path):
        return None, r.stderr.decode() + r.stdout.decode()
    return obj_path, ""


def smart_reloc_compare(obj_bytes, target_bytes, coff_relocs=None):
    """Compare bytes with relocation masking.
    Uses COFF relocation records if available, falls back to zero-span detection."""
    min_len = min(len(obj_bytes), len(target_bytes))
    max_len = max(len(obj_bytes), len(target_bytes))

    relocs = []
    if coff_relocs:
        # Use actual COFF relocation offsets (each is a 4-byte fixup site)
        relocs = [r for r in coff_relocs if r + 4 <= min_len]
    else:
        # Fallback: find 4-byte zero spans in obj that differ
        i = 0
        while i <= min_len - 4:
            if (
                obj_bytes[i : i + 4] == b"\x00\x00\x00\x00"
                and obj_bytes[i : i + 4] != target_bytes[i : i + 4]
            ):
                relocs.append(i)
                i += 4
            else:
                i += 1

    # Build reloc mask set for O(1) lookup
    reloc_set = set()
    for r in relocs:
        for j in range(4):
            if r + j < min_len:
                reloc_set.add(r + j)

    # Compare with relocs masked
    match_count = 0
    mismatches = []
    for i in range(min_len):
        if i in reloc_set:
            match_count += 1  # reloc bytes always count as matching
        elif obj_bytes[i] == target_bytes[i]:
            match_count += 1
        else:
            mismatches.append(i)

    masked_match = len(mismatches) == 0 and len(obj_bytes) == len(target_bytes)
    return masked_match, match_count, max_len, relocs


def parse_source_metadata(source_path):
    meta = {}
    try:
        with open(source_path) as f:
            for _ in range(50):
                line = f.readline()
                if not line:
                    break

                # Check // comment
                m = re.match(r'^//\s*([A-Z]+):\s*(.*)$', line.strip())
                if m:
                    meta[m.group(1)] = m.group(2).strip()

                # Check /* comment
                m2 = re.match(r'^/\*\s*([A-Z]+):\s*(.*?)\s*\*/$', line.strip())
                if m2:
                    meta[m2.group(1)] = m2.group(2).strip()
    except Exception:
        pass
    return meta

def update_source_status(source_path, new_status, blockers_to_remove=True):
    with open(source_path) as f:
        lines = f.readlines()

    with open(source_path, "w") as f:
        for line in lines:
            if re.match(r'^(//|/\*)\s*STATUS:', line):
                if line.startswith('//'):
                    f.write(f"// STATUS: {new_status}\n")
                else:
                    f.write(f"/* STATUS: {new_status} */\n")
            elif blockers_to_remove and re.match(r'^(//|/\*)\s*BLOCKER:', line):
                continue
            else:
                f.write(line)

app = typer.Typer(help="Quick compile-and-compare for reversed functions.")


@app.command()
def main(
    source: str = typer.Argument(help="C source file"),
    symbol: str | None = typer.Argument(None, help="COFF symbol name (e.g. _funcname)"),
    target_bin: str | None = typer.Argument(None, help="Target .bin file"),
    va: str | None = typer.Option(None, help="VA in hex (e.g. 0x10009310)"),
    size: int | None = typer.Option(None, help="Size in bytes"),
    cflags: str | None = typer.Option(None, help="Compiler flags"),
    update: bool = typer.Option(False, help="Auto-update STATUS in source file"),
    target: str | None = TargetOption,
):
    """Quick compile-and-compare for reversed functions."""
    cfg = get_config(target=target)

    # Optional: lint the file first to catch basic annotation errors
    anno = parse_c_file(Path(source))
    if anno:
        eval_errs, eval_warns = anno.validate()
        for e in eval_errs:
            rich.print(f"[bold red]LINT ERROR:[/bold red] {e}")
        for w in eval_warns:
            rich.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")

    meta = parse_source_metadata(source)

    symbol = symbol or meta.get("SYMBOL")
    if not symbol:
        print("ERROR: Symbol not provided in args and not found in source metadata")
        sys.exit(1)

    va_str = va
    if not va_str:
        # Check FUNCTION/LIBRARY/STUB marker like // FUNCTION: [TARGET] 0x100011f0
        for marker_key in ("FUNCTION", "LIBRARY", "STUB"):
            func_meta = meta.get(marker_key)
            if func_meta and "0x" in func_meta:
                va_str = "0x" + func_meta.split("0x")[1].split()[0]
                break

    size_val = size
    if size_val is None and "SIZE" in meta:
        size_val = int(meta["SIZE"])

    cflags_str = cflags or meta.get("CFLAGS", "/O2 /Gd")
    cflags = cflags_str.split()

    if va_str and size_val:
        va = int(va_str, 16)
        target_bytes = cfg.extract_dll_bytes(va, size_val)
    elif target_bin:
        with open(target_bin, "rb") as f:
            target_bytes = f.read()
    else:
        print("ERROR: Specify either target.bin or (VA and SIZE) via args or source metadata")
        sys.exit(1)

    workdir = tempfile.mkdtemp(prefix="test_func_")
    try:
        obj_path, err = compile_obj(cfg, os.path.abspath(source), cflags, workdir)
        if obj_path is None:
            print(f"COMPILE ERROR:\n{err}")
            sys.exit(1)

        result = parse_coff_symbol_bytes(obj_path, symbol)
        obj_bytes = result[0] if result[0] is not None else None
        coff_relocs = result[1] if result[0] is not None else None
        if obj_bytes is None:
            print(f"Symbol '{symbol}' not found in .obj")
            # List available symbols using LIEF
            available = list_obj_symbols(obj_path)
            if available:
                print("Available symbols:")
                for s in available:
                    print(f"  {s}")
            sys.exit(1)

        if len(obj_bytes) > len(target_bytes):
            obj_bytes = obj_bytes[:len(target_bytes)]

        matched, match_count, total, relocs = smart_reloc_compare(
            obj_bytes, target_bytes, coff_relocs
        )

        if matched:
            status_match = "RELOC" if relocs else "EXACT"
            if relocs:
                print(
                    f"RELOC-NORMALIZED MATCH: {total}/{total} bytes ({len(relocs)} relocations)"
                )
            else:
                print(f"EXACT MATCH: {total}/{total} bytes")

            if update:
                update_source_status(source, status_match)
                print(f"Updated status to {status_match} in {source}")
        else:
            print(f"MISMATCH: {match_count}/{total} bytes")
            print(f"\nTarget ({len(target_bytes)}B): {target_bytes.hex()}")
            print(f"Output ({len(obj_bytes)}B): {obj_bytes.hex()}")
            if len(obj_bytes) == len(target_bytes):
                diff = []
                for i in range(len(target_bytes)):
                    in_reloc = any(r <= i < r + 4 for r in relocs)
                    if target_bytes[i] != obj_bytes[i] and not in_reloc:
                        diff.append(
                            f"  [{i:3d}] target={target_bytes[i]:02x} got={obj_bytes[i]:02x}"
                        )
                if diff:
                    print("Diffs (non-reloc):")
                    for d in diff[:20]:
                        print(d)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
