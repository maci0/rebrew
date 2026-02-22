#!/usr/bin/env python3
"""Quick compile-and-compare for reversed functions.
Usage: python3 test_func.py <source.c> <symbol> <target.bin> [cflags]
       python3 test_func.py <source.c> <symbol> --va=0xHEX --size=N [cflags]
"""

import sys, os, re, struct, subprocess, tempfile, shutil
from pathlib import Path
from typing import Optional

import typer

from rebrew.config import load_config
from rebrew.matcher.parsers import parse_coff_symbol_bytes

# Lazy config — loaded when main() runs (not at import time)
_cfg = None


def _get_cfg(target=None):
    """Load config lazily from cwd."""
    global _cfg
    if _cfg is None:
        _cfg = load_config(target=target)
    return _cfg


def va_to_offset(cfg, va):
    return va - cfg.text_va + cfg.text_raw_offset


def extract_from_dll(cfg, va, size):
    with open(str(cfg.target_binary), "rb") as f:
        f.seek(va_to_offset(cfg, va))
        return f.read(size)


# parse_coff_symbol_bytes imported from rebrew.matcher.parsers


def compile_obj(cfg, source_path, cflags, workdir):
    """Compile .c to .obj using MSVC6 under Wine."""
    # Copy source to workdir for Wine compatibility
    src_name = os.path.basename(source_path)
    local_src = os.path.join(workdir, src_name)
    shutil.copy2(source_path, local_src)

    obj_name = os.path.splitext(src_name)[0] + ".obj"
    cl_path = str(cfg.compiler_command.split()[-1]) if " " in cfg.compiler_command else str(cfg.root / cfg.compiler_command)
    inc_path = str(cfg.compiler_includes)

    cmd = (
        ["wine", cl_path, "/nologo", "/c"]
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
    if len(obj_bytes) != len(target_bytes):
        return False, 0, len(obj_bytes), []

    relocs = []
    if coff_relocs:
        # Use actual COFF relocation offsets (each is a 4-byte fixup site)
        relocs = [r for r in coff_relocs if r + 4 <= len(obj_bytes)]
    else:
        # Fallback: find 4-byte zero spans in obj that differ
        i = 0
        while i <= len(obj_bytes) - 4:
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
            if r + j < len(obj_bytes):
                reloc_set.add(r + j)

    # Compare with relocs masked
    match_count = 0
    mismatches = []
    for i in range(len(obj_bytes)):
        if i in reloc_set:
            match_count += 1  # reloc bytes always count as matching
        elif obj_bytes[i] == target_bytes[i]:
            match_count += 1
        else:
            mismatches.append(i)

    masked_match = len(mismatches) == 0
    return masked_match, match_count, len(obj_bytes), relocs


def parse_source_metadata(source_path):
    meta = {}
    try:
        with open(source_path, "r") as f:
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
    with open(source_path, "r") as f:
        lines = f.readlines()
    
    with open(source_path, "w") as f:
        for line in lines:
            if re.match(r'^(//|/\*)\s*STATUS:', line):
                if line.startswith('//'):
                    f.write(f"// STATUS: {new_status}\\n")
                else:
                    f.write(f"/* STATUS: {new_status} */\\n")
            elif blockers_to_remove and re.match(r'^(//|/\*)\s*BLOCKER:', line):
                continue
            else:
                f.write(line)

app = typer.Typer(help="Quick compile-and-compare for reversed functions.")


@app.command()
def main(
    source: str = typer.Argument(help="C source file"),
    symbol: Optional[str] = typer.Argument(None, help="COFF symbol name (e.g. _funcname)"),
    target_bin: Optional[str] = typer.Argument(None, help="Target .bin file"),
    va: Optional[str] = typer.Option(None, help="VA in hex (e.g. 0x10009310)"),
    size: Optional[int] = typer.Option(None, help="Size in bytes"),
    cflags: Optional[str] = typer.Option(None, help="Compiler flags"),
    update: bool = typer.Option(False, help="Auto-update STATUS in source file"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target from rebrew.toml"),
):
    """Quick compile-and-compare for reversed functions."""
    cfg = _get_cfg(target=target)

    source = source
    meta = parse_source_metadata(source)

    symbol = symbol or meta.get("SYMBOL")
    if not symbol:
        print("ERROR: Symbol not provided in args and not found in source metadata")
        sys.exit(1)

    va_str = va
    if not va_str:
        # Check FUNCTION marker like // FUNCTION: SERVER 0x100011f0
        func_meta = meta.get("FUNCTION")
        if func_meta and "0x" in func_meta:
            va_str = "0x" + func_meta.split("0x")[1].split()[0]
    
    size_val = size
    if size_val is None and "SIZE" in meta:
        size_val = int(meta["SIZE"])

    cflags_str = cflags or meta.get("CFLAGS", "/O2 /Gd")
    cflags = cflags_str.split()

    if va_str and size_val:
        va = int(va_str, 16)
        target_bytes = extract_from_dll(cfg, va, size_val)
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
            # List available symbols
            with open(obj_path, "rb") as f:
                d = f.read()
            (sym_off,) = struct.unpack_from("<I", d, 8)
            (num_sym,) = struct.unpack_from("<I", d, 12)
            str_off = sym_off + num_sym * 18
            print("Available symbols:")
            j = 0
            while j < num_sym:
                e = d[sym_off + j * 18 : sym_off + j * 18 + 18]
                if e[:4] == b"\x00\x00\x00\x00":
                    (o,) = struct.unpack_from("<I", e, 4)
                    end = d.index(b"\x00", str_off + o)
                    n = d[str_off + o : end].decode()
                else:
                    n = e[:8].rstrip(b"\x00").decode()
                (sec,) = struct.unpack_from("<h", e, 12)
                if sec > 0:
                    print(f"  {n} (section {sec})")
                j += 1 + e[17]
            sys.exit(1)

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


if __name__ == "__main__":
    app()
