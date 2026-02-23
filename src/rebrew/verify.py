#!/usr/bin/env python3
"""verify.py - Traceability and verification tool for rebrew.

Analyzes src/*.c files, matches them against the target binary,
and reports status (EXACT, RELOC, MATCHING, etc.).
"""

import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from rebrew.annotation import (
    parse_c_file,
)


def make_r2_func(va: int, size: int, r2_name: str) -> dict:
    return {"va": va, "size": size, "r2_name": r2_name}


def make_ghidra_func(va: int, size: int, name: str) -> dict:
    return {"va": va, "size": size, "ghidra_name": name}


# ---------------------------------------------------------------------------
# Cross-tool function registry
# ---------------------------------------------------------------------------

# registry is now built using cfg values in build_function_registry

# r2 entries with known bogus sizes (analysis artifacts)
R2_BOGUS_SIZES = {0x1000AD40, 0x10018200}


def build_function_registry(
    r2_funcs: list[dict],
    cfg: Any,
    ghidra_path: Path | None = None,
) -> dict[int, dict]:
    """Build a unified function registry merging r2 + ghidra + exports.

    Returns dict keyed by VA with:
        detected_by: list of tool names
        size_by_tool: {tool: size}
        r2_name / ghidra_name: tool-specific names
        is_thunk: bool
        is_export: bool
        canonical_size: best-known size
    """
    registry: dict[int, dict] = {}

    # --- r2 functions ---
    for func in r2_funcs:
        va = func["va"]
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "r2_name": "",
                "ghidra_name": "",
                "is_thunk": va in cfg.iat_thunks,
                "is_export": va in cfg.dll_exports,
                "canonical_size": 0,
            },
        )
        entry["detected_by"].append("r2")
        r2_size = func["size"]
        if va not in R2_BOGUS_SIZES:
            entry["size_by_tool"]["r2"] = r2_size
        entry["r2_name"] = func["r2_name"]

    # --- Ghidra functions (from cached JSON) ---
    ghidra_funcs = []
    if ghidra_path and ghidra_path.exists():
        try:
            ghidra_funcs = json.loads(ghidra_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    for func in ghidra_funcs:
        va = func["va"]
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "r2_name": "",
                "ghidra_name": "",
                "is_thunk": va in cfg.iat_thunks,
                "is_export": va in cfg.dll_exports,
                "canonical_size": 0,
            },
        )
        if "ghidra" not in entry["detected_by"]:
            entry["detected_by"].append("ghidra")
        entry["size_by_tool"]["ghidra"] = func["size"]
        entry["ghidra_name"] = func["ghidra_name"]

    # --- Exports ---
    for va, _name in cfg.dll_exports.items():
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "r2_name": "",
                "ghidra_name": "",
                "is_thunk": False,
                "is_export": True,
                "canonical_size": 0,
            },
        )
        if "exports" not in entry["detected_by"]:
            entry["detected_by"].append("exports")

    # --- Resolve canonical size: prefer ghidra > r2 ---
    for _va, entry in registry.items():
        sizes = entry["size_by_tool"]
        if "ghidra" in sizes:
            entry["canonical_size"] = sizes["ghidra"]
        elif "r2" in sizes:
            entry["canonical_size"] = sizes["r2"]

    return registry


def load_ghidra_functions(path: Path) -> list[dict]:
    """Load cached ghidra_functions.json."""
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


# ---------------------------------------------------------------------------
# r2_functions.txt parser
# ---------------------------------------------------------------------------

_R2_LINE_RE = re.compile(r"\s*(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)")


def parse_r2_functions(path: Path) -> list[dict]:
    """Parse r2_functions.txt into list of {va, size, r2_name}."""
    funcs = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        print(f"WARNING: Cannot read {path}", file=sys.stderr)
        return funcs

    for line in text.splitlines():
        m = _R2_LINE_RE.match(line)
        if m:
            funcs.append(
                make_r2_func(
                    va=int(m.group(1), 16),
                    size=int(m.group(2)),
                    r2_name=m.group(3),
                )
            )
    return funcs




# extract_dll_bytes is now handled by cfg.extract_dll_bytes() in verify_entry


from rebrew.matcher.parsers import parse_coff_symbol_bytes

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_reversed_dir(reversed_dir: Path) -> list[dict]:
    """Scan target dir *.c files and parse annotations from each."""
    entries = []
    for cfile in sorted(reversed_dir.glob("*.c")):

        entry = parse_c_file(cfile)
        if entry is not None:
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Verification (--verify)
# ---------------------------------------------------------------------------


def verify_entry(entry: dict, cfg) -> tuple[bool, str]:
    """Compile a .c file and compare output bytes against DLL."""
    cfile = cfg.reversed_dir / entry["filepath"]
    if not cfile.exists():
        return False, f"File not found: {cfile}"

    cmd_parts = cfg.compiler_command.split()
    if len(cmd_parts) > 1 and cmd_parts[0] == "wine":
        cl_rel = Path(cmd_parts[1])
        cl_abs = str(cfg.root / cl_rel) if not cl_rel.is_absolute() else str(cl_rel)
        base_cmd = ["wine", cl_abs, "/nologo", "/c", "/MT", "/Gd"]
    else:
        cl_rel = Path(cfg.compiler_command)
        cl_abs = str(cfg.root / cl_rel) if not cl_rel.is_absolute() else str(cl_rel)
        base_cmd = [cl_abs, "/nologo", "/c", "/MT", "/Gd"]
    inc_path = str(cfg.compiler_includes)

    cflags_str = entry["cflags"]
    cflags = cflags_str.split() if cflags_str else ["/O2"]
    symbol = entry["symbol"] if entry["symbol"] else "_" + entry["name"]

    target_bytes = cfg.extract_dll_bytes(entry["va"], entry["size"])
    if target_bytes is None:
        return False, "Cannot extract DLL bytes"

    workdir = tempfile.mkdtemp(prefix="validate_")
    try:
        src_name = cfile.name
        local_src = os.path.join(workdir, src_name)
        shutil.copy2(str(cfile), local_src)

        obj_name = os.path.splitext(src_name)[0] + ".obj"
        cmd = (
            base_cmd
            + cflags
            + [f"/I{inc_path}", f"/Fo{obj_name}", src_name]
        )
        env = cfg.msvc_env()
        r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env, timeout=30)
        obj_path = os.path.join(workdir, obj_name)

        if r.returncode != 0 or not os.path.exists(obj_path):
            return False, f"Compile error: {r.stderr.decode()[:200]}"

        obj_bytes, reloc_offsets = parse_coff_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            return False, f"Symbol '{symbol}' not found in .obj"

        if len(obj_bytes) != len(target_bytes):
            return (
                False,
                f"Size mismatch: got {len(obj_bytes)}B, want {len(target_bytes)}B",
            )

        # Compare with reloc masking
        reloc_set = set()
        if reloc_offsets:
            for ro in reloc_offsets:
                for j in range(4):
                    if ro + j < len(obj_bytes):
                        reloc_set.add(ro + j)

        mismatches = []
        for i in range(len(obj_bytes)):
            if i in reloc_set:
                continue
            if obj_bytes[i] != target_bytes[i]:
                mismatches.append(i)

        if not mismatches:
            if reloc_offsets:
                return True, f"RELOC-NORM MATCH ({len(reloc_offsets)} relocs)"
            else:
                return True, "EXACT MATCH"
        else:
            return False, f"MISMATCH: {len(mismatches)} byte diffs at {mismatches[:5]}"

    except subprocess.TimeoutExpired:
        return False, "Compile timed out"
    except Exception as exc:
        return False, f"Error: {exc}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Text section size
# ---------------------------------------------------------------------------


def get_text_section_size(bin_path: Path) -> int:
    """Get .text section virtual size from binary headers."""
    try:
        from rebrew.binary_loader import load_binary
        info = load_binary(bin_path)
        return info.text_size
    except Exception:
        pass
    # Fallback: estimate from r2_functions.txt last function
    return 0x24000  # rough estimate


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.text import Text

from rebrew.cli import TargetOption, get_config

console = Console(stderr=True)
out_console = Console()

app = typer.Typer(help="Rebrew verification pipeline: compile each .c and verify bytes match.")

@app.callback(invoke_without_command=True)
def main(
    root: Path = typer.Option(
        None,
        "--root",
        help="Project root directory (auto-detected from rebrew.toml if omitted)",
    ),
    target: str | None = TargetOption,
    jobs: int = typer.Option(
        4,
        "-j",
        "--jobs",
        help="Number of parallel compile jobs",
    ),
):
    """Rebrew verification pipeline: compile each .c and verify bytes match."""
    try:
        cfg = get_config(target=target)
        bin_path = cfg.target_binary
        reversed_dir = cfg.reversed_dir
    except Exception:
        # Generic fallbacks
        bin_path = root / "binary.dll"
        reversed_dir = root / "src"
    r2_path = reversed_dir / "r2_functions.txt"
    ghidra_json_path = reversed_dir / "ghidra_functions.json"

    console.print(f"Scanning {reversed_dir}...")
    entries = scan_reversed_dir(reversed_dir)
    r2_funcs = parse_r2_functions(r2_path)

    registry = build_function_registry(r2_funcs, cfg, ghidra_json_path)

    unique_vas = set(e["va"] for e in entries)
    ghidra_count = sum(1 for r in registry.values() if "ghidra" in r["detected_by"])
    r2_count = sum(1 for r in registry.values() if "r2" in r["detected_by"])
    both_count = sum(
        1
        for r in registry.values()
        if "ghidra" in r["detected_by"] and "r2" in r["detected_by"]
    )
    thunk_count = sum(1 for r in registry.values() if r["is_thunk"])
    console.print(
        f"Found {len(entries)} annotations ({len(unique_vas)} unique VAs) "
        f"from {len(registry)} total functions "
        f"(r2: {r2_count}, ghidra: {ghidra_count}, both: {both_count}, "
        f"thunks: {thunk_count})"
    )

    # Verify

    if not bin_path.exists():
        console.print(f"[red bold]ERROR:[/] {bin_path} not found")
        return 1

    # Deduplicate: only verify once per VA
    seen_vas: set = set()
    unique_entries = []
    for entry in sorted(entries, key=lambda x: x["va"]):
        if entry["va"] not in seen_vas:
            seen_vas.add(entry["va"])
            unique_entries.append(entry)

    passed = 0
    failed = 0
    fail_details = []
    total = len(unique_entries)
    effective_jobs = min(jobs, total) if total else 1

    def _verify(e: dict) -> tuple:
        return (e, *verify_entry(e, cfg))

    with Progress(
        TextColumn("[bold blue]Verifying"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[dim]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("functions", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_jobs) as pool:
            futures = {pool.submit(_verify, e): e for e in unique_entries}
            for future in concurrent.futures.as_completed(futures):
                entry, ok, msg = future.result()
                name = entry['name']
                progress.update(task, advance=1, description=name)
                if ok:
                    passed += 1
                else:
                    failed += 1
                    fail_details.append((entry, msg))

    # Print failures
    if fail_details:
        out_console.print()
        for entry, msg in sorted(fail_details, key=lambda x: x[0]['va']):
            out_console.print(
                rf"  [red bold]\[FAIL][/] 0x{entry['va']:08X} {entry['name']}: {msg}"
            )

    # Summary
    style = "green" if failed == 0 else "red"
    result_text = Text()
    result_text.append("\nVerification: ")
    result_text.append(f"{passed}/{total} passed", style=style)
    if failed:
        result_text.append(", ")
        result_text.append(f"{failed} failed", style="red")
    out_console.print(result_text)

    if failed > 0:
        return 1

    return 0


def main_entry():
    app()

if __name__ == "__main__":
    main_entry()

