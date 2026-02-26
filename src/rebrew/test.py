#!/usr/bin/env python3
"""Quick compile-and-compare for reversed functions.

Usage:
    rebrew-test <source.c> [symbol] [--va 0xHEX --size N] [--cflags ...]
"""

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import rich
import typer

from rebrew.annotation import Annotation, parse_c_file, parse_c_file_multi, parse_source_metadata
from rebrew.cli import TargetOption, get_config
from rebrew.matcher.parsers import list_obj_symbols, parse_coff_symbol_bytes


def compile_obj(
    cfg: Any, source_path: str, cflags: list[str], workdir: str
) -> tuple[str | None, str]:
    """Compile .c to .obj using MSVC6 under Wine.

    Delegates to the unified ``rebrew.compile`` module.
    """
    from rebrew.compile import compile_to_obj

    return compile_to_obj(cfg, source_path, cflags, workdir)


def smart_reloc_compare(
    obj_bytes: bytes, target_bytes: bytes, coff_relocs: list[int] | None = None
) -> tuple[bool, int, int, list[int]]:
    """Compare bytes with relocation masking.

    Uses COFF relocation records if available, falls back to zero-span detection.
    """
    min_len = min(len(obj_bytes), len(target_bytes))
    max_len = max(len(obj_bytes), len(target_bytes))

    relocs = []
    if coff_relocs is not None:
        relocs = [r for r in coff_relocs if r + 4 <= min_len]
    else:
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

    reloc_set = set()
    for r in relocs:
        for j in range(4):
            if r + j < min_len:
                reloc_set.add(r + j)

    match_count = 0
    mismatches = []
    for i in range(min_len):
        if i in reloc_set or obj_bytes[i] == target_bytes[i]:
            match_count += 1
        else:
            mismatches.append(i)

    masked_match = len(mismatches) == 0 and len(obj_bytes) == len(target_bytes)
    return masked_match, match_count, max_len, relocs


def update_source_status(
    source_path: str | Path,
    new_status: str,
    blockers_to_remove: bool = True,
    target_va: int | None = None,
) -> None:
    """Update the STATUS annotation in a source file.

    Uses atomic write (write to .tmp, validate, rename) with .bak backup
    to prevent data loss from crashes or invalid writes.

    Args:
        target_va: If set, only update the STATUS line belonging to the
            annotation block whose FUNCTION/LIBRARY/STUB marker contains
            this VA.  When None (default), updates ALL STATUS lines.
    """
    source_path = Path(source_path)
    tmp_path = source_path.with_suffix(".c.tmp")
    bak_path = source_path.with_suffix(".c.bak")

    # Idempotency: skip if the (first) annotation already has the desired status
    if target_va is None:
        existing = parse_c_file(source_path)
        if existing is not None and existing.status == new_status:
            return

    with open(source_path, encoding="utf-8") as f:
        lines = f.readlines()

    # When target_va is set, track which annotation block we're in so we
    # only modify the STATUS/BLOCKER belonging to that specific function.
    in_target_block = target_va is None  # None → update all
    _MARKER_RE = re.compile(r"^(//|/\*)\s*(?:FUNCTION|LIBRARY|STUB):\s*\S+\s+(0x[0-9a-fA-F]+)")

    with open(tmp_path, "w", encoding="utf-8") as f:
        for line in lines:
            # Detect FUNCTION/LIBRARY/STUB markers to track annotation blocks
            if target_va is not None:
                marker_m = _MARKER_RE.match(line)
                if marker_m:
                    line_va = int(marker_m.group(2), 16)
                    in_target_block = line_va == target_va

            if in_target_block and re.match(r"^(//|/\*)\s*STATUS:", line):
                if line.startswith("//"):
                    f.write(f"// STATUS: {new_status}\n")
                else:
                    f.write(f"/* STATUS: {new_status} */\n")
            elif in_target_block and blockers_to_remove and re.match(r"^(//|/\*)\s*BLOCKER:", line):
                continue
            else:
                f.write(line)

    # Validate the written file re-parses correctly.
    # parse_c_file_multi only handles new-format annotations; fall back to
    # parse_c_file for old single-line headers.
    annos = parse_c_file_multi(tmp_path)
    if not annos and parse_c_file(tmp_path) is None:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"Post-write validation failed: {source_path} would not re-parse after status update"
        )

    # Atomic swap: backup original, rename tmp to source
    if source_path.exists():
        shutil.copy2(source_path, bak_path)
    tmp_path.rename(source_path)


_EPILOG = """\
[bold]Examples:[/bold]
  rebrew-test src/game_dll/my_func.c                  Auto-detect symbol, VA, size from annotations
  rebrew-test src/game_dll/my_func.c _my_func         Explicit symbol name
  rebrew-test f.c _sym --va 0x10009310 --size 42      Override VA and size from CLI
  rebrew-test f.c _sym --cflags "/O1 /Gd"             Override compiler flags
  rebrew-test src/game_dll/my_func.c --json            Machine-readable JSON output

[bold]How it works:[/bold]
  1. Compiles the .c file with MSVC6 (via Wine) using annotation CFLAGS
  2. Extracts the named COFF symbol from the .obj
  3. Compares compiled bytes against the original DLL bytes at the given VA
  4. Reports EXACT, RELOC (match after masking relocations), or MISMATCH

[dim]All parameters can be auto-detected from // FUNCTION, // STATUS, // SIZE,
// CFLAGS, and // SYMBOL annotations in the source file header.[/dim]"""

app = typer.Typer(
    help="Quick compile-and-compare for reversed functions.",
    rich_markup_mode="rich",
)


@app.command(epilog=_EPILOG)
def main(
    source: str = typer.Argument(help="C source file"),
    symbol: str | None = typer.Argument(None, help="COFF symbol name (e.g. _funcname)"),
    target_bin: str | None = typer.Argument(None, help="Target .bin file"),
    va: str | None = typer.Option(None, help="VA in hex (e.g. 0x10009310)"),
    size: int | None = typer.Option(None, help="Size in bytes"),
    cflags: str | None = typer.Option(None, help="Compiler flags"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Quick compile-and-compare for reversed functions."""
    cfg = get_config(target=target)

    # Optional: lint the file first to catch basic annotation errors
    anno = parse_c_file(Path(source))
    if anno:
        eval_errs, eval_warns = anno.validate()
        if not json_output:
            for e in eval_errs:
                rich.print(f"[bold red]LINT ERROR:[/bold red] {e}")
            for w in eval_warns:
                rich.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")

    # Multi-function support: if no explicit symbol/va/size, test all annotations
    if symbol is None and va is None and size is None:
        annotations = parse_c_file_multi(Path(source))
        if len(annotations) > 1:
            _test_multi(cfg, source, annotations, cflags, json_output=json_output)
            return

    meta = parse_source_metadata(source)

    symbol = symbol or meta.get("SYMBOL")
    if not symbol:
        if json_output:
            print(
                json.dumps(
                    {"source": source, "status": "ERROR", "error": "Symbol not provided"}, indent=2
                )
            )
            raise typer.Exit(code=1)
        print(
            "ERROR: Symbol not provided in args and not found in source metadata", file=sys.stderr
        )
        raise typer.Exit(code=1)

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
        try:
            size_val = int(meta["SIZE"])
        except ValueError:
            print(f"ERROR: Invalid SIZE annotation: {meta['SIZE']!r}", file=sys.stderr)
            raise typer.Exit(code=1)

    # Fallback default — should be set via annotation or config cflags_presets.
    cflags_str = cflags or meta.get("CFLAGS", "/O2 /Gd")
    cflags_parts = cflags_str.split()

    if va_str and size_val:
        va_int = int(va_str, 16)
        target_bytes = cfg.extract_dll_bytes(va_int, size_val)
    elif target_bin:
        with open(target_bin, "rb") as f:
            target_bytes = f.read()
            if size_val:
                target_bytes = target_bytes[:size_val]
    else:
        if json_output:
            print(
                json.dumps(
                    {"source": source, "status": "ERROR", "error": "No VA/SIZE or target_bin"},
                    indent=2,
                )
            )
            raise typer.Exit(code=1)
        print(
            "ERROR: Specify either target_bin or (VA and SIZE) via args or source metadata",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    workdir = tempfile.mkdtemp(prefix="test_func_")
    try:
        obj_path, err = compile_obj(cfg, source, cflags_parts, workdir)
        if obj_path is None:
            if json_output:
                err_dict = {
                    "source": source,
                    "symbol": symbol,
                    "va": va_str or "",
                    "size": size_val or 0,
                    "status": "COMPILE_ERROR",
                    "error": err,
                }
                print(json.dumps(err_dict, indent=2))
                raise typer.Exit(code=1)
            print(f"COMPILE ERROR:\n{err}")
            raise typer.Exit(code=1)

        obj_bytes, coff_relocs = parse_coff_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            if json_output:
                err_dict = {
                    "source": source,
                    "symbol": symbol,
                    "va": va_str or "",
                    "size": size_val or 0,
                    "status": "ERROR",
                    "error": f"Symbol '{symbol}' not found in .obj",
                }
                print(json.dumps(err_dict, indent=2))
                raise typer.Exit(code=1)
            print(f"Symbol '{symbol}' not found in .obj")
            available = list_obj_symbols(obj_path)
            if available:
                print("Available symbols:")
                for s in available:
                    print(f"  {s}")
            raise typer.Exit(code=1)

        if len(obj_bytes) > len(target_bytes):
            obj_bytes = obj_bytes[: len(target_bytes)]

        matched, match_count, total, relocs = smart_reloc_compare(
            obj_bytes, target_bytes, coff_relocs
        )

        if json_output:
            result_dict = build_result_dict(
                source,
                symbol,
                va_str or "",
                size_val or 0,
                matched,
                match_count,
                total,
                relocs,
                obj_bytes,
                target_bytes,
            )
            print(json.dumps(result_dict, indent=2))
        elif matched:
            if relocs:
                print(f"RELOC-NORMALIZED MATCH: {total}/{total} bytes ({len(relocs)} relocations)")
            else:
                print(f"EXACT MATCH: {total}/{total} bytes")
        else:
            print(f"MISMATCH: {match_count}/{total} bytes")
            print(f"\nTarget ({len(target_bytes)}B): {target_bytes.hex()}")
            print(f"Output ({len(obj_bytes)}B): {obj_bytes.hex()}")
            if len(obj_bytes) == len(target_bytes):
                reloc_set: set[int] = set()
                for r in relocs:
                    for j in range(4):
                        if r + j < len(target_bytes):
                            reloc_set.add(r + j)
                diff: list[str] = []
                for i in range(len(target_bytes)):
                    if target_bytes[i] != obj_bytes[i] and i not in reloc_set:
                        diff.append(
                            f"  [{i:3d}] target={target_bytes[i]:02x} got={obj_bytes[i]:02x}"
                        )
                if diff:
                    print("Diffs (non-reloc):")
                    for d in diff[:20]:
                        print(d)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def build_result_dict(
    source: str,
    symbol: str,
    va_str: str,
    size_val: int,
    matched: bool,
    match_count: int,
    total: int,
    relocs: list[int],
    obj_bytes: bytes,
    target_bytes: bytes,
) -> dict[str, Any]:
    """Build a JSON-serializable result dict for a single function test."""
    status = ("RELOC" if relocs else "EXACT") if matched else "MISMATCH"

    mismatches: list[dict[str, str | int]] = []
    if not matched:
        min_len = min(len(obj_bytes), len(target_bytes))
        reloc_set: set[int] = set()
        for r in relocs:
            for j in range(4):
                if r + j < min_len:
                    reloc_set.add(r + j)
        for i in range(min_len):
            if i not in reloc_set and obj_bytes[i] != target_bytes[i]:
                mismatches.append(
                    {
                        "offset": i,
                        "target": f"0x{target_bytes[i]:02x}",
                        "got": f"0x{obj_bytes[i]:02x}",
                    }
                )

    return {
        "source": source,
        "symbol": symbol,
        "va": va_str,
        "size": size_val,
        "status": status,
        "match_count": match_count,
        "total": total,
        "reloc_count": len(relocs),
        "obj_size": len(obj_bytes),
        "mismatches": mismatches,
    }


def _test_multi(
    cfg: Any,
    source: str,
    annotations: list[Annotation],
    cflags_override: str | None,
    *,
    json_output: bool = False,
) -> None:
    """Test all functions in a multi-function .c file.

    Compiles the file once, then extracts and compares each annotated
    symbol independently.
    """
    # Use cflags from first annotation as compile flags (all should share the same)
    cflags_str = cflags_override or annotations[0].cflags or "/O2 /Gd"
    cflags_parts = cflags_str.split()

    results_list: list[dict[str, Any]] = []

    workdir = tempfile.mkdtemp(prefix="test_multi_")
    try:
        obj_path, err = compile_obj(cfg, source, cflags_parts, workdir)
        if obj_path is None:
            if json_output:
                print(
                    json.dumps(
                        {"source": source, "status": "COMPILE_ERROR", "error": err}, indent=2
                    )
                )
                raise typer.Exit(code=1)
            print(f"COMPILE ERROR:\n{err}")
            raise typer.Exit(code=1)

        for ann in annotations:
            sym = ann.symbol
            if not sym:
                if json_output:
                    results_list.append(
                        {
                            "symbol": "",
                            "va": f"0x{ann.va:08x}",
                            "size": ann.size,
                            "status": "SKIPPED",
                            "error": "No SYMBOL annotation",
                        }
                    )
                else:
                    rich.print(f"[yellow]SKIP[/yellow] 0x{ann.va:08X} — no SYMBOL")
                continue

            if not ann.size:
                if json_output:
                    results_list.append(
                        {
                            "symbol": sym,
                            "va": f"0x{ann.va:08x}",
                            "size": 0,
                            "status": "SKIPPED",
                            "error": "No SIZE annotation",
                        }
                    )
                else:
                    rich.print(f"[yellow]SKIP[/yellow] {sym} — no SIZE")
                continue

            target_bytes = cfg.extract_dll_bytes(ann.va, ann.size)
            obj_bytes, coff_relocs = parse_coff_symbol_bytes(obj_path, sym)

            if obj_bytes is None:
                if json_output:
                    results_list.append(
                        {
                            "symbol": sym,
                            "va": f"0x{ann.va:08x}",
                            "size": ann.size,
                            "status": "ERROR",
                            "error": "Symbol not found in .obj",
                        }
                    )
                else:
                    rich.print(f"[red]MISSING[/red] {sym} — not found in .obj")
                continue

            if len(obj_bytes) > len(target_bytes):
                obj_bytes = obj_bytes[: len(target_bytes)]

            matched, match_count, total, relocs = smart_reloc_compare(
                obj_bytes, target_bytes, coff_relocs
            )

            if json_output:
                results_list.append(
                    build_result_dict(
                        source,
                        sym,
                        f"0x{ann.va:08x}",
                        ann.size,
                        matched,
                        match_count,
                        total,
                        relocs,
                        obj_bytes,
                        target_bytes,
                    )
                )
            elif matched:
                if relocs:
                    rich.print(
                        f"[green]RELOC[/green] {sym} — {total}/{total}B ({len(relocs)} relocs)"
                    )
                else:
                    rich.print(f"[bold green]EXACT[/bold green] {sym} — {total}/{total}B")
            else:
                rich.print(f"[red]MISMATCH[/red] {sym} — {match_count}/{total}B")

        if json_output:
            print(json.dumps({"source": source, "results": results_list}, indent=2))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
