"""Quick compile-and-compare for reversed functions.

Usage:
    rebrew test <source.c> [symbol] [--va 0xHEX --size N] [--cflags ...]
"""

import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import Annotation, parse_c_file, parse_c_file_multi, parse_source_metadata
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import TargetOption, error_exit, json_print, parse_va, require_config, target_marker
from rebrew.config import ProjectConfig
from rebrew.core import smart_reloc_compare
from rebrew.matcher.parsers import list_obj_symbols, parse_obj_symbol_bytes

console = Console(stderr=True)

# Regex for detecting FUNCTION/LIBRARY/STUB marker lines (used by update_source_status)
_MARKER_RE = re.compile(r"^(//|/\*)\s*(?:FUNCTION|LIBRARY|STUB):\s*\S+\s+(0x[0-9a-fA-F]+)")
_STATUS_RE = re.compile(r"^(//|/\*)\s*STATUS:")
_BLOCKER_RE = re.compile(r"^(//|/\*)\s*BLOCKER:")
# Matches any annotation key-value comment line (// KEY: ... or /* KEY: ... */)
_ANY_KV_LINE_RE = re.compile(r"^(?://|/\*)\s*[A-Z][A-Z_0-9]*:")


def compile_obj(
    cfg: ProjectConfig, source_path: str, cflags: list[str], workdir: str
) -> tuple[str | None, str]:
    """Compile .c to .obj using MSVC6 under Wine.

    Delegates to the unified ``rebrew.compile`` module.
    """
    from rebrew.compile import compile_to_obj

    return compile_to_obj(cfg, source_path, cflags, workdir)


def _find_block_lines(lines: list[str], target_va: int) -> set[int]:
    """Return line indices belonging to the annotation block for *target_va*.

    Handles both orderings:
    - KV after marker (rebrew):  ``// FUNCTION: ...`` then ``// STATUS: ...``
    - KV before marker (reccmp): ``// STATUS: ...`` then ``// FUNCTION: ...``
    """
    marker_positions: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        m = _MARKER_RE.match(line)
        if m:
            marker_positions.append((i, int(m.group(2), 16)))

    target_mk_idx: int | None = None
    for idx, (_, va) in enumerate(marker_positions):
        if va == target_va:
            target_mk_idx = idx
            break

    if target_mk_idx is None:
        return set()

    mk_line = marker_positions[target_mk_idx][0]
    result: set[int] = {mk_line}

    # Forward scan: include KV lines after the marker until code / next marker
    next_mk = (
        marker_positions[target_mk_idx + 1][0]
        if target_mk_idx + 1 < len(marker_positions)
        else len(lines)
    )
    for j in range(mk_line + 1, next_mk):
        stripped = lines[j].strip()
        if not stripped:
            continue
        if _ANY_KV_LINE_RE.match(lines[j]):
            result.add(j)
        else:
            break

    # Backward scan: include KV lines before the marker (reccmp ordering)
    prev_boundary = marker_positions[target_mk_idx - 1][0] if target_mk_idx > 0 else -1
    for j in range(mk_line - 1, prev_boundary, -1):
        stripped = lines[j].strip()
        if not stripped:
            continue
        if _ANY_KV_LINE_RE.match(lines[j]):
            result.add(j)
        else:
            break

    return result


def update_source_status(
    source_path: str | Path,
    new_status: str,
    blockers_to_remove: bool = True,
    target_va: int | None = None,
) -> None:
    """Update the STATUS annotation in a source file.

    Uses atomic write (write to .tmp, validate, rename) with .bak backup
    to prevent data loss from crashes or invalid writes.

    Handles both KV-after-marker and KV-before-marker (reccmp) orderings
    by precomputing block membership before the write pass.

    Args:
        target_va: If set, only update the STATUS line belonging to the
            annotation block whose FUNCTION/LIBRARY/STUB marker contains
            this VA.  When None (default), updates ALL STATUS lines.
    """
    source_path = Path(source_path)
    tmp_path = source_path.with_suffix(".c.tmp")
    bak_path = source_path.with_suffix(".c.bak")

    # Idempotency: skip if the annotation already has the desired status
    if target_va is None:
        existing_all = parse_c_file_multi(source_path)
        existing = existing_all[0] if existing_all else None
        if existing is not None and existing.status == new_status:
            return
    else:
        existing_annos = parse_c_file_multi(source_path)
        for ann in existing_annos:
            if ann.va == target_va:
                if ann.status == new_status and (not blockers_to_remove or not ann.blocker):
                    return
                break

    with source_path.open(encoding="utf-8") as f:
        lines = f.readlines()

    # Precompute which lines belong to the target annotation block.
    # This handles both KV-after-marker and KV-before-marker orderings.
    target_lines = _find_block_lines(lines, target_va) if target_va is not None else None

    changed = False
    with tmp_path.open("w", encoding="utf-8") as f:
        for i, line in enumerate(lines):
            in_block = target_lines is None or i in target_lines

            if in_block and _STATUS_RE.match(line):
                if line.startswith("//"):
                    new_line = f"// STATUS: {new_status}\n"
                else:
                    new_line = f"/* STATUS: {new_status} */\n"
                f.write(new_line)
                if new_line != line:
                    changed = True
            elif in_block and blockers_to_remove and _BLOCKER_RE.match(line):
                changed = True
                continue
            else:
                f.write(line)

    if not changed:
        tmp_path.unlink(missing_ok=True)
        return

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

    import os

    try:
        os.replace(tmp_path, source_path)
    except BaseException:
        if bak_path.exists() and source_path.exists():
            shutil.copy2(bak_path, source_path)
        raise


_EPILOG = """\
[bold]Examples:[/bold]

rebrew test src/game_dll/my_func.c                  Auto-detect symbol, VA, size from annotations

rebrew test src/game_dll/my_func.c _my_func         Explicit symbol name

rebrew test f.c _sym --va 0x10009310 --size 42      Override VA and size from CLI

rebrew test f.c _sym --cflags "/O1 /Gd"             Override compiler flags

rebrew test src/game_dll/my_func.c --json            Machine-readable JSON output

[bold]How it works:[/bold]

1. Compiles the .c file with MSVC6 (via Wine) using annotation CFLAGS

2. Extracts the named COFF symbol from the .obj

3. Compares compiled bytes against the original DLL bytes at the given VA

4. Reports EXACT, RELOC (match after masking relocations), or MISMATCH

[dim]All parameters can be auto-detected from // FUNCTION, // STATUS, // SIZE,
and // CFLAGS annotations. Symbol is derived from the C function definition.[/dim]"""

app = typer.Typer(
    help="Quick compile-and-compare for reversed functions.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
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
    """Compile a source file and compare one function against target bytes.

    This command supports both single-function and multi-function source files.
    In single-function mode it resolves ``symbol``, ``va``, and ``size`` from
    CLI arguments first, then falls back to source annotations. In multi-function
    mode (when no explicit symbol/va/size is provided), it compiles once and
    evaluates each annotated function independently.

    Comparison is relocation-aware: COFF relocation records are used to mask
    relocation-dependent byte spans before scoring exactness. Output status is
    reported as EXACT, RELOC, MISMATCH, or an error state.

    Args:
        source: Path to the C source file to compile.
        symbol: Optional COFF symbol name to extract from the produced object.
        target_bin: Optional path to a raw target byte blob for direct compare.
        va: Optional hex VA used with ``size`` to extract target bytes.
        size: Optional byte count for the target function.
        cflags: Optional compiler flags string overriding annotation/config defaults.
        json_output: Emit machine-readable JSON responses.
        target: Optional target profile name from ``rebrew-project.toml``.
    """
    cfg = require_config(target=target, json_mode=json_output)

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
    except (ImportError, OSError, ValueError, KeyError, AttributeError) as exc:
        # Log scan failure so users aren't surprised by missing reloc validation
        print(f"rebrew test: skipping reloc validation (scan_globals: {exc})", file=sys.stderr)

    # Optional: lint the file first to catch basic annotation errors
    lint_annos = parse_c_file_multi(Path(source), target_name=target_marker(cfg))
    for anno in lint_annos:
        eval_errs, eval_warns = anno.validate()
        if not json_output:
            for e in eval_errs:
                console.print(f"[bold red]LINT ERROR:[/bold red] {e}")
            for w in eval_warns:
                console.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")

    # Multi-function support: if no explicit symbol/va/size, test all annotations
    if symbol is None and va is None and size is None:
        annotations = parse_c_file_multi(Path(source), target_name=target_marker(cfg))
        if len(annotations) > 1:
            origin = annotations[0].origin if annotations else ""
            _test_multi(
                cfg.for_origin(origin),
                source,
                annotations,
                cflags,
                name_to_va=name_to_va,
                json_output=json_output,
            )
            return

    meta = parse_source_metadata(source)

    # Derive symbol from annotation, fallback to meta, then CLI
    if not symbol:
        # First try the parsed annotation object (derives from C func def)
        lint_anno = lint_annos[0] if lint_annos else None
        if lint_anno and lint_anno.symbol:
            symbol = lint_anno.symbol
    if not symbol:
        symbol = meta.get("SYMBOL")  # fallback for legacy annotations
    if not symbol:
        if json_output:
            error_exit("Symbol not provided", json_mode=True)
        error_exit("Could not derive symbol from C function definition or CLI args")

    va_str = va
    if not va_str:
        # Check FUNCTION/LIBRARY/STUB marker like // FUNCTION: [TARGET] 0x100011f0
        for marker_key in ("FUNCTION", "LIBRARY", "STUB"):
            func_meta = meta.get(marker_key)
            if func_meta and "0x" in func_meta:
                after_hex = func_meta.split("0x")[1].split()
                if after_hex:
                    va_str = "0x" + after_hex[0]
                    break

    size_val = size
    if size_val is None and "SIZE" in meta:
        try:
            size_val = int(meta["SIZE"])
        except ValueError:
            error_exit(f"Invalid SIZE annotation: {meta['SIZE']!r}")

    cflags_str = cflags or meta.get("CFLAGS", "/O2 /Gd")
    cflags_parts = cflags_str.split()

    origin = meta.get("ORIGIN", "")
    compile_cfg = cfg.for_origin(origin)

    if va_str is not None and size_val is not None:
        va_int = parse_va(va_str, json_mode=json_output)
        target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size_val)
    elif target_bin:
        target_bytes = Path(target_bin).read_bytes()
        if size_val is not None:
            target_bytes = target_bytes[:size_val]
    else:
        if json_output:
            error_exit("No VA/SIZE or target_bin", json_mode=True)
        error_exit("Specify either target_bin or (VA and SIZE) via args or source metadata")

    with tempfile.TemporaryDirectory(prefix="test_func_") as workdir:
        obj_path, err = compile_obj(compile_cfg, source, cflags_parts, workdir)
        if obj_path is None:
            error_exit(f"COMPILE ERROR:\n{err}", json_mode=json_output)

        obj_bytes, coff_relocs = parse_obj_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            if json_output:
                error_exit(f"Symbol '{symbol}' not found in .obj", json_mode=True)
            console.print(f"Symbol '{symbol}' not found in .obj")
            available = list_obj_symbols(obj_path)
            if available:
                console.print("Available symbols:")
                for s in available:
                    console.print(f"  {s}")
            raise typer.Exit(code=1)

        if len(obj_bytes) > len(target_bytes):
            console.print(
                f"[yellow]WARNING:[/yellow] compiled output ({len(obj_bytes)}B) "
                f"longer than target ({len(target_bytes)}B) — truncating"
            )
            obj_bytes = obj_bytes[: len(target_bytes)]

        matched, match_count, total, relocs, inv_relocs = smart_reloc_compare(
            obj_bytes, target_bytes, coff_relocs, name_to_va=name_to_va
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
                inv_relocs,
            )
            json_print(result_dict)
        elif matched:
            if relocs:
                console.print(
                    f"RELOC-NORMALIZED MATCH: {total}/{total} bytes ({len(relocs)} relocations)"
                )
            else:
                console.print(f"EXACT MATCH: {total}/{total} bytes")
        else:
            console.print(f"MISMATCH: {match_count}/{total} bytes")
            console.print(f"\nTarget ({len(target_bytes)}B): {target_bytes.hex()}")
            console.print(f"Output ({len(obj_bytes)}B): {obj_bytes.hex()}")
            if len(obj_bytes) == len(target_bytes):
                reloc_set: set[int] = set()
                for r in relocs:
                    for j in range(4):
                        if r + j < len(target_bytes):
                            reloc_set.add(r + j)
                inv_reloc_set: set[int] = set()
                for r in inv_relocs:
                    for j in range(4):
                        if r + j < len(target_bytes):
                            inv_reloc_set.add(r + j)
                diff: list[str] = []
                for i in range(len(target_bytes)):
                    if (
                        target_bytes[i] != obj_bytes[i] or i in inv_reloc_set
                    ) and i not in reloc_set:
                        diff.append(
                            f"  [{i:3d}] target={target_bytes[i]:02x} got={obj_bytes[i]:02x}"
                        )
                if diff:
                    console.print("Diffs (non-reloc):")
                    for d in diff[:20]:
                        console.print(d)


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
    invalid_relocs: list[int] | None = None,
) -> dict[str, Any]:
    """Build structured JSON output for one compile-and-compare result.

    The resulting payload is stable and machine-friendly for downstream tools,
    CI aggregation, and scripting. It includes a normalized status, aggregate
    match counts, relocation metadata, object size, and byte-level mismatch
    details (excluding relocation-masked offsets).

    Args:
        source: Source file path used for compilation.
        symbol: COFF symbol name tested.
        va_str: Function VA string (hex) used for extraction.
        size_val: Target size requested for extraction/comparison.
        matched: Whether the relocation-aware comparison fully matched.
        match_count: Number of bytes considered matching.
        total: Total bytes considered for score denominator.
        relocs: Relocation start offsets (4-byte spans each).
        obj_bytes: Compiled symbol bytes extracted from object output.
        target_bytes: Ground-truth target bytes.

    Returns:
        JSON-serializable dictionary with status, metrics, and mismatches.
    """
    status = ("RELOC" if relocs else "EXACT") if matched else "MISMATCH"

    mismatches: list[dict[str, str | int]] = []
    invalid_relocs = invalid_relocs or []
    inv_reloc_set = set()
    for r in invalid_relocs:
        for j in range(4):
            inv_reloc_set.add(r + j)
    if not matched:
        min_len = min(len(obj_bytes), len(target_bytes))
        reloc_set: set[int] = set()
        for r in relocs:
            for j in range(4):
                if r + j < min_len:
                    reloc_set.add(r + j)
        for i in range(min_len):
            if i not in reloc_set and (i in inv_reloc_set or obj_bytes[i] != target_bytes[i]):
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
    cfg: ProjectConfig,
    source: str,
    annotations: list[Annotation],
    cflags_override: str | None,
    *,
    name_to_va: dict[str, int] | None = None,
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

    with tempfile.TemporaryDirectory(prefix="test_multi_") as workdir:
        obj_path, err = compile_obj(cfg, source, cflags_parts, workdir)
        if obj_path is None:
            error_exit(f"COMPILE ERROR:\n{err}", json_mode=json_output)

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
                            "error": "No symbol (missing C function definition)",
                        }
                    )
                else:
                    console.print(f"[yellow]SKIP[/yellow] 0x{ann.va:08X} — no symbol")
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
                    console.print(f"[yellow]SKIP[/yellow] {sym} — no SIZE")
                continue

            target_bytes = extract_raw_bytes(cfg.target_binary, ann.va, ann.size)
            obj_bytes, coff_relocs = parse_obj_symbol_bytes(obj_path, sym)

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
                    console.print(f"[red]MISSING[/red] {sym} — not found in .obj")
                continue

            if len(obj_bytes) > len(target_bytes):
                obj_bytes = obj_bytes[: len(target_bytes)]

            matched, match_count, total, relocs, inv_relocs = smart_reloc_compare(
                obj_bytes, target_bytes, coff_relocs, name_to_va=name_to_va
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
                        inv_relocs,
                    )
                )
            elif matched:
                if relocs:
                    console.print(
                        f"[green]RELOC[/green] {sym} — {total}/{total}B ({len(relocs)} relocs)"
                    )
                else:
                    console.print(f"[bold green]EXACT[/bold green] {sym} — {total}/{total}B")
            else:
                console.print(f"[red]MISMATCH[/red] {sym} — {match_count}/{total}B")

        if json_output:
            json_print({"source": source, "results": results_list})


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
