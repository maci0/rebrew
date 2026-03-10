"""Quick compile-and-compare for reversed functions.

By default, after comparing, STATUS is auto-updated in the per-directory
metadata (via update_source_status). Use --no-promote to skip this.

Usage:
    rebrew test <source.c> [symbol] [--va 0xHEX --size N] [--cflags ...]
    rebrew test <source.c> --no-promote   # skip STATUS update
    rebrew test --all                     # batch test all reversed functions
    rebrew test --all --origin GAME       # batch mode, filter by origin
    rebrew test --all --dir src/game_dll/ # batch mode, restrict to subdir
"""

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import Annotation, parse_c_file_multi, parse_source_metadata
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    NEAR_MATCH_THRESHOLD,
    TargetOption,
    classify_match_status,
    error_exit,
    is_matched,
    json_print,
    parse_va,
    require_config,
    target_marker,
)
from rebrew.config import ProjectConfig
from rebrew.core import smart_reloc_compare
from rebrew.matcher.parsers import list_obj_symbols, parse_obj_symbol_bytes
from rebrew.metadata import update_source_status

console = Console(stderr=True)


def _expand_reloc_offsets(relocs: list[int], limit: int) -> set[int]:
    """Expand 4-byte relocation start offsets into a set of individual byte offsets."""
    return {r + j for r in relocs for j in range(4) if r + j < limit}


def _patch_verify_cache(
    cfg: ProjectConfig,
    va: int,
    new_status: str,
    match_count: int,
    total: int,
    reloc_count: int = 0,
) -> None:
    """Update the verify cache entry for *va* so status/todo stay in sync.

    When ``rebrew test`` promotes a function's metadata status, the
    verify cache (read by ``rebrew status`` and ``rebrew todo``) may
    still hold a stale result from a previous ``rebrew verify`` run.
    This helper patches the relevant entry in-place so that all tools
    agree on the current status immediately after a test.
    """
    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    if not cache_path.exists():
        return
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return

    entries = raw.get("entries", {})
    va_key = f"0x{va:08x}"
    entry = entries.get(va_key)
    if entry is None:
        return  # No cached entry to patch

    result = entry.get("result", {})
    old_status = result.get("status", "")
    if old_status == new_status:
        return  # Already in sync

    # Patch the result fields
    result["status"] = new_status
    match_pct = round(100.0 * match_count / total, 1) if total > 0 else 0.0
    result["match_percent"] = match_pct
    result["passed"] = is_matched(new_status)
    if total > 0:
        result["delta"] = total - match_count
    entry["result"] = result
    entries[va_key] = entry
    raw["entries"] = entries

    try:
        from rebrew.utils import atomic_write_text

        atomic_write_text(cache_path, json.dumps(raw, indent=2), encoding="utf-8")
    except (OSError, TypeError):
        pass  # Best-effort — don't crash test on cache write failure


def compile_obj(
    cfg: ProjectConfig, source_path: str, cflags: list[str], workdir: str
) -> tuple[str | None, str]:
    """Compile .c to .obj using MSVC6 under Wine.

    Delegates to the unified ``rebrew.compile`` module.
    """
    from rebrew.compile import compile_to_obj

    return compile_to_obj(cfg, source_path, cflags, workdir)


_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew test src/game_dll/my_func.c · · · · · · Auto-detect symbol, VA, size from source\n\n"
    "  rebrew test src/game_dll/my_func.c _my_func · · Explicit symbol name\n\n"
    "  rebrew test f.c _sym --va 0x10009310 --size 42 · Override VA and size from CLI\n\n"
    '  rebrew test f.c _sym --cflags "/O1 /Gd" · · · · Override compiler flags\n\n'
    "  rebrew test src/game_dll/my_func.c --no-promote  Skip STATUS metadata update\n\n"
    "  rebrew test src/game_dll/my_func.c --json · · · · Machine-readable JSON output\n\n"
    "  rebrew test --all · · · · · · · · · · · · · · · Batch test all reversed functions\n\n"
    "  rebrew test --all --origin GAME · · · · · · · · Only GAME-origin functions\n\n"
    "  rebrew test --all --dir src/game_dll/ · · · · · Restrict batch to a subdirectory\n\n"
    "  rebrew test --all --dry-run · · · · · · · · · · List batch candidates without testing\n\n"
    "[bold]Auto-promote (default behaviour):[/bold]\n\n"
    "  1. Compiles the .c file with MSVC6 (via Wine) using CFLAGS from metadata\n\n"
    "  2. Extracts the named COFF symbol from the .obj\n\n"
    "  3. Compares compiled bytes against the original DLL bytes at the given VA\n\n"
    "  4. Reports EXACT, RELOC (match after masking relocations), or STUB\n\n"
    "  5. Updates STATUS in metadata (EXACT / RELOC / NEAR_MATCHING) — skip with --no-promote (auto-skipped if file is outside project)\n\n"
    "  6. If EXACT/RELOC: clears any auto-generated BLOCKER from metadata\n\n"
    "[bold]Exit codes:[/bold]\n\n"
    "  0   EXACT or RELOC match (bytes identical or match after relocation masking)\n\n"
    "  1   NEAR_MATCHING or STUB (code needs improvement)\n\n"
    "  2   Build error (compilation failed)\n\n"
    "[dim]Parameters are auto-detected from // FUNCTION markers in source, "
    "plus STATUS, SIZE, and CFLAGS from rebrew-function.toml metadata.[/dim]"
)

app = typer.Typer(
    help="Compile-and-compare for reversed functions (auto-updates STATUS by default).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    source: str | None = typer.Argument(None, help="C source file (omit with --all)"),
    va: str | None = typer.Option(None, help="VA in hex (e.g. 0x10009310)"),
    symbol: str | None = typer.Option(None, "--symbol", help="COFF symbol name (e.g. _funcname)"),
    target_bin: str | None = typer.Option(None, "--target-bin", help="Target .bin file"),
    size: int | None = typer.Option(None, help="Size in bytes"),
    cflags: str | None = typer.Option(None, help="Compiler flags"),
    all_sources: bool = typer.Option(False, "--all", help="Batch test all reversed .c files"),
    batch_dir: str | None = typer.Option(
        None, "--dir", help="With --all, restrict to this subdirectory"
    ),
    origin: str | None = typer.Option(
        None, "--origin", help="With --all, filter by origin (GAME, MSVCRT, ZLIB)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    jobs: int | None = typer.Option(
        None, "-j", "--jobs", help="Number of parallel compile jobs (with --all)"
    ),
    no_promote: bool = typer.Option(
        False,
        "--no-promote",
        help="Skip auto-update of STATUS metadata after test (auto-skipped if file is outside project)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compile a source file and compare one function against target bytes.

    With --all, batch-tests every .c file found in the reversed directory
    (iterating via ``iter_sources``).  Optional --dir and --origin flags
    restrict the batch.  Without --all, a single source file must be provided.

    In single-function mode it resolves ``symbol``, ``va``, and ``size`` from
    CLI arguments first, then falls back to source markers. In multi-function
    mode (when no explicit symbol/va/size is provided), it compiles once and
    evaluates each annotated function independently.

    Comparison is relocation-aware: COFF relocation records are used to mask
    relocation-dependent byte spans before scoring exactness. Output status is
    reported as EXACT, RELOC, STUB, or an error state.

    Args:
        source: Path to the C source file to compile.
        symbol: Optional COFF symbol name to extract from the produced object.
        target_bin: Optional path to a raw target byte blob for direct compare.
        va: Optional hex VA used with ``size`` to extract target bytes.
        size: Optional byte count for the target function.
        cflags: Optional compiler flags string overriding annotation/config defaults.
        all_sources: Batch mode — test every .c file in reversed_dir.
        batch_dir: Optional subdirectory to restrict batch mode.
        origin: Optional origin filter for batch mode.
        dry_run: List batch candidates without running tests.
        json_output: Emit machine-readable JSON responses.
        target: Optional target profile name from ``rebrew-project.toml``.

    """
    cfg = require_config(target=target, json_mode=json_output)

    if source is not None:
        source_path = Path(source).resolve()
        # If testing a file outside the project's source tree (e.g. output/ or /tmp),
        # disable promotion by default to avoid accidentally updating metadata.
        if not source_path.is_relative_to(cfg.metadata_dir.resolve()):
            no_promote = True

    if all_sources:
        _run_all_batch(cfg, batch_dir, origin, dry_run, no_promote, json_output, jobs=jobs)
        return

    if source is None:
        error_exit(
            "Provide a source file, or use --all to batch test all files.", json_mode=json_output
        )
        return

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
    lint_annos = parse_c_file_multi(
        Path(source), target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    for anno in lint_annos:
        eval_errs, eval_warns = anno.validate()
        if not json_output:
            for e in eval_errs:
                console.print(f"[bold red]LINT ERROR:[/bold red] {e}")
            for w in eval_warns:
                console.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")

    # Multi-function support: if no explicit symbol/va/size, test all annotations
    if symbol is None and va is None and size is None:
        annotations = parse_c_file_multi(
            Path(source), target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
        )
        if len(annotations) > 1:
            _test_multi(
                cfg,
                source,
                annotations,
                cflags,
                name_to_va=name_to_va,
                no_promote=no_promote,
                json_output=json_output,
            )
            return

    meta = parse_source_metadata(source)

    # Derive symbol from annotation (C function definition)
    if not symbol:
        # First try the parsed annotation object (derives from C func def)
        lint_anno = lint_annos[0] if lint_annos else None
        if lint_anno and lint_anno.symbol:
            symbol = lint_anno.symbol
    if not symbol:
        error_exit(
            "Could not derive symbol from C function definition or CLI args", json_mode=json_output
        )

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
            error_exit(f"Invalid SIZE metadata: {meta['SIZE']!r}", json_mode=json_output)

    cflags_str = cflags or meta.get("CFLAGS", "/O2 /Gd")
    cflags_parts = cflags_str.split()

    if va_str is not None and size_val is not None:
        va_int = parse_va(va_str, json_mode=json_output)
        target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size_val)
    elif target_bin:
        target_bytes = Path(target_bin).read_bytes()
        if size_val is not None:
            target_bytes = target_bytes[:size_val]
    else:
        error_exit(
            "Specify either target_bin or (VA and SIZE) via args or source metadata",
            json_mode=json_output,
        )

    with tempfile.TemporaryDirectory(prefix="test_func_") as workdir:
        obj_path, err = compile_obj(cfg, source, cflags_parts, workdir)
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
            near = total > 0 and (match_count / total) >= NEAR_MATCH_THRESHOLD
            if near:
                label = "NEAR_MATCHING"
                color = "bold yellow"
            else:
                label = "STUB"
                color = "red"
            console.print(f"[{color}]{label}[/{color}]: {match_count}/{total} bytes")
            console.print(f"\nTarget ({len(target_bytes)}B): {target_bytes.hex()}")
            console.print(f"Output ({len(obj_bytes)}B): {obj_bytes.hex()}")
            if len(obj_bytes) == len(target_bytes):
                reloc_set = _expand_reloc_offsets(relocs, len(target_bytes))
                inv_reloc_set = _expand_reloc_offsets(inv_relocs, len(target_bytes))
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

    # Auto-promote: update STATUS in metadata from test result (skip with --no-promote)
    if not no_promote and va_str:
        va_int_for_promote = parse_va(va_str, json_mode=json_output)
        anno_module = lint_annos[0].module if lint_annos else ""
        old_status = lint_annos[0].status if lint_annos else ""
        new_status = classify_match_status(matched, match_count, total, relocs)
        if old_status == "PROVEN":
            if not json_output:
                console.print("[dim]STATUS → skipped (PROVEN)[/dim]")
        else:
            clear = is_matched(new_status)
            update_source_status(
                cfg.metadata_dir,
                new_status,
                anno_module,
                va_int_for_promote,
                clear_blockers=clear,
            )
            _patch_verify_cache(
                cfg,
                va_int_for_promote,
                new_status,
                match_count,
                total,
                len(relocs) if matched else 0,
            )
            if not json_output:
                console.print(f"[dim]STATUS → {new_status}[/dim]")


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
        invalid_relocs: Optional list of offsets containing mismatched relocations.

    Returns:
        JSON-serializable dictionary with status, metrics, and mismatches.

    """
    status = classify_match_status(matched, match_count, total, relocs)

    mismatches: list[dict[str, str | int]] = []
    invalid_relocs = invalid_relocs or []
    if not matched:
        min_len = min(len(obj_bytes), len(target_bytes))
        reloc_set = _expand_reloc_offsets(relocs, min_len)
        inv_reloc_set = _expand_reloc_offsets(invalid_relocs, min_len)
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
    no_promote: bool = False,
    json_output: bool = False,
) -> list[tuple[str, str]]:
    """Test all functions in a multi-function .c file.

    Compiles the file once, then extracts and compares each annotated
    symbol independently.

    Returns a list of ``(old_status, new_status)`` tuples for each tested
    function (used by batch mode for aggregate stats).
    """
    # Use cflags from first annotation as compile flags (all should share the same)
    cflags_str = cflags_override or annotations[0].cflags or "/O2 /Gd"
    cflags_parts = cflags_str.split()

    results_list: list[dict[str, Any]] = []
    status_transitions: list[tuple[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="test_multi_") as workdir:
        obj_path, err = compile_obj(cfg, source, cflags_parts, workdir)
        if obj_path is None:
            error_exit(f"COMPILE ERROR:\n{err}", json_mode=json_output)
            return status_transitions  # unreachable, but keeps type checker happy

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
                near = total > 0 and (match_count / total) >= NEAR_MATCH_THRESHOLD
                if near:
                    label = "NEAR_MATCHING"
                    color = "bold yellow" if (match_count / total) >= 0.97 else "yellow"
                    console.print(f"[{color}]{label}[/{color}] {sym} — {match_count}/{total}B")
                else:
                    console.print(f"[red]STUB[/red] {sym} — {match_count}/{total}B")

            # Determine new status from test result
            new_status = classify_match_status(matched, match_count, total, relocs)
            old_status = ann.status or "STUB"

            # Auto-promote: update STATUS in metadata (mirrors single-function path)
            if not no_promote:
                if old_status == "PROVEN":
                    status_transitions.append((old_status, old_status))
                    if not json_output:
                        console.print("[dim]  STATUS → skipped (PROVEN)[/dim]")
                else:
                    clear = is_matched(new_status)
                    update_source_status(
                        cfg.metadata_dir,
                        new_status,
                        ann.module,
                        ann.va,
                        clear_blockers=clear,
                    )
                    _patch_verify_cache(
                        cfg,
                        ann.va,
                        new_status,
                        match_count,
                        total,
                        len(relocs) if matched else 0,
                    )
                    status_transitions.append((old_status, new_status))
                    if not json_output:
                        console.print(f"[dim]  STATUS → {new_status}[/dim]")
            else:
                status_transitions.append((old_status, new_status))

        if json_output:
            json_print({"source": source, "results": results_list})

    return status_transitions


def _run_all_batch(
    cfg: "ProjectConfig",
    batch_dir: str | None,
    origin_filter: str | None,
    dry_run: bool,
    no_promote: bool,
    json_output: bool,
    jobs: int | None = None,
) -> None:
    """Batch-test all .c files using verify's parallel/cached engine.

    Delegates to :func:`rebrew.verify.prepare_entries` and
    :func:`rebrew.verify.run_verification` for parallel compilation
    with incremental caching.  STATUS is always promoted/demoted unless
    *no_promote* is True.

    Args:
        cfg: Project configuration.
        batch_dir: Optional subdirectory to restrict search (relative to reversed_dir).
        origin_filter: Optional origin string filter (e.g. "GAME", "MSVCRT").
        dry_run: If True, list candidates without running any tests.
        no_promote: Pass-through to suppress STATUS updates.
        json_output: Emit JSON output.
        jobs: Number of parallel compile jobs (default: from config).

    """
    from rebrew.verify import apply_status_updates, prepare_entries, run_verification

    if jobs is None:
        jobs = cfg.default_jobs

    # Reuse verify's scanning + caching engine
    unique_entries, passed, failed, fail_details, results, cached_count = prepare_entries(
        cfg,
        full=True,  # test --all always recompiles (no incremental)
        json_output=json_output,
    )

    if not unique_entries:
        if not json_output:
            console.print("[yellow]No testable source files found[/yellow]")
        return

    # Filter by batch_dir if specified
    if batch_dir:
        batch_root = (
            Path(batch_dir).resolve() if Path(batch_dir).is_absolute() else cfg.root / batch_dir
        )
        batch_root_str = str(batch_root)
        unique_entries = [
            e
            for e in unique_entries
            if str((cfg.reversed_dir / getattr(e, "filepath", "")).resolve()).startswith(
                batch_root_str
            )
        ]

    # Filter by origin if specified
    if origin_filter:
        unique_entries = [
            e
            for e in unique_entries
            if hasattr(e, "origin") and e.origin and e.origin.upper() == origin_filter.upper()
        ]

    if not unique_entries:
        if not json_output:
            console.print(
                f"[yellow]No source files match filters "
                f"(dir={batch_dir}, origin={origin_filter})[/yellow]"
            )
        return

    total = len(unique_entries)

    if dry_run:
        if json_output:
            json_print(
                {
                    "count": total,
                    "files": sorted({getattr(e, "filepath", "") for e in unique_entries}),
                }
            )
        else:
            console.print(f"[bold]Batch test candidates ({total} functions):[/bold]")
            for e in unique_entries:
                console.print(f"  0x{e.va:08X} {e.name} ({getattr(e, 'filepath', '')})")
        return

    if not json_output:
        console.print(f"\n[bold]Batch testing {total} function(s)…[/bold]\n")

    # Run verification in parallel
    v_passed, v_failed, v_fail_details, v_results, deferred = run_verification(
        unique_entries,
        cfg,
        jobs,
        total,
        0,  # cached_count=0 since we pass full=True
        json_output,
    )

    # Always promote/demote STATUS metadata unless --no-promote
    if not no_promote and deferred:
        apply_status_updates(deferred, cfg)

    # Build transitions for summary display (only include actual changes)
    transitions: list[tuple[str, str]] = []
    for entry, status, _delta in deferred:
        old_status = getattr(entry, "status", "") or "STUB"
        # PROVEN is sticky — verification result doesn't change it
        if old_status == "PROVEN":
            continue
        transitions.append((old_status, status))

    # Count unique files for the summary
    unique_files = len({getattr(e, "filepath", "") for e in unique_entries})

    if json_output:
        json_print(
            {
                "total": total,
                "passed": v_passed,
                "failed": v_failed,
                "results": v_results,
            }
        )
    else:
        _print_batch_summary(transitions, unique_files, 0)


# ---------------------------------------------------------------------------
# Batch summary
# ---------------------------------------------------------------------------

_RESULT_COLORS: dict[str, str] = {
    "EXACT": "bold green",
    "RELOC": "green",
    "NEAR_MATCHING": "yellow",
    "STUB": "red",
    "SKIP": "dim",
}


def _print_batch_summary(
    transitions: list[tuple[str, str]],
    total_files: int,
    skipped_no_size: int,
) -> None:
    """Print a rich summary table after batch testing."""
    if not transitions:
        console.print(
            f"\n[bold]Batch complete.[/bold] Tested {total_files} file(s), 0 functions compared."
        )
        return

    # --- Result counts ---
    result_counts: dict[str, int] = {}
    for _old, new in transitions:
        result_counts[new] = result_counts.get(new, 0) + 1

    # --- Transition counts (only where status changed) ---
    transition_counts: dict[tuple[str, str], int] = {}
    for old, new in transitions:
        if old != new:
            key = (old, new)
            transition_counts[key] = transition_counts.get(key, 0) + 1

    # --- Print ---
    console.print()
    console.print("[bold]━━━ Batch Summary ━━━[/bold]")
    console.print()

    # Result breakdown
    console.print(
        f"  [bold]{len(transitions)}[/bold] functions tested across {total_files} file(s)"
    )
    if skipped_no_size:
        console.print(f"  [dim]{skipped_no_size} file(s) skipped (no SIZE)[/dim]")
    console.print()

    for status in ("EXACT", "RELOC", "NEAR_MATCHING", "STUB"):
        count = result_counts.get(status, 0)
        if count == 0:
            continue
        color = _RESULT_COLORS.get(status, "white")
        pct = round(100.0 * count / len(transitions), 1)
        bar_len = int(20 * count / len(transitions))
        bar = "█" * max(bar_len, 1)
        console.print(f"  [{color}]{status:12s}  {count:4d}  ({pct:5.1f}%)  {bar}[/{color}]")

    # Other statuses not in the standard order
    for status in sorted(set(result_counts) - {"EXACT", "RELOC", "NEAR_MATCHING", "STUB"}):
        count = result_counts[status]
        console.print(f"  [dim]{status:12s}  {count:4d}[/dim]")

    # Status transitions
    if transition_counts:
        console.print()
        console.print("  [bold]Status changes:[/bold]")
        for (old, new), count in sorted(transition_counts.items(), key=lambda x: -x[1]):
            old_color = _RESULT_COLORS.get(old, "dim")
            new_color = _RESULT_COLORS.get(new, "dim")
            console.print(
                f"    [{old_color}]{old}[/{old_color}] → [{new_color}]{new}[/{new_color}]  ×{count}"
            )
    else:
        console.print()
        console.print("  [dim]No status changes.[/dim]")

    console.print()


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
