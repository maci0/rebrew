"""Compile-and-compare for reversed functions (single and batch modes).

By default, after comparing, STATUS is auto-updated in the per-directory
metadata (via update_source_status). Use --no-promote to skip this.

Usage:
    rebrew test <source.c> [--symbol NAME] [--va 0xHEX --size N] [--cflags ...]
    rebrew test <source.c> --no-promote   # skip STATUS update
    rebrew test --all                     # batch test all reversed functions
    rebrew test --all --origin GAME       # batch mode, filter by origin
    rebrew test --all --dir src/game_dll/ # batch mode, restrict to subdir
"""

import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import Annotation, parse_c_file_multi, parse_source_metadata
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    STATUS_COLORS,
    TargetOption,
    classify_match_status,
    error_exit,
    is_matched,
    is_status_sticky,
    json_print,
    parse_va,
    require_config,
    resolve_source_arg,
    should_promote_status,
    target_marker,
)
from rebrew.compile import (
    CompareResult,
    classify_compare_result,
    compile_and_compare,
    compile_to_obj,
)
from rebrew.config import ProjectConfig
from rebrew.core import build_name_to_va, smart_reloc_compare
from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
from rebrew.metadata import update_source_status

console = Console(stderr=True)

# At this match ratio, NEAR_MATCHING output is shown in bold yellow instead of
# plain yellow — visually distinguishing "almost there" from "far off".
_NEAR_MATCHING_BOLD_THRESHOLD = 0.97


def _expand_reloc_offsets(relocs: list[int], limit: int) -> set[int]:
    """Expand 4-byte relocation start offsets into a set of individual byte offsets."""
    return {r + j for r in relocs for j in range(4) if r + j < limit}


def _patch_verify_cache(
    cfg: ProjectConfig,
    va: int,
    new_status: str,
    match_count: int,
    total: int,
    *,
    delta: int | None = None,
) -> None:
    """Update the verify cache entry for *va* so status/todo stay in sync.

    When ``rebrew test`` promotes a function's metadata status, the
    verify cache (read by ``rebrew status`` and ``rebrew todo``) may
    still hold a stale result from a previous ``rebrew verify`` run.
    This helper patches the relevant entry in-place so that all tools
    agree on the current status immediately after a test.

    *delta* overrides the recomputed ``total - match_count`` when the
    caller has a real byte delta (the batch path gets one from verify;
    recomputing from match_percent would store a percent-scale number).
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
    if delta is not None:
        result["delta"] = delta
    elif total > 0:
        result["delta"] = total - match_count
    entry["result"] = result
    entries[va_key] = entry
    raw["entries"] = entries

    try:
        from rebrew.utils import atomic_write_text

        atomic_write_text(cache_path, json.dumps(raw, indent=2), encoding="utf-8")
    except (OSError, TypeError):
        pass  # Best-effort — don't crash test on cache write failure


_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew test src/game_dll/my_func.c · · · · · · Auto-detect symbol, VA, size from source\n\n"
    "  rebrew test src/game_dll/my_func.c --symbol _my_func · · Explicit symbol name\n\n"
    "  rebrew test f.c --symbol _sym --va 0x10009310 --size 42 · Override VA and size from CLI\n\n"
    '  rebrew test f.c --symbol _sym --cflags "/O1 /Gd" · · · · Override compiler flags\n\n'
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


def _watch_loop(source_path: Path, retest: Callable[[], None], interval: float = 1.0) -> None:
    """Poll source_path and re-run ``retest()`` on every file change.

    Thin wrapper over the shared :func:`rebrew.utils.watch_files` (which
    handles missing files, swallows ``typer.Exit`` from failed runs, and
    stops on Ctrl+C).
    """
    from rebrew.utils import watch_files

    watch_files([source_path], retest, interval=interval)


def _select_annotation_for_va(
    lint_annos: list[Annotation], va: str, json_output: bool
) -> Annotation | None:
    """The annotation whose VA matches *va*, or None if none does.

    Shared selection for the single-function path: an explicit ``--va`` on a
    multi-function file must target the function AT that VA, not the file's
    first annotation (which silently tested the wrong function before this
    helper — e.g. ``rebrew test multi.c --va 0x2000`` tested the first
    function's symbol at 0x2000).  Mirrors diff/prove/near-diag.
    """
    want_va = parse_va(va, json_mode=json_output)
    return next((a for a in lint_annos if a.va == want_va), None)


@app.callback(invoke_without_command=True)
def main(
    source: str | None = typer.Argument(None, help="C source file (omit with --all)"),
    va: str | None = typer.Option(None, "--va", help="VA in hex (e.g. 0x10009310)"),
    symbol: str | None = typer.Option(None, "--symbol", help="COFF symbol name (e.g. _funcname)"),
    target_bin: str | None = typer.Option(None, "--target-bin", help="Target .bin file"),
    size: int | None = typer.Option(None, "--size", help="Size in bytes"),
    cflags: str | None = typer.Option(None, "--cflags", help="Compiler flags"),
    all_sources: bool = typer.Option(False, "--all", help="Batch test all reversed .c files"),
    batch_dir: str | None = typer.Option(
        None, "--dir", help="With --all, restrict to this subdirectory"
    ),
    origin: str | None = typer.Option(
        None, "--origin", help="With --all, filter by origin (GAME, MSVCRT, ZLIB)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    jobs: int | None = typer.Option(
        None, "--jobs", "-j", help="Number of parallel compile jobs (with --all)"
    ),
    no_promote: bool = typer.Option(
        False,
        "--no-promote",
        help="Skip auto-update of STATUS metadata after test (auto-skipped if file is outside project)",
    ),
    force_status: bool = typer.Option(
        False,
        "--force-status",
        help=(
            "Force the STATUS update even from a sticky status — use to deliberately "
            "demote a stale PROVEN function to its actual result (single-function only)"
        ),
    ),
    watch: bool = typer.Option(
        False, "--watch", help="Watch the source file and re-test on every change"
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
        watch: Re-test the source file on every change (single-file mode only).
        json_output: Emit machine-readable JSON responses.
        target: Optional target profile name from ``rebrew-project.toml``.

    """
    cfg = require_config(target=target, json_mode=json_output)

    # Accept a hex VA or symbol name in addition to a .c path, like
    # `rebrew diff`/`rebrew prove` (resolve_source_arg returns the argument
    # unchanged when nothing matches, so the original error path is kept).
    if source is not None:
        source = str(resolve_source_arg(cfg, source))

    if watch and all_sources:
        error_exit("--watch cannot be combined with --all", json_mode=json_output)

    if source is not None:
        source_path = Path(source).resolve()
        # Safety: disable promotion for files outside the project source tree.
        if not source_path.is_relative_to(cfg.metadata_dir.resolve()):
            no_promote = True
            _status_skip_reason = "file outside project"
        else:
            _status_skip_reason = ""
    else:
        _status_skip_reason = ""

    if all_sources:
        if force_status:
            error_exit(
                "--force-status is single-function only — demote stale PROVEN "
                "functions individually with 'rebrew test <file> --force-status'",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        _run_all_batch(cfg, batch_dir, origin, dry_run, no_promote, json_output, jobs=jobs)
        return

    if source is None:
        error_exit(
            "Provide a source file, or use --all to batch test all files.", json_mode=json_output
        )
        return

    if watch:

        def _retest() -> None:
            # Re-run the full single-file test path; --watch must not nest.
            main(
                source=source,
                va=va,
                symbol=symbol,
                target_bin=target_bin,
                size=size,
                cflags=cflags,
                all_sources=False,
                batch_dir=None,
                origin=None,
                dry_run=dry_run,
                jobs=None,
                no_promote=no_promote,
                force_status=force_status,
                json_output=json_output,
                target=target,
            )

        _watch_loop(source_path, _retest)
        return

    # Build name -> VA map for relocation validation (shared with verify).
    name_to_va = build_name_to_va(cfg)
    if not name_to_va and not json_output:
        console.print("[dim]Skipping relocation validation (global data scan unavailable)[/dim]")

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
        annotations = lint_annos
        if len(annotations) > 1:
            if force_status:
                error_exit(
                    "--force-status is single-function only — demote stale PROVEN "
                    "functions individually with 'rebrew test <file> --force-status'",
                    json_mode=json_output,
                    code=EXIT_ERROR,
                )
            _test_multi(
                cfg,
                source,
                annotations,
                cflags,
                name_to_va=name_to_va,
                no_promote=no_promote,
                dry_run=dry_run,
                json_output=json_output,
            )
            return

    meta = parse_source_metadata(source, metadata_dir=cfg.metadata_dir)

    # Derive symbol from annotation (C function definition)
    sel_ann: Annotation | None = None
    if not symbol:
        if va is not None:
            # An explicit --va targets ONE function in (possibly) a
            # multi-function file: derive the symbol (and fallback size) from
            # the annotation whose VA matches.  Before this, main() used
            # lint_annos[0] — `rebrew test multi.c --va 0x2000` silently
            # tested the FIRST function's symbol at 0x2000 (e.g.
            # _exit_handler@12 instead of _CreateListenSocket).  Same rule as
            # diff/prove/near-diag: a requested VA picks its own function.
            # When NO annotation matches, the explicit --va is a user override
            # of a stale/absent annotation VA — fall back to the first
            # annotation's symbol/size (the near-diag va_from_flag semantics).
            sel_ann = _select_annotation_for_va(lint_annos, va, json_output)
            if sel_ann is None:
                sel_ann = lint_annos[0] if lint_annos else None
            if sel_ann and sel_ann.symbol:
                symbol = sel_ann.symbol
            if size is None and sel_ann and sel_ann.size:
                size = sel_ann.size
        else:
            # First try the parsed annotation object (derives from C func def)
            sel_ann = lint_annos[0] if lint_annos else None
            if sel_ann and sel_ann.symbol:
                symbol = sel_ann.symbol
    else:
        sel_ann = lint_annos[0] if lint_annos else None
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

    from rebrew.cli import resolve_cflags

    _mod = (sel_ann or lint_annos[0]).module if lint_annos else ""
    cflags_str = resolve_cflags(cfg, cflags or meta.get("CFLAGS", ""), _mod)

    section_va: int | None = None
    if va_str is not None and size_val is not None:
        va_int = parse_va(va_str, json_mode=json_output)
        section_va = va_int
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

    # Shared compile→extract→compare path (same as rebrew verify).
    cmp = compile_and_compare(
        cfg,
        source,
        symbol,
        target_bytes,
        cflags_str,
        name_to_va=name_to_va,
        section_va=section_va,
    )
    matched = cmp.matched
    relocs = cmp.reloc_offsets or []
    obj_bytes = cmp.obj_bytes or b""
    # Reconstruct match_count/total for cache + display from CompareResult.
    total = max(len(target_bytes), len(obj_bytes)) if (obj_bytes or target_bytes) else 0
    match_count = int(round(cmp.match_percent / 100.0 * total)) if total else 0
    if matched:
        match_count = total

    if cmp.status == "COMPILE_ERROR":
        error_exit(f"COMPILE ERROR:\n{cmp.message}", json_mode=json_output, code=EXIT_ERROR)

    if json_output:
        result_dict = build_result_dict_from_compare(
            source,
            symbol,
            va_str or "",
            size_val or 0,
            cmp,
            target_bytes,
        )
        if no_promote and _status_skip_reason:
            # Fold the skip reason into the single JSON document so --json
            # output stays a single parseable object.
            result_dict["status_skip_reason"] = _status_skip_reason
        json_print(result_dict)
    else:
        _print_compare_result(cmp, target_bytes)

    # Auto-promote: update STATUS in metadata from test result (skip with --no-promote)
    if no_promote:
        if _status_skip_reason and not json_output:
            console.print(f"[dim]STATUS update skipped ({_status_skip_reason})[/dim]")
    elif va_str:
        va_int_for_promote = parse_va(va_str, json_mode=json_output)
        anno_module = lint_annos[0].module if lint_annos else ""
        old_status = lint_annos[0].status if lint_annos else ""
        # Prefer CompareResult.status so SIZE_MISMATCH / COMPILE_ERROR are preserved.
        new_status = (
            cmp.status if cmp.status else classify_match_status(matched, match_count, total, relocs)
        )
        if not force_status and not should_promote_status(old_status, new_status):
            if is_status_sticky(old_status) and not json_output:
                console.print(f"[dim]STATUS → skipped ({old_status})[/dim]")
        elif dry_run:
            # --dry-run must not write: preview the STATUS change (the compile
            # itself already ran — it is read-only). Matches verify --dry-run.
            if not json_output:
                console.print(
                    f"[dim]would update STATUS → {new_status} for "
                    f"0x{va_int_for_promote:x} ({anno_module})[/dim]"
                )
        else:
            clear = is_matched(new_status)
            update_source_status(
                cfg.metadata_dir,
                new_status,
                anno_module,
                va_int_for_promote,
                clear_blockers=clear,
                force=force_status,
            )
            _patch_verify_cache(
                cfg,
                va_int_for_promote,
                new_status,
                match_count,
                total,
            )
            if not json_output:
                console.print(f"[dim]STATUS → {new_status}[/dim]")

    # Documented exit-code contract: 0 = EXACT/RELOC match, 1 = needs work
    # (NEAR_MATCHING/STUB/SIZE_MISMATCH), 2 = build error (above).
    if not is_matched(cmp.status):
        raise typer.Exit(code=EXIT_MISMATCH)


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

    Prefer :func:`build_result_dict_from_compare` when a :class:`CompareResult`
    is already available.
    """
    status = classify_match_status(matched, match_count, total, relocs)
    return _result_dict_body(
        source,
        symbol,
        va_str,
        size_val,
        status,
        matched,
        match_count,
        total,
        relocs,
        obj_bytes,
        target_bytes,
        invalid_relocs or [],
    )


def build_result_dict_from_compare(
    source: str,
    symbol: str,
    va_str: str,
    size_val: int,
    cmp: CompareResult,
    target_bytes: bytes,
) -> dict[str, Any]:
    """Build JSON from a :class:`CompareResult` (canonical status source)."""
    relocs = cmp.reloc_offsets or []
    obj_bytes = cmp.obj_bytes or b""
    total = max(len(target_bytes), len(obj_bytes)) if (obj_bytes or target_bytes) else 0
    match_count = total if cmp.matched else int(round(cmp.match_percent / 100.0 * total))
    return _result_dict_body(
        source,
        symbol,
        va_str,
        size_val,
        cmp.status,
        cmp.matched,
        match_count,
        total,
        relocs,
        obj_bytes,
        target_bytes,
        cmp.inv_reloc_offsets,
    )


def _result_dict_body(
    source: str,
    symbol: str,
    va_str: str,
    size_val: int,
    status: str,
    matched: bool,
    match_count: int,
    total: int,
    relocs: list[int],
    obj_bytes: bytes,
    target_bytes: bytes,
    invalid_relocs: list[int],
) -> dict[str, Any]:
    mismatches: list[dict[str, str | int]] = []
    if not matched and obj_bytes:
        min_len = min(len(obj_bytes), len(target_bytes))
        reloc_set = _expand_reloc_offsets(relocs, min_len)
        inv_reloc_set = _expand_reloc_offsets(invalid_relocs, min_len)
        mismatches.extend(
            {
                "offset": i,
                "target": f"0x{target_bytes[i]:02x}",
                "got": f"0x{obj_bytes[i]:02x}",
            }
            for i in range(min_len)
            if i not in reloc_set and (i in inv_reloc_set or obj_bytes[i] != target_bytes[i])
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


def _print_compare_result(cmp: CompareResult, target_bytes: bytes) -> None:
    """Human-readable single-function compare output."""
    relocs = cmp.reloc_offsets or []
    inv_relocs = cmp.inv_reloc_offsets
    obj_bytes = cmp.obj_bytes or b""
    total = max(len(target_bytes), len(obj_bytes)) if (obj_bytes or target_bytes) else 0
    match_count = total if cmp.matched else int(round(cmp.match_percent / 100.0 * total))

    if cmp.matched:
        if relocs:
            console.print(
                f"RELOC-NORMALIZED MATCH: {total}/{total} bytes ({len(relocs)} relocations)"
            )
        else:
            console.print(f"EXACT MATCH: {total}/{total} bytes")
        return

    color = STATUS_COLORS.get(cmp.status, "red")
    near_hint = (
        " — run 'rebrew match <file> --flag-sweep-only' to try flag variants"
        if cmp.status == "NEAR_MATCHING"
        else ""
    )
    console.print(f"[{color}]{cmp.status}[/{color}]: {match_count}/{total} bytes{near_hint}")
    if not obj_bytes:
        if cmp.message:
            console.print(cmp.message)
        return
    console.print(f"\nTarget ({len(target_bytes)}B): {target_bytes.hex()}")
    console.print(f"Output ({len(obj_bytes)}B): {obj_bytes.hex()}")
    if len(obj_bytes) == len(target_bytes):
        reloc_set = _expand_reloc_offsets(relocs, len(target_bytes))
        inv_reloc_set = _expand_reloc_offsets(inv_relocs, len(target_bytes))
        diff: list[str] = [
            f"  [{i:3d}] target={target_bytes[i]:02x} got={obj_bytes[i]:02x}"
            for i in range(len(target_bytes))
            if (target_bytes[i] != obj_bytes[i] or i in inv_reloc_set) and i not in reloc_set
        ]
        if diff:
            console.print("Diffs (non-reloc):")
            for d in diff[:20]:
                console.print(d)


def _test_multi(
    cfg: ProjectConfig,
    source: str,
    annotations: list[Annotation],
    cflags_override: str | None,
    *,
    name_to_va: dict[str, int] | None = None,
    no_promote: bool = False,
    dry_run: bool = False,
    json_output: bool = False,
) -> None:
    """Test all functions in a multi-function .c file.

    Compiles the file once, then extracts and compares each annotated
    symbol independently.
    """

    # Per-function cflags can differ in a multi-function file (metadata
    # overrides) — compiling once with the FIRST annotation's flags silently
    # mis-compiled the others (false statuses + wrong promotions).  Group by
    # effective cflags and compile once per group.
    def _effective_cflags(ann: Annotation) -> str:
        if cflags_override:
            return cflags_override
        from rebrew.cli import resolve_cflags

        return resolve_cflags(cfg, ann.cflags, getattr(ann, "module", ""))

    results_list: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="test_multi_") as workdir:
        objs: dict[str, Any] = {}
        for cf in {_effective_cflags(a) for a in annotations}:
            # Distinct obj name per cflags group — compile_to_obj derives the
            # .obj name from the source stem, so without this every group
            # would overwrite the same obj and all but the last would compare
            # against the wrong bytes.
            import hashlib

            obj_name = f"{Path(source).stem}_{hashlib.sha256(cf.encode()).hexdigest()[:8]}.obj"
            obj_path, err = compile_to_obj(cfg, source, cf.split(), workdir, obj_name=obj_name)
            if obj_path is None:
                error_exit(f"COMPILE ERROR (cflags {cf}):\n{err}", json_mode=json_output)
            objs[cf] = obj_path

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
            obj_path = objs[_effective_cflags(ann)]
            # Single LIEF parse for symbol bytes + typed relocs.
            obj_bytes, reloc_dict, full_relocs = parse_obj_symbol_and_relocs(obj_path, sym)

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

            coff_relocs = full_relocs if full_relocs else reloc_dict

            # Size mismatch must be computed on the ORIGINAL lengths — truncating
            # first makes an over-long obj report false EXACT (and get promoted).
            size_mismatch = len(obj_bytes) != len(target_bytes)
            cmp_obj = obj_bytes
            cmp_tgt = target_bytes
            if size_mismatch:
                if len(cmp_obj) > len(cmp_tgt):
                    cmp_obj = cmp_obj[: len(cmp_tgt)]
                else:
                    cmp_tgt = cmp_tgt[: len(cmp_obj)]

            matched, match_count, total, relocs, inv_relocs = smart_reloc_compare(
                cmp_obj,
                cmp_tgt,
                coff_relocs,
                name_to_va=name_to_va,
                section_va=ann.va,
            )
            # Same classifier as compile_and_compare / verify.
            va_hint = f"0x{ann.va:08x}" if getattr(ann, "va", None) else "<source>"
            if size_mismatch:
                size_hint = ""
                if total > 0 and total - match_count == 0:
                    # Every common byte matched — the annotation SIZE is wrong,
                    # not the decompilation.  Point at the fix directly.
                    size_hint = (
                        f" — ALL {total} common bytes match: the SIZE annotation is off; "
                        f"compiled size is {len(obj_bytes)}B (annotation says {ann.size}) — "
                        f"update the // SIZE line"
                    )
                msg = (
                    f"SIZE_MISMATCH: Size {len(obj_bytes)}B vs {len(target_bytes)}B "
                    f"({total - match_count} byte diffs in common prefix){size_hint} — "
                    f"run 'rebrew diff {va_hint}' to see the byte differences"
                )
            else:
                msg = (
                    f"RELOC-NORM MATCH ({len(relocs)} relocs)"
                    if matched and relocs
                    else (
                        "EXACT MATCH" if matched else f"NEAR_MATCHING/STUB: {total - match_count}"
                    )
                )
            cmp = classify_compare_result(
                False if size_mismatch else matched,
                msg,
                cmp_tgt,
                cmp_obj,
                relocs,
                inv_relocs,
                size_mismatch=size_mismatch,
                # Same pre-truncation length diff compile_and_compare threads —
                # without it, a SIZE_MISMATCH delta misses the length diff.
                size_delta=abs(len(obj_bytes) - len(target_bytes)) if size_mismatch else 0,
            )
            matched = cmp.matched
            new_status = cmp.status
            match_count = (
                total if matched else int(round(cmp.match_percent / 100.0 * total)) if total else 0
            )

            if json_output:
                results_list.append(
                    build_result_dict_from_compare(
                        source,
                        sym,
                        f"0x{ann.va:08x}",
                        ann.size,
                        cmp,
                        target_bytes,
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
                color = STATUS_COLORS.get(new_status, "red")
                if new_status == "NEAR_MATCHING" and total > 0:
                    ratio = match_count / total
                    if ratio >= _NEAR_MATCHING_BOLD_THRESHOLD:
                        color = "bold yellow"
                console.print(f"[{color}]{new_status}[/{color}] {sym} — {match_count}/{total}B")

            old_status = ann.status or "STUB"

            # Auto-promote: update STATUS in metadata (mirrors single-function path)
            if not no_promote:
                if not should_promote_status(old_status, new_status):
                    if is_status_sticky(old_status) and not json_output:
                        console.print(f"[dim]  STATUS → skipped ({old_status})[/dim]")
                elif dry_run:
                    # --dry-run must not write: preview (compile already ran).
                    if not json_output:
                        console.print(
                            f"[dim]  would update STATUS → {new_status} for "
                            f"0x{ann.va:x} ({ann.module})[/dim]"
                        )
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
                    )
                    if not json_output:
                        console.print(f"[dim]  STATUS → {new_status}[/dim]")

        if json_output:
            json_print({"source": source, "results": results_list})

    return


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
    (
        unique_entries,
        passed,
        failed,
        fail_details,
        results,
        cached_count,
        size_divergences,
        _missing_sizes,
    ) = prepare_entries(
        cfg,
        full=True,  # test --all always recompiles (no incremental)
        json_output=json_output,
    )

    if size_divergences and not json_output:
        console.print(
            f"[yellow]warning:[/yellow] {len(size_divergences)} function(s) have annotation "
            "SIZE differing from the binary-derived size; run with --json for details"
        )

    if not unique_entries:
        if json_output:
            if dry_run:
                # Same dry-run shape as the non-empty path (canonical keys).
                json_print({"total": 0, "files": [], "functions": []})
            else:
                json_print({"total": 0, "passed": 0, "failed": 0, "results": []})
        else:
            console.print("[yellow]No testable source files found[/yellow]")
        return

    # Filter by batch_dir if specified
    if batch_dir:
        batch_root = (
            Path(batch_dir).resolve()
            if Path(batch_dir).is_absolute()
            else cfg.reversed_dir / batch_dir
        )
        batch_root_str = str(batch_root)
        unique_entries = [
            e
            for e in unique_entries
            if str((cfg.reversed_dir / e.filepath).resolve()).startswith(batch_root_str)
        ]

    # Filter by origin if specified
    if origin_filter:
        unique_entries = [
            e
            for e in unique_entries
            if hasattr(e, "origin") and e.origin and e.origin.upper() == origin_filter.upper()
        ]

    if not unique_entries:
        if json_output:
            if dry_run:
                json_print({"total": 0, "files": [], "functions": []})
            else:
                json_print({"total": 0, "passed": 0, "failed": 0, "results": []})
        else:
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
                    # Canonical "total" key, matching the empty-batch and
                    # non-dry-run result payloads.
                    "total": total,
                    "files": sorted({e.filepath for e in unique_entries}),
                    # Sorted by filepath so "functions" pairs 1:1 with "files"
                    # (which a consumer may zip).  "current_status" is the
                    # ANNOTATED status — distinct from result "status" (the
                    # compile outcome) in the non-dry-run payload.
                    "functions": sorted(
                        (
                            {
                                "va": f"0x{e.va:08x}",
                                "name": getattr(e, "name", ""),
                                "filepath": getattr(e, "filepath", ""),
                                "current_status": getattr(e, "status", ""),
                            }
                            for e in unique_entries
                        ),
                        key=lambda f: f["filepath"],
                    ),
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

    # Sync the verify cache so status/todo don't keep reporting stale
    # pre-batch statuses (the single-file path patches per function).
    if not no_promote:
        for r in v_results:
            try:
                va_int = int(r["va"], 16)
            except (ValueError, TypeError, KeyError):
                continue
            pct = r.get("match_percent") or 0.0
            _patch_verify_cache(
                cfg,
                va_int,
                r.get("status", ""),
                round(pct),
                100,
                # verify's real byte delta — recomputing from match_percent
                # would store a percent-scale number into the byte field
                # (todo.py's ROI thresholds read it as bytes).
                delta=r.get("delta"),
            )

    # Build transitions for summary display
    transitions: list[tuple[str, str]] = []
    for entry, status, _delta in deferred:
        old_status = getattr(entry, "status", "") or "STUB"
        # Sticky statuses (PROVEN) keep their status regardless of byte-level result
        if is_status_sticky(old_status):
            transitions.append((old_status, old_status))
        else:
            transitions.append((old_status, status))

    # Count unique files for the summary
    unique_files = len({e.filepath for e in unique_entries})

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

    for status in ("EXACT", "RELOC", "PROVEN", "NEAR_MATCHING", "STUB"):
        count = result_counts.get(status, 0)
        if count == 0:
            continue
        color = STATUS_COLORS.get(status, "white")
        pct = round(100.0 * count / len(transitions), 1)
        bar_len = int(20 * count / len(transitions))
        bar = "█" * max(bar_len, 1)
        console.print(f"  [{color}]{status:12s}  {count:4d}  ({pct:5.1f}%)  {bar}[/{color}]")

    # Other statuses not in the standard order
    for status in sorted(
        set(result_counts) - {"EXACT", "RELOC", "PROVEN", "NEAR_MATCHING", "STUB"}
    ):
        count = result_counts[status]
        console.print(f"  [dim]{status:12s}  {count:4d}[/dim]")

    # Status transitions
    if transition_counts:
        console.print()
        console.print("  [bold]Status changes:[/bold]")
        for (old, new), count in sorted(transition_counts.items(), key=lambda x: -x[1]):
            old_color = STATUS_COLORS.get(old, "dim")
            new_color = STATUS_COLORS.get(new, "dim")
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
