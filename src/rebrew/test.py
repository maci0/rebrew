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

import hashlib
import logging
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import Annotation, parse_c_file_multi, parse_source_metadata
from rebrew.binary_loader import PADDING_BYTES, extract_raw_bytes
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
from rebrew.core import build_iat_region, build_name_to_va, smart_reloc_compare
from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
from rebrew.metadata import set_fields_batch, update_field, update_source_status

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

    Thin local wrapper over the single shared implementation
    :func:`rebrew.verify.patch_verify_cache_entries` (identity check +
    cross-process lock included).
    """
    from rebrew.verify import patch_verify_cache_entries

    patch_verify_cache_entries(
        cfg,
        [
            {
                "va": va,
                "status": new_status,
                "match_count": match_count,
                "total": total,
                "delta": delta,
            }
        ],
    )


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
    fix_size: bool = typer.Option(
        False,
        "--fix-size",
        help=(
            "Fix a stale SIZE annotation when ALL common bytes match: writes the "
            "compiled size into metadata and reclassifies as EXACT/RELOC.  "
            "No-op when the mismatch is a real byte difference."
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
        # Flag-combination usage error — exit 2, not "needs code work" (1).
        error_exit("--watch cannot be combined with --all", json_mode=json_output, code=EXIT_ERROR)

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
        if fix_size:
            error_exit(
                "--fix-size is file-scoped — batch size repair is 'rebrew verify --fix-sizes'",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        _run_all_batch(cfg, batch_dir, origin, dry_run, no_promote, json_output, jobs=jobs)
        return

    if source is None:
        # Usage error — exit 2, not "needs code work" (1).
        error_exit(
            "Provide a source file, or use --all to batch test all files.",
            json_mode=json_output,
            code=EXIT_ERROR,
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
                fix_size=fix_size,
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
    # CLI overrides are authoritative — apply them to the parsed annotation
    # before validating, so a fresh function tested with --va/--size does not
    # report "Invalid SIZE: 0" (the values are right there on the command
    # line; the annotation SIZE is only a fallback).  Only SIZE is applied:
    # --va SELECTS the annotation in multi-function files, so it must not be
    # overwritten.
    if size is not None:
        for anno in lint_annos:
            anno.size = size
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
                fix_size=fix_size,
            )
            return

    meta = parse_source_metadata(source, metadata_dir=cfg.metadata_dir)

    # Derive symbol from annotation (C function definition).  The
    # VA-based selection happens UNCONDITIONALLY (not just when symbol is
    # absent): an explicit --va on a multi-module file must target the
    # function AT that VA for symbol derivation AND for the metadata
    # promotion below — with --symbol given, the old code fell to
    # lint_annos[0], writing SIZE/CFLAGS/STATUS under the FIRST module
    # even though the function tested was at the requested VA.
    sel_ann: Annotation | None = None
    if va is not None:
        # An explicit --va targets ONE function in (possibly) a
        # multi-function file: derive the symbol (and fallback size) from
        # the annotation whose VA matches.  Same rule as diff/prove/
        # near-diag: a requested VA picks its own function.  When NO
        # annotation matches, the explicit --va is a user override of a
        # stale/absent annotation VA — fall back to the first annotation's
        # symbol/size (the near-diag va_from_flag semantics).
        sel_ann = _select_annotation_for_va(lint_annos, va, json_output)
        if sel_ann is None:
            sel_ann = lint_annos[0] if lint_annos else None
    else:
        # No --va: first try the parsed annotation object (derives from
        # the C function definition).
        sel_ann = lint_annos[0] if lint_annos else None
    if not symbol and sel_ann and sel_ann.symbol:
        symbol = sel_ann.symbol
    if size is None and sel_ann and sel_ann.size:
        size = sel_ann.size
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

    # --fix-size: a SIZE_MISMATCH where every common byte matched is a stale
    # SIZE annotation, not a decompilation problem.  Write the compiled size
    # into metadata and reclassify as a real match.  Requires a VA (metadata
    # is keyed by (module, va)); --target-bin runs have no VA and are skipped.
    # The evidence check verifies the region beyond the common prefix before
    # trusting the compiled size.
    if (
        fix_size
        and cmp.status == "SIZE_MISMATCH"
        and cmp.match_percent == 100.0
        and cmp.full_obj_size is not None
        and cmp.full_obj_bytes is not None
        and section_va is not None
        and _fix_size_evidence_ok(
            cfg, section_va, cmp.full_obj_bytes, target_bytes, cmp.reloc_offsets or []
        )
    ):
        new_size = cmp.full_obj_size
        anno_module = lint_annos[0].module if lint_annos else ""
        if not dry_run:
            try:
                update_field(cfg.metadata_dir, section_va, "size", new_size, anno_module)
            except Exception as exc:  # noqa: BLE001 — metadata write is best-effort
                logging.warning(
                    "Could not persist fixed SIZE 0x%x: %s (the .c still claims the stale size)",
                    section_va,
                    exc,
                )
        else:
            if not json_output:
                console.print(
                    f"[dim]would fix SIZE {size_val or 0} → {new_size} for "
                    f"0x{section_va:x} (--dry-run)[/dim]"
                )
        matched = True
        total = new_size
        match_count = new_size
        size_val = new_size
        relocs = cmp.reloc_offsets or []
        cmp = classify_compare_result(
            True,
            f"RELOC-NORM MATCH ({len(relocs)} relocs)" if relocs else "EXACT MATCH",
            target_bytes,
            cmp.obj_bytes,
            relocs,
            cmp.inv_reloc_offsets,
            full_obj_size=new_size,
            full_obj_bytes=cmp.full_obj_bytes,
        )
        # The extraction at the STALE annotation size no longer reflects the
        # function — re-extract at the fixed size so JSON/display totals are
        # self-consistent (a too-big annotation would otherwise report
        # total=old-size against the new size metadata).
        target_bytes = extract_raw_bytes(cfg.target_binary, section_va, new_size)

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
        # The metadata writes must target the FUNCTION ACTUALLY TESTED — with
        # `--va` on a multi-annotation file, that is the selected annotation,
        # not the file's first (writing under the first module's key created
        # a phantom (first_module, requested_va) entry while the real entry
        # stayed stale).
        promote_ann = sel_ann if sel_ann is not None else (lint_annos[0] if lint_annos else None)
        anno_module = promote_ann.module if promote_ann else ""
        # Persist the resolved SIZE alongside STATUS so downstream tools
        # (diff, near-diag) can resolve it from metadata like STATUS — a
        # hand-written fresh function would otherwise stay at SIZE=0 forever
        # and `rebrew diff` fails with "Invalid SIZE: 0".
        if size_val and not no_promote and not dry_run:
            try:
                update_field(
                    cfg.metadata_dir, va_int_for_promote, "size", int(size_val), anno_module
                )
            except Exception as exc:  # noqa: BLE001 — metadata write is best-effort
                logging.warning(
                    "Could not persist SIZE for 0x%x: %s (downstream diff/near-diag "
                    "may report an invalid size)",
                    va_int_for_promote,
                    exc,
                )
        # Persist an EXPLICIT --cflags override so `rebrew verify` recompiles
        # with the flags that produced the match — without this, verify uses
        # the project defaults and demotes an EXACT /O1 match to NEAR_MATCHING.
        if cflags and not no_promote and not dry_run:
            try:
                update_field(
                    cfg.metadata_dir, va_int_for_promote, "cflags", cflags_str, anno_module
                )
            except Exception as exc:  # noqa: BLE001 — metadata write is best-effort
                logging.warning(
                    "Could not persist CFLAGS for 0x%x: %s (verify may recompile "
                    "with different flags and demote the match)",
                    va_int_for_promote,
                    exc,
                )
        old_status = promote_ann.status if promote_ann else ""
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
    # On SIZE_MISMATCH, cmp.obj_bytes is truncated to the target length — use
    # the recorded full compiled size so total/obj_size report the real
    # function length instead of the common-prefix slice.
    obj_len = cmp.full_obj_size if cmp.full_obj_size is not None else len(obj_bytes)
    total = max(len(target_bytes), obj_len) if (obj_bytes or target_bytes) else 0
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
        obj_size=obj_len,
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
    obj_size: int | None = None,
) -> dict[str, Any]:
    mismatches: list[dict[str, str | int]] = []
    if not matched and obj_bytes:
        min_len = min(len(obj_bytes), len(target_bytes))
        reloc_set = _expand_reloc_offsets(relocs or [], min_len)
        inv_reloc_set = _expand_reloc_offsets(invalid_relocs or [], min_len)
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
        "obj_size": len(obj_bytes) if obj_size is None else obj_size,
        "mismatches": mismatches,
    }


def _fix_size_evidence_ok(
    cfg: ProjectConfig,
    ann_va: int,
    obj_bytes: bytes,
    target_bytes: bytes,
    reloc_offsets: list[int],
) -> bool:
    """True when fixing the SIZE annotation to ``len(obj_bytes)`` is safe.

    The "all common bytes match" gate only covers the common prefix — the
    region beyond it is unverified.  Two directions hide different hazards:

    - compiled LONGER than the annotated slice: re-extract the binary at the
      compiled size and require the newly visible bytes to match (reloc-
      masked).  A false fix here writes a size that hides unreproduced code
      (the annotated slice cut the function short but the tail differs).
    - compiled SHORTER than the annotated slice: the bytes beyond the
      compiled function must be padding (0xCC/0x90).  If they are real code,
      the annotation may cover a function my C only partially reproduces —
      shrinking the size would produce a false EXACT on later runs.

    Fallback: when the padding/extension checks refuse (e.g. a discovery
    boundary merged the NEXT function into the annotation), consult the
    disassembly extent — the authoritative function end.  If it equals the
    compiled size, the compiled function IS the whole function, so fixing to
    the compiled size is safe.  The walk is conservative: a premature stop
    (loop ``jmp`` read as a tail call) yields a smaller extent and refuses.
    """
    if len(obj_bytes) > len(target_bytes):
        ext = extract_raw_bytes(cfg.target_binary, ann_va, len(obj_bytes))
        if len(ext) != len(obj_bytes):
            # Extraction hit the section end — cannot verify the tail.
            return False
        n = len(obj_bytes)
        masked = _expand_reloc_offsets(reloc_offsets, n)
        if all(i in masked or obj_bytes[i] == ext[i] for i in range(n)):
            return True
        # Tail mismatch — the compiled bytes do not reproduce the binary
        # beyond the annotated slice.  Only the disassembly extent can save
        # this, and only if it agrees with the compiled size.
        extent = _disasm_extent(cfg, ann_va)
        return extent is not None and extent == len(obj_bytes)
    if len(target_bytes) > len(obj_bytes):
        extra = target_bytes[len(obj_bytes) :]
        if all(b in PADDING_BYTES for b in extra):
            return True
        # The annotation covers real code beyond the compiled function.  If
        # the disassembly extent matches the compiled size, the annotation
        # merged the next function (or trailing data) — safe to fix.
        extent = _disasm_extent(cfg, ann_va)
        return extent is not None and extent == len(obj_bytes)
    return True


def _disasm_extent(cfg: ProjectConfig, va: int) -> int | None:
    """Disassembly-derived function extent at *va* (best-effort)."""
    from rebrew.binary_loader import function_extent_from_disasm

    try:
        return function_extent_from_disasm(cfg.target_binary, va)
    except Exception:
        return None


def _print_compare_result(cmp: CompareResult, target_bytes: bytes) -> None:
    """Human-readable single-function compare output."""
    relocs = cmp.reloc_offsets or []
    inv_relocs = cmp.inv_reloc_offsets
    obj_bytes = cmp.obj_bytes or b""
    # Same full-size honoring as the JSON builder: on SIZE_MISMATCH the
    # compiled bytes were truncated to the target length for comparison.
    obj_len = cmp.full_obj_size if cmp.full_obj_size is not None else len(obj_bytes)
    total = max(len(target_bytes), obj_len) if (obj_bytes or target_bytes) else 0
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
    size_hint = ""
    if cmp.status == "SIZE_MISMATCH" and cmp.match_percent == 100.0 and obj_len:
        # Every common byte matched — only the SIZE annotation is stale.
        # Same hint as the multi-function path; --fix-size automates it.
        size_hint = (
            f" — all common bytes match; the SIZE annotation is off "
            f"(compiled {obj_len}B vs annotation {len(target_bytes)}B) — "
            f"re-run with --fix-size to correct it"
        )
    console.print(
        f"[{color}]{cmp.status}[/{color}]: {match_count}/{total} bytes{near_hint}{size_hint}"
    )
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
    fix_size: bool = False,
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
    # Tracks whether ANY function came back unmatched — the documented exit
    # contract (help: "1 NEAR_MATCHING or STUB") must hold for multi-function
    # files too, not just single-function and --all (the multi path
    # previously always exited 0, a false green for CI gates).
    any_failed = False
    # Tooling failures (extraction/obj problems) exit 2 like COMPILE_ERROR —
    # a CI script must not read them as "fix your code" (exit 1).
    any_extract_error = False

    with tempfile.TemporaryDirectory(prefix="test_multi_") as workdir:
        objs: dict[str, Any] = {}
        for cf in {_effective_cflags(a) for a in annotations}:
            # Distinct obj name per cflags group — compile_to_obj derives the
            # .obj name from the source stem, so without this every group
            # would overwrite the same obj and all but the last would compare
            # against the wrong bytes.
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
            if not target_bytes:
                any_extract_error = True
                if json_output:
                    results_list.append(
                        {
                            "symbol": sym,
                            "va": f"0x{ann.va:08x}",
                            "size": ann.size,
                            "status": "EXTRACT_ERROR",
                            "error": "Cannot extract target bytes",
                        }
                    )
                else:
                    console.print(f"[red]EXTRACT_ERROR[/red] {sym} — cannot extract target bytes")
                continue
            try:
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
                    iat_region=build_iat_region(cfg),
                )
            except (ValueError, OSError) as exc:
                # Post-compile object extraction/compare failure — the source
                # compiled fine, so this is NOT a COMPILE_ERROR.  Mirror
                # compile_and_compare's EXTRACT_ERROR labeling so a malformed
                # .obj aborts only this symbol, never the whole multi-function
                # file (previously a LIEF raise crashed the batch with a
                # traceback and no JSON output).
                any_extract_error = True
                if json_output:
                    results_list.append(
                        {
                            "symbol": sym,
                            "va": f"0x{ann.va:08x}",
                            "size": ann.size,
                            "status": "EXTRACT_ERROR",
                            "error": str(exc)[:200],
                        }
                    )
                else:
                    console.print(f"[red]EXTRACT_ERROR[/red] {sym} — {exc}")
                continue
            # --fix-size: when ALL common bytes match, the SIZE annotation is
            # stale, not the code — write the compiled size into metadata and
            # reclassify as a real match (mirrors verify --fix-sizes, but the
            # compiled size is the definitive evidence at test time instead of
            # the registry-derived canonical size).  The evidence check
            # verifies the region beyond the common prefix first.
            fixed_size = False
            if (
                size_mismatch
                and fix_size
                and total > 0
                and total - match_count == 0
                and _fix_size_evidence_ok(cfg, ann.va, obj_bytes, target_bytes, relocs)
            ):
                new_size = len(obj_bytes)
                if not dry_run:
                    set_fields_batch(
                        cfg.metadata_dir,
                        [{"module": ann.module, "va": ann.va, "fields": {"size": new_size}}],
                    )
                else:
                    if not json_output:
                        console.print(
                            f"[dim]  would fix SIZE {ann.size} → {new_size} for "
                            f"0x{ann.va:x} (--dry-run)[/dim]"
                        )
                ann.size = new_size
                fixed_size = True
                size_mismatch = False
                matched = True
                total = new_size
                match_count = new_size
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
                        f"re-run with --fix-size to correct it"
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
            if not matched:
                any_failed = True

            if json_output:
                result_dict = build_result_dict_from_compare(
                    source,
                    sym,
                    f"0x{ann.va:08x}",
                    ann.size,
                    cmp,
                    target_bytes,
                )
                if fixed_size:
                    # cmp.obj_bytes was truncated for the comparison — report
                    # the fixed (full) sizes so the JSON is self-consistent.
                    result_dict["status"] = new_status
                    result_dict["size"] = new_size
                    result_dict["total"] = new_size
                    result_dict["match_count"] = new_size
                    result_dict["obj_size"] = new_size
                    result_dict["mismatches"] = []
                results_list.append(result_dict)
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

    if not dry_run:
        # Honor the documented exit-code contract (help: "0 EXACT or RELOC
        # match; 1 NEAR_MATCHING or STUB; 2 Build error") — the multi-
        # function path previously always exited 0, a false green for CI
        # gates (mirrors _run_all_batch).
        if any_extract_error:
            raise typer.Exit(code=EXIT_ERROR)
        if any_failed:
            raise typer.Exit(code=EXIT_MISMATCH)

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
        patches: list[dict[str, Any]] = []
        for r in v_results:
            try:
                va_int = int(r["va"], 16)
            except (ValueError, TypeError, KeyError):
                continue
            pct = r.get("match_percent") or 0.0
            patches.append(
                {
                    "va": va_int,
                    "status": r.get("status", ""),
                    "match_count": round(pct),
                    "total": 100,
                    # verify's real byte delta — recomputing from match_percent
                    # would store a percent-scale number into the byte field
                    # (todo.py's ROI thresholds read it as bytes).
                    "delta": r.get("delta"),
                }
            )
        # One read + one write for the whole batch (the per-result patch was
        # O(N) full-file rewrites of verify_cache.json).
        from rebrew.verify import patch_verify_cache_entries

        patch_verify_cache_entries(cfg, patches)

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
        _print_batch_summary(transitions, unique_files)

    if not dry_run:
        # Honor the documented exit-code contract (help: "0 EXACT or RELOC
        # match; 1 NEAR_MATCHING or STUB; 2 Build error") — the batch path
        # previously always exited 0, a false green for CI gates.
        if any(r.get("status") == "COMPILE_ERROR" for r in v_results):
            raise typer.Exit(code=EXIT_ERROR)
        if v_failed > 0:
            raise typer.Exit(code=EXIT_MISMATCH)


# ---------------------------------------------------------------------------
# Batch summary
# ---------------------------------------------------------------------------


def _print_batch_summary(
    transitions: list[tuple[str, str]],
    total_files: int,
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
