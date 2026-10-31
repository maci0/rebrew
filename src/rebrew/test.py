"""Compile-and-compare for reversed functions (single and batch modes).

By default, after comparing, metadata is written back: STATUS, plus SIZE and any
explicit --cflags/--toolchain you passed, so that a later `rebrew verify`
recompiles the way this run did.  Pass --no-promote to measure without writing
anything — use it whenever the run is a question, not a record, because the
persisted CFLAGS is what every other tool resolves for that function.

A repeated single-file run reuses that target's name-to-VA map from
`.rebrew/name_to_va_cache.json` when the sources, metadata, and target binary
are unchanged. One changed source reuses the other files' parsed facts.
`rebrew test --all` still recompiles every selected file.

Usage:
    rebrew test <source.c> [--symbol NAME] [--va 0xHEX --size N] [--cflags ...]
    rebrew test <source.c> --no-promote   # skip STATUS update
    rebrew test --all                     # batch: verify's engine, always recompiles
    rebrew test --all --module GAME       # batch mode, filter by module
    rebrew test --all --dir src/game_dll/ # batch mode, restrict to subdir
"""

import threading
lazy import contextlib
lazy import hashlib
lazy import json
lazy import logging
lazy import math
lazy from collections.abc import Callable
lazy from dataclasses import replace
lazy from pathlib import Path
lazy from typing import Any, TypeGuard

import typer
from typer.models import TyperPath

from rebrew.cli import (
    CFLAGS_HELP,
    DIR_HELP,
    EXIT_ERROR,
    EXIT_MISMATCH,
    JOBS_HELP,
    MODULE_HELP,
    SIZE_HELP,
    SOURCE_HELP,
    WATCH_FILE_HELP,
    AllTargetsOption,
    SourceTargetsOption,
    TargetOption,
    all_items_option,
    all_targets_run,
    console,
    error_exit,
    json_print,
    option_default,
    parse_va,
    require_config,
    require_source_arg,
    source_targets_run,
)
lazy from rebrew.coff_reloc import (
    CatalogScanError,
    binding_summary,
    build_iat_region,
    build_name_to_va,
    known_bindings_match,
    refresh_binding_evidence,
    relocation_binding_evidence,
    smart_reloc_compare,
)
lazy from rebrew.compiler.compile import (
    UNCLASSIFIED_DIFF,
    CompareResult,
    classify_compare_result,
    clears_blocker,
    compile_and_compare,
    compile_to_obj,
    is_matched,
    matched_byte_count,
)
lazy from rebrew.compiler.context import CompileContext
lazy from rebrew.config import ProjectConfig, target_module
lazy from rebrew.formats.binary_loader import PADDING_BYTES, extract_raw_bytes
lazy from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
lazy from rebrew.metadata.bindings import (
    SourceBinding,
    min_valid_va_for,
    read_source_bindings,
)
lazy from rebrew.metadata.functions import (
    is_status_parked,
    set_fields_batch,
    should_promote_status,
    update_field,
    update_source_status,
)
lazy from rebrew.present import bar_plain
lazy from rebrew.status_style import DISPLAY_STATUSES, STATUS_COLORS
lazy from rebrew.utils import floor_pct, untrusted_ident

# At this match ratio, NEAR_MATCHING output is shown in bold steel blue instead of
# plain steel blue — visually distinguishing "almost there" from "far off".
_NEAR_MATCHING_BOLD_THRESHOLD = 0.97

# Single-file `rebrew test` is one process per invocation. The name map and
# each file's parse facts are remembered here and under the project `.rebrew`
# directory. An unchanged tree returns the stored map. One changed source
# reuses the other files' facts. `build_name_to_va` itself stays uncached: a
# failed scan must not become a stored empty map, and a read-only caller must
# not grow a file in the project.
_NAME_MAP_CACHE_VERSION = 2
_NAME_MAP_CACHE_MAX = 4
_NAME_MAP_CACHE_FILENAME = "name_to_va_cache.json"
_name_map_cache: dict[str, dict[str, int]] = {}
_name_map_cache_lock = threading.Lock()


def _cmake_pin_for(source: str | Path, cfg: ProjectConfig) -> tuple[str | None, str]:
    """The CMake per-file toolchain + flags pin for *source*, if any.

    ``test``/``verify`` normally resolve toolchain/flags from metadata →
    libraries → project defaults, never reading the generated CMake build
    tree.  But the shipped link compiles a CMake-pinned file with
    ``/REBREW_TOOLCHAIN:...`` + ``COMPILE_FLAGS``, so a per-function number
    describing the default compile does not describe the shipped bytes.
    Returns ``(toolchain, flags)`` from ``flags.make``, both empty/None when
    the file is not pinned or there is no configured build tree.
    """
    build_dir = Path(getattr(cfg, "build_dir", "build"))
    try:
        from rebrew.build_check import per_file_pin
    except ImportError:
        return None, ""
    return per_file_pin(Path(source), build_dir)


def _pin_overrides_metadata(pin_flags: str, metadata_flags: str) -> bool:
    """True when the build compiles the file with flags the metadata did not produce.

    ``rebrew build cmake-flags`` writes the metadata's per-file flags into the CMake
    build, so a pin equal to the metadata-resolved flags is the metadata's own
    value and a new ``--cflags`` reaches the build on the next configure.
    Defines are compared out: ``cmake-flags`` drops them from the flags it
    writes, so a metadata ``/D`` never appears in the pin.
    """

    def flags(s: str) -> set[str]:
        return {t for t in s.split() if not t.startswith(("/D", "-D"))}

    return bool(pin_flags) and flags(pin_flags) != flags(metadata_flags)


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
    match_percent: float | None = None,
    context_hash: str | None = None,
    pending: list[dict[str, object]] | None = None,
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

    *match_percent* is the CompareResult percent (target-length denominator);
    when omitted the cache recomputes from ``match_count / total``, which
    drifts on SIZE_MISMATCH / truncated compares.

    *context_hash* is the digest the verdict was earned under (None = bare
    source) and is part of the cache row's identity, so the patched entry
    records it rather than inheriting the previous run's.

    *pending* collects the patch instead of writing it.  One write costs a
    full read, JSON decode, identity check, re-serialize and locked rewrite
    of a document that grows with the function count, so a per-function loop
    hands each patch to this list and applies the whole batch once via
    :func:`rebrew.verify_cache.patch_verify_cache_entries`.

    Thin local wrapper over the single shared implementation
    :func:`rebrew.verify_cache.patch_verify_cache_entries` (identity check +
    cross-process lock included).
    """
    from rebrew.verify_cache import patch_verify_cache_entries

    patch: dict[str, object] = {
        "va": va,
        "status": new_status,
        "match_count": match_count,
        "total": total,
        "delta": delta,
        "context_hash": context_hash,
    }
    if match_percent is not None:
        patch["match_percent"] = match_percent
    if pending is not None:
        pending.append(patch)
        return
    patch_verify_cache_entries(cfg, [patch])


_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew test src/game/my_func.c\n\n"
    "  rebrew test src/game/my_func.c --no-promote --json\n\n"
    "  rebrew test --all --dry-run\n\n"
    "  rebrew test --all --dir src/game/\n\n"
    "[dim]Compiles and compares function bytes with the reference. Resolves identity, SIZE, and CFLAGS from the C definition and dedicated metadata/configuration. By default, records the byte verdict in STATUS and clears auto-generated BLOCKER on EXACT/RELOC. --no-promote measures without metadata writes; files outside the project are not promoted.[/dim]\n\n"
    "[bold]Batch verification:[/bold]\n\n"
    "  test --all always recompiles. verify reuses unchanged cached results.\n\n"
    "Exit codes: 0 byte match; 1 byte mismatch; 2 usage/config/build error; 130 interrupted; 141 output pipe closed.\n\n"
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
    lint_annos: list[SourceBinding], va: str, json_output: bool
) -> SourceBinding | None:
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
    source: str | None = typer.Argument(None, help=SOURCE_HELP + " (omit with --all)"),
    va: str | None = typer.Option(
        None, "--va", help="Target VA in hex (default: from metadata). Excludes --all."
    ),
    symbol: str | None = typer.Option(
        None,
        "--symbol",
        help="Compiled symbol name (default: from metadata or source definition). Excludes --all.",
    ),
    target_bin: str | None = typer.Option(
        None,
        "--target-bin",
        help="Raw function byte slice to compare against. Excludes --all.",
        click_type=TyperPath(path_type=str),
    ),
    size: int | None = typer.Option(None, "--size", help=f"{SIZE_HELP}. Excludes --all."),
    cflags: str | None = typer.Option(None, "--cflags", help=f"{CFLAGS_HELP}. Excludes --all."),
    toolchain: str | None = typer.Option(
        None,
        "--toolchain",
        help="Compiler profile (e.g. msvc-5.0); overrides the project default. Excludes --all.",
    ),
    all_sources: bool = all_items_option("reversed .c file"),
    batch_dir: str | None = typer.Option(
        None,
        "--dir",
        help=f"{DIR_HELP}. Requires --all",
        click_type=TyperPath(path_type=str),
    ),
    origin: str | None = typer.Option(None, "--module", help=f"{MODULE_HELP}. Requires --all"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    jobs: int | None = typer.Option(None, "--jobs", "-j", help=f"{JOBS_HELP}. Requires --all"),
    no_promote: bool = typer.Option(
        False,
        "--no-promote",
        help=(
            "Measure without metadata writes. Otherwise records STATUS and explicit --cflags/--toolchain/--size overrides for future runs. Use this when trying candidate settings"
        ),
    ),
    force_status: bool = typer.Option(
        False,
        "--force-status",
        help=(
            "Write the STATUS even where the promotion policy refuses it: unpark a "
            "SKIP function or replace a STUB with SIZE_MISMATCH (single-function only)"
        ),
    ),
    fix_sizes: bool = typer.Option(
        False,
        "--fix-sizes",
        help=(
            "Fix stale SIZE metadata when all common bytes match: writes the compiled size into metadata and reclassifies as EXACT/RELOC.  No-op when the mismatch is a real byte difference"
        ),
    ),
    linked: bool = typer.Option(
        False,
        "--linked",
        help=(
            "Compare linker-resolved bytes in a padded shell; requires a VA; excludes --all, --context, and --fix-sizes"
        ),
    ),
    watch: bool = typer.Option(
        False,
        "--watch",
        help=WATCH_FILE_HELP,
    ),
    context: Path | None = typer.Option(
        None,
        "--context",
        help=(
            "C declarations to compile with the source (e.g. 'rebrew export context' output); "
            "the result records the context hash it was earned under"
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
    source_targets: bool = SourceTargetsOption,
) -> None:
    """Compile a source file and compare one function against target bytes.

    With --all, batch-tests every .c file found in the reversed directory (iterating via iter_sources).  Optional --dir and --module flags restrict the batch.  Without --all, a single source file must be provided.

    In single-function mode it resolves symbol, va, and size from CLI arguments first, then falls back to dedicated metadata and optional address anchors. In multi-function mode (when no explicit symbol/va/size is provided), it compiles once and evaluates each annotated function independently.

    Comparison is relocation-aware: COFF relocation records are used to mask relocation-dependent byte spans before scoring exactness. Output status is reported as EXACT, RELOC, NEAR_MATCHING, SIZE_MISMATCH, STUB, or an error state.

    Args: source: Path to the C source file to compile. symbol: Optional COFF symbol name to extract from the produced object. target_bin: Optional path to a raw target byte blob for direct compare. va: Optional hex VA used with size to extract target bytes. size: Optional byte count for the target function. cflags: Optional compiler flags string overriding annotation/config defaults. toolchain: Vendored compiler profile overriding the project default. all_sources: Batch mode — verify's engine over every .c file in reversed_dir (always recompiles). batch_dir: Optional subdirectory to restrict batch mode. origin: Optional module filter for batch mode. dry_run: List batch candidates without running tests. jobs: Parallel compile jobs for --all (defaults to the project [project].jobs). no_promote: Measure only — write no STATUS, CFLAGS, TOOLCHAIN, or SIZE. force_status: Write STATUS where the promotion policy refuses it (unpark a SKIP, replace a STUB with SIZE_MISMATCH); single-function only. fix_sizes: Rewrite a stale SIZE when all common bytes match. linked: Linked compare (shell + real DLL link, no reloc masking); single-function only and needs a VA. watch: Re-test the source file on every change (single-file mode only). context: Extra declarations to compile with the source; the result records the context hash the match was earned under. json_output: Emit machine-readable JSON responses. target: Optional target profile name from rebrew-project.toml. all_targets: Repeat the run across every configured target; refused with --va, --target-bin, and --watch.
    """
    if option_default(watch, False) and option_default(json_output, False):
        error_exit("--watch is terminal-only; omit --json", json_mode=True)
    all_targets = option_default(all_targets, False)
    source_targets = option_default(source_targets, False)
    if all_targets:
        # --va/--target-bin pin ONE target's address space and --watch blocks
        # the sweep; none survive a multi-target run.
        for clash, why in (
            (watch, "--watch"),
            (va, "--va"),
            (target_bin, "--target-bin"),
        ):
            if clash:
                error_exit(
                    f"--all-targets and {why} are mutually exclusive "
                    "(each target resolves its own)",
                    json_mode=json_output,
                )
    if source_targets:
        for scope_clash, flag in (
            (all_sources, "--all"),
            (batch_dir, "--dir"),
            (origin, "--module"),
            (va, "--va"),
            (symbol, "--symbol"),
            (size, "--size"),
            (target_bin, "--target-bin"),
            (watch, "--watch"),
            (linked, "--linked"),
        ):
            value = option_default(scope_clash, None)
            if value or (flag == "--size" and value is not None):
                error_exit(
                    f"--source-targets and {flag} are mutually exclusive", json_mode=json_output
                )

    if option_default(all_sources, False):
        for value, flag in (
            (cflags, "--cflags"),
            (toolchain, "--toolchain"),
            (size, "--size"),
            (va, "--va"),
            (symbol, "--symbol"),
            (target_bin, "--target-bin"),
        ):
            if option_default(value, None) is not None:
                error_exit(
                    f"{flag} cannot be combined with --all",
                    json_mode=option_default(json_output, False),
                    code=EXIT_ERROR,
                )
    else:
        for unused, flag in ((batch_dir, "--dir"), (origin, "--module"), (jobs, "--jobs")):
            if option_default(unused, None) is not None:
                error_exit(
                    f"{flag} requires --all",
                    json_mode=option_default(json_output, False),
                    code=EXIT_ERROR,
                )

    if source_targets and source is not None:
        source = str(Path(source).resolve())

    def run_one(n: str) -> None:
        main(
            source=source,
            va=None,
            symbol=symbol,
            target_bin=None,
            size=size,
            cflags=cflags,
            toolchain=toolchain,
            all_sources=all_sources,
            batch_dir=batch_dir,
            origin=origin,
            dry_run=dry_run,
            jobs=jobs,
            no_promote=no_promote,
            force_status=force_status,
            fix_sizes=fix_sizes,
            linked=linked,
            watch=False,
            context=context,
            json_output=json_output,
            target=n,
            all_targets=False,
            source_targets=False,
        )

    if source_targets_run(
        source,
        enabled=source_targets,
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=run_one,
        root=None,
    ):
        return
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=run_one,
        root=None,
    ):
        return
    cfg = require_config(target=target, json_mode=json_output)

    # The optional compile context: a file of types/prototypes compiled with
    # the source (typically `rebrew export context --output ctx.c`).  It is a compile
    # input (merged into the compile unit and hashed into the result), so a
    # missing file fails loud instead of silently compiling without it.
    from rebrew.compiler.context import load_compile_context

    try:
        compile_context = load_compile_context(context)
    except (OSError, UnicodeDecodeError) as exc:
        error_exit(f"--context {context}: {exc}", json_mode=json_output)

    # Accept a hex VA or symbol name in addition to a .c path, like
    # `rebrew diff`/`rebrew prove`.  An unresolvable argument exits here with
    # one wording instead of the downstream "Could not derive symbol".
    if source is not None:
        if va is None and source.lower().startswith("0x"):
            try:
                int(source, 16)
            except ValueError:
                pass
            else:
                va = source
        source = str(require_source_arg(cfg, source, json_mode=json_output))

    if watch and all_sources:
        error_exit("--watch cannot be combined with --all", json_mode=json_output, code=EXIT_ERROR)

    if linked and all_sources:
        error_exit("--linked is single-function only", json_mode=json_output, code=EXIT_ERROR)
    if linked and context is not None:
        # The linked path compiles inside a padded shell and never merges a
        # context: accepting the flag would silently drop it.
        error_exit(
            "--linked and --context are mutually exclusive; the linked compare "
            "compiles a padded shell and takes no context",
            json_mode=json_output,
            code=EXIT_ERROR,
        )
    if linked and fix_sizes:
        error_exit(
            "--linked and --fix-sizes are mutually exclusive — the linked compare "
            "has no relocation masking to reclassify",
            json_mode=json_output,
            code=EXIT_ERROR,
        )

    if source is not None:
        # Safety: disable promotion for files outside the project source tree.
        no_promote, _status_skip_reason = _status_skip_for_source(cfg, source, no_promote)
    else:
        _status_skip_reason = ""

    if all_sources:
        if force_status:
            error_exit(
                "--force-status is single-function only: use "
                "'rebrew test <file> --va <VA> --force-status'",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        if fix_sizes:
            error_exit(
                "--fix-sizes is file-scoped — batch size repair is 'rebrew verify --fix-sizes'",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        # The batch path is verify's shared pipeline (scan → scope →
        # compile → STATUS sync), emitted in test's shape:
        # always recompile (full), filterable by --dir/--module, measurable
        # via --no-promote.
        emit_test_batch(
            cfg,
            batch_dir=batch_dir,
            origin_filter=origin,
            dry_run=dry_run,
            no_promote=no_promote,
            json_output=json_output,
            jobs=jobs,
            context=compile_context,
        )
        return

    if source is None:
        # Usage error — exit 2, not "needs code work" (1).
        error_exit(
            "Provide a source file, or use --all to batch test all files.",
            json_mode=json_output,
            code=EXIT_ERROR,
        )

    if watch:

        def _retest() -> None:
            # Re-run the full single-file test path; --watch must not nest.
            # Forward every CLI param — an omitted one leaks as a truthy
            # OptionInfo on direct main() re-entry (see docs/DEVELOPMENT.md).
            main(
                source=source,
                va=va,
                symbol=symbol,
                target_bin=target_bin,
                size=size,
                cflags=cflags,
                toolchain=toolchain,
                all_sources=False,
                batch_dir=None,
                origin=None,
                dry_run=dry_run,
                jobs=None,
                no_promote=no_promote,
                force_status=force_status,
                fix_sizes=fix_sizes,
                linked=linked,
                watch=False,
                context=context,
                json_output=json_output,
                target=target,
            )

        _watch_loop(Path(source).resolve(), _retest)
        return

    lint_annos, name_to_va = _lint_preamble(cfg, source, size=size, json_output=json_output)

    # Multi-function support: if no explicit symbol/va/size, test all annotations
    if symbol is None and va is None and size is None:
        annotations = lint_annos
        if len(annotations) > 1:
            if target_bin:
                error_exit(
                    "--target-bin needs a single function — use --va or --symbol to select one",
                    json_mode=json_output,
                    code=EXIT_ERROR,
                )
            if linked:
                error_exit(
                    "--linked needs a single annotated function — use --va to select one",
                    json_mode=json_output,
                    code=EXIT_ERROR,
                )
            if force_status:
                error_exit(
                    "--force-status is single-function only: use "
                    "'rebrew test <file> --va <VA> --force-status'",
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
                fix_sizes=fix_sizes,
                toolchain=toolchain,
                context=compile_context,
            )
            return

    result = _run_test_impl(
        cfg,
        source,
        va=va,
        symbol=symbol,
        target_bin=target_bin,
        size=size,
        cflags=cflags,
        toolchain=toolchain,
        force_status=force_status,
        fix_sizes=fix_sizes,
        linked=linked,
        compile_context=compile_context,
        dry_run=dry_run,
        no_promote=no_promote,
        json_output=json_output,
        status_skip_reason=_status_skip_reason,
        lint_annos=lint_annos,
        name_to_va=name_to_va,
    )
    if json_output:
        json_print(result)

    # Documented exit-code contract (epilog): 0 = EXACT/RELOC match,
    # 1 = needs work (NEAR_MATCHING/STUB/SIZE_MISMATCH), 2 = tooling error
    # (COMPILE_ERROR raises inside the run; an EXTRACT_ERROR exits 2 as well
    # so single-file, multi-function, and batch modes agree).
    if result["status"] == "EXTRACT_ERROR":
        raise typer.Exit(code=EXIT_ERROR)
    if not is_matched(result["status"]):
        raise typer.Exit(code=EXIT_MISMATCH)


def _resolve_total_and_match_count(
    cmp: CompareResult,
    target_bytes: bytes,
) -> tuple[int, int, int]:
    """Return (obj_len, total, match_count) from a CompareResult and target bytes."""
    obj_bytes = cmp.obj_bytes or b""
    # On SIZE_MISMATCH, cmp.obj_bytes is truncated to the common length — use
    # the recorded full compiled size so total/obj_size report the real
    # function length instead of the common-prefix slice.  match_count still
    # reconstructs against the compared length (see matched_byte_count).
    obj_len = cmp.full_obj_size if cmp.full_obj_size is not None else len(obj_bytes)
    total = max(len(target_bytes), obj_len) if (obj_bytes or target_bytes) else 0
    match_count = matched_byte_count(
        cmp.match_percent,
        matched=cmp.matched,
        compared_len=len(obj_bytes),
        total=total,
        match_count=cmp.match_count,
    )
    return obj_len, total, match_count


def build_result_dict_from_compare(
    source: str,
    symbol: str,
    va_str: str,
    size_val: int,
    cmp: CompareResult,
    target_bytes: bytes,
    *,
    include_mismatches: bool = True,
) -> dict[str, Any]:
    """Build JSON from a :class:`CompareResult` (canonical status source).

    Pass ``include_mismatches=False`` when the caller will not serialize the
    result: the per-byte mismatch list is a dict plus two f-strings for every
    differing byte, which the plain terminal path discards.
    """
    relocs = cmp.reloc_offsets or []
    obj_bytes = cmp.obj_bytes or b""
    obj_len, total, match_count = _resolve_total_and_match_count(cmp, target_bytes)
    result = _result_dict_body(
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
        context_hash=cmp.context_hash,
        include_mismatches=include_mismatches,
    )
    if cmp.relocation_bindings is not None:
        result["relocation_bindings"] = cmp.relocation_bindings
    return result


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
    context_hash: str | None = None,
    include_mismatches: bool = True,
) -> dict[str, Any]:
    mismatches: list[dict[str, str | int]] = []
    if include_mismatches and not matched and obj_bytes:
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
        # SHA-256 of the compile context this verdict was earned under, or
        # null when the function was compiled without one.
        "context_hash": context_hash,
        "mismatches": mismatches,
    }


def _fix_size_evidence_ok(
    cfg: ProjectConfig,
    ann_va: int,
    obj_bytes: bytes,
    target_bytes: bytes,
    reloc_offsets: list[int],
    *,
    relocation_bindings: list[dict[str, Any]] | None = None,
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
    if getattr(cfg, "check_known_bindings", False):
        reference = extract_raw_bytes(cfg.target_binary, ann_va, len(obj_bytes))
        if relocation_bindings is None or not known_bindings_match(
            relocation_bindings,
            reference,
            iat_region=build_iat_region(cfg),
        ):
            return False
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
    from rebrew.formats.binary_loader import function_extent_from_disasm

    try:
        return function_extent_from_disasm(cfg.target_binary, va)
    except Exception as exc:
        logging.getLogger(__name__).debug("extent failed for 0x%x: %s", va, exc)
        return None


def _print_compare_result(cmp: CompareResult, target_bytes: bytes) -> None:
    """Human-readable single-function compare output."""
    relocs = cmp.reloc_offsets or []
    inv_relocs = cmp.inv_reloc_offsets
    obj_bytes = cmp.obj_bytes or b""
    obj_len, total, match_count = _resolve_total_and_match_count(cmp, target_bytes)

    if cmp.matched:
        if cmp.status == "EXACT" and relocs:
            console.print(
                f"EXACT MATCH: {total}/{total} bytes in the raw link "
                f"({len(relocs)} relocations resolved; object compare is RELOC)"
            )
        elif relocs:
            console.print(
                f"RELOC-NORMALIZED MATCH: {total}/{total} bytes ({len(relocs)} relocations)"
            )
        else:
            console.print(f"EXACT MATCH: {total}/{total} bytes")
        return

    color = STATUS_COLORS.get(cmp.status, "red")
    near_hint = (
        " — run 'rebrew match flags <file>' to try flag variants"
        if cmp.status == "NEAR_MATCHING"
        else ""
    )
    size_hint = ""
    if (
        cmp.status == "SIZE_MISMATCH"
        and (
            cmp.match_percent is not None
            and math.isclose(cmp.match_percent, 100.0, rel_tol=1e-7, abs_tol=1e-7)
        )
        and obj_len
    ):
        # Every common byte matched — only the SIZE annotation is stale.
        # Same hint as the multi-function path; --fix-sizes automates it.
        size_hint = (
            f" — all common bytes match; the SIZE annotation is off "
            f"(compiled {obj_len}B vs annotation {len(target_bytes)}B) — "
            f"re-run with --fix-sizes to correct it"
        )
    console.print(
        f"[{color}]{untrusted_ident(cmp.status)}[/{color}]: "
        f"{match_count}/{total} bytes{near_hint}{size_hint}"
    )
    if not obj_bytes:
        if cmp.message:
            console.print(untrusted_ident(cmp.message))
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


def _status_skip_for_source(cfg: ProjectConfig, source: str, no_promote: bool) -> tuple[bool, str]:
    """Return ``(no_promote, reason)`` for a source path.

    Sources outside the metadata tree are promoted only when an explicit
    compiled-library identity binds them inside the project. Unbound external
    files remain measure-only, and the reason is reported in JSON.
    """
    source_path = Path(source).resolve()
    if not source_path.is_relative_to(cfg.metadata_dir.resolve()):
        bound_library = source_path.is_relative_to(cfg.root.resolve()) and any(
            entry.kind == "LIBRARY" and not entry.is_data
            for entry in read_source_bindings(
                source_path,
                target_name=target_module(cfg),
                metadata_dir=cfg.metadata_dir,
                project_root=cfg.root,
            )
        )
        if not bound_library:
            return True, "file outside project"
    return no_promote, ""


def _stat_token(path: Path) -> tuple[str, int, int, int]:
    """``(path, mtime_ns, size, ino)``, or ``-1`` when *path* cannot be stat'ed."""
    try:
        st = path.stat()
    except OSError:
        return (str(path), -1, -1, -1)
    return (str(path), st.st_mtime_ns, st.st_size, st.st_ino)


def _feed(hasher: Any, text: str) -> None:
    hasher.update(text.encode("utf-8", "surrogateescape"))
    hasher.update(b"\n")


def _json_int(value: object) -> bool:
    """True for a JSON integer. ``bool`` is an ``int`` subclass and is rejected."""
    return isinstance(value, int) and not isinstance(value, bool)


def _name_map_identity(cfg: ProjectConfig) -> str:
    """Hash of name-map inputs other than per-file source and header stats."""
    from rebrew.config import METADATA_FILENAME, target_module
    from rebrew.metadata.data import DATA_METADATA_FILENAME
    from rebrew.metadata.storage import metadata_store
    from rebrew.sources import source_exts
    from rebrew.utils import binary_fingerprint, preset_module_key

    exports = getattr(cfg, "dll_exports", None) or {}
    export_pairs = tuple(
        sorted(
            (va, name)
            for va, name in exports.items()
            if isinstance(name, str) and name and isinstance(va, int)
        )
    )
    raw_modules = getattr(cfg, "target_modules", None) or ()
    modules = tuple(sorted(str(module) for module in raw_modules))
    binary = getattr(cfg, "target_binary", None)
    metadata_dir = Path(cfg.metadata_dir)
    hasher = hashlib.sha256()
    _feed(hasher, f"v {_NAME_MAP_CACHE_VERSION}")
    _feed(hasher, f"module {preset_module_key(target_module(cfg))}")
    _feed(hasher, f"modules {modules!r}")
    _feed(hasher, f"exports {export_pairs!r}")
    _feed(hasher, f"exts {tuple(source_exts(cfg))!r}")
    _feed(hasher, f"root {cfg.root}")
    _feed(hasher, f"reversed {cfg.reversed_dir}")
    _feed(hasher, f"metadata {metadata_dir}")
    _feed(hasher, f"shared {getattr(cfg, 'shared_dir', '') or ''}")
    _feed(hasher, f"binary {binary_fingerprint(binary) if binary else ''}")
    _feed(hasher, f"functions {metadata_store(metadata_dir / METADATA_FILENAME).fingerprint()!r}")
    _feed(hasher, f"data {metadata_store(metadata_dir / DATA_METADATA_FILENAME).fingerprint()!r}")
    return hasher.hexdigest()


def _source_token_map(cfg: ProjectConfig) -> dict[str, list[int] | None]:
    """Resolved source and header path to ``[mtime_ns, size, ino]``.

    ``None`` means the path could not be stat'ed. That path stays in the
    cache key and its parse facts are not reused.
    """
    from rebrew.sources import iter_sources_and_headers

    tokens: dict[str, list[int] | None] = {}
    for path in iter_sources_and_headers(Path(cfg.reversed_dir), cfg):
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        try:
            st = path.stat()
        except OSError:
            tokens[key] = None
        else:
            tokens[key] = [st.st_mtime_ns, st.st_size, st.st_ino]
    return tokens


def _name_map_key(identity: str, tokens: dict[str, list[int] | None]) -> str:
    hasher = hashlib.sha256()
    _feed(hasher, identity)
    for path in sorted(tokens):
        _feed(hasher, f"{path} {tokens[path]!r}")
    return hasher.hexdigest()


def _name_map_cache_path(cfg: ProjectConfig) -> Path:
    return Path(cfg.root) / ".rebrew" / _NAME_MAP_CACHE_FILENAME


def _remember_name_map(key: str, mapping: dict[str, int]) -> dict[str, int]:
    stored = dict(mapping)
    with _name_map_cache_lock:
        _name_map_cache.pop(key, None)
        _name_map_cache[key] = stored
        while len(_name_map_cache) > _NAME_MAP_CACHE_MAX:
            _name_map_cache.pop(next(iter(_name_map_cache)))
    return dict(stored)


def _cached_name_map(key: str) -> dict[str, int] | None:
    with _name_map_cache_lock:
        cached = _name_map_cache.get(key)
        if cached is None:
            return None
        _name_map_cache[key] = _name_map_cache.pop(key)
        return dict(cached)


def _read_name_map_payload(path: Path) -> dict[str, Any] | None:
    """Version-2 cache document, or ``None`` when the file is missing or older."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError, UnicodeError, json.JSONDecodeError:
        return None
    if not isinstance(raw, dict) or raw.get("version") != _NAME_MAP_CACHE_VERSION:
        return None
    return raw


def _valid_name_map(mapping: object) -> dict[str, int] | None:
    """Copy *mapping* when every VA is an integer. A bool VA is a cache miss."""
    if not isinstance(mapping, dict):
        return None
    loaded: dict[str, int] = {}
    for name, va in mapping.items():
        if not isinstance(name, str) or not _json_int(va):
            return None
        loaded[name] = va
    return loaded


def _scan_fact_ok(facts: object) -> TypeGuard[dict[str, Any]]:
    """True when *facts* is a per-file scan record safe to apply."""
    if not isinstance(facts, dict) or not isinstance(facts.get("apply"), bool):
        return False
    if not facts["apply"]:
        fname = facts.get("fname", None)
        header = facts.get("header", None)
        if "fname" in facts and not isinstance(fname, str):
            return False
        return "header" not in facts or isinstance(header, bool)
    if not isinstance(facts.get("fname"), str) or not isinstance(facts.get("header"), bool):
        return False
    bindings = facts.get("bindings")
    externs = facts.get("externs")
    if not isinstance(bindings, list) or not isinstance(externs, list):
        return False
    for row in bindings:
        if (
            not isinstance(row, dict)
            or not _json_int(row.get("va"))
            or not _json_int(row.get("line"))
        ):
            return False
    return all(isinstance(row, dict) for row in externs)


def _annotation_facts_ok(rows: object) -> TypeGuard[list[dict[str, Any]]]:
    """True when *rows* can be restored without reading the source again."""
    if not isinstance(rows, list):
        return False
    for row in rows:
        if not isinstance(row, dict) or not _json_int(row.get("va")):
            return False
        line = row.get("line", 0)
        if line is None:
            line = 0
        if not _json_int(line):
            return False
    return True


def _reusable_name_map_facts(
    payload: dict[str, Any] | None,
    identity: str,
    tokens: dict[str, list[int] | None],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]] | None:
    """Facts whose stored stat still matches, or ``None`` when replay is unsafe.

    An identity change (module, exports, metadata, binary) and an empty fact
    table both refuse the partial path. A changed or new path is simply
    absent, so the next scan reads that file.
    """
    if payload is None or payload.get("identity") != identity:
        return None
    files = payload.get("files")
    if not isinstance(files, dict) or not files:
        return None
    scan_facts: dict[str, dict[str, Any]] = {}
    annotation_facts: dict[str, list[dict[str, Any]]] = {}
    for path, token in tokens.items():
        if token is None:
            continue
        record = files.get(path)
        if not isinstance(record, dict) or record.get("st") != token:
            continue
        scan = record.get("scan")
        if _scan_fact_ok(scan):
            scan_facts[path] = scan
        if "annotations" in record and _annotation_facts_ok(record.get("annotations")):
            annotation_facts[path] = record["annotations"]
    return scan_facts, annotation_facts


def _name_map_file_records(
    tokens: dict[str, list[int] | None],
    scan_out: dict[str, dict[str, Any]],
    annotation_out: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Per-file facts this scan actually produced. Unreadable paths are omitted."""
    files: dict[str, Any] = {}
    for path, token in tokens.items():
        if token is None:
            continue
        scan = scan_out.get(path)
        if not _scan_fact_ok(scan):
            continue
        record: dict[str, Any] = {"st": token, "scan": scan}
        if path in annotation_out and _annotation_facts_ok(annotation_out[path]):
            record["annotations"] = annotation_out[path]
        files[path] = record
    return files


def _store_disk_name_map(
    path: Path,
    key: str,
    identity: str,
    mapping: dict[str, int],
    files: dict[str, Any],
) -> None:
    from rebrew.utils import atomic_write_text

    payload = {
        "version": _NAME_MAP_CACHE_VERSION,
        "key": key,
        "identity": identity,
        "map": mapping,
        "files": files,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps(payload, sort_keys=True, separators=(",", ":")))
    except OSError:
        return


def _scan_test_name_map(
    cfg: ProjectConfig,
    *,
    scan_facts: dict[str, dict[str, Any]] | None = None,
    annotation_facts: dict[str, list[dict[str, Any]]] | None = None,
) -> tuple[dict[str, int], dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    scan_out: dict[str, dict[str, Any]] = {}
    annotation_out: dict[str, list[dict[str, Any]]] = {}
    mapping = build_name_to_va(
        cfg,
        scan_facts=scan_facts,
        scan_facts_out=scan_out,
        annotation_facts=annotation_facts,
        annotation_facts_out=annotation_out,
    )
    return mapping, scan_out, annotation_out


def _load_test_name_map(cfg: ProjectConfig) -> dict[str, int]:
    """Return the active target's name-to-VA map for a single-file test.

    An exact match returns the stored map and does not scan. The same
    identity with a changed source reuses the other files' parse facts and
    reads the file that changed. A metadata, binary, module, or export
    change scans every file. ``CatalogScanError`` is not stored. A key that
    cannot be built scans again and does not write a cache. Callers that
    must not write into the project keep calling ``build_name_to_va``
    directly.
    """
    try:
        identity = _name_map_identity(cfg)
        tokens = _source_token_map(cfg)
        key = _name_map_key(identity, tokens)
    except OSError, ValueError, KeyError, AttributeError, TypeError:
        return build_name_to_va(cfg)
    cached = _cached_name_map(key)
    if cached is not None:
        return cached
    path = _name_map_cache_path(cfg)
    payload = _read_name_map_payload(path)
    if payload is not None and payload.get("key") == key:
        loaded = _valid_name_map(payload.get("map"))
        if loaded is not None:
            return _remember_name_map(key, loaded)
    reused = _reusable_name_map_facts(payload, identity, tokens)
    if reused is None:
        mapping, scan_out, annotation_out = _scan_test_name_map(cfg)
    else:
        scan_facts, annotation_facts = reused
        try:
            mapping, scan_out, annotation_out = _scan_test_name_map(
                cfg,
                scan_facts=scan_facts,
                annotation_facts=annotation_facts,
            )
        except CatalogScanError, OSError, ValueError, KeyError, AttributeError, TypeError:
            mapping, scan_out, annotation_out = _scan_test_name_map(cfg)
    _store_disk_name_map(
        path,
        key,
        identity,
        mapping,
        _name_map_file_records(tokens, scan_out, annotation_out),
    )
    return _remember_name_map(key, mapping)


def _lint_preamble(
    cfg: ProjectConfig,
    source: str,
    *,
    size: int | None,
    json_output: bool,
) -> tuple[list[SourceBinding], dict[str, int]]:
    """Build the name→VA map and lint the source's annotations once.

    Shared by the callback's multi-function dispatch and by the
    single-function path (:func:`run_test` and the callback), so the lint
    warnings print exactly once per invocation.

    An explicit ``size`` is authoritative for validation, so a fresh function
    tested with ``--va/--size`` does not report "Invalid SIZE: 0". Retain the
    stored sizes for persistence decisions. ``--va`` SELECTS an annotation
    in multi-function files, so it is not applied here.

    The map is reused across single-file invocations while its inputs match.
    One changed source is read again; the other files' facts stay.
    A failed scan still exits: the relocations are not checked against an
    empty map, and the failure is not cached.

    Raises:
        typer.Exit: The VA-map scan failed (fail closed, never mask the
            relocations against an empty map).
    """
    try:
        name_to_va = _load_test_name_map(cfg)
    except CatalogScanError as exc:
        error_exit(str(exc), json_mode=json_output, code=EXIT_ERROR)

    lint_annos = read_source_bindings(
        Path(source),
        target_name=target_module(cfg),
        metadata_dir=cfg.metadata_dir,
        project_root=cfg.root,
    )
    lint_annos = [anno for anno in lint_annos if not anno.is_data]
    for anno in lint_annos:
        evaluated = replace(anno, size=size) if size is not None else anno
        eval_errs, eval_warns = evaluated.validate(min_va=min_valid_va_for(cfg))
        if not json_output:
            for e in eval_errs:
                console.print(f"[bold red]LINT ERROR:[/bold red] {untrusted_ident(e)}")
            for w in eval_warns:
                console.print(f"[bold yellow]LINT WARNING:[/bold yellow] {untrusted_ident(w)}")
    return lint_annos, name_to_va


def _run_test_impl(
    cfg: ProjectConfig,
    source: str,
    *,
    va: str | None = None,
    symbol: str | None = None,
    target_bin: str | None = None,
    size: int | None = None,
    cflags: str | None = None,
    toolchain: str | None = None,
    force_status: bool = False,
    fix_sizes: bool = False,
    linked: bool = False,
    compile_context: CompileContext | None = None,
    dry_run: bool = False,
    no_promote: bool = False,
    json_output: bool = False,
    status_skip_reason: str = "",
    lint_annos: list[SourceBinding],
    name_to_va: dict[str, int],
) -> dict[str, Any]:
    """Compile one function and return the ``rebrew test --json`` result object.

    The single-function core: resolve the symbol / VA / SIZE (CLI overrides
    first, then the source markers and metadata), compile and compare, render
    the human result when *json_output* is false, and auto-promote STATUS and
    SIZE unless *no_promote*.  The object is returned for a match and for a
    mismatch alike; a compile failure raises through ``error_exit``.

    *lint_annos* and *name_to_va* come from :func:`_lint_preamble`, so the
    source is parsed and the project's VA map scanned once per invocation.
    """
    # Select metadata by VA independently of an explicit symbol override.
    sel_ann: SourceBinding | None = None
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
    elif symbol and len(lint_annos) > 1:
        sel_ann = next((a for a in lint_annos if a.symbol == symbol), None)
        if sel_ann is None:
            error_exit(
                f"No annotation for symbol {symbol!r}; use --va to select its address",
                json_mode=json_output,
            )
    else:
        sel_ann = lint_annos[0] if lint_annos else None
    symbol_mismatch = False
    if sel_ann is not None and sel_ann.name and sel_ann.prototype:
        from rebrew.metadata.bindings import derive_c_symbol

        derived_symbol = derive_c_symbol(sel_ann.name, sel_ann.prototype)
        if symbol and derived_symbol and symbol != derived_symbol:
            symbol_mismatch = True
            no_promote = True
            status_skip_reason = "explicit symbol differs from selected function"
        elif derived_symbol:
            symbol = derived_symbol
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
        va_str = f"0x{sel_ann.va:x}" if sel_ann is not None and sel_ann.va else None

    size_val = size
    from rebrew.compiler.overrides import resolve_cflags, resolve_compile_overrides

    _mod = (sel_ann or lint_annos[0]).module if lint_annos else ""
    # Shared fallback chain (per-function metadata → per-library
    # rebrew-libraries.toml → preset → compiler.cflags); an explicit
    # --toolchain / --cflags wins over the metadata value.  Prefer the
    # selected annotation's fields, already scoped to the active target.
    if sel_ann is not None:
        _ann_toolchain: str | None = sel_ann.toolchain or None
        _ann_cflags: str | None = sel_ann.cflags or None
    else:
        _ann_toolchain = None
        _ann_cflags = None
    toolchain_name, cflags_str = resolve_compile_overrides(
        cfg,
        Path(source).resolve().parent,
        toolchain or _ann_toolchain,
        cflags or _ann_cflags,
        _mod,
    )
    # Honour the CMake per-file pin when it exists and no metadata/library
    # override already named a toolchain: the real link compiles this file with
    # the pin, so a number describing the default compile does not describe the
    # shipped bytes.  (Flags follow too when the metadata was silent.)
    cm_pin_tc, cm_pin_flags = _cmake_pin_for(source, cfg)
    if cm_pin_flags and not (cflags or _ann_cflags):
        cflags_str = cm_pin_flags
    if cm_pin_tc and not toolchain_name:
        toolchain_name = cm_pin_tc

    section_va: int | None = None
    if target_bin:
        no_promote = True
        status_skip_reason = "comparison uses a raw target byte slice"
        if fix_sizes:
            error_exit(
                "--fix-sizes cannot use --target-bin; compare against the configured binary",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        if linked:
            error_exit(
                "--linked needs the target binary's section geometry — use --va/--size, "
                "not --target-bin",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        target_bytes = Path(target_bin).read_bytes()
        if size_val is not None:
            target_bytes = target_bytes[:size_val]
        # --target-bin runs compare a raw byte blob with no VA — but the
        # FUNCTION binding still carries the function's VA, and REL32 callee
        # validation needs it (section_va=None masks every call as valid).
        # Resolve it from the annotation so call targets are validated.
        if section_va is None:
            if va_str is not None:
                section_va = parse_va(va_str, json_mode=json_output)
            elif sel_ann is not None and getattr(sel_ann, "va", None):
                section_va = sel_ann.va
    elif va_str is not None and size_val is not None:
        va_int = parse_va(va_str, json_mode=json_output)
        section_va = va_int
        target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size_val)
    else:
        hint = ""
        if va_str is not None:
            try:
                from rebrew.catalog import cached_function_list

                va_int = parse_va(va_str, json_mode=json_output)
                for f in cached_function_list(cfg):
                    if int(f["va"]) == va_int and int(f.get("size") or 0) > 0:
                        hint = (
                            f" (the inventory has SIZE {int(f['size'])} for this VA — "
                            "pass `--size`, or backfill with `rebrew coverage catalog --fix-sizes`)"
                        )
                        break
            except (ValueError, OSError, KeyError, TypeError) as exc:
                # The hint is the only part of the error that names the known
                # size; losing it turns a backfillable gap into a bare "no size".
                logging.getLogger(__name__).debug(
                    "inventory size hint lookup for VA %s failed: %s", va_str, exc
                )
        error_exit(
            "Specify either target_bin or (VA and SIZE) via args or source metadata" + hint,
            json_mode=json_output,
        )

    from rebrew.verify_hash import comparison_inputs, comparison_inputs_current

    measured_inputs = comparison_inputs(
        cfg,
        Path(source),
        target_bytes,
        toolchain=toolchain_name,
        cflags=cflags_str,
        module=_mod,
        va=section_va or 0,
        context_hash=compile_context.sha256 if compile_context is not None else "",
    )
    # Shared compile→extract→compare path (same as rebrew verify), or the
    # --linked oracle: compile in a padded shell, LINK a real DLL at the
    # target base, compare linker-resolved bytes without reloc masking.
    if linked:
        assert section_va is not None  # --target-bin rejected above
        from rebrew.compiler.compile import compile_and_compare_linked

        cmp = compile_and_compare_linked(
            cfg,
            source,
            target_bytes,
            cflags_str,
            va=section_va,
            toolchain=toolchain_name,
        )
    else:
        cmp = compile_and_compare(
            cfg,
            source,
            symbol,
            target_bytes,
            cflags_str,
            name_to_va=name_to_va,
            section_va=section_va,
            toolchain=toolchain_name,
            context=compile_context,
        )
    # Reconstruct match_count/total for cache + display from CompareResult.
    # Prefer full_obj_size for total (SIZE_MISMATCH truncates obj_bytes) but
    # take match_count from CompareResult when present (avoids float round-trip).
    _obj_len, total, match_count = _resolve_total_and_match_count(cmp, target_bytes)
    if not comparison_inputs_current(cfg, Path(source), measured_inputs):
        measured_inputs = None
    if cmp.status == "RELOC" and not target_bin and not symbol_mismatch:
        # Recorded linked EXACT evidence that still describes this compare
        # (same inputs, same raw-link image) keeps the function EXACT.
        from rebrew.linked_exact import LINKED_MESSAGE, linked_exact_holds

        _stored_ann = sel_ann if sel_ann is not None else (lint_annos[0] if lint_annos else None)
        kept = linked_exact_holds(
            cfg, _stored_ann.verification if _stored_ann else None, measured_inputs
        )
        if kept is not None:
            cmp.status = "EXACT"
            cmp.message = LINKED_MESSAGE
            measured_inputs = kept

    if cmp.status == "COMPILE_ERROR":
        error_exit(f"COMPILE ERROR:\n{cmp.message}", json_mode=json_output, code=EXIT_ERROR)

    # --fix-sizes: a SIZE_MISMATCH where every common byte matched is a stale
    # SIZE annotation, not a decompilation problem.  Write the compiled size
    # into metadata and reclassify as a real match.  Requires a VA (metadata
    # is keyed by (module, va)); --target-bin runs have no VA and are skipped.
    # The evidence check verifies the region beyond the common prefix before
    # trusting the compiled size.
    if (
        fix_sizes
        and cmp.status == "SIZE_MISMATCH"
        and (
            cmp.match_percent is not None
            and math.isclose(cmp.match_percent, 100.0, rel_tol=1e-7, abs_tol=1e-7)
        )
        and cmp.full_obj_size is not None
        and cmp.full_obj_bytes is not None
        and section_va is not None
        and _fix_size_evidence_ok(
            cfg,
            section_va,
            cmp.full_obj_bytes,
            target_bytes,
            cmp.reloc_offsets or [],
            relocation_bindings=cmp.relocation_bindings,
        )
    ):
        new_size = cmp.full_obj_size
        # The final SIZE/STATUS path persists this corrected size once.
        if (dry_run or no_promote) and not json_output:
            console.print(
                f"[dim]would fix SIZE {size_val or 0} → {new_size} for "
                f"0x{section_va:x} ({'--dry-run' if dry_run else '--no-promote'})[/dim]"
            )
        total = new_size
        match_count = new_size
        size_val = new_size
        relocs = cmp.reloc_offsets or []
        binding_evidence = cmp.relocation_bindings
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
        cmp.relocation_bindings = binding_evidence
        # The rebuilt result drops the context digest the verdict was earned
        # under; every reader downstream (the JSON payload, the verify-cache
        # patch) takes it from here, so re-attach it like the multi-function
        # path does after its own rebuild.
        cmp.context_hash = compile_context.sha256 if compile_context is not None else None
        # The extraction at the STALE annotation size no longer reflects the
        # function — re-extract at the fixed size so JSON/display totals are
        # self-consistent (a too-big annotation would otherwise report
        # total=old-size against the new size metadata).
        target_bytes = extract_raw_bytes(cfg.target_binary, section_va, new_size)
        if cmp.relocation_bindings is not None:
            cmp.relocation_bindings = refresh_binding_evidence(
                cmp.relocation_bindings, target_bytes, iat_region=build_iat_region(cfg)
            )
        if measured_inputs:
            measured_inputs["reference_hash"] = hashlib.sha256(target_bytes).hexdigest()
            measured_inputs["reference_size"] = str(len(target_bytes))
            measured_inputs.pop("input_hash", None)
            measured_inputs["input_hash"] = hashlib.sha256(
                json.dumps(measured_inputs, sort_keys=True, ensure_ascii=True).encode()
            ).hexdigest()

    result_dict = build_result_dict_from_compare(
        source,
        symbol,
        va_str or "",
        size_val or 0,
        cmp,
        target_bytes,
        # Only --json serializes the per-byte mismatch list; the terminal path
        # reads only status/status_skip_reason out of this dict, so building
        # a dict and two f-strings per differing byte there is pure waste.
        include_mismatches=json_output,
    )
    if no_promote and status_skip_reason:
        # Fold the skip reason into the single JSON document so --json
        # output stays a single parseable object.
        result_dict["status_skip_reason"] = status_skip_reason
    if not json_output:
        _print_compare_result(cmp, target_bytes)

    # Auto-promote: update STATUS in metadata from test result (skip with --no-promote)
    if no_promote:
        if status_skip_reason and not json_output:
            console.print(
                f"[dim]STATUS update skipped ({untrusted_ident(status_skip_reason)})[/dim]"
            )
    elif va_str:
        va_int_for_promote = parse_va(va_str, json_mode=json_output)
        # The metadata writes must target the FUNCTION ACTUALLY TESTED — with
        # `--va` on a multi-annotation file, that is the selected annotation,
        # not the file's first (writing under the first module's key created
        # a phantom (first_module, requested_va) entry while the real entry
        # stayed stale).
        promote_ann = sel_ann if sel_ann is not None else (lint_annos[0] if lint_annos else None)
        anno_module = promote_ann.module if promote_ann else ""
        if not anno_module:
            # The marker filter can exclude every annotation (e.g. a fresh
            # file whose module differs from the target module) — fall back
            # to the file's own marker for the requested VA so the SIZE /
            # STATUS writes land under the real (module, VA) key instead of
            # raising on an empty module (or worse, writing an unreadable one).
            from rebrew.metadata.bindings import module_for_va as _module_for_va

            anno_module = _module_for_va(Path(source), va_int_for_promote)
        # Persist the resolved SIZE alongside STATUS so downstream tools
        # (diff, near-diag) can resolve it from metadata like STATUS — a
        # hand-written fresh function would otherwise stay at SIZE=0 forever
        # and `rebrew diff` fails with "Invalid SIZE: 0".
        if (
            size_val
            and not no_promote
            and not dry_run
            and (
                promote_ann is None
                or promote_ann.va != va_int_for_promote
                or promote_ann.size != size_val
            )
        ):
            try:
                update_field(
                    cfg.metadata_dir,
                    va_int_for_promote,
                    "size",
                    int(size_val),
                    anno_module,
                    updated_by="test",
                )
                console.print(f"[dim]SIZE persisted → {int(size_val)}[/dim]")
            except Exception as exc:  # metadata write is best-effort
                logging.warning(
                    "Could not persist SIZE for 0x%x: %s (downstream diff/near-diag "
                    "may report an invalid size)",
                    va_int_for_promote,
                    exc,
                )
        # Persist an EXPLICIT --cflags override so `rebrew verify` recompiles
        # with the flags that produced the match — without this, verify uses
        # the project defaults and demotes an EXACT /O1 match to NEAR_MATCHING.
        # A CMake-pinned file is excluded: writing here both lies about the
        # build (the link ignores metadata) and can break it (documented
        # C1001/C1083 from persisting the build's own flag pair).  Refuse
        # loudly instead of silently corrupting the metadata.
        cm_pin_tc, cm_pin_flags = _cmake_pin_for(source, cfg)
        if (
            cflags
            and _pin_overrides_metadata(cm_pin_flags, resolve_cflags(cfg, _ann_cflags, _mod))
            and not no_promote
            and not dry_run
        ):
            error_exit(
                f"{source} is CMake-pinned (flags: {cm_pin_flags!r}); --cflags"
                " would be recorded but never shipped — refuse to write it. "
                "Edit the CMakeLists.txt pin instead.",
                json_mode=json_output,
            )
        if cflags and not no_promote and not dry_run:
            try:
                update_field(
                    cfg.metadata_dir,
                    va_int_for_promote,
                    "cflags",
                    cflags_str,
                    anno_module,
                    updated_by="test",
                )
                # Say so: this is the value every other tool now resolves for the
                # function, so a measurement run changes the build's flags.
                console.print(f"[dim]CFLAGS persisted → {untrusted_ident(cflags_str)}[/dim]")
            except Exception as exc:  # metadata write is best-effort
                logging.warning(
                    "Could not persist CFLAGS for 0x%x: %s (verify may recompile "
                    "with different flags and demote the match)",
                    va_int_for_promote,
                    exc,
                )
        # Persist an EXPLICIT --toolchain override for the same reason: the
        # function's best compiler may differ from the project default (the
        # target is a mix of MSVC 4.2/5.0/6.0 output), and verify must
        # recompile with the toolchain that produced the match.
        # Guarded on the CLI argument, not the resolved name: a CMake-pinned
        # file folds `cm_pin_tc` into `toolchain_name` above, and persisting
        # the build's own pin is the same lie the --cflags guard refuses.
        if toolchain and not no_promote and not dry_run:
            try:
                update_field(
                    cfg.metadata_dir,
                    va_int_for_promote,
                    "toolchain",
                    toolchain,
                    anno_module,
                    updated_by="test",
                )
                console.print(f"[dim]TOOLCHAIN persisted → {untrusted_ident(toolchain)}[/dim]")
            except Exception as exc:  # metadata write is best-effort
                logging.warning(
                    "Could not persist TOOLCHAIN for 0x%x: %s (verify may recompile "
                    "with the project default compiler)",
                    va_int_for_promote,
                    exc,
                )
        # An unmarked function reads as STUB, matching the multi-function
        # path and print_test_summary: an empty status is a placeholder
        # verdict, not a free pass to write SIZE_MISMATCH over a function
        # the user never classified.
        old_status = (promote_ann.status if promote_ann else "") or "STUB"
        # CompareResult.status is the one classification point, so
        # SIZE_MISMATCH / COMPILE_ERROR survive unchanged.
        new_status = cmp.status
        if not force_status and not should_promote_status(old_status, new_status):
            if is_status_parked(old_status) and not json_output:
                console.print(f"[dim]STATUS → skipped ({untrusted_ident(old_status)})[/dim]")
            # A refused promotion with the SAME status still carries fresh
            # metrics: status/todo rank ROI from the cache's match_percent and
            # byte delta, so a NEAR_MATCHING improved from 60% to 92% must land
            # even though there is no status transition to hang the patch on
            # (the batch path patches every result for this reason).
            if not dry_run and new_status == old_status and compile_context is None:
                if measured_inputs:
                    update_source_status(
                        cfg.metadata_dir,
                        new_status,
                        anno_module,
                        va_int_for_promote,
                        clear_blockers=False,
                        updated_by="test",
                        verification={**measured_inputs, "status": new_status, "writer": "test"},
                    )
                # A context-scoped run writes nothing to the shared verify
                # cache: the entry cannot record the digest it was earned
                # under, so a later context-free run would read a verdict it
                # never compiled (same rule as `rebrew verify --context`).
                _patch_verify_cache(
                    cfg,
                    va_int_for_promote,
                    new_status,
                    match_count,
                    total,
                    delta=cmp.delta,
                    match_percent=cmp.match_percent,
                    context_hash=cmp.context_hash,
                )
        elif dry_run:
            # --dry-run must not write: preview the STATUS change (the compile
            # itself already ran — it is read-only). Matches verify --dry-run.
            if not json_output:
                console.print(
                    f"[dim]would update STATUS → {untrusted_ident(new_status)} for "
                    f"0x{va_int_for_promote:x} ({untrusted_ident(anno_module)})[/dim]"
                )
        else:
            clear = clears_blocker(new_status, Path(source))
            written = update_source_status(
                cfg.metadata_dir,
                new_status,
                anno_module,
                va_int_for_promote,
                clear_blockers=clear,
                force=force_status,
                updated_by="test",
                verification={**measured_inputs, "status": new_status, "writer": "test"}
                if measured_inputs
                else None,
            )
            if not written:
                # The two holders of a verdict move together: the cached
                # status outranks the metadata STATUS, so patching the cache
                # with a verdict the store refused would make `rebrew status`
                # and `rebrew todo` report a status the store never accepted.
                logging.warning(
                    "promotion policy refused %s for %s 0x%x: the function is "
                    "parked or classified as a documented STUB, so the verify "
                    "cache is left alone",
                    new_status,
                    anno_module,
                    va_int_for_promote,
                )
            elif compile_context is None:
                _patch_verify_cache(
                    cfg,
                    va_int_for_promote,
                    new_status,
                    match_count,
                    total,
                    # Pass the real byte delta when available: for SIZE_MISMATCH
                    # the recomputed total - match_count is 0 (obj_bytes is
                    # truncated to the target length), which todo would read as
                    # a "0B diff — try flag sweep" quick-win.
                    delta=cmp.delta,
                    match_percent=cmp.match_percent,
                    context_hash=cmp.context_hash,
                )
            if written and not json_output:
                console.print(f"[dim]STATUS → {untrusted_ident(new_status)}[/dim]")
    return result_dict


def run_test(
    cfg: ProjectConfig,
    source: Path | str,
    *,
    no_promote: bool = False,
    json_output: bool = False,
) -> dict[str, Any]:
    """Compile one source file and byte-compare its function to the target.

    The single-function pipeline ``rebrew test <source> --json`` runs, with
    no CLI overrides: the symbol, VA and SIZE come from the source markers
    and the project metadata, and the compile flags from the project's
    toolchain resolution.  Returns the exact object the CLI prints
    (``source``, ``symbol``, ``va``, ``size``, ``status``, ``match_count``,
    ``total``, ``reloc_count``, ``obj_size``, ``context_hash``,
    ``mismatches``).  A byte mismatch is a result, not an error: the object
    is returned for both match and mismatch, and *no_promote* keeps the
    engine from writing STATUS/SIZE back into the project metadata.

    Raises:
        typer.Exit: A tooling failure that the CLI reports through
            ``error_exit`` (compile error, unextractable target bytes).
    """
    resolved = str(require_source_arg(cfg, str(source), json_mode=json_output))
    no_promote, status_skip_reason = _status_skip_for_source(cfg, resolved, no_promote)
    lint_annos, name_to_va = _lint_preamble(cfg, resolved, size=None, json_output=json_output)
    return _run_test_impl(
        cfg,
        resolved,
        no_promote=no_promote,
        json_output=json_output,
        status_skip_reason=status_skip_reason,
        lint_annos=lint_annos,
        name_to_va=name_to_va,
    )


def _test_multi(
    cfg: ProjectConfig,
    source: str,
    annotations: list[SourceBinding],
    cflags_override: str | None,
    *,
    name_to_va: dict[str, int] | None = None,
    no_promote: bool = False,
    dry_run: bool = False,
    json_output: bool = False,
    fix_sizes: bool = False,
    toolchain: str | None = None,
    context: CompileContext | None = None,
) -> None:
    """Test all functions in a multi-function .c file.

    Compiles the file once, then extracts and compares each annotated
    symbol independently.
    """

    # Per-function cflags AND toolchains can differ in a multi-function file
    # (metadata overrides) — compiling once with the FIRST annotation's flags
    # silently mis-compiled the others (false statuses + wrong promotions).
    # Group by effective (toolchain, cflags) via the shared fallback chain
    # (annotation → per-library rebrew-libraries.toml → preset → project
    # default) so this path compiles each function exactly like verify_entry
    # and the single-function path do; an explicit --toolchain / --cflags
    # wins over the annotation value.
    def _effective_overrides(ann: SourceBinding) -> tuple[str | None, str]:
        from rebrew.compiler.overrides import resolve_compile_overrides_cached

        return resolve_compile_overrides_cached(
            cfg,
            Path(source).resolve().parent,
            toolchain or getattr(ann, "toolchain", ""),
            cflags_override or getattr(ann, "cflags", ""),
            getattr(ann, "module", ""),
        )

    results_list: list[dict[str, Any]] = []
    # Tracks whether ANY function came back unmatched — the documented exit
    # contract (help: "1 NEAR_MATCHING or STUB") must hold for multi-function
    # files too, not just single-function and --all.
    any_failed = False
    # Tooling failures (extraction/obj problems) exit 2 like COMPILE_ERROR —
    # a CI script must not read them as "fix your code" (exit 1).
    any_extract_error = False

    from rebrew.compiler.temp_dirs import writable_temp_dir
    from rebrew.compiler.toolchain import TOOLCHAINS
    from rebrew.utils import safe_shlex_split

    workdir = writable_temp_dir("test_multi_")
    try:
        objs: dict[tuple[str | None, str], Any] = {}
        cache_patches: list[dict[str, object]] = []
        from rebrew.verify_hash import comparison_inputs, comparison_inputs_current

        group_inputs: dict[tuple[str | None, str], dict[str, str] | None] = {}
        for group_idx, (tc_name, cf) in enumerate(_effective_overrides(a) for a in annotations):
            # One compile per distinct (toolchain, cflags): every annotation
            # resolves the same override for most of a file, and a compile is a
            # container invocation, not a parse.
            if (tc_name, cf) in objs:
                continue
            # A per-group object, so groups never read each other's bytes.
            # Only msvc (/Fo) and posix (-o) honor an explicit name; borland
            # and dos name the object after the source stem, so those groups
            # get their own workdir and the compiler-chosen name instead.
            spec = TOOLCHAINS.get(tc_name) if tc_name else None
            if spec is not None and spec.effective_arg_style not in ("msvc", "posix"):
                group_workdir = workdir / f"g{group_idx}"
                group_workdir.mkdir(parents=True, exist_ok=True)
                obj_name = None
            else:
                group_key = f"{tc_name or ''}\x00{cf}"
                group_workdir = workdir
                # surrogateescape: cflags come from an annotation read with
                # it, so a legacy byte in an -I path arrives here as a lone
                # surrogate, which a strict encode refuses to hash.
                group_digest = hashlib.sha256(
                    group_key.encode("utf-8", errors="surrogateescape")
                ).hexdigest()[:8]
                obj_name = f"{Path(source).stem}_{group_digest}.obj"
            group_inputs[(tc_name, cf)] = comparison_inputs(
                cfg,
                Path(source),
                b"",
                toolchain=tc_name,
                cflags=cf,
                module="",
                va=0,
                context_hash=context.sha256 if context is not None else "",
            )
            obj_path, err = compile_to_obj(
                cfg,
                source,
                safe_shlex_split(cf),
                group_workdir,
                obj_name=obj_name,
                toolchain=tc_name,
                context=context,
            )
            if obj_path is None:
                error_exit(
                    f"COMPILE ERROR (toolchain {tc_name}, cflags {cf}):\n{err}",
                    json_mode=json_output,
                )
            objs[(tc_name, cf)] = obj_path

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
                    console.print(f"[yellow]SKIP[/yellow] {untrusted_ident(sym)} — no SIZE")
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
                obj_path = objs[_effective_overrides(ann)]
                # Single LIEF parse for symbol bytes + typed relocs.
                obj_bytes, reloc_dict, full_relocs = parse_obj_symbol_and_relocs(obj_path, sym)

                if obj_bytes is None:
                    # Same failure class as a malformed .obj below: label it
                    # EXTRACT_ERROR (not "ERROR"/MISSING) so verify-cache,
                    # reports, and the exit-code contract treat all three
                    # post-compile extraction failures identically.
                    any_extract_error = True
                    if json_output:
                        results_list.append(
                            {
                                "symbol": sym,
                                "va": f"0x{ann.va:08x}",
                                "size": ann.size,
                                "status": "EXTRACT_ERROR",
                                "error": "Symbol not found in .obj",
                            }
                        )
                    else:
                        console.print(
                            f"[red]EXTRACT_ERROR[/red] {untrusted_ident(sym)} — not found in .obj"
                        )
                    continue

                if any(rec.format == "elf-xtensa" for rec in full_relocs):
                    from rebrew.compiler.xtensa import link_xtensa_function

                    obj_bytes = link_xtensa_function(
                        cfg, obj_path, sym, ann.va, name_to_va, _effective_overrides(ann)[0]
                    )
                    full_relocs, reloc_dict = [], {}

                coff_relocs = full_relocs or reloc_dict

                # Size mismatch must be computed on the ORIGINAL lengths — truncating
                # first makes an over-long obj report false EXACT (and get promoted).
                size_mismatch = len(obj_bytes) != len(target_bytes)
                orig_obj_len = len(obj_bytes)
                orig_tgt_len = len(target_bytes)
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
                    check_known_bindings=getattr(cfg, "check_known_bindings", False),
                )
            except Exception as exc:
                # Post-compile object extraction/compare failure — the source
                # compiled fine, so this is NOT a COMPILE_ERROR.  Mirror
                # compile_and_compare's EXTRACT_ERROR labeling so a malformed
                # .obj aborts only this symbol, never the whole multi-function
                # file.  ANY exception here isolates to this symbol (logged
                # below); the batch continues with the remaining annotations.
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
                    console.print(
                        f"[red]EXTRACT_ERROR[/red] {untrusted_ident(sym)} — {untrusted_ident(exc)}"
                    )
                continue
            # --fix-sizes: when ALL common bytes match, the SIZE annotation is
            # stale, not the code — write the compiled size into metadata and
            # reclassify as a real match (mirrors verify --fix-sizes, but the
            # compiled size is the definitive evidence at test time instead of
            # the registry-derived canonical size).  The evidence check
            # verifies the region beyond the common prefix first.
            fixed_size = False
            if (
                size_mismatch
                and fix_sizes
                and total > 0
                and total - match_count == 0
                and _fix_size_evidence_ok(
                    cfg,
                    ann.va,
                    obj_bytes,
                    target_bytes,
                    relocs,
                    relocation_bindings=(
                        relocation_binding_evidence(
                            obj_bytes,
                            target_bytes,
                            coff_relocs,
                            name_to_va,
                            section_va=ann.va,
                            iat_region=build_iat_region(cfg),
                        )
                        if getattr(cfg, "check_known_bindings", False)
                        else None
                    ),
                )
            ):
                new_size = len(obj_bytes)
                if not dry_run and not no_promote:
                    try:
                        set_fields_batch(
                            cfg.metadata_dir,
                            [{"module": ann.module, "va": ann.va, "fields": {"size": new_size}}],
                        )
                    except Exception as exc:  # metadata write is best-effort
                        logging.warning(
                            "Could not persist fixed SIZE 0x%x: %s (the .c still claims "
                            "the stale size)",
                            ann.va,
                            exc,
                        )
                elif not json_output:
                    console.print(
                        f"[dim]  would fix SIZE {ann.size} → {new_size} for "
                        f"0x{ann.va:x} ({'--dry-run' if dry_run else '--no-promote'})[/dim]"
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
                        f"re-run with --fix-sizes to correct it"
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
                        "EXACT MATCH"
                        if matched
                        else f"{UNCLASSIFIED_DIFF}: {total - match_count} byte diffs"
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
                # Full (pre-truncation) lengths, like _extract_and_compare: a 20B
                # candidate against an 8B annotation is a real over-long
                # SIZE_MISMATCH, not an 8B stub body.
                full_obj_size=orig_obj_len if size_mismatch else None,
                full_obj_bytes=obj_bytes if size_mismatch else None,
                full_target_size=orig_tgt_len if size_mismatch else None,
            )
            cmp.context_hash = context.sha256 if context is not None else None
            if getattr(cfg, "check_known_bindings", False):
                cmp.relocation_bindings = relocation_binding_evidence(
                    obj_bytes,
                    target_bytes,
                    coff_relocs,
                    name_to_va,
                    section_va=ann.va,
                    iat_region=build_iat_region(cfg),
                )
                summary = binding_summary(cmp.relocation_bindings)
                if summary:
                    cmp.message = f"{cmp.message}; {summary}"
            matched = cmp.matched
            new_status = cmp.status
            # smart_reloc_compare's total is the common (truncated) length —
            # same denominator classify used for match_percent.
            match_count = matched_byte_count(
                cmp.match_percent,
                matched=matched,
                compared_len=total,
                total=total,
                match_count=cmp.match_count,
            )
            if not matched:
                any_failed = True
            measured_inputs = group_inputs.get(_effective_overrides(ann))
            if measured_inputs and not comparison_inputs_current(
                cfg, Path(source), measured_inputs
            ):
                measured_inputs = None
            if measured_inputs:
                measured_inputs = dict(measured_inputs)
                measured_reference = (
                    extract_raw_bytes(cfg.target_binary, ann.va, ann.size)
                    if fixed_size
                    else target_bytes
                )
                measured_inputs["reference_hash"] = hashlib.sha256(measured_reference).hexdigest()
                measured_inputs["reference_size"] = str(len(measured_reference))
                measured_inputs["module"] = ann.module
                measured_inputs["va"] = f"0x{ann.va:x}"
                measured_inputs.pop("input_hash", None)
                measured_inputs["input_hash"] = hashlib.sha256(
                    json.dumps(measured_inputs, sort_keys=True, ensure_ascii=True).encode()
                ).hexdigest()
            if new_status == "RELOC":
                # Same linked-EXACT rule as the single-function path.
                from rebrew.linked_exact import LINKED_MESSAGE, linked_exact_holds

                kept = linked_exact_holds(cfg, ann.verification, measured_inputs)
                if kept is not None:
                    cmp.status = new_status = "EXACT"
                    cmp.message = LINKED_MESSAGE
                    measured_inputs = kept

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
                    result_dict["size"] = ann.size
                    result_dict["total"] = ann.size
                    result_dict["match_count"] = ann.size
                    result_dict["obj_size"] = ann.size
                    result_dict["mismatches"] = []
                results_list.append(result_dict)
            elif matched:
                if relocs and new_status == "RELOC":
                    console.print(
                        f"[green]RELOC[/green] {untrusted_ident(sym)} — "
                        f"{total}/{total}B ({len(relocs)} relocs)"
                    )
                else:
                    console.print(
                        f"[bold green]EXACT[/bold green] {untrusted_ident(sym)} — {total}/{total}B"
                    )
            else:
                color = STATUS_COLORS.get(new_status, "red")
                if new_status == "NEAR_MATCHING" and total > 0:
                    ratio = match_count / total
                    if ratio >= _NEAR_MATCHING_BOLD_THRESHOLD:
                        color = "bold yellow"
                console.print(
                    f"[{color}]{untrusted_ident(new_status)}[/{color}] "
                    f"{untrusted_ident(sym)} — {match_count}/{total}B"
                )

            # No STATUS recorded yet is "", not "STUB": should_promote_status
            # protects a *documented* STUB, and a function the user never
            # classified has none to protect.  Defaulting to "STUB" here
            # (the single-function path at _promote_status does not) made the
            # batch path drop the verdict into no metadata write at all.
            old_status = ann.status or ""

            # Auto-promote: update STATUS in metadata (mirrors single-function path)
            if not no_promote:
                if not should_promote_status(old_status, new_status):
                    if is_status_parked(old_status) and not json_output:
                        console.print(
                            f"[dim]  STATUS → skipped ({untrusted_ident(old_status)})[/dim]"
                        )
                    # A refused promotion with the SAME status still carries fresh
                    # metrics: status/todo rank ROI from the cache's match_percent
                    # and byte delta (same rule as the single-file path).
                    if not dry_run and new_status == old_status and context is None:
                        if measured_inputs:
                            update_source_status(
                                cfg.metadata_dir,
                                new_status,
                                ann.module,
                                ann.va,
                                clear_blockers=False,
                                updated_by="test",
                                verification={
                                    **measured_inputs,
                                    "status": new_status,
                                    "writer": "test",
                                },
                            )
                        _patch_verify_cache(
                            cfg,
                            ann.va,
                            new_status,
                            match_count,
                            total,
                            delta=cmp.delta,
                            match_percent=cmp.match_percent,
                            context_hash=cmp.context_hash,
                            pending=cache_patches,
                        )
                elif dry_run:
                    # --dry-run must not write: preview (compile already ran).
                    if not json_output:
                        console.print(
                            f"[dim]  would update STATUS → {untrusted_ident(new_status)} for "
                            f"0x{ann.va:x} ({untrusted_ident(ann.module)})[/dim]"
                        )
                else:
                    clear = clears_blocker(new_status, Path(source))
                    written = update_source_status(
                        cfg.metadata_dir,
                        new_status,
                        ann.module,
                        ann.va,
                        clear_blockers=clear,
                        updated_by="test",
                        verification={**measured_inputs, "status": new_status, "writer": "test"}
                        if measured_inputs
                        else None,
                    )
                    if not written:
                        # Same refusal rule as the single-file path: a cache
                        # entry the store refused would outrank the metadata
                        # STATUS it never accepted.
                        logging.warning(
                            "promotion policy refused %s for %s 0x%x: the "
                            "function is parked or classified as a documented "
                            "STUB, so the verify cache is left alone",
                            new_status,
                            ann.module,
                            ann.va,
                        )
                    elif context is None:
                        # Same rule as the single-file path: a context-scoped
                        # verdict must not be written to the shared cache.
                        _patch_verify_cache(
                            cfg,
                            ann.va,
                            new_status,
                            match_count,
                            total,
                            # The real byte delta, as the single-file path
                            # passes: recomputing total - match_count yields 0
                            # for a SIZE_MISMATCH (obj truncated to the
                            # target), which todo then reads as a "0B diff —
                            # try flag sweep" quick-win.
                            delta=cmp.delta,
                            match_percent=cmp.match_percent,
                            context_hash=cmp.context_hash,
                            pending=cache_patches,
                        )
                    if written and not json_output:
                        console.print(f"[dim]  STATUS → {untrusted_ident(new_status)}[/dim]")

        if cache_patches:
            from rebrew.verify_cache import patch_verify_cache_entries

            patch_verify_cache_entries(cfg, cache_patches)

        if json_output:
            json_print({"source": source, "results": results_list})
    finally:
        from rebrew.compiler.temp_dirs import remove_temp_dir

        with contextlib.suppress(OSError):
            remove_temp_dir(workdir)

    # Honor the documented exit-code contract (help: "0 EXACT or RELOC
    # match; 1 NEAR_MATCHING or STUB; 2 Build error") — including under
    # --dry-run, which still compiles/compares and only skips STATUS
    # writes (mirrors the single-function path).
    if any_extract_error:
        raise typer.Exit(code=EXIT_ERROR)
    if any_failed:
        raise typer.Exit(code=EXIT_MISMATCH)


def emit_test_batch(
    cfg: ProjectConfig,
    *,
    batch_dir: str | None,
    origin_filter: str | None,
    dry_run: bool,
    no_promote: bool,
    json_output: bool,
    jobs: int | None = None,
    context: CompileContext | None = None,
) -> None:
    """Run the shared batch pipeline, emitted in ``test --all`` shape.

    Always recompiles (full).  ``--dry-run`` lists candidates without
    compiling; ``--no-promote`` measures without writing STATUS.  Raises
    typer.Exit per the exit-code contract (0 match, 1 needs-work,
    2 tooling).
    """
    from rebrew.verify import build_report, patch_cache_from_results, run_batch

    if jobs is None:
        jobs = cfg.default_jobs
    # Scope preview without compiling: prepare_entries is cheap, the
    # compile is not — dry-run lists candidates straight from the scan.
    if dry_run:
        from rebrew.verify import prepare_entries, scope_entries

        scanned = prepare_entries(cfg, True, json_output, context=context)
        scoped = scope_entries(
            scanned[0],
            (scanned[1], scanned[2], scanned[3], scanned[4], scanned[5]),
            (scanned[6], scanned[7]),
            batch_dir=batch_dir,
            origin_filter=origin_filter,
            cfg=cfg,
            json_output=json_output,
        )
        unique_entries, total = scoped[0], scoped[1]
        if json_output:
            json_print(
                {
                    "total": total,
                    "files": sorted({e.filepath for e in unique_entries}),
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
            if not unique_entries:
                console.print("[yellow]No testable source files found[/yellow]")
                return
            console.print(f"[bold]Batch test candidates ({total} functions):[/bold]")
            for e in unique_entries:
                console.print(
                    f"  0x{e.va:08X} {untrusted_ident(e.name)} "
                    f"({untrusted_ident(getattr(e, 'filepath', ''))})"
                )
        return

    if not json_output:
        console.print("\n[bold]Batch testing…[/bold]\n")
    batch = run_batch(
        cfg,
        full=True,  # test --all always recompiles (no incremental)
        json_output=json_output,
        jobs=jobs,
        dry_run=False,
        batch_dir=batch_dir,
        origin_filter=origin_filter,
        no_promote=no_promote,
        context=context,
    )
    if not batch.entries:
        if json_output:
            json_print(
                build_report(
                    cfg,
                    [],
                    0,
                    0,
                    0,
                    batch.size_divergences,
                    batch.missing_sizes,
                    batch.duplicate_vas,
                    dry_run=False,
                    compile_context=context,
                    provenance="test",
                    library_providers=batch.library_providers,
                )
            )
        else:
            console.print("[yellow]No testable source files found[/yellow]")
        return
    # Sync the verify cache so status/todo don't keep reporting stale
    # pre-batch statuses (the single-file path patches per function).
    if not no_promote:
        patch_cache_from_results(cfg, batch.results)
    if json_output:
        # Same shape as `rebrew verify --json` (see build_report) —
        # verify-only extras are null on this path.  ``dry_run`` is the
        # preview flag (already early-returned above); ``--no-promote``
        # is measure-only and must not flip this field.
        json_print(
            build_report(
                cfg,
                batch.results,
                batch.passed,
                batch.failed,
                batch.total,
                batch.size_divergences,
                batch.missing_sizes,
                batch.duplicate_vas,
                dry_run=False,
                compile_context=context,
                provenance="test",
                library_providers=batch.library_providers,
                library_total=sum(int(r["va"], 16) in batch.library_vas for r in batch.results),
                library_passed=sum(
                    r.get("passed", False) and int(r["va"], 16) in batch.library_vas
                    for r in batch.results
                ),
            )
        )
    else:
        print_test_summary(batch.deferred, len({e.filepath for e in batch.entries}))
    if any(r.get("status") in ("COMPILE_ERROR", "EXTRACT_ERROR") for r in batch.results):
        raise typer.Exit(code=EXIT_ERROR)
    if batch.failed > 0:
        raise typer.Exit(code=EXIT_MISMATCH)


def print_test_summary(deferred: list[tuple[SourceBinding, str, int]], total_files: int) -> None:
    """Compact batch summary for ``rebrew test --all`` (STATUS transitions)."""
    transitions: list[tuple[str, str]] = []
    for entry, status, _delta in deferred:
        old_status = getattr(entry, "status", "") or ""
        # Mirror should_promote_status: parked SKIP never moves.
        if should_promote_status(old_status, status):
            transitions.append((old_status, status))
        else:
            transitions.append((old_status, old_status))
    if not transitions:
        console.print(
            f"\n[bold]Batch complete.[/bold] Tested {total_files} file(s), 0 functions compared."
        )
        return
    result_counts: dict[str, int] = {}
    for _old, new in transitions:
        result_counts[new] = result_counts.get(new, 0) + 1
    transition_counts: dict[tuple[str, str], int] = {}
    for old, new in transitions:
        if old != new:
            transition_counts[(old, new)] = transition_counts.get((old, new), 0) + 1
    console.print()
    console.print("[bold]━━━ Batch Summary ━━━[/bold]")
    console.print()
    console.print(
        f"  [bold]{len(transitions)}[/bold] functions tested across {total_files} file(s)"
    )
    console.print()
    print_batch_status_rows(result_counts, len(transitions))
    for status in sorted(set(result_counts) - set(DISPLAY_STATUSES)):
        console.print(f"  [dim]{untrusted_ident(status):12s}  {result_counts[status]:4d}[/dim]")
    if transition_counts:
        console.print()
        console.print("  [bold]Status changes:[/bold]")
        for (old, new), count in sorted(transition_counts.items(), key=lambda x: -x[1]):
            # An unclassified function (no STATUS yet) has no name to print.
            old_label = old or "NEW"
            console.print(
                f"    [{STATUS_COLORS.get(old, 'dim')}]{untrusted_ident(old_label)}"
                f"[/{STATUS_COLORS.get(old, 'dim')}] → "
                f"[{STATUS_COLORS.get(new, 'dim')}]{untrusted_ident(new)}"
                f"[/{STATUS_COLORS.get(new, 'dim')}]  ×{count}"
            )
    else:
        console.print()
        console.print("  [dim]No status changes.[/dim]")
    console.print()


def print_batch_status_rows(result_counts: dict[str, int], total: int) -> None:
    """Print one 40-cell bar per status, as that status's share of *total*."""
    for status in DISPLAY_STATUSES:
        count = result_counts.get(status, 0)
        if count == 0 or total <= 0:
            continue
        color = STATUS_COLORS.get(status, "white")
        pct = floor_pct(count, total)
        bar = bar_plain(count, total)
        console.print(
            f"  [{color}]{untrusted_ident(status):12s}  {count:4d}  ({pct:5.1f}%)  {bar}[/{color}]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
