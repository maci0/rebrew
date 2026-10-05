"""verify.py — Batch compile-and-compare for all reversed functions.

Compiles every annotated ``.c`` file and compares object bytes against the
target binary.  Results are classified by :class:`~rebrew.compile.CompareResult`
(EXACT, RELOC, STUB, COMPILE_ERROR, …).

After verification, STATUS is promoted/demoted in ``rebrew-functions.toml``
via :func:`~rebrew.metadata.update_statuses_batch` unless ``--dry-run`` or
``--no-promote`` is set; the ``.c`` files are **never modified**.  A
PROVEN function gets the byte verdict like any other: PROVEN is not a
byte match and is not protected from demotion.

With ``--compare`` it compares the current run against the last good
baseline (``.rebrew/verify_baseline.toml``) and exits with code 1 on any
regression (suitable for CI / pre-commit hooks).
"""

import concurrent.futures
import contextlib
import functools
import json
import logging
import math
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.compile import CompareResult, CompareStatus
    from rebrew.compile_cache import CacheBackend
    from rebrew.compile_context import CompileContext

import capstone
import typer
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from rebrew.annotation import Annotation, min_valid_va_for
from rebrew.catalog import (
    build_function_registry,
    cached_function_list,
    count_detection_sources,
    scan_reversed_dir,
)
from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    AllTargetsOption,
    RootOption,
    TargetOption,
    all_targets_run,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
)
from rebrew.compile import (
    clears_blocker,
)
from rebrew.compile_overrides import resolve_compile_overrides_cached
from rebrew.config import ProjectConfig, inventory_path_for, module_marker
from rebrew.match_semantics import EFFECTIVE_MATCH_NOTE, is_effective_match
from rebrew.metadata import should_promote_status
from rebrew.metadata_doc import canonical_va_key
from rebrew.sources import contained_path, source_roots
from rebrew.status_style import STATUS_COLORS
from rebrew.utils import (
    atomic_write_text,
    floor_pct,
    interruptible_pool,
    preset_module_key,
    read_json_text,
    untrusted_ident,
)
from rebrew.verify_cache import (
    VerifyCacheEntry,
    cache_path_for,
    load_verify_cache,
    order_result_row,
    save_verify_cache,
)
from rebrew.verify_hash import expected_text_functions
from rebrew.workspace.status import EARNED_STATUSES

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _failed_result(status: "CompareStatus", message: str = "") -> "CompareResult":
    """Create a failed CompareResult with default zero values."""
    from rebrew.compile import CompareResult

    return CompareResult(
        matched=False,
        status=status,
        match_percent=0.0,
        delta=0,
        obj_bytes=None,
        reloc_offsets=None,
        message=message or status,
        match_count=0,
    )


@functools.lru_cache(maxsize=256)
def _fenced_naked_note_cached(path_key: str, _mtime_ns: int, _size: int, _ino: int) -> str:
    """Fence probe keyed by (path, mtime, size, inode) for multi-function TUs.

    Path alone would keep a stale "fenced" / "unfenced" answer after an
    in-process edit (verify --watch, test→verify loops).  The stat key matches
    :func:`rebrew.utils.read_source_text`'s memo so the note tracks the file.
    """
    try:
        from rebrew.utils import read_source_text

        text, _ = read_source_text(Path(path_key))
    except OSError:
        return ""
    if "#ifdef REBREW_ALLOW_NAKED" not in text:
        return ""
    return (
        "source is fenced naked (#ifdef REBREW_ALLOW_NAKED): the comparison "
        "build compiles the #else fallback, which cannot byte-match — "
        "byte-identity requires a REBREW_ALLOW_NAKED build "
        "(`rebrew build round-trip --allow-naked`; for reccmp, build the recomp "
        "binary with -DREBREW_ALLOW_NAKED=1)"
    )


def _fenced_naked_note(cfile: Path) -> str:
    """Return an explanatory note when *cfile* guards its body behind the
    ``REBREW_ALLOW_NAKED`` fence.

    A fenced naked source compiles its ``#else`` fallback in the comparison
    build — for byte-identity the ``#ifdef`` branch must be active.  When
    such a function fails to byte-match, the bare mismatch hides the real
    cause (the build lacks the define), so name it: the caller can then use
    ``rebrew build round-trip --allow-naked`` (or build the reccmp recomp binary
    with ``-DREBREW_ALLOW_NAKED=1``) instead of chasing a phantom source bug.
    """
    try:
        st = cfile.stat()
    except OSError:
        return ""
    try:
        path_key = str(cfile.resolve())
    except OSError:
        path_key = str(cfile)
    return _fenced_naked_note_cached(path_key, st.st_mtime_ns, st.st_size, st.st_ino)


def _entry_symbol(entry: Any) -> str:
    """COFF symbol for *entry*, synthesizing it for legacy marker-only entries.

    Mangling must stay consistent with the COFF symbol lookup in
    parsers._parse_coff (which handles _/name_/_name variants).  Keep the
    annotation symbol as-is when present; only synthesize "_" + name for
    legacy entries lacking a symbol field.  Do not double-prefix.
    """
    if entry.symbol:
        return str(entry.symbol)
    if entry.name and not entry.name.startswith("_"):
        return "_" + str(entry.name)
    return str(entry.name or entry.symbol or "")


def verify_entry(
    entry: Annotation,
    cfg: ProjectConfig,
    cache: "CacheBackend | None" = None,
    *,
    name_to_va: dict[str, int] | None = None,
    context: "CompileContext | None" = None,
    _precompiled_obj: str | None = None,
) -> "CompareResult":
    """Compile a .c file and compare output bytes against DLL.

    Delegates to ``compile_and_compare`` for the compile→extract→compare flow.
    When *cache* is provided, compilation results are reused across calls
    for the same source content + flags — critical for multi-function files
    where the same .c is compiled once and multiple symbols extracted.
    *_precompiled_obj* (batch path) skips the compile when the batch already
    produced this entry's object; ``None`` compiles as before.

    *name_to_va* is the shared data-catalog map used for DIR32 absolute
    validation, same source as ``rebrew test``.  *context* is the project's
    compile context (``rebrew export context`` output), merged into the compile unit
    and recorded on the result as its digest.
    """
    from rebrew.compile import compile_and_compare

    batch_inputs = entry.comparison_inputs if _precompiled_obj is not None else None
    entry.comparison_inputs = None
    cfile = contained_path(source_roots(cfg), entry.filepath)
    if cfile is None:
        # ``file`` is metadata-supplied: an absolute or ``..`` value would
        # compile a path outside the project's source trees.
        return _failed_result(
            "MISSING_FILE", f"MISSING_FILE: {entry.filepath} escapes the source trees"
        )
    if not cfile.exists():
        return _failed_result("MISSING_FILE", f"MISSING_FILE: {cfile}")

    if entry.va < min_valid_va_for(cfg):
        # A VA below the valid floor is an annotation problem (a data-range
        # VA that slipped past the marker filter), NOT a compile failure —
        # labeling it COMPILE_ERROR showed a bogus "compile error" in the
        # summary and tripped the CI gate as if the source failed to build.
        # The floor is arch-aware: 16-bit DOS targets address code from
        # segment 0 (MZ VAs legitimately start at 0).
        return _failed_result("INVALID_VA", "INVALID_VA: VA too low")
    if entry.size <= 0:
        return _failed_result("MISSING_SIZE", "MISSING_SIZE: No SIZE annotation")

    # Shared fallback chain (per-function metadata → per-library
    # rebrew-libraries.toml → preset → compiler.cflags) so verify compiles
    # every function of a library with the same toolchain + flags as
    # match/diff/test.
    toolchain, cflags = resolve_compile_overrides_cached(
        cfg,
        cfile.parent,
        getattr(entry, "toolchain", ""),
        getattr(entry, "cflags", ""),
        getattr(entry, "module", ""),
    )
    symbol = _entry_symbol(entry)

    from rebrew.binary_loader import extract_raw_bytes

    target_bytes = extract_raw_bytes(cfg.target_binary, entry.va, entry.size)
    if not target_bytes:
        # Extraction failure is a binary/tooling problem, not a source
        # compile problem — EXTRACT_ERROR (same stage label compile.py uses
        # for post-compile extraction failures), so the summary and CI gate
        # don't blame the .c file.  When the function list is available and
        # the annotation VA is not a function in it, the likeliest cause is a
        # stale annotation (binary updated since the marker was written) —
        # say so instead of a bare tooling error.
        hint = ""
        try:
            from rebrew.catalog.loaders import cached_function_vas

            vas = cached_function_vas(cfg)
            if vas and entry.va not in vas:
                hint = (
                    f" (annotation VA 0x{entry.va:x} is not a function in the "
                    "current function list — stale annotation? re-run "
                    "`rebrew intake` or edit the marker VA)"
                )
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            # Best-effort hint: narrow the catch so a broken cache or config
            # parse surfaces as a real error instead of silently swallowing
            # the diagnostic worse than no hint at all.
            log.debug("verify hint lookup failed: %s", exc)
        return _failed_result("EXTRACT_ERROR", "Cannot extract DLL bytes" + hint)

    from rebrew.verify_hash import comparison_inputs

    entry.comparison_inputs = comparison_inputs(
        cfg,
        cfile,
        target_bytes,
        toolchain=toolchain,
        cflags=cflags,
        module=entry.module,
        va=entry.va,
        context_hash=context.sha256 if context is not None else "",
    )
    if _precompiled_obj is not None and (
        not batch_inputs
        or not entry.comparison_inputs
        or any(
            batch_inputs[field] != entry.comparison_inputs[field]
            for field in (
                "source_hash",
                "headers_hash",
                "compiler_hash",
                "toolchain",
                "cflags",
                "defines",
            )
        )
    ):
        entry.comparison_inputs = None
    result = compile_and_compare(
        cfg,
        cfile,
        symbol,
        target_bytes,
        cflags,
        cache=cache,
        name_to_va=name_to_va,
        section_va=entry.va,
        toolchain=toolchain,
        context=context,
        _precompiled_obj=_precompiled_obj,
    )
    from rebrew.verify_hash import comparison_inputs_current

    if not comparison_inputs_current(cfg, cfile, entry.comparison_inputs):
        entry.comparison_inputs = None
    if not result.matched:
        # A fenced naked source compiled without REBREW_ALLOW_NAKED produces
        # its empty #else fallback — the mismatch is the build matrix, not
        # the decompilation.  Name it instead of leaving a bare byte diff.
        note = _fenced_naked_note(cfile)
        if note:
            result.message = f"{result.message} {note}".strip()
    if not result.matched and result.obj_bytes:
        # Populate diff_lines (number of differing disassembly lines) for
        # UNMATCHED functions only — matched functions are 0 trivially, and
        # a full disassembly diff per function is wasted work on the common
        # exact/reloc path.  Feeds the recovery-consumed
        # verify_results.diff_lines column (it was documented
        # but never produced, so every row was NULL).  Best-effort: any
        # disassembly failure leaves it None.
        try:
            from rebrew.binary_loader import capstone_mode_for_arch
            from rebrew.matcher import diff_functions

            d = diff_functions(
                target_bytes,
                result.obj_bytes,
                result.reloc_offsets,
                as_dict=True,
                # Counts only — verify reads summary.structural / summary.reg.
                # Full per-instruction rows would rebuild hex/disasm for every
                # mismatch in a batch (often hundreds of functions).
                summary_only=True,
                # Register-encoding diffs are classified separately (RR) so a
                # register-only delta is distinguishable from real structural
                # churn.  Register masking is x86-32 specific; other arches
                # fall back to the plain structural diff.
                register_aware=getattr(cfg, "arch", "") == "x86_32",
                # Same arch wiring as diff.py / match_sweep: 16-bit targets
                # need cs_mode + 2-byte reloc slots, not the 32-bit defaults,
                # and a non-x86 arch needs its own CS_ARCH or the counts come
                # from a mis-decode.
                cs_arch=getattr(cfg, "capstone_arch", capstone.CS_ARCH_X86),
                cs_mode=capstone_mode_for_arch(getattr(cfg, "arch", "")),
                pointer_size=getattr(cfg, "pointer_size", 4),
            )
            if d is not None:
                result.diff_lines = int(d["summary"]["structural"])
                result.reg_delta = int(d["summary"]["reg"])
                # Effective match (reccmp parity): every real delta byte is a
                # register-allocation difference — same instructions, same
                # operands, different registers.  Not byte-identical, but the
                # cause is compiler register allocation, not source logic —
                # name it so the user does not chase a phantom source bug.
                # Exposed to recovery via the result row (effective_match).
                # Classification is shared with near-diag (match_semantics).
                if is_effective_match(
                    structural=int(d["summary"]["structural"]), register=int(d["summary"]["reg"])
                ):
                    result.effective_match = True
                    result.message = f"{result.message} {EFFECTIVE_MATCH_NOTE}".strip()
        except Exception as exc:  # diff_lines is best-effort
            # The logging call itself is inside the guard on purpose: a bad
            # format argument here would otherwise escape this handler and
            # fail the whole verify run, which is exactly what a best-effort
            # block exists to prevent (it once reported 31/283 instead of
            # 281/283 because this line referenced a missing attribute).
            with contextlib.suppress(Exception):
                log.debug("diff_lines failed for 0x%x: %s", entry.va, exc)
            result.diff_lines = None
    # Structural code-similarity score (0–100), computed for EVERY verified
    # function with compiled bytes — matched (short-circuit ~100) and
    # unmatched alike — so the recovery-consumed verify_results.similarity
    # column carries a per-function value.  Reuses the optional `resembl`
    # scoring core; best-effort like diff_lines (a missing extra or a scoring
    # failure leaves it None rather than failing the run).
    if result.obj_bytes:
        try:
            from rebrew.matcher import code_similarity

            result.similarity = code_similarity(target_bytes, result.obj_bytes)
        except Exception as exc:  # similarity is best-effort
            with contextlib.suppress(Exception):  # see diff_lines above
                log.debug("similarity failed for 0x%x: %s", entry.va, exc)
            result.similarity = None
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Rebrew verification pipeline: compile each .c and verify bytes match.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew verify · · · · · · · · · · · · · Verify all .c files (rich progress bar)\n\n"
        "  rebrew verify --json · · · · · · · · · · Emit structured JSON report to stdout\n\n"
        "  rebrew verify --output report.json · · · · · · Export the JSON report to a file\n\n"
        "  rebrew verify --jobs 8 · · · · · · · · · · · Use 8 parallel compile jobs\n\n"
        "  rebrew verify --target mygame · · · · · · · · · Verify a specific target\n\n"
        "  rebrew verify --compare · · · · · · · · · Compare against last run, detect regressions\n\n"
        "  rebrew verify --full --jobs 8 · · · · · · · · Force full re-verify with 8 workers\n\n"
        "  rebrew verify --summary · · · · · · · · · Show detailed STATUS breakdown table\n\n"
        "[bold]How it works:[/bold]\n\n"
        "  For each .c file in reversed_dir, compiles it, extracts the symbol, "
        "and compares the output bytes against the target binary. Reports EXACT, "
        "RELOC (match after relocation masking), NEAR_MATCHING, STUB, or COMPILE_ERROR.\n\n"
        "[bold]Exit codes:[/bold]\n\n"
        "  0   All functions passed verification\n\n"
        "  1   Failures or regressions detected\n\n"
        "  2   Build or config error (also a usage error: unknown flag, missing argument)\n\n"
        "[dim]130 = interrupted (Ctrl+C), 141 = stdout closed early (piped into head).[/dim]\n\n"
        "[dim]Requires rebrew-project.toml with valid compiler and target binary paths.[/dim]"
    ),
)


_STATUS_RANK: dict[str, int] = {
    # Verify never emits PROVEN (a metadata status from `rebrew prove`); a
    # PROVEN row in an older baseline ranks below RELOC, not a byte match.
    "EXACT": 0,
    "RELOC": 1,
    "PROVEN": 2,
    "STUB": 2,
    "NEAR_MATCHING": 2,
    "SIZE_MISMATCH": 2,
    # SKIP is a user parking classification ("don't touch"), not a verdict —
    # it neither passes nor fails the gate (ranked with the neutral band so
    # a newly-SKIPped entry is not a "new failure").
    "SKIP": 2,
    "COMPILE_ERROR": 3,
    "EXTRACT_ERROR": 3,
    "MISSING_FILE": 4,
    "MISSING_SIZE": 4,
    # Pre-compile annotation failure (VA outside the image / below the valid
    # floor) — a metadata problem, not a compile failure.  Ranked with the
    # other MISSING_* annotation problems so it never shows up as a bogus
    # "compile error" in the summary or the CI gate.
    "INVALID_VA": 4,
    # A tooling failure that fails the gate in both modes (fail closed): a
    # worker crash on a previously-EXACT function must fail CI, not pass
    # silently.  See diff_reports, which reports it as a regression.
    "INTERNAL_ERROR": 6,
    "FAIL": 5,
}

# Fine-grained status ordering WITHIN the _STATUS_RANK bands, so same-rank
# changes (NEAR_MATCHING → STUB, both rank 2) are still detected as
# regressions/improvements by the --compare gate.
_STATUS_ORDER: dict[str, int] = {
    "EXACT": 0,
    "RELOC": 1,
    # Baseline rows only (see _STATUS_RANK): below RELOC, above the
    # unmatched statuses.
    "PROVEN": 2,
    "NEAR_MATCHING": 3,
    "SIZE_MISMATCH": 4,
    "STUB": 5,
    # SKIP shares STUB's order: parking/unparking work is status-equal, so a
    # STUB → SKIP transition is not a regression and SKIP → STUB is not an
    # "improvement" — the gate stays silent either way.
    "SKIP": 5,
    "COMPILE_ERROR": 6,
    "EXTRACT_ERROR": 6,
    "MISSING_FILE": 7,
    "MISSING_SIZE": 7,
    "INVALID_VA": 7,
    "INTERNAL_ERROR": 9,
    "FAIL": 8,
}

#: Statuses that rank with SKIP in ``_STATUS_RANK``: a verdict the user has not
#: reached yet.  Parking or unparking one of them is status-equal, so neither
#: direction reads as a regression or an improvement.
_NEUTRAL_BAND: frozenset[str] = frozenset({"PROVEN", "STUB", "NEAR_MATCHING", "SIZE_MISMATCH"})


def _parking_equal(previous_status: str, current_status: str) -> bool:
    """True when the only change is SKIP entering or leaving the neutral band."""
    if previous_status == current_status:
        return False
    if "SKIP" not in (previous_status, current_status):
        return False
    return current_status in _NEUTRAL_BAND or previous_status in _NEUTRAL_BAND


def _va_display(key: Any) -> str:
    """Render a canonical VA key back to a readable string."""
    if isinstance(key, int) and key >= 0:
        return f"0x{key:08x}"
    return str(key)


def diff_reports(
    previous: dict[str, Any],
    current: dict[str, Any],
    scope: set[str] | None = None,
) -> dict[str, Any]:
    """Compare two JSON verify reports and highlight changes in status or match percentage.

    Args:
        previous: The previous run's full JSON results dict.
        current: The newly generated full JSON results dict.
        scope: Display-form VA keys (``0x%08x``) the run covered.  A scoped run
            leaves the baseline whole-project, so every out-of-scope entry is
            absent from ``current`` and would otherwise be reported as
            ``removed``.  ``None`` compares the whole corpus.

    Returns:
        A dict with 'regressions', 'improvements', 'new', and 'removed' lists
        plus an 'unchanged_count'.

    """
    previous_results = {
        canonical_va_key(r["va"]): r
        for r in previous.get("results", [])
        if isinstance(r, dict) and "va" in r
    }
    current_results = {
        canonical_va_key(r["va"]): r
        for r in current.get("results", [])
        if isinstance(r, dict) and "va" in r
    }

    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    new_items: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    unchanged_count = 0

    unknown_order = max(_STATUS_ORDER.values()) + 1

    def _sort_key(k: Any) -> tuple[bool, Any]:
        # Mixed int/str canonical keys must sort without TypeError.
        return (isinstance(k, str), k)

    for va in sorted(current_results, key=_sort_key):
        current_item = current_results[va]
        current_status = str(current_item.get("status", "FAIL"))

        # A tooling crash on a previously-passing function IS a regression:
        # fail closed in --compare too (plain verify already exits 1 via the
        # failed total).  INTERNAL_ERROR now lands in fail_details, so the
        # only rows not counted here are ones that also failed before.
        if current_status == "INTERNAL_ERROR":
            previous_status = str(previous_results.get(va, {}).get("status", "FAIL"))
            if va not in previous_results or previous_status != "INTERNAL_ERROR":
                regressions.append(
                    {
                        "va": _va_display(va),
                        "name": str(
                            current_item.get("name") or previous_results.get(va, {}).get("name", "")
                        ),
                        "previous_status": previous_status,
                        "current_status": current_status,
                        "delta": int(current_item.get("delta", 0)),
                    }
                )
            else:
                unchanged_count += 1
            continue

        current_order = _STATUS_ORDER.get(current_status, unknown_order)

        if va not in previous_results:
            new_items.append(
                {
                    "va": _va_display(va),
                    "name": str(current_item.get("name", "")),
                    "status": current_status,
                }
            )
            continue

        previous_item = previous_results[va]
        previous_status = str(previous_item.get("status", "FAIL"))
        previous_order = _STATUS_ORDER.get(previous_status, unknown_order)

        if _parking_equal(previous_status, current_status):
            unchanged_count += 1
            continue

        if current_order == previous_order:
            # Same fine-grained status: only a match-percentage drop beyond
            # _COMPARE_DROP_PCT is a regression (e.g. NEAR_MATCHING 95% → 40%).
            prev_pct = previous_item.get("match_percent")
            curr_pct = current_item.get("match_percent")
            if (
                isinstance(prev_pct, (int, float))
                and isinstance(curr_pct, (int, float))
                and math.isfinite(prev_pct)
                and math.isfinite(curr_pct)
                and curr_pct < prev_pct - _COMPARE_DROP_PCT
            ):
                regressions.append(
                    {
                        "va": _va_display(va),
                        "name": str(current_item.get("name") or previous_item.get("name", "")),
                        "previous_status": previous_status,
                        "current_status": current_status,
                        "delta": int(current_item.get("delta", 0)),
                        "previous_match_percent": floor_pct(float(prev_pct), 100, 1),
                        "current_match_percent": floor_pct(float(curr_pct), 100, 1),
                    }
                )
                continue
            unchanged_count += 1
            continue
        change = {
            "va": _va_display(va),
            "name": str(current_item.get("name") or previous_item.get("name", "")),
            "previous_status": previous_status,
            "current_status": current_status,
            "delta": int(current_item.get("delta", 0)),
        }
        if current_order < previous_order:
            improvements.append(change)
        else:
            regressions.append(change)

    for va in sorted(previous_results, key=_sort_key):
        if va in current_results:
            continue
        if scope is not None and _va_display(va) not in scope:
            continue
        previous_item = previous_results[va]
        removed.append(
            {
                "va": _va_display(va),
                "name": str(previous_item.get("name", "")),
                "status": str(previous_item.get("status", "FAIL")),
            }
        )

    return {
        "regressions": regressions,
        "improvements": improvements,
        "new": new_items,
        "removed": removed,
        "unchanged_count": unchanged_count,
    }


# Same-rank match-percentage drop that counts as a --compare regression
# (e.g. NEAR_MATCHING 95% → 40%).  Smaller wobbles are measurement noise.
_COMPARE_DROP_PCT = 5.0

# How many rows a display list shows before it stops printing; the JSON
# report always carries every row.
_DISPLAY_ROWS_MAX = 15

# How many unwritten STATUS updates one warning names before it defers to a
# count; a run with hundreds of orphans would drown the log.
_ORPHAN_REPORT_LIMIT = 10


@app.callback(invoke_without_command=True)
def main(
    file: str | None = typer.Argument(
        None, help="Restrict to one source file (e.g. src/x/foo.c) for per-file CI gating"
    ),
    root: Path | None = RootOption,
    jobs: int | None = typer.Option(
        None,
        "--jobs",
        "-j",
        help="Number of parallel compile jobs (default: from project.jobs or 4)",
    ),
    output_path: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the JSON report to a file (explicit export; the --compare "
        "baseline lives in .rebrew/ and needs no flag)",
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        "-s",
        help="Show summary table with STATUS breakdown and match percentages",
    ),
    diff_mode: bool = typer.Option(
        False,
        "--compare",
        help="Compare against last saved report and detect regressions",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        help="Force full verification, ignoring cached results",
    ),
    fix_sizes: bool = typer.Option(
        False,
        "--fix-sizes",
        help="Correct annotation SIZE from the binary-derived size: stale sizes "
        "(false SIZE_MISMATCH) and missing sizes (MISSING_SIZE stubs, which "
        "rebrew test refuses) are both backfilled into metadata",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    batch_dir: str | None = typer.Option(
        None, "--dir", help="Restrict to this subdirectory of reversed_dir"
    ),
    origin: str | None = typer.Option(None, "--origin", help="Restrict to one module (e.g. GAME)"),
    no_promote: bool = typer.Option(
        False,
        "--no-promote",
        help="Measure only: write NOTHING to rebrew-functions.toml (report + cache still save)",
    ),
    watch: bool = typer.Option(
        False, "--watch", help="Re-verify all sources whenever any .c file changes"
    ),
    nolib: bool = typer.Option(
        False,
        "--nolib",
        help="Exclude LIBRARY-marked functions from verification — the reccmp "
        "--nolib equivalent (gate on game code only; CRT/zlib sources are not "
        "counted or compiled)",
    ),
    prune_orphans: bool = typer.Option(
        False,
        "--prune-orphans",
        help="Delete metadata blocks whose VA has no source marker (orphans) "
        "before verifying — same scan as `rebrew orphans prune`",
    ),
    data: bool = typer.Option(
        False,
        "--data",
        help="Byte-compare built .data/.rdata against the reference, per metadata symbol",
    ),
    built: Path | None = typer.Option(
        None,
        "--built",
        help="Built binary for --data/--whole-binary/--text comparison (default: build/<target>)",
    ),
    raw_link: bool = typer.Option(
        False,
        "--raw-link",
        help="Ack that --built is the raw link, not a postlinked deliverable. "
        "Without it or a matching configured raw_link, --data suppresses DRIFT status write-backs (a raw link's "
        ".data divergence is postlink-supplied and would flip wrong statuses)",
    ),
    text: bool = typer.Option(
        False,
        "--text",
        help="Check .text function placement against markers (position-alignment gate)",
    ),
    whole_binary: bool = typer.Option(
        False,
        "--whole-binary",
        help="Compare built binary against the reference: sections, "
        "exports, imports, resources, headers",
    ),
    context: Path | None = typer.Option(
        None,
        "--context",
        help=(
            "C declarations to compile with every source (e.g. 'rebrew export context' output); "
            "each result records the context hash it was earned under"
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
) -> None:
    """Rebrew verification pipeline: compile each .c and verify bytes match."""
    all_targets = option_default(all_targets, False)
    # An OptionInfo reaching the jobs bound is truthy, so a direct callback
    # call from a test would feed min(jobs, fresh_count) an object.
    jobs = option_default(jobs, None)
    if all_targets:
        # Per-target artifacts would collide: one watch loop blocks the
        # sweep, one --output file is overwritten by every target, one
        # --built binary cannot be every target's build output.
        for clash, why in (
            (watch, "--watch"),
            (output_path, "--output"),
            (built, "--built"),
        ):
            if clash:
                error_exit(
                    f"--all-targets and {why} are mutually exclusive (each target needs its own)",
                    json_mode=json_output,
                )
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda n: main(
            file=file,
            root=root,
            jobs=jobs,
            output_path=None,
            summary=summary,
            diff_mode=diff_mode,
            full=full,
            fix_sizes=fix_sizes,
            dry_run=dry_run,
            batch_dir=batch_dir,
            origin=origin,
            no_promote=no_promote,
            watch=False,
            nolib=nolib,
            prune_orphans=prune_orphans,
            data=data,
            built=None,
            raw_link=raw_link,
            text=text,
            whole_binary=whole_binary,
            context=context,
            json_output=json_output,
            target=n,
            all_targets=False,
        ),
    ):
        return
    cfg = require_config(target=target, json_mode=json_output, root=root)
    if jobs is None:
        jobs = cfg.default_jobs

    # The configured raw linker output carries its acknowledgement even when
    # explicitly selected with --built. Other paths still require --raw-link.
    cfg_raw_link: Path | None = getattr(cfg, "raw_link", None)
    if cfg_raw_link is not None:
        if built is None:
            built = cfg_raw_link
        if built.resolve() == cfg_raw_link.resolve():
            raw_link = True

    # The optional compile context (see `rebrew test --context`).  It is a
    # compile input: merged into every compile unit and hashed into each
    # result; the cache identity records the digest, so a cached verdict is
    # only served to a run pinned to the same context.
    from rebrew.compile_context import load_compile_context

    try:
        compile_context = load_compile_context(context)
    except (OSError, UnicodeDecodeError) as exc:
        error_exit(f"--context {context}: {exc}", json_mode=json_output)

    if compile_context is not None and not json_output:
        console.print(
            "[dim]--context: verdicts are cached per context digest, so a "
            "changed context re-compiles them[/dim]"
        )

    # 16-bit NE compare walks per-function objects (OMF via omf16).  That
    # needs a profile registered with bits=16 whose object extension is
    # .obj/.o (MSVC 1.x, Borland 2.0/3.1, Watcom wcc, or a plugin that
    # declares the same).  Delphi 1.0 is bits=16 but emits a linked NE
    # (.exe), so it is not this loop.  A 32/64-bit profile short-circuits
    # too — otherwise every stub would burn the compile loop into
    # COMPILE_ERROR rows.  (The original skip predated the 16-bit profiles
    # and, later, named only msvc-1.52, which hid the other object pipelines.)
    from rebrew.binary_loader import is_ne

    if getattr(cfg, "target_binary", None) and is_ne(cfg.target_binary):
        from rebrew.toolchain import TOOLCHAINS
        from rebrew.toolchain_detect import bitness16_profiles

        profile = getattr(cfg, "compiler_profile", "") or "msvc-6.0"
        spec = TOOLCHAINS.get(profile)
        object_profiles = tuple(
            name for name in bitness16_profiles() if TOOLCHAINS[name].obj_ext in {".obj", ".o"}
        )
        emits_object = spec is not None and spec.bits == 16 and spec.obj_ext in {".obj", ".o"}
        if not emits_object:
            known = ", ".join(object_profiles) or "msvc-1.52"
            if spec is not None and spec.bits == 16:
                msg = (
                    "verify: 16-bit NE compare needs a per-function object; "
                    f"profile {profile!r} emits {spec.obj_ext!r}.  "
                    f"Object profiles: {known}.  "
                    "Skipping the compile/compare loop."
                )
            else:
                msg = (
                    "verify: 16-bit NE targets need a bits=16 profile that "
                    f"emits an object ({known}); "
                    f"current profile is {profile!r}.  Skipping the compile/compare loop."
                )
            if json_output:
                json_print({"skipped": True, "reason": msg, "arch": "x86_16"})
            else:
                console.print(f"[yellow]{untrusted_ident(msg)}[/yellow]")
            # A skip that verifies zero functions must not read as success —
            # CI would green on skipped work.  EXIT_ERROR (2): the project
            # cannot verify this target as configured (usage/config error),
            # not "code needs work" (1).
            raise typer.Exit(code=EXIT_ERROR)

    if watch:
        from rebrew.sources import iter_sources
        from rebrew.utils import watch_files

        def _sources() -> list[Path]:
            # Re-resolve every poll so a .c created DURING the session (e.g.
            # `rebrew skeleton` for a newly discovered function) is watched —
            # the old code captured the list once at startup and silently
            # stopped covering new files.
            return list(iter_sources(cfg.reversed_dir, cfg))

        def _retest() -> None:
            main(
                root=root,
                jobs=jobs,
                output_path=output_path,
                summary=summary,
                diff_mode=diff_mode,
                full=full,
                json_output=json_output,
                dry_run=dry_run,
                fix_sizes=fix_sizes,
                nolib=nolib,
                prune_orphans=prune_orphans,
                data=data,
                built=built,
                raw_link=raw_link,
                text=text,
                whole_binary=whole_binary,
                context=context,
                batch_dir=batch_dir,
                origin=origin,
                file=file,
                no_promote=no_promote,
                watch=False,  # never nest watch loops
                target=target,
            )

        watch_files(_sources(), _retest, path_provider=_sources)
        return

    previous_report: dict[str, Any] | None = None
    diff_warning: str | None = None
    if diff_mode:
        from rebrew.verify_cache import load_baseline

        previous_report, diff_warning = load_baseline(cfg)
        if diff_warning and not json_output:
            console.print(f"[yellow]warning:[/yellow] {untrusted_ident(diff_warning)}")

    orphans_pruned = 0
    if prune_orphans:
        from rebrew.orphans import OrphanInventoryError, find_orphans, split_prunable

        try:
            orphans = split_prunable(cfg, *find_orphans(cfg))
        except OrphanInventoryError as exc:
            error_exit(str(exc), json_mode=json_output)
        # --no-promote is measure-only for rebrew-functions.toml (same as
        # STATUS / SIZE): preview prune counts, never delete blocks.
        if dry_run or no_promote:
            orphans_pruned = len(orphans)
            if not json_output and orphans_pruned:
                console.print(
                    f"  [dim]Would prune[/dim] {orphans_pruned} orphaned metadata block(s)"
                )
        elif orphans:
            from rebrew.data_metadata import delete_data_entries_batch
            from rebrew.metadata import delete_entries_batch

            orphans_pruned = delete_entries_batch(
                cfg.metadata_dir,
                [
                    (o["module"], int(o["va"], 16))
                    for o in orphans
                    if o["store"] == "rebrew-functions.toml"
                ],
            )
            orphans_pruned += delete_data_entries_batch(
                cfg.metadata_dir,
                [
                    (o["module"], int(o["va"], 16))
                    for o in orphans
                    if o["store"] == "rebrew-data.toml"
                ],
            )
            if not json_output:
                console.print(
                    f"[green]Pruned:[/green] deleted {orphans_pruned} orphaned metadata block(s)"
                )

    data_report: dict[str, Any] | None = None
    if data:
        from rebrew.data_verify import (
            section_symbol_bytes,
            verify_data_bytes,
        )

        built_path = built or (cfg.root / "build" / cfg.target_name)
        if not built_path.exists():
            error_exit(
                f"{built_path} not found — build the project first (or pass --built <path>)",
                json_mode=json_output,
            )
        metadata_path = cfg.metadata_dir / "rebrew-data.toml"
        if not metadata_path.exists():
            error_exit(f"data metadata not found: {metadata_path}", json_mode=json_output)
        ref_bytes, ref_sizes = section_symbol_bytes(
            metadata_path=metadata_path,
            binary_path=cfg.target_binary,
            cfg=cfg,
        )
        built_bytes, built_sizes = section_symbol_bytes(
            metadata_path=metadata_path, binary_path=built_path, cfg=cfg
        )
        data_report = verify_data_bytes(
            metadata_path=metadata_path,
            expected=ref_bytes,
            actual=built_bytes,
            sizes={va: ref_sizes.get(va, built_sizes.get(va, 0)) for va in ref_sizes | built_sizes},
            cfg=cfg,
        )
        # A postlinked binary is not evidence.  Where a project's postlink step
        # copies whole sections from the reference (rebrew's own `data` fixer
        # does exactly that), every symbol in them matches by construction and
        # this check grades its own answer key.  A *perfect* score on a section
        # the build does not yet produce is the tell, so say so rather than
        # reporting a vacuous pass.
        _dsec = None
        try:
            from rebrew.binary_loader import load_binary

            _rb = load_binary(cfg.target_binary)
            _bb = load_binary(built_path)
            for _sname in (".data", ".rdata"):
                _rs, _bs = _rb.sections.get(_sname), _bb.sections.get(_sname)
                if _rs is None or _bs is None or _rs.raw_size != _bs.raw_size:
                    continue
                _r = bytes(_rb.data[_rs.file_offset : _rs.file_offset + _rs.raw_size])
                _b = bytes(_bb.data[_bs.file_offset : _bs.file_offset + _bs.raw_size])
                if _r == _b and _rs.raw_size:
                    _dsec = _sname
                    break
        except (OSError, ValueError, KeyError, AttributeError):
            _dsec = None
        if _dsec and not json_output:
            console.print(
                f"[yellow]warning:[/yellow] {untrusted_ident(built_path.name)}'s "
                f"{untrusted_ident(_dsec)} is byte-identical to the "
                f"reference. If the build postlinks by copying that section, these results are "
                f"tautological — point --built at the raw link instead."
            )
        if _dsec:
            data_report["section_copied_warning"] = _dsec
        if not dry_run:
            from rebrew.data_metadata import (
                load_data_metadata,
                set_data_fields_batch,
            )

            entries = load_data_metadata(cfg.metadata_dir)
            status_updates: list[dict[str, Any]] = []
            for row in data_report["results"]:
                module, va, status = row["module"], int(row["va"], 16), row["status"]
                entry = entries.get((module, va))
                if entry is not None:
                    status_updates.append(
                        {
                            "module": module,
                            "va": va,
                            "fields": {"status": status},
                            "verification": {
                                "status": status,
                                "writer": "verify",
                                "input_hash": row["input_hash"],
                                "definition_hash": row["definition_hash"],
                            },
                            # Provenance: this is the measurement, so the row
                            # names the tool and the time it was taken.  The
                            # coverage document's verify_results[] mirror is
                            # derived; this stamp is the canonical record.
                            "updated_by": "verify",
                        }
                    )
            if status_updates:
                if raw_link:
                    set_data_fields_batch(cfg.metadata_dir, status_updates)
                else:
                    # A raw link's .data divergence is postlink-supplied by
                    # design (AMBIGUOUS).  Without an explicit --raw-link ack we
                    # cannot tell DRIFT from the shipped deliverable, so writing
                    # DRIFT (or VERIFIED) statuses would corrupt the tool-owned
                    # rebrew-data.toml.  Suppress the write-back and say so.
                    data_report["raw_link_status_suppressed"] = True
                    if not json_output:
                        console.print(
                            "[yellow]warning:[/yellow] --built looks like a raw link; "
                            "status write-back suppressed (pass --raw-link to write DRIFT/VERIFIED)"
                        )
        if not json_output:
            from rebrew.present import ratio_bar

            console.print(
                f"data: {data_report['matched']} matched, "
                f"{len(data_report['mismatched'])} mismatched, "
                f"{len(data_report['missing'])} missing "
                f"({data_report['compared']} of {data_report['total']} symbols compared, "
                f"{data_report['coverage']:.0%} of symbols)"
            )
            if data_report["total"]:
                console.print(ratio_bar(data_report["compared"], data_report["total"]))
            if data_report["not_comparable"]:
                console.print(
                    f"  [dim]{data_report['not_comparable']} symbol(s) not comparable: no file bytes "
                    f"(zero-fill tail) or outside {'.data/.rdata'} — a zero above bounds only what "
                    f"was compared[/dim]"
                )
            for m in data_report["mismatched"][:_DISPLAY_ROWS_MAX]:
                console.print(
                    f"  [red]FAIL[/red] {untrusted_ident(m['name'])} ({m['va']}): "
                    f"first diff at +{m['first_diff']}"
                )
            for name in data_report["missing"][:_DISPLAY_ROWS_MAX]:
                console.print(
                    f"  [yellow]MISSING[/yellow] {untrusted_ident(name)} (no built bytes)"
                )

    text_report: dict[str, Any] | None = None
    if text:
        from rebrew.text_audit import audit_text, collect_actual_vas

        built_path = built or (cfg.root / "build" / cfg.target_name)
        if not built_path.exists():
            error_exit(
                f"{built_path} not found — build the project first (or pass --built <path>)",
                json_mode=json_output,
            )
        expected = expected_text_functions(cfg)
        try:
            actual = collect_actual_vas(cfg.root, built_path)
        except (RuntimeError, OSError, ValueError) as exc:
            error_exit(f"cannot inventory build objects: {exc}", json_mode=json_output)
        rows, n_ok, n_bad, n_missing = audit_text(expected, actual)
        text_report = {
            "functions": len(expected),
            "found": n_ok + n_bad,
            "correct": n_ok,
            "misplaced": n_bad,
            "missing": n_missing,
            "misplaced_list": [r for r in rows if r["status"] != "OK"][:_DISPLAY_ROWS_MAX],
        }
        if not json_output:
            console.print(
                f"text: {len(expected)} functions  correct-VA: {n_ok}  "
                f"misplaced: {n_bad}  missing: {n_missing}"
            )
            for r in text_report["misplaced_list"]:
                if r["status"] == "MISPLACED":
                    console.print(
                        f"  [red]MISPLACED[/red] {untrusted_ident(r['symbol']):32} "
                        f"exp {int(r['expected'], 16):#010x}  "
                        f"our {int(r['actual'], 16):#010x}  d {r['delta']:+#x}"
                    )
                else:
                    console.print(
                        f"  [yellow]MISSING[/yellow] {untrusted_ident(r['symbol']):32} "
                        f"exp {r['expected']}  MISSING from build"
                    )

    whole_report: dict[str, Any] | None = None
    if whole_binary:
        from rebrew.binary_gate import (
            check_layout_freshness,
            compare_snapshots,
            snapshot_binary,
        )

        built_path = built or (cfg.root / "build" / cfg.target_name)
        if not built_path.exists():
            error_exit(
                f"{built_path} not found — build the project first (or pass --built <path>)",
                json_mode=json_output,
            )
        whole_report = compare_snapshots(
            snapshot_binary(cfg.target_binary), snapshot_binary(built_path)
        )
        whole_report["layout"] = check_layout_freshness(
            cfg.root / "layout" / cfg.target_name, cfg.target_binary
        )
        whole_report["match"] = bool(whole_report["match"] and whole_report["layout"]["match"])
        if not json_output:
            if whole_report["match"]:
                console.print("[green]whole-binary: match[/green]")
            else:
                console.print("[red]whole-binary: drift[/red]")
                for err in whole_report["errors"]:
                    console.print(f"  [red]error[/red]: {untrusted_ident(err)}")
                for area in (
                    "file",
                    "sections",
                    "exports",
                    "imports",
                    "relocations",
                    "rsrc",
                    "headers",
                ):
                    part = whole_report[area]
                    if not part["match"]:
                        if area == "relocations":
                            console.print(
                                f"  [yellow]relocations[/yellow]: "
                                f"{len(part['missing'])} missing, {len(part['added'])} extra"
                            )
                            for side in ("expected", "actual"):
                                layout = part[f"{side}_layout"]
                                if layout:
                                    console.print(
                                        f"    {side}: {layout['block_bytes']} block bytes, "
                                        f"{layout['section_bytes']} section bytes, "
                                        f"{layout['directory_bytes']} directory bytes"
                                    )
                        else:
                            console.print(f"  [yellow]{area}[/yellow]: {part}")
                layout = whole_report["layout"]
                if not layout["match"]:
                    if layout["status"] == "unreadable":
                        console.print(
                            f"  [yellow]layout[/yellow]: {untrusted_ident(layout['error'])}"
                        )
                    else:
                        console.print(
                            f"  [yellow]layout[/yellow]: {untrusted_ident(layout['status'])} — "
                            "regenerate with rebrew build layout"
                        )

    batch = run_batch(
        cfg,
        full=full,
        json_output=json_output,
        jobs=jobs,
        dry_run=dry_run,
        batch_dir=batch_dir,
        origin_filter=origin,
        batch_file=file,
        nolib=nolib,
        no_promote=no_promote,
        context=compile_context,
    )
    _save_report(
        cfg,
        batch,
        data_report=data_report,
        text_report=text_report,
        whole_report=whole_report,
        previous_report=previous_report,
        diff_warning=diff_warning,
        diff_mode=diff_mode,
        summary=summary,
        output_path=output_path,
        dry_run=dry_run,
        no_promote=no_promote,
        json_output=json_output,
        compile_context=compile_context,
        fix_sizes=fix_sizes,
        orphans_pruned=orphans_pruned,
    )


@dataclass
class BatchResult:
    """Verdict bundle from the shared batch pipeline (no display, no files)."""

    entries: list[Annotation]
    total: int
    passed: int
    failed: int
    fail_details: list[tuple[Annotation, str]]
    results: list[dict[str, Any]]
    deferred: list[tuple[Annotation, str, int]]
    size_divergences: list[dict[str, Any]]
    missing_sizes: list[dict[str, Any]]
    duplicate_vas: list[dict[str, str]]
    library_excluded: int
    excluded_keys: set[str]
    cached_count: int
    #: Functions named by the discovery inventory (function_structure.json) —
    #: the denominator "how much is not yet reversed" for the report summary.
    inventory_count: int = 0
    #: VAs `rebrew status` counts as library code (see :func:`_library_vas`).
    library_vas: frozenset[int] = frozenset()
    #: Library ancestry is independent of a compiled or prebuilt provider.
    library_providers: list[dict[str, Any]] = field(default_factory=list)


def run_batch(
    cfg: Any,
    *,
    full: bool,
    json_output: bool,
    jobs: int,
    dry_run: bool = False,
    batch_dir: str | None = None,
    origin_filter: str | None = None,
    batch_file: str | None = None,
    nolib: bool = False,
    no_promote: bool = False,
    context: "CompileContext | None" = None,
) -> BatchResult:
    """Shared batch pipeline: scan → scope → compile → STATUS sync.

    prepare_entries → scope → run_verification → STATUS sync.  Returns the
    verdict bundle; each caller emits its own shape
    (``test --all`` prints a compact summary, ``verify`` saves the full
    report + baseline + gate).  *no_promote* (test's measure-only mode)
    previews STATUS writes while the results still compute.
    """
    (
        unique_entries,
        passed,
        failed,
        fail_details,
        results,
        cached_count,
        size_divergences,
        missing_sizes,
        duplicate_vas,
        name_to_va,
        inventory_count,
    ) = prepare_entries(cfg, full, json_output, context=context)
    library_vas = frozenset(_library_vas(cfg, unique_entries))
    from rebrew.function_providers import resolve_library_providers

    library_providers = resolve_library_providers(
        cfg, unique_entries, _library_header_rows(cfg), library_vas
    )
    (
        unique_entries,
        total,
        passed,
        failed,
        fail_details,
        results,
        cached_count,
        size_divergences,
        missing_sizes,
        library_excluded,
        excluded_keys,
    ) = scope_entries(
        unique_entries,
        (passed, failed, fail_details, results, cached_count),
        (size_divergences, missing_sizes),
        nolib=nolib,
        batch_dir=batch_dir,
        origin_filter=origin_filter,
        batch_file=batch_file,
        cfg=cfg,
        json_output=json_output,
    )

    cached_vas = {r["va"] for r in results}
    if unique_entries:
        v_passed, v_failed, v_fail_details, v_results, deferred = run_verification(
            [e for e in unique_entries if f"0x{e.va:08x}" not in cached_vas],
            cfg,
            jobs,
            total,
            cached_count,
            json_output,
            context,
            name_to_va=name_to_va,
        )
    else:
        v_passed, v_failed, v_fail_details, v_results, deferred = 0, 0, [], [], []
    passed += v_passed
    failed += v_failed
    fail_details.extend(v_fail_details)
    results.extend(v_results)

    # Promote/demote STATUS metadata unless --dry-run / --no-promote
    _apply_or_preview_status(deferred, cfg, dry_run or no_promote)

    results.sort(key=lambda r: r["va"])

    return BatchResult(
        entries=unique_entries,
        total=total,
        passed=passed,
        failed=failed,
        fail_details=fail_details,
        results=results,
        deferred=deferred,
        size_divergences=size_divergences,
        missing_sizes=missing_sizes,
        duplicate_vas=duplicate_vas,
        library_excluded=library_excluded,
        excluded_keys=excluded_keys,
        cached_count=cached_count,
        inventory_count=inventory_count,
        library_vas=library_vas,
        library_providers=library_providers,
    )


#: Report schema version.  2 = the ``test --all`` and ``verify`` JSON
#: payloads share one shape (same top-level keys, same result rows —
#: ``RESULT_FIELDS`` in verify_cache); the writer records which command
#: produced the report in ``provenance``.
REPORT_SCHEMA_VERSION = 2


def build_report(
    cfg: Any,
    results: list[dict[str, Any]],
    passed: int,
    failed: int,
    total: int,
    size_divergences: list[dict[str, Any]],
    missing_sizes: list[dict[str, Any]],
    duplicate_vas: list[dict[str, str]],
    *,
    dry_run: bool,
    compile_context: "CompileContext | None",
    provenance: str,
    library_excluded: int = 0,
    orphans_pruned: int = 0,
    library_passed: int = 0,
    library_total: int = 0,
    library_providers: list[dict[str, Any]] | None = None,
    data_report: dict[str, Any] | None = None,
    text_report: dict[str, Any] | None = None,
    whole_report: dict[str, Any] | None = None,
    inventory_count: int = 0,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble the batch report — one shape for ``verify`` and ``test --all``.

    Both commands emit the same top-level keys and the same result rows;
    verify-only extras (``data``/``text``/``whole_binary``) are null on the
    test path, and ``files``/``functions`` stay test-``--dry-run``-only
    (a candidate listing, not a verdict report).

    *now* overrides the report's ``timestamp`` (the default is the current
    UTC instant), so a report captured from a replayed run is byte-comparable
    with the run it replays instead of differing in that one field.
    """
    timestamp = (now or datetime.now(UTC)).isoformat()
    # Single-pass status counting instead of 7 separate iterations.
    _status_counts: dict[str, int] = {}
    for _r in results:
        _s = _r["status"]
        _status_counts[_s] = _status_counts.get(_s, 0) + 1
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "provenance": provenance,
        "timestamp": timestamp,
        "target": getattr(cfg, "target_name", ""),
        "binary": str(getattr(cfg, "target_binary", "")),
        # SHA-256 of the compile context every verdict in this run was
        # earned under; null when the run compiled without one.
        "context_hash": compile_context.sha256 if compile_context is not None else None,
        "dry_run": dry_run,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "exact": _status_counts.get("EXACT", 0),
            "reloc": _status_counts.get("RELOC", 0),
            "stub": _status_counts.get("STUB", 0),
            "matching": _status_counts.get("NEAR_MATCHING", 0),
            "size_mismatch": _status_counts.get("SIZE_MISMATCH", 0),
            "compile_error": _status_counts.get("COMPILE_ERROR", 0),
            "missing_file": _status_counts.get("MISSING_FILE", 0),
            "byte_matched": _status_counts.get("EXACT", 0) + _status_counts.get("RELOC", 0),
            # Passes on functions `rebrew status` counts as library code, not progress.
            "library_passed": library_passed,
            "library_total": library_total,
            "library_providers": {
                kind: sum(row["provider"] == kind for row in (library_providers or []))
                for kind in ("compiled", "prebuilt", "unresolved")
            },
            "library_excluded": library_excluded,
            "orphans_pruned": orphans_pruned,
            # Not-yet-reversed denominator: functions the inventory names but
            # no reversed source covers yet (0 when no inventory file exists).
            "inventory_count": inventory_count,
        },
        "size_divergences": size_divergences,
        "missing_sizes": missing_sizes,
        "duplicate_vas": duplicate_vas,
        "results": results,
        "libraries": library_providers or [],
        "data": data_report,
        "text": text_report,
        "whole_binary": whole_report,
    }


def _save_report(
    cfg: Any,
    batch: BatchResult,
    *,
    data_report: dict[str, Any] | None,
    text_report: dict[str, Any] | None,
    whole_report: dict[str, Any] | None,
    previous_report: dict[str, Any] | None,
    diff_warning: str | None,
    diff_mode: bool,
    summary: bool,
    output_path: str | None,
    dry_run: bool,
    json_output: bool,
    compile_context: "CompileContext | None",
    fix_sizes: bool,
    orphans_pruned: int,
    no_promote: bool = False,
    now: datetime | None = None,
) -> None:
    """Assemble the verify report, save cache + baseline, print, gate."""
    results = batch.results
    library_results = [r for r in results if int(r["va"], 16) in batch.library_vas]
    library_total = len(library_results)
    library_passed = sum(1 for r in library_results if r["passed"])
    passed, failed, total = batch.passed, batch.failed, batch.total
    size_divergences, missing_sizes = batch.size_divergences, batch.missing_sizes
    report = build_report(
        cfg,
        results,
        passed,
        failed,
        total,
        size_divergences,
        missing_sizes,
        batch.duplicate_vas,
        dry_run=dry_run,
        compile_context=compile_context,
        provenance="verify",
        library_excluded=batch.library_excluded,
        orphans_pruned=orphans_pruned,
        data_report=data_report,
        text_report=text_report,
        whole_report=whole_report,
        inventory_count=batch.inventory_count,
        library_passed=library_passed,
        library_total=library_total,
        library_providers=batch.library_providers,
        now=now,
    )

    # Warn only on ACTIONABLE divergences.  An EXACT/RELOC annotation
    # size is byte-match evidence that `_partition_size_fixes` deliberately
    # keeps (rewriting it demotes a real match -- measured on guild-rebrew:
    # one `--fix-sizes` run took byte-matched 264 -> 252).  A fully-protected
    # set is the intended state, not a defect, so warning on it fired every run
    # with nothing to do.  The kept count is mentioned only when some
    # divergences ARE actionable, so the number matches what `--fix-sizes`
    # would touch.
    _appl_div, _prot_div = _partition_size_fixes(size_divergences)
    if _appl_div and not json_output:
        _kept = f" ({len(_prot_div)} kept as EXACT/RELOC evidence)" if _prot_div else ""
        console.print(
            f"[yellow]warning:[/yellow] {len(_appl_div)} function(s) have annotation "
            f"SIZE differing from the binary-derived size{_kept}; run with --json for details"
        )

    sizes_fixed = 0
    if fix_sizes and (size_divergences or missing_sizes):
        all_size_fixes = size_divergences + missing_sizes
        # Never rewrite a size that is already producing a byte match.
        all_size_fixes, protected_fixes = _partition_size_fixes(all_size_fixes)
        report["sizes_protected"] = protected_fixes
        if protected_fixes and not json_output:
            console.print(
                f"[yellow]Kept {len(protected_fixes)} annotation size(s): already "
                f"EXACT/RELOC at that size, so the annotation is evidence and the "
                f"canonical size is the unreliable side.[/yellow]"
            )
            for d in protected_fixes:
                console.print(
                    f"  [dim]kept {d['va']} SIZE {d['annotation_size']} "
                    f"(canonical {d['binary_size']}) {untrusted_ident(d['name'])}[/dim]"
                )
        # --no-promote writes nothing to rebrew-functions.toml (SIZE included).
        preview_sizes = dry_run or no_promote
        sizes_fixed = _apply_size_fixes(cfg, all_size_fixes, preview_sizes)
        if not json_output:
            for d in all_size_fixes:
                action = "Would fix" if preview_sizes else "Fixed"
                console.print(
                    f"  {action} {d['va']} SIZE {d['annotation_size']} -> "
                    f"{d['binary_size']} ({untrusted_ident(d['name'])})"
                )
            if dry_run:
                console.print(
                    f"[dim]{len(all_size_fixes)} size fix(es) — re-run without "
                    "--dry-run to write[/dim]"
                )
            elif no_promote and all_size_fixes:
                console.print(
                    f"[dim]{len(all_size_fixes)} size fix(es) previewed — "
                    "re-run without --no-promote to write[/dim]"
                )
        report["sizes_fixed"] = sizes_fixed
        if not preview_sizes and sizes_fixed:
            # The report was assembled from the pre-fix scan; strip the
            # just-fixed VAs so the same-run payload is not self-contradictory
            # ("sizes_fixed: N" next to the same entries still listed as
            # missing/stale).  Their cached results reflect the pre-fix state
            # and re-evaluate on the next run.
            fixed_vas = {d["va"] for d in all_size_fixes}
            size_divergences = [d for d in size_divergences if d["va"] not in fixed_vas]
            missing_sizes = [d for d in missing_sizes if d["va"] not in fixed_vas]
            report["size_divergences"] = size_divergences
            report["missing_sizes"] = missing_sizes

    # F9: a failed --compare gate must not record state — the baseline is
    # preserved below, and the verify cache write below is skipped too so a CI
    # failure leaves no new entries behind.
    diff_result: dict[str, Any] | None = None
    if diff_mode and previous_report is not None:
        # A scope flag leaves the baseline whole-project, so without this the
        # out-of-scope entries read as `removed`.
        scope = {str(r.get("va")) for r in results} or None
        diff_result = diff_reports(previous_report, report, scope=scope)
    data_failed = 0
    if data_report is not None:
        data_failed = len(data_report.get("mismatched") or ()) + len(
            data_report.get("missing") or ()
        )
    whole_failed = bool(whole_report is not None and not whole_report.get("match"))
    text_misplaced = text_report["misplaced"] if text_report else 0
    gate_failed = _gate_fails(
        diff_result,
        failed,
        text_misplaced=text_misplaced,
        data_failed=data_failed,
        whole_failed=whole_failed,
    )

    # Context-scoped runs save like bare runs: each entry carries the
    # context digest it was earned under, and the hit check serves a row
    # only when the supplied context matches exactly (prepare_entries).
    # --no-promote still saves the cache/baseline/report; it only skips
    # rebrew-functions.toml (STATUS, SIZE, orphan prune).
    if not dry_run and not (diff_mode and gate_failed):
        cache_path = cache_path_for(cfg)
        try:
            save_verify_cache(
                cache_path,
                cfg,
                results,
                batch.entries,
                preserve_keys=batch.excluded_keys,
            )
        except (OSError, TypeError) as exc:
            # Warn on stderr regardless of json mode — silent cache-I/O
            # failures degrade performance invisibly.
            log.warning("Could not write verify cache to %s: %s", cache_path, exc)

    # The --compare baseline lives in .rebrew next to the cache (both are
    # local, gitignored run state — db/verify_results.json was never
    # committed either).  A regressed run must not overwrite the last good
    # baseline, or the gate would self-heal on the next invocation:
    # --compare advances it only on a passing gate, plain verify always.
    # A scope-filtered run never writes it: the next full run would then
    # compare the whole corpus against a one-file baseline and report every
    # out-of-scope function as `new`.  (The current run's own diff is
    # scope-filtered above, so it reports no out-of-scope `removed` rows.)
    if not dry_run and not (diff_mode and gate_failed) and not batch.excluded_keys:
        from rebrew.verify_cache import save_baseline

        try:
            save_baseline(cfg, report)
        except (OSError, TypeError, ValueError) as exc:
            # Baseline I/O must not abort after a successful verify — the
            # report was already earned; losing the baseline only weakens
            # the next --compare gate.
            log.warning("Could not write verify baseline: %s", exc)

    # `-o` is an explicit export of the report just computed, independent of
    # the baseline: it was nested in the baseline guard above, so every
    # scope-filtered run (`--dir`, `--nolib`, a positional FILE) and a
    # failing --compare gate silently wrote no file and printed nothing.
    if not dry_run and output_path:
        out_file = Path(output_path)
        try:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(out_file, json.dumps(report, indent=2), encoding="utf-8")
        except OSError as exc:
            log.warning("Could not write verify report to %s: %s", out_file, exc)
        else:
            if not json_output:
                console.print(f"Report written to {untrusted_ident(out_file)}")

    if json_output:
        if diff_mode:
            payload: dict[str, Any] = {"report": report, "diff": diff_result}
            if diff_warning:
                payload["warning"] = diff_warning
            json_print(payload)
        else:
            json_print(report)

        _raise_if_regression(gate_failed)
        return

    merge_count = 0
    under = [
        d
        for d in size_divergences
        if d.get("annotation_size")
        and d.get("binary_size")
        and d["annotation_size"] < d["binary_size"]
    ]
    if under:
        try:
            _bin = Path(cfg.target_binary).read_bytes()
        except OSError:
            _bin = b""
        if _bin:
            _base, _secs = _pe_sections_for_merge_check(_bin)
            if _secs:
                for d in under:
                    try:
                        _va = int(str(d["va"]), 16)
                    except (ValueError, TypeError):
                        continue
                    for _sva, _soff, _sraw in _secs:
                        if _sva <= _va < _sva + _sraw:
                            if _looks_like_inventory_merge(
                                _bin,
                                _va,
                                _base,
                                _soff + (_va - _sva),
                                d["annotation_size"],
                                d["binary_size"],
                            ):
                                merge_count += 1
                            break

    _print_results(
        results,
        batch.fail_details,
        diff_result,
        diff_warning,
        diff_mode,
        summary,
        total,
        passed,
        failed,
        library_passed=library_passed,
        library_total=library_total,
        size_divergences=size_divergences,
        merge_count=merge_count,
        library_providers=batch.library_providers,
    )

    _raise_if_regression(gate_failed)


def _apply_size_fixes(cfg: Any, size_divergences: list[dict[str, Any]], dry_run: bool) -> int:
    """Correct annotation SIZE from the binary-derived size for each divergence.

    Returns the number of sizes written (0 in dry-run).  The binary-derived
    canonical size comes from the function registry (disassembly-derived),
    so a stale annotation size (a false SIZE_MISMATCH / truncated byte
    extraction) is replaced with the real one.
    """
    from rebrew.metadata import set_fields_batch

    updates: list[dict[str, Any]] = []
    for d in size_divergences:
        va = int(d["va"], 16)
        module = d.get("module") or cfg.marker
        updates.append({"module": module, "va": va, "fields": {"size": d["binary_size"]}})
    if not dry_run and updates:
        # One TOML read-modify-write for the whole batch (per-entry writes
        # were N full rewrites).
        set_fields_batch(cfg.metadata_dir, updates)
        return len(updates)
    return 0


def _gate_fails(
    diff_result: dict[str, Any] | None,
    failed: int,
    *,
    text_misplaced: int = 0,
    data_failed: int = 0,
    whole_failed: bool = False,
) -> bool:
    """True when the CI regression gate must fail this run.

    With a baseline (*diff_result*), only regressions and newly-broken
    entries fail the run — pre-existing failures are the baseline's
    business.  Without a baseline, any failed function fails the run.
    A misplaced ``--text`` function fails the gate in both modes: placement
    drift means the link no longer reproduces the reference layout, which no
    byte-level verdict covers.  The same applies to ``--data`` symbol
    mismatches/missing entries and a failed ``--whole-binary`` compare —
    auxiliary gates that were requested must fail the command when they
    detect drift (exit-code contract: "Failures or regressions detected").
    """
    if text_misplaced or data_failed or whole_failed:
        return True
    if diff_result is not None:
        if diff_result["regressions"]:
            return True
        # Unknown statuses rank worse than any known failure (fail closed):
        # they never read as "no worse than FAIL".
        unknown_rank = max(_STATUS_RANK.values()) + 1
        return any(
            _STATUS_RANK.get(str(i.get("status", "FAIL")), unknown_rank)
            >= _STATUS_RANK["COMPILE_ERROR"]
            for i in diff_result.get("new", [])
        )
    return failed > 0


def _raise_if_regression(gate_failed: bool) -> None:
    """Raise ``typer.Exit(EXIT_MISMATCH)`` per the CI regression gate.

    Takes the verdict :func:`_gate_fails` already produced for this run, so
    the gate is evaluated once rather than re-scanned at every raise site.
    """
    if gate_failed:
        raise typer.Exit(code=EXIT_MISMATCH)


# ---------------------------------------------------------------------------
# Phase helpers
# ---------------------------------------------------------------------------


#: Functions start on a 16-byte boundary, so the canonical size is the
#: annotation length rounded up to the next multiple of this.
_FUNCTION_ALIGNMENT = 16


def _alignment_padding(ann_size: int, canonical: int) -> bool:
    """Whether the canonical size is just the annotation rounded up to the
    next 16-byte function-alignment boundary (functions start 16-aligned, so
    the function-list extent includes the trailing pad). The annotation is the
    true code length and the two agree on the code; this is not a divergence."""
    if ann_size >= canonical:
        return False  # only a trailing pad counts, never a shorter annotation
    pad = canonical - ann_size
    return pad < _FUNCTION_ALIGNMENT and canonical % _FUNCTION_ALIGNMENT == 0


def _skip_validated_overcount(ann_size: int, canonical: int, status: str | None) -> bool:
    """Whether an over-counted annotation (ann > canonical) is proven correct.

    A function whose bytes EXACT/RELOC-matched — or that earned PROVEN — at
    the annotation size has exercised exactly that many real bytes: the
    canonical side (a Ghidra fragment or a stale list entry) is the
    unreliable one, and flagging it as an annotation bug is noise.
    Under-counts (ann < canonical) are never skipped: a truncated annotation
    can false-EXACT on a prefix.  PROVEN is included for the same reason
    :func:`_partition_size_fixes` protects it.
    """
    return ann_size > canonical and status in EARNED_STATUSES


def _partition_size_fixes(
    fixes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split size fixes into ``(appliable, protected)``.

    A function that already reports EXACT/RELOC has compiled and compared
    byte-for-byte at its annotated size: that size is *evidence*, and the
    canonical side — heuristic discovery, which merges adjacent functions when
    the only boundary is ``ret`` plus padding, and which counts trailing jump
    tables the body excludes — is the unreliable one.  Rewriting those sizes
    demotes real matches: on guild-rebrew a single ``--fix-sizes`` run rewrote
    13 sizes and dropped byte-matched functions from 264 to 252.

    ``_skip_validated_overcount`` already protects over-counts, but an
    *under*-count on a byte-matched entry is exactly the jump-table case and
    was being applied automatically.  Protect both directions and report them
    instead.

    PROVEN counts here too.  It is not a byte match, but earning it requires
    compiling and comparing at the annotated size, and the under-count case is
    precisely a body size the canonical figure inflates with trailing jump
    tables: ``vfs_OpenStream`` is body 667 against a canonical 704 that
    includes a 5-entry jump table and a 13-byte case map, and 667 is the
    correct value.
    """
    protected = [f for f in fixes if str(f.get("status", "")).upper() in EARNED_STATUSES]
    if not protected:
        return fixes, []
    protected_vas = {f["va"] for f in protected}
    return [f for f in fixes if f["va"] not in protected_vas], protected


def _size_divergence_action(ann_size: int, canonical: int, status: str | None) -> str:
    """Classify an annotation-vs-canonical size difference.

    Returns 'skip' (padding or a validated over-count), 'warn', or 'ok'."""
    if canonical <= 0 or ann_size <= 0 or abs(canonical - ann_size) <= 1:
        return "ok"
    if _alignment_padding(ann_size, canonical):
        return "skip"
    if _skip_validated_overcount(ann_size, canonical, status):
        return "skip"
    return "warn"


def patch_cache_from_results(cfg: Any, v_results: list[dict[str, Any]]) -> None:
    """Sync the verify cache from batch results (one read + one write).

    Used by ``rebrew test --all`` so promoted statuses show up in status/todo
    immediately.  A worker crash (INTERNAL_ERROR) is not a verdict and is
    never patched.
    """
    from rebrew.verify_cache import patch_verify_cache_entries

    patches: list[dict[str, Any]] = []
    for r in v_results:
        try:
            va_int = int(r["va"], 16)
        except (ValueError, TypeError, KeyError):
            continue
        if r.get("status") == "INTERNAL_ERROR":
            continue
        # No byte counts: the row carries only a percent, and a percent-scale
        # total would fill a missing byte delta with 100 - percent (todo.py's
        # ROI thresholds read it as bytes).  An absent percent is left out
        # rather than written as 0.0: the writer keeps the last real
        # measurement when a patch carries neither counts nor percent.
        patch: dict[str, Any] = {
            "va": va_int,
            "status": r.get("status", ""),
            "delta": r.get("delta"),
            # Cache identity: the row's own context digest, so a patch never
            # leaves the entry pointing at the context of an earlier run.
            "context_hash": r.get("context_hash"),
        }
        pct = r.get("match_percent")
        if pct is not None:
            patch["match_percent"] = pct
        patches.append(patch)
    patch_verify_cache_entries(cfg, patches)


def scope_entries(
    unique_entries: list[Annotation],
    cached: tuple[int, int, list[tuple[Annotation, str]], list[dict[str, Any]], int],
    size_audits: tuple[list[dict[str, Any]], list[dict[str, Any]]],
    *,
    nolib: bool = False,
    batch_dir: str | None = None,
    origin_filter: str | None = None,
    batch_file: str | None = None,
    cfg: Any,
    json_output: bool = False,
) -> tuple[
    list[Annotation],
    int,
    int,
    int,
    list[tuple[Annotation, str]],
    list[dict[str, Any]],
    int,
    list[dict[str, Any]],
    list[dict[str, Any]],
    int,
    set[str],
]:
    """Restrict the batch work list to --nolib/--dir/--origin scope.

    Shared by ``rebrew verify`` and ``rebrew test --all`` so both batch
    paths filter identically.  *batch_dir* resolves against
    ``cfg.reversed_dir`` with real path containment (a raw string prefix
    also matched sibling directories).  *origin_filter* matches the
    annotation's module — ORIGIN is derivable from the FUNCTION-marker
    module, which is also what test's old ``origin`` attribute check meant
    (it matched nothing since Annotation has no such field).

    Returns ``(entries, total, passed, failed, fail_details, results,
    cached_count, size_divergences, missing_sizes, library_excluded,
    excluded_keys)`` — the filtered work list plus the filtered
    pre-compile state.  Cached rows for excluded entries stay in the cache
    file; only the run scope shrinks.
    """
    passed, failed, fail_details, results, cached_count = cached
    size_divergences, missing_sizes = size_audits
    library_excluded = 0
    excluded_keys: set[str] = set()
    all_keys = {f"0x{e.va:08x}" for e in unique_entries}
    # --nolib (reccmp equivalent): drop LIBRARY-marked functions entirely —
    # from the work list, the cached results already counted, and the size
    # audit — so the gate reflects game code only.  Excluded functions are
    # neither compiled nor counted, exactly like reccmp's --nolib filter.
    if nolib:
        lib_vas = _library_vas(cfg, unique_entries) & {e.va for e in unique_entries}
        if lib_vas:
            unique_entries = [e for e in unique_entries if e.va not in lib_vas]
            library_excluded = len(lib_vas)
    if batch_dir:
        raw_dir = Path(batch_dir)
        if raw_dir.is_absolute():
            batch_root = raw_dir.resolve()
        else:
            # Project-relative first (src/shared), then relative to the
            # reversed dir (Units/vfs) — shared sources live outside
            # reversed_dir, so a reversed-only resolution can never scope
            # them.
            root_hit = (Path(cfg.root) / raw_dir).resolve()
            batch_root = (
                root_hit if root_hit.is_dir() else (Path(cfg.reversed_dir) / raw_dir).resolve()
            )
        # Path-aware containment: a raw string prefix also matched sibling
        # directories (`game_dll_extra` under `game_dll`) and broke on a root
        # with `..` in it; resolve both sides and compare real paths.
        unique_entries = [
            e
            for e in unique_entries
            if (Path(cfg.reversed_dir) / e.filepath).resolve().is_relative_to(batch_root)
        ]
    if origin_filter:
        want = preset_module_key(origin_filter)
        unique_entries = [e for e in unique_entries if preset_module_key(e.module or "") == want]
    if batch_file:
        raw = Path(batch_file)
        if raw.is_absolute():
            target = raw.resolve()
        else:
            # Project-relative first (src/x/foo.c), then relative to the
            # reversed dir (foo.c) — whichever names an existing file.
            root_hit = (Path(cfg.root) / raw).resolve()
            target = root_hit if root_hit.is_file() else (Path(cfg.reversed_dir) / raw).resolve()
        unique_entries = [
            e for e in unique_entries if (Path(cfg.reversed_dir) / e.filepath).resolve() == target
        ]
    if not unique_entries and (batch_dir or origin_filter or batch_file):
        # A scope filter that matched nothing (a mistyped --dir or --origin)
        # would otherwise verify zero functions and exit green.  --nolib is
        # not in this set: emptying the work list that way is the point.
        from rebrew.cli import error_exit

        scope = batch_file or batch_dir or origin_filter
        error_exit(
            f"no annotations found for {scope} — empty scope is not a green gate",
            json_mode=json_output,
        )
    if library_excluded or batch_dir or origin_filter or batch_file:
        keep = {f"0x{e.va:08x}" for e in unique_entries}
        # Every scope flag narrows the run, so every dropped entry must be
        # preserved in the cache file: --nolib, --dir, --origin and the
        # positional FILE all erase the rows they exclude otherwise, and the
        # next unscoped run recompiles the whole corpus.
        excluded_keys = all_keys - keep
        results = [r for r in results if r.get("va") in keep]
        # Key on va, like the result/size filters beside it: a list scan with
        # dataclass equality is O(failures x entries) field-by-field.
        fail_details = [(e, m) for e, m in fail_details if f"0x{e.va:08x}" in keep]
        size_divergences = [d for d in size_divergences if d.get("va") in keep]
        missing_sizes = [d for d in missing_sizes if d.get("va") in keep]
        # Recompute the pre-compile counts from the filtered structures —
        # the cached rows that were dropped are no longer "results".
        passed = sum(1 for r in results if r.get("passed", False))
        failed = len(fail_details)
        cached_count = len(results)
        if not json_output:
            scope = (
                f"--nolib excluded {library_excluded}"
                if nolib and library_excluded
                else f"scoped to {len(unique_entries)}"
            )
            console.print(f"[dim]{scope} function(s)[/dim]")
    total = len(unique_entries)
    return (
        unique_entries,
        total,
        passed,
        failed,
        fail_details,
        results,
        cached_count,
        size_divergences,
        missing_sizes,
        library_excluded,
        excluded_keys,
    )


def _inventory_count(cfg: ProjectConfig, reversed_dir: Path) -> int:
    """Number of functions in the discovery inventory (0 when unavailable).

    Per-target override aware (ADR: ``inventory_file``); a missing or
    corrupt file is a 0, not a scan failure — the count is reporting
    context, not a gate.
    """
    import json as _json

    path = inventory_path_for(reversed_dir, cfg)
    try:
        data = _json.loads(read_json_text(path))
        return len(data) if isinstance(data, list) else 0
    except (OSError, _json.JSONDecodeError, ValueError):
        return 0


def _library_header_rows(cfg: Any) -> dict[int, dict[str, str]]:
    """Rows the ``library_*.h`` headers of this target contribute, cached.

    Keyed on the header paths and their ``(mtime_ns, size, ino)``, so an edited
    header re-parses and ``verify --watch`` still sees the change while two
    calls in one run (the library set and the ``--nolib`` filter) parse the
    tree once.  The size and inode are what catch a same-size rename-over
    inside one mtime tick (an editor's atomic save, a ``cp -p`` restore, a
    coarse-timestamp filesystem), which mtime alone cannot see; same triple
    every other per-file memo in the tree carries.

    The parse runs outside the lock and the publish inside it, so two
    workers racing on the same key both parse but only one entry survives.
    """
    from rebrew.annotation import parse_library_header
    from rebrew.sources import iter_library_headers

    marker = preset_module_key(module_marker(cfg))
    headers = list(iter_library_headers(cfg.reversed_dir, cfg))
    key = (marker, tuple((str(h), *_stat_identity(h)) for h in headers))
    with _LIBRARY_HEADER_CACHE_LOCK:
        cached = _LIBRARY_HEADER_CACHE.get(key)
        if cached is not None:
            # Promote inside the lock, like the insert below.  Releasing it
            # first lets a peer's eviction drop the key, and the orphaned
            # move_to_end then raises KeyError instead of returning the rows.
            _LIBRARY_HEADER_CACHE.move_to_end(key)
    if cached is not None:
        return cached
    rows: dict[int, dict[str, str]] = {}
    for header in headers:
        for e in parse_library_header(header, metadata_dir=cfg.metadata_dir):
            if preset_module_key(e.module or "") in ("", marker):
                rows[e.va] = {
                    "marker_type": e.marker_type or "LIBRARY",
                    "module": e.module or "",
                    "name": e.name,
                    "symbol": e.symbol,
                }
    # Bounded LRU, not clear-on-miss: ``verify --all-targets`` walks one
    # target per iteration in this process, and a single slot re-parsed the
    # whole ``library_*.h`` tree on every target's turn.
    with _LIBRARY_HEADER_CACHE_LOCK:
        _LIBRARY_HEADER_CACHE[key] = rows
        _LIBRARY_HEADER_CACHE.move_to_end(key)
        while len(_LIBRARY_HEADER_CACHE) > _LIBRARY_HEADER_CACHE_MAX:
            del _LIBRARY_HEADER_CACHE[next(iter(_LIBRARY_HEADER_CACHE))]
    return rows


_LIBRARY_HEADER_CACHE: OrderedDict[Any, dict[int, dict[str, str]]] = OrderedDict()
_LIBRARY_HEADER_CACHE_MAX = 8
# Guarded: verify -j N resolves library VAs from worker threads.
_LIBRARY_HEADER_CACHE_LOCK = threading.Lock()


def _stat_identity(path: Path) -> tuple[int, int, int]:
    """``(mtime_ns, size, ino)`` for *path*, all 0 when it is unreadable."""
    try:
        st = path.stat()
    except OSError:
        return (0, 0, 0)
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def _library_vas(cfg: Any, entries: list[Annotation]) -> set[int]:
    """VAs of this target that are library code, by `rebrew status`'s rule.

    A compiled FUNCTION entry is library code when a ``library_*.h`` header of
    this target attributes its VA (the header row wins, as in
    :func:`rebrew.naming.load_data`) or its module is in ``external_libs``
    (:func:`rebrew.naming.external_vas`).  Headers of other targets are ignored.
    """
    from rebrew.naming import external_vas

    rows = {
        e.va: {
            "marker_type": getattr(e, "marker_type", "") or "",
            "module": getattr(e, "module", "") or "",
        }
        for e in entries
    }
    rows.update(_library_header_rows(cfg))
    return external_vas(rows, getattr(cfg, "external_libs", None))


def prepare_entries(
    cfg: ProjectConfig,
    full: bool,
    json_output: bool,
    context: "CompileContext | None" = None,
) -> tuple[
    list[Annotation],
    int,
    int,
    list[tuple[Annotation, str]],
    list[dict[str, Any]],
    int,
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, str]],
    dict[str, int],
    int,
]:
    """Scan reversed_dir, deduplicate entries, and check the verify cache.

    Returns (unique_entries, passed, failed, fail_details, results,
    cached_count, size_divergences, missing_sizes, duplicate_vas, name_to_va,
    inventory_count).  ``inventory_count`` is the number of functions named
    by the discovery inventory (0 when the file is missing/corrupt) — the
    report summary's denominator for not-yet-reversed functions.
    ``duplicate_vas`` names the dropped sources: ``{"va", "kept", "dropped"}``
    per duplicate-VA annotation (first source wins, the rest never compile).
    ``name_to_va`` is the symbol catalog built from the same scan (plus
    globals/metadata) so ``run_verification`` does not re-parse the tree.

    With *context* set the cache is still consulted, but only entries whose
    stored ``context_hash`` equals the supplied digest hit: a cached verdict
    was earned under one specific set of declarations, and a changed digest
    is a different compile input, not a still-valid match.
    """
    reversed_dir = cfg.reversed_dir
    ghidra_json_path = inventory_path_for(reversed_dir, cfg)

    console.print(f"Scanning {untrusted_ident(reversed_dir)}...")
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    # Build the reloc-validation catalog from this scan — avoids a second
    # full parse_c_file_multi walk inside run_verification.
    from rebrew.coff_reloc import CatalogScanError, build_name_to_va

    try:
        name_to_va = build_name_to_va(cfg, annotations=entries)
    except CatalogScanError as exc:
        error_exit(str(exc), json_mode=json_output)
    funcs = cached_function_list(cfg)
    registry = build_function_registry(funcs, cfg, ghidra_json_path, cfg.target_binary)

    unique_vas = {e.va for e in entries}
    ghidra_count, list_count, both_count, thunk_count = count_detection_sources(registry)
    console.print(
        f"Found {len(entries)} annotations ({len(unique_vas)} unique VAs); "
        f"inventory: {len(registry)} functions "
        f"(list: {list_count}, ghidra: {ghidra_count}, both: {both_count}, "
        f"thunks: {thunk_count})"
    )

    if not cfg.target_binary.exists():
        error_exit(f"{cfg.target_binary} not found", json_mode=json_output)

    # Filter out non-compilable annotations and deduplicate by VA
    va_to_kept: dict[int, Annotation] = {}
    unique_entries: list[Annotation] = []
    data_count = 0
    library_header_count = 0
    duplicate_vas: list[tuple[int, str, str]] = []
    for entry in sorted(entries, key=lambda x: x.va):
        if getattr(entry, "is_data", False):
            data_count += 1
            continue
        fp = getattr(entry, "filepath", "")
        if fp and fp.endswith(".h"):
            library_header_count += 1
            continue
        kept = va_to_kept.get(entry.va)
        if kept is None:
            va_to_kept[entry.va] = entry
            unique_entries.append(entry)
        else:
            # Duplicate VA: the first source wins and the rest are DROPPED
            # from this run (they are never compiled).  Say so loudly — a
            # silent keep-first hides a stale annotation in CI.
            duplicate_vas.append(
                (entry.va, getattr(kept, "filepath", ""), getattr(entry, "filepath", ""))
            )
    if duplicate_vas:
        for va, kept_fp, dropped_fp in duplicate_vas:
            msg = (
                f"duplicate VA 0x{va:08x}: keeping {kept_fp or '<unknown>'}; "
                f"dropping {dropped_fp or '<unknown>'} from this run"
            )
            log.warning("prepare_entries: %s", msg)
            console.print(f"[yellow]warning:[/yellow] {untrusted_ident(msg)}")
        if json_output:
            console.print(
                "[yellow]warning:[/yellow] "
                f"{len(duplicate_vas)} duplicate VA(s) dropped "
                "(see 'duplicate_vas' in the report JSON)"
            )
    if data_count and not json_output:
        console.print(f"Skipped {data_count} DATA/GLOBAL entries (not compilable)")
    if library_header_count and not json_output:
        console.print(f"Skipped {library_header_count} library declarations (no source binding)")

    passed = 0
    failed = 0
    fail_details: list[tuple[Annotation, str]] = []
    results: list[dict[str, Any]] = []

    cache_path = cache_path_for(cfg)
    verify_cache_obj = None if full else load_verify_cache(cache_path, cfg)
    entries_cache: dict[str, VerifyCacheEntry] = (
        verify_cache_obj.entries if verify_cache_obj else {}
    )
    cached_count = 0

    for entry in unique_entries:
        va_key = f"0x{entry.va:08x}"
        cached_entry = entries_cache.get(va_key)
        if cached_entry is None:
            continue

        # The cache holds byte verdicts only.  A PROVEN row is not one (an
        # older rebrew cached it as a pass); re-verify it once.
        if cached_entry.status == "PROVEN":
            continue

        if cached_entry.filepath != getattr(entry, "filepath", ""):
            continue
        if cached_entry.symbol != _entry_symbol(entry):
            continue

        # Same VA re-annotated under another module is a different function
        # for STATUS purposes — a stale verdict earned under the old module
        # must not be served (legacy rows without a module still hit).
        # preset_module_key, like every other module comparison in this file:
        # byte equality made a spelling difference re-verify the whole target.
        if cached_entry.module and preset_module_key(cached_entry.module) != preset_module_key(
            getattr(entry, "module", "")
        ):
            continue

        # One shared identity check (see verify_hash.entry_fingerprint):
        # resolved toolchain/cflags, defines, size, per-entry header closure,
        # and source hash.  Legacy entries ("" / -1 fields) are re-verified
        # once.  Cosmetic-only CFLAGS differences (reorder, dedup) still hit.
        from rebrew.verify_hash import cflags_equivalent, entry_fingerprint

        fp = entry_fingerprint(cfg, entry)
        if fp is None:
            continue
        if not cached_entry.toolchain or cached_entry.toolchain != fp.toolchain:
            continue
        if not cached_entry.defines or cached_entry.defines != fp.defines:
            continue
        if not cflags_equivalent(cached_entry.cflags, fp.cflags):
            continue
        if cached_entry.size != fp.size:
            continue
        if not cached_entry.headers_fp or cached_entry.headers_fp != fp.headers_fp:
            continue
        # Context digest must match exactly: a cached verdict earned bare
        # (None) is a different compile input than one earned under
        # declarations, and vice versa.  Legacy entries record the hit only
        # when the current run is also context-free (pre-digest rows carry
        # None and were only ever written by bare-source runs).
        if cached_entry.context_hash != (context.sha256 if context is not None else None):
            continue
        cached_source = contained_path(source_roots(cfg), getattr(entry, "filepath", ""))
        if cached_source is None:
            # A ``file`` outside the source trees is not a cache candidate.
            continue
        try:
            cached_source.stat()
        except OSError:
            # File deleted between fingerprint and stat — treat as a miss.
            continue
        if fp.source_hash != cached_entry.source_hash:
            continue

        results.append(cached_entry.result_row())
        if cached_entry.passed:
            passed += 1
        else:
            failed += 1
            fail_details.append((entry, str(cached_entry.message)))
        cached_count += 1

    if verify_cache_obj is not None and not json_output:
        fresh_count = len(unique_entries) - cached_count
        console.print(
            f"Incremental: {cached_count} cached, {fresh_count} to verify (use --full to force all)"
        )

    # Detect annotation SIZE vs binary-derived canonical size divergence.
    # A stale annotation size makes byte extraction slice the binary at the
    # wrong length (false EXACT on truncated functions, or a misleading
    # SIZE_MISMATCH).  Report-only: the annotation stays authoritative.
    size_divergences: list[dict[str, Any]] = []
    # MISSING_SIZE (no annotation size at all): the 0-byte compare is vacuous
    # and rebrew test refuses the entry.  --fix-sizes backfills the canonical
    # size so documented stubs become testable.  Tracked separately so the
    # divergence warning above stays accurate (these don't "differ", they're
    # absent).
    missing_sizes: list[dict[str, Any]] = []
    for entry in unique_entries:
        reg = registry.get(entry.va)
        if not reg:
            continue
        canonical = reg.get("canonical_size") or 0
        ann_size = entry.size or 0
        stored = str(getattr(entry, "status", "") or "")
        if _size_divergence_action(ann_size, canonical, stored) == "warn":
            size_divergences.append(
                {
                    "va": f"0x{entry.va:08x}",
                    "annotation_size": ann_size,
                    "binary_size": canonical,
                    "name": entry.name or entry.symbol or "",
                    "module": getattr(entry, "module", ""),
                    # Needed by --fix-sizes: a byte-matched entry's size is
                    # evidence, not a defect (see _partition_size_fixes).
                    "status": stored,
                }
            )
        elif canonical > 0 and ann_size == 0:
            missing_sizes.append(
                {
                    "va": f"0x{entry.va:08x}",
                    "annotation_size": 0,
                    "binary_size": canonical,
                    "name": entry.name or entry.symbol or "",
                    "module": getattr(entry, "module", ""),
                }
            )
    size_divergences.sort(key=lambda d: d["va"])
    missing_sizes.sort(key=lambda d: d["va"])

    duplicate_rows = [
        {"va": f"0x{va:08x}", "kept": kept, "dropped": dropped}
        for va, kept, dropped in duplicate_vas
    ]
    return (
        unique_entries,
        passed,
        failed,
        fail_details,
        results,
        cached_count,
        size_divergences,
        missing_sizes,
        duplicate_rows,
        name_to_va,
        _inventory_count(cfg, reversed_dir),
    )


def run_verification(
    entries_to_verify: list[Annotation],
    cfg: Any,
    jobs: int,
    total: int,
    cached_count: int,
    json_output: bool,
    context: "CompileContext | None" = None,
    name_to_va: dict[str, int] | None = None,
) -> tuple[
    int, int, list[tuple[Annotation, str]], list[dict[str, Any]], list[tuple[Annotation, str, int]]
]:
    """Run parallel verification and classify results.

    Returns (passed, failed, fail_details, results, deferred_fixes).
    *context* is threaded to every ``verify_entry`` so each result carries
    the digest of the context it was compiled under.
    *name_to_va* is the shared symbol catalog from ``prepare_entries``; when
    omitted the catalog is built here (standalone callers / tests).
    """
    passed = 0
    failed = 0
    internal_errors = 0
    fail_details: list[tuple[Annotation, str]] = []
    results: list[dict[str, Any]] = []
    deferred_fixes: list[tuple[Annotation, str, int]] = []

    fresh_count = len(entries_to_verify)
    # The CLI --jobs flag bypasses config's _positive_int validation — clamp
    # here so `--jobs 0` (or negative) cannot crash ThreadPoolExecutor.
    effective_jobs = max(1, min(jobs, fresh_count)) if fresh_count else 1

    try:
        from rebrew.compile_cache import get_project_cache

        compile_cache = get_project_cache(cfg)
    except (ImportError, OSError):
        compile_cache = None

    # Shared once for the whole batch — same catalog `rebrew test` uses.
    # Fail closed: a VA-map scan failure aborts the run instead of masking
    # relocs against an empty map (false RELOC).
    if name_to_va is None:
        from rebrew.coff_reloc import CatalogScanError, build_name_to_va

        try:
            name_to_va = build_name_to_va(cfg)
        except CatalogScanError as exc:
            error_exit(str(exc), json_mode=json_output)

    def _verify(
        e: Annotation,
    ) -> tuple[Annotation, "CompareResult"]:
        precompiled = _batch_objs.get(id(e)) if _batch_objs else None
        return (
            e,
            verify_entry(
                e,
                cfg,
                cache=compile_cache,
                name_to_va=name_to_va,
                context=context,
                _precompiled_obj=precompiled,
            ),
        )

    # Batch pre-compile (ADR-021): group cache-miss entries by (toolchain,
    # cflags) and compile each group with one container invocation instead
    # of one per function.  Entries that can't batch (context-merged units,
    # recompile backend, exotic arg styles) compile individually inside
    # verify_entry as before — _batch_objs only carries what the batch
    # produced.
    _batch_objs: dict[int, str] = {}
    try:
        from rebrew.compile import precompile_batch
        from rebrew.compile_overrides import resolve_compile_overrides_cached
        from rebrew.verify_hash import comparison_inputs

        for entry in entries_to_verify:
            source = contained_path(source_roots(cfg), entry.filepath)
            if source is None:
                continue
            toolchain, flags = resolve_compile_overrides_cached(
                cfg, source.parent, entry.toolchain, entry.cflags, entry.module
            )
            entry.comparison_inputs = comparison_inputs(
                cfg,
                source,
                b"",
                toolchain=toolchain,
                cflags=flags,
                module=entry.module,
                va=entry.va,
                context_hash=context.sha256 if context is not None else "",
            )

        _batch_objs = precompile_batch(cfg, entries_to_verify, cache=compile_cache, context=context)
    except Exception as exc:  # batch is an optimization; never fail the run
        log.debug("batch pre-compile skipped: %s", exc)

    try:
        with Progress(
            TextColumn("[bold blue]Verifying"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.description}"),
            console=console,
            disable=json_output,
        ) as progress:
            task = progress.add_task("functions", total=total)
            if cached_count > 0:
                progress.update(task, advance=cached_count, description="cached")

            with interruptible_pool(effective_jobs) as pool:
                # Bounded submission: submitting every entry up front (verify
                # batches can be thousands of functions) builds one Future + one
                # queued task per entry — the exact pattern flag_sweep was
                # deliberately changed away from (matcher/compiler.py, flag_sweep).  Submit
                # effective_jobs at a time and refill as each completes, so
                # memory stays proportional to the worker count, not the corpus.
                futures: dict[concurrent.futures.Future[Any], Annotation] = {}
                entry_iter = iter(entries_to_verify)
                for _ in range(effective_jobs):
                    with contextlib.suppress(StopIteration):
                        e = next(entry_iter)
                        futures[pool.submit(_verify, e)] = e
                # Drain-and-refill: wait with FIRST_COMPLETED so refilled pool slots
                # are re-evaluated immediately instead of stalling idle workers
                # behind an as_completed snapshot barrier.
                while futures:
                    done, _ = concurrent.futures.wait(
                        futures, return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    for future in done:
                        entry = futures.pop(future)
                        is_internal_error = False
                        try:
                            _entry, result = future.result()
                        except Exception as exc:
                            is_internal_error = True
                            internal_errors += 1
                            log.warning(
                                "Internal error verifying %s",
                                getattr(entry, "name", "?"),
                                exc_info=True,
                            )
                            if internal_errors <= 5:
                                console.print(
                                    f"[yellow]warning:[/yellow] internal error verifying "
                                    f"{untrusted_ident(getattr(entry, 'name', '?'))}: "
                                    f"{untrusted_ident(exc)}"
                                )
                            result = _failed_result("INTERNAL_ERROR", f"INTERNAL_ERROR: {exc}")
                        # Refill the pool slot with the next entry (if any).
                        with contextlib.suppress(StopIteration):
                            e = next(entry_iter)
                            futures[pool.submit(_verify, e)] = e

                        name = entry.name
                        progress.update(task, advance=1, description=name)

                        if result.matched:
                            passed += 1
                        else:
                            failed += 1
                            # A tooling crash fails the gate in BOTH modes: plain
                            # verify counts it in the failed total (exit 1 below),
                            # and --compare must not skip it either (fail closed —
                            # a crashed worker on a previously-EXACT function is a
                            # gate failure, not a silent pass).
                            fail_details.append((entry, result.message))

                        # An INTERNAL_ERROR is a tooling failure, not a verification
                        # verdict — never let it overwrite the function's real STATUS
                        # in rebrew-functions.toml (an EXACT/NEAR_MATCHING function would
                        # be permanently demoted to COMPILE_ERROR).
                        if not is_internal_error:
                            deferred_fixes.append((entry, result.status, result.delta))

                        results.append(
                            order_result_row(
                                {
                                    "va": f"0x{entry.va:08x}",
                                    "name": name,
                                    "symbol": _entry_symbol(entry),
                                    "module": getattr(entry, "module", ""),
                                    "filepath": getattr(entry, "filepath", ""),
                                    "size": getattr(entry, "size", 0),
                                    "status": result.status,
                                    "message": result.message,
                                    "passed": result.matched,
                                    "match_percent": result.match_percent,
                                    "delta": result.delta,
                                    "diff_lines": result.diff_lines,
                                    "similarity": result.similarity,
                                    "reg_delta": result.reg_delta,
                                    "effective_match": result.effective_match,
                                    "context_hash": result.context_hash,
                                }
                            )
                        )
    finally:
        # Batch-published .obj files are no longer needed — drop lasting temp
        # dirs so a long-lived process does not accumulate one per --full run.
        with contextlib.suppress(Exception):
            from rebrew.compile import cleanup_batch_obj_dirs

            cleanup_batch_obj_dirs()

    if internal_errors > 0 and not json_output:
        console.print(
            f"[yellow]warning:[/yellow] {internal_errors} function(s) failed with internal errors "
            f"(tooling failures — counted as failures so the gate fails closed in "
            f"both plain and --compare modes)"
        )

    # The pool drains in completion order, and `done` is a set of futures, so
    # these three lists would otherwise be a function of thread timing.  The
    # STATUS batch creates any missing metadata entry as it walks them, so an
    # unordered walk writes rebrew-functions.toml in a different section order
    # on every run of the same corpus.  Sort on the entry's own identity.
    def _entry_order(item: tuple[Any, ...]) -> tuple[str, int, str]:
        entry = item[0]
        return (
            getattr(entry, "module", "") or "",
            int(getattr(entry, "va", 0) or 0),
            getattr(entry, "name", "") or "",
        )

    fail_details.sort(key=_entry_order)
    deferred_fixes.sort(key=_entry_order)
    # The JSON payload is read in the same order by anyone diffing two runs
    # (or replaying one under an injected clock), so it gets the same sort:
    # in completion order it is a diff of thread timing, not of the corpus.
    results.sort(
        key=lambda row: (
            str(row.get("module", "")),
            int(str(row.get("va", "0")), 16),
            str(row.get("name", "")),
        )
    )

    return passed, failed, fail_details, results, deferred_fixes


def _apply_or_preview_status(
    deferred_fixes: list[tuple[Annotation, str, int]], cfg: Any, dry_run: bool
) -> None:
    """Apply STATUS metadata updates, or preview them for ``--dry-run`` / ``--no-promote``."""
    if not deferred_fixes:
        return
    if dry_run:
        for entry, status, _delta in deferred_fixes:
            module: str = getattr(entry, "module", "") or ""
            # Mirror apply_status_updates' promotion decision so the preview
            # only claims updates a real run would actually write: parked SKIP
            # never moves and a STUB's placeholder size-mismatch keeps the
            # user's classification.  The path guards are the writer's alone —
            # a preview names what the run decided, not what it will find.
            if not should_promote_status(getattr(entry, "status", ""), status):
                continue
            console.print(
                f"[dim]would update STATUS → {untrusted_ident(status)} for "
                f"0x{entry.va:x} ({untrusted_ident(module)})[/dim]"
            )
        return
    apply_status_updates(deferred_fixes, cfg)


def _status_store_label(cfg: Any) -> str:
    """Name the metadata store, the way the orphaned-branch warning above does."""
    return getattr(cfg, "metadata_dir", "the metadata store")


def _warn_unwritten_statuses(
    updates: list[dict[str, Any]], exc: BaseException, store: str, *, exc_info: bool = False
) -> None:
    """Report a failed batch STATUS write with the count of verdicts it dropped.

    The run still reports its compile-and-compare results, so the loss is only
    visible here.  A bare "could not update" reads as housekeeping; the count
    and the staleness note are what tell the operator that ``rebrew status``
    will show the pre-run STATUS until something writes it back.
    """
    if not updates:
        return
    log.warning(
        "Could not update STATUS metadata: %s. %d verified STATUS update(s) were not "
        "written to %s; their stored status is now stale: %s",
        exc,
        len(updates),
        store,
        "; ".join(
            f"0x{int(u['va']):x} ({u.get('module') or '?'}) -> {u['new_status']}"
            for u in updates[:_ORPHAN_REPORT_LIMIT]
        ),
        exc_info=exc_info,
    )
    if len(updates) > _ORPHAN_REPORT_LIMIT:
        log.warning("... and %d more unwritten STATUS updates", len(updates) - _ORPHAN_REPORT_LIMIT)


def apply_status_updates(
    deferred_fixes: list[tuple[Annotation, str, int]],
    cfg: Any,
) -> None:
    """Promote/demote STATUS metadata to match verification results.

    Called unconditionally after verification — both ``rebrew verify``
    and ``rebrew test --all`` always keep metadata in sync with the
    compile-and-compare truth.  Blockers are cleared only on a byte match.
    """
    updates: list[dict[str, Any]] = []
    orphaned: list[str] = []
    for entry, status, _delta in deferred_fixes:
        fp = contained_path(source_roots(cfg), getattr(entry, "filepath", ""))
        if fp is None or not fp.exists():
            # Dropping the verdict silently left the stored STATUS stale while
            # the run reported the result as authoritative; name the losers.
            orphaned.append(
                f"0x{entry.va:x} ({getattr(entry, 'module', '') or '?'})"
                f" -> {status}: source {getattr(entry, 'filepath', '')!r} not found"
            )
            continue
        module: str = getattr(entry, "module", "") or ""
        if not module:
            orphaned.append(f"0x{entry.va:x} -> {status}: annotation names no module")
            continue
        current_status = getattr(entry, "status", "")
        # Parked SKIP never moves; a STUB's placeholder always size-mismatches
        # (keep the user's classification); unchanged status is a no-op.  All
        # decided by should_promote_status.
        if current_status != status and not should_promote_status(current_status, status):
            continue
        updates.append(
            {
                "module": module,
                "va": entry.va,
                "new_status": status,
                "clear_blockers": clears_blocker(status, fp),
                "updated_by": "verify",
                **(
                    {
                        "verification": {
                            **(entry.comparison_inputs or {}),
                            "writer": "verify",
                            "status": status,
                        }
                    }
                    if getattr(entry, "comparison_inputs", None)
                    else {}
                ),
            }
        )

    if orphaned:
        log.warning(
            "%d of %d verified STATUS updates were not written to %s; "
            "their stored status is now stale: %s",
            len(orphaned),
            len(deferred_fixes),
            getattr(cfg, "metadata_dir", "the metadata store"),
            "; ".join(orphaned[:_ORPHAN_REPORT_LIMIT]),
        )
        if len(orphaned) > _ORPHAN_REPORT_LIMIT:
            log.warning(
                "... and %d more unwritten STATUS updates",
                len(orphaned) - _ORPHAN_REPORT_LIMIT,
            )

    try:
        # Batch all STATUS writes into one TOML read-modify-write
        # (per-entry RMW was ~9s at 260 entries, minutes at
        # thousands).
        from rebrew.metadata import update_statuses_batch

        update_statuses_batch(cfg.metadata_dir, updates)
    except OSError as exc:
        # STATUS sync is best-effort — a read-only or unwritable metadata
        # file must not abort the whole verify run (and lose the report
        # the user waited for).  Warn and keep the verification results,
        # but say how many verdicts were dropped and that the store is now
        # stale, the way the orphaned branch above does: without the count
        # the run reads as a clean report that simply promoted nothing.
        _warn_unwritten_statuses(updates, exc, _status_store_label(cfg))
    except Exception as exc:
        # Unexpected failures (parse bugs, lock races) must not wipe the
        # report either, but they are not routine I/O — keep the traceback.
        _warn_unwritten_statuses(updates, exc, _status_store_label(cfg), exc_info=True)


def _pe_sections_for_merge_check(data: bytes) -> tuple[int, list[tuple[int, int, int]]]:
    """``(image_base, [(section_va, raw_offset, raw_size), ...])`` for a PE image.

    Local and minimal on purpose: this runs once per verify and pulling in the
    full section reader would make a two-cause warning depend on the layout
    machinery it is meant to be independent of.
    """
    import struct as _struct

    if len(data) < 0x40:
        return 0, []
    try:
        pe = _struct.unpack_from("<I", data, 0x3C)[0]
        nsec = _struct.unpack_from("<H", data, pe + 6)[0]
        optsz = _struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        base = _struct.unpack_from("<I", data, opt + 28)[0]
    except _struct.error:
        return 0, []
    out: list[tuple[int, int, int]] = []
    off = opt + optsz
    for i in range(nsec):
        s = off + i * 40
        try:
            # +12 is VirtualAddress, +16 SizeOfRawData, +20 PointerToRawData
            va, raw_size, raw_off = _struct.unpack_from("<III", data, s + 12)
        except _struct.error:
            break
        out.append((base + va, raw_off, raw_size))
    return base, out


def _looks_like_inventory_merge(
    binary: bytes, va: int, image_base: int, start_off: int, ann_size: int, span: int
) -> bool:
    """Whether ``[va+ann_size, va+span)`` opens with a new function.

    An under-count has two causes and they need opposite responses: a TRUNCATED
    annotation is work to reverse, while an INVENTORY MERGE is a discovery defect
    and reversing it is wasted.  The distinguisher is cheap -- a function ends in
    a `ret` and the next one opens with a stack-frame prologue -- so it needs no
    disassembler, only the bytes.

    Round 190 measured `cm_ExTransferCurrencyNoKill` at 144 annotated against a
    2,208-byte inventory entry and found `c3 90 90` then `81 ec 28 02 00 00` at
    +144: the annotation was right and the inventory was two functions.
    """
    # The annotation is rounded up to the next 16-byte function boundary, so the
    # function's own `ret` can sit up to that much BEFORE the annotation's size --
    # cm_ExTransferCurrencyNoKill's ret is at +141 against an annotated 144.  Start
    # the scan below the annotation size or every merge is missed.
    lo, hi = start_off + max(0, ann_size - 16), start_off + span
    # ONE source of truth for what opens a function.  This detector used to carry
    # its own four shapes while `discover._starts_function` grew to eight across
    # rounds 196-197 and 245 -- so the two disagreed about the same bytes, and this
    # one missed cm_DispatchProduction's neighbour (`8b 44 24 04`, a first-argument
    # load) until round 247.  `openers` is kept as a fallback only for callers
    # without a loader handle.
    openers = (
        b"\x55\x8b\xec",  # push ebp; mov ebp, esp
        b"\x81\xec",  # sub esp, imm32
        b"\x83\xec",  # sub esp, imm8
        b"\x6a\xff\x68",  # push -1; push <seh>
        b"\xa1",  # mov eax, [<global>]
        b"\x8b\x44\x24\x04",  # mov eax, [esp+4]
        b"\x8b\x4c\x24\x04",  # mov ecx, [esp+4]
    )
    for i in range(lo, min(hi, len(binary)) - 8):
        if binary[i] != 0xC3:  # ret
            continue
        for j in range(i + 1, min(i + 13, len(binary) - 4)):
            if binary[j] == 0x90:  # skip the alignment nops
                continue
            if any(binary.startswith(op, j) for op in openers) or (
                binary.startswith(b"\xb8", j) and j + 5 < len(binary) and binary[j + 5] == 0xC3
            ):
                return True
            break
    # And the simplest case of all, which the loop above cannot reach: the
    # annotation's OWN END opens a function.  A `switch` puts its jump table after
    # the code's `ret`, so at cm_DispatchProduction the `ret` is at +113 while the
    # annotation ends at +144 (116 bytes of code, a 28-byte table of .text
    # addresses) -- 31 bytes earlier than the 16-byte back-scan looks, and the
    # next function starts exactly at +144 (`8b 44 24 04`, round 246).  Testing
    # the boundary directly costs one comparison and needs no window at all.
    end = start_off + ann_size
    if end + 4 <= len(binary):
        j = end
        while j < len(binary) and binary[j] in (0x90, 0xCC):
            j += 1
        if any(binary.startswith(op, j) for op in openers) or (
            binary.startswith(b"\xb8", j) and j + 5 < len(binary) and binary[j + 5] == 0xC3
        ):
            return True
    return False


def _print_results(
    results: list[dict[str, Any]],
    fail_details: list[tuple[Annotation, str]],
    diff_result: dict[str, Any] | None,
    diff_warning: str | None,
    diff_mode: bool,
    show_summary: bool,
    total: int,
    passed: int,
    failed: int,
    library_passed: int = 0,
    library_total: int = 0,
    size_divergences: list[dict[str, Any]] | None = None,
    merge_count: int = 0,
    library_providers: list[dict[str, Any]] | None = None,
) -> None:
    """Print diff report, summary table, and failure details.

    ``size_divergences`` is reported here because an annotation SHORTER than
    the binary's function is the one size problem that cannot show up as a
    failure: the compiler emits the annotation's bytes, the comparison sees
    exactly those bytes match, and the verdict is EXACT or RELOC on a prefix.
    The divergence reached only the JSON and `rebrew status`, so a run could
    print "262/262 passed" while a function was thousands of bytes truncated
    -- guild-rebrew had cm_ExTransferCurrencyNoKill annotated at 144 bytes
    against a 2,208-byte binary, and nothing on screen said so.
    """
    if diff_mode and diff_result is not None:
        regressions = diff_result["regressions"]
        improvements = diff_result["improvements"]
        new_items = diff_result["new"]
        removed = diff_result["removed"]

        console.print()
        console.print(f"{len(regressions)} regressions detected:")
        for item in regressions:
            console.print(
                "  "
                f"{untrusted_ident(item['name'])}  "
                f"{untrusted_ident(item['previous_status'])} -> "
                f"{untrusted_ident(item['current_status'])}  "
                f"(delta: {item['delta']}B)"
            )

        console.print()
        console.print(f"{len(improvements)} improvements:")
        for item in improvements:
            console.print(
                f"  {untrusted_ident(item['name'])}  "
                f"{untrusted_ident(item['previous_status'])} -> "
                f"{untrusted_ident(item['current_status'])}"
            )

        if new_items:
            console.print()
            console.print(f"{len(new_items)} new:")
            for item in new_items:
                console.print(
                    f"  {untrusted_ident(item['name'])}  {untrusted_ident(item['status'])}"
                )

        if removed:
            console.print()
            console.print(f"{len(removed)} removed:")
            for item in removed:
                console.print(
                    f"  {untrusted_ident(item['name'])}  {untrusted_ident(item['status'])}"
                )

        if diff_warning:
            console.print()
            console.print(f"[yellow]warning:[/yellow] {untrusted_ident(diff_warning)}")

        if regressions:
            console.print()
            console.print(
                "[dim]Tip: run 'rebrew diff <va>' on the regressed functions "
                "to see the byte differences[/dim]"
            )

    if show_summary:
        render_verify_summary(results)

    if fail_details:
        console.print()

        res_by_va = {int(r["va"], 16): r for r in results}

        # Sort failures: lowest match_percent first, then by VA
        def _fail_sort_key(item: tuple[Annotation, str]) -> tuple[float, int]:
            entry, _ = item
            return (_row_match_pct(res_by_va.get(entry.va)), entry.va)

        for entry, msg in sorted(fail_details, key=_fail_sort_key):
            res_dict = res_by_va.get(entry.va)
            st = str(res_dict["status"]) if res_dict else "FAIL"
            fp = getattr(entry, "filepath", "")
            ln = getattr(entry, "line", 0)
            fp_suffix = (
                f" [dim]({untrusted_ident(fp)}:{ln})[/]"
                if fp and ln
                else f" [dim]({untrusted_ident(fp)})[/]"
                if fp
                else ""
            )
            if st in ("STUB", "NEAR_MATCHING"):
                match_pct = _row_match_pct(res_dict)
                sim = res_dict.get("similarity") if res_dict else None
                sim_str = f" / sim {sim:.1f}" if isinstance(sim, (int, float)) else ""
                console.print(
                    rf"  [red bold]\[{floor_pct(match_pct, 100):.1f}%{sim_str}][/] "
                    rf"0x{entry.va:08X} {untrusted_ident(entry.name)}{fp_suffix}: "
                    rf"{untrusted_ident(msg)}"
                )
            elif st in (
                "COMPILE_ERROR",
                "EXTRACT_ERROR",
                "MISSING_FILE",
                "MISSING_SIZE",
                "INVALID_VA",
            ):
                console.print(
                    rf"  [red bold]\[{st}][/] 0x{entry.va:08X} "
                    rf"{untrusted_ident(entry.name)}{fp_suffix}: {untrusted_ident(msg)}"
                )
            else:
                console.print(
                    rf"  [red bold]\[FAIL][/] 0x{entry.va:08X} "
                    rf"{untrusted_ident(entry.name)}{fp_suffix}: {untrusted_ident(msg)}"
                )

    # Summary
    style = "green" if failed == 0 else "red"
    result_text = Text()
    # The headline uses the progress bar and JSON report's combined total.
    # Separate game and library results below it to keep reversing progress clear.
    result_text.append("\nVerification: ")
    result_text.append(f"{passed}/{total} passed", style=style)
    if failed:
        result_text.append(", ")
        result_text.append(f"{failed} failed", style="red")
    if library_total:
        library_failed = library_total - library_passed
        game_failed = failed - library_failed
        result_text.append("\n  Game: ")
        result_text.append(
            f"{passed - library_passed}/{total - library_total} passed",
            style="red" if game_failed else "green",
        )
        if game_failed:
            result_text.append(f", {game_failed} failed", style="red")
        result_text.append("; compiled libraries: ")
        result_text.append(
            f"{library_passed}/{library_total} passed",
            style="red" if library_failed else "green",
        )
        if library_failed:
            result_text.append(f", {library_failed} failed", style="red")
    console.print(result_text)
    if library_providers:
        prebuilt = sum(row["provider"] == "prebuilt" for row in library_providers)
        unresolved = sum(row["provider"] == "unresolved" for row in library_providers)
        console.print(
            f"[dim]Library providers: {prebuilt} prebuilt (not compiled), "
            f"{unresolved} unresolved[/dim]"
        )
    under = [
        d
        for d in (size_divergences or [])
        if d.get("annotation_size")
        and d.get("binary_size")
        and d["annotation_size"] < d["binary_size"]
    ]
    if under:
        short = sum(d["binary_size"] - d["annotation_size"] for d in under)
        worst = max(under, key=lambda d: d["binary_size"] - d["annotation_size"])
        console.print(
            f"[yellow]warning: {len(under)} function(s) are SHORTER than the "
            f"binary's function ({short} bytes missing in total)[/yellow]"
        )
        console.print(
            f"[dim]  worst: {untrusted_ident(worst.get('name') or '')} at "
            f"{untrusted_ident(str(worst.get('va')))} -- annotated "
            f"{worst['annotation_size']} bytes against {worst['binary_size']} "
            f"in the binary[/dim]"
        )
        console.print(
            "[dim]  these pass as EXACT/RELOC on a prefix: the annotation's own "
            "bytes match, and anything past them is not compared. Not a failure "
            "-- a measure of what is not yet reversed. `rebrew verify --json` "
            "lists them under size_divergences.[/dim]"
        )
        if merge_count:
            console.print(
                f"[dim]  {merge_count} of them open with a new function before the "
                "inventory's size -- a `ret` then a prologue. Those are INVENTORY "
                "MERGES, not truncated annotations: the annotation is right and the "
                "discovery entry spans several functions. Reversing them is wasted "
                "work; the inventory is what to fix.[/dim]"
            )
        else:
            console.print(
                "[dim]  careful: an under-count has TWO causes and this cannot tell "
                "them apart. Either the annotation is truncated, or the inventory "
                "entry spans several functions and is not one function at all."
                "[/dim]"
            )
    if any(r["status"] == "MISSING_SIZE" for r in results):
        n = sum(1 for r in results if r["status"] == "MISSING_SIZE")
        console.print(
            f"[dim]hint: {n} function(s) have no SIZE — backfill from the "
            "inventory with `rebrew verify --fix-sizes` (or `rebrew coverage catalog "
            "--fix-sizes` without verifying).[/dim]"
        )


def _row_match_pct(row: dict[str, Any] | None) -> float:
    """Match percent of a report row, 0.0 when absent.

    A cache-served row carries no percent when no real measurement ever
    recorded one (``VerifyCacheEntry.match_percent`` is ``float | None``).
    """
    if row is None:
        return 0.0
    pct = row.get("match_percent")
    return float(pct) if isinstance(pct, (int, float)) and math.isfinite(pct) else 0.0


def render_verify_summary(results: list[dict[str, Any]]) -> None:
    """Print the verification summary tables. Match % has a bar of that ratio."""
    from rebrew.present import bar_plain, count_column

    console.print()
    table = Table(title="Verification Summary", show_header=True, expand=False, pad_edge=False)
    table.add_column("VA", style="cyan", width=12, no_wrap=True)
    table.add_column("Symbol", style="magenta", overflow="ellipsis", no_wrap=True)
    count_column(table, "Size", width=8)
    table.add_column("Status", style="bold", width=14, no_wrap=True, overflow="ellipsis")
    count_column(table, "Match %", width=8)
    count_column(table, "Delta", width=8)
    count_column(table, "Sim %", width=8)

    for r in results:
        st = r["status"]
        color = STATUS_COLORS.get(st, "red")
        st_str = f"[{color}]{untrusted_ident(st)}[/{color}]"

        show_pct = st in ("STUB", "NEAR_MATCHING")
        pct = f"{floor_pct(_row_match_pct(r), 100):.1f}%" if show_pct else "-"
        # ``delta`` is ``int | None`` on a cache-served row and the key is
        # always present, so ``.get(..., 0)`` never substitutes: an absent delta
        # printed as ``NoneB``.  Treat it as the unmeasured value it is.
        delta = r.get("delta")
        dt = f"{delta}B" if isinstance(delta, (int, float)) and not isinstance(delta, bool) else "-"
        sim = r.get("similarity")
        sim_str = f"{sim:.1f}%" if isinstance(sim, (int, float)) else "-"
        table.add_row(
            r["va"], untrusted_ident(r["name"]), f"{r['size']}B", st_str, pct, dt, sim_str
        )

    console.print(table)

    exact = sum(1 for r in results if r["status"] == "EXACT")
    reloc = sum(1 for r in results if r["status"] == "RELOC")
    near_matching = sum(1 for r in results if r["status"] == "NEAR_MATCHING")
    stub = sum(1 for r in results if r["status"] == "STUB")

    stat_table = Table(title="STATUS Breakdown", show_header=False, expand=False, pad_edge=False)
    stat_table.add_column("Category", style="cyan", width=16, no_wrap=True)
    count_column(stat_table, "Count", width=8)
    stat_table.add_row("EXACT", str(exact))
    stat_table.add_row("RELOC", str(reloc))
    stat_table.add_row("NEAR_MATCHING", str(near_matching))
    stat_table.add_row("STUB", str(stub))

    console.print(stat_table)
    # Match % is each function's own ratio, not the pass count above.
    for r in results:
        if r["status"] not in ("STUB", "NEAR_MATCHING"):
            continue
        match_pct = _row_match_pct(r)
        console.print(f"{untrusted_ident(r['name'])}  {floor_pct(match_pct, 100):.1f}% match")
        console.print(bar_plain(match_pct, 100))


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
