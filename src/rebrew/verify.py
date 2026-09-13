"""verify.py — Batch compile-and-compare for all reversed functions.

Compiles every annotated ``.c`` file and compares object bytes against the
target binary.  Results are classified by :class:`~rebrew.compile.CompareResult`
(EXACT, RELOC, STUB, COMPILE_ERROR, …).

After verification, STATUS is always promoted/demoted in
``rebrew-functions.toml`` via :func:`~rebrew.metadata.update_statuses_batch`
— the ``.c`` files are **never modified**.  PROVEN status is sticky and
never demoted.

With ``--compare`` it compares the current run against the last saved
``db/verify_results.json`` and exits with code 1 on any regression (suitable
for CI / pre-commit hooks).
"""

import concurrent.futures
import contextlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.compile import CompareResult
    from rebrew.compile_cache import CacheBackend
    from rebrew.context import CompileContext

import typer
from rich.console import Console
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
    STATUS_COLORS,
    TargetOption,
    error_exit,
    json_print,
    require_config,
)
from rebrew.compile import (
    is_matched,
)
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.metadata import should_promote_status
from rebrew.utils import atomic_write_text
from rebrew.verify_cache import (
    VerifyCacheEntry,
    _load_verify_cache,
    _save_verify_cache,
    canonical_va_key,
)
from rebrew.verify_hash import (
    _DEFAULT_TOOLCHAIN,
    _entry_headers_fp,
    _expected_text_functions,
    _source_hash,
)

log = logging.getLogger(__name__)

#: Sentinel stored in VerifyCacheEntry.toolchain when no override names a
#: compiler (the project's default profile applies).  Distinct from ``""`` so
#: legacy entries (written before the field existed) are re-verified once.

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _failed_result(status: str, message: str = "") -> "CompareResult":
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
    )


def _fenced_naked_note(cfile: Path) -> str:
    """Return an explanatory note when *cfile* guards its body behind the
    ``REBREW_ALLOW_NAKED`` fence.

    A fenced naked source compiles its ``#else`` fallback in the comparison
    build — for byte-identity the ``#ifdef`` branch must be active.  When
    such a function fails to byte-match, the bare mismatch hides the real
    cause (the build lacks the define), so name it: the caller can then use
    ``rebrew round-trip --allow-naked`` (or build the reccmp recomp binary
    with ``-DREBREW_ALLOW_NAKED=1``) instead of chasing a phantom source bug.
    """
    try:
        from rebrew.utils import read_source_text

        text, _ = read_source_text(cfile)
    except OSError:
        return ""
    if "#ifdef REBREW_ALLOW_NAKED" not in text:
        return ""
    return (
        "source is fenced naked (#ifdef REBREW_ALLOW_NAKED): the comparison "
        "build compiles the #else fallback, which cannot byte-match — "
        "byte-identity requires a REBREW_ALLOW_NAKED build "
        "(`rebrew round-trip --allow-naked`; for reccmp, build the recomp "
        "binary with -DREBREW_ALLOW_NAKED=1)"
    )


def verify_entry(
    entry: Annotation,
    cfg: ProjectConfig,
    cache: "CacheBackend | None" = None,
    *,
    name_to_va: dict[str, int] | None = None,
    context: "CompileContext | None" = None,
) -> "CompareResult":
    """Compile a .c file and compare output bytes against DLL.

    Delegates to ``compile_and_compare`` for the compile→extract→compare flow.
    When *cache* is provided, compilation results are reused across calls
    for the same source content + flags — critical for multi-function files
    where the same .c is compiled once and multiple symbols extracted.

    *name_to_va* is the shared data-catalog map used for DIR32 absolute
    validation, same source as ``rebrew test``.  *context* is the project's
    compile context (``rebrew context`` output), merged into the compile unit
    and recorded on the result as its digest.
    """
    from rebrew.compile import compile_and_compare

    cfile = cfg.reversed_dir / entry.filepath
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

    from rebrew.cli import resolve_compile_overrides

    # Shared fallback chain (per-function metadata → per-library
    # rebrew-libraries.toml → preset → compiler.cflags) so verify compiles
    # every function of a library with the same toolchain + flags as
    # match/diff/test.
    toolchain, cflags = resolve_compile_overrides(
        cfg,
        cfile.parent,
        getattr(entry, "toolchain", ""),
        getattr(entry, "cflags", ""),
        getattr(entry, "module", ""),
    )
    # Symbol mangling must stay consistent with the COFF symbol lookup in
    # parsers._parse_coff (which handles _/name_/_name variants).  Keep the
    # annotation symbol as-is when present; only synthesize "_" + name for
    # legacy entries lacking a symbol field.  Do not double-prefix.
    if entry.symbol:
        symbol = entry.symbol
    elif entry.name and not entry.name.startswith("_"):
        symbol = "_" + entry.name
    else:
        symbol = entry.name or entry.symbol or ""

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
            funcs = cached_function_list(cfg)
            if funcs and entry.va not in {f["va"] for f in funcs}:
                hint = (
                    f" (annotation VA 0x{entry.va:x} is not a function in the "
                    "current function list — stale annotation? re-run "
                    "`rebrew intake` or edit the marker VA)"
                )
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            # Best-effort hint: narrow the catch so a broken cache or config
            # parse surfaces as a real error instead of silently swallowing
            # the diagnostic worse than no hint at all.
            import logging as _logging  # local to except

            _logging.getLogger(__name__).debug("verify hint lookup failed: %s", exc)
        return _failed_result("EXTRACT_ERROR", "Cannot extract DLL bytes" + hint)

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
    )
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
        # exact/reloc path.  Feeds the recoverage-consumed
        # verify_results.diff_lines column (db-review F2: it was documented
        # but never produced, so every row was NULL).  Best-effort: any
        # disassembly failure leaves it None.
        try:
            from rebrew.matcher import diff_functions

            d = diff_functions(
                target_bytes,
                result.obj_bytes,
                result.reloc_offsets,
                as_dict=True,
                # Register-encoding diffs are classified separately (RR) so a
                # register-only delta is distinguishable from real structural
                # churn.  Register masking is x86-32 specific; other arches
                # fall back to the plain structural diff.
                register_aware=getattr(cfg, "arch", "") == "x86_32",
            )
            if d is not None:
                result.diff_lines = int(d["summary"]["structural"])
                result.reg_delta = int(d["summary"]["reg"])
                # Effective match (reccmp parity): every real delta byte is a
                # register-allocation difference — same instructions, same
                # operands, different registers.  Not byte-identical, but the
                # cause is compiler register allocation, not source logic —
                # name it so the user does not chase a phantom source bug.
                # Exposed to recoverage via the result row (effective_match).
                if d["summary"]["structural"] == 0 and d["summary"]["reg"] > 0:
                    result.effective_match = True
                    note = (
                        "effective match: differs only in register allocation — "
                        "not byte-identical; reccmp counts this as 100% (run "
                        "'rebrew prove' for PROVEN, or register-nudging C "
                        "tweaks for byte-identity)"
                    )
                    result.message = f"{result.message} {note}".strip()
        except Exception:  # diff_lines is best-effort
            result.diff_lines = None
    # Structural code-similarity score (0–100), computed for EVERY verified
    # function with compiled bytes — matched (short-circuit ~100) and
    # unmatched alike — so the recoverage-consumed verify_results.similarity
    # column carries a per-function value.  Reuses the optional `resembl`
    # scoring core; best-effort like diff_lines (a missing extra or a scoring
    # failure leaves it None rather than failing the run).
    if result.obj_bytes:
        try:
            from rebrew.matcher import code_similarity

            result.similarity = code_similarity(target_bytes, result.obj_bytes)
        except Exception:  # similarity is best-effort
            result.similarity = None
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


console = Console(stderr=True)

app = typer.Typer(
    help="Rebrew verification pipeline: compile each .c and verify bytes match.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew verify · · · · · · · · · · · · · Verify all .c files (rich progress bar)\n\n"
        "  rebrew verify --json · · · · · · · · · · Emit structured JSON report to stdout\n\n"
        "  rebrew verify -o db/verify_results.json · Write JSON report to file\n\n"
        "  rebrew verify -j 8 · · · · · · · · · · · Use 8 parallel compile jobs\n\n"
        "  rebrew verify -t mygame · · · · · · · · · Verify a specific target\n\n"
        "  rebrew verify --compare · · · · · · · · · Compare against last run, detect regressions\n\n"
        "  rebrew verify --full -j 8 · · · · · · · · Force full re-verify with 8 workers\n\n"
        "  rebrew verify --summary · · · · · · · · · Show detailed STATUS breakdown table\n\n"
        "[bold]How it works:[/bold]\n\n"
        "  For each .c file in reversed_dir, compiles it, extracts the COFF symbol, "
        "and compares the output bytes against the original DLL. Reports EXACT, "
        "RELOC (match after relocation masking), STUB, or COMPILE_ERROR.\n\n"
        "[bold]Exit codes:[/bold]\n\n"
        "  0   All functions passed verification\n\n"
        "  1   Failures or regressions detected\n\n"
        "[dim]Requires rebrew-project.toml with valid compiler and target binary paths. "
        "Run 'rebrew catalog' first to generate coverage data.[/dim]"
    ),
)

_STATUS_RANK: dict[str, int] = {
    # PROVEN is a post-verify semantic promotion, NOT a byte match: a proven
    # function compiles to bytes that differ from the target (every PROVEN
    # entry carries delta > 0).  It ranks below RELOC so a byte-identical
    # goal does not count it as done, and RELOC -> PROVEN reads as the
    # regression it is.
    "EXACT": 0,
    "RELOC": 1,
    "PROVEN": 2,
    "STUB": 2,
    "NEAR_MATCHING": 2,
    "SIZE_MISMATCH": 2,
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
    # Ordered just below RELOC and above the unmatched statuses: proven code
    # is semantically right but not byte-identical, so NEAR_MATCHING ->
    # PROVEN is still an improvement while RELOC -> PROVEN is a regression.
    "PROVEN": 2,
    "NEAR_MATCHING": 3,
    "SIZE_MISMATCH": 4,
    "STUB": 5,
    "COMPILE_ERROR": 6,
    "EXTRACT_ERROR": 6,
    "MISSING_FILE": 7,
    "MISSING_SIZE": 7,
    "INVALID_VA": 7,
    "INTERNAL_ERROR": 9,
    "FAIL": 8,
}


def _va_display(key: Any) -> str:
    """Render a canonical VA key back to a readable string."""
    if isinstance(key, int) and key >= 0:
        return f"0x{key:08x}"
    return str(key)


def diff_reports(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare two JSON verify reports and highlight changes in status or match percentage.

    Args:
        previous: The previous run's full JSON results dict.
        current: The newly generated full JSON results dict.

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

    fail_rank = _STATUS_RANK["FAIL"]

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

        current_order = _STATUS_ORDER.get(current_status, fail_rank + 1)

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
        previous_order = _STATUS_ORDER.get(previous_status, fail_rank + 1)

        if current_order == previous_order:
            # Same fine-grained status: only a match-percentage drop beyond
            # _COMPARE_DROP_PCT is a regression (e.g. NEAR_MATCHING 95% → 40%).
            prev_pct = previous_item.get("match_percent")
            curr_pct = current_item.get("match_percent")
            if (
                isinstance(prev_pct, (int, float))
                and isinstance(curr_pct, (int, float))
                and curr_pct < prev_pct - _COMPARE_DROP_PCT
            ):
                regressions.append(
                    {
                        "va": _va_display(va),
                        "name": str(current_item.get("name") or previous_item.get("name", "")),
                        "previous_status": previous_status,
                        "current_status": current_status,
                        "delta": int(current_item.get("delta", 0)),
                        "previous_match_percent": round(float(prev_pct), 1),
                        "current_match_percent": round(float(curr_pct), 1),
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


@app.callback(invoke_without_command=True)
def main(
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Project root directory (auto-detected from rebrew-project.toml if omitted)",
    ),
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
        help="Write JSON report to file (default: project db_dir/verify_results.json)",
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
        "before verifying — same scan as `rebrew orphans --prune`",
    ),
    data: bool = typer.Option(
        False,
        "--data",
        help="Byte-compare built .data/.rdata against the reference, "
        "per metadata symbol (needs --built)",
    ),
    built: Path | None = typer.Option(
        None,
        "--built",
        help="Built binary for --data/--whole-binary/--text comparison (default: build/<target>)",
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
        "exports, imports, resources, headers (needs --built)",
    ),
    context: Path | None = typer.Option(
        None,
        "--context",
        help=(
            "C declarations to compile with every source (e.g. 'rebrew context' output); "
            "each result records the context hash it was earned under"
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rebrew verification pipeline: compile each .c and verify bytes match."""
    cfg = require_config(target=target, json_mode=json_output, root=root)
    if jobs is None:
        jobs = cfg.default_jobs

    # The optional compile context (see `rebrew test --context`).  It is a
    # compile input: merged into every compile unit, hashed into each result,
    # and never combined with the result cache (the entry type carries no
    # context digest, so a cached verdict cannot be attributed to it).
    from rebrew.context import load_compile_context

    try:
        compile_context = load_compile_context(context)
    except (OSError, UnicodeDecodeError) as exc:
        error_exit(f"--context {context}: {exc}", json_mode=json_output)

    if compile_context is not None and not json_output:
        console.print(
            "[dim]--context: result cache bypassed; every verdict is compiled "
            "under the supplied context[/dim]"
        )

    # 16-bit NE targets need a 16-bit compiler profile (msvc-1.52 — DOSBox
    # image / rebrew.msvc16).  When one is configured, verify runs normally
    # through compile_and_compare (which routes the 16-bit OMF objects via
    # omf16).  Only short-circuit when the project has no 16-bit profile —
    # otherwise every stub would burn the compile loop into COMPILE_ERROR
    # rows.  (The original skip predated the msvc-1.52 profile and silently
    # hid the working 16-bit pipeline.)
    from rebrew.binary_loader import is_ne

    if getattr(cfg, "target_binary", None) and is_ne(cfg.target_binary):
        profile = getattr(cfg, "compiler_profile", "") or "msvc-6.0"
        if profile != "msvc-1.52":
            msg = (
                "verify: 16-bit NE targets need the msvc-1.52 profile "
                "(DOSBox CL.EXE — 'profile = \"msvc-1.52\"' in rebrew-project.toml); "
                f"current profile is {profile!r}.  Skipping the compile/compare loop."
            )
            if json_output:
                json_print({"skipped": True, "reason": msg, "arch": "x86_16"})
            else:
                console.print(f"[yellow]{msg}[/yellow]")
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
            # stopped covering new files (idempotency-review F8).
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
                text=text,
                whole_binary=whole_binary,
                context=context,
                watch=False,  # never nest watch loops
                target=target,
            )

        watch_files(_sources(), _retest, path_provider=_sources)
        return

    out_file = Path(output_path) if output_path else cfg.db_dir / "verify_results.json"
    previous_report, diff_warning = _load_previous_report(out_file, diff_mode, json_output)

    orphans_pruned = 0
    if prune_orphans:
        from rebrew.orphans import find_orphans, split_prunable

        orphans = split_prunable(cfg, *find_orphans(cfg))
        if dry_run:
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
        from rebrew.data_verify import section_symbol_bytes, verify_data_bytes

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
            metadata_path=metadata_path, binary_path=cfg.target_binary
        )
        built_bytes, built_sizes = section_symbol_bytes(
            metadata_path=metadata_path, binary_path=built_path
        )
        data_report = verify_data_bytes(
            metadata_path=metadata_path,
            expected=ref_bytes,
            actual=built_bytes,
            sizes={va: ref_sizes.get(va, built_sizes.get(va, 0)) for va in ref_sizes | built_sizes},
        )
        if not dry_run:
            from rebrew.data_metadata import (
                DATA_STATUS_DRIFT,
                DATA_STATUS_UNCHECKED,
                DATA_STATUS_VERIFIED,
                load_data_metadata,
                set_data_field,
            )

            entries = load_data_metadata(cfg.metadata_dir)
            names_by_va: dict[int, tuple[str, str]] = {}
            for (module, va), fields in entries.items():
                name = str(fields.get("name") or "")
                if name:
                    names_by_va[va] = (module, name)
            drift_names = {str(m["name"]) for m in data_report["mismatched"]}
            missing_names = set(data_report["missing"])
            matched_names = {
                names_by_va[va][1] for va in ref_sizes if va in names_by_va
            } - drift_names
            for va, (module, name) in names_by_va.items():
                if name in drift_names or name in missing_names:
                    status = DATA_STATUS_DRIFT
                elif name in matched_names or va in built_bytes:
                    status = DATA_STATUS_VERIFIED
                else:
                    status = DATA_STATUS_UNCHECKED
                if entries[(module, va)].get("status") != status:
                    set_data_field(cfg.metadata_dir, va, "status", status, module)
        if not json_output:
            console.print(
                f"data: {data_report['matched']} matched, "
                f"{len(data_report['mismatched'])} mismatched, "
                f"{len(data_report['missing'])} missing"
            )
            for m in data_report["mismatched"][:15]:
                console.print(
                    f"  [red]FAIL[/red] {m['name']} ({m['va']}): first diff at +{m['first_diff']}"
                )
            for name in data_report["missing"][:15]:
                console.print(f"  [yellow]MISSING[/yellow] {name} (no built bytes)")

    text_report: dict[str, Any] | None = None
    if text:
        from rebrew.text_audit import audit_text, collect_actual_vas

        built_path = built or (cfg.root / "build" / cfg.target_name)
        if not built_path.exists():
            error_exit(
                f"{built_path} not found — build the project first (or pass --built <path>)",
                json_mode=json_output,
            )
        expected = _expected_text_functions(cfg)
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
            "misplaced_list": [r for r in rows if r["status"] != "OK"][:15],
        }
        if not json_output:
            console.print(
                f"text: {len(expected)} functions  correct-VA: {n_ok}  "
                f"misplaced: {n_bad}  missing: {n_missing}"
            )
            for r in text_report["misplaced_list"]:
                if r["status"] == "MISPLACED":
                    console.print(
                        f"  [red]MISPLACED[/red] {r['symbol']:32} "
                        f"exp {int(r['expected'], 16):#010x}  "
                        f"our {int(r['actual'], 16):#010x}  d {r['delta']:+#x}"
                    )
                else:
                    console.print(
                        f"  [yellow]MISSING[/yellow] {r['symbol']:32} "
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
                for area in ("sections", "exports", "imports", "rsrc", "headers"):
                    part = whole_report[area]
                    if not part["match"]:
                        console.print(f"  [yellow]{area}[/yellow]: {part}")
                layout = whole_report["layout"]
                if not layout["match"]:
                    console.print(
                        f"  [yellow]layout[/yellow]: {layout['status']} — "
                        "regenerate with rebrew gen-layout"
                    )

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
    ) = prepare_entries(
        cfg,
        full,
        json_output,
        context=compile_context,
    )

    total = len(unique_entries)

    # --nolib (reccmp equivalent): drop LIBRARY-marked functions entirely —
    # from the work list, the cached results already counted, and the size
    # audit — so the gate reflects game code only.  Excluded functions are
    # neither compiled nor counted, exactly like reccmp's --nolib filter.
    library_excluded = 0
    nolib_excluded_keys: set[str] = set()
    if nolib:
        lib_vas = {e.va for e in unique_entries if getattr(e, "marker_type", "") == "LIBRARY"}
        if lib_vas:
            lib_keys = {f"0x{v:08x}" for v in lib_vas}
            nolib_excluded_keys = lib_keys
            unique_entries = [e for e in unique_entries if e.va not in lib_vas]
            results = [r for r in results if r.get("va") not in lib_keys]
            fail_details = [(e, m) for e, m in fail_details if e.va not in lib_vas]
            size_divergences = [d for d in size_divergences if d.get("va") not in lib_keys]
            missing_sizes = [d for d in missing_sizes if d.get("va") not in lib_keys]
            # Recompute the pre-compile counts from the filtered structures —
            # the cached rows that were dropped are no longer "results".
            passed = sum(1 for r in results if r.get("passed", False))
            failed = len(fail_details)
            library_excluded = len(lib_vas)
            total = len(unique_entries)
    if library_excluded and not json_output:
        console.print(
            f"[dim]--nolib: excluded {library_excluded} LIBRARY function(s) from verification[/dim]"
        )

    cached_vas = {r["va"] for r in results}
    v_passed, v_failed, v_fail_details, v_results, deferred = run_verification(
        [e for e in unique_entries if f"0x{e.va:08x}" not in cached_vas],
        cfg,
        jobs,
        total,
        cached_count,
        json_output,
        compile_context,
    )
    passed += v_passed
    failed += v_failed
    fail_details.extend(v_fail_details)
    results.extend(v_results)

    # Always promote/demote STATUS metadata to match verification results
    _apply_or_preview_status(deferred, cfg, dry_run)

    results.sort(key=lambda r: r["va"])

    # Overlay PROVEN status from metadata onto results.  PROVEN is a
    # post-verify promotion (from `rebrew prove`) that byte-level comparison
    # cannot detect.  Preserve it only over the byte states a proven function
    # legitimately produces — its compiled bytes differ from the target, so
    # the byte compare yields NEAR_MATCHING or SIZE_MISMATCH.  COMPILE_ERROR,
    # EXTRACT_ERROR, MISSING_FILE, or STUB mean the source no longer builds
    # or the annotation changed: the PROVEN claim is stale and must not be
    # masked as a pass.
    proven_vas: set[str] = {
        f"0x{entry.va:08x}" for entry in unique_entries if getattr(entry, "status", "") == "PROVEN"
    }
    # A PROVEN claim is honored over the byte states a proven function
    # legitimately produces: NEAR_MATCHING / SIZE_MISMATCH (bytes differ
    # structurally). A blocker-documented STUB is also legitimate now —
    # `rebrew prove` accepts those (developed function parked at a wall,
    # classifier <60% on a real body), so verify must not demote a fresh
    # prove-earned PROVEN back to STUB.
    _proven_compatible = ("NEAR_MATCHING", "SIZE_MISMATCH")
    _blocker_documented_stub_vas: set[str] = {
        f"0x{entry.va:08x}"
        for entry in unique_entries
        if getattr(entry, "status", "") == "PROVEN"
        and bool(getattr(entry, "blocker", "") or getattr(entry, "blocker_delta", 0))
    }
    overlaid_vas: set[str] = set()
    # Raw byte-level truth for overlaid entries — the verify cache must store
    # the result as compiled, not the metadata-derived PROVEN.  The overlay is
    # re-applied from CURRENT metadata at every report run (including cached
    # results), so baking PROVEN into the cache would mask a later STATUS
    # demotion with a stale cached pass.
    raw_statuses: dict[str, tuple[str, bool]] = {}
    if proven_vas:
        for r in results:
            compatible = r["status"] in _proven_compatible or (
                r["status"] == "STUB" and r["va"] in _blocker_documented_stub_vas
            )
            if r["va"] in proven_vas and compatible:
                raw_statuses[r["va"]] = (r["status"], bool(r.get("passed", False)))
                was_failed = not r.get("passed", False)
                r["status"] = "PROVEN"
                r["passed"] = True
                overlaid_vas.add(r["va"])
                if was_failed:
                    passed += 1
                    failed -= 1
        # Remove only the OVERLAID functions from fail_details (they may have
        # been added from stale cache entries before the overlay).  A PROVEN
        # function that now fails as COMPILE_ERROR stays in the failure list
        # the overlay must not hide its diagnostic.
        fail_details = [(e, m) for e, m in fail_details if f"0x{e.va:08x}" not in overlaid_vas]

        # Flag stale PROVEN claims: metadata says PROVEN but the byte compile
        # cannot support it (source no longer builds, annotation changed, or
        # the status was hand-claimed).  The real byte result stands and a
        # metadata: warning is emitted — a claimed PROVEN is only honored
        # over the byte states a proven function legitimately produces
        # (metadata-review F2).  The demotion is written through (force —
        # PROVEN stickiness protects earned claims, but a STUB/COMPILE_ERROR
        # body demonstrably no longer contains the proven code, so the claim
        # is void and the warning must fire exactly once).
        # A stale claim is a byte state that cannot support PROVEN.  Two
        # statuses are excluded: EXACT/RELOC are the documented PROVEN upgrade
        # (`should_promote_status` allows PROVEN → EXACT/RELOC, and the
        # promotion above already wrote it), and INTERNAL_ERROR is a tooling
        # crash, not a verdict — it is not in metadata's KNOWN_STATUSES, so
        # persisting it over PROVEN would store an invalid status (and log a
        # phantom demotion for a function whose bytes were never compared).
        stale_proven = sorted(
            r["va"]
            for r in results
            if r["va"] in proven_vas
            and r["va"] not in overlaid_vas
            and r["status"] not in ("EXACT", "RELOC", "INTERNAL_ERROR")
        )
        if stale_proven and not dry_run:
            from rebrew.metadata import update_statuses_batch

            by_va = {r["va"]: r for r in results}
            by_entry = {f"0x{e.va:08x}": e for e in unique_entries}
            update_statuses_batch(
                cfg.metadata_dir,
                [
                    {
                        "module": getattr(by_entry[va], "module", "") or "",
                        "va": by_entry[va].va,
                        "new_status": by_va[va]["status"],
                        "clear_blockers": False,
                        "force": True,
                        "updated_by": "verify",
                    }
                    for va in stale_proven
                    if getattr(by_entry.get(va), "module", "") and by_va[va]["status"] != "PROVEN"
                ],
            )
        for va in stale_proven:
            status = next(r["status"] for r in results if r["va"] == va)
            console.print(
                f"  [yellow]metadata: warning:[/yellow] PROVEN claim for {va} not "
                f"backed by a byte-match (compiled: {status}) — demoted to the "
                "real byte result; re-run rebrew verify once the code byte-matches"
            )

    timestamp = datetime.now(UTC).isoformat()
    # Single-pass status counting instead of 7 separate iterations.
    _status_counts: dict[str, int] = {}
    for _r in results:
        _s = _r["status"]
        _status_counts[_s] = _status_counts.get(_s, 0) + 1
    report = {
        "schema_version": 1,
        "timestamp": timestamp,
        "target": cfg.target_name,
        "binary": str(cfg.target_binary),
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
            "proven": _status_counts.get("PROVEN", 0),
            "stub": _status_counts.get("STUB", 0),
            "matching": _status_counts.get("NEAR_MATCHING", 0),
            "size_mismatch": _status_counts.get("SIZE_MISMATCH", 0),
            "compile_error": _status_counts.get("COMPILE_ERROR", 0),
            "missing_file": _status_counts.get("MISSING_FILE", 0),
            # Byte-identical accounting: PROVEN is semantic equivalence, not a
            # byte match — for a byte-identical goal only exact+reloc count.
            "byte_matched": _status_counts.get("EXACT", 0) + _status_counts.get("RELOC", 0),
            "library_excluded": library_excluded,
            "orphans_pruned": orphans_pruned,
        },
        "size_divergences": size_divergences,
        "missing_sizes": missing_sizes,
        "duplicate_vas": duplicate_vas,
        "results": results,
        "data": data_report,
        "text": text_report,
        "whole_binary": whole_report,
    }

    if size_divergences and not json_output:
        console.print(
            f"[yellow]warning:[/yellow] {len(size_divergences)} function(s) have annotation "
            "SIZE differing from the binary-derived size; run with --json for details"
        )

    sizes_fixed = 0
    if fix_sizes and (size_divergences or missing_sizes):
        all_size_fixes = size_divergences + missing_sizes
        sizes_fixed = _apply_size_fixes(cfg, all_size_fixes, dry_run)
        if not json_output:
            for d in all_size_fixes:
                action = "Would fix" if dry_run else "Fixed"
                console.print(
                    f"  {action} {d['va']} SIZE {d['annotation_size']} -> "
                    f"{d['binary_size']} ({d['name']})"
                )
            if dry_run:
                console.print(
                    f"[dim]{len(all_size_fixes)} size fix(es) — re-run without "
                    "--dry-run to write[/dim]"
                )
        report["sizes_fixed"] = sizes_fixed
        if not dry_run and sizes_fixed:
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
    # preserved below, and the compile cache is skipped too so a CI failure
    # leaves no new cache entries behind.
    diff_result: dict[str, Any] | None = None
    if diff_mode and previous_report is not None:
        diff_result = diff_reports(previous_report, report)
    gate_failed = _gate_fails(
        diff_result,
        failed,
        text_misplaced=text_report["misplaced"] if text_report else 0,
    )

    # A context-scoped run stores nothing: its verdicts were earned under
    # declarations the cache entry type cannot record, so writing them would
    # serve them back to a later context-free run that never compiled them.
    if not dry_run and not (diff_mode and gate_failed) and compile_context is None:
        cache_path = cfg.root / ".rebrew" / "verify_cache.json"
        try:
            _save_verify_cache(
                cache_path,
                cfg,
                results,
                unique_entries,
                raw_statuses,
                preserve_keys=nolib_excluded_keys,
            )
        except (OSError, TypeError):
            # Warn on stderr regardless of json mode — silent cache-I/O
            # failures degrade performance invisibly.
            logging.warning("Could not write verify cache to %s", cache_path)

    if json_output or output_path or diff_mode or not dry_run:
        report_json = json.dumps(report, indent=2)
        # In --compare mode the report IS the baseline for future runs — a
        # regressed run must not overwrite the last good baseline, or the
        # gate would self-heal on the next invocation.  Plain verify always
        # records the report (pre-existing failures are the baseline's
        # business); --compare advances it only on a passing gate.  The
        # default location is honored in PLAIN mode too — the help promises
        # "default: project db_dir/verify_results.json", and a first
        # `rebrew verify --compare` needs a baseline from a prior plain run
        # (previously nothing was written unless --json/--output/--compare
        # were passed, so --compare's first run was a silent no-op gate).
        if not dry_run and not (diff_mode and gate_failed):
            out_file.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(out_file, report_json, encoding="utf-8")
            if not json_output:
                console.print(f"Report written to {out_file}")

        if json_output:
            if diff_mode:
                payload: dict[str, Any] = {"report": report, "diff": diff_result}
                if diff_warning:
                    payload["warning"] = diff_warning
                json_print(payload)
            else:
                json_print(report)

            _raise_if_regression(
                diff_result,
                failed,
                text_misplaced=text_report["misplaced"] if text_report else 0,
            )
            return

    _print_results(
        results,
        fail_details,
        diff_result,
        diff_warning,
        diff_mode,
        summary,
        total,
        passed,
        failed,
    )

    _raise_if_regression(
        diff_result,
        failed,
        text_misplaced=text_report["misplaced"] if text_report else 0,
    )


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
        # were N full rewrites — perf-review F2).
        set_fields_batch(cfg.metadata_dir, updates)
        return len(updates)
    return 0


def _gate_fails(
    diff_result: dict[str, Any] | None, failed: int, *, text_misplaced: int = 0
) -> bool:
    """True when the CI regression gate must fail this run.

    With a baseline (*diff_result*), only regressions and newly-broken
    entries fail the run — pre-existing failures are the baseline's
    business.  Without a baseline, any failed function fails the run.
    A misplaced ``--text`` function fails the gate in both modes: placement
    drift means the link no longer reproduces the reference layout, which no
    byte-level verdict covers.
    """
    if text_misplaced:
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


def _raise_if_regression(
    diff_result: dict[str, Any] | None, failed: int, *, text_misplaced: int = 0
) -> None:
    """Raise ``typer.Exit(EXIT_MISMATCH)`` per the CI regression gate.

    Shared gate logic lives in :func:`_gate_fails`; this raises on it.
    """
    if _gate_fails(diff_result, failed, text_misplaced=text_misplaced):
        raise typer.Exit(code=EXIT_MISMATCH)


# ---------------------------------------------------------------------------
# Phase helpers
# ---------------------------------------------------------------------------


def _load_previous_report(
    out_file: Path,
    diff_mode: bool,
    json_output: bool,
) -> tuple[dict[str, Any] | None, str | None]:
    """Load previous verify report for --compare mode."""
    if not diff_mode:
        return None, None

    diff_warning: str | None = None
    previous_report: dict[str, Any] | None = None

    if not out_file.exists():
        diff_warning = f"No previous verify report at {out_file}; skipping diff"
    else:
        try:
            loaded = json.loads(out_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                previous_report = loaded
            else:
                diff_warning = f"Previous verify report at {out_file} is invalid JSON object"
        except (OSError, json.JSONDecodeError) as exc:
            diff_warning = f"Could not read previous verify report at {out_file}: {exc}"

    if diff_warning and not json_output:
        console.print(f"[yellow]warning:[/yellow] {diff_warning}")

    return previous_report, diff_warning


def _alignment_padding(ann_size: int, canonical: int) -> bool:
    """Whether the canonical size is just the annotation rounded up to the
    next 16-byte function-alignment boundary (functions start 16-aligned, so
    the function-list extent includes the trailing pad). The annotation is the
    true code length and the two agree on the code; this is not a divergence."""
    pad = canonical - ann_size
    if not (0 < pad <= 15):
        return False
    return (ann_size + pad) % 16 == 0


def _skip_validated_overcount(ann_size: int, canonical: int, status: str | None) -> bool:
    """Whether an over-counted annotation (ann > canonical) is proven correct.

    A function whose bytes EXACT/RELOC-matched at the annotation size has
    exercised exactly that many real bytes: the canonical side (a Ghidra
    fragment or a stale list entry) is the unreliable one, and flagging it as
    an annotation bug is noise. Under-counts (ann < canonical) are never
    skipped: a truncated annotation can false-EXACT on a prefix."""
    return ann_size > canonical and status in ("EXACT", "RELOC")


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
]:
    """Scan reversed_dir, deduplicate entries, and check the verify cache.

    Returns (unique_entries, passed, failed, fail_details, results,
    cached_count, size_divergences, missing_sizes, duplicate_vas).
    ``duplicate_vas`` names the dropped sources: ``{"va", "kept", "dropped"}``
    per duplicate-VA annotation (first source wins, the rest never compile).

    With *context* set the result cache is not consulted at all: a cached
    verdict was earned by compiling the bare source, and the cache entry type
    records no context digest to compare against, so serving it under a
    context would report a match the context never produced.  Re-verifying is
    the only correct answer until the entry type carries the digest.
    """
    reversed_dir = cfg.reversed_dir
    ghidra_json_path = reversed_dir / FUNCTION_STRUCTURE_JSON

    console.print(f"Scanning {reversed_dir}...")
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    funcs = cached_function_list(cfg)
    registry = build_function_registry(funcs, cfg, ghidra_json_path, cfg.target_binary)

    unique_vas = {e.va for e in entries}
    ghidra_count, list_count, both_count, thunk_count = count_detection_sources(registry)
    console.print(
        f"Found {len(entries)} annotations ({len(unique_vas)} unique VAs) "
        f"from {len(registry)} total functions "
        f"(list: {list_count}, ghidra: {ghidra_count}, both: {both_count}, "
        f"thunks: {thunk_count})"
    )

    if not cfg.target_binary.exists():
        error_exit(f"{cfg.target_binary} not found", json_mode=json_output)

    # Filter out non-compilable annotations and deduplicate by VA
    seen_vas: set[int] = set()
    unique_entries: list[Annotation] = []
    data_count = 0
    library_header_count = 0
    duplicate_vas: list[tuple[int, str, str]] = []
    for entry in sorted(entries, key=lambda x: x.va):
        if getattr(entry, "marker_type", "FUNCTION") in ("DATA", "GLOBAL", "BSS", "RODATA", "VTBL"):
            data_count += 1
            continue
        fp = getattr(entry, "filepath", "")
        if fp and fp.endswith(".h"):
            library_header_count += 1
            continue
        if entry.va not in seen_vas:
            seen_vas.add(entry.va)
            unique_entries.append(entry)
        else:
            # Duplicate VA: the first source wins and the rest are DROPPED
            # from this run (they are never compiled).  Say so loudly — a
            # silent keep-first hides a stale annotation in CI.
            kept = next(e for e in unique_entries if e.va == entry.va)
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
            console.print(f"[yellow]warning:[/yellow] {msg}")
        if json_output:
            console.print(
                "[yellow]warning:[/yellow] "
                f"{len(duplicate_vas)} duplicate VA(s) dropped "
                "(see 'duplicate_vas' in the report JSON)"
            )
    if data_count and not json_output:
        console.print(f"Skipped {data_count} DATA/GLOBAL/BSS/RODATA/VTBL entries (not compilable)")
    if library_header_count and not json_output:
        console.print(
            f"Skipped {library_header_count} library header entries (identified, not compiled)"
        )

    # Check cache
    passed = 0
    failed = 0
    fail_details: list[tuple[Annotation, str]] = []
    results: list[dict[str, Any]] = []

    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    verify_cache_obj = (
        None if (full or context is not None) else _load_verify_cache(cache_path, cfg)
    )
    entries_cache: dict[str, VerifyCacheEntry] = (
        verify_cache_obj.entries if verify_cache_obj else {}
    )
    cached_count = 0

    for entry in unique_entries:
        va_key = f"0x{entry.va:08x}"
        cached_entry = entries_cache.get(va_key)
        if cached_entry is None:
            continue

        # A cached PROVEN result is impossible under the current writer (the
        # cache stores raw byte results only — the PROVEN overlay is applied
        # at report time from CURRENT metadata).  Any cached PROVEN therefore
        # comes from pre-fix code that baked the overlay in, and cannot be
        # trusted after a metadata STATUS demotion: the stale pass would mask
        # the demotion forever.  Treat it as a miss and re-verify once.
        if cached_entry.result.status == "PROVEN":
            continue

        if cached_entry.filepath != getattr(entry, "filepath", ""):
            continue

        # CFLAGS/TOOLCHAIN come from rebrew-functions.toml AND the config
        # fallback chain (per-function → per-library rebrew-libraries.toml →
        # preset → [compiler].cflags), so a metadata edit is invisible to the
        # source hash below.  The entry stores the RESOLVED effective values
        # the compile used; compare against the freshly-resolved ones so a
        # `rebrew library set` / `rebrew cfg set-cflags` / [compiler].cflags
        # edit invalidates cached results (previously only the metadata CFLAGS
        # were compared, leaving stale EXACT/RELOC served after a config
        # change — and TOOLCHAIN was not stored at all, so a library toolchain
        # override swap served stale results for every function under it).
        import shlex

        from rebrew.cli import resolve_compile_overrides

        _tc, _cf2 = resolve_compile_overrides(
            cfg,
            (cfg.reversed_dir / entry.filepath).parent if entry.filepath else cfg.root,
            getattr(entry, "toolchain", ""),
            getattr(entry, "cflags", ""),
            getattr(entry, "module", ""),
        )
        # Legacy entries written before the toolchain field existed carry ""
        # re-verify them once (same pattern as cflags/headers_fp).
        if not cached_entry.toolchain:
            continue
        if cached_entry.toolchain != (_tc or _DEFAULT_TOOLCHAIN):
            continue

        # Per-target defines are compile inputs invisible to the source hash
        # and cflags string — a defines edit (a version switch in a shared
        # multi-version source) must invalidate the entry.
        if not cached_entry.defines:
            continue  # legacy entry
        if cached_entry.defines != (
            ",".join(sorted(getattr(cfg, "defines", None) or [])) or "(none)"
        ):
            continue

        if cached_entry.cflags != _cf2:
            # Raw strings differ — but only a change that could alter the
            # compiled object is material.  A rebrew-libraries.toml edit that
            # merely reorders flags (e.g. preset vs override ordering) or
            # deduplicates them compiles identically, so compare the
            # canonicalized equivalence class (observational equivalence:
            # the compiler is the observer) and treat it as a hit.  A legacy
            # or degenerate entry ("" on either side) is re-verified once.
            if not (cached_entry.cflags and _cf2):
                continue
            from rebrew.compile_cache import canonicalize_cflags

            if canonicalize_cflags(shlex.split(cached_entry.cflags)) != canonicalize_cflags(
                shlex.split(_cf2)
            ):
                continue

        # SIZE is metadata-only too (catalog --fix-sizes rewrites it without
        # touching the .c); a size change must invalidate the cached result.
        if cached_entry.size != (entry.size or 0):
            continue

        filepath = cfg.reversed_dir / getattr(entry, "filepath", "")
        if not filepath.exists():
            continue

        # Per-source header dependency: editing a header this source reaches
        # must invalidate the entry (the old global headers_hash gate
        # re-verified the whole cache on any header change).  Legacy entries
        # written before headers_fp existed carry "" and are re-verified once,
        # like the cflags/size legacy handling.
        if not cached_entry.headers_fp:
            continue
        if cached_entry.headers_fp != _entry_headers_fp(cfg, filepath, _cf2):
            continue

        try:
            current_mtime = filepath.stat().st_mtime_ns
        except OSError:
            # File deleted between exists() and stat() — treat as a miss.
            continue
        if current_mtime != cached_entry.mtime_ns:
            try:
                current_hash = _source_hash(filepath)
            except OSError:
                continue
            if current_hash != cached_entry.source_hash:
                continue

        results.append(cached_entry.result.to_dict())
        if cached_entry.result.passed:
            passed += 1
        else:
            failed += 1
            fail_details.append((entry, str(cached_entry.result.message)))
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
    )


def run_verification(
    entries_to_verify: list[Annotation],
    cfg: Any,
    jobs: int,
    total: int,
    cached_count: int,
    json_output: bool,
    context: "CompileContext | None" = None,
) -> tuple[
    int, int, list[tuple[Annotation, str]], list[dict[str, Any]], list[tuple[Annotation, str, int]]
]:
    """Run parallel verification and classify results.

    Returns (passed, failed, fail_details, results, deferred_fixes).
    *context* is threaded to every ``verify_entry`` so each result carries
    the digest of the context it was compiled under.
    """
    passed = 0
    failed = 0
    internal_errors = 0
    fail_details: list[tuple[Annotation, str]] = []
    results: list[dict[str, Any]] = []
    deferred_fixes: list[tuple[Annotation, str, int]] = []

    fresh_count = len(entries_to_verify)
    # The CLI -j flag bypasses config's _positive_int validation — clamp
    # here so `-j 0` (or negative) cannot crash ThreadPoolExecutor.
    effective_jobs = max(1, min(jobs, fresh_count)) if fresh_count else 1

    try:
        from rebrew.compile_cache import get_compile_cache

        compile_cache = get_compile_cache(cfg.root, getattr(cfg, "cache_backend", "diskcache"))
    except (ImportError, OSError):
        compile_cache = None

    # Shared once for the whole batch — same catalog `rebrew test` uses.
    # Fail closed: a VA-map scan failure aborts the run instead of masking
    # relocs against an empty map (false RELOC).
    from rebrew.coff_reloc import CatalogScanError, build_name_to_va

    try:
        name_to_va = build_name_to_va(cfg)
    except CatalogScanError as exc:
        error_exit(str(exc), json_mode=json_output)

    def _verify(
        e: Annotation,
    ) -> tuple[Annotation, "CompareResult"]:
        return (
            e,
            verify_entry(e, cfg, cache=compile_cache, name_to_va=name_to_va, context=context),
        )

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

        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_jobs) as pool:
            # Bounded submission: submitting every entry up front (verify
            # batches can be thousands of functions) builds one Future + one
            # queued task per entry — the exact pattern flag_sweep was
            # deliberately changed away from (compiler.py:541).  Submit
            # effective_jobs at a time and refill as each completes, so
            # memory stays proportional to the worker count, not the corpus.
            futures: dict[concurrent.futures.Future[Any], Annotation] = {}
            entry_iter = iter(entries_to_verify)
            for _ in range(min(effective_jobs, len(entries_to_verify))):
                with contextlib.suppress(StopIteration):
                    e = next(entry_iter)
                    futures[pool.submit(_verify, e)] = e
            # Drain-and-refill: as_completed snapshots at call time, so new
            # submissions need the outer while to re-arm the iterator.
            while futures:
                for future in concurrent.futures.as_completed(futures):
                    entry = futures.pop(future)
                    is_internal_error = False
                    try:
                        _entry, result = future.result()
                    except Exception as exc:
                        is_internal_error = True
                        internal_errors += 1
                        log.debug(
                            "Internal error verifying %s",
                            getattr(entry, "name", "?"),
                            exc_info=True,
                        )
                        if internal_errors <= 5:
                            console.print(
                                f"[yellow]warning:[/yellow] internal error verifying "
                                f"{getattr(entry, 'name', '?')}: {exc}"
                            )
                        from rebrew.compile import CompareResult

                        result = CompareResult(
                            matched=False,
                            status="INTERNAL_ERROR",
                            match_percent=0.0,
                            delta=0,
                            obj_bytes=None,
                            reloc_offsets=None,
                            message=f"INTERNAL_ERROR: {exc}",
                        )
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
                    # in rebrew-functions.toml (previously EXACT/NEAR_MATCHING were
                    # permanently demoted to COMPILE_ERROR).
                    if not is_internal_error:
                        deferred_fixes.append((entry, result.status, result.delta))

                    results.append(
                        {
                            "va": f"0x{entry.va:08x}",
                            "name": name,
                            "symbol": getattr(entry, "symbol", "") or "_" + name,
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

    if internal_errors > 0 and not json_output:
        console.print(
            f"[yellow]warning:[/yellow] {internal_errors} function(s) failed with internal errors "
            f"(tooling failures — counted as failures so the gate fails closed in "
            f"both plain and --compare modes)"
        )

    return passed, failed, fail_details, results, deferred_fixes


def _apply_or_preview_status(
    deferred_fixes: list[tuple[Annotation, str, int]], cfg: Any, dry_run: bool
) -> None:
    """Apply STATUS metadata updates, or preview them with ``--dry-run``."""
    if not deferred_fixes:
        return
    if dry_run:
        for entry, status, _delta in deferred_fixes:
            module: str = getattr(entry, "module", "") or ""
            # Mirror apply_status_updates' decision so the preview only claims
            # updates a real run would actually write: sticky statuses (PROVEN)
            # are never demoted and a STUB's placeholder size-mismatch keeps
            # the user's classification.
            if not should_promote_status(getattr(entry, "status", ""), status):
                continue
            console.print(
                f"[dim]would update STATUS → {status} for 0x{entry.va:x} ({module})[/dim]"
            )
        return
    apply_status_updates(deferred_fixes, cfg)


def apply_status_updates(
    deferred_fixes: list[tuple[Annotation, str, int]],
    cfg: Any,
) -> None:
    """Promote/demote STATUS metadata to match verification results.

    Called unconditionally after verification — both ``rebrew verify``
    and ``rebrew test --all`` always keep metadata in sync with the
    compile-and-compare truth.

    PROVEN status is sticky and never demoted.
    """
    updates: list[dict[str, Any]] = []
    for entry, status, _delta in deferred_fixes:
        fp = cfg.reversed_dir / getattr(entry, "filepath", "")
        if not fp.exists():
            continue
        module: str = getattr(entry, "module", "") or ""
        if not module:
            continue
        current_status = getattr(entry, "status", "")
        # Sticky statuses (PROVEN) are never demoted; a STUB's placeholder
        # always size-mismatches (keep the user's classification); unchanged
        # status is a no-op.  All decided by should_promote_status.
        if not should_promote_status(current_status, status):
            continue
        updates.append(
            {
                "module": module,
                "va": entry.va,
                "new_status": status,
                "clear_blockers": is_matched(status),
                "updated_by": "verify",
            }
        )

    try:
        # Batch all STATUS writes into one TOML read-modify-write
        # (perf-review F2: per-entry RMW was ~9s at 260 entries, minutes at
        # thousands).
        from rebrew.metadata import update_statuses_batch

        update_statuses_batch(cfg.metadata_dir, updates)
    except OSError as exc:
        # STATUS sync is best-effort — a read-only or unwritable metadata
        # file must not abort the whole verify run (and lose the report
        # the user waited for).  Warn and keep the verification results.
        logging.warning("Could not update STATUS metadata: %s", exc)


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
) -> None:
    """Print diff report, summary table, and failure details."""
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
                f"{item['name']}  {item['previous_status']} -> {item['current_status']}  "
                f"(delta: {item['delta']}B)"
            )

        console.print()
        console.print(f"{len(improvements)} improvements:")
        for item in improvements:
            console.print(
                f"  {item['name']}  {item['previous_status']} -> {item['current_status']}"
            )

        if new_items:
            console.print()
            console.print(f"{len(new_items)} new:")
            for item in new_items:
                console.print(f"  {item['name']}  {item['status']}")

        if removed:
            console.print()
            console.print(f"{len(removed)} removed:")
            for item in removed:
                console.print(f"  {item['name']}  {item['status']}")

        if diff_warning:
            console.print()
            console.print(f"Warning: {diff_warning}")

        if regressions:
            console.print()
            console.print(
                "[dim]Tip: run 'rebrew diff <va>' on the regressed functions "
                "to see the byte differences[/dim]"
            )

    if show_summary:
        console.print()
        table = Table(title="Verification Summary", show_header=True)
        table.add_column("VA", style="cyan")
        table.add_column("Symbol", style="magenta")
        table.add_column("Size", justify="right")
        table.add_column("Status", style="bold")
        table.add_column("Match %", justify="right")
        table.add_column("Delta", justify="right")
        table.add_column("Sim %", justify="right")

        for r in results:
            st = r["status"]
            color = STATUS_COLORS.get(st, "red")
            st_str = f"[{color}]{st}[/{color}]"

            pct = f"{r['match_percent']:.1f}%" if st in ("STUB", "NEAR_MATCHING") else "-"
            dt = f"{r.get('delta', 0)}B" if st in ("STUB", "NEAR_MATCHING") else "-"
            sim = r.get("similarity")
            sim_str = f"{sim:.1f}%" if isinstance(sim, (int, float)) else "-"
            table.add_row(r["va"], r["name"], f"{r['size']}B", st_str, pct, dt, sim_str)

        console.print(table)

        exact = sum(1 for r in results if r["status"] == "EXACT")
        reloc = sum(1 for r in results if r["status"] == "RELOC")
        proven = sum(1 for r in results if r["status"] == "PROVEN")
        near_matching = sum(1 for r in results if r["status"] == "NEAR_MATCHING")
        stub = sum(1 for r in results if r["status"] == "STUB")

        stat_table = Table(title="STATUS Breakdown", show_header=False)
        stat_table.add_column("Category", style="cyan")
        stat_table.add_column("Count", justify="right")
        stat_table.add_row("EXACT", str(exact))
        stat_table.add_row("RELOC", str(reloc))
        if proven:
            stat_table.add_row("PROVEN", str(proven))
        stat_table.add_row("NEAR_MATCHING", str(near_matching))
        stat_table.add_row("STUB", str(stub))

        console.print(stat_table)

    # Print failures
    if fail_details:
        console.print()

        # Build lookup for results to get match_percent
        res_by_va = {int(r["va"], 16): r for r in results}

        # Sort failures: lowest match_percent first, then by VA
        def _fail_sort_key(item: tuple[Annotation, str]) -> tuple[float, int]:
            entry, _ = item
            r = res_by_va.get(entry.va)
            mp = r.get("match_percent") if r else 0.0
            return (mp or 0.0, entry.va)

        for entry, msg in sorted(fail_details, key=_fail_sort_key):
            res_dict = res_by_va.get(entry.va)
            st = str(res_dict["status"]) if res_dict else "FAIL"
            fp = getattr(entry, "filepath", "")
            ln = getattr(entry, "line", 0)
            fp_suffix = f" [dim]({fp}:{ln})[/]" if fp and ln else f" [dim]({fp})[/]" if fp else ""
            if st in ("STUB", "NEAR_MATCHING"):
                match_pct = float(res_dict.get("match_percent", 0.0)) if res_dict else 0.0
                sim = res_dict.get("similarity") if res_dict else None
                sim_str = f" / sim {sim:.1f}" if isinstance(sim, (int, float)) else ""
                console.print(
                    rf"  [red bold]\[{match_pct:.1f}%{sim_str}][/] 0x{entry.va:08X} {entry.name}{fp_suffix}: {msg}"
                )
            elif st in (
                "COMPILE_ERROR",
                "EXTRACT_ERROR",
                "MISSING_FILE",
                "MISSING_SIZE",
                "INVALID_VA",
            ):
                console.print(
                    rf"  [red bold]\[{st}][/] 0x{entry.va:08X} {entry.name}{fp_suffix}: {msg}"
                )
            else:
                console.print(
                    rf"  [red bold]\[FAIL][/] 0x{entry.va:08X} {entry.name}{fp_suffix}: {msg}"
                )

    # Summary
    style = "green" if failed == 0 else "red"
    result_text = Text()
    result_text.append("\nVerification: ")
    result_text.append(f"{passed}/{total} passed", style=style)
    if failed:
        result_text.append(", ")
        result_text.append(f"{failed} failed", style="red")
    console.print(result_text)


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
