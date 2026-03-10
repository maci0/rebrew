"""verify.py — Batch compile-and-compare for all reversed functions.

Compiles every annotated ``.c`` file and compares object bytes against the
target binary.  Results are classified by :class:`~rebrew.compile.CompareResult`
(EXACT, RELOC, STUB, COMPILE_ERROR, …).

After verification, STATUS is always promoted/demoted in
``rebrew-function.toml`` via :func:`~rebrew.metadata.update_source_status`
— the ``.c`` files are **never modified**.  PROVEN status is sticky and
never demoted.

With ``--compare`` it compares the current run against the last saved
``db/verify_results.json`` and exits with code 1 on any regression (suitable
for CI / pre-commit hooks).
"""

import concurrent.futures
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.compile import CompareResult
    from rebrew.compile_cache import CompileCache

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from rebrew.annotation import Annotation
from rebrew.catalog import (
    build_function_registry,
    parse_function_list,
    scan_reversed_dir,
)
from rebrew.cli import TargetOption, error_exit, is_matched, json_print, require_config
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.metadata import update_source_status
from rebrew.utils import atomic_write_text

# ---------------------------------------------------------------------------
# Verification (--verify)
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


def verify_entry(
    entry: Annotation,
    cfg: ProjectConfig,
    cache: "CompileCache | None" = None,
) -> "CompareResult":
    """Compile a .c file and compare output bytes against DLL.

    Delegates to ``compile_and_compare`` for the compile→extract→compare flow.
    When *cache* is provided, compilation results are reused across calls
    for the same source content + flags — critical for multi-function files
    where the same .c is compiled once and multiple symbols extracted.
    """
    from rebrew.compile import compile_and_compare

    cfile = cfg.reversed_dir / entry.filepath
    if not cfile.exists():
        return _failed_result("MISSING_FILE", f"MISSING_FILE: {cfile}")

    if entry.va < 0x1000:
        return _failed_result("COMPILE_ERROR", "INVALID_VA: VA too low")
    if entry.size <= 0:
        return _failed_result("MISSING_SIZE", "MISSING_SIZE: No SIZE annotation")

    cflags_str = entry.cflags
    cflags = cflags_str if cflags_str else "/O2"
    symbol = entry.symbol if entry.symbol else "_" + entry.name

    from rebrew.binary_loader import extract_raw_bytes

    target_bytes = extract_raw_bytes(cfg.target_binary, entry.va, entry.size)
    if not target_bytes:
        return _failed_result("COMPILE_ERROR", "Cannot extract DLL bytes")

    return compile_and_compare(cfg, cfile, symbol, target_bytes, cflags, cache=cache)


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
    "EXACT": 0,
    "RELOC": 1,
    "STUB": 2,
    "NEAR_MATCHING": 2,
    "COMPILE_ERROR": 3,
    "MISSING_FILE": 4,
    "FAIL": 5,
}


def _compiler_config_hash(cfg: ProjectConfig) -> str:
    parts = [
        cfg.compiler_command,
        cfg.base_cflags,
        str(cfg.compiler_includes),
        str(cfg.compiler_libs),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _source_hash(filepath: Path) -> str:
    return hashlib.sha256(filepath.read_bytes()).hexdigest()


@dataclass
class VerifyResult:
    """Represents the verification result of a single compiled function."""

    status: str
    va: str | int
    size: int = 0
    filepath: str = ""
    name: str = ""
    symbol: str = ""
    delta: int | None = None
    match_percent: float | None = None
    passed: bool = False  # Added this field
    message: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifyResult":
        """Reconstruct a VerifyResult from a JSON dictionary."""
        return cls(
            status=str(d.get("status", "")),
            va=d.get("va", ""),
            size=int(d.get("size", 0)),
            filepath=str(d.get("filepath", "")),
            name=str(d.get("name", "")),
            symbol=str(d.get("symbol", "")),
            delta=d.get("delta"),
            match_percent=d.get("match_percent"),
            passed=bool(d.get("passed", False)),  # Added this field
            message=str(d.get("message", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert this VerifyResult to a JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class VerifyCacheEntry:
    """A single cache entry linking a source file hash to its VerifyResult."""

    source_hash: str
    filepath: str
    mtime_ns: int
    result: VerifyResult

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifyCacheEntry":
        """Reconstruct a VerifyCacheEntry from a JSON dictionary."""
        return cls(
            source_hash=str(d.get("source_hash", "")),
            filepath=str(d.get("filepath", "")),
            mtime_ns=int(d.get("mtime_ns", 0)),
            result=VerifyResult.from_dict(d.get("result", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert this VerifyCacheEntry to a JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class VerifyCache:
    """The root structure of the verification cache file."""

    version: int
    compiler_hash: str
    target: str
    entries: dict[str, VerifyCacheEntry]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifyCache":
        """Reconstruct a VerifyCache from a JSON dictionary."""
        return cls(
            version=int(d.get("version", 0)),
            compiler_hash=str(d.get("compiler_hash", "")),
            target=str(d.get("target", "")),
            entries={
                str(k): VerifyCacheEntry.from_dict(v)
                for k, v in d.get("entries", {}).items()
                if isinstance(v, dict)
            },
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert this VerifyCache to a JSON-serializable dictionary."""
        return asdict(self)


def _load_verify_cache(cache_path: Path, cfg: ProjectConfig) -> VerifyCache | None:
    if not cache_path.exists():
        return None
    try:
        data = VerifyCache.from_dict(json.loads(cache_path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError):
        return None
    if data.version != 1:
        return None
    if data.target != cfg.target_name:
        return None
    if data.compiler_hash != _compiler_config_hash(cfg):
        return None
    return data


def _save_verify_cache(
    cache_path: Path,
    cfg: ProjectConfig,
    results: list[dict[str, Any]],
    entries: list[Annotation],
) -> None:
    filepath_info: dict[str, tuple[int, str]] = {}
    for entry in entries:
        relative_path = getattr(entry, "filepath", "")
        if not relative_path:
            continue
        filepath = cfg.reversed_dir / relative_path
        if filepath.exists():
            filepath_info[relative_path] = (filepath.stat().st_mtime_ns, _source_hash(filepath))

    cache_entries: dict[str, dict[str, Any]] = {}
    for result in results:
        va_key = result["va"]
        filepath = result.get("filepath", "")
        file_info = filepath_info.get(filepath)
        if file_info is None:
            continue
        mtime, source_hash = file_info

        # Ensure result has default fields present
        res_dict = {
            "status": result.get("status", ""),
            "va": va_key,
            "size": result.get("size", 0),
            "filepath": filepath,
            "name": result.get("name", ""),
            "symbol": result.get("symbol", ""),
            "delta": result.get("delta", None),
            "match_percent": result.get("match_percent", None),
            "passed": result.get("passed", False),
            "message": result.get("message", ""),
        }

        cache_entries[str(va_key)] = {
            "source_hash": source_hash,
            "filepath": filepath,
            "mtime_ns": mtime,
            "result": res_dict,
        }

    cache_data = VerifyCache(
        version=1,
        compiler_hash=_compiler_config_hash(cfg),
        target=cfg.target_name,
        entries={str(k): VerifyCacheEntry.from_dict(v) for k, v in cache_entries.items()},
    )
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(cache_path, json.dumps(cache_data.to_dict(), indent=2), encoding="utf-8")


def diff_reports(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare two JSON verify reports and highlight changes in status or match percentage.

    Args:
        previous: The previous run's full JSON results dict.
        current: The newly generated full JSON results dict.

    Returns:
        A dict containing separated lists of 'regressions', 'fixes', and 'improvements'.

    """
    previous_results = {
        str(r["va"]): r for r in previous.get("results", []) if isinstance(r, dict) and "va" in r
    }
    current_results = {
        str(r["va"]): r for r in current.get("results", []) if isinstance(r, dict) and "va" in r
    }

    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    new_items: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    unchanged_count = 0

    fail_rank = _STATUS_RANK["FAIL"]

    for va in sorted(current_results):
        current_item = current_results[va]
        current_status = str(current_item.get("status", "FAIL"))
        current_rank = _STATUS_RANK.get(current_status, fail_rank)

        if va not in previous_results:
            new_items.append(
                {
                    "va": va,
                    "name": str(current_item.get("name", "")),
                    "status": current_status,
                }
            )
            continue

        previous_item = previous_results[va]
        previous_status = str(previous_item.get("status", "FAIL"))
        previous_rank = _STATUS_RANK.get(previous_status, fail_rank)

        if current_rank < previous_rank:
            improvements.append(
                {
                    "va": va,
                    "name": str(current_item.get("name") or previous_item.get("name", "")),
                    "previous_status": previous_status,
                    "current_status": current_status,
                    "delta": int(current_item.get("delta", 0)),
                }
            )
        elif current_rank > previous_rank:
            regressions.append(
                {
                    "va": va,
                    "name": str(current_item.get("name") or previous_item.get("name", "")),
                    "previous_status": previous_status,
                    "current_status": current_status,
                    "delta": int(current_item.get("delta", 0)),
                }
            )
        else:
            unchanged_count += 1

    for va in sorted(previous_results):
        if va in current_results:
            continue
        previous_item = previous_results[va]
        removed.append(
            {
                "va": va,
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


@app.callback(invoke_without_command=True)
def main(
    root: Path = typer.Option(
        None,
        "--root",
        help="Project root directory (auto-detected from rebrew-project.toml if omitted)",
    ),
    jobs: int | None = typer.Option(
        None,
        "-j",
        "--jobs",
        help="Number of parallel compile jobs (default: from [project].jobs or 4)",
    ),
    output_path: str | None = typer.Option(
        None, "-o", "--output", help="Write JSON report to file (default: db/verify_results.json)"
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
        help=(
            "Force full verification, ignoring cached results "
            "(also required after header/include changes)"
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rebrew verification pipeline: compile each .c and verify bytes match."""
    cfg = require_config(target=target, json_mode=json_output)
    if jobs is None:
        jobs = cfg.default_jobs

    out_file = Path(output_path) if output_path else cfg.root / "db" / "verify_results.json"
    previous_report, diff_warning = _load_previous_report(out_file, diff_mode, json_output)

    unique_entries, passed, failed, fail_details, results, cached_count = prepare_entries(
        cfg,
        full,
        json_output,
    )

    total = len(unique_entries)

    v_passed, v_failed, v_fail_details, v_results, deferred = run_verification(
        [e for e in unique_entries if not any(r["va"] == f"0x{e.va:08x}" for r in results)],
        cfg,
        jobs,
        total,
        cached_count,
        json_output,
    )
    passed += v_passed
    failed += v_failed
    fail_details.extend(v_fail_details)
    results.extend(v_results)

    # Always promote/demote STATUS metadata to match verification results
    if deferred:
        apply_status_updates(deferred, cfg)

    results.sort(key=lambda r: r["va"])

    # Overlay PROVEN status from metadata onto results.  PROVEN is a
    # post-verify promotion (from `rebrew prove`) that byte-level comparison
    # cannot detect.  We preserve it so the cache, report, and pass/fail
    # counts all stay consistent.
    proven_vas: set[str] = {
        f"0x{entry.va:08x}" for entry in unique_entries if getattr(entry, "status", "") == "PROVEN"
    }
    if proven_vas:
        for r in results:
            if r["va"] in proven_vas and r["status"] not in ("EXACT", "RELOC"):
                was_failed = not r.get("passed", False)
                r["status"] = "PROVEN"
                r["passed"] = True
                if was_failed:
                    passed += 1
                    failed -= 1
        # Remove PROVEN functions from fail_details (they may have been
        # added from stale cache entries before the overlay).
        fail_details = [(e, m) for e, m in fail_details if f"0x{e.va:08x}" not in proven_vas]

    timestamp = datetime.now(UTC).isoformat()
    report = {
        "timestamp": timestamp,
        "target": cfg.target_name,
        "binary": str(cfg.target_binary),
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "exact": sum(1 for r in results if r["status"] == "EXACT"),
            "reloc": sum(1 for r in results if r["status"] == "RELOC"),
            "proven": sum(1 for r in results if r["status"] == "PROVEN"),
            "stub": sum(1 for r in results if r["status"] == "STUB"),
            "matching": sum(1 for r in results if r["status"] == "NEAR_MATCHING"),
            "compile_error": sum(1 for r in results if r["status"] == "COMPILE_ERROR"),
            "missing_file": sum(1 for r in results if r["status"] == "MISSING_FILE"),
        },
        "results": results,
    }

    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    try:
        _save_verify_cache(cache_path, cfg, results, unique_entries)
    except (OSError, TypeError):
        if not json_output:
            console.print(f"[yellow]Warning:[/] Could not write verify cache to {cache_path}")

    diff_result: dict[str, Any] | None = None
    if diff_mode and previous_report is not None:
        diff_result = diff_reports(previous_report, report)

    if json_output or output_path or diff_mode:
        report_json = json.dumps(report, indent=2)
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

            has_regressions = bool(diff_result and diff_result["regressions"])
            if failed > 0 or has_regressions:
                raise typer.Exit(code=1)
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
        json_output,
    )

    has_regressions = bool(diff_result and diff_result["regressions"])
    if failed > 0 or has_regressions:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Phase helpers
# ---------------------------------------------------------------------------


def _load_previous_report(
    out_file: Path,
    diff_mode: bool,
    json_output: bool,
) -> tuple[dict[str, Any] | None, str | None]:
    """Load previous verify report for --diff mode."""
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
        console.print(f"[yellow]Warning:[/] {diff_warning}")

    return previous_report, diff_warning


def prepare_entries(
    cfg: Any,
    full: bool,
    json_output: bool,
) -> tuple[list[Annotation], int, int, list[tuple[Annotation, str]], list[dict[str, Any]], int]:
    """Scan reversed_dir, filter entries, check cache. Returns (unique_entries, passed, failed, fail_details, results, cached_count)."""
    reversed_dir = cfg.reversed_dir
    func_list_path = cfg.function_list
    ghidra_json_path = reversed_dir / FUNCTION_STRUCTURE_JSON

    console.print(f"Scanning {reversed_dir}...")
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    funcs = parse_function_list(func_list_path)
    registry = build_function_registry(funcs, cfg, ghidra_json_path)

    unique_vas = {e.va for e in entries}
    ghidra_count = sum(1 for r in registry.values() if "ghidra" in r["detected_by"])
    list_count = sum(1 for r in registry.values() if "list" in r["detected_by"])
    both_count = sum(
        1 for r in registry.values() if "ghidra" in r["detected_by"] and "list" in r["detected_by"]
    )
    thunk_count = sum(1 for r in registry.values() if r["is_thunk"])
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
    verify_cache_obj = None if full else _load_verify_cache(cache_path, cfg)
    entries_cache: dict[str, VerifyCacheEntry] = (
        verify_cache_obj.entries if verify_cache_obj else {}
    )
    cached_count = 0

    for entry in unique_entries:
        va_key = f"0x{entry.va:08x}"
        cached_entry = entries_cache.get(va_key)
        if cached_entry is None:
            continue

        if cached_entry.filepath != getattr(entry, "filepath", ""):
            continue

        filepath = cfg.reversed_dir / getattr(entry, "filepath", "")
        if not filepath.exists():
            continue

        current_mtime = filepath.stat().st_mtime_ns
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

    return unique_entries, passed, failed, fail_details, results, cached_count


def run_verification(
    entries_to_verify: list[Annotation],
    cfg: Any,
    jobs: int,
    total: int,
    cached_count: int,
    json_output: bool,
) -> tuple[
    int, int, list[tuple[Annotation, str]], list[dict[str, Any]], list[tuple[Annotation, str, int]]
]:
    """Run parallel verification and classify results. Returns (passed, failed, fail_details, results, deferred_fixes)."""
    passed = 0
    failed = 0
    internal_errors = 0
    fail_details: list[tuple[Annotation, str]] = []
    results: list[dict[str, Any]] = []
    deferred_fixes: list[tuple[Annotation, str, int]] = []

    fresh_count = len(entries_to_verify)
    effective_jobs = min(jobs, fresh_count) if fresh_count else 1

    try:
        from rebrew.compile_cache import get_compile_cache

        compile_cache = get_compile_cache(cfg.root)
    except (ImportError, OSError):
        compile_cache = None

    def _verify(
        e: Annotation,
    ) -> tuple[Annotation, "CompareResult"]:
        return (e, verify_entry(e, cfg, cache=compile_cache))

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
            futures = {pool.submit(_verify, e): e for e in entries_to_verify}
            for future in concurrent.futures.as_completed(futures):
                entry = futures[future]
                try:
                    _entry, result = future.result()
                except Exception as exc:  # noqa: BLE001
                    internal_errors += 1
                    if internal_errors <= 5:
                        console.print(
                            f"[yellow]WARNING:[/] internal error verifying "
                            f"{getattr(entry, 'name', '?')}: {exc}"
                        )
                    from rebrew.compile import CompareResult

                    result = CompareResult(
                        matched=False,
                        status="COMPILE_ERROR",
                        match_percent=0.0,
                        delta=0,
                        obj_bytes=None,
                        reloc_offsets=None,
                        message=f"INTERNAL_ERROR: {exc}",
                    )

                name = entry.name
                progress.update(task, advance=1, description=name)

                if result.matched:
                    passed += 1
                else:
                    failed += 1
                    fail_details.append((entry, result.message))

                deferred_fixes.append((entry, result.status, result.delta))

                results.append(
                    {
                        "va": f"0x{entry.va:08x}",
                        "name": name,
                        "filepath": getattr(entry, "filepath", ""),
                        "size": getattr(entry, "size", 0),
                        "status": result.status,
                        "message": result.message,
                        "passed": result.matched,
                        "match_percent": result.match_percent,
                        "delta": result.delta,
                    }
                )

    if internal_errors > 0 and not json_output:
        console.print(
            f"[yellow]WARNING:[/] {internal_errors} function(s) failed with internal errors "
            f"(counted as mismatches)"
        )

    return passed, failed, fail_details, results, deferred_fixes


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
    for entry, status, _delta in deferred_fixes:
        fp = cfg.reversed_dir / getattr(entry, "filepath", "")
        if not fp.exists():
            continue
        module: str = getattr(entry, "module", "") or ""
        if not module:
            continue
        current_status = getattr(entry, "status", "")
        # PROVEN is sticky — never touch it
        if current_status == "PROVEN":
            continue
        if current_status == status:
            continue
        clear = is_matched(status)
        update_source_status(cfg.metadata_dir, status, module, entry.va, clear_blockers=clear)


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
    json_output: bool,
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

    if show_summary:
        console.print()
        table = Table(title="Verification Summary", show_header=True)
        table.add_column("VA", style="cyan")
        table.add_column("Symbol", style="magenta")
        table.add_column("Size", justify="right")
        table.add_column("Status", style="bold")
        table.add_column("Match %", justify="right")
        table.add_column("Delta", justify="right")

        _STATUS_COLORS: dict[str, str] = {
            "EXACT": "[green]EXACT[/]",
            "RELOC": "[green]RELOC[/]",
            "STUB": "[dim]STUB[/]",
            "PROVEN": "[magenta]PROVEN[/]",
            "NEAR_MATCHING": "[yellow]NEAR_MATCHING[/]",
            "COMPILE_ERROR": "[red]ERROR[/]",
        }
        for r in results:
            st = r["status"]
            st_str = _STATUS_COLORS.get(st, f"[red]{st}[/]")

            pct = f"{r['match_percent']:.1f}%" if st in ("STUB", "NEAR_MATCHING") else "-"
            dt = f"{r.get('delta', 0)}B" if st in ("STUB", "NEAR_MATCHING") else "-"
            table.add_row(r["va"], r["name"], f"{r['size']}B", st_str, pct, dt)

        console.print(table)

        exact = sum(1 for r in results if r["status"] == "EXACT")
        reloc = sum(1 for r in results if r["status"] == "RELOC")
        proven = sum(1 for r in results if r["status"] == "PROVEN")
        mismatch_0b = sum(
            1 for r in results if r["status"] == "MISMATCH" and r.get("delta", 0) == 0
        )
        mismatch_1_5 = sum(
            1 for r in results if r["status"] == "MISMATCH" and 1 <= r.get("delta", 0) <= 5
        )
        mismatch_6_20 = sum(
            1 for r in results if r["status"] == "MISMATCH" and 6 <= r.get("delta", 0) <= 20
        )
        mismatch_21 = sum(
            1 for r in results if r["status"] == "MISMATCH" and r.get("delta", 0) > 20
        )

        stat_table = Table(title="STATUS Breakdown", show_header=False)
        stat_table.add_column("Category", style="cyan")
        stat_table.add_column("Count", justify="right")
        stat_table.add_row("EXACT", str(exact))
        stat_table.add_row("RELOC", str(reloc))
        if proven:
            stat_table.add_row("PROVEN", str(proven))
        mismatch_total = mismatch_0b + mismatch_1_5 + mismatch_6_20 + mismatch_21
        stat_table.add_row("NEAR_MATCHING", str(mismatch_total))

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
                console.print(
                    rf"  [red bold]\[{match_pct:.1f}%][/] 0x{entry.va:08X} {entry.name}{fp_suffix}: {msg}"
                )
            elif st in ("COMPILE_ERROR", "MISSING_FILE"):
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
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
