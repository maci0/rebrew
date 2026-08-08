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
import logging
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
    count_detection_sources,
    parse_function_list,
    scan_reversed_dir,
)
from rebrew.cli import (
    EXIT_MISMATCH,
    MIN_VALID_VA,
    STATUS_COLORS,
    TargetOption,
    error_exit,
    is_matched,
    json_print,
    require_config,
    should_promote_status,
)
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.metadata import update_source_status
from rebrew.utils import atomic_write_text

log = logging.getLogger(__name__)

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


def verify_entry(
    entry: Annotation,
    cfg: ProjectConfig,
    cache: "CompileCache | None" = None,
    *,
    name_to_va: dict[str, int] | None = None,
) -> "CompareResult":
    """Compile a .c file and compare output bytes against DLL.

    Delegates to ``compile_and_compare`` for the compile→extract→compare flow.
    When *cache* is provided, compilation results are reused across calls
    for the same source content + flags — critical for multi-function files
    where the same .c is compiled once and multiple symbols extracted.

    *name_to_va* is the shared data-catalog map used for DIR32 absolute
    validation — same source as ``rebrew test``.
    """
    from rebrew.compile import compile_and_compare

    cfile = cfg.reversed_dir / entry.filepath
    if not cfile.exists():
        return _failed_result("MISSING_FILE", f"MISSING_FILE: {cfile}")

    if entry.va < MIN_VALID_VA:
        return _failed_result("COMPILE_ERROR", "INVALID_VA: VA too low")
    if entry.size <= 0:
        return _failed_result("MISSING_SIZE", "MISSING_SIZE: No SIZE annotation")

    from rebrew.cli import resolve_cflags

    cflags_str = entry.cflags
    # Shared fallback chain (per-function → preset → compiler.cflags) so
    # verify compiles with the same flags as match/diff/test.
    cflags = resolve_cflags(cfg, cflags_str, getattr(entry, "module", ""))
    symbol = entry.symbol if entry.symbol else "_" + entry.name

    from rebrew.binary_loader import extract_raw_bytes

    target_bytes = extract_raw_bytes(cfg.target_binary, entry.va, entry.size)
    if not target_bytes:
        return _failed_result("COMPILE_ERROR", "Cannot extract DLL bytes")

    return compile_and_compare(
        cfg,
        cfile,
        symbol,
        target_bytes,
        cflags,
        cache=cache,
        name_to_va=name_to_va,
        section_va=entry.va,
    )


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
    # PROVEN is a post-verify semantic promotion — not worse than byte match.
    # Rank with RELOC so NEAR_MATCHING → PROVEN is an improvement, never a regression.
    "EXACT": 0,
    "RELOC": 1,
    "PROVEN": 1,
    "STUB": 2,
    "NEAR_MATCHING": 2,
    "SIZE_MISMATCH": 2,
    "COMPILE_ERROR": 3,
    "EXTRACT_ERROR": 3,
    "MISSING_FILE": 4,
    "MISSING_SIZE": 4,
    "FAIL": 5,
}

# Fine-grained status ordering WITHIN the _STATUS_RANK bands, so same-rank
# changes (NEAR_MATCHING → STUB, both rank 2) are still detected as
# regressions/improvements by the --compare gate.
_STATUS_ORDER: dict[str, int] = {
    "EXACT": 0,
    "RELOC": 1,
    "PROVEN": 1,
    "NEAR_MATCHING": 2,
    "SIZE_MISMATCH": 3,
    "STUB": 4,
    "COMPILE_ERROR": 5,
    "EXTRACT_ERROR": 5,
    "MISSING_FILE": 6,
    "MISSING_SIZE": 6,
    "FAIL": 7,
}


def _compare_logic_hash() -> str:
    """Hash of the rebrew modules whose logic changes verification RESULTS.

    The version string alone is static during development (editable installs
    stay "0.1.0" across code changes), so it cannot invalidate a cache written
    by an earlier build of the same version.  Hashing the source of the
    modules that drive comparison/extraction/symbol-derivation means any code
    change to that pipeline invalidates cached results — stale EXTRACT_ERROR
    or wrong RELOC/NEAR_MATCHING entries can never be served as truth after a
    fix.  Computed once per process (source files are stable for the lifetime
    of one rebrew invocation).
    """
    import functools

    from rebrew.annotation import _kv_to_annotation
    from rebrew.binary_loader import extract_raw_bytes
    from rebrew.compile import _extract_and_compare, classify_compare_result
    from rebrew.core.matching import smart_reloc_compare
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    @functools.lru_cache(maxsize=1)
    def _hash() -> str:
        h = hashlib.sha256()
        for mod in (
            _kv_to_annotation,
            classify_compare_result,
            smart_reloc_compare,
            parse_obj_symbol_and_relocs,
            _extract_and_compare,
            extract_raw_bytes,
        ):
            src = Path(mod.__code__.co_filename).read_bytes()
            h.update(src)
            h.update(b"\x00")
        return h.hexdigest()

    return _hash()


def _compiler_config_hash(cfg: ProjectConfig) -> str:
    parts = [
        cfg.compiler_command,
        getattr(cfg, "compiler_runner", ""),
        cfg.base_cflags,
        str(cfg.compiler_includes),
        str(cfg.compiler_libs),
        # Content hash of the comparison/extraction logic: a code change that
        # alters results for the SAME source+compiler (e.g. the EXTRACT_ERROR
        # / STUB-symbol fixes) must invalidate cached results.  The package
        # version string alone is static during development.
        _compare_logic_hash(),
        # NOTE: cfg.cflags and cfg.cflags_presets are INTENTIONALLY absent —
        # verify never reads them (per-function CFLAGS come from metadata and
        # are part of each cache entry).  Do not add them here.
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _external_includes_hash(cfg: ProjectConfig) -> str:
    """Digest of headers in the config-level ``-I`` include dirs.

    These live OUTSIDE ``reversed_dir`` (e.g. ``-Ireferences/zlib-1.1.3``),
    so the reversed-dir walk in :func:`_headers_hash` misses them — but an
    edit to such a header changes every translation unit that includes it,
    and cached verify entries are served without recompiling.  Reuses the
    compile cache's ``include_fingerprint`` (name+size+mtime stat walk,
    memoized per directory) so both caches agree on the same dirs.
    """
    import shlex

    from rebrew.compile_cache import include_fingerprint

    inc_dirs: list[str] = []
    inc = getattr(cfg, "compiler_includes", None)
    if inc:
        inc_dirs.append(str(inc))
    for flag in shlex.split(getattr(cfg, "base_cflags", "") or ""):
        if flag.startswith("-I"):
            inc_dirs.append(flag[2:])
    h = hashlib.sha256()
    for d in sorted(set(inc_dirs)):
        h.update(include_fingerprint(d).encode("utf-8"))
        h.update(b"\x02")
    return h.hexdigest()


def _headers_hash(cfg: ProjectConfig) -> str:
    """SHA256 of every header file reachable from the project's source tree.

    If a shared header changes, every translation unit that includes it must be
    re-verified.  Returns a stable hash that captures the union of all .h files
    under cfg.reversed_dir plus the config-level ``-I`` include dirs (see
    :func:`_external_includes_hash`).  (The compile cache tracks headers
    independently via ``compile_cache.include_fingerprint``; this hash guards
    the verify cache, which also covers include dirs outside ``reversed_dir``.)

    Memoized behind a cheap stat fingerprint (path + mtime_ns + size): when no
    header changed since the last call, the full content reads are skipped.
    The fingerprint is authoritative for the common cases (edit, create,
    delete); an edit that preserves BOTH mtime_ns and size is not detected
    within one process (the memo returns the cached digest).  Content hashing
    still runs on the first call per fingerprint, and each fresh process
    recomputes from content, so cross-run correctness is preserved.
    """
    src_dir = Path(cfg.reversed_dir)
    if not src_dir.exists():
        return ""

    ext_digest = _external_includes_hash(cfg)
    stat_fp = _headers_stat_fingerprint(src_dir) + (ext_digest,)
    cached = _HEADERS_HASH_CACHE.get(stat_fp)
    if cached is not None:
        return cached

    h = hashlib.sha256()
    # Sorted for stable hashing across runs / platforms.
    for hfile in sorted(src_dir.rglob("*.h")):
        try:
            rel = hfile.relative_to(src_dir).as_posix()
            h.update(rel.encode("utf-8"))
            h.update(b"\x00")  # separator to prevent path/content collision
            h.update(hfile.read_bytes())
            h.update(b"\x01")  # entry separator
        except OSError:
            continue
    h.update(ext_digest.encode("utf-8"))
    h.update(b"\x03")
    digest = h.hexdigest()
    if len(_HEADERS_HASH_CACHE) >= _HEADERS_HASH_CACHE_MAX:
        _HEADERS_HASH_CACHE.clear()
    _HEADERS_HASH_CACHE[stat_fp] = digest
    return digest


# Stat fingerprint of the header tree: (path, mtime_ns, size) per header,
# plus the external-includes digest as the final element.
# Key for the memoized _headers_hash — avoids re-reading every .h when the
# tree is unchanged across the two calls per verify run.
_HEADERS_HASH_CACHE: dict[tuple[tuple[str, int, int] | str, ...], str] = {}
_HEADERS_HASH_CACHE_MAX = 8  # one entry per distinct header-tree state


def _headers_stat_fingerprint(src_dir: Path) -> tuple[tuple[str, int, int], ...]:
    """Return sorted (rel_path, mtime_ns, size) tuples for all .h files."""
    entries: list[tuple[str, int, int]] = []
    for hfile in src_dir.rglob("*.h"):
        try:
            st = hfile.stat()
            rel = hfile.relative_to(src_dir).as_posix()
            entries.append((rel, st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    return tuple(sorted(entries))


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
    passed: bool = False
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
            passed=bool(d.get("passed", False)),
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
    cflags: str = ""
    """Per-function CFLAGS used for the cached run.

    CFLAGS live in ``rebrew-function.toml``, not in the ``.c`` file, so the
    source hash alone cannot detect a flag change (``rebrew match
    --fix-cflags`` rewrites metadata and leaves the source untouched).
    Entries written before this field existed carry ``""`` and are re-verified
    once."""

    size: int = -1
    """Annotation SIZE at cache time.

    SIZE is metadata-only (``rebrew-function.toml``) — editing it via
    ``rebrew catalog --fix-sizes`` never touches the ``.c`` mtime, so the
    source hash cannot detect it either.  Entries written before this field
    existed carry ``-1`` (unknown) and are re-verified once."""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifyCacheEntry":
        """Reconstruct a VerifyCacheEntry from a JSON dictionary."""
        return cls(
            source_hash=str(d.get("source_hash", "")),
            filepath=str(d.get("filepath", "")),
            mtime_ns=int(d.get("mtime_ns", 0)),
            result=VerifyResult.from_dict(d.get("result", {})),
            cflags=str(d.get("cflags", "")),
            size=int(d.get("size", -1)),
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
    headers_hash: str = ""  # SHA256 of all .h files under reversed_dir; "" means unchecked
    binary_id: str = ""  # SHA256 of target binary (mtime_ns + size); "" = legacy cache

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifyCache":
        """Reconstruct a VerifyCache from a JSON dictionary."""
        raw_entries = d.get("entries", {})
        if not isinstance(raw_entries, dict):
            raw_entries = {}
        return cls(
            version=int(d.get("version", 0)),
            compiler_hash=str(d.get("compiler_hash", "")),
            target=str(d.get("target", "")),
            headers_hash=str(d.get("headers_hash", "")),
            binary_id=str(d.get("binary_id", "")),
            entries={
                str(k): VerifyCacheEntry.from_dict(v)
                for k, v in raw_entries.items()
                if isinstance(v, dict)
            },
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert this VerifyCache to a JSON-serializable dictionary."""
        return asdict(self)


def _binary_id(cfg: ProjectConfig) -> str:
    """Stable id for the target binary (mtime_ns + size), "" when unreadable.

    Guards the verify cache: a rebuilt binary of the same target name must
    invalidate cached results, which the target-name check alone misses.
    """
    try:
        st = Path(cfg.target_binary).stat()
    except (OSError, TypeError):
        return ""
    return hashlib.sha256(f"{st.st_mtime_ns}:{st.st_size}".encode()).hexdigest()


def _load_verify_cache(cache_path: Path, cfg: ProjectConfig) -> VerifyCache | None:
    if not cache_path.exists():
        return None
    try:
        data = VerifyCache.from_dict(json.loads(cache_path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError, TypeError, ValueError, AttributeError):
        return None
    if data.version != 1:
        return None
    if data.target != cfg.target_name:
        return None
    if data.compiler_hash != _compiler_config_hash(cfg):
        return None
    if data.headers_hash != _headers_hash(cfg):
        return None
    # Legacy caches carry no binary_id — accept them; a cached binary_id that
    # no longer matches the current binary must invalidate.
    if data.binary_id and data.binary_id != _binary_id(cfg):
        return None
    return data


def _save_verify_cache(
    cache_path: Path,
    cfg: ProjectConfig,
    results: list[dict[str, Any]],
    entries: list[Annotation],
    raw_statuses: dict[str, tuple[str, bool]] | None = None,
) -> None:
    filepath_info: dict[str, tuple[int, str]] = {}
    cflags_by_va: dict[str, str] = {}
    size_by_va: dict[str, int] = {}
    for entry in entries:
        va_key = f"0x{entry.va:08x}"
        cflags_by_va[va_key] = entry.cflags or ""
        size_by_va[va_key] = entry.size or 0
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
        # Overlaid PROVEN entries store their pre-overlay byte result so a
        # later metadata STATUS demotion is not masked by a stale cache hit.
        if raw_statuses is not None and va_key in raw_statuses:
            res_dict["status"], res_dict["passed"] = raw_statuses[va_key]

        cache_entries[str(va_key)] = {
            "source_hash": source_hash,
            "filepath": filepath,
            "mtime_ns": mtime,
            "result": res_dict,
            "cflags": cflags_by_va.get(str(va_key), ""),
            "size": size_by_va.get(str(va_key), 0),
        }

    cache_data = VerifyCache(
        version=1,
        compiler_hash=_compiler_config_hash(cfg),
        headers_hash=_headers_hash(cfg),
        target=cfg.target_name,
        binary_id=_binary_id(cfg),
        entries={str(k): VerifyCacheEntry.from_dict(v) for k, v in cache_entries.items()},
    )
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(cache_path, json.dumps(cache_data.to_dict(), indent=2), encoding="utf-8")


def _canonical_va_key(va: Any) -> Any:
    """Normalize a VA to a canonical comparison key.

    Hex strings (``0x1000`` vs ``0x00001000``) map to the same int so report
    format drift can't silently break diffing.  Non-hex values pass through
    unchanged (still unique).
    """
    if isinstance(va, int):
        return va
    if isinstance(va, str):
        s = va.strip()
        if s[:2].lower() == "0x":
            try:
                return int(s, 16)
            except ValueError:
                return s
    return str(va)


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
        _canonical_va_key(r["va"]): r
        for r in previous.get("results", [])
        if isinstance(r, dict) and "va" in r
    }
    current_results = {
        _canonical_va_key(r["va"]): r
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
        current_order = _STATUS_ORDER.get(current_status, fail_rank)

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
        previous_order = _STATUS_ORDER.get(previous_status, fail_rank)

        if current_order == previous_order:
            # Same fine-grained status: only a match-percentage drop is a
            # regression (e.g. NEAR_MATCHING 95% → 40%).
            prev_pct = previous_item.get("match_percent")
            curr_pct = current_item.get("match_percent")
            if (
                isinstance(prev_pct, (int, float))
                and isinstance(curr_pct, (int, float))
                and curr_pct < prev_pct - 5.0
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
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    watch: bool = typer.Option(
        False, "--watch", help="Re-verify all sources whenever any .c file changes"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rebrew verification pipeline: compile each .c and verify bytes match."""
    cfg = require_config(target=target, json_mode=json_output, root=root)
    if jobs is None:
        jobs = cfg.default_jobs

    if watch:
        from rebrew.cli import iter_sources
        from rebrew.utils import watch_files

        sources = list(iter_sources(cfg.reversed_dir, cfg))

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
                watch=False,  # never nest watch loops
                target=target,
            )

        watch_files(sources, _retest)
        return

    out_file = Path(output_path) if output_path else cfg.db_dir / "verify_results.json"
    previous_report, diff_warning = _load_previous_report(out_file, diff_mode, json_output)

    (
        unique_entries,
        passed,
        failed,
        fail_details,
        results,
        cached_count,
        size_divergences,
    ) = prepare_entries(
        cfg,
        full,
        json_output,
    )

    total = len(unique_entries)

    cached_vas = {r["va"] for r in results}
    v_passed, v_failed, v_fail_details, v_results, deferred = run_verification(
        [e for e in unique_entries if f"0x{e.va:08x}" not in cached_vas],
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
    _proven_compatible = ("NEAR_MATCHING", "SIZE_MISMATCH")
    overlaid_vas: set[str] = set()
    # Raw byte-level truth for overlaid entries — the verify cache must store
    # the result as compiled, not the metadata-derived PROVEN.  The overlay is
    # re-applied from CURRENT metadata at every report run (including cached
    # results), so baking PROVEN into the cache would mask a later STATUS
    # demotion with a stale cached pass.
    raw_statuses: dict[str, tuple[str, bool]] = {}
    if proven_vas:
        for r in results:
            if r["va"] in proven_vas and r["status"] in _proven_compatible:
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
        # — the overlay must not hide its diagnostic.
        fail_details = [(e, m) for e, m in fail_details if f"0x{e.va:08x}" not in overlaid_vas]

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
        },
        "size_divergences": size_divergences,
        "results": results,
    }

    if size_divergences and not json_output:
        console.print(
            f"[yellow]warning:[/yellow] {len(size_divergences)} function(s) have annotation "
            "SIZE differing from the binary-derived size; run with --json for details"
        )

    # F9: a failed --compare gate must not record state — the baseline is
    # preserved below, and the compile cache is skipped too so a CI failure
    # leaves no new cache entries behind.
    diff_result: dict[str, Any] | None = None
    if diff_mode and previous_report is not None:
        diff_result = diff_reports(previous_report, report)
    gate_failed = _gate_fails(diff_result, failed)

    if not dry_run and not (diff_mode and gate_failed):
        cache_path = cfg.root / ".rebrew" / "verify_cache.json"
        try:
            _save_verify_cache(cache_path, cfg, results, unique_entries, raw_statuses)
        except (OSError, TypeError):
            # Warn on stderr regardless of json mode — silent cache-I/O
            # failures degrade performance invisibly.
            logging.warning("Could not write verify cache to %s", cache_path)

    if json_output or output_path or diff_mode:
        report_json = json.dumps(report, indent=2)
        # In --compare mode the report IS the baseline for future runs — a
        # regressed run must not overwrite the last good baseline, or the
        # gate would self-heal on the next invocation.  Plain verify always
        # records the report (pre-existing failures are the baseline's
        # business); --compare advances it only on a passing gate.
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

            _raise_if_regression(diff_result, failed)
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

    _raise_if_regression(diff_result, failed)


def _gate_fails(diff_result: dict[str, Any] | None, failed: int) -> bool:
    """True when the CI regression gate must fail this run.

    With a baseline (*diff_result*), only regressions and newly-broken
    entries fail the run — pre-existing failures are the baseline's
    business.  Without a baseline, any failed function fails the run.
    """
    if diff_result is not None:
        if diff_result["regressions"]:
            return True
        return any(
            _STATUS_RANK.get(str(i.get("status", "FAIL")), _STATUS_RANK["FAIL"])
            >= _STATUS_RANK["COMPILE_ERROR"]
            for i in diff_result.get("new", [])
        )
    return failed > 0


def _raise_if_regression(diff_result: dict[str, Any] | None, failed: int) -> None:
    """Raise ``typer.Exit(EXIT_MISMATCH)`` per the CI regression gate.

    Shared gate logic lives in :func:`_gate_fails`; this raises on it.
    """
    if _gate_fails(diff_result, failed):
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


def prepare_entries(
    cfg: ProjectConfig,
    full: bool,
    json_output: bool,
) -> tuple[
    list[Annotation],
    int,
    int,
    list[tuple[Annotation, str]],
    list[dict[str, Any]],
    int,
    list[dict[str, Any]],
]:
    """Scan reversed_dir, deduplicate entries, and check the verify cache.

    Returns (unique_entries, passed, failed, fail_details, results,
    cached_count, size_divergences).
    """
    reversed_dir = cfg.reversed_dir
    func_list_path = cfg.function_list
    ghidra_json_path = reversed_dir / FUNCTION_STRUCTURE_JSON

    console.print(f"Scanning {reversed_dir}...")
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    funcs = parse_function_list(func_list_path)
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

        # CFLAGS come from rebrew-function.toml, not the .c file, so a flag
        # change is invisible to the source hash below.
        if cached_entry.cflags != (entry.cflags or ""):
            continue

        # SIZE is metadata-only too (catalog --fix-sizes rewrites it without
        # touching the .c); a size change must invalidate the cached result.
        if cached_entry.size != (entry.size or 0):
            continue

        filepath = cfg.reversed_dir / getattr(entry, "filepath", "")
        if not filepath.exists():
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
    for entry in unique_entries:
        reg = registry.get(entry.va)
        if not reg:
            continue
        canonical = reg.get("canonical_size") or 0
        ann_size = entry.size or 0
        if canonical > 0 and ann_size > 0 and abs(canonical - ann_size) > 1:
            size_divergences.append(
                {
                    "va": f"0x{entry.va:08x}",
                    "annotation_size": ann_size,
                    "binary_size": canonical,
                    "name": entry.name or entry.symbol or "",
                }
            )
    size_divergences.sort(key=lambda d: d["va"])

    return unique_entries, passed, failed, fail_details, results, cached_count, size_divergences


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

    # Shared once for the whole batch — same catalog `rebrew test` uses.
    from rebrew.core import build_name_to_va

    name_to_va = build_name_to_va(cfg)

    def _verify(
        e: Annotation,
    ) -> tuple[Annotation, "CompareResult"]:
        return (e, verify_entry(e, cfg, cache=compile_cache, name_to_va=name_to_va))

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
                is_internal_error = False
                try:
                    _entry, result = future.result()
                except Exception as exc:  # noqa: BLE001
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

                # An INTERNAL_ERROR is a tooling failure, not a verification
                # verdict — never let it overwrite the function's real STATUS
                # in rebrew-function.toml (previously EXACT/NEAR_MATCHING were
                # permanently demoted to COMPILE_ERROR).
                if not is_internal_error:
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
            f"[yellow]warning:[/yellow] {internal_errors} function(s) failed with internal errors "
            f"(counted as mismatches)"
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

        for r in results:
            st = r["status"]
            color = STATUS_COLORS.get(st, "red")
            st_str = f"[{color}]{st}[/{color}]"

            pct = f"{r['match_percent']:.1f}%" if st in ("STUB", "NEAR_MATCHING") else "-"
            dt = f"{r.get('delta', 0)}B" if st in ("STUB", "NEAR_MATCHING") else "-"
            table.add_row(r["va"], r["name"], f"{r['size']}B", st_str, pct, dt)

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
