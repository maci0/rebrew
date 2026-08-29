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
import functools
import hashlib
import json
import logging
import threading
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.compile import CompareResult
    from rebrew.compile_cache import CacheBackend

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
from rebrew.metadata import MATCHED_STATUSES, should_promote_status
from rebrew.utils import atomic_write_text

log = logging.getLogger(__name__)

#: Sentinel stored in VerifyCacheEntry.toolchain when no override names a
#: compiler (the project's default profile applies).  Distinct from ``""`` so
#: legacy entries (written before the field existed) are re-verified once.
_DEFAULT_TOOLCHAIN = "(default)"

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
    # Pre-compile annotation failure (VA outside the image / below the valid
    # floor) — a metadata problem, not a compile failure.  Ranked with the
    # other MISSING_* annotation problems so it never shows up as a bogus
    # "compile error" in the summary or the CI gate.
    "INVALID_VA": 4,
    # A tooling failure, not a code verdict — kept out of the --compare
    # regression gate entirely (see diff_reports), so a worker crash on a
    # previously-EXACT function never looks like a code regression in CI.
    "INTERNAL_ERROR": 6,
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
    "INVALID_VA": 6,
    "INTERNAL_ERROR": 8,
    "FAIL": 7,
}


@functools.lru_cache(maxsize=1)
def _compare_logic_hash() -> str:
    """Hash of the rebrew modules whose logic changes verification RESULTS.

    The version string alone is static during development (editable installs
    stay "0.1.0" across code changes), so it cannot invalidate a cache written
    by an earlier build of the same version.  Hashing the source of the
    comparison pipeline means any code change invalidates cached results —
    stale EXTRACT_ERROR or wrong RELOC/NEAR_MATCHING entries can never be
    served as truth after a fix.  Computed once per process (source files are
    stable for the lifetime of one rebrew invocation).

    The hash covers the WHOLE ``rebrew`` package source rather than a
    hand-maintained module list: result-affecting code lives across
    ``core.matching`` (reloc validation), ``core.toolchain`` (compiler env),
    ``cli.resolve_cflags`` (flags), ``binary_loader`` (IAT masking) and
    others, and a manual list inevitably drifts — a missed module then ships
    a fix without invalidating caches written by the pre-fix build.

    The ``lru_cache`` lives on THIS function (not a nested helper): the old
    version decorated an inner ``_hash()`` re-created on every call, so the
    full-package source hash was recomputed on every verify run despite the
    "once per process" claim (slop-review).
    """
    import rebrew

    h = hashlib.sha256()
    pkg_root = Path(rebrew.__file__).resolve().parent
    # Deterministic order; only .py source (skip vendored binaries,
    # __pycache__, .so/.pyd extensions).
    for path in sorted(pkg_root.rglob("*.py")):
        try:
            h.update(path.read_bytes())
        except OSError:
            continue
        h.update(b"\x00")
    return h.hexdigest()


def _compiler_config_hash(cfg: ProjectConfig) -> str:
    # Do NOT inline target binary mtime/size here — compiler config is an
    # input to the cache predicate, not a per-call probe of the binary.  The
    # binary identity is guarded separately via VerifyCache.binary_id and
    # _verify_cache_matches_identity; mixing it in would bust the cache on
    # every run that touches the binary even when nothing relevant changed.
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
        # NOTE: cfg.cflags and cfg.cflags_presets are NOT hashed here — they
        # feed the effective-flags resolution, which is stored PER ENTRY in
        # the cache (see _save_verify_cache) and compared at hit-check time,
        # so a config-level cflags/preset edit invalidates the affected
        # entries without nuking the whole cache.
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
    """Return sorted (rel_path, mtime_ns, size) tuples for all .h files.

    Not memoized: headers can change within a process lifetime (``verify
    --watch`` re-runs in-process; tests mutate headers between calls), and a
    stale fingerprint would serve a stale ``_headers_hash``.
    """
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


def _entry_headers_fp(cfg: ProjectConfig, filepath: Path, cflags_str: str) -> str:
    """Per-source header-dependency fingerprint for a verify-cache entry.

    Resolves the source's ``#include`` closure against the same dirs the
    compile would search (``compiler_includes``, the source's own dir, and
    the ``/I`` dirs of the base + resolved per-function flags) and hashes the
    reached headers via ``compile_cache.header_dependency_hash``.  Editing a
    header therefore re-verifies exactly the entries whose source reaches it
    — replacing the old global ``headers_hash`` gate that re-verified
    everything on any header change.  Returns ``""`` when the source cannot
    be read (the entry is treated as stale).
    """
    import shlex

    from rebrew.compile import extract_include_dirs, resolve_include_flags
    from rebrew.compile_cache import header_dependency_hash

    source_dir = filepath.parent
    inc_path = str(getattr(cfg, "compiler_includes", "") or "")
    flags = shlex.split(getattr(cfg, "base_cflags", "") or "") + shlex.split(cflags_str)
    flags = resolve_include_flags(flags, source_dir, cfg.root)
    include_dirs = [d for d in [inc_path, str(source_dir), *extract_include_dirs(flags)] if d]
    try:
        content = filepath.read_bytes().decode("utf-8", errors="surrogateescape")
    except OSError:
        return ""
    return header_dependency_hash(content, str(source_dir), include_dirs)


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
    similarity: float | None = None
    reg_delta: int | None = None
    effective_match: bool = False

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
            similarity=d.get("similarity"),
            reg_delta=d.get("reg_delta"),
            effective_match=bool(d.get("effective_match", False)),
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

    CFLAGS live in ``rebrew-functions.toml``, not in the ``.c`` file, so the
    source hash alone cannot detect a flag change (``rebrew match
    --fix-cflags`` rewrites metadata and leaves the source untouched).
    Entries written before this field existed carry ``""`` and are re-verified
    once."""

    size: int = -1
    """Annotation SIZE at cache time.

    SIZE is metadata-only (``rebrew-functions.toml``) — editing it via
    ``rebrew catalog --fix-sizes`` never touches the ``.c`` mtime, so the
    source hash cannot detect it either.  Entries written before this field
    existed carry ``-1`` (unknown) and are re-verified once."""

    headers_fp: str = ""
    """Per-source header-dependency fingerprint (reached ``#include`` closure).

    Computed via ``compile_cache.header_dependency_hash`` over the same
    search dirs the compile uses, so editing a header re-verifies exactly the
    entries whose source reaches it.  This replaced the global
    ``headers_hash`` gate, which invalidated *every* entry on any header
    change.  Entries written before this field existed carry ``""`` and are
    re-verified once."""

    toolchain: str = ""
    """Resolved per-function toolchain override at cache time (e.g. ``watcom``).

    The TOOLCHAIN field lives in ``rebrew-functions.toml`` / ``rebrew-libraries.toml``,
    not in the ``.c`` file, so the source hash cannot detect a toolchain
    change.  Only the resolved *cflags* were stored before this field, so a
    library ``TOOLCHAIN`` override edit served stale EXACT/RELOC for every
    function under it (the config fallback chain: per-function → per-library
    → project default).  ``"(default)"`` records "no override — project
    profile applies"; ``""`` marks a legacy entry, re-verified once."""

    defines: str = ""
    """Per-target compile-time defines at cache time (sorted, comma-joined).

    ``targets.<name>.defines`` feed ``#ifdef`` deltas in shared multi-version
    sources — they are compile inputs invisible to the source hash and the
    resolved cflags string, so a defines edit must invalidate the entry.
    ``""`` marks a legacy entry, re-verified once."""

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
            headers_fp=str(d.get("headers_fp", "")),
            toolchain=str(d.get("toolchain", "")),
            defines=str(d.get("defines", "")),
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
    headers_hash: str = ""  # informational only — per-entry headers_fp is authoritative
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


_VERIFY_CACHE_LOCK = threading.Lock()


@contextlib.contextmanager
def _verify_cache_write_lock(cache_path: Path) -> Iterator[None]:
    """Thread + cross-process lock around a verify-cache read-modify-write.

    Same discipline as metadata.py's ``_metadata_write_lock``: the thread
    lock serializes in-process writers; an advisory ``flock`` on a sidecar
    ``.lock`` file serializes concurrent processes (e.g. ``rebrew verify
    --watch`` saving while ``rebrew test`` patches a promotion — without
    it, interleaved read-modify-writes silently drop one side's update and
    status/todo serve a stale entry).  Falls back to the thread lock alone
    on platforms without ``fcntl``.
    """
    try:
        import fcntl
    except ImportError:  # non-POSIX (no advisory file locks)
        fcntl = None  # type: ignore[assignment]

    with _VERIFY_CACHE_LOCK:
        if fcntl is None:
            yield
            return
        lock_path = Path(str(cache_path) + ".lock")
        with lock_path.open("w", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_fh, fcntl.LOCK_UN)


def _cache_identity_matches(raw: dict[str, Any], cfg: ProjectConfig) -> bool:
    """True when a parsed verify-cache document belongs to *cfg*'s identity.

    Single definition of the ``(target, compiler_hash)`` check shared by
    :func:`verify_cache_matches_cfg` (whole-file predicate) and
    :func:`patch_verify_cache_entries` (in-lock guard), so the two cannot
    drift.
    """
    return bool(
        raw.get("target") == cfg.target_name
        and raw.get("compiler_hash") == _compiler_config_hash(cfg)
    )


def verify_cache_matches_cfg(cache_path: Path, cfg: ProjectConfig) -> bool:
    """True when the verify cache was written for this project's identity.

    The cache stores its ``target``/``compiler_hash``/``headers_hash``/
    ``binary_id`` provenance; patchers (``rebrew test`` promoting a STATUS)
    must not write into a cache that belongs to a DIFFERENT target or
    compiler — in a multi-target project, ``rebrew test -t CLIENT`` would
    otherwise patch the entries a previous ``verify -t SERVER`` wrote, and
    the next SERVER verify would accept the whole file and serve CLIENT's
    status for SERVER functions at the same VA.

    NOTE: this reads the file WITHOUT the write lock — suitable for
    diagnostics/predicates.  Patchers must re-check the identity inside
    :func:`_verify_cache_write_lock` (as ``patch_verify_cache_entries``
    does): a check performed before acquiring the lock can be invalidated
    by a concurrent writer swapping the cache between check and patch.
    """
    if not cache_path.exists():
        return False
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return _cache_identity_matches(data, cfg)


def patch_verify_cache_entries(cfg: ProjectConfig, patches: list[dict[str, Any]]) -> None:
    """Apply verify-cache patches with ONE read + ONE write, guarded.

    Shared by every STATUS promotion site (``rebrew test``, ``rebrew match``
    GA splice, batch flag sweep) so ``rebrew status``/``rebrew todo`` agree
    with the freshly-promoted metadata immediately — previously only test
    patched the cache, so a match run's ``STUB → RELOC`` promotion left
    status/todo reporting the stale cached STUB until the next full verify.

    Guards: the cache must belong to THIS project's identity (target +
    compiler_hash — a multi-target `test -t CLIENT` must not patch entries a
    `verify -t SERVER` wrote), checked INSIDE the shared cross-process lock
    so a concurrent verify's full-cache save cannot swap the file between an
    outside check and the locked read-modify-write, and the read-modify-write
    itself runs under that lock so a concurrent ``verify --watch`` save
    cannot interleave and drop the patch.

    *patches*: list of dicts with ``va`` (int), ``status``, ``match_count``,
    ``total``, optional ``delta`` (int|None).
    """
    if not patches:
        return
    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    if not cache_path.exists():
        # Absent — nothing to patch.  (Checked before locking because taking
        # the lock would create the ``.lock`` sidecar in a possibly
        # not-yet-existing directory; a cache created after this point simply
        # gets patched by the next promotion.)
        return
    with _verify_cache_write_lock(cache_path):
        try:
            raw = json.loads(cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logging.warning(
                "Could not read verify cache %s — status may be stale: %s", cache_path, exc
            )
            return

        if not _cache_identity_matches(raw, cfg):
            # Wrong identity — patching would misattribute status to the
            # wrong target/compiler.  Nothing to do; the next real verify
            # writes a correct cache.
            return

        entries = raw.get("entries", {})
        changed = False
        for p in patches:
            va_key = f"0x{p['va']:08x}"
            entry = entries.get(va_key)
            if entry is None:
                continue  # No cached entry to patch
            result = entry.get("result", {})
            old_status = result.get("status", "")
            if old_status == p["status"]:
                continue  # Already in sync
            result["status"] = p["status"]
            total = p["total"]
            match_pct = round(100.0 * p["match_count"] / total, 1) if total > 0 else 0.0
            result["match_percent"] = match_pct
            result["passed"] = p["status"] in MATCHED_STATUSES
            if p.get("delta") is not None:
                result["delta"] = p["delta"]
            elif total > 0:
                result["delta"] = total - p["match_count"]
            entry["result"] = result
            entries[va_key] = entry
            changed = True

        if not changed:
            return
        raw["entries"] = entries

        try:
            from rebrew.utils import atomic_write_text

            atomic_write_text(cache_path, json.dumps(raw, indent=2), encoding="utf-8")
        except (OSError, TypeError) as exc:
            logging.warning(
                "Could not patch verify cache %s — status may be stale: %s", cache_path, exc
            )


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
    # Header invalidation is per-entry via VerifyCacheEntry.headers_fp (a
    # reached-header fingerprint), checked at serve time in prepare_entries —
    # the old global headers_hash gate re-verified the whole cache on any
    # header change, defeating per-source precision.
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
    headers_fp_by_va: dict[str, str] = {}
    toolchain_by_va: dict[str, str] = {}
    defines_norm = ",".join(sorted(getattr(cfg, "defines", None) or [])) or "(none)"
    for entry in entries:
        va_key = f"0x{entry.va:08x}"
        # Store the RESOLVED effective flags (per-function metadata → module
        # preset → [compiler].cflags → default) — the flags the compile
        # actually used.  The old code stored only the metadata CFLAGS, so a
        # `rebrew cfg set-cflags` or [compiler].cflags edit changed the
        # effective flags without changing the cache key or entry guard, and
        # stale results kept being served (config-review F3).
        from rebrew.cli import resolve_compile_overrides

        _tc, _cf = resolve_compile_overrides(
            cfg,
            (cfg.reversed_dir / entry.filepath).parent if entry.filepath else cfg.root,
            getattr(entry, "toolchain", ""),
            getattr(entry, "cflags", ""),
            getattr(entry, "module", ""),
        )
        cflags_by_va[va_key] = _cf
        size_by_va[va_key] = entry.size or 0
        toolchain_by_va[va_key] = _tc or _DEFAULT_TOOLCHAIN
        relative_path = getattr(entry, "filepath", "")
        if not relative_path:
            continue
        filepath = cfg.reversed_dir / relative_path
        if filepath.exists():
            filepath_info[relative_path] = (filepath.stat().st_mtime_ns, _source_hash(filepath))
            headers_fp_by_va[va_key] = _entry_headers_fp(cfg, filepath, _cf)

    cache_entries: dict[str, dict[str, Any]] = {}
    for result in results:
        va_key = result["va"]
        filepath = result.get("filepath", "")
        file_info = filepath_info.get(filepath)
        if file_info is None:
            continue
        # A tooling crash is not a verification verdict — never cache it: a
        # transient worker failure would otherwise be re-served forever as a
        # phantom failure (status count, coverage overlay, todo "0B diff"
        # quick-win) until a --full re-verify.
        if result.get("status") == "INTERNAL_ERROR":
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
            "similarity": result.get("similarity", None),
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
            "headers_fp": headers_fp_by_va.get(str(va_key), ""),
            "toolchain": toolchain_by_va.get(str(va_key), ""),
            "defines": defines_norm,
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
    with _verify_cache_write_lock(cache_path):
        atomic_write_text(cache_path, json.dumps(cache_data.to_dict(), indent=2), encoding="utf-8")


def canonical_va_key(va: Any) -> Any:
    """Normalize a verify-cache VA key to its canonical form.

    Hex strings (``0x1000`` vs ``0x00001000``) map to the same int so report
    format drift can't silently break diffing.  Non-hex values pass through
    unchanged (still unique).  This is the single parser for keys written by
    ``_save_verify_cache``; readers elsewhere must use it.
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

        # A tooling crash is not a code verdict: skip INTERNAL_ERROR rows
        # entirely (no regression/improvement/new classification), so a
        # worker exception on a previously-EXACT function never shows up as
        # a code regression in the --compare CI gate.  The count is still
        # surfaced separately by run_verification's internal_errors report.
        if current_status == "INTERNAL_ERROR":
            continue

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
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rebrew verification pipeline: compile each .c and verify bytes match."""
    cfg = require_config(target=target, json_mode=json_output, root=root)
    if jobs is None:
        jobs = cfg.default_jobs

    # 16-bit NE targets need a 16-bit compiler profile (msvc1.52 — DOSBox
    # image / rebrew.msvc16).  When one is configured, verify runs normally
    # through compile_and_compare (which routes the 16-bit OMF objects via
    # omf16).  Only short-circuit when the project has no 16-bit profile —
    # otherwise every stub would burn the compile loop into COMPILE_ERROR
    # rows.  (The original skip predated the msvc1.52 profile and silently
    # hid the working 16-bit pipeline.)
    from rebrew.binary_loader import is_ne

    if getattr(cfg, "target_binary", None) and is_ne(cfg.target_binary):
        profile = getattr(cfg, "compiler_profile", "") or "msvc6"
        if profile != "msvc1.52":
            msg = (
                "verify: 16-bit NE targets need the msvc1.52 profile "
                "(DOSBox CL.EXE — 'profile = \"msvc1.52\"' in rebrew-project.toml); "
                f"current profile is {profile!r}.  Skipping the compile/compare loop."
            )
            if json_output:
                json_print({"skipped": True, "reason": msg, "arch": "x86_16"})
            else:
                console.print(f"[yellow]{msg}[/yellow]")
            return

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
                watch=False,  # never nest watch loops
                target=target,
            )

        watch_files(_sources(), _retest, path_provider=_sources)
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
        missing_sizes,
    ) = prepare_entries(
        cfg,
        full,
        json_output,
    )

    total = len(unique_entries)

    # --nolib (reccmp equivalent): drop LIBRARY-marked functions entirely —
    # from the work list, the cached results already counted, and the size
    # audit — so the gate reflects game code only.  Excluded functions are
    # neither compiled nor counted, exactly like reccmp's --nolib filter.
    library_excluded = 0
    if nolib:
        lib_vas = {e.va for e in unique_entries if getattr(e, "marker_type", "") == "LIBRARY"}
        if lib_vas:
            lib_keys = {f"0x{v:08x}" for v in lib_vas}
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
        # the overlay must not hide its diagnostic.
        fail_details = [(e, m) for e, m in fail_details if f"0x{e.va:08x}" not in overlaid_vas]

        # Flag stale PROVEN claims: metadata says PROVEN but the byte compile
        # cannot support it (source no longer builds, annotation changed, or
        # the status was hand-claimed).  The real byte result stands and a
        # metadata: warning is emitted — a claimed PROVEN is only honored
        # over the byte states a proven function legitimately produces
        # (metadata-review F2).
        stale_proven = sorted(
            r["va"] for r in results if r["va"] in proven_vas and r["va"] not in overlaid_vas
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
        },
        "size_divergences": size_divergences,
        "missing_sizes": missing_sizes,
        "results": results,
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
    gate_failed = _gate_fails(diff_result, failed)

    if not dry_run and not (diff_mode and gate_failed):
        cache_path = cfg.root / ".rebrew" / "verify_cache.json"
        try:
            _save_verify_cache(cache_path, cfg, results, unique_entries, raw_statuses)
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
        # One TOML read-modify-write for the whole batch (per-entry set_field
        # was N full rewrites — perf-review F2).
        set_fields_batch(cfg.metadata_dir, updates)
        return len(updates)
    return 0


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
    list[dict[str, Any]],
]:
    """Scan reversed_dir, deduplicate entries, and check the verify cache.

    Returns (unique_entries, passed, failed, fail_details, results,
    cached_count, size_divergences, missing_sizes).
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
        if canonical > 0 and ann_size > 0 and abs(canonical - ann_size) > 1:
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

    return (
        unique_entries,
        passed,
        failed,
        fail_details,
        results,
        cached_count,
        size_divergences,
        missing_sizes,
    )


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
    # The CLI -j flag bypasses config's _positive_int validation — clamp
    # here so `-j 0` (or negative) cannot crash ThreadPoolExecutor.
    effective_jobs = max(1, min(jobs, fresh_count)) if fresh_count else 1

    try:
        from rebrew.compile_cache import get_compile_cache

        compile_cache = get_compile_cache(cfg.root, getattr(cfg, "cache_backend", "diskcache"))
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
                        # Tooling failures are reported via the internal-errors
                        # warning, not the code-failure list — a crash is not a
                        # verdict on the function's source.
                        if not is_internal_error:
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
                        }
                    )

    if internal_errors > 0 and not json_output:
        console.print(
            f"[yellow]warning:[/yellow] {internal_errors} function(s) failed with internal errors "
            f"(tooling failures — counted in the failed total but NOT treated as "
            f"code regressions by --compare)"
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
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
