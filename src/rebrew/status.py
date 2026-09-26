"""status.py – At-a-glance reversing progress overview.

Aggregates coverage data from annotations, function structure, and verify
cache into a concise project health dashboard.  No compilation is performed.

Usage::

    rebrew status                   Quick project overview
    rebrew status --json            Machine-readable JSON output
    rebrew status -t client_exe     Status for a specific target
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rebrew.cli import (
    DISPLAY_STATUSES,
    STATUS_COLORS,
    AllTargetsOption,
    TargetOption,
    all_targets_run,
    console,
    json_print,
    option_default,
    require_config,
)
from rebrew.config import ProjectConfig
from rebrew.present import BAR_WIDTH as _BAR_WIDTH
from rebrew.present import filled_cells as _filled
from rebrew.present import ratio_bar as _bar
from rebrew.sources import iter_sources
from rebrew.utils import clip_span, floor_pct
from rebrew.workspace.status import MATCHED_STATUSES

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

# Same display order as cli.DISPLAY_STATUSES (byte-matched, PROVEN, then
# NEAR/STUB).
_STATUS_ORDER = list(DISPLAY_STATUSES)


@dataclass
class VerifyInfo:
    """Summary of the last verify run."""

    timestamp: str = ""
    passed: int = 0
    failed: int = 0
    total: int = 0
    stale: bool = False  # sources changed since the cache was written
    #: Passes on VAs status counts as library code (not progress).
    library_passed: int = 0
    #: Last-verify rows on library-attributed VAs, passed or not.
    library_total: int = 0


@dataclass
class StatusReport:
    """Aggregated project health data."""

    target: str = ""
    binary: str = ""
    arch: str = ""

    # Function counts
    total_functions: int = 0
    covered_functions: int = 0
    source_files: int = 0

    # Per-status breakdown
    status_counts: dict[str, int] = field(default_factory=dict)

    # Byte-level coverage
    matched_bytes: int = 0
    total_text_bytes: int = 0
    #: Bytes of functions not byte-matched (annotated or not yet started).
    unmatched_bytes: int = 0
    #: .text bytes in no function: alignment fill (CC/90/00) and the rest.
    #: None when the binary could not be read (not measured, not zero).
    padding_bytes: int | None = None
    unattributed_bytes: int | None = None

    # Naked reconstructions (`// SOURCE: naked`) that are byte-exact via a
    # generated skeleton — reproduced, NOT decompiled.  Counted separately so
    # coverage can distinguish "decompiled" from "byte-covered via asm".
    naked_matched: int = 0
    naked_bytes: int = 0

    # Per-module status breakdown: {module: {status: count}}
    module_status: dict[str, dict[str, int]] = field(default_factory=dict)

    # Library attributions (lib-match identifications) excluded from the
    # progress table — counted here so the number stays visible.
    library_identified: int = 0

    # Verify cache summary
    verify_info: VerifyInfo | None = None

    # Effective-status overlay: how many functions' reported status differs
    # from their metadata status because the verify cache overrode it, and
    # how many are stuck on MISSING_SIZE (metadata SIZE missing → verify
    # could not extract).  Surfaced so the overlay is not emergent behavior.
    verify_overrides: int = 0
    verify_missing_size: int = 0
    # Functions whose entire byte delta is register allocation
    # (effective_match in the verify cache) — the prove queue.
    effective_matches: int = 0

    # W019 quick-lint result: number of .c files with inline metadata comments.
    # 0 means no issues found (or scan not yet run).
    inline_metadata_warning: int = 0

    # Data verification verdicts from rebrew-data.toml STATUS (written by
    # `verify --data`): verified / drift / unchecked symbol counts, and the
    # same counts per section. This target's module and library modules only.
    data_verified: int = 0
    data_drift: int = 0
    data_unchecked: int = 0
    data_sections: dict[str, dict[str, int]] = field(default_factory=dict)
    # Verified symbol bytes inside the file-backed .data and .rdata, and
    # the size of those ranges. The BSS tail is not file bytes, so it stays
    # a symbol count and is not part of this ratio.
    data_verified_bytes: int = 0
    data_total_bytes: int = 0

    # Derived percentages
    @property
    def coverage_pct(self) -> float:
        """Percentage of total functions that have a C source file (covered)."""
        if self.total_functions == 0:
            return 0.0
        return floor_pct(self.covered_functions, self.total_functions)

    @property
    def matched_pct(self) -> float:
        """Percentage of total functions that are byte-matched (EXACT or RELOC).

        PROVEN is excluded: it records semantic equivalence while the
        compiled bytes still differ from the target.
        """
        if self.total_functions == 0:
            return 0.0
        return floor_pct(self.matched_functions, self.total_functions)

    @property
    def matched_functions(self) -> int:
        """Number of byte-matched (EXACT or RELOC) functions."""
        return sum(self.status_counts.get(s, 0) for s in MATCHED_STATUSES)

    @property
    def decompiled_pct(self) -> float:
        """Percentage of total functions byte-matched by REAL C (naked
        reconstructions excluded): ct-recomp's "decompiled" vs "byte-covered
        via asm" split."""
        if self.total_functions == 0:
            return 0.0
        decompiled = max(0, self.matched_functions - self.naked_matched)
        return floor_pct(decompiled, self.total_functions)

    @property
    def byte_coverage_pct(self) -> float:
        """Percentage of ``.text`` bytes in byte-matched (EXACT/RELOC) functions,
        library attributions included."""
        if self.total_text_bytes == 0:
            return 0.0
        return floor_pct(self.matched_bytes, self.total_text_bytes)

    @property
    def data_total(self) -> int:
        """Named data symbols on this target (verified + drift + unchecked)."""
        return self.data_verified + self.data_drift + self.data_unchecked

    @property
    def data_byte_pct(self) -> float:
        """Share of file-backed ``.data`` and ``.rdata`` covered by VERIFIED symbols."""
        if self.data_total_bytes == 0:
            return 0.0
        return floor_pct(self.data_verified_bytes, self.data_total_bytes)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        d: dict[str, Any] = {
            "target": self.target,
            "binary": self.binary,
            "arch": self.arch,
            "functions": {
                "total": self.total_functions,
                "covered": self.covered_functions,
            },
            "status": self.status_counts,
            "modules": self.module_status,
            "library_identified": self.library_identified,
            "coverage_pct": self.coverage_pct,
            "matched_pct": self.matched_pct,
            "decompiled_pct": self.decompiled_pct,
            "naked_matched": self.naked_matched,
            "source_files": self.source_files,
            "data": {
                "verified": self.data_verified,
                "drift": self.data_drift,
                "unchecked": self.data_unchecked,
                "total": self.data_total,
                "sections": {
                    name: self.data_sections[name]
                    for name in _ordered_data_sections(self.data_sections)
                },
            },
        }
        if self.data_total_bytes > 0:
            d["data"]["verified_bytes"] = self.data_verified_bytes
            d["data"]["total_bytes"] = self.data_total_bytes
            d["data"]["byte_pct"] = self.data_byte_pct
        if self.total_text_bytes > 0:
            d["matched_bytes"] = self.matched_bytes
            d["total_text_bytes"] = self.total_text_bytes
            d["byte_coverage_pct"] = self.byte_coverage_pct
            d["unmatched_bytes"] = self.unmatched_bytes
            d["padding_bytes"] = self.padding_bytes
            d["unattributed_bytes"] = self.unattributed_bytes
        if self.verify_info is not None:
            d["last_verify"] = {
                "timestamp": self.verify_info.timestamp,
                "passed": self.verify_info.passed,
                "library_passed": self.verify_info.library_passed,
                "library_total": self.verify_info.library_total,
                "failed": self.verify_info.failed,
                "total": self.verify_info.total,
                "stale": self.verify_info.stale,
            }
            # The effective-status overlay (verify cache vs metadata).
            d["verify_cache"] = {
                "overrides": self.verify_overrides,
                "missing_size": self.verify_missing_size,
                "effective_matches": self.effective_matches,
            }
        if self.inline_metadata_warning:
            d["inline_metadata_warning"] = self.inline_metadata_warning
        return d


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


def _entry_va(entry_data: dict[str, Any]) -> int | None:
    """The VA of a verify-cache row, or None when it has none or it is malformed."""
    try:
        return int(str(entry_data.get("va")), 16)
    except ValueError:
        return None


def _load_verify_info(
    cfg: ProjectConfig, library_vas: frozenset[int] | set[int] = frozenset()
) -> VerifyInfo | None:
    """Load last verify summary from the verify cache file.

    Passes on *library_vas* are also counted separately: verify compiles
    them, but status leaves library code out of progress.
    """
    from rebrew.verify_cache import load_verify_cache_raw

    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    raw = load_verify_cache_raw(cfg)
    if raw is None:
        return None

    if not isinstance(raw, dict) or raw.get("version") != 2:
        return None
    # A cache written for another target (or with stale compiler/hash state)
    # must not be presented as this project's verification summary.
    if raw.get("target") != getattr(cfg, "target_name", ""):
        return None
    raw_bin = raw.get("binary_id")
    if raw_bin:
        from rebrew.verify_cache import _binary_id

        if raw_bin != _binary_id(cfg):
            return None

    entries = raw.get("entries")
    if not isinstance(entries, dict) or not entries:
        return None

    passed = 0
    failed = 0
    library_passed = 0
    library_total = 0
    for entry_data in entries.values():
        if not isinstance(entry_data, dict):
            continue
        # A row without a verdict status is malformed — skipped, never
        # counted as failed.
        if not entry_data.get("status"):
            continue
        on_library = _entry_va(entry_data) in library_vas
        library_total += on_library
        if entry_data.get("passed", False):
            passed += 1
            library_passed += on_library
        else:
            failed += 1

    # Try to get a last-modified timestamp from the file.
    # Rendered in UTC with an explicit suffix: an unlabeled wall time is
    # read as local, so a host in America/New_York would mis-age the cache
    # by several hours relative to the UTC instant we store.
    try:
        mtime = cache_path.stat().st_mtime
        timestamp = datetime.fromtimestamp(mtime, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except OSError:
        timestamp = ""

    # Freshness: a source newer than the cache means the summary is stale.
    # stat inside the loop races vs a write that races vs another writer —
    # read once, compare against that snapshot.
    stale = False
    try:
        cache_mtime_ns = cache_path.stat().st_mtime_ns
    except OSError:
        cache_mtime_ns = 0
    if cache_mtime_ns:
        for src in iter_sources(cfg.reversed_dir, cfg):
            try:
                if src.stat().st_mtime_ns > cache_mtime_ns:
                    stale = True
                    break
            except OSError:
                continue

    return VerifyInfo(
        timestamp=timestamp,
        passed=passed,
        failed=failed,
        total=passed + failed,
        stale=stale,
        library_passed=library_passed,
        library_total=library_total,
    )


def load_verify_statuses(cfg: ProjectConfig) -> dict[int, str]:
    """Load per-VA verify statuses from the verify cache.

    Returns a dict mapping VA -> verify status (e.g. "EXACT", "NEAR_MATCHING",
    "COMPILE_ERROR").  Used to override optimistic source statuses.
    """
    return {va: status for va, (status, _effective) in load_verify_details(cfg).items()}


def load_verify_details(cfg: ProjectConfig) -> dict[int, tuple[str, bool]]:
    """Load per-VA ``(status, effective_match)`` from the verify cache.

    *effective_match* marks functions whose entire delta is register
    allocation (reccmp's 100% effective-match case) — candidates worth
    proving even though bytes differ.
    """
    from rebrew.verify_cache import CACHE_VERSION, load_verify_cache_raw

    raw = load_verify_cache_raw(cfg)
    if raw is None:
        return {}

    if not isinstance(raw, dict) or raw.get("version") != CACHE_VERSION:
        return {}
    # Same target guard as _load_verify_info: another target's cache must not
    # override this project's source statuses.
    if raw.get("target") != getattr(cfg, "target_name", ""):
        return {}
    raw_bin = raw.get("binary_id")
    if raw_bin:
        from rebrew.verify_cache import _binary_id

        if raw_bin != _binary_id(cfg):
            return {}

    entries = raw.get("entries")
    if not isinstance(entries, dict):
        return {}

    details: dict[int, tuple[str, bool]] = {}
    for va_str, entry_data in entries.items():
        if not isinstance(entry_data, dict):
            continue
        status = entry_data.get("status", "")
        if not status:
            continue
        from rebrew.verify_cache import canonical_va_key

        va = canonical_va_key(va_str)
        if not isinstance(va, int):
            continue
        details[va] = (status, bool(entry_data.get("effective_match", False)))
    return details


def effective_status(ann_status: str, cached: str | None) -> str:
    """The status reported for a function: metadata *ann_status* overlaid by
    the verify cache verdict *cached* (``None`` when uncached).

    Metadata PROVEN and SKIP win: `rebrew prove` compiles after any cached
    verdict (the next verify/test replaces PROVEN), and SKIP is user parking.
    Metadata STUB wins over the cache's SIZE_MISMATCH/MISSING_SIZE/STUB (a
    stub's size mismatch is expected); every other cached verdict wins.
    """
    if ann_status in ("PROVEN", "SKIP"):
        return ann_status
    if ann_status == "STUB" and cached in ("SIZE_MISMATCH", "MISSING_SIZE", "STUB"):
        return ann_status
    return cached or ann_status


#: Fill bytes the linker and compiler place between functions.
_PADDING_BYTES = frozenset((0xCC, 0x90, 0x00))


def classify_text_gaps(text: bytes, text_va: int, spans: list[tuple[int, int]]) -> tuple[int, int]:
    """``(padding, unattributed)``: bytes of *text* in none of *spans*.

    *spans* are ``(va, size)`` function extents.  A gap byte that is
    alignment fill counts as padding; anything else is code or data no known
    function covers (a thunk, a switch table, an undiscovered function).
    """
    covered = bytearray(len(text))
    for va, size in spans:
        lo = max(0, va - text_va)
        hi = min(len(text), va - text_va + size)
        if hi > lo:
            covered[lo:hi] = b"\x01" * (hi - lo)
    padding = unattributed = 0
    for byte, hit in zip(text, covered, strict=True):
        if not hit:
            if byte in _PADDING_BYTES:
                padding += 1
            else:
                unattributed += 1
    return padding, unattributed


def _text_gaps(cfg: ProjectConfig, spans: list[tuple[int, int]]) -> tuple[int, int] | None:
    """:func:`classify_text_gaps` over the target's ``.text``; None if unreadable."""
    if not cfg.target_binary.is_file():
        return None
    try:
        from rebrew.binary_loader import load_binary

        info = load_binary(cfg.target_binary)
        sec = info.sections[".text"]
    except (OSError, KeyError, ValueError):
        return None
    text = info.data[sec.file_offset : sec.file_offset + min(sec.size, sec.raw_size)]
    return classify_text_gaps(text, sec.va, spans)


def _compute_text_size(cfg: ProjectConfig) -> int:
    """Compute .text section size from binary headers. Returns 0 if unavailable."""
    if not cfg.target_binary.exists():
        return 0
    try:
        from rebrew.sections import get_text_section_size

        return get_text_section_size(
            cfg.target_binary,
            root=getattr(cfg, "root", None),
            target=str(getattr(cfg, "target_name", "") or ""),
        )
    except (ImportError, OSError, ValueError):
        return 0


def collect_status(cfg: ProjectConfig) -> StatusReport:
    """Collect all project health data into a StatusReport.

    This is the single testable entry point for status data collection.
    It reads source markers, metadata, and function structure (no compilation).

    When a verify cache exists, verify results override source statuses
    so that functions which fail verification (NEAR_MATCHING, COMPILE_ERROR) are
    not counted as byte-matched.
    """
    from rebrew.naming import load_data
    from rebrew.sources import iter_sources

    report = StatusReport(
        target=cfg.target_name,
        binary=str(cfg.target_binary),
        arch=cfg.arch,
    )

    try:
        ghidra_funcs, existing, _covered_vas = load_data(cfg)
        from rebrew.naming import external_vas, inside_annotated_vas, scope_to_target

        # Before scoping: external .lib rows carry library modules
        # (D3DX8, MSVCRT, …) and must leave the denominators whatever the
        # module — identified external code is not pending work.  The flag
        # is `targets.<name>.external_libs` (plus LIBRARY marker rows).
        library_vas = external_vas(existing, getattr(cfg, "external_libs", None))
        existing = scope_to_target(existing, cfg)
    except (OSError, json.JSONDecodeError, KeyError, ValueError):
        # Graceful degradation: return zeroed report.  ValueError is what the
        # loaders raise for a corrupt structure JSON, so omitting it meant the
        # documented fallback skipped exactly the case it exists for.
        return report

    ghidra_vas = {f.va for f in ghidra_funcs}

    # Progress counts game functions only: library attributions are tallied
    # separately below, so the headline denominators cover FUNCTION rows plus
    # the ghidra inventory MINUS identified library code — counting the
    # binary's whole inventory (game + CRT/zlib/static libs) made coverage
    # read "half done" when library code was never work.
    function_vas = {va for va in existing if va not in library_vas}
    # Switch arms and split bodies inside an annotated function are not
    # functions (the same rule `rebrew todo` applies).
    pseudo_vas = inside_annotated_vas(ghidra_funcs, existing)
    report.total_functions = len(function_vas | (ghidra_vas - library_vas - pseudo_vas))
    report.covered_functions = len(function_vas)

    src_dir = Path(cfg.reversed_dir)
    report.source_files = len(iter_sources(src_dir, cfg))

    # Load verify cache to override source statuses.
    # Metadata statuses may be optimistic (e.g. STATUS: RELOC) while
    # the actual verify result is STUB.  Verify results are authoritative.
    verify_details = load_verify_details(cfg)
    verify_statuses = {va: status for va, (status, _eff) in verify_details.items()}

    # Single pass: status breakdown + byte-level coverage.
    status_counts: dict[str, int] = {}
    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    # Pseudo-functions (switch arms inside an annotated function) are not
    # starts: cutting at one gave the arm the rest of its matched parent.
    starts = sorted((size_by_va.keys() | existing.keys()) - pseudo_vas)

    def _span(va: int, info: dict[str, str]) -> int:
        """Bytes of *va*, cut at the next function start.

        A compiled function's annotated SIZE is what verify compared, so it
        wins; the inventory extent can include padding or a split body.  A
        library row is never compiled, so its SIZE is unchecked (often short
        of the linked body) and the discovered extent wins there.
        """
        try:
            annotated = int(info.get("size") or 0)
        except (TypeError, ValueError):
            annotated = 0
        inventory = size_by_va.get(va, 0)
        size = (inventory or annotated) if va in library_vas else (annotated or inventory)
        return clip_span(starts, va, size)

    matched_bytes = 0
    unmatched_bytes = 0
    spans: list[tuple[int, int]] = []
    naked_matched = 0
    naked_bytes = 0
    verify_overrides = 0
    verify_missing_size = 0
    effective_matches = 0
    library_identified = 0
    for va, info in existing.items():
        # External .lib attributions (lib-match identifications + modules
        # flagged in external_libs) are not reversing progress: count them
        # separately so the progress table answers "how much of this
        # binary's code is reversed".  They DO count toward .text byte
        # coverage: the deliverable must reproduce the whole image, and
        # stock-linked library bytes are reproduced bytes.  The row's own
        # STATUS is ignored: the attribution is the identification.
        if va in library_vas:
            library_identified += 1
            size = _span(va, info)
            matched_bytes += size
            spans.append((va, size))
            # Bucketed as LIBRARY: a status left over from before the row was
            # identified as library code would read as reversing progress.
            module = info.get("module") or "?"
            report.module_status.setdefault(module, {})
            report.module_status[module]["LIBRARY"] = (
                report.module_status[module].get("LIBRARY", 0) + 1
            )
            continue
        ann_status = info.get("status", "STUB")
        # A naked reconstruction (`// SOURCE: naked`) is byte-exact via a
        # generated skeleton — reproduced, not decompiled (ct-recomp's
        # NAKED_REQUIRED vs PURE_C_EXACT distinction).  Detected from the
        # source annotation so the bucket survives metadata status churn.
        naked = info.get("source") == "naked"
        effective = effective_status(ann_status, verify_statuses.get(va))
        if effective != ann_status:
            verify_overrides += 1
        if effective == "MISSING_SIZE":
            verify_missing_size += 1
        if verify_details.get(va, ("", False))[1] and effective not in MATCHED_STATUSES:
            effective_matches += 1
        status_counts[effective] = status_counts.get(effective, 0) + 1
        size = _span(va, info)
        spans.append((va, size))
        if effective in MATCHED_STATUSES:
            if naked:
                naked_matched += 1
                naked_bytes += size
            matched_bytes += size
        else:
            unmatched_bytes += size
        module = info.get("module") or "?"
        report.module_status.setdefault(module, {})
        report.module_status[module][effective] = report.module_status[module].get(effective, 0) + 1
    report.status_counts = status_counts
    report.library_identified = library_identified
    report.matched_bytes = matched_bytes
    report.naked_matched = naked_matched
    report.naked_bytes = naked_bytes
    report.total_text_bytes = _compute_text_size(cfg)
    # Functions nobody has started (not pseudo-functions, not library code).
    for va in ghidra_vas - existing.keys() - library_vas - pseudo_vas:
        size = clip_span(starts, va, size_by_va.get(va, 0))
        unmatched_bytes += size
        spans.append((va, size))
    report.unmatched_bytes = unmatched_bytes
    gaps = _text_gaps(cfg, spans)
    if gaps is not None:
        report.padding_bytes, report.unattributed_bytes = gaps
    report.verify_overrides = verify_overrides
    report.verify_missing_size = verify_missing_size
    report.effective_matches = effective_matches

    # Data verdicts: count rebrew-data.toml STATUS values written by
    # `verify --data`.  Named symbols only — unnamed inventory rows carry
    # no verdict.
    from rebrew.data_layout import estimate_type_size
    from rebrew.data_metadata import load_data_metadata, module_visible_to_target

    verified_spans: list[tuple[int, int]] = []
    for (module, va), fields in load_data_metadata(cfg.metadata_dir).items():
        if not module_visible_to_target(module, cfg):
            continue
        if not fields.get("name"):
            continue
        verdict = str(fields.get("status") or "UNCHECKED").upper()
        if verdict == "VERIFIED":
            bucket = "verified"
            report.data_verified += 1
        elif verdict == "DRIFT":
            bucket = "drift"
            report.data_drift += 1
        else:
            bucket = "unchecked"
            report.data_unchecked += 1
        section = str(fields.get("section") or "").strip().lower() or "(no section)"
        counts = report.data_sections.setdefault(
            section, {"verified": 0, "drift": 0, "unchecked": 0}
        )
        counts[bucket] += 1
        if bucket != "verified":
            continue
        try:
            size = int(fields.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        if size <= 0 and fields.get("type"):
            size = estimate_type_size(str(fields["type"]))
        if size > 0:
            verified_spans.append((va, va + size))
    report.data_verified_bytes, report.data_total_bytes = data_byte_coverage(
        verified_spans, _initialized_data_ranges(cfg)
    )

    # Verify info
    report.verify_info = _load_verify_info(cfg, library_vas)

    # Quick W019 scan: files ``rebrew lint --fix`` can migrate — counted by
    # lint's own rule (shared header parser, no full lint run).
    from rebrew.lint import count_migratable_files

    report.inline_metadata_warning = count_migratable_files(src_dir, cfg)

    return report


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------


_DATA_SECTION_ORDER = (".data", ".rdata", ".bss")
# Row ticks. Shorter than the headline bar so the table stays one line.
_TICK_WIDTH = 16


def _ordered_data_sections(sections: dict[str, dict[str, int]]) -> list[str]:
    """``.data``, ``.rdata``, ``.bss``, then any other section name."""
    head = [name for name in _DATA_SECTION_ORDER if name in sections]
    tail = sorted(name for name in sections if name not in _DATA_SECTION_ORDER)
    return head + tail


def _covered_bytes(spans: list[tuple[int, int]]) -> int:
    """Bytes covered by half-open spans. Overlap counts once."""
    ordered = sorted((lo, hi) for lo, hi in spans if hi > lo)
    if not ordered:
        return 0
    total = 0
    start, end = ordered[0]
    for lo, hi in ordered[1:]:
        if lo <= end:
            end = max(end, hi)
        else:
            total += end - start
            start, end = lo, hi
    return total + end - start


def data_byte_coverage(
    spans: list[tuple[int, int]], ranges: list[tuple[int, int]]
) -> tuple[int, int]:
    """Verified bytes inside *ranges*, and the size of those ranges.

    *spans* are half-open extents of VERIFIED symbols. A symbol that runs
    past the file-backed range is clipped. Overlap counts once.
    """
    total = sum(max(0, hi - lo) for lo, hi in ranges)
    clipped: list[tuple[int, int]] = []
    for lo, hi in spans:
        for rlo, rhi in ranges:
            start, end = max(lo, rlo), min(hi, rhi)
            if end > start:
                clipped.append((start, end))
    return _covered_bytes(clipped), total


def _initialized_data_ranges(cfg: ProjectConfig) -> list[tuple[int, int]]:
    """File-backed ``.data`` and ``.rdata`` ranges.

    Virtual size past the raw size is the BSS tail: those bytes are not in
    the file, and ``verify --data`` does not compare them. Raw size past the
    virtual size is file alignment. The overlap is the bytes a verified
    symbol can cover.
    """
    path = getattr(cfg, "target_binary", None)
    if path is None or not Path(path).is_file():
        return []
    try:
        from rebrew.binary_loader import load_binary

        info = load_binary(Path(path))
    except (OSError, KeyError, ValueError):
        return []
    ranges: list[tuple[int, int]] = []
    for name in (".data", ".rdata"):
        sec = info.sections.get(name)
        if sec is None:
            continue
        extent = min(int(sec.size), int(sec.raw_size))
        if extent > 0:
            ranges.append((int(sec.va), int(sec.va) + extent))
    return ranges


def _ticks(part: float, whole: float) -> str:
    """Proportional tick marks for a table row. No empty trail."""
    return "█" * _filled(part, whole, _TICK_WIDTH)


def _breakdown_table() -> Table:
    """Count table. Fixed columns, so the function and data tables align."""
    table = Table(
        show_header=True,
        header_style="bold",
        pad_edge=False,
        padding=(0, 2),
        box=None,
        expand=False,
    )
    table.add_column(width=16, no_wrap=True)
    table.add_column("Count", justify="right", width=12, no_wrap=True)
    table.add_column("%", justify="right", width=7, no_wrap=True)
    table.add_column("", width=_TICK_WIDTH, no_wrap=True)
    return table


def _data_block(report: StatusReport) -> list[Any]:
    """Data verdicts for this target, in the same columns as functions.

    When the binary has file-backed ``.data`` / ``.rdata``, a bar above the
    table shows the share of those bytes covered by VERIFIED symbols. It is
    labeled ``of data``, so it does not read as a second ``.text`` figure.
    """
    total = report.data_total
    if total == 0:
        return []
    block: list[Any] = []
    if report.data_total_bytes > 0:
        headline = Text()
        headline.append(f"{report.data_byte_pct}% of data", style="bold green")
        headline.append(
            f"    {report.data_verified_bytes:,}B / {report.data_total_bytes:,}B",
            style="dim",
        )
        block.append(headline)
        block.append(_bar(report.data_verified_bytes, report.data_total_bytes, _BAR_WIDTH))
    header = Text()
    header.append("Data", style="bold")
    header.append(f"  {report.data_verified}/{total} verified")
    if report.data_drift:
        header.append(f", {report.data_drift} drift", style="red")

    table = _breakdown_table()
    table.columns[0].header = "Data"
    rows = (
        ("VERIFIED", report.data_verified, "green"),
        ("DRIFT", report.data_drift, "red"),
        ("UNCHECKED", report.data_unchecked, "yellow"),
    )
    for label, count, color in rows:
        if count == 0:
            continue
        table.add_row(
            f"[{color}]{label}[/{color}]",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{floor_pct(count, total)}%[/{color}]",
            f"[{color}]{_ticks(count, total)}[/{color}]",
        )
    for name in _ordered_data_sections(report.data_sections):
        counts = report.data_sections[name]
        section_total = counts["verified"] + counts["drift"] + counts["unchecked"]
        count_cell = f"{counts['verified']}/{section_total}"
        if counts["drift"]:
            count_cell += f", {counts['drift']} drift"
        table.add_row(
            f"[dim]{name}[/dim]",
            f"[dim]{count_cell}[/dim]",
            "",
            f"[dim]{_ticks(counts['verified'], section_total)}[/dim]",
        )
    block.append(header)
    block.append(table)
    return block


def _panel_title(report: StatusReport) -> str:
    """Target, the binary's file name, and the arch. Not the full path."""
    parts = [f"[bold]{report.target}[/bold]"]
    binary = str(report.binary or "")
    if binary:
        name = Path(binary).name
        if name and name != report.target:
            parts.append(f"[dim]{name}[/dim]")
    if report.arch:
        parts.append(f"[dim]{report.arch}[/dim]")
    return "  ".join(parts)


def _headline(report: StatusReport) -> tuple[Text, Text | None]:
    """The one progress percentage, and the bar that pictures it.

    ``.text`` share when that size is known, otherwise the function share.
    The bar uses the same ratio, so it cannot disagree with the number.
    """
    if report.total_text_bytes > 0:
        text = Text()
        text.append(f"{report.byte_coverage_pct}% of .text", style="bold green")
        text.append(
            f"    {report.matched_bytes:,}B / {report.total_text_bytes:,}B",
            style="dim",
        )
        return text, _bar(report.matched_bytes, report.total_text_bytes, _BAR_WIDTH)
    text = Text(
        f"{report.matched_functions}/{report.total_functions} functions  ({report.matched_pct}%)",
        style="bold green",
    )
    bar = None
    if report.total_functions > 0:
        bar = _bar(report.matched_functions, report.total_functions, _BAR_WIDTH)
    return text, bar


def _render_terminal(report: StatusReport) -> None:
    """Render the status report as a rich terminal dashboard."""
    proven = report.status_counts.get("PROVEN", 0)

    headline, bar = _headline(report)

    # --- Status table ---
    status_table = _breakdown_table()
    status_table.columns[0].header = "Status"

    for status in _STATUS_ORDER:
        count = report.status_counts.get(status, 0)
        if count == 0:
            continue
        pct = floor_pct(count, report.total_functions)
        color = STATUS_COLORS.get(status, "white")
        status_table.add_row(
            f"[{color}]{status}[/{color}]",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{pct}%[/{color}]",
            f"[{color}]{_ticks(count, report.total_functions)}[/{color}]",
        )

    # Other statuses not in the standard order
    other_statuses = sorted(set(report.status_counts) - set(_STATUS_ORDER))
    for status in other_statuses:
        count = report.status_counts[status]
        if count == 0:
            continue
        pct = floor_pct(count, report.total_functions)
        color = STATUS_COLORS.get(status, "red")
        status_table.add_row(
            f"[{color}]{status}[/{color}]",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{pct}%[/{color}]",
            f"[{color}]{_ticks(count, report.total_functions)}[/{color}]",
        )

    # Functions without a source file: the rows then add up to the total.
    no_source = report.total_functions - report.covered_functions
    if no_source > 0:
        status_table.add_row(
            "[dim](no source)[/dim]",
            f"[dim]{no_source}[/dim]",
            f"[dim]{floor_pct(no_source, report.total_functions)}%[/dim]",
            f"[dim]{_ticks(no_source, report.total_functions)}[/dim]",
        )

    # --- Summary lines ---
    summary_lines: list[str] = []

    if proven:
        summary_lines.append(
            f"[magenta]{proven} PROVEN[/magenta]  [dim]semantically equivalent, bytes still"
            " differ (not byte-matched)[/dim]"
        )

    # Naked reconstructions: byte-exact via generated asm, NOT decompiled.
    # The honest split (ct-recomp's NAKED vs PURE_C_EXACT): decompiled_pct
    # excludes them so mass-generated skeletons can't inflate progress.
    if report.naked_matched:
        summary_lines.append(
            f"[magenta]{report.decompiled_pct}% decompiled[/magenta]"
            f"  [dim]({report.naked_matched} naked reconstructions, {report.naked_bytes:,}B"
            " byte-exact but not decompiled — implement the C bodies)[/dim]"
        )

    # Every .text byte accounted for, so the gap under the headline is explained.
    if (
        report.total_text_bytes > 0
        and report.padding_bytes is not None
        and report.unattributed_bytes is not None
    ):
        summary_lines.append(
            "[dim]"
            f"unmatched {report.unmatched_bytes:,}B"
            f"    padding {report.padding_bytes:,}B"
            f"    no function {report.unattributed_bytes:,}B"
            "[/dim]"
        )

    # Source file count, and library rows that are not reversing progress.
    sources = f"[dim]{report.source_files} source files[/dim]"
    if report.library_identified:
        sources += (
            f"    [green]{report.library_identified} library[/green]"
            "  [dim]not reversing progress[/dim]"
        )
    summary_lines.append(sources)

    # Pointer to the prioritized next-action list (PRD 05 status requirement)
    summary_lines.append(
        "[bold]Next[/bold]  rebrew todo"
        if report.total_functions > 0
        else "[dim]No functions yet[/dim]"
    )

    # Verify info
    if report.verify_info is not None:
        v = report.verify_info
        verify_color = "green" if v.failed == 0 else "yellow"
        stale_suffix = "  [yellow]stale[/yellow]" if v.stale else ""
        summary_lines.append(
            f"Last verify  [{verify_color}]{v.passed - v.library_passed}/"
            f"{v.total - v.library_total} byte-matched[/{verify_color}]"
            f", [red]{v.failed - (v.library_total - v.library_passed)} failed[/red]"
            + (f", {v.library_passed}/{v.library_total} library" if v.library_total else "")
            + f"  [dim]{v.timestamp}[/dim]{stale_suffix}"
        )
        # Effective-status overlay: verify results override metadata statuses.
        if report.verify_overrides:
            summary_lines.append(
                f"[dim]Effective status: {report.verify_overrides} function(s) overridden"
                " by verify cache (metadata says otherwise — see docs/ANNOTATIONS.md)[/dim]"
            )
        if report.verify_missing_size:
            summary_lines.append(
                f"[yellow]{report.verify_missing_size} function(s) MISSING_SIZE[/yellow]"
                " — set SIZE via metadata (rebrew cfg set) then re-run verify"
            )
        if report.effective_matches:
            summary_lines.append(
                f"[cyan]{report.effective_matches} effective match(es)[/cyan]"
                " — register-allocation-only delta, prove candidates"
            )

    # W019 inline metadata warning
    if report.inline_metadata_warning:
        n = report.inline_metadata_warning
        summary_lines.append(
            f"[yellow]Warning:[/yellow] {n} file(s) contain inline STATUS/CFLAGS/SIZE comments"
            " — run [bold]rebrew lint[/bold] to migrate to rebrew-functions.toml"
        )

    # --- Assemble panel ---
    from rich.console import Group

    panel_rows: list[Any] = [headline]
    if bar is not None:
        panel_rows.append(bar)
    if report.total_functions > 0:
        counts = Text()
        if report.total_text_bytes > 0:
            counts.append("Functions", style="bold")
            counts.append(f"  {report.matched_functions}/{report.total_functions}    ")
        counts.append("With source", style="bold")
        counts.append(f"  {report.covered_functions}/{report.total_functions}")
        panel_rows.append(counts)
    if status_table.row_count:
        panel_rows.extend([Text(""), status_table])
    data_block = _data_block(report)
    if data_block:
        panel_rows.append(Text(""))
        panel_rows.extend(data_block)
    panel_content = Group(
        *panel_rows,
        Text(""),
        *[Text.from_markup(line) for line in summary_lines],
    )

    panel = Panel(
        panel_content,
        title=_panel_title(report),
        border_style="blue",
    )
    console.print(panel)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew status · · · · · · · Quick project overview\n\n"
    "  rebrew status --json · · · · Machine-readable JSON output\n\n"
    "  rebrew status -t client_exe · Status for a specific target\n\n"
    "[dim]Reads source markers, metadata, and function structure (no compilation needed). "
    "Run 'rebrew verify' first for verify stats, or 'rebrew catalog' for function data.[/dim]"
)

app = typer.Typer(
    help="At-a-glance reversing progress overview.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
) -> None:
    """Show reversing progress overview for the current project."""
    all_targets = option_default(all_targets, False)
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda n: main(json_output=json_output, target=n, all_targets=False),
    ):
        return
    cfg = require_config(target=target, json_mode=json_output)
    report = collect_status(cfg)

    if json_output:
        json_print(report.to_dict())
        return

    _render_terminal(report)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
