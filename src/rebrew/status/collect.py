"""collect.py – Status report model and project health data collection.

Aggregates coverage data from annotations, function structure, data metadata,
and the verify cache into a :class:`StatusReport`.  No compilation is performed.
"""

import logging
import sys
from dataclasses import dataclass, field
from typing import Any
lazy import bisect
lazy import json
lazy from datetime import UTC, datetime
lazy from pathlib import Path

lazy from rebrew.config import ProjectConfig
lazy from rebrew.formats.binary_model import BinaryInfo
lazy from rebrew.source.discovery import iter_sources
lazy from rebrew.utils import (
    clip_span,
    floor_pct,
    last_change_ns,
    merged_span_bytes,
)
lazy from rebrew.workspace.status import MATCHED_STATUSES, STATUS_ALIASES, STUB_PLACEHOLDER_STATUSES

log = logging.getLogger(__name__)

__all__ = [
    "CODE_ACCOUNT_CAPTION",
    "DATA_SECTION_ORDER",
    "SourceData",
    "StatusReport",
    "VerifyInfo",
    "attach_file_similarity",
    "classify_text_gaps",
    "classify_unattributed_ranges",
    "code_account_headline",
    "code_account_parts",
    "collect_status",
    "compare_file_bytes",
    "compute_text_size",
    "cut_range",
    "data_byte_coverage",
    "effective_status",
    "find_built_image",
    "initialized_data_ranges",
    "linker_produced_match",
    "load_cache_raw",
    "load_verify_details",
    "load_verify_info",
    "load_verify_statuses",
    "merge_claimed",
    "native_tail_span",
    "ordered_data_sections",
    "pe_data_directory",
    "postlink_copied_ranges",
    "span_is_copied",
    "target_binary",
    "unclaimed",
]


def _status_binding(name: str, default: Any, *, alias: str | None = None) -> Any:
    """Resolve *name* (or *alias*) from ``rebrew.status`` when loaded so monkeypatches take effect."""
    status_mod = sys.modules.get("rebrew.status")
    if status_mod is None:
        return default
    if alias is not None:
        aliased = getattr(status_mod, alias, default)
        if aliased is not default:
            return aliased
    return getattr(status_mod, name, default)


#: What the code-account percentage counts. Status, todo, and catalog print this.
CODE_ACCOUNT_CAPTION = "Matched functions, identified libraries, and alignment padding."

DATA_SECTION_ORDER = (".data", ".rdata", ".bss")


def ordered_data_sections(sections: dict[str, dict[str, int]]) -> list[str]:
    """``.data``, ``.rdata``, ``.bss``, then any other section name."""
    head = [name for name in DATA_SECTION_ORDER if name in sections]
    tail = sorted(name for name in sections if name not in DATA_SECTION_ORDER)
    return head + tail


def code_account_parts(pct: float, accounted: int, total: int) -> tuple[str, str]:
    """Label and byte line for the code account of a known virtual ``.text``."""
    return (
        f"Code account  {pct}% of virtual .text",
        f"    {accounted:,}B / {total:,}B",
    )


def code_account_headline(pct: float, accounted: int, total: int) -> str:
    """The code-account sentence, one line, shared by every progress surface."""
    label, amounts = code_account_parts(pct, accounted, total)
    return f"{label}{amounts}"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VerifyInfo:
    """Summary of the last verify run."""

    timestamp: str = ""
    passed: int = 0
    failed: int = 0
    total: int = 0
    stale: bool = False  # sources/metadata newer than cache, or its mtime unreadable
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
    similarity: dict[str, dict[str, float | int]] = field(default_factory=dict)

    # Byte-level coverage
    matched_bytes: int = 0
    #: Function extents per verdict, including LIBRARY and NO_SOURCE.
    status_bytes: dict[str, int] = field(default_factory=dict)
    total_text_bytes: int = 0
    #: Bytes of non-matching function extents, unstarted functions, and
    #: unverified native tails.
    unmatched_bytes: int = 0
    #: Alignment-fill bytes in .text gaps and native tails; non-fill gaps are
    #: listed in unattributed_ranges. None when the binary could not be read.
    padding_bytes: int | None = None
    unattributed_ranges: list[tuple[int, int]] = field(default_factory=list)
    # Alignment fill found inside those tails; counted as padding.
    tail_padding_bytes: int = 0
    # Discoverer extent beyond the body a compile measured.  Attributed to the
    # function, never compared, so it stays out of the matched bytes; listed
    # here so a reader can audit which bytes those are instead of trusting a
    # lump sum.
    unverified_tail_ranges: list[tuple[int, int]] = field(default_factory=list)
    unattributed_bytes: int | None = None

    # Naked reconstructions (`source = "naked"`) that are byte-exact via a
    # generated skeleton — reproduced, NOT decompiled.  Counted separately so
    # coverage can distinguish "decompiled" from "byte-covered via asm".
    naked_matched: int = 0
    naked_bytes: int = 0

    # Per-module status breakdown: {module: {status: count}}
    module_status: dict[str, dict[str, int]] = field(default_factory=dict)

    # Library attributions (library match identifications) excluded from the
    # progress table — counted here so the number stays visible.
    library_identified: int = 0
    #: LIBRARY bytes attributed by derived span: an identified row without a
    #: recorded extent owns the unclaimed bytes up to the next known start.
    library_derived_bytes: int = 0
    #: Trusted coverage only: the library rows' bytes, and the rows and bytes a
    #: trusted verdict matched (``library_verified_bytes`` is inside
    #: ``matched_bytes``). A library row without one is library, not verified:
    #: neither matched nor counted against the original code.
    library_bytes: int = 0
    library_verified: int = 0
    library_verified_bytes: int = 0

    # Verify cache summary
    verify_info: VerifyInfo | None = None

    # Set when the function inventory could not be loaded and every count on
    # this report is therefore zero rather than measured.  Empty on a normal
    # run.  Rendered and serialized so a degraded report never reads as
    # "nothing left to do".
    load_error: str = ""

    # Effective-status overlay: how many functions' reported status differs
    # from their metadata status because the verify cache overrode it, and
    # how many are stuck on MISSING_SIZE (metadata SIZE missing → verify
    # could not extract).  Surfaced so the overlay is not emergent behavior.
    verify_overrides: int = 0
    verify_missing_size: int = 0
    # Functions whose entire byte delta is register allocation
    # (effective_match in the verify cache) — the prove queue.
    effective_matches: int = 0

    # Data verification verdicts from rebrew-data.toml STATUS (written by
    # `verify --data`): symbol counts per verdict, and the same counts per
    # section. This target's module and library modules only. EXACT also counts
    # in data_verified (its bytes match); DISPLACED also counts in data_drift
    # (the link put it elsewhere), so the byte buckets keep their meaning.
    data_exact: int = 0
    data_verified: int = 0
    data_displaced: int = 0
    data_drift: int = 0
    data_unchecked: int = 0
    data_sections: dict[str, dict[str, int]] = field(default_factory=dict)
    # Verified symbol bytes inside the file-backed .data and .rdata, and
    # the size of those ranges. The BSS tail is not file bytes, so it stays
    # a symbol count and is not part of this ratio.
    data_verified_bytes: int = 0
    data_total_bytes: int = 0
    #: Disjoint file-backed byte counts; uncertain verdicts win overlaps.
    data_bytes: dict[str, int] = field(default_factory=dict)
    data_conflicting_verified_bytes: int = 0

    # Whole-file compare of the image the linker wrote. Span is the longer
    # length, so a shorter file's tail counts as unmatched.
    file_matched_bytes: int = 0
    file_total_bytes: int = 0
    file_built: str = ""
    file_sections: dict[str, dict[str, int]] = field(default_factory=dict)
    #: Configured `[targets.<name>].raw_link` that names no file. Empty when
    #: unset, or when the file is there. Reported rather than scored as
    #: zero: a mistyped path would otherwise look like a project that has
    #: never been built.
    file_missing_raw_link: str = ""

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
    def accounted_text_bytes(self) -> int:
        """Matched function bytes, library bytes credited by the active coverage mode, and alignment fill."""
        return self.matched_bytes + (self.padding_bytes or 0)

    @property
    def byte_coverage_pct(self) -> float:
        """Share of ``.text`` that is a matched function or alignment fill.

        Library bytes credited by the active coverage mode count with the
        matched functions. ``CC``, ``NOP``, and zero bytes sitting between
        those functions are alignment, so they count too. Bytes that belong to
        no function stay outside the percentage.
        """
        if self.total_text_bytes == 0:
            return 0.0
        return floor_pct(self.accounted_text_bytes, self.total_text_bytes)

    @property
    def data_total(self) -> int:
        """Named data symbols on this target (verified + drift + unchecked)."""
        return self.data_verified + self.data_drift + self.data_unchecked

    @property
    def data_byte_pct(self) -> float:
        """Share of initialized data verified without conflicting verdicts."""
        if self.data_total_bytes == 0:
            return 0.0
        return floor_pct(self.data_verified_bytes, self.data_total_bytes)

    @property
    def file_similarity_pct(self) -> float:
        """Same-offset share of the longer of the reference and the built image."""
        if self.file_total_bytes == 0:
            return 0.0
        return floor_pct(self.file_matched_bytes, self.file_total_bytes)

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
            "similarity": self.similarity,
            "modules": self.module_status,
            "library_identified": self.library_identified,
            "coverage_pct": self.coverage_pct,
            "matched_pct": self.matched_pct,
            "decompiled_pct": self.decompiled_pct,
            "naked_matched": self.naked_matched,
            "naked_bytes": self.naked_bytes,
            "source_files": self.source_files,
            "data": {
                "exact": self.data_exact,
                "verified": self.data_verified,
                "displaced": self.data_displaced,
                "drift": self.data_drift,
                "unchecked": self.data_unchecked,
                "total": self.data_total,
                "sections": {
                    name: self.data_sections[name]
                    for name in ordered_data_sections(self.data_sections)
                },
            },
        }
        if self.data_total_bytes > 0:
            d["data"]["verified_bytes"] = self.data_verified_bytes
            d["data"]["total_bytes"] = self.data_total_bytes
            d["data"]["byte_pct"] = self.data_byte_pct
            d["data"]["bytes"] = self.data_bytes
            d["data"]["conflicting_verified_bytes"] = self.data_conflicting_verified_bytes
        if self.total_text_bytes > 0:
            d["matched_bytes"] = self.matched_bytes
            d["total_text_bytes"] = self.total_text_bytes
            d["byte_coverage_pct"] = self.byte_coverage_pct
            d["unmatched_bytes"] = self.unmatched_bytes
            d["padding_bytes"] = self.padding_bytes
            d["unattributed_bytes"] = self.unattributed_bytes
            d["status_bytes"] = self.status_bytes
            d["accounted_text_bytes"] = self.accounted_text_bytes
            d["library_derived_bytes"] = self.library_derived_bytes
        if self.unattributed_ranges:
            d["unattributed_ranges"] = [
                {"va": f"0x{va:08x}", "size": size} for va, size in self.unattributed_ranges
            ]
        if self.unverified_tail_ranges:
            d["unverified_tail_ranges"] = [
                {"va": f"0x{va:08x}", "size": size} for va, size in self.unverified_tail_ranges
            ]
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

        if self.file_total_bytes > 0:
            d["file"] = {
                "matched_bytes": self.file_matched_bytes,
                "total_bytes": self.file_total_bytes,
                "similarity_pct": self.file_similarity_pct,
                "built": self.file_built,
                "unmatched_bytes": self.file_total_bytes - self.file_matched_bytes,
                "sections": self.file_sections,
            }
        if self.file_missing_raw_link:
            d["missing_raw_link"] = self.file_missing_raw_link
        if self.load_error:
            d["load_error"] = self.load_error
        return d


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


def compare_file_bytes(reference: bytes, built: bytes) -> tuple[int, int]:
    """Same-offset match count and span.

    The span is the longer length. Bytes the shorter file does not have are
    unmatched, so a truncated image cannot score as the whole reference.
    """
    span = max(len(reference), len(built))
    if len(reference) == len(built) and reference == built:
        return span, span
    # A byte matches where the XOR of the two images is zero: the big-integer XOR and
    # bytes.count run over whole words in C instead of one Python comparison per byte.
    size = min(len(reference), len(built))
    xor = int.from_bytes(reference[:size], "little") ^ int.from_bytes(built[:size], "little")
    return xor.to_bytes(size, "little").count(0), span


def linker_produced_match(
    reference: bytes,
    built: bytes,
    splice: tuple[int, int] | None = None,
) -> tuple[int, int]:
    """Match count and span, with a reference-byte splice left out of both.

    ``splice`` is a half-open ``[start, end)`` in each buffer. Dropping it
    from the span means copied answer-key bytes cannot raise the score. A
    tail past the shorter file still counts as unmatched.
    """
    if splice is None:
        return compare_file_bytes(reference, built)
    start, end = splice
    if start < 0 or end < start:
        return compare_file_bytes(reference, built)

    def cut(buf: bytes) -> bytes:
        if start >= len(buf):
            return buf
        return buf[:start] + buf[min(end, len(buf)) :]

    return compare_file_bytes(cut(reference), cut(built))


def find_built_image(root: Path, target_name: str, raw_link: Path | None = None) -> Path | None:
    """The image status scores.

    A configured ``raw_link`` is that file only: a missing one does not fall
    back to the postlinked ``build/<target>``. Without one, only
    ``build/<target>`` is eligible; another target's image is never substituted.
    """
    if raw_link is not None:
        path = Path(raw_link)
        return path if path.is_file() else None
    direct = Path(root) / "build" / target_name
    return direct if direct.is_file() else None


def _display_built(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return str(path)


def attach_file_similarity(report: StatusReport, cfg: ProjectConfig) -> None:
    """Score the raw link when configured, otherwise the built image."""
    raw = getattr(cfg, "raw_link", None)
    built = find_built_image(cfg.root, cfg.target_name, raw)
    if built is None:
        # A configured raw_link never falls back to build/<target>, so a
        # missing one scores nothing at all.  Say so: the panel would
        # otherwise read as "not built yet" on a project that built fine.
        if raw is not None:
            report.file_missing_raw_link = _display_built(cfg.root, Path(raw))
            log.warning(
                "status: configured raw_link %s does not exist, no image "
                "similarity score (not falling back to build/%s)",
                raw,
                cfg.target_name,
            )
        return
    ref = Path(getattr(cfg, "target_binary", "") or "")
    if not ref.is_file():
        return
    reference, produced = ref.read_bytes(), built.read_bytes()
    matched, total = compare_file_bytes(reference, produced)
    report.file_matched_bytes = matched
    report.file_total_bytes = total
    report.file_built = _display_built(cfg.root, built)
    loaded = _status_binding("target_binary", target_binary, alias="_target_binary")(cfg)
    if loaded is not None:
        cursor = 0
        for sec in sorted(loaded[1].sections.values(), key=lambda s: s.file_offset):
            lo, hi = (
                max(cursor, sec.file_offset),
                min(len(reference), sec.file_offset + sec.raw_size),
            )
            if hi <= lo:
                continue
            same, span = compare_file_bytes(reference[lo:hi], produced[lo:hi])
            report.file_sections[sec.name] = {"matched_bytes": same, "total_bytes": span}
            cursor = hi
        report.file_sections["headers / other"] = {
            "matched_bytes": matched
            - sum(s["matched_bytes"] for s in report.file_sections.values()),
            "total_bytes": total - sum(s["total_bytes"] for s in report.file_sections.values()),
        }


def _entry_va(entry_data: dict[str, Any]) -> int | None:
    """The VA of a verify-cache row, or None when it has none or it is malformed."""
    try:
        return int(str(entry_data.get("va")), 16)
    except ValueError:
        return None


def load_cache_raw(cfg: ProjectConfig) -> dict[str, Any] | None:
    """The verify-cache document for *cfg*, or None when it is not ours.

    One guard for every status reader: a cache written for another target,
    another binary, another compiler config, or another cache schema
    version must not drive this project's summary or effective statuses.
    The predicate itself lives in :mod:`rebrew.verify.cache` so status, todo,
    residue, and the compile path cannot drift apart on what "ours" means —
    each re-deriving it is how a cache earned under an older toolchain kept
    being reported as current while ``rebrew verify`` recompiled it away.
    """
    from rebrew.verify.cache import cache_identity_matches, load_verify_cache_raw

    # Every status reader only looks at the document, so share the memoized
    # entries instead of deep-copying the whole cache per reader.
    raw = load_verify_cache_raw(cfg, isolate=False)
    if not isinstance(raw, dict) or not cache_identity_matches(raw, cfg):
        return None
    return raw


def load_verify_info(
    cfg: ProjectConfig,
    library_vas: frozenset[int] | set[int] = frozenset(),
    raw: dict[str, Any] | None = None,
    *,
    sources: list[Path] | None = None,
) -> VerifyInfo | None:
    """Load last verify summary from the verify cache file.

    Passes on *library_vas* are also counted separately: verify compiles
    them, but status leaves library code out of progress.  *raw* is the
    already-validated document when the caller has one, so a run that also
    needs the effective statuses reads the cache once.
    """
    from rebrew.metadata.functions import metadata_path
    from rebrew.verify.cache import cache_path_for

    cache_path = cache_path_for(cfg, for_read=True)
    if raw is None:
        raw = _status_binding("load_cache_raw", load_cache_raw, alias="_load_cache_raw")(cfg)
    if raw is None:
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

    # ISO-8601 with an explicit offset, like every other instant the package
    # emits: a trailing " UTC" would make the field unreadable by
    # ``datetime.fromisoformat``, and minute truncation reports the same
    # instant for two consecutive runs.
    cache_mtime_ns: int | None
    try:
        st = cache_path.stat()
        timestamp = datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat(timespec="seconds")
        cache_mtime_ns = st.st_mtime_ns
    except OSError:
        timestamp = ""
        cache_mtime_ns = None
    # Freshness: a source or function metadata changed after the cache makes
    # the summary stale; SIZE/CFLAGS/TOOLCHAIN edits need no source rewrite.
    # ``last_change_ns`` includes ctime, so a same-size rewrite that restored
    # the old mtime still reads as newer.  Stat once per path and compare
    # against the cache snapshot.  An unreadable cache mtime leaves freshness
    # unknown, which reports stale rather than current.
    stale = cache_mtime_ns is None
    if cache_mtime_ns:
        scan_sources = _status_binding("iter_sources", iter_sources)
        paths = scan_sources(cfg.reversed_dir, cfg) if sources is None else sources
        for src in [*paths, metadata_path(cfg)]:
            try:
                if last_change_ns(src.stat()) > cache_mtime_ns:
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
    details = _status_binding("load_verify_details", load_verify_details)(cfg)
    return {va: status for va, (status, _effective) in details.items()}


def load_verify_details(
    cfg: ProjectConfig, raw: dict[str, Any] | None = None
) -> dict[int, tuple[str, bool]]:
    """Load per-VA ``(status, effective_match)`` from the verify cache.

    *effective_match* marks functions whose entire delta is register
    allocation (reccmp's 100% effective-match case) — candidates worth
    proving even though bytes differ.  *raw* is the already-validated
    document when the caller has one.
    """
    from rebrew.metadata.document import canonical_va_key

    if raw is None:
        raw = _status_binding("load_cache_raw", load_cache_raw, alias="_load_cache_raw")(cfg)
    if raw is None:
        return {}

    entries = raw.get("entries")
    if not isinstance(entries, dict):
        return {}

    details: dict[int, tuple[str, bool]] = {}
    for va_str, entry_data in entries.items():
        if not isinstance(entry_data, dict):
            continue
        status = entry_data.get("status", "")
        # A hand-edited non-string would reach effective_status's .strip().
        if not isinstance(status, str) or not status:
            continue
        va = canonical_va_key(va_str)
        if not isinstance(va, int):
            continue
        details[va] = (status, bool(entry_data.get("effective_match", False)))
    return details


def _canonical_status_fast(value: str) -> str:
    """Canonical status without the alias lookup on the hot path.

    Most inputs are already canonical TOML/cache spellings; only the
    ``NEAR_MATCH`` alias needs folding.  ``canonical_status`` in
    ``metadata.functions`` remains the full normalization for cold paths.
    """
    folded = value.strip().upper()
    return STATUS_ALIASES.get(folded, folded)


def effective_status(ann_status: str, cached: str | None) -> str:
    """The status reported for a function: metadata *ann_status* overlaid by
    the verify cache verdict *cached* (``None`` when uncached).

    Both sides are canonical spellings (``canonical_status``): upper case,
    trimmed, with the ``NEAR_MATCH`` alias folded to ``NEAR_MATCHING``. The
    writer already stores that spelling; a hand-edited lower-case row must
    take the same branch.

    Metadata PROVEN and SKIP win: `rebrew prove` compiles after any cached
    verdict (the next verify/test replaces PROVEN), and SKIP is user parking.
    Metadata STUB wins over the cache's SIZE_MISMATCH/MISSING_SIZE/STUB (a
    stub's size mismatch is expected); every other cached verdict wins.
    A sourced function without either status defaults to STUB.
    """
    ann = _canonical_status_fast(ann_status or "")
    cache = _canonical_status_fast(cached) if cached and str(cached).strip() else None
    if ann in ("PROVEN", "SKIP"):
        return ann
    if (
        ann == "STUB"
        and cache is not None
        and (cache == "STUB" or cache in STUB_PLACEHOLDER_STATUSES)
    ):
        return ann
    return cache or ann or "STUB"


#: Fill bytes the linker and compiler place between functions.
_PADDING_BYTES = b"\xcc\x90\x00"


def _count_gap(chunk: bytes, padding: int, unattributed: int) -> tuple[int, int]:
    """Fold one uncovered *chunk* into the running gap totals.

    Recognize fill at the edges; zero operands inside unknown code are not
    alignment. ``bytes.strip`` scans in C.
    """
    # ponytail: edge-fill heuristic; decode gaps if precise attribution is needed.
    fill = len(chunk) - len(chunk.strip(_PADDING_BYTES))
    return padding + fill, unattributed + (len(chunk) - fill)


def native_tail_span(
    span_start: int,
    span_size: int,
    inventory_size: int,
    next_start: int | None,
    text_hi: int,
) -> tuple[int, int] | None:
    """Bytes between a matched body and the row's native extent end.

    A discoverer extent can be longer than the annotated body: a split part,
    an internal jump table, or alignment the next entry does not start on.
    Those bytes belong to the discovered function, so attribute them instead
    of leaving them as unattributed ``NO_FUNCTION`` fill.  They stay unmatched:
    the byte comparison only covered *span_size*.
    """
    end = span_start + span_size
    native_end = span_start + inventory_size
    if next_start is not None:
        native_end = min(native_end, next_start)
    native_end = min(native_end, text_hi)
    if native_end <= end:
        return None
    return end, native_end - end


def _span_intervals(
    text: bytes, text_va: int, spans: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Clamp each ``(va, size)`` span to a half-open interval in *text*."""
    intervals: list[tuple[int, int]] = []
    for va, size in spans:
        lo = max(0, va - text_va)
        hi = min(len(text), va - text_va + size)
        if hi > lo:
            intervals.append((lo, hi))
    return intervals


def classify_text_gaps(text: bytes, text_va: int, spans: list[tuple[int, int]]) -> tuple[int, int]:
    """``(padding, unattributed)``: bytes of *text* in none of *spans*.

    *spans* are ``(va, size)`` function extents. Edge runs of alignment fill
    count as padding; anything else is code or data no known
    function covers (a thunk, a switch table, an undiscovered function).

    Only the complement of the spans is classified: the covered ranges are
    merged into an interval list and the gaps between them are counted in
    place, so the cost tracks the gap bytes rather than the section size.
    """
    intervals = _span_intervals(text, text_va, spans)
    padding = unattributed = 0
    cursor = 0
    for lo, hi in sorted(intervals):
        if lo > cursor:
            padding, unattributed = _count_gap(text[cursor:lo], padding, unattributed)
        cursor = max(cursor, hi)
    if cursor < len(text):
        padding, unattributed = _count_gap(text[cursor:], padding, unattributed)
    return padding, unattributed


def classify_unattributed_ranges(
    text: bytes, text_va: int, spans: list[tuple[int, int]]
) -> tuple[int, list[tuple[int, int]]]:
    """``(padding, unattributed_ranges)`` for bytes of *text* in no span.

    Edge alignment fill counts as padding; the middle of each gap is returned
    as an absolute ``(va, size)`` range so a caller can tell what the
    unattributed bytes are instead of only how many.
    """
    intervals = _span_intervals(text, text_va, spans)
    padding = 0
    ranges: list[tuple[int, int]] = []
    cursor = 0
    for lo, hi in sorted(intervals) + [(len(text), len(text))]:
        if lo > cursor:
            chunk = text[cursor:lo]
            lead = len(chunk) - len(chunk.lstrip(_PADDING_BYTES))
            trail = len(chunk) - len(chunk.rstrip(_PADDING_BYTES))
            fill = min(len(chunk), lead + trail)
            padding += fill
            if len(chunk) - fill > 0:
                ranges.append((text_va + cursor + lead, len(chunk) - fill))
        cursor = max(cursor, hi)
    return padding, ranges


def _text_gap_ranges(
    cfg: ProjectConfig, spans: list[tuple[int, int]]
) -> tuple[int, list[tuple[int, int]]] | None:
    """:func:`classify_unattributed_ranges` over the target's ``.text``."""
    if not cfg.target_binary.is_file():
        return None
    try:
        from rebrew.formats.binary_loader import load_binary

        info = load_binary(cfg.target_binary)
        sec = info.sections[".text"]
    except (OSError, KeyError, ValueError) as exc:
        log.warning("cannot load %s for .text gap ranges: %s", cfg.target_binary, exc)
        return None
    text_bytes = info.data[sec.file_offset : sec.file_offset + min(sec.size, sec.raw_size)]
    return classify_unattributed_ranges(text_bytes, sec.va, spans)


def _split_tail_fill(
    cfg: ProjectConfig, ranges: list[tuple[int, int]]
) -> tuple[int, list[tuple[int, int]]]:
    """Split native tails into ``(fill_bytes, measured_ranges)``.

    A native tail beyond the compiled body is either fill or code the compile
    never measured.  Only fill leaves the unverified bucket, so a table is not
    reclassified as padding by a byte-looking guess.
    """
    if not ranges or not cfg.target_binary.is_file():
        return 0, list(ranges)
    try:
        from rebrew.formats.binary_loader import PADDING_BYTES, load_binary

        info = load_binary(cfg.target_binary)
        sec = info.sections[".text"]
    except (OSError, KeyError, ValueError) as exc:
        log.warning("cannot load %s for tail fill split: %s", cfg.target_binary, exc)
        return 0, list(ranges)
    text_bytes = info.data[sec.file_offset : sec.file_offset + min(sec.size, sec.raw_size)]
    fill = 0
    kept: list[tuple[int, int]] = []
    for lo, size in ranges:
        start = lo - sec.va
        chunk = text_bytes[start : start + size]
        if len(chunk) == size and all(b in PADDING_BYTES for b in chunk):
            fill += size
        else:
            kept.append((lo, size))
    return fill, kept


def compute_text_size(cfg: ProjectConfig) -> int:
    """Compute .text section size from binary headers. Returns 0 if unavailable."""
    if not cfg.target_binary.exists():
        return 0
    try:
        from rebrew.binary.sections import get_text_section_size

        return get_text_section_size(
            cfg.target_binary,
            root=getattr(cfg, "root", None),
            target=str(getattr(cfg, "target_name", "") or ""),
        )
    except (ImportError, OSError, ValueError) as exc:
        # 0 hides the byte-coverage bar, which reads as "no coverage" rather
        # than "the section headers could not be read".
        log.warning(".text size unavailable, byte coverage omitted: %s", exc)
        return 0


def merge_claimed(claimed: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort half-open intervals and union the ones that overlap or touch.

    Subtraction needs only the union, and a merged list is disjoint, so
    :func:`unclaimed` can bisect to the first overlapping claim instead of
    walking every earlier function in the section.
    """
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(claimed):
        if hi <= lo:
            continue
        if merged and lo <= merged[-1][1]:
            if hi > merged[-1][1]:
                merged[-1] = (merged[-1][0], hi)
        else:
            merged.append((lo, hi))
    return merged


def unclaimed(lo: int, hi: int, claimed: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Subtract *claimed* (sorted and disjoint) half-open intervals from a span."""
    if hi <= lo:
        return []
    index = bisect.bisect_left(claimed, (lo, lo))
    if index and claimed[index - 1][1] > lo:
        index -= 1
    pieces: list[tuple[int, int]] = []
    cursor = lo
    count = len(claimed)
    while index < count:
        claim_lo, claim_hi = claimed[index]
        index += 1
        if claim_lo >= hi:
            break
        if claim_hi <= cursor:
            continue
        if claim_lo > cursor:
            pieces.append((cursor, claim_lo))
        cursor = claim_hi
        if cursor >= hi:
            break
    if cursor < hi:
        pieces.append((cursor, hi))
    return pieces


#: ``load_data`` return value: inventory functions, resolved rows, and the
#: VA-to-file navigation map.
SourceData = tuple[list[Any], dict[int, dict[str, str]], dict[int, str]]


def data_byte_coverage(
    spans: list[tuple[int, int]], ranges: list[tuple[int, int]]
) -> tuple[int, int]:
    """Covered bytes inside *ranges*, and the size of their union.

    *spans* are half-open symbol extents. A symbol that runs
    past the file-backed range is clipped. Overlap counts once.
    """
    total = merged_span_bytes(ranges)
    if not spans or not ranges:
        return 0, total
    # Ranges in real use are the .data/.rdata file extents (a handful), but a
    # symbol can span several when they are fragmented; walk both lists in
    # sorted order once instead of testing every (span, range) pair.
    sorted_ranges = sorted((lo, hi) for lo, hi in ranges if hi > lo)
    clipped: list[tuple[int, int]] = []
    ri = 0
    for lo, hi in sorted(spans):
        if hi <= lo:
            continue
        while ri < len(sorted_ranges) and sorted_ranges[ri][1] <= lo:
            ri += 1
        rj = ri
        while rj < len(sorted_ranges) and sorted_ranges[rj][0] < hi:
            start = max(lo, sorted_ranges[rj][0])
            end = min(hi, sorted_ranges[rj][1])
            if end > start:
                clipped.append((start, end))
            rj += 1
    return merged_span_bytes(clipped), total


def pe_data_directory(info: BinaryInfo, kind: str) -> tuple[int, int]:
    """``(va, size)`` of the PE data directory *kind* (``IAT``, ``IMPORT_TABLE``), or ``(0, 0)``.

    Read from :attr:`BinaryInfo.data_directories`, which the loader fills for
    either optional-header magic. A directory the image does not carry is
    ``(0, 0)``: the caller must not treat that as an address to cut, and
    ``(0, 0)`` is the only value that says "absent".
    """
    for directory in info.data_directories:
        if directory.kind == kind:
            return directory.va, directory.size
    return 0, 0


def cut_range(ranges: list[tuple[int, int]], lo: int, hi: int) -> list[tuple[int, int]]:
    """Drop ``[lo, hi)`` from every range."""
    if hi <= lo:
        return ranges
    out: list[tuple[int, int]] = []
    for start, end in ranges:
        if hi <= start or lo >= end:
            out.append((start, end))
            continue
        if start < lo:
            out.append((start, min(end, lo)))
        if hi < end:
            out.append((max(start, hi), end))
    return [(a, b) for a, b in out if b > a]


def target_binary(cfg: ProjectConfig) -> tuple[Path, BinaryInfo] | None:
    """Path and parse of the configured target binary, or None if unusable."""
    path = getattr(cfg, "target_binary", None)
    if path is None or not Path(path).is_file():
        return None
    try:
        from rebrew.formats.binary_loader import load_binary

        return Path(path), load_binary(Path(path))
    except (OSError, KeyError, ValueError) as exc:
        log.warning("cannot load %s for target binary: %s", path, exc)
        return None


def initialized_data_ranges(cfg: ProjectConfig) -> list[tuple[int, int]]:
    """File-backed ``.data`` and ``.rdata`` the link is responsible for.

    Virtual size past the raw size is the BSS tail: those bytes are not in
    the file, so their verdicts count symbols rather than initialized bytes.
    Raw size past the virtual size is file alignment. The overlap is the
    initialized bytes a verified symbol can cover.

    The IAT and the import directory through the end of ``.rdata`` are not
    in that overlap. ``postlink`` copies both from the reference, so a raw
    link that differs there has not lost game data.
    """
    loaded = _status_binding("target_binary", target_binary, alias="_target_binary")(cfg)
    if loaded is None:
        return []
    _path, info = loaded
    ranges: list[tuple[int, int]] = []
    rdata_end = 0
    for name in (".data", ".rdata"):
        sec = info.sections.get(name)
        if sec is None:
            continue
        extent = min(int(sec.size), int(sec.raw_size))
        if extent <= 0:
            continue
        start = int(sec.va)
        ranges.append((start, start + extent))
        if name == ".rdata":
            rdata_end = start + extent
    iat_va, iat_size = pe_data_directory(info, "IAT")
    imp_va, _imp_size = pe_data_directory(info, "IMPORT_TABLE")
    if iat_size:
        ranges = cut_range(ranges, iat_va, iat_va + iat_size)
    # An image with no import directory (a static link) has no import tail
    # to drop: imp_va is 0 there, and cutting from 0 would empty every range.
    if imp_va and rdata_end:
        ranges = cut_range(ranges, imp_va, rdata_end)
    return ranges


def postlink_copied_ranges(cfg: ProjectConfig) -> list[tuple[int, int]]:
    """IAT, and the import directory through the end of ``.rdata``.

    ``postlink`` copies both from the reference. A raw-link difference there
    is not a data row the status table should call drift.
    """
    loaded = _status_binding("target_binary", target_binary, alias="_target_binary")(cfg)
    if loaded is None:
        return []
    _path, info = loaded
    rdata = info.sections.get(".rdata")
    rdata_end = 0
    if rdata is not None:
        extent = min(int(rdata.size), int(rdata.raw_size))
        if extent > 0:
            rdata_end = int(rdata.va) + extent
    copied: list[tuple[int, int]] = []
    iat_va, iat_size = pe_data_directory(info, "IAT")
    imp_va, _imp_size = pe_data_directory(info, "IMPORT_TABLE")
    if iat_size:
        copied.append((iat_va, iat_va + iat_size))
    if imp_va and rdata_end > imp_va:
        copied.append((imp_va, rdata_end))
    return copied


def span_is_copied(va: int, size: int, copied: list[tuple[int, int]]) -> bool:
    """True when ``[va, va + size)`` sits entirely inside a copied range."""
    if size <= 0:
        return False
    end = va + size
    return any(lo <= va and end <= hi for lo, hi in copied)


def collect_status(
    cfg: ProjectConfig,
    *,
    tree: list[Path] | None = None,
    data: SourceData | None = None,
    trusted: Any = None,
    bound_inventory: list[dict[str, Any]] | None = None,
) -> StatusReport:
    """Collect all project health data into a StatusReport.

    This is the single testable entry point for status data collection.
    It reads source bindings, metadata, and function structure (no compilation).

    When a verify cache exists, its byte verdicts override metadata statuses so
    that functions which fail verification (NEAR_MATCHING, COMPILE_ERROR) are
    not counted as byte-matched.  Metadata PROVEN/SKIP always win, and a
    metadata STUB wins over the cache's STUB/SIZE_MISMATCH/MISSING_SIZE
    placeholders (see :func:`effective_status`).

    *tree* and *data* are a :func:`rebrew.source.discovery.scan_files` result and the
    matching :func:`rebrew.naming.load_data` result for this config.  A caller
    that already loaded them (``todo`` does) passes both so the scan and
    source-binding pass are not repeated.

    *bound_inventory* is the retained inventory (``trusted_function_list``) a
    caller has already bound *trusted* against for this config and *tree*
    (``trusted.bind``); the source scan and the bind are not repeated.
    """
    from rebrew.naming import load_data
    from rebrew.source.discovery import scan_files

    report = StatusReport(
        target=cfg.target_name,
        binary=str(cfg.target_binary),
        arch=cfg.arch,
    )

    # One traversal of the reversed tree serves every consumer below
    # (`load_data`'s source and library-header passes, the file count, and the
    # inline-metadata census).  Each of those is a whole-tree walk on its own,
    # and a project's tree holds one directory read per subdirectory per walk.
    if tree is None:
        tree = scan_files(cfg.reversed_dir)

    attach_file_sim = _status_binding(
        "attach_file_similarity", attach_file_similarity, alias="_attach_file_similarity"
    )

    try:
        ghidra_funcs, existing, _covered_vas = (
            data if data is not None else load_data(cfg, tree=tree)
        )
        from rebrew.naming import external_vas, inside_annotated_vas, scope_to_target

        # Before scoping: external .lib rows carry library modules
        # (D3DX8, MSVCRT, …) and must leave the denominators whatever the
        # module — identified external code is not pending work.  The flag
        # is `targets.<name>.external_libs` (plus LIBRARY binding rows).
        library_vas = external_vas(existing, getattr(cfg, "external_libs", None))
        existing = scope_to_target(existing, cfg)
        if trusted is not None:
            from rebrew.catalog.loaders import scan_reversed_dir, trusted_function_list

            inventory = bound_inventory
            if inventory is None:
                inventory = trusted_function_list(cfg)
                trusted.bind(
                    cfg, scan_reversed_dir(cfg.reversed_dir, cfg=cfg, scanned=tree), inventory
                )
            sizes = {int(item["va"]): int(item["size"]) for item in inventory}
            existing = {
                va: {
                    **info,
                    "size": str(sizes[va]),
                    "status": (
                        record.status
                        if (
                            record := trusted.verdict(
                                cfg.root, cfg.reversed_dir / info["filename"], va
                            )
                        )
                        else "UNKNOWN"
                    ),
                    "kind": "FUNCTION",
                    "source": "",
                }
                for va, info in existing.items()
                if va in sizes
            }
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        if trusted is not None:
            raise
        # Graceful degradation: return zeroed report.  ValueError is what the
        # loaders raise for a corrupt structure JSON, so omitting it meant the
        # documented fallback skipped exactly the case it exists for.  The
        # failure is reported because a zeroed panel reads as "no work left"
        # on a project that has thousands of pending functions.
        log.warning(
            "status: could not load the function inventory (%s: %s); reporting zeroed coverage",
            type(exc).__name__,
            exc,
        )
        report.load_error = f"{type(exc).__name__}: {exc}"
        attach_file_sim(report, cfg)
        return report

    ghidra_vas = {f.va for f in ghidra_funcs}

    # Count FUNCTION rows and inventory entries, excluding recorded library
    # attributions. Vendored library code tracked as FUNCTION still counts;
    # this classification describes tracked work, not the code's origin.
    function_vas = {va for va in existing if va not in library_vas}
    # Switch arms and split bodies inside an annotated function are not
    # functions (the same rule `rebrew todo` applies).
    pseudo_vas = inside_annotated_vas(ghidra_funcs, existing) if trusted is None else set()
    report.total_functions = len(function_vas | (ghidra_vas - library_vas - pseudo_vas))
    report.covered_functions = len(function_vas)

    src_dir = Path(cfg.reversed_dir)
    scan_sources = _status_binding("iter_sources", iter_sources)
    sources = scan_sources(src_dir, cfg, scanned=tree)
    report.source_files = len(sources)

    # Load the verify cache for the effective-status overlay.
    # Metadata statuses may be optimistic (e.g. STATUS: RELOC) while
    # the actual verify result is STUB.  A cached byte verdict wins except
    # against metadata PROVEN/SKIP, and a metadata STUB wins over the cache's
    # STUB/SIZE_MISMATCH/MISSING_SIZE placeholders (effective_status).
    # One validated read serves both the per-VA details below and the
    # summary: each load deep-copies the whole document.
    cache_raw = (
        _status_binding("load_cache_raw", load_cache_raw, alias="_load_cache_raw")(cfg)
        if trusted is None
        else None
    )
    verify_details = (
        _status_binding("load_verify_details", load_verify_details)(cfg, cache_raw)
        if trusted is None
        else {}
    )
    verify_statuses = {va: status for va, (status, _eff) in verify_details.items()}

    similarity_values: dict[str, list[float]] = {}
    # Single pass: status breakdown + byte-level coverage.
    status_counts: dict[str, int] = {}
    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    loaded = _status_binding("target_binary", target_binary, alias="_target_binary")(cfg)
    text_section = loaded[1].sections.get(".text") if loaded is not None else None
    # Pseudo-functions (switch arms inside an annotated function) are not
    # starts: cutting at one gave the arm the rest of its matched parent.
    starts = sorted((size_by_va.keys() | existing.keys()) - pseudo_vas)
    inventory_starts = sorted(size_by_va)

    def _span(va: int, info: dict[str, str]) -> tuple[int, int]:
        """Start and size of *va*, clipped to .text and the next function.

        A compiled function's annotated SIZE is what verify compared, so it
        wins; the inventory extent can include padding or a split body.
        Library extents can be truncated in either annotation or discovery
        (for example, at the first return before another branch's epilogue),
        so retain the larger extent, bounded by the next function and .text.
        """
        try:
            annotated = int(info.get("size") or 0)
        except TypeError, ValueError:
            annotated = 0
        inventory = size_by_va.get(va, 0)
        size = max(inventory, annotated) if va in library_vas else (annotated or inventory)
        # A negative SIZE is truthy, so it would win the selection above and
        # then move matched_bytes the wrong way.
        size = clip_span(starts, va, max(size, 0))
        if text_section is not None:
            lo = max(va, text_section.va)
            hi = min(va + size, text_section.va + text_section.size)
            va, size = lo, max(0, hi - lo)
        return va, size

    matched_bytes = 0
    unmatched_bytes = 0
    spans: list[tuple[int, int]] = []
    native_tails: list[tuple[int, int]] = []
    naked_matched = 0
    naked_bytes = 0
    verify_overrides = 0
    verify_missing_size = 0
    effective_matches = 0
    library_identified = 0
    derived_starts: list[int] = []
    for va, info in existing.items():
        # External .lib attributions (library match identifications + modules
        # flagged in external_libs) are not reversing progress: count them
        # separately so the progress table answers "how much of this
        # binary's code is reversed".  They DO count toward .text byte
        # coverage: the deliverable must reproduce the whole image, and
        # stock-linked library bytes are reproduced bytes.  The row's own
        # STATUS is ignored: the attribution is the identification.
        if va in library_vas:
            library_identified += 1
            span_va, size = _span(va, info)
            if size == 0:
                derived_starts.append(span_va)
            if trusted is None:
                matched_bytes += size
                report.status_bytes["LIBRARY"] = report.status_bytes.get("LIBRARY", 0) + size
            else:
                # Trusted coverage reads the project's classification as which
                # code is library, never as a match: only a trusted verdict
                # matches a library row.
                report.library_bytes += size
                if info.get("status") in MATCHED_STATUSES:
                    report.library_verified += 1
                    report.library_verified_bytes += size
                    matched_bytes += size
                    report.status_bytes["LIBRARY"] = report.status_bytes.get("LIBRARY", 0) + size
            spans.append((span_va, size))
            # Bucketed as LIBRARY: a status left over from before the row was
            # identified as library code would read as reversing progress.
            module = info.get("module") or "?"
            report.module_status.setdefault(module, {})
            report.module_status[module]["LIBRARY"] = (
                report.module_status[module].get("LIBRARY", 0) + 1
            )
            continue
        ann_status = info.get("status", "STUB")
        # A naked reconstruction (`source = "naked"`) is byte-exact via a
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
        score = info.get("similarity")
        if score is not None and effective == ann_status:
            similarity_values.setdefault(effective, []).append(float(score))
        span_va, size = _span(va, info)
        inventory_size = size_by_va.get(va, 0)
        report.status_bytes[effective] = report.status_bytes.get(effective, 0) + size
        spans.append((span_va, size))
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
        if text_section is not None and inventory_size > size:
            # Only a discovered entry defines a native boundary. A metadata row
            # without an inventory extent cannot claim the bytes after it, so a
            # split row must not cut the previous entry's native tail short.
            index = bisect.bisect_right(inventory_starts, va)
            next_start = inventory_starts[index] if index < len(inventory_starts) else None
            tail = native_tail_span(
                span_va,
                size,
                inventory_size,
                next_start,
                text_section.va + text_section.size,
            )
            if tail is not None:
                native_tails.append(tail)
    report.similarity = {
        status: {"count": len(values), "mean": sum(values) / len(values)}
        for status, values in similarity_values.items()
    }
    report.status_counts = status_counts
    report.library_identified = library_identified
    report.matched_bytes = matched_bytes
    report.naked_matched = naked_matched
    report.naked_bytes = naked_bytes
    get_text_size = _status_binding(
        "compute_text_size", compute_text_size, alias="_compute_text_size"
    )
    report.total_text_bytes = text_section.size if text_section is not None else get_text_size(cfg)
    # Functions nobody has started (not pseudo-functions, not library code).
    for va in ghidra_vas - existing.keys() - library_vas - pseudo_vas:
        span_va, size = _span(va, {})
        unmatched_bytes += size
        report.status_bytes["NO_SOURCE"] = report.status_bytes.get("NO_SOURCE", 0) + size
        spans.append((span_va, size))
    claimed = merge_claimed([(va, va + size) for va, size in spans if size > 0])
    tail_bytes = 0
    tail_ranges: list[tuple[int, int]] = []
    for va, size in native_tails:
        for lo, hi in unclaimed(va, va + size, claimed):
            tail_bytes += hi - lo
            tail_ranges.append((lo, hi - lo))
            spans.append((lo, hi - lo))
    if tail_ranges:
        # The discoverer extent runs to the next start, so a tail is usually the
        # alignment fill after the body.  Fill is padding, not function bytes:
        # counting it as unverified code made the coverage table read as if
        # whole functions were missing when only their alignment was.
        fill_bytes, measured = _split_tail_fill(cfg, tail_ranges)
        tail_bytes -= fill_bytes
        report.tail_padding_bytes = fill_bytes
        report.unverified_tail_ranges = measured
    if tail_bytes:
        unmatched_bytes += tail_bytes
        report.status_bytes["UNVERIFIED_TAIL"] = tail_bytes

    # An identified LIBRARY row without a recorded extent still owns the bytes
    # up to the next known start. Attribute only bytes no other span claims, so
    # a coarse inventory function or a started row always wins, and never extend
    # past .text.
    if derived_starts and text_section is not None:
        text_lo = text_section.va
        text_hi = text_section.va + text_section.size
        known_starts = sorted(set(starts) | {min(va, text_hi) for va in derived_starts} | {text_hi})
        claimed = merge_claimed([(span_va, span_va + size) for span_va, size in spans if size > 0])

        derived = 0
        for va in sorted(set(derived_starts)):
            lo = max(va, text_lo)
            index = bisect.bisect_right(known_starts, va)
            hi = known_starts[index] if index < len(known_starts) else text_hi
            hi = min(hi, text_hi)
            for piece_lo, piece_hi in unclaimed(lo, hi, claimed):
                length = piece_hi - piece_lo
                if length <= 0:
                    continue
                derived += length
                spans.append((piece_lo, length))
        report.library_derived_bytes = derived
        if trusted is None:
            matched_bytes += derived
            report.matched_bytes = matched_bytes
            report.status_bytes["LIBRARY"] = report.status_bytes.get("LIBRARY", 0) + derived
        else:
            report.library_bytes += derived

    report.unmatched_bytes = unmatched_bytes
    gaps = _text_gap_ranges(cfg, spans)
    if gaps is not None:
        report.padding_bytes = gaps[0] + report.tail_padding_bytes
        report.unattributed_ranges = gaps[1]
        # Any virtual tail with no file bytes remains unaccounted for.
        report.unattributed_bytes = (
            report.total_text_bytes
            - matched_bytes
            - unmatched_bytes
            - report.padding_bytes
            - (report.library_bytes - report.library_verified_bytes)
        )
    report.verify_overrides = verify_overrides
    report.verify_missing_size = verify_missing_size
    report.effective_matches = effective_matches

    # Data verdicts: count rebrew-data.toml STATUS values written by
    # `verify --data`.  Named symbols only — unnamed inventory rows carry
    # no verdict.
    from rebrew.data.layout import data_symbol_size
    from rebrew.metadata.data import (
        DATA_STATUS_DISPLACED,
        DATA_STATUS_EXACT,
        data_status_bucket,
        load_data_metadata,
        module_visible_to_target,
    )

    data_spans: dict[str, list[tuple[int, int]]] = {"verified": [], "drift": [], "unchecked": []}
    copied = _status_binding("postlink_copied_ranges", postlink_copied_ranges)(cfg)
    for (module, va), fields in load_data_metadata(cfg.metadata_dir, deepcopy=False).items():
        if not module_visible_to_target(module, cfg):
            continue
        if not fields.get("name"):
            continue
        size = data_symbol_size(fields, arch=getattr(cfg, "arch", "x86_32"))
        if span_is_copied(va, size, copied):
            continue
        verdict = str(fields.get("status") or "").strip().upper() if trusted is None else ""
        bucket = data_status_bucket(verdict)
        if bucket == "verified":
            report.data_verified += 1
            report.data_exact += verdict == DATA_STATUS_EXACT
        elif bucket == "drift":
            report.data_drift += 1
            report.data_displaced += verdict == DATA_STATUS_DISPLACED
        else:
            report.data_unchecked += 1
        section = str(fields.get("section") or "").strip().lower() or "(no section)"
        counts = report.data_sections.setdefault(
            section, {"verified": 0, "drift": 0, "unchecked": 0}
        )
        counts[bucket] += 1
        if size > 0:
            data_spans[bucket].append((va, va + size))
    ranges = _status_binding(
        "initialized_data_ranges", initialized_data_ranges, alias="_initialized_data_ranges"
    )(cfg)
    # Count each byte once. DRIFT beats UNCHECKED beats VERIFIED when
    # overlapping symbols disagree, so uncertainty cannot inflate progress.
    cumulative: list[tuple[int, int]] = []
    previous = 0
    for bucket in ("drift", "unchecked", "verified"):
        cumulative.extend(data_spans[bucket])
        covered, report.data_total_bytes = data_byte_coverage(cumulative, ranges)
        report.data_bytes[bucket] = covered - previous
        previous = covered
    report.data_bytes["untracked"] = report.data_total_bytes - previous
    report.data_verified_bytes = report.data_bytes["verified"]
    verified, _ = data_byte_coverage(data_spans["verified"], ranges)
    report.data_conflicting_verified_bytes = verified - report.data_verified_bytes

    # Verify info
    if trusted is None:
        get_verify_info = _status_binding(
            "load_verify_info", load_verify_info, alias="_load_verify_info"
        )
        report.verify_info = get_verify_info(cfg, library_vas, cache_raw, sources=sources)
        attach_file_sim(report, cfg)

    return report
