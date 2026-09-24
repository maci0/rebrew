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
from rebrew.sources import iter_sources
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

    # Non-library functions with a non-empty BLOCKER whose effective status
    # is neither byte-matched (EXACT/RELOC) nor parked (SKIP): the set
    # `rebrew todo -c blocked` lists.
    unresolved_blockers: int = 0

    # Data verification verdicts from rebrew-data.toml STATUS (written by
    # `verify --data`): verified / drift / unchecked symbol counts.
    data_verified: int = 0
    data_drift: int = 0
    data_unchecked: int = 0

    # Derived percentages
    @property
    def coverage_pct(self) -> float:
        """Percentage of total functions that have a C source file (covered)."""
        if self.total_functions == 0:
            return 0.0
        return round(100.0 * self.covered_functions / self.total_functions, 1)

    @property
    def matched_pct(self) -> float:
        """Percentage of total functions that are byte-matched (EXACT or RELOC).

        PROVEN is excluded: it records semantic equivalence while the
        compiled bytes still differ from the target.
        """
        if self.total_functions == 0:
            return 0.0
        return round(100.0 * self.matched_functions / self.total_functions, 1)

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
        return round(100.0 * decompiled / self.total_functions, 1)

    @property
    def byte_coverage_pct(self) -> float:
        """Percentage of ``.text`` bytes in byte-matched (EXACT/RELOC) functions,
        library attributions included."""
        if self.total_text_bytes == 0:
            return 0.0
        return round(100.0 * self.matched_bytes / self.total_text_bytes, 1)

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
            "unresolved_blockers": self.unresolved_blockers,
            "data": {
                "verified": self.data_verified,
                "drift": self.data_drift,
                "unchecked": self.data_unchecked,
            },
        }
        if self.total_text_bytes > 0:
            d["matched_bytes"] = self.matched_bytes
            d["total_text_bytes"] = self.total_text_bytes
            d["byte_coverage_pct"] = self.byte_coverage_pct
        if self.verify_info is not None:
            d["last_verify"] = {
                "timestamp": self.verify_info.timestamp,
                "passed": self.verify_info.passed,
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


def _load_verify_info(cfg: ProjectConfig) -> VerifyInfo | None:
    """Load last verify summary from the verify cache file."""
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

    entries = raw.get("entries")
    if not isinstance(entries, dict) or not entries:
        return None

    passed = 0
    failed = 0
    for entry_data in entries.values():
        if not isinstance(entry_data, dict):
            continue
        # A row without a verdict status is malformed — skipped, never
        # counted as failed.
        if not entry_data.get("status"):
            continue
        if entry_data.get("passed", False):
            passed += 1
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
    from rebrew.verify_cache import load_verify_cache_raw

    raw = load_verify_cache_raw(cfg)
    if raw is None:
        return {}

    if not isinstance(raw, dict):
        return {}
    # Same target guard as _load_verify_info: another target's cache must not
    # override this project's source statuses.
    if raw.get("target") != getattr(cfg, "target_name", ""):
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
        from rebrew.naming import external_vas, scope_to_target

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
    report.total_functions = len(function_vas | (ghidra_vas - library_vas))
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
    matched_bytes = 0
    naked_matched = 0
    naked_bytes = 0
    verify_overrides = 0
    verify_missing_size = 0
    effective_matches = 0
    unresolved_blockers = 0
    library_identified = 0
    for va, info in existing.items():
        # External .lib attributions (lib-match identifications + modules
        # flagged in external_libs) are not reversing progress: count them
        # separately so the progress table answers "how much of this
        # binary's code is reversed".  They DO count toward .text byte
        # coverage: the deliverable must reproduce the whole image, and
        # stock-linked library bytes are reproduced bytes.
        if va in library_vas:
            lib_status = (info.get("status") or "STUB").upper()
            if lib_status in MATCHED_STATUSES:
                library_identified += 1
                size = size_by_va.get(va)
                if size is None:
                    try:
                        size = int(info.get("size") or 0)
                    except (TypeError, ValueError):
                        size = 0
                matched_bytes += size
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
        # Blocked work: the function is still unmatched and not parked.
        # `rebrew todo -c blocked` lists exactly these (same effective rule).
        if info.get("blocker") and effective not in (*MATCHED_STATUSES, "SKIP"):
            unresolved_blockers += 1
        if effective != ann_status:
            verify_overrides += 1
        if effective == "MISSING_SIZE":
            verify_missing_size += 1
        if verify_details.get(va, ("", False))[1] and effective not in MATCHED_STATUSES:
            effective_matches += 1
        status_counts[effective] = status_counts.get(effective, 0) + 1
        if effective in MATCHED_STATUSES:
            # Fall back to annotation-metadata SIZE when the Ghidra
            # function_structure.json is missing/stale — otherwise every
            # matched byte counted 0 and coverage read 0%.
            size = size_by_va.get(va)
            if size is None:
                try:
                    size = int(info.get("size") or 0)
                except (TypeError, ValueError):
                    size = 0
            if naked:
                naked_matched += 1
                naked_bytes += size
            matched_bytes += size
        module = info.get("module") or "?"
        report.module_status.setdefault(module, {})
        report.module_status[module][effective] = report.module_status[module].get(effective, 0) + 1
    report.status_counts = status_counts
    report.library_identified = library_identified
    report.matched_bytes = matched_bytes
    report.naked_matched = naked_matched
    report.naked_bytes = naked_bytes
    report.total_text_bytes = _compute_text_size(cfg)
    report.verify_overrides = verify_overrides
    report.verify_missing_size = verify_missing_size
    report.effective_matches = effective_matches
    report.unresolved_blockers = unresolved_blockers

    # Data verdicts: count rebrew-data.toml STATUS values written by
    # `verify --data`.  Named symbols only — unnamed inventory rows carry
    # no verdict.
    from rebrew.data_metadata import load_data_metadata

    for fields in load_data_metadata(cfg.metadata_dir).values():
        if not fields.get("name"):
            continue
        verdict = str(fields.get("status") or "UNCHECKED").upper()
        if verdict == "VERIFIED":
            report.data_verified += 1
        elif verdict == "DRIFT":
            report.data_drift += 1
        else:
            report.data_unchecked += 1

    # Verify info
    report.verify_info = _load_verify_info(cfg)

    # Quick W019 scan: files ``rebrew lint --fix`` can migrate — counted by
    # lint's own rule (shared header parser, no full lint run).
    from rebrew.lint import count_migratable_files

    report.inline_metadata_warning = count_migratable_files(src_dir, cfg)

    return report


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------


def _render_terminal(report: StatusReport) -> None:
    """Render the status report as a rich terminal dashboard."""
    # --- Header ---
    header_parts = [f"[bold]{report.target}[/bold]"]
    if report.binary:
        header_parts.append(f"[dim]{report.binary}[/dim]")
    header_parts.append(f"[dim]({report.arch})[/dim]")

    # --- Coverage bar ---
    bar_width = 40
    filled = int(bar_width * report.coverage_pct / 100) if report.total_functions > 0 else 0

    exact = report.status_counts.get("EXACT", 0)
    reloc = report.status_counts.get("RELOC", 0)
    proven = report.status_counts.get("PROVEN", 0)
    matching = report.status_counts.get("NEAR_MATCHING", 0)
    stub = report.status_counts.get("STUB", 0)

    bar_text = Text()
    bar_text.append("  Coverage  ", style="bold")
    bar_text.append("█" * filled, style="green")
    bar_text.append("░" * (bar_width - filled), style="dim")
    bar_text.append(
        f"  {report.covered_functions}/{report.total_functions}  ({report.coverage_pct}%)",
        style="bold",
    )

    # --- Status table ---
    status_table = Table(
        show_header=True,
        header_style="bold",
        pad_edge=False,
        box=None,
        expand=True,
    )
    status_table.add_column("Status", width=20)
    status_table.add_column("Count", justify="right", width=8)
    status_table.add_column("% of Total", justify="right", width=10)
    status_table.add_column("", width=20)  # Visual bar

    for status in _STATUS_ORDER:
        count = report.status_counts.get(status, 0)
        if count == 0:
            continue
        pct = round(100.0 * count / report.total_functions, 1) if report.total_functions else 0.0
        color = STATUS_COLORS.get(status, "white")
        mini_bar_len = int(20 * count / max(report.total_functions, 1))
        mini_bar = "█" * max(mini_bar_len, 1)
        status_table.add_row(
            f"[{color}]{status}[/{color}]",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{pct}%[/{color}]",
            f"[{color}]{mini_bar}[/{color}]",
        )

    # Other statuses not in the standard order
    other_statuses = sorted(set(report.status_counts) - set(_STATUS_ORDER))
    for status in other_statuses:
        count = report.status_counts[status]
        if count == 0:
            continue
        pct = round(100.0 * count / report.total_functions, 1) if report.total_functions else 0.0
        color = STATUS_COLORS.get(status, "red")
        status_table.add_row(
            f"[{color}]{status}[/{color}]",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{pct}%[/{color}]",
            "",
        )

    # --- Summary lines ---
    summary_lines: list[str] = []

    # Matched percentage
    summary_lines.append(
        f"  [green bold]{report.matched_pct}%[/green bold] byte-matched"
        f"  [dim]({exact + reloc} EXACT+RELOC / {report.total_functions} total)[/dim]"
    )

    # Naked reconstructions: byte-exact via generated asm, NOT decompiled.
    # The honest split (ct-recomp's NAKED vs PURE_C_EXACT): decompiled_pct
    # excludes them so mass-generated skeletons can't inflate progress.
    if report.naked_matched:
        summary_lines.append(
            f"  [magenta]{report.decompiled_pct}% decompiled[/magenta]"
            f"  [dim]({report.naked_matched} naked reconstructions, {report.naked_bytes:,}B"
            " byte-exact but not decompiled — implement the C bodies)[/dim]"
        )

    # Byte coverage
    if report.total_text_bytes > 0:
        summary_lines.append(
            f"  [cyan]{report.byte_coverage_pct}%[/cyan] .text bytes covered"
            f"  [dim]({report.matched_bytes:,}B / {report.total_text_bytes:,}B)[/dim]"
        )

    # Source file count
    summary_lines.append(f"  [dim]{report.source_files} source files[/dim]")
    if report.library_identified:
        summary_lines.append(
            f"  [dim]library:[/dim] [green]{report.library_identified} identified[/green] "
            "(lib-match attributions, not reversing progress)"
        )

    # Unresolved BLOCKERs (understood-blocked work needing attention)
    if report.unresolved_blockers:
        summary_lines.append(
            f"  [yellow]{report.unresolved_blockers} unresolved BLOCKER(s)[/yellow]"
            " — see rebrew todo / BLOCKER metadata"
        )

    # Data verification verdicts (from `verify --data`)
    data_total = report.data_verified + report.data_drift + report.data_unchecked
    if data_total:
        summary_lines.append(
            f"  [dim]data:[/dim] [green]{report.data_verified} verified[/green] / "
            f"[red]{report.data_drift} drift[/red] / "
            f"[dim]{report.data_unchecked} unchecked[/dim]"
        )

    # Pointer to the prioritized next-action list (PRD 05 status requirement)
    summary_lines.append(
        "  [bold]Next:[/bold] rebrew todo"
        if report.total_functions > 0
        else "  [dim]No functions yet[/dim]"
    )

    # Verify info
    if report.verify_info is not None:
        v = report.verify_info
        verify_color = "green" if v.failed == 0 else "yellow"
        stale_suffix = " [yellow](stale — run rebrew verify)[/yellow]" if v.stale else ""
        summary_lines.append(
            f"  Last verify: [{verify_color}]{v.passed} passed[/{verify_color}]"
            f"  [red]{v.failed} failed[/red]"
            f"  [dim]({v.timestamp})[/dim]{stale_suffix}"
        )
        # Effective-status overlay: verify results override metadata statuses.
        if report.verify_overrides:
            summary_lines.append(
                f"  [dim]Effective status: {report.verify_overrides} function(s) overridden"
                " by verify cache (metadata says otherwise — see docs/ANNOTATIONS.md)[/dim]"
            )
        if report.verify_missing_size:
            summary_lines.append(
                f"  [yellow]{report.verify_missing_size} function(s) MISSING_SIZE[/yellow]"
                " — set SIZE via metadata (rebrew cfg set) then re-run verify"
            )
        if report.effective_matches:
            summary_lines.append(
                f"  [cyan]{report.effective_matches} effective match(es)[/cyan]"
                " — register-allocation-only delta, prove candidates"
            )

    # W019 inline metadata warning
    if report.inline_metadata_warning:
        n = report.inline_metadata_warning
        summary_lines.append(
            f"  [yellow]Warning:[/yellow] {n} file(s) contain inline STATUS/CFLAGS/SIZE comments"
            " — run [bold]rebrew lint[/bold] to migrate to rebrew-functions.toml"
        )

    # --- Assemble panel ---
    from rich.console import Group

    panel_content = Group(
        bar_text,
        Text(""),  # spacer
        status_table,
        Text(""),  # spacer
        *[Text.from_markup(line) for line in summary_lines],
    )

    panel = Panel(
        panel_content,
        title="[bold]Rebrew Status[/bold]  " + "  ".join(header_parts),
        subtitle=(
            f"[green]{exact}E[/green] [cyan]{reloc}R[/cyan]"
            f" [magenta]{proven}P[/magenta] [yellow]{matching}M[/yellow]"
            f" [dim]{stub}S[/dim] → [bold]{report.matched_pct}%[/bold]"
        ),
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
