"""status.py – At-a-glance reversing progress overview.

Aggregates coverage data from annotations, function structure, and verify
cache into a concise project health dashboard.  No compilation is performed.

Usage::

    rebrew status                   Quick project overview
    rebrew status --json            Machine-readable JSON output
    rebrew status -t client_exe     Status for a specific target
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rebrew.cli import STATUS_COLORS, TargetOption, json_print, require_config
from rebrew.config import ProjectConfig
from rebrew.sources import iter_sources

# Regex that matches an inline metadata comment line (``// STATUS: EXACT``,
# ``// SIZE: 120``, ``// CFLAGS: /O2``, ``/* BLOCKER: ... */``, etc.).  The
# key set mirrors annotation.METADATA_KEYS but is kept inline to avoid a
# circular-import chain from status → annotation at module load time.
_W019_INLINE_RE = re.compile(
    r"(?://|/\*)\s*"
    r"(STATUS|ORIGIN|CFLAGS|SKIP|GLOBALS|BLOCKER|BLOCKER_DELTA|SOURCE|NOTE|"
    r"SECTION|GHIDRA|SIZE|ANALYSIS|PROVE_CONSTRAINTS|TOOLCHAIN)\s*:",
    re.IGNORECASE,
)
# Marker line (same shape as annotation.NEW_FUNC_CAPTURE_RE) — opens a header
# block whose following ``// KEY:`` comment lines are inline-metadata
# candidates (mirrors lint._parse_multi_headers' block attachment).
_W019_MARKER_RE = re.compile(
    r"(?://|/\*)\s*(?P<type>FUNCTION|LIBRARY|STUB|GLOBAL|DATA):\s*"
    r"(?P<module>\S+)\s+(?P<va>0x[0-9a-fA-F]+)"
)

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_STATUS_ORDER = ["EXACT", "RELOC", "NEAR_MATCHING", "STUB", "PROVEN"]


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

    # Per-module status breakdown: {module: {status: count}}
    module_status: dict[str, dict[str, int]] = field(default_factory=dict)

    # Verify cache summary
    verify_info: VerifyInfo | None = None

    # Effective-status overlay: how many functions' reported status differs
    # from their metadata status because the verify cache overrode it, and
    # how many are stuck on MISSING_SIZE (metadata SIZE missing → verify
    # could not extract).  Surfaced so the overlay is not emergent behavior.
    verify_overrides: int = 0
    verify_missing_size: int = 0

    # W019 quick-lint result: number of .c files with inline metadata comments.
    # 0 means no issues found (or scan not yet run).
    inline_metadata_warning: int = 0

    # Number of functions with a non-empty BLOCKER in rebrew-function.toml —
    # i.e. work that is currently understood-blocked and needs attention.
    unresolved_blockers: int = 0

    # Derived percentages
    @property
    def coverage_pct(self) -> float:
        """Percentage of total functions that have a C source file (covered)."""
        if self.total_functions == 0:
            return 0.0
        return round(100.0 * self.covered_functions / self.total_functions, 1)

    @property
    def matched_pct(self) -> float:
        """Percentage of total functions that are EXACT, RELOC, or PROVEN (byte-matched)."""
        if self.total_functions == 0:
            return 0.0
        exact = self.status_counts.get("EXACT", 0)
        reloc = self.status_counts.get("RELOC", 0)
        proven = self.status_counts.get("PROVEN", 0)
        return round(100.0 * (exact + reloc + proven) / self.total_functions, 1)

    @property
    def byte_coverage_pct(self) -> float:
        """Percentage of total binary bytes that are EXACT, RELOC, or PROVEN."""
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
            "coverage_pct": self.coverage_pct,
            "matched_pct": self.matched_pct,
            "source_files": self.source_files,
            "unresolved_blockers": self.unresolved_blockers,
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
            }
        if self.inline_metadata_warning:
            d["inline_metadata_warning"] = self.inline_metadata_warning
        return d


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


def _load_verify_info(cfg: ProjectConfig) -> VerifyInfo | None:
    """Load last verify summary from the verify cache file."""
    from rebrew.cli import load_verify_cache_raw

    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    raw = load_verify_cache_raw(cfg)
    if raw is None:
        return None

    if not isinstance(raw, dict) or raw.get("version") != 1:
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
        result = entry_data.get("result")
        if not isinstance(result, dict):
            continue  # null/malformed result — skip, don't count as failed
        if result.get("passed", False):
            passed += 1
        else:
            failed += 1

    # Try to get a last-modified timestamp from the file
    try:
        mtime = cache_path.stat().st_mtime
        timestamp = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
    except OSError:
        timestamp = ""

    # Freshness: a source newer than the cache means the summary is stale.
    stale = False
    cache_mtime_ns = 0
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


def _load_verify_statuses(cfg: ProjectConfig) -> dict[int, str]:
    """Load per-VA verify statuses from the verify cache.

    Returns a dict mapping VA -> verify status (e.g. "EXACT", "NEAR_MATCHING",
    "COMPILE_ERROR").  Used to override optimistic source statuses.
    """
    from rebrew.cli import load_verify_cache_raw

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

    statuses: dict[int, str] = {}
    for va_str, entry_data in entries.items():
        if not isinstance(entry_data, dict):
            continue
        result = entry_data.get("result", {})
        status = result.get("status", "")
        if not status:
            continue
        try:
            va = int(va_str, 16) if va_str.startswith("0x") else int(va_str)
        except (ValueError, TypeError):
            continue
        statuses[va] = status
    return statuses


def _compute_text_size(cfg: ProjectConfig) -> int:
    """Compute .text section size from binary headers. Returns 0 if unavailable."""
    if not cfg.target_binary.exists():
        return 0
    try:
        from rebrew.catalog.sections import get_text_section_size

        return get_text_section_size(cfg.target_binary)
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

    # Load function data (same path as rebrew todo)
    try:
        ghidra_funcs, existing, _covered_vas = load_data(cfg)
    except (OSError, json.JSONDecodeError, KeyError):
        # Graceful degradation: return zeroed report
        return report

    ghidra_vas = {f.va for f in ghidra_funcs}
    covered_vas_set = set(existing.keys())
    report.total_functions = len(ghidra_vas | covered_vas_set)
    report.covered_functions = len(existing)

    # Count source files
    src_dir = Path(cfg.reversed_dir)
    report.source_files = len(iter_sources(src_dir, cfg))

    # Load verify cache to override source statuses.
    # Metadata statuses may be optimistic (e.g. STATUS: RELOC) while
    # the actual verify result is STUB.  Verify results are authoritative.
    verify_statuses = _load_verify_statuses(cfg)

    # Single pass: status breakdown + byte-level coverage.
    # Exception: PROVEN (from rebrew prove) is a post-verify promotion that
    # takes precedence over verify cache RELOC/EXACT results.
    status_counts: dict[str, int] = {}
    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    matched_bytes = 0
    verify_overrides = 0
    verify_missing_size = 0
    unresolved_blockers = 0
    for va, info in existing.items():
        if info.get("blocker"):
            unresolved_blockers += 1
        ann_status = info.get("status", "STUB")
        # Metadata is authoritative for STUB (a stub's size mismatch is
        # expected); only more actionable cache states (COMPILE_ERROR,
        # matched) override.  Same rule as todo.py.
        if ann_status == "PROVEN":
            effective = ann_status
        elif ann_status == "STUB":
            cached = verify_statuses.get(va)
            effective = (
                cached
                if cached and cached not in ("SIZE_MISMATCH", "MISSING_SIZE", "STUB")
                else ann_status
            )
        else:
            effective = verify_statuses.get(va, ann_status)
        if effective != ann_status:
            verify_overrides += 1
        if effective == "MISSING_SIZE":
            verify_missing_size += 1
        status_counts[effective] = status_counts.get(effective, 0) + 1
        if effective in ("EXACT", "RELOC", "PROVEN"):
            # Fall back to annotation-metadata SIZE when the Ghidra
            # function_structure.json is missing/stale — otherwise every
            # matched byte counted 0 and coverage read 0%.
            size = size_by_va.get(va)
            if size is None:
                try:
                    size = int(info.get("size") or 0)
                except (TypeError, ValueError):
                    size = 0
            matched_bytes += size
        module = info.get("module") or "?"
        report.module_status.setdefault(module, {})
        report.module_status[module][effective] = report.module_status[module].get(effective, 0) + 1
    report.status_counts = status_counts
    report.matched_bytes = matched_bytes
    report.total_text_bytes = _compute_text_size(cfg)
    report.verify_overrides = verify_overrides
    report.verify_missing_size = verify_missing_size
    report.unresolved_blockers = unresolved_blockers

    # Verify info
    report.verify_info = _load_verify_info(cfg)

    # Quick W019 scan: detect .c files that still have inline metadata comments.
    # This is intentionally fast (grep-style, no full parse) — the expensive
    # full lint is ``rebrew lint``.
    report.inline_metadata_warning = _count_inline_metadata_files(src_dir, cfg)

    return report


def _count_inline_metadata_files(src_dir: Path, cfg: ProjectConfig) -> int:
    """Return the number of source files ``rebrew lint --fix`` can migrate.

    Mirrors lint's W019 rule (see ``_check_W019_inline_metadata`` in lint.py):
    a file counts when an inline metadata key (STATUS, CFLAGS, SIZE, BLOCKER,
    ...) is attached to a marker header block and that field is NOT already
    owned by the metadata store.  Markerless occurrences — e.g. the documented
    ``// CFLAGS: /DREBREW_ALLOW_NAKED`` naked-guard convention in an ``#else``
    branch — and keys already backed by metadata are deliberately not counted,
    so the "run rebrew lint to migrate" hint is always actionable.

    Only scans files returned by ``iter_sources`` so that the extension filter
    (``cfg.source_ext``) is respected.  Uses a single regex pass per file
    rather than a full annotation parse to keep the hot-path fast.
    """
    from rebrew.data_metadata import load_data_metadata
    from rebrew.metadata import load_metadata
    from rebrew.sources import iter_sources

    fn_entries = load_metadata(cfg.metadata_dir)
    data_entries = load_data_metadata(cfg.metadata_dir)
    count = 0
    for src in iter_sources(src_dir, cfg):
        try:
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if _has_migratable_inline_metadata(lines, fn_entries, data_entries):
            count += 1
    return count


def _has_migratable_inline_metadata(
    lines: list[str],
    fn_entries: dict[tuple[str, int], dict[str, Any]],
    data_entries: dict[tuple[str, int], dict[str, Any]],
) -> bool:
    """True when *lines* carry an inline metadata key that lint W019/--fix acts on.

    Header-block state machine mirroring lint._parse_multi_headers: a marker
    line opens a block; ``// KEY:`` comment lines attach to the open block
    until real C code appears (comment lines do not close it); keys seen
    outside a block — before the first marker or after code — buffer as
    "pending" for the next marker block.  Pending keys are dropped at EOF,
    matching the parser's orphan handling.
    """
    pending: list[str] = []
    in_block = False
    block: tuple[str, str, int] | None = None  # (marker_type, module, va_int)

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        is_comment = stripped.startswith("//") or stripped.startswith("/*")

        marker = _W019_MARKER_RE.match(stripped) if is_comment else None
        if marker:
            # Pending keys attach to THIS new block in lint's parser, so their
            # metadata-backing is judged against the new (module, va).
            new_block = (marker.group("type"), marker.group("module"), int(marker.group("va"), 16))
            for k in pending:
                if not _w019_key_backed(k, new_block, fn_entries, data_entries):
                    return True
            pending = []
            block = new_block
            in_block = True
            continue

        kv = _W019_INLINE_RE.search(stripped) if is_comment else None
        if kv:
            key = kv.group(1)
            if (
                in_block
                and block is not None
                and not _w019_key_backed(key, block, fn_entries, data_entries)
            ):
                return True
            if not in_block:
                pending.append(key)
            continue

        # Any other comment line (name hint, explanation, block comment) keeps
        # the header block open; only real code closes it.
        if not is_comment:
            in_block = False

    return False


def _w019_key_backed(
    key: str,
    block: tuple[str, str, int],
    fn_entries: dict[tuple[str, int], dict[str, Any]],
    data_entries: dict[tuple[str, int], dict[str, Any]],
) -> bool:
    """True when the metadata store already owns *key* for *block*'s function.

    Mirrors lint's metadata overlay: for DATA/GLOBAL blocks only
    size/section/note are sourced from rebrew-data.toml; everything else comes
    from rebrew-function.toml.
    """
    marker_type, module, va = block
    mod_va = (module, va)
    if marker_type in ("DATA", "GLOBAL"):
        if key.lower() in {"size", "section", "note"}:
            entry = data_entries.get(mod_va, {})
            return key.lower() in {k.lower() for k in entry}
        return False
    entry = fn_entries.get(mod_va, {})
    return key.lower() in {k.lower() for k in entry}


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
        f"  [dim]({exact + reloc + proven} EXACT+RELOC+PROVEN"
        f" / {report.total_functions} total)[/dim]"
    )

    # Byte coverage
    if report.total_text_bytes > 0:
        summary_lines.append(
            f"  [cyan]{report.byte_coverage_pct}%[/cyan] .text bytes covered"
            f"  [dim]({report.matched_bytes:,}B / {report.total_text_bytes:,}B)[/dim]"
        )

    # Source file count
    summary_lines.append(f"  [dim]{report.source_files} source files[/dim]")

    # Unresolved BLOCKERs (understood-blocked work needing attention)
    if report.unresolved_blockers:
        summary_lines.append(
            f"  [yellow]{report.unresolved_blockers} unresolved BLOCKER(s)[/yellow]"
            " — see rebrew todo / BLOCKER metadata"
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

    # W019 inline metadata warning
    if report.inline_metadata_warning:
        n = report.inline_metadata_warning
        summary_lines.append(
            f"  [yellow]Warning:[/yellow] {n} file(s) contain inline STATUS/CFLAGS/SIZE comments"
            " — run [bold]rebrew lint[/bold] to migrate to rebrew-function.toml"
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
) -> None:
    """Show reversing progress overview for the current project."""
    cfg = require_config(target=target, json_mode=json_output)
    report = collect_status(cfg)

    if json_output:
        json_print(report.to_dict())
        return

    _render_terminal(report)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
