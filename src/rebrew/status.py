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
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rebrew.cli import TargetOption, json_print, require_config
from rebrew.config import ProjectConfig

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_STATUS_ORDER = ["EXACT", "RELOC", "NEAR_MATCH", "STUB", "PROVEN"]
_STATUS_COLORS: dict[str, str] = {
    "EXACT": "green",
    "RELOC": "cyan",
    "NEAR_MATCH": "yellow",
    "STUB": "dim",
    "PROVEN": "green",
    "COMPILE_ERROR": "red",
    "MISSING_FILE": "red",
}


@dataclass
class VerifyInfo:
    """Summary of the last verify run."""

    timestamp: str = ""
    passed: int = 0
    failed: int = 0
    total: int = 0


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

    # Verify cache summary
    verify_info: VerifyInfo | None = None

    # Derived percentages
    @property
    def coverage_pct(self) -> float:
        if self.total_functions == 0:
            return 0.0
        return round(100.0 * self.covered_functions / self.total_functions, 1)

    @property
    def matched_pct(self) -> float:
        """Percentage of total functions that are EXACT or RELOC (byte-matched)."""
        if self.total_functions == 0:
            return 0.0
        exact = self.status_counts.get("EXACT", 0)
        reloc = self.status_counts.get("RELOC", 0)
        proven = self.status_counts.get("PROVEN", 0)
        return round(100.0 * (exact + reloc + proven) / self.total_functions, 1)

    @property
    def byte_coverage_pct(self) -> float:
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
            "coverage_pct": self.coverage_pct,
            "matched_pct": self.matched_pct,
            "source_files": self.source_files,
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
            }
        return d


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


def _load_verify_info(cfg: ProjectConfig) -> VerifyInfo | None:
    """Load last verify summary from the verify cache file."""
    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    if not cache_path.exists():
        return None
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    entries = raw.get("entries", {})
    if not entries:
        return None

    passed = 0
    failed = 0
    for entry_data in entries.values():
        if not isinstance(entry_data, dict):
            continue
        result = entry_data.get("result", {})
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

    return VerifyInfo(
        timestamp=timestamp,
        passed=passed,
        failed=failed,
        total=passed + failed,
    )


def _load_verify_statuses(cfg: ProjectConfig) -> dict[int, str]:
    """Load per-VA verify statuses from the verify cache.

    Returns a dict mapping VA -> verify status (e.g. "EXACT", "NEAR_MATCH",
    "COMPILE_ERROR").  Used to override optimistic annotation statuses.
    """
    cache_path = cfg.root / ".rebrew" / "verify_cache.json"
    if not cache_path.exists():
        return {}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}

    statuses: dict[int, str] = {}
    for va_str, entry_data in raw.get("entries", {}).items():
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
    """Compute .text section size from binary headers if available."""
    if not cfg.target_binary.exists():
        return 0
    try:
        from rebrew.catalog.sections import text_section_size

        return text_section_size(cfg.target_binary)
    except (ImportError, OSError, ValueError):
        return 0


def collect_status(cfg: ProjectConfig) -> StatusReport:
    """Collect all project health data into a StatusReport.

    This is the single testable entry point for status data collection.
    It reads annotations and function structure but performs no compilation.

    When a verify cache exists, verify results override annotation statuses
    so that functions which fail verification (NEAR_MATCH, COMPILE_ERROR) are
    not counted as byte-matched.
    """
    from rebrew.cli import iter_sources
    from rebrew.naming import load_data

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

    report.total_functions = len(ghidra_funcs)
    report.covered_functions = len(existing)

    # Count source files
    src_dir = Path(cfg.reversed_dir)
    report.source_files = len(iter_sources(src_dir, cfg))

    # Load verify cache to override annotation statuses.
    # Annotations in .c files may be optimistic (e.g. STATUS: RELOC) while
    # the actual verify result is STUB.  Verify results are authoritative.
    verify_statuses = _load_verify_statuses(cfg)

    # Status breakdown — use verify result when available, annotation as fallback.
    # Exception: PROVEN (from rebrew prove) is a post-verify promotion that
    # takes precedence over verify cache RELOC/EXACT results.
    status_counts: dict[str, int] = {}
    for va, info in existing.items():
        ann_status = info.get("status", "STUB")
        s = "PROVEN" if ann_status == "PROVEN" else verify_statuses.get(va, ann_status)
        status_counts[s] = status_counts.get(s, 0) + 1
    report.status_counts = status_counts

    # Byte-level coverage: sum sizes of matched functions (EXACT + RELOC + PROVEN)
    # Uses the effective status (verify-overridden, but PROVEN wins)
    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    matched_bytes = 0
    for va, info in existing.items():
        ann_status = info.get("status")
        effective = "PROVEN" if ann_status == "PROVEN" else verify_statuses.get(va, ann_status)
        if effective in ("EXACT", "RELOC", "PROVEN"):
            matched_bytes += size_by_va.get(va, 0)
    report.matched_bytes = matched_bytes
    report.total_text_bytes = _compute_text_size(cfg)

    # Verify info
    report.verify_info = _load_verify_info(cfg)

    return report


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

_STATUS_LABELS: dict[str, str] = {
    "EXACT": "✅ EXACT",
    "RELOC": "🔗 RELOC",
    "PROVEN": "🔒 PROVEN",
    "NEAR_MATCH": "🔶 NEAR_MATCH",
    "STUB": "📝 STUB",
}


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
    near_match = report.status_counts.get("NEAR_MATCH", 0)
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
        color = _STATUS_COLORS.get(status, "white")
        label = _STATUS_LABELS.get(status, status)
        mini_bar_len = int(20 * count / max(report.total_functions, 1))
        mini_bar = "█" * max(mini_bar_len, 1)
        status_table.add_row(
            f"[{color}]{label}[/{color}]",
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
        color = _STATUS_COLORS.get(status, "red")
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

    # Verify info
    if report.verify_info is not None:
        v = report.verify_info
        verify_color = "green" if v.failed == 0 else "yellow"
        summary_lines.append(
            f"  Last verify: [{verify_color}]{v.passed} passed[/{verify_color}]"
            f"  [red]{v.failed} failed[/red]"
            f"  [dim]({v.timestamp})[/dim]"
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
            f" [magenta]{proven}P[/magenta] [yellow]{near_match}M[/yellow]"
            f" [dim]{stub}S[/dim] → [bold]{report.matched_pct}%[/bold]"
        ),
        border_style="blue",
    )
    console.print(panel)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = """\
[bold]Examples:[/bold]

rebrew status                    Quick project overview

rebrew status --json             Machine-readable JSON output

rebrew status -t client_exe      Status for a specific target

[dim]Reads annotations and function structure, no compilation needed.
Run 'rebrew verify' first for verify stats, or 'rebrew catalog' for function data.[/dim]"""

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
