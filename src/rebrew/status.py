"""status.py – Project reversing status overview.

Scans annotation headers across all configured targets and prints a
Rich-formatted summary of reversing progress: STATUS, ORIGIN, and MARKER
breakdowns, byte coverage, and identified libraries.
"""

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rebrew.catalog import get_text_section_size, merge_ranges, scan_reversed_dir
from rebrew.cli import TargetOption, error_exit, json_print
from rebrew.config import ProjectConfig, load_config

# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

_DONE_STATUSES = {"EXACT", "RELOC", "MATCHING", "MATCHING_RELOC"}


@dataclass
class TargetStats:
    """Aggregated stats for a single target."""

    name: str
    file_count: int = 0
    total_bytes_reversed: int = 0
    text_section_size: int = 0

    status_counts: dict[str, int] = field(default_factory=dict)
    origin_counts: dict[str, int] = field(default_factory=dict)
    marker_counts: dict[str, int] = field(default_factory=dict)

    # Derived
    @property
    def done_count(self) -> int:
        """Number of functions with a done status (EXACT, RELOC, MATCHING, MATCHING_RELOC)."""
        return sum(self.status_counts.get(s, 0) for s in _DONE_STATUSES)

    @property
    def stub_count(self) -> int:
        """Number of functions still in STUB status."""
        return self.status_counts.get("STUB", 0)

    @property
    def coverage_pct(self) -> float:
        """Byte coverage as a percentage of the .text section."""
        if self.text_section_size == 0:
            return 0.0
        return self.total_bytes_reversed / self.text_section_size * 100.0

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dict for JSON output."""
        return {
            "target": self.name,
            "files": self.file_count,
            "done": self.done_count,
            "stubs": self.stub_count,
            "coverage_pct": round(self.coverage_pct, 2),
            "coverage_bytes": self.total_bytes_reversed,
            "text_size": self.text_section_size,
            "by_status": dict(self.status_counts),
            "by_origin": dict(self.origin_counts),
            "by_marker": dict(self.marker_counts),
        }


def collect_target_stats(
    target_name: str,
    reversed_dir: Path,
    bin_path: Path | None = None,
    cfg: ProjectConfig | None = None,
) -> TargetStats:
    """Scan a target's reversed directory and aggregate annotation stats."""
    stats = TargetStats(name=target_name)

    if not reversed_dir.exists():
        return stats

    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    stats.file_count = len(entries)

    status_ctr: Counter[str] = Counter()
    origin_ctr: Counter[str] = Counter()
    marker_ctr: Counter[str] = Counter()
    func_ranges: list[tuple[int, int]] = []
    for entry in entries:
        status_ctr[entry["status"]] += 1
        origin_ctr[entry["origin"]] += 1
        marker_ctr[entry["marker_type"]] += 1
        if entry["marker_type"] not in ("GLOBAL", "DATA") and entry["status"] != "STUB":
            start = entry["va"]
            end = start + max(entry["size"], 0)
            func_ranges.append((start, end))

    merged_ranges = merge_ranges(func_ranges)
    total_size = sum(end - start for start, end in merged_ranges)

    # Approximate implicit padding between functions (NOP/INT3 alignment).
    # Gaps of <=15 bytes between consecutive functions are likely linker padding.
    # Negative gaps (overlapping functions) are clamped to zero to avoid
    # inflating the byte count.
    padding_size = 0
    if merged_ranges:
        for i in range(len(merged_ranges) - 1):
            prev_end = merged_ranges[i][1]
            next_start = merged_ranges[i + 1][0]
            gap = next_start - prev_end
            if gap < 0:
                # Overlapping functions — skip, don't add negative padding
                continue
            if 0 < gap <= 15:
                padding_size += gap

    stats.status_counts = dict(status_ctr)
    stats.origin_counts = dict(origin_ctr)
    stats.marker_counts = dict(marker_ctr)
    stats.total_bytes_reversed = total_size + padding_size

    if bin_path and bin_path.exists():
        stats.text_section_size = get_text_section_size(bin_path)

    return stats


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

_STATUS_COLORS = {
    "EXACT": "green",
    "RELOC": "cyan",
    "MATCHING": "yellow",
    "MATCHING_RELOC": "yellow",
    "STUB": "red",
}

_STATUS_ORDER = ["EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB"]


def _render_target(console: Console, stats: TargetStats) -> None:
    """Print a Rich panel for a single target."""
    # Header line
    done = stats.done_count
    total = stats.file_count
    pct_str = f"{stats.coverage_pct:.1f}%" if stats.text_section_size else "N/A"

    title = Text(f"  {stats.name}  ", style="bold white on blue")

    # --- Status table ---
    tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tbl.add_column("Category", style="dim")
    tbl.add_column("Value")
    tbl.add_column("Count", justify="right")
    tbl.add_column("", justify="left")  # bar

    # STATUS rows (fixed order)
    for status in _STATUS_ORDER:
        count = stats.status_counts.get(status, 0)
        if count == 0:
            continue
        bar_len = int(count / max(total, 1) * 30)
        bar = "█" * bar_len
        color = _STATUS_COLORS.get(status, "white")
        tbl.add_row("STATUS", f"[{color}]{status}[/]", str(count), f"[{color}]{bar}[/]")

    # ORIGIN rows
    for origin in sorted(stats.origin_counts):
        count = stats.origin_counts[origin]
        tbl.add_row("ORIGIN", origin, str(count), "")

    # MARKER rows
    for marker in sorted(stats.marker_counts):
        count = stats.marker_counts[marker]
        tbl.add_row("MARKER", marker, str(count), "")

    # Summary line
    subtitle_parts = [
        f"[bold]{done}[/]/{total} functions done",
        f"[bold]{stats.total_bytes_reversed:,}[/]/{stats.text_section_size:,} bytes"
        if stats.text_section_size
        else f"[bold]{stats.total_bytes_reversed:,}[/] bytes",
        f"[bold]{pct_str}[/] coverage",
    ]
    subtitle = "  ·  ".join(subtitle_parts)

    console.print(Panel(tbl, title=title, subtitle=subtitle, border_style="blue"))


def _render_project_summary(console: Console, all_stats: list[TargetStats]) -> None:
    """Print aggregate summary across all targets."""
    total_files = sum(s.file_count for s in all_stats)
    total_done = sum(s.done_count for s in all_stats)
    total_stubs = sum(s.stub_count for s in all_stats)
    total_bytes = sum(s.total_bytes_reversed for s in all_stats)
    total_text = sum(s.text_section_size for s in all_stats)
    pct = (total_bytes / total_text * 100.0) if total_text else 0.0

    tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tbl.add_column("Target")
    tbl.add_column("Files", justify="right")
    tbl.add_column("Done", justify="right")
    tbl.add_column("Stubs", justify="right")
    tbl.add_column("Coverage", justify="right")

    for s in all_stats:
        cov = f"{s.coverage_pct:.1f}%" if s.text_section_size else "—"
        tbl.add_row(s.name, str(s.file_count), str(s.done_count), str(s.stub_count), cov)

    if len(all_stats) > 1:
        tbl.add_row(
            "[bold]TOTAL[/]",
            f"[bold]{total_files}[/]",
            f"[bold]{total_done}[/]",
            f"[bold]{total_stubs}[/]",
            f"[bold]{pct:.1f}%[/]" if total_text else "—",
        )

    console.print(Panel(tbl, title="[bold]Project Overview[/]", border_style="green"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Project reversing status overview.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew status                          Rich dashboard with progress bars

rebrew status --json                   Machine-readable JSON output

rebrew status -t server.dll            Status for a specific target

[bold]What it shows:[/bold]

Total functions, bytes matched, status breakdown (EXACT / RELOC / MATCHING /
STUB), per-origin coverage, and byte coverage percentage.

[dim]Scans reversed_dir for annotation headers.
Run 'rebrew catalog --json' first to generate coverage data.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    target: str | None = TargetOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Print an overview of reversing progress for the project."""
    try:
        cfg = load_config(target=target)
    except (FileNotFoundError, KeyError) as exc:
        error_exit(str(exc))

    # Determine which targets to report on
    targets_to_show = [target] if target is not None else list(cfg.all_targets)

    all_stats: list[TargetStats] = []
    for tgt_name in targets_to_show:
        tgt_cfg = load_config(root=cfg.root, target=tgt_name)
        stats = collect_target_stats(
            target_name=tgt_name,
            reversed_dir=tgt_cfg.reversed_dir,
            bin_path=tgt_cfg.target_binary,
            cfg=tgt_cfg,
        )
        all_stats.append(stats)

    # --- JSON output ---
    if json_output:
        data = {
            "project": cfg.project_name,
            "targets": [s.to_dict() for s in all_stats],
        }
        json_print(data)
        return

    # --- Rich output ---
    console = Console(stderr=True)
    console.print()

    for stats in all_stats:
        _render_target(console, stats)
        console.print()

    if len(all_stats) > 1:
        _render_project_summary(console, all_stats)
        console.print()


def main_entry() -> None:
    """Run the status CLI app."""
    app()


if __name__ == "__main__":
    main_entry()
