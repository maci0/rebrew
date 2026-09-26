"""data_render.py — Rich output for the data scanner.

Renders the dispatch tables, the BSS layout report, the global scan, and the
coverage summary.  Presentation only: it reads the scanner's dataclasses and
prints them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rebrew.present import bar_plain, count_column, ratio_bar

if TYPE_CHECKING:
    from rebrew.data_scan import BssReport, DispatchTable, ScanResult


def render_dispatch(console: Console, tables: list[DispatchTable]) -> None:
    """Print a Rich table of detected dispatch tables."""
    if not tables:
        console.print("  [dim]No dispatch tables detected.[/]")
        return

    total_entries = sum(t.num_entries for t in tables)
    total_resolved = sum(t.resolved for t in tables)
    coverage_str = f"({total_resolved / total_entries:.0%})" if total_entries else ""
    summary_body = (
        f"[bold]{len(tables)}[/] dispatch tables, "
        f"[bold]{total_entries}[/] total entries, "
        f"[bold]{total_resolved}[/] resolved {coverage_str}"
    )
    if total_entries:
        summary_body += "\n" + bar_plain(total_resolved, total_entries)
    console.print(Panel(summary_body, title="Dispatch Tables"))

    for tbl in tables:
        t = Table(
            title=f"0x{tbl.va:08x} ({tbl.section}) — {tbl.num_entries} entries, {tbl.coverage:.0%} resolved",
            show_lines=False,
        )
        t.add_column("#", style="dim", width=4)
        t.add_column("Target VA", width=12)
        t.add_column("Name", min_width=30)
        t.add_column("Status", width=10)

        for idx, entry in enumerate(tbl.entries):
            status_color = {
                "EXACT": "green",
                "RELOC": "blue",
                "NEAR_MATCHING": "yellow",
                "STUB": "red",
            }.get(entry.status, "dim")

            name_str = entry.name or "[dim]???[/]"
            status_str = (
                f"[{status_color}]{entry.status}[/{status_color}]" if entry.status else "[dim]—[/]"
            )

            t.add_row(
                str(idx),
                f"0x{entry.target_va:08x}",
                name_str,
                status_str,
            )
        console.print(t)
        console.print()


def render_bss(console: Console, report: BssReport) -> None:
    """Print BSS layout verification report."""
    if not report.bss_size:
        console.print("  [dim]No .bss section found in binary.[/]")
        return

    console.print(
        Panel(
            f"BSS at [bold]0x{report.bss_va:08x}[/], size [bold]{report.bss_size:,}[/] bytes\n"
            f"Known globals: [bold]{len(report.known_entries)}[/], "
            f"coverage: [bold]{report.coverage_pct:.1f}%[/] of .bss "
            f"({report.coverage_bytes:,}B of {report.bss_size:,}B)\n"
            f"{bar_plain(report.coverage_bytes, report.bss_size)}\n"
            f"Gaps detected: [bold]{('[red]' + str(len(report.gaps)) + '[/red]') if report.gaps else '[green]0[/green]'}[/]",
            title="[bold]BSS Layout Verification[/]",
            border_style="blue",
        )
    )

    if report.known_entries:
        tbl = Table(show_header=True, header_style="bold", border_style="dim")
        tbl.add_column("VA", style="cyan", no_wrap=True)
        tbl.add_column("Name")
        tbl.add_column("Size", justify="right")
        tbl.add_column("Source", style="dim")

        for entry in report.known_entries:
            tbl.add_row(
                f"0x{entry.va:08x}",
                entry.name,
                f"{entry.size_hint}B",
                entry.source_file,
            )
        console.print(tbl)
        console.print()

    if report.gaps:
        gap_tbl = Table(
            title="[bold red]BSS Gaps (potential missing globals)[/]",
            show_header=True,
            header_style="bold",
            border_style="red",
        )
        gap_tbl.add_column("Offset", style="cyan", no_wrap=True)
        gap_tbl.add_column("Size", justify="right")
        gap_tbl.add_column("Between")

        for gap in report.gaps:
            gap_tbl.add_row(
                f"0x{gap.offset:08x}",
                f"{gap.size}B",
                f"{gap.before} → {gap.after}",
            )
        console.print(gap_tbl)
    else:
        console.print("  [green]✓ No gaps detected in BSS layout[/]")


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------


def render_globals(console: Console, scan: ScanResult, conflicts_only: bool = False) -> None:
    """Print a Rich table of globals."""
    entries = list(scan.globals.values())
    if conflicts_only:
        conflict_names = {c["name"] for c in scan.type_conflicts}
        entries = [e for e in entries if e.name in conflict_names]

    if not entries:
        console.print("[dim]No globals found.[/]")
        return

    tbl = Table(show_header=True, header_style="bold", border_style="dim")
    tbl.add_column("VA", style="cyan", no_wrap=True)
    tbl.add_column("Name")
    tbl.add_column("Type")
    tbl.add_column("Section", style="dim")
    tbl.add_column("Files", style="dim")

    for entry in sorted(entries, key=lambda e: (e.va or 0xFFFFFFFF, e.name)):
        va_str = f"0x{entry.va:08x}" if entry.va else "—"
        files_str = ", ".join(entry.declared_in[:3])
        if len(entry.declared_in) > 3:
            files_str += f" (+{len(entry.declared_in) - 3})"
        type_cell = f"{entry.type_str} ⚠ CONFLICT" if entry.conflict else entry.type_str
        style = "red" if entry.conflict else ""
        tbl.add_row(va_str, entry.name, type_cell, entry.section or "—", files_str, style=style)

    title = "[bold]Type Conflicts[/]" if conflicts_only else "[bold]Global Data Inventory[/]"
    console.print(Panel(tbl, title=title, border_style="blue"))


def section_summary(scan: ScanResult, sections: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-section progress: globals, annotated bytes, and % byte coverage.

    Annotated bytes are estimated from each annotated global's declared type
    (via the shared data_layout type-size model).  A section with no
    annotatable contribution reports coverage 0.0%.
    """
    from rebrew.data_layout import estimate_type_size

    per_section: dict[str, dict[str, Any]] = {}
    for entry in scan.globals.values():
        sec_name = entry.section or "unknown"
        s = per_section.setdefault(
            sec_name, {"name": sec_name, "globals": 0, "annotated": 0, "annotated_bytes": 0}
        )
        s["globals"] += 1
        if entry.annotated:
            s["annotated"] += 1
            s["annotated_bytes"] += estimate_type_size(entry.type_str) if entry.type_str else 4

    out: list[dict[str, Any]] = []
    for sec_name in [".data", ".rdata", ".bss", "unknown"]:
        sec_data = per_section.get(sec_name)
        if sec_data is None:
            continue
        sec = sections.get(sec_name)
        size = int(sec.get("size", 0)) if sec else 0
        coverage = (sec_data["annotated_bytes"] / size * 100.0) if size else 0.0
        out.append(
            {
                "name": sec_name,
                "globals": sec_data["globals"],
                "annotated": sec_data["annotated"],
                "annotated_bytes": sec_data["annotated_bytes"],
                "section_size": size,
                "coverage_pct": round(coverage, 1),
            }
        )
    return out


def render_summary(console: Console, scan: ScanResult, sections: dict[str, dict[str, Any]]) -> None:
    """Print section-level summary."""
    rows = section_summary(scan, sections)

    tbl = Table(
        show_header=True,
        header_style="bold",
        box=None,
        padding=(0, 1),
        pad_edge=False,
        expand=False,
    )
    tbl.add_column("Section", no_wrap=True)
    count_column(tbl, "Globals", width=8)
    count_column(tbl, "Annotated", width=10)
    count_column(tbl, "Bytes", width=28)
    count_column(tbl, "% Coverage", width=11)

    bars: list[Text] = []
    for row in rows:
        sec_name = row["name"]
        size = int(row["section_size"] or 0)
        size_str = f"{size:,}B" if size else "—"
        coverage_str = f"{row['coverage_pct']}%" if size else "—"
        tbl.add_row(
            sec_name,
            str(row["globals"]),
            str(row["annotated"]),
            f"{row['annotated_bytes']:,}B / {size_str}",
            coverage_str,
        )
        if size:
            # Each section is its own whole, so the bar is that section's ratio.
            label = Text()
            label.append(f"{sec_name}  {coverage_str} of section", style="dim")
            bars.append(label)
            bars.append(ratio_bar(row["annotated_bytes"], size))

    annotated = sum(1 for g in scan.globals.values() if g.annotated)
    total = len(scan.globals)
    conflicts = len(scan.type_conflicts)

    subtitle = f"{total} globals ({annotated} annotated, {total - annotated} extern-only)"
    if conflicts:
        subtitle += f" — [red]{conflicts} type conflicts[/]"

    console.print(
        Panel(
            Group(tbl, *bars),
            title="[bold]Data Section Summary[/]",
            subtitle=subtitle,
            border_style="green",
        )
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
