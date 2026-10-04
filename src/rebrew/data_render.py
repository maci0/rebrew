"""data_render.py — Rich output for the data scanner.

Renders the dispatch tables, the BSS layout report, the global scan, and the
coverage summary.  Presentation only: it reads the scanner's dataclasses and
prints them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from rebrew.present import bar_plain, count_column, ratio_bar
from rebrew.status_style import STATUS_COLORS
from rebrew.utils import floor_pct, merged_span_bytes, untrusted_literal, untrusted_text

if TYPE_CHECKING:
    from rebrew.data_scan import BssReport, DispatchTable, ScanResult


def render_dispatch(console: Console, tables: list[DispatchTable]) -> None:
    """Print a Rich table of detected dispatch tables."""
    if not tables:
        console.print("  [dim]No dispatch tables detected.[/]")
        return

    total_entries = sum(t.num_entries for t in tables)
    total_resolved = sum(t.resolved for t in tables)
    coverage_str = f"({floor_pct(total_resolved, total_entries, 0):.0f}%)" if total_entries else ""
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
            title=(
                f"0x{tbl.va:08x} ({untrusted_text(tbl.section)}) — {tbl.num_entries} entries, "
                f"{floor_pct(tbl.resolved, tbl.num_entries, 0):.0f}% resolved"
            ),
            show_lines=False,
        )
        t.add_column("#", style="dim", width=4)
        t.add_column("Target VA", width=12)
        t.add_column("Name", min_width=30)
        t.add_column("Status", width=10)

        for idx, entry in enumerate(tbl.entries):
            status_color = STATUS_COLORS.get(entry.status, "dim")

            name_str = untrusted_text(entry.name) if entry.name else "[dim]???[/]"
            status_str = (
                f"[{status_color}]{untrusted_text(entry.status)}[/{status_color}]"
                if entry.status
                else "[dim]—[/]"
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
                untrusted_text(entry.name),
                f"{entry.size_hint}B",
                untrusted_text(entry.source_file),
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
                f"{untrusted_text(gap.before)} → {untrusted_text(gap.after)}",
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
        if conflicts_only:
            # The globals exist; none of them conflict. "No globals found."
            # here would blame an empty scan for a clean result.
            console.print("[dim]No type conflicts found.[/]")
        else:
            console.print(
                "[dim]No globals found. Annotate sources with GLOBAL:/DATA: markers, "
                "or record the global in rebrew-data.toml, then re-run.[/]"
            )
        return

    tbl = Table(show_header=True, header_style="bold", border_style="dim")
    tbl.add_column("VA", style="cyan", no_wrap=True)
    tbl.add_column("Name")
    tbl.add_column("Type")
    tbl.add_column("Section", style="dim")
    tbl.add_column("Owner", style="dim")
    tbl.add_column("Users", style="dim")
    tbl.add_column("Declarations", style="dim")

    def paths(names: list[str]) -> str:
        shown = ", ".join(untrusted_text(name) for name in names[:3])
        if len(names) > 3:
            shown += f" (+{len(names) - 3})"
        return shown or "—"

    for entry in sorted(entries, key=lambda e: (e.va or 0xFFFFFFFF, e.name)):
        va_str = f"0x{entry.va:08x}" if entry.va else "—"
        type_literal = untrusted_literal(entry.type_str)
        type_cell = Syntax(type_literal, "c", theme="ansi_dark").highlight(type_literal)
        type_cell.rstrip()
        type_cell.no_wrap = False
        if entry.conflict:
            type_cell.append(" ⚠ CONFLICT", style="bold red")
        owners = (
            entry.defined_in
            + entry.generated_owners
            + [f"{owner['library']}:{owner['member']}" for owner in entry.library_owners]
        )
        style = "red" if entry.conflict or len(owners) > 1 else ""
        tbl.add_row(
            va_str,
            untrusted_text(entry.name),
            type_cell,
            untrusted_text(entry.section) if entry.section else "—",
            paths(owners)
            if owners
            else (
                "layout span"
                if entry.storage_kind == "span"
                else "compiler literal"
                if entry.storage_kind == "literal"
                else f"view of {entry.backing}"
                if entry.backing
                else "—"
            ),
            paths(entry.referenced_in),
            paths(entry.declared_in),
            style=style,
        )

    title = "[bold]Type Conflicts[/]" if conflicts_only else "[bold]Global Data Inventory[/]"
    console.print(Panel(tbl, title=title, border_style="blue"))
    console.print(
        "[dim]Owner is a source definition or library:object with link-map evidence. "
        "Views identify their backing allocation; layout spans have no separate owner. "
        "Import pointers are linker-owned. — means none established. "
        "Users are syntactic references; declarations alone "
        "are not users.[/]"
    )


def section_summary(scan: ScanResult, sections: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-section progress: globals, annotated bytes, and % byte coverage.

    Annotated bytes are estimated from each annotated global's declared type
    (via the shared data_layout type-size model) and reported as the union of
    those spans, so overlapping names and a size hint that runs past the
    section do not inflate the count.  ``declared_bytes`` is the raw sum of the
    type sizes.  A section with no annotatable contribution reports coverage
    0.0%.
    """
    from rebrew.data_layout import estimate_type_size

    per_section: dict[str, dict[str, Any]] = {}
    for entry in scan.globals.values():
        # A declaration with no address is not in a section. Counting it as
        # "unknown" invented a fourth section for link stand-ins whose bytes
        # already belong to a named global. A VA that misses every section
        # still lands in unknown.
        if not entry.va and not entry.section:
            continue
        sec_name = entry.section or "unknown"
        s = per_section.setdefault(
            sec_name,
            {"name": sec_name, "globals": 0, "annotated": 0, "declared_bytes": 0, "ranges": []},
        )
        s["globals"] += 1
        if entry.annotated:
            s["annotated"] += 1
            size_hint = estimate_type_size(entry.type_str) if entry.type_str else 4
            s["declared_bytes"] += size_hint
            if entry.va and size_hint > 0:
                s["ranges"].append((entry.va, entry.va + size_hint))

    out: list[dict[str, Any]] = []
    # The four canonical names lead, in a fixed order; any other section the
    # loader reported (an NE target's SEG0/SEG3, say) follows sorted, so a
    # global in it still reaches the table instead of only the `total`.
    known = [".data", ".rdata", ".bss", "unknown"]
    for sec_name in known + sorted(set(per_section) - set(known)):
        sec_data = per_section.get(sec_name)
        if sec_data is None:
            continue
        sec = sections.get(sec_name)
        size = int(sec.get("size", 0)) if sec else 0
        # Coverage measures the union of the annotated spans, clipped to the
        # section: a stale `extern char g[0x8000]` in a 16 KB .data and two
        # names for one address both used to push the ratio past 100%. The
        # byte count reported beside it is that same union, so the number, the
        # ratio and the bar are one figure rather than three; `declared_bytes`
        # keeps the raw sum of the declared type sizes.
        sec_va = int(sec.get("va", 0)) if sec else 0
        covered = merged_span_bytes(sec_data["ranges"], (sec_va, size) if size else None)
        out.append(
            {
                "name": sec_name,
                "globals": sec_data["globals"],
                "annotated": sec_data["annotated"],
                "annotated_bytes": covered,
                "declared_bytes": sec_data["declared_bytes"],
                "section_size": size,
                "coverage_pct": floor_pct(covered, size),
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
