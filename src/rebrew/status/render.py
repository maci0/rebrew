"""render.py – Rich terminal dashboard rendering for rebrew status."""

lazy import sys
lazy from pathlib import Path
lazy from typing import Any

lazy from rich.markup import escape
lazy from rich.panel import Panel
lazy from rich.text import Text

from rebrew.status_style import DISPLAY_STATUSES, STATUS_COLORS
lazy from rebrew.cli import console
lazy from rebrew.present import BAR_WIDTH, filled_cells, ratio_bar
lazy from rebrew.status.collect import (
    CODE_ACCOUNT_CAPTION,
    StatusReport,
    code_account_parts,
    ordered_data_sections,
)
lazy from rebrew.utils import TerminalTable, floor_pct

__all__ = [
    "STATUS_ORDER",
    "TICK_WIDTH",
    "breakdown_table",
    "data_block",
    "file_rows",
    "headline",
    "panel_title",
    "render_terminal",
    "ticks",
]

# Same display order as ``status_style.DISPLAY_STATUSES`` (byte-matched, PROVEN, then
# NEAR/STUB).
STATUS_ORDER = list(DISPLAY_STATUSES)

# Row ticks. Shorter than the headline bar so the table stays one line.
TICK_WIDTH = 16


def _status_console() -> Any:
    """Resolve ``rebrew.status.console`` when loaded so test monkeypatches take effect."""
    status_mod = sys.modules.get("rebrew.status")
    return getattr(status_mod, "console", console) if status_mod is not None else console


def ticks(part: float, whole: float) -> str:
    """Proportional tick marks for a table row. No empty trail."""
    return "█" * filled_cells(part, whole, TICK_WIDTH)


def breakdown_table(*, byte_counts: bool = False, percent: bool = True) -> TerminalTable:
    """Count table with optional function byte totals.

    ``percent`` adds a ratio column and tick marks. The code-account table
    leaves it off: that percentage already leads the block, and a per-status
    ratio reads as a second match score.
    """
    table = TerminalTable(
        show_header=True,
        header_style="bold",
        pad_edge=False,
        padding=(0, 2),
        box=None,
        expand=False,
    )
    table.add_column(width=16, no_wrap=True)
    table.add_column("Count", justify="right", width=12, no_wrap=True)
    if byte_counts:
        table.add_column(".text bytes", justify="right", width=12, no_wrap=True)
    if percent:
        table.add_column("Count %", justify="right", width=7, no_wrap=True)
        table.add_column("", width=TICK_WIDTH, no_wrap=True)
    return table


def data_block(report: StatusReport) -> list[Any]:
    """Data verdicts for this target, in the same columns as functions.

    The bar uses all initialized data bytes and the symbols' stored VERIFIED
    verdicts, rather than a comparison of the currently scored built image.
    """
    total = report.data_total
    if total == 0 and report.data_total_bytes == 0:
        return []
    block: list[Any] = []
    if total > 0 and report.data_verified == 0 and report.data_drift == 0:
        block.append(
            Text("Data verification: no verified bytes recorded for this target.", style="yellow")
        )
        block.append(
            Text(
                "Function matches do not verify data bytes. Run verify --data against a raw link.",
                style="dim",
            )
        )
    if report.data_total_bytes > 0:
        headline_text = Text()
        headline_text.append(
            f"{report.data_byte_pct}% of .data+.rdata verified (stored verdicts)",
            style="bold green",
        )
        headline_text.append(
            f"    {report.data_verified_bytes:,}B / {report.data_total_bytes:,}B",
            style="dim",
        )
        block.append(headline_text)
        block.append(ratio_bar(report.data_verified_bytes, report.data_total_bytes, BAR_WIDTH))
        if report.data_bytes:
            block.append(
                Text(
                    "    ".join(
                        f"{bucket} {report.data_bytes[bucket]:,}B"
                        for bucket in ("drift", "unchecked", "untracked")
                    ),
                    style="dim",
                )
            )
        block.append(Text(".data + .rdata; excludes BSS and copied imports", style="dim"))
        if report.data_conflicting_verified_bytes:
            block.append(
                Text(
                    f"{report.data_conflicting_verified_bytes:,}B in VERIFIED records overlap"
                    " DRIFT/UNCHECKED records"
                    " (counted as unverified)",
                    style="yellow",
                )
            )
    header = Text()
    header.append("Data", style="bold")
    header.append(f"  {report.data_verified}/{total} verified")
    if report.data_exact:
        header.append(f" ({report.data_exact} at the reference VA)", style="green")
    if report.data_drift:
        header.append(f", {report.data_drift} drift", style="red")
    if report.data_displaced:
        header.append(f" ({report.data_displaced} displaced)", style="red")

    # The byte headline is the data percentage. A symbol-count percent beside
    # it names a wider population (it includes BSS) and reads as a disagreement.
    show_symbol_pct = report.data_total_bytes <= 0
    table = breakdown_table(percent=show_symbol_pct)
    table.columns[0].header = "Data"
    rows = (
        ("EXACT", report.data_exact, "green"),
        ("VERIFIED", report.data_verified - report.data_exact, "green"),
        ("DISPLACED", report.data_displaced, "red"),
        ("DRIFT", report.data_drift - report.data_displaced, "red"),
        ("UNCHECKED", report.data_unchecked, "yellow"),
    )
    for label, count, color in rows:
        if count == 0:
            continue
        ratio = (
            (
                f"[{color}]{floor_pct(count, total)}%[/{color}]",
                f"[{color}]{ticks(count, total)}[/{color}]",
            )
            if show_symbol_pct
            else ()
        )
        table.add_row(
            f"[{color}]{label}[/{color}]",
            f"[{color}]{count}[/{color}]",
            *ratio,
        )
    sections = TerminalTable(box=None, pad_edge=False, padding=(0, 2))
    sections.add_column("Section", no_wrap=True)
    for label in ("Verified", "Drift", "Unchecked", "Total"):
        sections.add_column(label, justify="right", no_wrap=True)
    for name in ordered_data_sections(report.data_sections):
        counts = report.data_sections[name]
        section_total = counts["verified"] + counts["drift"] + counts["unchecked"]
        sections.add_row(
            name,
            str(counts["verified"]),
            str(counts["drift"]),
            str(counts["unchecked"]),
            str(section_total),
        )
    block.append(header)
    block.append(table)
    if sections.row_count:
        block.extend([Text(""), sections])
    return block


def panel_title(report: StatusReport) -> str:
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


def file_rows(report: StatusReport) -> list[Any]:
    """Linked-file agreement, the panel's top block. Empty when no image was scored.

    This is the raw same-offset compare. It is a different measure from the
    code account below: a high file score can sit next to a lower accounted
    share, and the other way around.
    """
    if report.file_missing_raw_link:
        return [
            Text.assemble(
                ("configured raw_link missing: ", "yellow"),
                (report.file_missing_raw_link, "yellow"),
            )
        ]
    if report.file_total_bytes <= 0:
        return []
    text = Text()
    text.append(f"Linked file  {report.file_similarity_pct}% same offset", style="bold")
    text.append(
        f"    {report.file_matched_bytes:,}B / {report.file_total_bytes:,}B",
        style="dim",
    )
    if report.file_built:
        text.append(f"    {report.file_built}", style="dim")
    rows: list[Any] = [
        text,
        ratio_bar(report.file_matched_bytes, report.file_total_bytes, BAR_WIDTH),
    ]
    gap = report.file_total_bytes - report.file_matched_bytes
    rows.append(Text(f"{gap:,}B differ or are missing", style="dim"))
    if report.file_sections:
        table = TerminalTable(box=None, pad_edge=False, padding=(0, 2))
        table.add_column("File region", no_wrap=True)
        for label in ("Same bytes", "Different / missing", "Total bytes"):
            table.add_column(label, justify="right", no_wrap=True)
        for name, counts in report.file_sections.items():
            same, total = counts["matched_bytes"], counts["total_bytes"]
            table.add_row(name, f"{same:,}", f"{total - same:,}", f"{total:,}")
        rows.append(table)
        text_on_disk = report.file_sections.get(".text", {}).get("total_bytes", 0)
        if text_on_disk and report.total_text_bytes and text_on_disk != report.total_text_bytes:
            rows.append(
                Text(
                    f".text on disk is {text_on_disk:,}B, including file alignment.",
                    style="dim",
                )
            )
            rows.append(
                Text(
                    f"Code accounting uses the virtual size, {report.total_text_bytes:,}B.",
                    style="dim",
                )
            )
        else:
            rows.append(Text("File regions are on-disk sizes, including alignment.", style="dim"))
        if gap:
            name, counts = max(
                report.file_sections.items(),
                key=lambda item: item[1]["total_bytes"] - item[1]["matched_bytes"],
            )
            region_gap = counts["total_bytes"] - counts["matched_bytes"]
            if region_gap:
                rows.append(Text(f"Largest gap: {name} {region_gap:,}B of {gap:,}B", style="dim"))
        rows.append(Text(""))
    return rows


def headline(report: StatusReport) -> tuple[Text, Text | None]:
    """The code-account percentage, and the bar that pictures it.

    Virtual ``.text`` share when that size is known, otherwise the function
    share. The bar uses the same ratio, so it cannot disagree with the number.
    The linked-file percentage is a separate block and is not repeated here.
    """
    if report.total_text_bytes > 0:
        text = Text()
        accounted = report.accounted_text_bytes
        label, amounts = code_account_parts(
            report.byte_coverage_pct, accounted, report.total_text_bytes
        )
        text.append(label, style="bold green")
        text.append(amounts, style="dim")
        return text, ratio_bar(accounted, report.total_text_bytes, BAR_WIDTH)
    text = Text(
        f"{report.matched_functions}/{report.total_functions} functions  ({report.matched_pct}%)",
        style="bold green",
    )
    bar = None
    if report.total_functions > 0:
        bar = ratio_bar(report.matched_functions, report.total_functions, BAR_WIDTH)
    return text, bar


def render_terminal(report: StatusReport) -> None:
    """Render the status report as a rich terminal dashboard."""
    proven = report.status_counts.get("PROVEN", 0)

    headline_text, bar = headline(report)

    # --- Status table ---
    show_bytes = bool(report.status_bytes)
    byte_percentages = show_bytes and report.total_text_bytes > 0
    denominator = report.total_text_bytes if byte_percentages else report.total_functions
    # Byte rows already sit under the code-account percentage. A second ratio
    # on each status made RELOC look like an unfinished score.
    status_table = breakdown_table(byte_counts=show_bytes, percent=not byte_percentages)
    status_table.columns[0].header = "Status"

    def ratio_cells(part: float, *, color: str) -> tuple[str, ...]:
        if byte_percentages:
            return ()
        return (
            f"[{color}]{floor_pct(part, denominator)}%[/{color}]",
            f"[{color}]{ticks(part, denominator)}[/{color}]",
        )

    for status in STATUS_ORDER:
        count = report.status_counts.get(status, 0)
        if count == 0:
            continue
        part = report.status_bytes.get(status, 0) if byte_percentages else count
        color = STATUS_COLORS.get(status, "white")
        status_table.add_row(
            f"[{color}]{status}[/{color}]",
            f"[{color}]{count}[/{color}]",
            *([f"{report.status_bytes.get(status, 0):,}"] if show_bytes else []),
            *ratio_cells(part, color=color),
        )

    # Other statuses not in the standard order
    other_statuses = sorted(set(report.status_counts) - set(STATUS_ORDER))
    for status in other_statuses:
        count = report.status_counts[status]
        if count == 0:
            continue
        part = report.status_bytes.get(status, 0) if byte_percentages else count
        color = STATUS_COLORS.get(status, "red")
        status_table.add_row(
            f"[{color}]{status}[/{color}]",
            f"[{color}]{count}[/{color}]",
            *([f"{report.status_bytes.get(status, 0):,}"] if show_bytes else []),
            *ratio_cells(part, color=color),
        )

    # Functions without a source file: the rows then add up to the total.
    no_source = report.total_functions - report.covered_functions
    if no_source > 0:
        part = report.status_bytes.get("NO_SOURCE", 0) if byte_percentages else no_source
        status_table.add_row(
            "[dim]NO_SOURCE[/dim]",
            f"[dim]{no_source}[/dim]",
            *([f"{report.status_bytes.get('NO_SOURCE', 0):,}"] if show_bytes else []),
            *ratio_cells(part, color="dim"),
        )

    if show_bytes:
        for label, count_text, size in (
            (
                "LIBRARY",
                f"{report.library_identified:,}",
                report.status_bytes.get("LIBRARY", 0) if report.library_identified else None,
            ),
            ("UNVERIFIED_TAIL", "", report.status_bytes.get("UNVERIFIED_TAIL")),
            ("PADDING", "", report.padding_bytes),
            ("NO_FUNCTION", "", report.unattributed_bytes),
        ):
            if size is not None:
                color = STATUS_COLORS.get(label, "dim")
                status_table.add_row(
                    f"[{color}]{label}[/{color}]",
                    count_text,
                    f"{size:,}",
                    *ratio_cells(size, color=color),
                )

    # --- Summary lines ---
    summary_lines: list[str] = []

    if proven:
        summary_lines.append(
            f"[{STATUS_COLORS['PROVEN']}]{proven} PROVEN[/{STATUS_COLORS['PROVEN']}]"
            "  [dim]semantically equivalent, bytes still"
            " differ (not byte-matched)[/dim]"
        )

    # Naked reconstructions: byte-exact via generated asm, NOT decompiled.
    # The honest split (ct-recomp's NAKED vs PURE_C_EXACT): decompiled_pct
    # excludes them so mass-generated skeletons can't inflate progress.
    if report.naked_matched:
        # A function count, same split as decompiled_pct. A bare percentage
        # here sat under the code-account percentage and read as a second one.
        decompiled = max(0, report.matched_functions - report.naked_matched)
        summary_lines.append(
            f"{decompiled}/{report.total_functions} functions decompiled"
            f"  [dim]({report.naked_matched} naked reconstructions, {report.naked_bytes:,}B"
            " byte-exact but not decompiled; implement the C bodies)[/dim]"
        )

    # Repeat the gap only when the status table is not already a byte ledger.
    if (
        not show_bytes
        and report.total_text_bytes > 0
        and report.padding_bytes is not None
        and report.unattributed_bytes is not None
    ):
        summary_lines.append(
            "[dim]"
            f"UNMATCHED {report.unmatched_bytes:,}B"
            f"    PADDING {report.padding_bytes:,}B"
            f"    NO_FUNCTION {report.unattributed_bytes:,}B"
            "[/dim]"
        )

    summary_lines.append(f"[dim]{report.source_files} source files scanned[/dim]")

    if report.load_error:
        # Replaces "No functions yet": the zero counts are unmeasured, not
        # measured as zero, and the operator needs the cause to act.
        # Escape the exception text: it carries project-file content (paths,
        # TOML keys) that would otherwise be parsed as Rich markup.
        summary_lines.append(
            f"[red]inventory load failed[/red]  [dim]{escape(report.load_error)}[/dim]"
        )
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
            f"Verify cache  [{verify_color}]{v.passed - v.library_passed}/"
            f"{v.total - v.library_total} byte-matched[/{verify_color}]"
            f", [red]{v.failed - (v.library_total - v.library_passed)} failed[/red]"
            + (
                f", {v.library_passed}/{v.library_total} compiled libraries"
                if v.library_total
                else ""
            )
            + f"  [dim]{v.timestamp}[/dim]{stale_suffix}"
        )
        # Effective-status overlay: verify results override metadata statuses.
        if report.verify_overrides:
            summary_lines.append(
                f"[dim]Effective status: {report.verify_overrides} function(s) overridden"
                " by verify cache (metadata says otherwise — see the rebrew repo's"
                " docs/ANNOTATIONS.md)[/dim]"
            )
        if report.verify_missing_size:
            summary_lines.append(
                f"[{STATUS_COLORS['MISSING_SIZE']}]{report.verify_missing_size} function(s) MISSING_SIZE"
                f"[/{STATUS_COLORS['MISSING_SIZE']}]"
                " — set SIZE via metadata (rebrew cfg set) then re-run verify"
            )
        if report.effective_matches:
            summary_lines.append(
                f"[{STATUS_COLORS['NEAR_MATCHING']}]{report.effective_matches} effective match(es)"
                f"[/{STATUS_COLORS['NEAR_MATCHING']}]"
                " — register-allocation-only delta, prove candidates"
            )

    # --- Assemble panel ---
    from rich.console import Group

    # The linked file leads. The code account under it is a different measure.
    panel_rows: list[Any] = file_rows(report)
    panel_rows.append(headline_text)
    if bar is not None:
        panel_rows.append(bar)
    if show_bytes:
        panel_rows.append(Text(CODE_ACCOUNT_CAPTION, style="dim"))
    if report.total_functions > 0:
        counts = Text()
        counts.append("Game functions", style="bold")
        counts.append(f"  {report.total_functions:,},  {report.matched_functions:,} byte-matched")
        if report.covered_functions != report.matched_functions:
            counts.append(f",  {report.covered_functions:,} with source")
        if no_source > 0:
            counts.append(f",  {no_source:,} no source")
        panel_rows.append(counts)
    if report.library_identified:
        library_line = (
            f"Libraries  {report.library_identified:,}, in the code account"
            if report.total_text_bytes > 0
            else f"Libraries  {report.library_identified:,}, omitted from the game total"
        )
        panel_rows.append(Text(library_line, style=STATUS_COLORS["LIBRARY"]))
    if status_table.row_count:
        if byte_percentages:
            panel_rows.append(Text("EXACT and RELOC are both byte matches.", style="dim"))
            panel_rows.append(Text("Each row is that many bytes of virtual .text.", style="dim"))
        panel_rows.extend([Text(""), status_table])
    rendered_data_block = data_block(report)
    if rendered_data_block:
        panel_rows.append(Text(""))
        panel_rows.extend(rendered_data_block)
    panel_content = Group(
        *panel_rows,
        Text(""),
        *[Text.from_markup(line) for line in summary_lines],
    )

    panel = Panel(
        panel_content,
        title=panel_title(report),
        border_style="blue",
        expand=False,
    )
    _status_console().print(panel)
