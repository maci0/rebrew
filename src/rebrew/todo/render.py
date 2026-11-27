"""Terminal rendering helpers for ``rebrew todo``."""

from typing import Any
lazy from collections.abc import Callable

lazy from rich.panel import Panel

from rebrew.status_style import STATUS_COLORS
lazy from rebrew.present import ratio_bar
lazy from rebrew.utils import TerminalTable, floor_pct
lazy from rebrew.utils import console as default_console

from .models import (
    CAT_COMPILE_ERROR,
    CAT_DATA_DRIFT,
    CAT_DOCUMENTED,
    CAT_EXACT_ONLY,
    CAT_EXTRACT_ERROR,
    CAT_FIX_DELTA,
    CAT_IDENTIFY_LIBRARY,
    CAT_IMPROVE_MATCH,
    CAT_MISSING_ANNOTATION,
    CAT_NAKED,
    CAT_POSTLINK,
    CAT_RUN_PROVER,
    CAT_SETUP,
    CAT_START_DATA,
    CAT_START_FUNCTION,
    TodoItem,
)

CATEGORY_COLORS = {
    CAT_SETUP: "bold white",
    CAT_COMPILE_ERROR: "red",
    CAT_EXTRACT_ERROR: "red",
    CAT_FIX_DELTA: "green",
    CAT_IMPROVE_MATCH: "yellow",
    CAT_START_FUNCTION: "cyan",
    CAT_MISSING_ANNOTATION: "dim",
    CAT_IDENTIFY_LIBRARY: "blue",
    CAT_RUN_PROVER: "cyan",
    CAT_DOCUMENTED: "dim",
    CAT_NAKED: "magenta",
    CAT_DATA_DRIFT: "yellow",
    CAT_START_DATA: "cyan",
    CAT_EXACT_ONLY: "blue",
    CAT_POSTLINK: "magenta",
}

#: Title letters. These five stay visible at zero; every other status is
#: printed beside them when its count is nonzero, so the letters partition
#: the covered functions instead of hiding SIZE_MISMATCH and the rest.
LETTER_STATUSES = (
    ("EXACT", "E", STATUS_COLORS["EXACT"]),
    ("RELOC", "R", STATUS_COLORS["RELOC"]),
    ("PROVEN", "P", STATUS_COLORS["PROVEN"]),
    ("NEAR_MATCHING", "M", STATUS_COLORS["NEAR_MATCHING"]),
    ("STUB", "S", STATUS_COLORS["STUB"]),
)

_DEFAULT_CODE_ACCOUNT_CAPTION = "Matched functions, identified libraries, and alignment padding."


def _default_code_account_headline(pct: float, accounted: int, total: int) -> str:
    return f"Code account  {pct}% of virtual .text    {accounted:,}B / {total:,}B"


def coverage_status_markup(status_counts: dict[str, int]) -> str:
    """E/R/P/M/S plus every other nonzero status, one token per covered row."""
    parts = [
        f"[{color}]{status_counts.get(name, 0)}{letter}[/{color}]"
        for name, letter, color in LETTER_STATUSES
    ]
    known = {name for name, _letter, _color in LETTER_STATUSES}
    for name in sorted(status_counts):
        count = status_counts[name]
        if name not in known and count:
            color = STATUS_COLORS.get(name, "dim")
            parts.append(f"[{color}]{count} {name}[/{color}]")
    return " ".join(parts)


def render_matched_headline(
    matched: int,
    total: int,
    *,
    accounted_bytes: int = 0,
    text_bytes: int = 0,
    out_console: Any = None,
    code_account_caption: str = _DEFAULT_CODE_ACCOUNT_CAPTION,
    code_account_headline_fn: Callable[[float, int, int], str] | None = None,
) -> None:
    """Print the same progress line ``rebrew status`` prints.

    With a known virtual ``.text``, that is the code account (matched
    functions, identified libraries, and alignment padding) and the
    byte-matched function count under it. Without a measured section the
    function share is the percentage, and it is not called a byte match.
    """
    target_console = default_console if out_console is None else out_console
    if text_bytes > 0:
        headline_fn = code_account_headline_fn or _default_code_account_headline
        pct = floor_pct(accounted_bytes, text_bytes)
        target_console.print(f"  [bold]{headline_fn(pct, accounted_bytes, text_bytes)}[/bold]")
        target_console.print(f"  [dim]{code_account_caption}[/dim]")
        target_console.print(ratio_bar(accounted_bytes, text_bytes))
        if total > 0:
            target_console.print(f"  {matched}/{total} functions byte-matched")
        return
    pct = floor_pct(matched, total)
    target_console.print(f"  [bold]{matched}/{total} functions  ({pct}%)[/bold]")
    if total > 0:
        target_console.print(ratio_bar(matched, total))


def render_stats_header(
    status_counts: dict[str, int],
    *,
    covered: int,
    total_funcs: int,
    exact: int,
    reloc: int,
    proven: int,
    matching: int,
    stub: int,
    documented: int,
    denominator: int,
    out_console: Any = None,
) -> None:
    """Print the single-line coverage breakdown for ``--stats`` or empty lists."""
    target_console = default_console if out_console is None else out_console
    toolchain = (
        f"  [dim]· [green]{exact}[/green] identical straight from the toolchain[/dim]"
        if reloc
        else ""
    )
    extra = "".join(
        f"  [{STATUS_COLORS.get(name, 'dim')}]{name}: {status_counts[name]}"
        f"[/{STATUS_COLORS.get(name, 'dim')}]"
        for name in sorted(status_counts)
        if name not in {row[0] for row in LETTER_STATUSES} and status_counts[name]
    )
    target_console.print(
        f"  [bold]Coverage[/bold]: {covered} covered"
        f"  ({total_funcs} in Ghidra function list)"
        f"  [{STATUS_COLORS['EXACT']}]EXACT: {exact}[/{STATUS_COLORS['EXACT']}]"
        f"  [{STATUS_COLORS['RELOC']}]RELOC: {reloc}[/{STATUS_COLORS['RELOC']}]"
        f"  [{STATUS_COLORS['PROVEN']}]PROVEN: {proven}[/{STATUS_COLORS['PROVEN']}]"
        f"  [{STATUS_COLORS['NEAR_MATCHING']}]NEAR_MATCHING: {matching}[/{STATUS_COLORS['NEAR_MATCHING']}]"
        f"  [{STATUS_COLORS['STUB']}]STUB: {stub}[/{STATUS_COLORS['STUB']}]"
        f"  [dim]DOCUMENTED: {documented}[/dim]"
        f"{extra}"
        f"  → [bold]{exact + reloc}/{denominator}[/bold] functions byte-matched{toolchain}"
    )


def render_todo_panel(
    display_items: list[TodoItem],
    all_items: list[TodoItem],
    status_counts: dict[str, int],
    pct_label: str,
    offset: int,
    *,
    out_console: Any = None,
) -> None:
    """Render the prioritized action table inside a Rich panel and footer."""
    target_console = default_console if out_console is None else out_console
    # Match % is the figure that must not read as 100% for a near miss.  Fixed
    # widths that sum past a dumb terminal (80) are reduced evenly and that
    # column collapses to nothing, so only Name and Description flex.
    table = TerminalTable(
        show_header=True, header_style="bold", pad_edge=False, expand=True, padding=(0, 1)
    )
    table.add_column("#", style="dim", width=3, justify="right", no_wrap=True)
    table.add_column("Cat", width=10, no_wrap=True, overflow="ellipsis")
    table.add_column("VA", width=10, no_wrap=True, overflow="ellipsis")
    table.add_column("Impact", width=8, justify="right", no_wrap=True)
    table.add_column("Name", ratio=1, no_wrap=True, overflow="ellipsis")
    table.add_column("Match %", width=7, justify="right", no_wrap=True)
    table.add_column("Δ", width=5, justify="right", no_wrap=True)
    table.add_column("Description", ratio=2, no_wrap=True, overflow="ellipsis")

    for i, item in enumerate(display_items, 1):
        color = CATEGORY_COLORS.get(item.category, "white")
        cat_label = item.category.replace("-", "\u2011")  # non-breaking hyphen for display
        match_str = (
            f"{floor_pct(item.match_percent, 100):.1f}%" if item.match_percent is not None else "—"
        )
        delta_str = f"{item.byte_delta}B" if item.byte_delta is not None else "—"
        table.add_row(
            str(i),
            f"[{color}]{cat_label}[/{color}]",
            f"0x{item.va:08x}" if item.category != CAT_SETUP else "",
            f"{item.impact_bytes}B" if item.impact_bytes else "—",
            item.name,
            match_str,
            delta_str,
            item.description,
        )

    cat_parts: dict[str, int] = {}
    for item in all_items:
        cat_parts[item.category] = cat_parts.get(item.category, 0) + 1
    subtitle = "  ".join(
        f"[{CATEGORY_COLORS.get(cat, 'white')}]{cat}: {cnt}[/{CATEGORY_COLORS.get(cat, 'white')}]"
        for cat, cnt in sorted(cat_parts.items(), key=lambda x: -x[1])
    )

    panel = Panel(
        table,
        title=(
            f"[bold]Rebrew TODO[/bold] — {len(all_items)} actions"
            f"  {coverage_status_markup(status_counts)} ({pct_label})"
        ),
        subtitle=subtitle,
        border_style="blue",
    )
    target_console.print(panel)
    skipped = f", skipped {offset}" if offset else ""
    target_console.print(f"  Showing {len(display_items)} of {len(all_items)} items{skipped}")
    target_console.print(
        "  Ranked by affected bytes; setup first, linked-match audits last. "
        "Impact is scope, not a promised coverage gain."
    )
    target_console.print(
        "  Tip: use [bold]rebrew todo --category <category>[/bold] to filter  |  [bold]rebrew todo --stats[/bold] for stats"
    )


__all__ = [
    "CATEGORY_COLORS",
    "LETTER_STATUSES",
    "coverage_status_markup",
    "render_matched_headline",
    "render_stats_header",
    "render_todo_panel",
]
