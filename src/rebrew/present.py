"""Shared terminal layout for progress bars and numeric columns.

One bar width for every percentage of a measured whole. A ratio at or above
100% fills every cell and draws no empty cells. A ratio of 0 draws no filled
cells. A positive share that rounds to zero cells still fills one, so a
small ratio stays visible. Numeric columns stay a fixed width; text columns
are the ones that may grow.
"""

from __future__ import annotations

from rich.table import Table
from rich.text import Text

# Same width as the rebrew status .text bar.
BAR_WIDTH = 40


def filled_cells(part: float, whole: float, width: int = BAR_WIDTH) -> int:
    """Cells of *width* that *part* / *whole* fills, clamped to *width*."""
    if whole <= 0 or part <= 0:
        return 0
    cells = int(width * part / whole)
    if cells <= 0:
        return 1
    return min(width, cells)


def bar_plain(part: float, whole: float, width: int = BAR_WIDTH) -> str:
    """Block string for *part* / *whole*. Empty cells are the unfilled share."""
    filled = filled_cells(part, whole, width)
    return "█" * filled + "░" * (width - filled)


def ratio_bar(part: float, whole: float, width: int = BAR_WIDTH) -> Text:
    """Rich bar. Filled cells are green, the remainder dim."""
    filled = filled_cells(part, whole, width)
    bar = Text()
    bar.append("█" * filled, style="green")
    bar.append("░" * (width - filled), style="dim")
    return bar


def count_column(table: Table, header: str, *, width: int = 8) -> None:
    """Right-aligned numeric column that does not grow on a wide terminal."""
    table.add_column(header, justify="right", width=width, no_wrap=True, overflow="ellipsis")
