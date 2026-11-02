"""Report size and style signals for the rebrew source tree.

For each ``.py`` file under ``src/`` and ``tests/`` the command counts lines,
TODO markers, loop statements, and missing ``from __future__ import
annotations`` imports, then prints files above the requested line threshold.
These are prompts for a human, not refactoring rules.
"""

from __future__ import annotations

from pathlib import Path
lazy from typing import Any

import typer

lazy from rebrew.cli import console, json_print
lazy from rebrew.utils import TerminalTable

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew dev refactor  # Suggest refactoring opportunities\n\n"
    "  # Only large files, machine-readable\n"
    "  rebrew dev refactor --min-lines 400 --json\n\n"
    "  rebrew dev refactor --repository ../rebrew  # Point at a different tree\n"
)


app = typer.Typer(
    help="Analyze the rebrew source tree and suggest refactoring opportunities.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def _collect_python_files(root: Path) -> list[Path]:
    """Return all .py files under src/ and tests/, in a stable order.

    ``Path.glob`` yields directory order, which differs between checkouts,
    so the findings table and the JSON report came out in a different order
    for the same tree.
    """
    py_files: list[Path] = []
    for pattern in ("src/**/*.py", "tests/**/*.py"):
        py_files.extend(root.glob(pattern))
    return sorted(py_files)


def _analyse_file(path: Path, root: Path) -> dict[str, Any]:
    """Per-file line and loop counts for the suggestions."""
    relative = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"file": relative, "error": f"cannot read: {exc}"}

    lines = text.splitlines()
    num_lines = len(lines)
    too_long = num_lines > 500
    many_todos = sum(1 for line in lines if "TODO" in line.upper())
    missing_typing = "from __future__ import annotations" not in text and ": [" not in text
    for_loop_count = sum(1 for line in lines if line.strip().startswith("for "))
    while_loop_count = sum(1 for line in lines if line.strip().startswith("while "))

    return {
        "file": relative,
        "lines": num_lines,
        "too_long": too_long,
        "todos": many_todos,
        "missing_typing": missing_typing,
        "for_loops": for_loop_count,
        "while_loops": while_loop_count,
        "suggestions": _make_suggestions(
            too_long, many_todos, missing_typing, for_loop_count, while_loop_count
        ),
    }


def _make_suggestions(
    too_long: bool,
    todos: int,
    missing_typing: bool,
    for_loops: int,
    while_loops: int,
) -> list[str]:
    suggestions: list[str] = []
    if too_long:
        suggestions.append("Consider splitting this module into smaller, focused files.")
    if todos:
        suggestions.append(
            f"Address {todos} TODO comment(s) – they often indicate unfinished refactoring."
        )
    if missing_typing:
        suggestions.append("Add `from __future__ import annotations` and complete type hints.")
    if for_loops > 10:
        suggestions.append(
            "Many for-loops detected – review for vectorisation or parallel execution opportunities."
        )
    if while_loops > 5:
        suggestions.append(
            "Multiple while loops – ensure they have clear exit conditions; consider using functions with early returns."
        )
    if not suggestions:
        suggestions.append("No obvious refactoring triggers detected.")
    return suggestions


@app.callback(invoke_without_command=True)
def main(
    root: Path = typer.Option(
        Path("."),
        "--repository",
        exists=True,
        file_okay=False,
        help="Python repository root to scan",
    ),
    min_lines: int = typer.Option(
        200,
        "--min-lines",
        min=0,
        help="Minimum file length in lines (0 reports every file)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output results as JSON",
    ),
) -> None:
    """Scan the source tree and print refactoring recommendations."""
    root = root.resolve()

    files = _collect_python_files(root)
    results: list[dict[str, Any]] = []
    for f in files:
        info = _analyse_file(f, root)
        if "error" in info or info["lines"] >= min_lines:
            results.append(info)

    if json_output:
        json_print({"files": results})
        return

    table = TerminalTable(show_header=True, header_style="bold magenta")
    table.add_column("File", style="dim", width=40)
    table.add_column("Lines", justify="right")
    table.add_column("Suggestions")
    for r in results:
        table.add_row(
            r["file"],
            str(r.get("lines", "-")),
            "\n".join(r["suggestions"]) if "suggestions" in r else r["error"],
        )
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
