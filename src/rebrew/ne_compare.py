"""Compare physical NE bytes independently of relocation and content inventories."""

from pathlib import Path
from typing import Any

import typer

from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    console,
    error_exit,
    json_print,
    resolve_binary_arg,
)
from rebrew.formats.ne_analysis import NeImage, byte_score, relocation_census, segment_budget
from rebrew.formats.ne_loader import NeParseError

app = typer.Typer(
    help="Compare NE file/segment bytes and report separate content overlap.",
    epilog="Examples:\n\n  rebrew binary ne-compare build/HOLIDAY.EXE --json\n\n  rebrew binary ne-compare rebuilt.EXE --original reference.EXE --window 32\n\nContent overlap is not source recovery; exit status follows complete file equality.",
)


def compare_images(original: Path, rebuilt: Path, window: int = 32) -> dict[str, Any]:
    """Inventory both layouts, exact agreement, fixups and overlapping content."""
    a, b = NeImage(original), NeImage(rebuilt)
    covered, total = byte_score(a, b, window)
    budget = {i: (length, count) for i, length, count in segment_budget(a, b, window)}
    rows = []
    for i in range(max(a.seg_count, b.seg_count)):
        left = a.segments[i] if i < a.seg_count else None
        right = b.segments[i] if i < b.seg_count else None
        rows.append(
            {
                "segment": i + 1,
                "original": left,
                "rebuilt": right,
                "exact": left is not None
                and right is not None
                and a.seg_bytes(i) == b.seg_bytes(i),
                "content_bytes": budget.get(i, (0, 0))[1],
            }
        )
    inventories = []
    for ne in (a, b):
        atypes, rtypes = relocation_census(ne)
        inventories.append(
            {
                "binary": str(ne.path),
                "module": ne.module,
                "alignment": ne.align,
                "address_types": dict(atypes),
                "relocation_types": dict(rtypes),
            }
        )
    return {
        "original": inventories[0],
        "rebuilt": inventories[1],
        "identical": a.data == b.data,
        "same_offset_bytes": sum(x == y for x, y in zip(a.data, b.data, strict=False)),
        "original_bytes": total,
        "rebuilt_bytes": len(b.data),
        "window": window,
        "content_bytes": covered,
        "segments": rows,
        "trailing_content": {"bytes": budget[-1][0], "content_bytes": budget[-1][1]},
    }


@app.callback(invoke_without_command=True)
def main(
    rebuilt: Path = typer.Argument(..., help="Rebuilt NE executable"),
    original: Path | None = typer.Option(
        None, "--original", help="Reference (default: configured target)"
    ),
    window: int = typer.Option(32, min=1, help="Minimum full content window"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compare without updating stored verdicts."""
    reference = resolve_binary_arg(original, target=target, json_mode=json_output)
    try:
        report = compare_images(reference, rebuilt, window)
    except (OSError, ValueError, NeParseError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(f"File identical: {report['identical']}")
        console.print(
            f"Same offset: {report['same_offset_bytes']:,}/{report['original_bytes']:,} bytes"
        )
        console.print(
            f"Content overlap: {report['content_bytes']:,}/{report['original_bytes']:,} bytes (window {window})"
        )
        for row in report["segments"]:
            console.print(
                f"Segment {row['segment']}: exact={row['exact']}, content={row['content_bytes']:,}B"
            )
    if not report["identical"]:
        raise typer.Exit(EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
