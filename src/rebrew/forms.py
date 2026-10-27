"""Inspect and verify Delphi 1 form streams in NE images or standalone form data."""

lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import EXIT_ERROR, TargetOption, console, error_exit, json_print, resolve_binary_arg
lazy from rebrew.formats.dfm import encode, render, scan_forms

app = typer.Typer(
    help="Decode Delphi 1 form streams and verify lossless re-encoding.",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binary forms --json\n\n"
        "  rebrew binary forms original/holiday.exe\n\n"
        "  rebrew binary forms recovered.DFM --json\n\n"
        "Unsupported candidate streams are reported explicitly; event names do not prove event bodies."
    ),
)


def form_report(binary: Path) -> dict[str, Any]:
    """Return decoded forms, event-name evidence and round-trip failures."""
    data = binary.read_bytes()
    forms, errors = scan_forms(data)
    return {
        "binary": str(binary),
        "forms": [
            {
                "offset": offset,
                "end": end,
                "class": root.cls,
                "name": root.name,
                "roundtrip": encode(root) == data[offset + 4 : end],
                "events": [
                    {"component": component.name, "event": event, "handler": handler}
                    for component in root.walk()
                    for event, handler in component.events()
                ],
                "text": render(root),
            }
            for offset, root, end in forms
        ],
        "unsupported_candidates": errors,
    }


@app.callback(invoke_without_command=True)
def main(
    binary: Path | None = typer.Argument(None, help="NE executable or standalone form stream"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Decode supported forms; fail when a candidate or round trip is incomplete."""
    path = resolve_binary_arg(binary, target=target, json_mode=json_output)
    try:
        report = form_report(path)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    failed = bool(report["unsupported_candidates"]) or any(
        not form["roundtrip"] for form in report["forms"]
    )
    if json_output:
        json_print(report)
    else:
        console.print(
            f"{len(report['forms'])} form(s), {len(report['unsupported_candidates'])} unsupported candidate(s)"
        )
        for form in report["forms"]:
            console.print(f"0x{form['offset']:x}: {form['class']} {form['name']}", markup=False)
            console.print(form["text"], markup=False)
        for item in report["unsupported_candidates"]:
            console.print(f"0x{item['offset']:x}: {item['error']}", markup=False)
    if failed:
        raise typer.Exit(EXIT_ERROR)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
