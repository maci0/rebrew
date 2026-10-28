"""bin-score — same-offset byte agreement between the reference and a build.

The reconstruction score is per-section same-position equality: aligned sections
in a PE keep the reference file offsets, so a byte that matches at the same file
offset is a byte whose placement and content are both right. `verify` reports
per-function and per-section verdicts; this reports the one number the layout work
optimizes, with the same breakdown.

The reference's own section windows define what is compared, so a shortened or
padded build never gains credit for bytes beyond the reference's sections.

Usage::

    rebrew binary score --built build/<target>
    rebrew binary score --built build/<target> --reference original.exe --json
"""

from __future__ import annotations

lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import (
    BUILT_IMAGE_HELP,
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
)
lazy from rebrew.formats.binary_loader import load_binary

app = typer.Typer(
    help="Report same-offset byte agreement between the reference and a built image.",
    rich_markup_mode="rich",
    no_args_is_help=True,
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binary score --built build/Europa1400Gold_TL.exe\n\n"
        "  rebrew binary score --built build/other.exe --json"
    ),
)

_COMPARED = (".text", ".rdata", ".data", ".data1", ".rsrc")


def score(reference: bytes, built: bytes, reference_sections: dict[str, Any]) -> dict[str, Any]:
    """Same-offset matches overall and per reference section window."""
    sections: dict[str, dict[str, int]] = {}
    total = 0
    compared = 0
    info_total = 0
    info_compared = 0
    for name in _COMPARED:
        section = reference_sections.get(name)
        if section is None:
            continue
        start = section.file_offset
        end = start + section.raw_size
        window = min(end, len(built))
        same = 0
        informative_same = 0
        informative_compared = 0
        for i in range(start, window):
            if reference[i]:
                informative_compared += 1
                if reference[i] == built[i]:
                    informative_same += 1
                    same += 1
            elif built[i] == 0:
                same += 1
        sections[name] = {
            "same": same,
            "compared": max(0, window - start),
            "informative_same": informative_same,
            "informative_compared": informative_compared,
        }
        total += same
        compared += max(0, window - start)
        info_total += informative_same
        info_compared += informative_compared
    file_compared = min(len(reference), len(built))
    file_same = 0
    file_info_same = 0
    file_info_compared = 0
    for i in range(file_compared):
        if reference[i]:
            file_info_compared += 1
            if reference[i] == built[i]:
                file_info_same += 1
                file_same += 1
        elif built[i] == 0:
            file_same += 1
    return {
        "same": total,
        "compared": compared,
        "ratio": round(total / compared, 6) if compared else 0.0,
        "sections": sections,
        "informative": {
            "same": info_total,
            "compared": info_compared,
            "ratio": round(info_total / info_compared, 6) if info_compared else 0.0,
        },
        "file": {
            "same": file_same,
            "compared": file_compared,
            "ratio": round(file_same / file_compared, 6) if file_compared else 0.0,
            "informative_same": file_info_same,
            "informative_compared": file_info_compared,
        },
    }


@app.callback(invoke_without_command=True)
def main(
    built: Path = typer.Option(..., "--built", exists=True, dir_okay=False, help=BUILT_IMAGE_HELP),
    reference: Path | None = typer.Option(
        None, "--reference", help="Reference image (default: the target's binary)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Score *built* against the reference at the same file offsets."""
    cfg = require_config(target=target, json_mode=json_output)
    reference_path = reference or Path(cfg.target_binary)
    if not reference_path.is_absolute():
        reference_path = Path(cfg.root) / reference_path
    for path in (reference_path, built):
        if not path.exists():
            error_exit(f"{path} not found", json_mode=json_output)
    try:
        ref_info = load_binary(reference_path)
        built_info = load_binary(built)
    except (OSError, ValueError) as exc:
        error_exit(f"cannot read image: {exc}", json_mode=json_output)
    result = score(ref_info.data, built_info.data, ref_info.sections)
    if json_output:
        json_print({"reference": str(reference_path), "built": str(built), **result})
        return
    console.print(
        f"same-offset bytes {result['same']:,} of {result['compared']:,} ({result['ratio']:.2%})"
    )
    for name, row in result["sections"].items():
        console.print(f"  {name:7} {row['same']:>9,} of {row['compared']:>9,}")
