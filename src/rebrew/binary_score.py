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

#: Windows at least this wide compare with NumPy; smaller ones stay on the
#: plain loop, since importing NumPy costs more than it saves below ~1 MiB.
_VECTOR_COMPARE_MIN_BYTES = 1 << 20

#: One vectorized span. Keeps the two boolean temporaries bounded per worker
#: while a whole-image pass still amortizes the array setup.
_COMPARE_CHUNK_BYTES = 1 << 20


def _count_window(reference: bytes, built: bytes, start: int, end: int) -> tuple[int, int, int]:
    """Same-offset (matches, informative matches, informative bytes) over ``[start, end)``.

    The range is clipped to the shorter buffer, so a window past the end of
    either image counts only the bytes both sides actually hold.

    A zero reference byte counts as a match only when the build is also zero;
    informative bytes are the reference's nonzero ones, which carry content.
    """
    stop = min(end, len(reference), len(built))
    start = max(start, 0)
    if stop <= start:
        return 0, 0, 0
    if stop - start < _VECTOR_COMPARE_MIN_BYTES:
        same = 0
        informative_same = 0
        informative_compared = 0
        for i in range(start, stop):
            if reference[i]:
                informative_compared += 1
                if reference[i] == built[i]:
                    informative_same += 1
                    same += 1
            elif built[i] == 0:
                same += 1
        return same, informative_same, informative_compared

    import numpy as np  # deferred: only the score command pays this import

    same = 0
    informative_same = 0
    informative_compared = 0
    for base in range(start, stop, _COMPARE_CHUNK_BYTES):
        chunk_end = min(base + _COMPARE_CHUNK_BYTES, stop)
        width = chunk_end - base
        ref = np.frombuffer(reference, dtype=np.uint8, count=width, offset=base)
        bul = np.frombuffer(built, dtype=np.uint8, count=width, offset=base)
        # An equal pair is a match whether the reference byte is nonzero or
        # both sides are zero, so `same` is just the equal-byte count.
        equal = ref == bul
        informative = ref != 0
        same += int(np.count_nonzero(equal))
        informative_same += int(np.count_nonzero(equal & informative))
        informative_compared += int(np.count_nonzero(informative))
    return same, informative_same, informative_compared


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
        window = min(end, len(built), len(reference))
        same, informative_same, informative_compared = _count_window(
            reference, built, start, window
        )
        clipped = max(0, window - max(start, 0))
        sections[name] = {
            "same": same,
            "compared": clipped,
            "informative_same": informative_same,
            "informative_compared": informative_compared,
        }
        total += same
        compared += clipped
        info_total += informative_same
        info_compared += informative_compared
    file_compared = min(len(reference), len(built))
    file_same, file_info_same, file_info_compared = _count_window(
        reference, built, 0, file_compared
    )
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
