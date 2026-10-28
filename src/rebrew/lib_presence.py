"""lib-presence — find one COFF object's functions in a reference binary.

An ``/INCLUDE`` list can be import-correct and still force archive members the
reference does not carry; guild-rebrew's d3dx8 list did exactly that for 13 of 15
members, adding ~190 KB of code the target never had. The existing tools answer
adjacent questions only: ``library match`` searches a library for bytes taken
from the binary, and signature scans have nothing to key on for an unreferenced
member. This command searches the binary for each symbol body of an object,
masking that object's relocation slots, and reports where the body sits.

A match is evidence that the reference contains those bytes, not that the linker
selected this member: identical bodies and masked wrappers can overlap.
"""

from __future__ import annotations

lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
)
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.gen_flirt_pat import parse_coff_obj

#: Minimum reloc-free anchor used to find a body inside the image.
ANCHOR_BYTES = 24
#: A body counts as present at this fraction of its non-relocation bytes.
PRESENT_RATIO = 0.85
#: Absolute floor for that fraction, so tiny bodies cannot pass on luck.
PRESENT_MIN_FIXED = 48

app = typer.Typer(
    help=(
        "Locate one COFF object's function bodies in the reference binary and "
        "report present/absent per symbol."
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew library presence --object member.obj\n\n"
        "  rebrew library presence --object member.obj --binary build/other.exe --json"
    ),
)


def _anchor(body: bytes, relocs: set[int]) -> tuple[int, bytes] | None:
    """First reloc-free 24-byte window of *body*, preferring unique bytes."""
    for start in range(0, max(0, len(body) - ANCHOR_BYTES), 4):
        if any(i in relocs for i in range(start, start + ANCHOR_BYTES)):
            continue
        window = body[start : start + ANCHOR_BYTES]
        if window.count(0) >= 10:
            continue
        return start, window
    return None


def locate_body(text: bytes, body: bytes, relocs: set[int]) -> dict[str, Any] | None:
    """Best masked match of *body* in *text*: located offset and fixed-byte ratio."""
    total = sum(1 for i in range(len(body)) if i not in relocs)
    if total < PRESENT_MIN_FIXED or len(body) < ANCHOR_BYTES:
        return None
    anchor = _anchor(body, relocs)
    if anchor is None:
        return None
    start, window = anchor
    best: dict[str, Any] | None = None
    pos = text.find(window)
    while pos >= 0:
        base = pos - start
        if base >= 0 and base + len(body) <= len(text):
            window_ref = text[base : base + len(body)]
            same = sum(1 for i in range(len(body)) if i not in relocs and window_ref[i] == body[i])
            ratio = same / total
            if best is None or same > best["fixed_matched"]:
                best = {
                    "offset": base,
                    "fixed_matched": same,
                    "fixed_total": total,
                    "ratio": round(ratio, 4),
                }
        pos = text.find(window, pos + 1)
    return best


def classify(best: dict[str, Any] | None, tested: bool) -> str:
    """Present, absent or unknown for one body.

    ``tested`` is false when the body has too few fixed bytes to search for;
    a searched body with no candidate at all counts as absent.
    """
    if not tested:
        return "unknown"
    if best is None:
        return "absent"
    if best["ratio"] >= PRESENT_RATIO and best["fixed_matched"] >= PRESENT_MIN_FIXED:
        return "present"
    if best["ratio"] < 0.5:
        return "absent"
    return "unknown"


def audit_object(text: bytes, text_va: int, object_path: Path) -> list[dict[str, Any]]:
    """Per-symbol presence rows for one object, sorted by verdict then VA."""
    rows: list[dict[str, Any]] = []
    try:
        symbols = parse_coff_obj(object_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot parse {object_path}: {exc}") from exc
    for symbol, body, relocs in symbols:
        if not body:
            continue
        fixed_total = sum(1 for i in range(len(body)) if i not in relocs)
        tested = fixed_total >= PRESENT_MIN_FIXED and len(body) >= ANCHOR_BYTES
        best = locate_body(text, body, relocs) if tested else None
        verdict = classify(best, tested)
        rows.append(
            {
                "symbol": symbol,
                "verdict": verdict,
                "va": f"0x{text_va + best['offset']:x}" if best else None,
                "ratio": best["ratio"] if best else None,
                "fixed_matched": best["fixed_matched"] if best else 0,
                "fixed_total": best["fixed_total"] if best else fixed_total,
            }
        )
    order = {"present": 0, "unknown": 1, "absent": 2}
    rows.sort(key=lambda r: (order[r["verdict"]], r["va"] or "0xffffffff"))
    return rows


@app.callback(invoke_without_command=True)
def main(
    object_path: Path = typer.Option(
        ..., "--object", exists=True, dir_okay=False, help="COFF object to look for"
    ),
    binary: Path | None = typer.Option(
        None, "--binary", help="Image to search (default: the target's reference binary)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Report where each of *object_path*'s function bodies appear in the image."""
    cfg = require_config(target=target, json_mode=json_output)
    image_path = binary or Path(cfg.target_binary)
    if not image_path.is_absolute():
        image_path = Path(cfg.root) / image_path
    if not image_path.exists():
        error_exit(f"{image_path} not found", json_mode=json_output)
    try:
        binary_info = load_binary(image_path)
    except (OSError, ValueError) as exc:
        error_exit(f"cannot read {image_path}: {exc}", json_mode=json_output)
    section = binary_info.sections.get(".text")
    if section is None:
        error_exit(f"{image_path} has no .text section", json_mode=json_output)
    text = binary_info.data[section.file_offset : section.file_offset + section.raw_size]
    try:
        rows = audit_object(text, section.va, object_path)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    counts = {
        verdict: sum(1 for r in rows if r["verdict"] == verdict)
        for verdict in ("present", "absent", "unknown")
    }
    if json_output:
        json_print({"object": str(object_path), "counts": counts, "symbols": rows})
        return
    console.print(
        f"{object_path.name}: {counts['present']} present, {counts['absent']} absent, "
        f"{counts['unknown']} unknown"
    )
    for row in rows:
        detail = row["symbol"]
        if row["va"]:
            detail += f"  {row['va']}  {row['fixed_matched']}/{row['fixed_total']}"
        console.print(f"  {row['verdict']:8} {detail}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
