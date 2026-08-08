"""``rebrew resource`` — PE resource (``.rsrc``) comparison for byte-identical work.

``rebrew verify``/``diff`` only look at function bytes; a resource byte diff is
invisible to them.  These commands compare/extract the ``.rsrc`` section so a
recompiled PE's resources can be checked against the original (e.g. the
``.rsrc`` 0x5400 vs 0x1000 gap in np-rebrew).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.binary_loader import load_binary
from rebrew.cli import EXIT_MISMATCH, json_print

console = Console(stderr=True)

app = typer.Typer(
    help="Compare / extract PE resource (.rsrc) sections.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew resource compare np_recompiled.exe original/notepad.exe\n"
        "  rebrew resource compare -j np_recompiled.exe original/notepad.exe\n"
        "  rebrew resource extract np_recompiled.exe -o out/notepad.rsrc\n"
    ),
)


def _rsrc_bytes(path: Path) -> tuple[bytes | None, dict[str, Any]]:
    """Return (.rsrc raw bytes, section info) for *path*, or (None, {})."""
    info = load_binary(path)
    sec = info.sections.get(".rsrc")
    if sec is None:
        return None, {}
    raw = info.data[sec.file_offset : sec.file_offset + sec.raw_size]
    return raw, {
        "va": sec.va,
        "size": sec.size,
        "raw_size": sec.raw_size,
        "file_offset": sec.file_offset,
    }


@app.command("compare")
def compare(
    recompiled: Path = typer.Argument(..., help="Recompiled PE (e.g. np_recompiled.exe)"),
    original: Path = typer.Argument(..., help="Original PE (e.g. original/notepad.exe)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Byte-compare the .rsrc sections of two PEs; exit 1 when they differ."""
    a_bytes, a_info = _rsrc_bytes(recompiled)
    b_bytes, b_info = _rsrc_bytes(original)

    report: dict[str, Any] = {
        "recompiled": str(recompiled),
        "original": str(original),
        "match": False,
        "recompiled_rsrc": {"present": a_bytes is not None, **a_info},
        "original_rsrc": {"present": b_bytes is not None, **b_info},
    }
    if a_bytes is not None and b_bytes is not None:
        report["recompiled_rsrc"]["sha256"] = hashlib.sha256(a_bytes).hexdigest()
        report["original_rsrc"]["sha256"] = hashlib.sha256(b_bytes).hexdigest()
        report["match"] = a_bytes == b_bytes
        if not report["match"]:
            limit = min(len(a_bytes), len(b_bytes))
            first_diff = next((i for i in range(limit) if a_bytes[i] != b_bytes[i]), limit)
            diff_bytes = sum(1 for i in range(limit) if a_bytes[i] != b_bytes[i])
            report["first_diff_offset"] = first_diff
            report["diff_bytes"] = diff_bytes
            report["size_delta"] = len(a_bytes) - len(b_bytes)
    elif a_bytes is None or b_bytes is None:
        report["match"] = False

    if json_output:
        json_print(report)
    else:
        a_present = report["recompiled_rsrc"]["present"]
        b_present = report["original_rsrc"]["present"]
        if not a_present and not b_present:
            console.print("[yellow]Neither PE has a .rsrc section.[/yellow]")
        elif report["match"]:
            console.print(
                f"[green].rsrc sections are byte-identical[/green] ({len(a_bytes or b'')} bytes)"
            )
        else:
            console.print("[red].rsrc sections differ:[/red]")
            console.print(
                f"  recompiled: {len(a_bytes) if a_bytes else 'missing'} bytes"
                f" ({report['recompiled_rsrc'].get('sha256', '')[:12]})"
            )
            console.print(
                f"  original:   {len(b_bytes) if b_bytes else 'missing'} bytes"
                f" ({report['original_rsrc'].get('sha256', '')[:12]})"
            )
            if "first_diff_offset" in report:
                console.print(
                    f"  first diff at offset 0x{report['first_diff_offset']:x}, "
                    f"{report['diff_bytes']} differing bytes, "
                    f"size delta {report['size_delta']:+d}"
                )

    if not report["match"]:
        raise typer.Exit(code=EXIT_MISMATCH)


@app.command("extract")
def extract(
    pe: Path = typer.Argument(..., help="PE to extract the .rsrc section from"),
    output: Path = typer.Option(Path("resource.rsrc"), "--output", "-o", help="Output file"),
) -> None:
    """Extract the .rsrc section raw bytes to *output*."""
    raw, info = _rsrc_bytes(pe)
    if raw is None:
        console.print(f"[yellow]{pe} has no .rsrc section.[/yellow]")
        raise typer.Exit(code=EXIT_MISMATCH)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    console.print(
        f"Wrote {len(raw)} bytes of .rsrc from {pe} to {output} "
        f"(va=0x{info['va']:x}, raw_size=0x{info['raw_size']:x})"
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
