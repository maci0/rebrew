"""symbol-addrs — export function symbols as a splat-style ``symbol_addrs.csv``.

The decomp-scene's splat ecosystem uses a flat two-column CSV (``0xVA,name``)
as the interchange format between the binary splitter, m2c, and the diff
tooling.  Rebrew keeps the same information in per-directory
``rebrew-functions.toml`` + annotations, but there is no portable export —
Ghidra imports, splat-style tooling, and third-party viewers all expect the
CSV.  This command writes it.

Format (splat-compatible):
    ``0x80123456,Function_Name``

One line per FUNCTION/LIBRARY/STUB annotation, sorted by VA, GLOBAL/DATA
markers excluded (they describe data, not callable code).

Usage:
    rebrew symbol-addrs --out symbol_addrs.csv
    rebrew symbol-addrs -t mygame --out build/symbol_addrs.csv
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import TargetOption, iter_annotations, require_config
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

app = typer.Typer(
    help="Export function symbols as a splat-style symbol_addrs.csv.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    out: Path = typer.Option(Path("symbol_addrs.csv"), "--out", help="Output CSV path"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Write ``0xVA,name`` lines for every annotated function, sorted by VA."""
    cfg = require_config(target=target, json_mode=json_output)
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    marker = target_marker(cfg)
    rows: list[tuple[int, str]] = []
    skipped = 0
    for _path, annos in iter_annotations(sources, target=marker, metadata_dir=cfg.metadata_dir):
        for a in annos:
            if a.marker_type in ("GLOBAL", "DATA"):
                continue
            name = a.symbol or a.name or ""
            if not name:
                skipped += 1
                continue
            rows.append((a.va, name))
    rows.sort(key=lambda r: r[0])
    lines = [f"0x{va:08X},{name}" for va, name in rows]

    atomic_write_text(out, "\n".join(lines) + "\n", encoding="utf-8")
    if json_output:
        from rebrew.cli import json_print

        json_print(
            {
                "out": str(out),
                "symbols": len(rows),
                "skipped_unnamed": skipped,
            }
        )
        return
    console.print(
        f"[green]Wrote {len(rows)} symbol(s) to {out}[/green]"
        + (f" ({skipped} unnamed skipped)" if skipped else "")
    )


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
