"""binsync_export.py - Experimental BinSync export support.

Reads the project's annotations and exports them as a BinSync TOML repository.
"""

from pathlib import Path

import tomlkit
import typer

from rebrew.catalog.loaders import scan_reversed_dir
from rebrew.cli import TargetOption, require_config

app = typer.Typer(help="Experimental BinSync export support.")


@app.callback(invoke_without_command=True)
def main(
    outdir: Path = typer.Argument(..., help="Output directory for the BinSync repository state"),
    target: str | None = TargetOption,
) -> None:
    """Export rebrew annotations to an experimental BinSync state directory."""
    cfg = require_config(target)

    # Initialize directory
    outdir.mkdir(parents=True, exist_ok=True)
    funcs_dir = outdir / "functions"
    funcs_dir.mkdir(parents=True, exist_ok=True)

    # Load all annotations
    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)

    typer.echo(f"Exporting {len(entries)} annotations to {outdir}...", err=True)

    # Write functions
    count = 0
    for entry in entries:
        if entry.marker_type in ("GLOBAL", "DATA"):
            continue

        va = entry.va
        size = entry.size
        # Fallback to symbol -> name -> func_va
        name = entry.symbol or entry.name or f"func_{va:08x}"

        doc = tomlkit.document()
        info = tomlkit.table()
        info["name"] = name
        info["addr"] = va
        if size > 0:
            info["size"] = size
        doc["info"] = info

        # header = tomlkit.table()
        # header["type"] = f"void {name}()"  # To be implemented precisely
        # doc["header"] = header

        out_path = funcs_dir / f"{va:08x}.toml"
        out_path.write_text(tomlkit.dumps(doc), encoding="utf-8")
        count += 1

    typer.echo(f"Exported {count} functions to BinSync format at {outdir}.", err=True)
