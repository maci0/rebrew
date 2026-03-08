"""binsync_export.py - Experimental BinSync export support.

Reads the project's annotations and exports them as a BinSync TOML repository.
"""

from pathlib import Path

import tomlkit
import typer
from rich.console import Console

from rebrew.catalog.loaders import scan_reversed_dir
from rebrew.cli import TargetOption, json_print, require_config

app = typer.Typer(help="Experimental BinSync export support.", rich_markup_mode="rich")

console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def main(
    outdir: Path = typer.Argument(..., help="Output directory for the BinSync repository state"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Export rebrew annotations to an experimental BinSync state directory."""
    cfg = require_config(target=target, json_mode=json_output)

    # Initialize directory
    outdir.mkdir(parents=True, exist_ok=True)
    funcs_dir = outdir / "functions"
    funcs_dir.mkdir(parents=True, exist_ok=True)

    # Load all annotations
    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)

    if not json_output:
        console.print(f"Exporting {len(entries)} annotations to {outdir}...")

    # Write functions
    written: list[str] = []
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

        out_path = funcs_dir / f"{va:08x}.toml"
        out_path.write_text(tomlkit.dumps(doc), encoding="utf-8")
        written.append(str(out_path))

    if json_output:
        json_print({"outdir": str(outdir), "count": len(written), "files": written})
    else:
        console.print(f"Exported {len(written)} functions to BinSync format at {outdir}.")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
