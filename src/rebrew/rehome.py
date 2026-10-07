"""rehome.py - Point function rows at the source file that now defines them.

Moving a function's definition between multi-function files (restoring the
original translation-unit layout) leaves its row's ``file`` naming the old
file, and ``rebrew test`` then looks for the symbol in the wrong object.
``merge`` and ``split`` retarget the rows they move; a hand move had no writer.
"""

from pathlib import Path
from typing import Any

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config

app = typer.Typer(
    help="Point function rows at the source file that now defines them.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source rehome 0x1000ca90=src/game/command.c · Re-home one function\n\n"
        "  rebrew source rehome 0x1000ca90=a.c 0x1000cb20=a.c --dry-run\n\n"
        "[dim]The destination must define the row's function; the definition text "
        "is not moved.[/dim]"
    ),
)


def rehome_functions(cfg: Any, specs: list[str], *, dry_run: bool = False) -> list[dict[str, Any]]:
    """Set each ``0xVA=PATH`` function row's ``file`` to PATH after checking PATH defines it."""
    from rebrew.c_parser import find_c_function_definitions
    from rebrew.metadata import (
        get_entry,
        identity_file,
        record_migrated_markers,
        validate_identity_file,
    )
    from rebrew.sources import target_marker

    module = target_marker(cfg) or ""
    if not module:
        raise ValueError("no target marker configured to address the function metadata")
    rows: list[dict[str, Any]] = []
    for spec in specs:
        va_s, sep, value = spec.partition("=")
        value = value.strip()
        if not sep or not value:
            raise ValueError(f"rehome wants 0xVA=PATH, got {spec!r}")
        va = int(va_s, 16)
        entry = get_entry(cfg.metadata_dir, va, module)
        name = str(entry.get("name") or str(entry.get("symbol") or "").lstrip("_"))
        if not name:
            raise ValueError(f"no function row at {module}.0x{va:x}")
        path = Path(value)
        if not path.is_absolute():
            path = cfg.root / path
        if not path.is_file():
            raise ValueError(f"{value} is not a file")
        defined = {fn for fn, _ in find_c_function_definitions(path.read_text(errors="replace"))}
        if name not in defined:
            raise ValueError(f"{value} does not define {name}")
        identity = validate_identity_file(identity_file(path, cfg.metadata_dir))
        rows.append(
            {
                "va": f"0x{va:x}",
                "name": name,
                "old_file": str(entry.get("file") or ""),
                "file": identity,
            }
        )
    if not dry_run:
        record_migrated_markers(
            cfg.metadata_dir,
            [
                {"module": module, "va": int(r["va"], 16), "identity": {"file": r["file"]}}
                for r in rows
            ],
            updated_by="rehome",
        )
    return rows


@app.callback(invoke_without_command=True)
def main(
    specs: list[str] = typer.Argument(
        ..., metavar="0xVA=PATH", help="Function VA and its new file"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Point function rows at the source file that now defines them."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        rows = rehome_functions(cfg, specs, dry_run=dry_run)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print({"rows": rows, "dry_run": dry_run})
        return
    for r in rows:
        console.print(f"{r['va']} {r['name']}: {r['old_file'] or '-'} -> {r['file']}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
