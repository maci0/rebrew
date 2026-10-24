"""Clear a saved per-function compiler flag override through the metadata writer."""

import typer

from rebrew.blocker import resolve_function
from rebrew.cli import SOURCE_HELP, TargetOption, console, error_exit, json_print, require_config
from rebrew.metadata.functions import get_entry, remove_field

app = typer.Typer(
    help="Clear a saved function CFLAGS override; inspect effective settings with diagnose config.",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source clear-cflags 0x401000 --dry-run --json\n\n"
        "  rebrew source clear-cflags src/game.c --va 0x401000\n\n"
        "  rebrew diagnose config src/game.c --json"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    function: str = typer.Argument(..., help=SOURCE_HELP),
    va: str | None = typer.Option(
        None, "--va", help="Disambiguate VA in a multi-function file (hex)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Drop only the selected row's CFLAGS; preserve its verdict and history."""
    cfg = require_config(target=target, json_mode=json_output)
    module, address = resolve_function(cfg, function, va, json_output)
    try:
        entry = get_entry(cfg.metadata_dir, address, module)
        if not entry:
            error_exit("function has no stored metadata row", json_mode=json_output)
        cleared = False if dry_run else remove_field(cfg.metadata_dir, address, "cflags", module)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    report = {
        "module": module,
        "va": f"0x{address:08x}",
        "previous_cflags": entry.get("cflags"),
        "dry_run": dry_run,
        "cleared": cleared,
    }
    if json_output:
        json_print(report)
    else:
        console.print(report)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)
