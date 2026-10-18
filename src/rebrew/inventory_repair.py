"""Review and repair selected native function inventory extents."""

import typer

from rebrew.catalog.inventory import repair_inventory_extents
from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
)

app = typer.Typer(
    help="Repair native inventory extents or explicitly admit reviewed missing entries.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binary repair-extents 0x401000=16 --reason proof --dry-run\n\n"
        "  rebrew binary repair-extents 0x401010=3 --add-missing --reason proof"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    specifications: list[str] = typer.Argument(..., help="Native 0xVA=SIZE repairs"),
    reason: str = typer.Option(..., "--reason", help="Reviewed native boundary evidence"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    add_missing: bool = typer.Option(
        False, "--add-missing", help="Explicitly admit reviewed functions absent from the inventory"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Repair selected inventory extents; source metadata and verdicts stay separate."""
    cfg = require_config(target=target, json_mode=json_output)
    updates: dict[int, int] = {}
    try:
        for spec in specifications:
            address, separator, value = spec.partition("=")
            if not separator:
                raise ValueError("extent repairs require 0xVA=SIZE")
            va, size = parse_va(address, json_mode=json_output), int(value, 0)
            if va in updates and updates[va] != size:
                raise ValueError(f"conflicting sizes for 0x{va:x}")
            updates[va] = size
        report = repair_inventory_extents(
            cfg,
            updates,
            reason=reason,
            dry_run=dry_run,
            expected_digest=expected_digest,
            add_missing=add_missing,
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
