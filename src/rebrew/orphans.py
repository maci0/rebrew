"""orphans.py - Prune orphaned metadata entries and remove a VA's metadata block.

An *orphan* is a ``rebrew-functions.toml`` / ``rebrew-data.toml`` block whose
``(module, va)`` has no ``// FUNCTION:`` / ``// DATA:`` / ``// GLOBAL:``
marker in any source file — left behind when a function is deleted, moved to
another file without its marker, or re-discovered at a new VA.  Verify,
status, and todo all read the source annotations, so orphans are invisible
there and accumulate silently.

``rebrew orphans`` lists them (default) or deletes them (``--prune``);
``rebrew orphans drop`` removes one VA's block on demand.
"""

from typing import Any

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

app = typer.Typer(
    help="List or prune orphaned metadata blocks (no source marker).",
    rich_markup_mode="rich",
)


def find_orphans(cfg: Any) -> tuple[list[tuple[str, int, str]], list[tuple[str, int, str]]]:
    """Return ``(function_orphans, data_orphans)`` as ``(module, va, store)`` triples.

    A metadata block is orphaned when no source annotation claims its
    ``(module, va)``.  Pure metadata + source logic — no writes.

    Safety rule: a block whose VA is a real function in the target's
    function list is *not* an orphan even without a marker — the source
    file may be mid-split, the marker may live under a different module
    spelling, or the function may simply not be reversed yet.  Deleting
    its block would destroy earned STATUS.  Only blocks whose VA is
    absent from the function list (stale annotations, scratch VAs like
    ``0xdeadbeef``) are reported.
    """
    from rebrew.catalog import cached_function_list, scan_reversed_dir
    from rebrew.data_metadata import load_data_metadata
    from rebrew.metadata import load_metadata

    live: set[tuple[str, int]] = set()
    for entry in scan_reversed_dir(cfg.reversed_dir, cfg=cfg):
        module = getattr(entry, "module", "") or ""
        va = int(getattr(entry, "va", 0) or 0)
        if module and va:
            live.add((module, va))
    known_vas: set[int] = set()
    try:
        for f in cached_function_list(cfg) or []:
            va = int(f.get("va", 0) or 0)
            if va:
                known_vas.add(va)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        known_vas = set()
    fn_orphans = [
        (module, va, "rebrew-functions.toml")
        for (module, va) in sorted(load_metadata(cfg.metadata_dir))
        if (module, va) not in live and va not in known_vas
    ]
    data_entries = load_data_metadata(cfg.metadata_dir)
    data_orphans = [
        (module, va, "rebrew-data.toml")
        for (module, va) in sorted(data_entries)
        if (module, va) not in live
        and va not in known_vas
        # Import slots (.idata/.edata) never have source markers by design —
        # they are inventory, not annotations.  Pruning them would delete the
        # import inventory `rebrew data` maintains.
        and str(data_entries[(module, va)].get("section") or "") not in (".idata", ".edata")
        # A named data entry is claimed by name even without a VA marker —
        # only unnamed entries with no marker are true orphans.
        and not str(data_entries[(module, va)].get("name") or "").strip()
    ]
    return fn_orphans, data_orphans


def split_prunable(
    cfg: Any,
    fn_orphans: list[tuple[str, int, str]],
    data_orphans: list[tuple[str, int, str]],
    *,
    include_matched: bool = False,
) -> list[dict[str, Any]]:
    """Split orphans into the prunable subset (held-back matched excluded).

    Shared by the ``orphans --prune`` path and ``verify --prune-orphans`` so
    both hold back EXACT/RELOC/PROVEN blocks unless *include_matched*.
    """
    orphans = _orphan_dicts(cfg, fn_orphans, data_orphans)
    if include_matched:
        return orphans
    return [o for o in orphans if o["status"] not in ("EXACT", "RELOC", "PROVEN")]


def _orphan_dicts(
    cfg: Any,
    fn_orphans: list[tuple[str, int, str]],
    data_orphans: list[tuple[str, int, str]],
) -> list[dict[str, Any]]:
    from rebrew.data_metadata import get_data_entry
    from rebrew.metadata import get_entry

    dicts = []
    for module, va, store in fn_orphans + data_orphans:
        if store == "rebrew-data.toml":
            status = str(get_data_entry(cfg.metadata_dir, va, module).get("status") or "")
        else:
            status = str(get_entry(cfg.metadata_dir, va, module).get("status") or "")
        dicts.append({"module": module, "va": f"0x{va:x}", "store": store, "status": status})
    return dicts


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    prune: bool = typer.Option(False, "--prune", help="Delete the orphaned blocks"),
    include_matched: bool = typer.Option(
        False,
        "--include-matched",
        help="Also prune orphans whose block claims EXACT/RELOC/PROVEN",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """List orphaned metadata blocks (VA with no source marker); --prune deletes them."""
    if ctx.invoked_subcommand is not None:
        return
    cfg = require_config(target=target, json_mode=json_output)
    fn_orphans, data_orphans = find_orphans(cfg)
    total = len(fn_orphans) + len(data_orphans)

    orphans = _orphan_dicts(cfg, fn_orphans, data_orphans)
    if json_output:
        json_print({"orphans": orphans, "pruned": 0})
        return
    if total == 0:
        console.print("[green]No orphaned metadata blocks.[/green]")
        return
    for o in orphans:
        flag = " [red]matched[/red]" if o["status"] in ("EXACT", "RELOC", "PROVEN") else ""
        console.print(f"  [yellow]orphan[/yellow] {o['module']} {o['va']} ({o['store']}){flag}")

    if not prune:
        console.print(
            f"\n{total} orphaned block(s) — re-run with [bold]--prune[/bold] to delete them"
        )
        return

    # Matched orphans (EXACT/RELOC/PROVEN with no marker) are held back —
    # split_prunable is the shared gate with verify --prune-orphans.
    doomed = split_prunable(cfg, fn_orphans, data_orphans, include_matched=include_matched)
    held_count = total - len(doomed)
    if dry_run:
        console.print(
            f"\n[yellow]Dry run:[/yellow] {len(doomed)} orphaned block(s) would be deleted"
            + (f" ({held_count} matched held back)" if held_count and not include_matched else "")
        )
        return
    if held_count and not include_matched:
        console.print(
            f"[yellow]Holding back {held_count} matched orphan(s)[/yellow] "
            "(EXACT/RELOC/PROVEN with no marker — re-attach a marker or pass "
            "[bold]--include-matched[/bold])"
        )

    from rebrew.data_metadata import delete_data_entries_batch
    from rebrew.metadata import delete_entries_batch

    pruned = delete_entries_batch(
        cfg.metadata_dir,
        [(o["module"], int(o["va"], 16)) for o in doomed if o["store"] == "rebrew-functions.toml"],
    )
    pruned += delete_data_entries_batch(
        cfg.metadata_dir,
        [(o["module"], int(o["va"], 16)) for o in doomed if o["store"] == "rebrew-data.toml"],
    )
    console.print(f"\n[green]Pruned:[/green] deleted {pruned} orphaned block(s)")


@app.command("drop")
def drop(
    target_ident: str = typer.Argument(..., help="Hex VA (0x...), file path, or symbol"),
    va_override: str | None = typer.Option(None, "--va", help="VA when TARGET is a file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Delete one VA's metadata block from rebrew-functions.toml / rebrew-data.toml."""
    from rebrew.blocker import _resolve_target

    cfg = require_config(target=target, json_mode=json_output)
    module, va_int = _resolve_target(cfg, target_ident, va_override, json_output)

    from rebrew.data_metadata import delete_data_entries_batch, get_data_entry
    from rebrew.metadata import delete_entries_batch, get_entry

    fn_hit = bool(get_entry(cfg.metadata_dir, va_int, module))
    data_hit = bool(get_data_entry(cfg.metadata_dir, va_int, module))
    if not fn_hit and not data_hit:
        error_exit(
            f"No metadata block for {module} 0x{va_int:x} — nothing to drop",
            json_mode=json_output,
        )
    stores = "/".join(
        s for s, hit in (("rebrew-functions.toml", fn_hit), ("rebrew-data.toml", data_hit)) if hit
    )
    if dry_run:
        if json_output:
            json_print(
                {
                    "module": module,
                    "va": f"0x{va_int:x}",
                    "stores": stores,
                    "dropped": False,
                    "dry_run": True,
                }
            )
        else:
            console.print(f"  [dim]Would drop[/dim] {module} 0x{va_int:x} block ({stores})")
        return
    dropped = 0
    if fn_hit:
        dropped += delete_entries_batch(cfg.metadata_dir, [(module, va_int)])
    if data_hit:
        dropped += delete_data_entries_batch(cfg.metadata_dir, [(module, va_int)])
    if json_output:
        json_print({"module": module, "va": f"0x{va_int:x}", "stores": stores, "dropped": dropped})
    else:
        console.print(f"[green]Dropped:[/green] {module} 0x{va_int:x} block ({stores})")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
