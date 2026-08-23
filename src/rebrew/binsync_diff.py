"""binsync_diff.py — Read-only divergence report between rebrew and a BinSync state.

Compares the local project (reversed annotations + catalog/project file) against a
BinSync state directory and reports every place the two disagree, without
touching disk.  Designed for CI (exit 1 on any divergence, pure JSON on stdout)
and for previewing an import (the same ``--module`` / ``--target`` filter).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from rebrew.binsync_state import index_local_and_catalog, load_binsync_state
from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.utils import strip_body

log = logging.getLogger(__name__)

app = typer.Typer(
    help="Show where rebrew and a BinSync state directory diverge (read-only).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync-diff ./binsync_state · · · · · · Show divergences\n\n"
        "  rebrew binsync-diff ./state --json · · · · · · · Machine-readable report\n\n"
        "  rebrew binsync-diff ./state --module SERVER · · One module only\n\n"
        "[dim]Read-only: never writes. Exits 1 when any divergence exists (CI-friendly). "
        "Same filtering semantics as binsync-import --dry-run.[/dim]"
    ),
)

console = Console(stderr=True)

# Mirrors binsync_import — single source of "meaningful" would be a new shared
# module, but duplicating the 3-line predicate keeps these CLIs independently
# importable (and ruff F401-clean for the non-imported one).
_GENERIC_RE = re.compile(r"^_?(func_|FUN_)[0-9a-fA-F]+(@\d+)?$")
_GHIDRA_GENERIC_RE = re.compile(r"^(FUN_|DAT_|switchdata|thunk_)")
_PLACEHOLDER_RE = re.compile(r"^g_[0-9a-fA-F]{4,8}$")


def _is_meaningful(name: str) -> bool:
    return bool(name) and not (
        _GENERIC_RE.match(name) or _GHIDRA_GENERIC_RE.match(name) or _PLACEHOLDER_RE.match(name)
    )


@app.callback(invoke_without_command=True)
def main(
    state_dir: Path = typer.Argument(..., help="BinSync state directory to compare"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    module: str | None = typer.Option(None, "--module", help="Only this module (e.g. SERVER)"),
    target: str | None = TargetOption,
) -> None:
    """Show where rebrew and a BinSync state diverge (read-only, no writes)."""
    if not state_dir.exists():
        error_exit(f"State directory not found: {state_dir}", json_mode=json_output)
    if not state_dir.is_dir():
        error_exit(f"Not a directory: {state_dir}", json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)

    funcs_by_va, globals_by_va = load_binsync_state(state_dir)
    if not funcs_by_va and not globals_by_va:
        error_exit(f"No BinSync data found in {state_dir}", json_mode=json_output)

    local_by_va, catalog_by_va, catalog_vas = index_local_and_catalog(cfg)

    divergences: list[dict[str, str]] = []
    new_in_binsync: list[dict[str, str]] = []
    skipped = 0

    # --- Functions ---
    for va, bs_entry in sorted(funcs_by_va.items()):
        bs_name = bs_entry.get("name", "")
        bs_proto = bs_entry.get("prototype", "")
        local = local_by_va.get(va)

        if local is not None and module is not None and getattr(local, "module", "") != module:
            skipped += 1
            continue

        if local is None:
            if va in catalog_vas and _is_meaningful(bs_name):
                new_in_binsync.append(
                    {"va": f"0x{va:08x}", "binsync": bs_name, "status": "new_in_binsync"}
                )
                divergences.append(
                    {
                        "va": f"0x{va:08x}",
                        "field": "new_function",
                        "local": "",
                        "binsync": bs_name,
                        "kind": "new_in_binsync",
                    }
                )
            else:
                skipped += 1
            continue

        # Existing annotation — check name + prototype
        local_name = getattr(local, "symbol", "") or getattr(local, "name", "") or ""
        raw_proto = getattr(local, "prototype", "") or ""
        local_proto = strip_body(raw_proto) if raw_proto else ""
        # prototype divergence
        if bs_proto and bs_proto != local_proto:
            # Local prototype with body stripped vs binsync header type
            # Report even though prototype import is orthogonal to name conflicts
            divergences.append(
                {
                    "va": f"0x{va:08x}",
                    "field": "prototype",
                    "local": local_proto,
                    "binsync": bs_proto,
                    "kind": "prototype_mismatch",
                }
            )

        if not bs_name or not _is_meaningful(bs_name):
            continue
        # same name ignoring cdecl prefix
        bs_stripped = bs_name[1:] if bs_name.startswith("_") else bs_name
        local_stripped = local_name[1:] if local_name.startswith("_") else local_name
        if bs_stripped == local_stripped:
            continue
        if not _is_meaningful(local_name):
            divergences.append(
                {
                    "va": f"0x{va:08x}",
                    "field": "name",
                    "local": local_name,
                    "binsync": bs_name,
                    "kind": "generic_vs_meaningful",
                }
            )
        else:
            divergences.append(
                {
                    "va": f"0x{va:08x}",
                    "field": "name",
                    "local": local_name,
                    "binsync": bs_name,
                    "kind": "conflict",
                    "filepath": str(getattr(local, "filepath", "")),
                }
            )

    # --- Globals ---
    for va, bs_entry in sorted(globals_by_va.items()):
        bs_name = bs_entry.get("name", "")
        if not bs_name or not _is_meaningful(bs_name):
            continue
        if va in funcs_by_va:
            continue
        local = local_by_va.get(va)
        if local is not None and module is not None and getattr(local, "module", "") != module:
            skipped += 1
            continue
        local_name = (
            getattr(local, "name", "") or getattr(local, "symbol", "") or "" if local else ""
        )
        if local is None:
            divergences.append(
                {
                    "va": f"0x{va:08x}",
                    "field": "global_name",
                    "local": "",
                    "binsync": bs_name,
                    "kind": "new_global_in_binsync",
                }
            )
        elif local_name != bs_name:
            divergences.append(
                {
                    "va": f"0x{va:08x}",
                    "field": "global_name",
                    "local": local_name,
                    "binsync": bs_name,
                    "kind": "global_name_mismatch",
                }
            )

    if json_output:
        result: dict[str, object] = {
            "state_dir": str(state_dir),
            "divergences": len(divergences),
            "skipped": skipped,
        }
        if module is not None:
            result["module"] = module
        if divergences:
            result["items"] = divergences
        if new_in_binsync:
            result["new_in_binsync"] = new_in_binsync
        json_print(result)
        if divergences:
            raise typer.Exit(code=1)
        return

    if not divergences:
        console.print("[green]No divergences — rebrew and BinSync are in sync.[/green]")
        return

    table = Table(title=f"BinSync divergences ({len(divergences)})", show_lines=False)
    table.add_column("VA", style="cyan", no_wrap=True)
    table.add_column("Field")
    table.add_column("Local", overflow="fold")
    table.add_column("BinSync", style="bold", overflow="fold")
    table.add_column("Kind", style="dim")
    for d in divergences[:200]:
        table.add_row(
            d.get("va", ""),
            d.get("field", ""),
            d.get("local", ""),
            d.get("binsync", ""),
            d.get("kind", ""),
        )
    console.print(table)
    if len(divergences) > 200:
        console.print(f"[dim]… and {len(divergences) - 200} more (see --json)[/dim]")
    raise typer.Exit(code=1)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
