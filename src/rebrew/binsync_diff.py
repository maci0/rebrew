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

import tomlkit
import typer
from rich.console import Console
from rich.table import Table

from rebrew.catalog.loaders import scan_reversed_dir
from rebrew.cli import TargetOption, error_exit, json_print, require_config

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


def _strip_body(prototype: str) -> str:
    brace = prototype.find("{")
    return prototype[:brace].strip() if brace != -1 else prototype.strip()


def _load_binsync_state(
    state_dir: Path,
) -> tuple[dict[int, dict[str, str]], dict[int, dict[str, str]]]:
    funcs: dict[int, dict[str, str]] = {}
    funcs_dir = state_dir / "functions"
    if funcs_dir.is_dir():
        for p in funcs_dir.glob("*.toml"):
            try:
                doc = tomlkit.parse(p.read_text(encoding="utf-8"))
            except Exception:
                log.debug("unparseable BinSync function TOML %s", p.name, exc_info=True)
                continue
            info = doc.get("info", {})
            if not isinstance(info, dict):
                continue
            addr = info.get("addr")
            if addr is None:
                try:
                    addr = int(p.stem, 16)
                except ValueError:
                    continue
            try:
                va = int(addr)
            except (TypeError, ValueError):
                continue
            entry: dict[str, str] = {}
            name = info.get("name")
            if isinstance(name, str) and name:
                entry["name"] = name
            header = doc.get("header", {})
            if isinstance(header, dict):
                htype = header.get("type")
                if isinstance(htype, str) and htype.strip():
                    entry["prototype"] = htype.strip()
            funcs[va] = entry

    globals_map: dict[int, dict[str, str]] = {}
    gv_path = state_dir / "global_vars.toml"
    if gv_path.exists():
        try:
            doc = tomlkit.parse(gv_path.read_text(encoding="utf-8"))
            for _k, entry in doc.items():
                if not isinstance(entry, dict):
                    continue
                addr = entry.get("addr")
                if addr is None:
                    try:
                        addr = int(_k, 0)
                    except ValueError:
                        continue
                try:
                    va = int(addr)
                except (TypeError, ValueError):
                    continue
                gname = entry.get("name")
                if isinstance(gname, str) and gname:
                    globals_map[va] = {"name": gname}
        except Exception:
            log.debug("unparseable BinSync global_vars.toml", exc_info=True)
            pass
    return funcs, globals_map


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

    funcs_by_va, globals_by_va = _load_binsync_state(state_dir)
    if not funcs_by_va and not globals_by_va:
        error_exit(f"No BinSync data found in {state_dir}", json_mode=json_output)

    # Local index: reversed + catalog (same as import)
    local_entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    local_by_va: dict[int, object] = {}
    for e in local_entries:
        va = getattr(e, "va", 0)
        if va and (va not in local_by_va or getattr(e, "marker_type", "") == "FUNCTION"):
            local_by_va[va] = e

    catalog_by_va: dict[int, object] = {}
    catalog_vas: set[int] = set()
    try:
        import warnings

        from rebrew.catalog.loaders import parse_function_list
        from rebrew.catalog.registry import build_function_registry
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            funcs = parse_function_list(cfg.function_list)
        ghidra_path = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON
        registry = build_function_registry(funcs, cfg, ghidra_path, cfg.target_binary)
        for va, reg_entry in registry.items():
            if va in local_by_va:
                continue
            if reg_entry.get("is_thunk"):
                continue
            size = int(reg_entry.get("canonical_size", 0) or 0)
            if size <= 0:
                continue
            raw_name = (
                reg_entry.get("list_name") or reg_entry.get("ghidra_name") or f"func_{va:08x}"
            )
            catalog_by_va[va] = type(
                "CatalogFunc",
                (),
                {
                    "va": va,
                    "size": size,
                    "name": raw_name,
                    "symbol": "",
                    "module": "",
                    "prototype": "",
                    "marker_type": "FUNCTION",
                    "filepath": "",
                    "status": "",
                },
            )()
    except Exception:
        log.debug("catalog scan failed — treating as empty", exc_info=True)
        pass
    catalog_vas = set(catalog_by_va.keys())

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
        local_proto = _strip_body(raw_proto) if raw_proto else ""
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
