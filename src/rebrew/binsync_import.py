"""binsync_import.py — Import a BinSync state directory into rebrew metadata.

Reads a BinSync state directory (as produced by ``rebrew binsync-export`` or
any BinSync-aware decompiler) and offers to apply function renames,
prototype updates, and global names back into the rebrew project.

This is the minimal inverse of :mod:`rebrew.binsync_export` and does not
require ``libbs`` — it reads plain TOML via ``tomlkit``.  Conflict handling
mirrors :mod:`rebrew.ghidra.commands` (``--accept-binsync`` / ``--accept-local``).

Typical flow::

    rebrew binsync-export ./state          # team member renames in IDA
    rebrew binsync-import ./state --dry-run
    rebrew binsync-import ./state --accept-binsync

Functions whose local name is generic (``func_…``, ``FUN_…``) are updated
without conflict; when both sides have meaningful names a conflict is reported
and no write occurs unless ``--accept-binsync`` or ``--accept-local`` is given.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import typer
from rich.console import Console

from rebrew.binsync_state import index_local_and_catalog, load_binsync_state
from rebrew.cli import TargetOption, error_exit, json_print, require_config

log = logging.getLogger(__name__)

app = typer.Typer(
    help="Import a BinSync state directory into rebrew metadata.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync-import ./state --dry-run · · · Preview without writing\n\n"
        "  rebrew binsync-import ./state --accept-binsync · Accept BinSync names\n\n"
        "  rebrew binsync-import ./state --accept-local · · Keep local, record provenance\n\n"
        "  rebrew binsync-import ./state --module SERVER · Only import one module\n\n"
        "[dim]Reads functions/*.toml, global_vars.toml, and structs/*.toml from a BinSync\n"
        "state directory and applies names/prototypes/globals back to rebrew metadata.[/dim]"
    ),
)

console = Console(stderr=True)

# Mirrors rebrew.ghidra.commands._GENERIC_NAME_RE, plus our own placeholder globals
_GENERIC_NAME_RE = re.compile(r"^_?(func_|FUN_)[0-9a-fA-F]+(@\d+)?$")
_GHIDRA_GENERIC_RE = re.compile(r"^(FUN_|DAT_|switchdata|thunk_)")
# Our own synthetic placeholder for DATA/GLOBAL entries with missing declarations
_PLACEHOLDER_GLOBAL_RE = re.compile(r"^g_[0-9a-fA-F]{4,8}$")


def _is_generic(name: str) -> bool:
    return bool(_GENERIC_NAME_RE.match(name))


def _is_meaningful(name: str) -> bool:
    return bool(name) and not (
        _is_generic(name) or _GHIDRA_GENERIC_RE.match(name) or _PLACEHOLDER_GLOBAL_RE.match(name)
    )


def _strip_cdecl_prefix(name: str) -> str:
    return name[1:] if name.startswith("_") else name


@app.callback(invoke_without_command=True)
def main(
    state_dir: Path = typer.Argument(..., help="BinSync state directory to import"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    module: str | None = typer.Option(
        None, "--module", help="Only import this module (e.g. SERVER)"
    ),
    accept_binsync: bool = typer.Option(
        False, "--accept-binsync", help="Accept BinSync names for all conflicts"
    ),
    accept_local: bool = typer.Option(
        False, "--accept-local", help="Keep local names for all conflicts (records provenance)"
    ),
    create_missing: bool = typer.Option(
        False,
        "--create-missing",
        help="Create STUB files for BinSync functions not in the project catalog",
    ),
    target: str | None = TargetOption,
) -> None:
    """Import a BinSync state directory into rebrew metadata."""
    if accept_binsync and accept_local:
        error_exit(
            "--accept-binsync and --accept-local are mutually exclusive", json_mode=json_output
        )

    if not state_dir.exists():
        error_exit(f"State directory not found: {state_dir}", json_mode=json_output)
    if not state_dir.is_dir():
        error_exit(f"Not a directory: {state_dir}", json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)

    funcs_by_va, globals_by_va = load_binsync_state(state_dir)

    if not funcs_by_va and not globals_by_va:
        error_exit(f"No BinSync data found in {state_dir}", json_mode=json_output)

    local_by_va, catalog_by_va, catalog_vas = index_local_and_catalog(cfg)

    # Also collect scan for module routing of globals that have no direct annotation
    # (DATA entries are in local_by_va; unannotated externs are not — but those
    # can't be imported meaningfully anyway)

    proposed: list[dict[str, str]] = []  # for dry-run / json
    conflicts: list[dict[str, str]] = []
    applied_names = 0
    applied_protos = 0
    applied_globals = 0
    skipped = 0

    # --- Function names + prototypes ---
    for va, bs_entry in sorted(funcs_by_va.items()):
        bs_name = bs_entry.get("name", "")
        bs_proto = bs_entry.get("prototype", "")

        # Module filter: only import entries whose local module matches filter
        local = local_by_va.get(va)
        if local is not None and module is not None and getattr(local, "module", "") != module:
            skipped += 1
            continue

        # If no local function at this VA, distinguish catalog-known vs
        # truly unknown.  Catalog-known + BinSync-known can become stubs;
        # unknown is just skipped.
        if local is None:
            if va in catalog_vas and _is_meaningful(bs_name) and bs_name.strip():
                # Surface as proposed_missing; optionally create a stub
                bs_stripped = _strip_cdecl_prefix(bs_name) if bs_name.startswith("_") else bs_name
                if create_missing:
                    if dry_run:
                        proposed.append(
                            {
                                "va": f"0x{va:08x}",
                                "field": "new_function",
                                "local": "",
                                "binsync": bs_name,
                                "action": "would create STUB",
                            }
                        )
                        skipped += 1
                        continue
                    # Create a STUB file for this new function.  Keep it minimal
                    # (the shared skeleton helper has its own CLI parsing and
                    # metadata logic that doesn't fit this batch path).
                    try:
                        target_func = (
                            bs_stripped if bs_stripped.isidentifier() else f"func_{va:08x}"
                        )
                        cat = catalog_by_va.get(va)
                        size_hint = int(getattr(cat, "size", 0) or 0) if cat else 0
                        out_path = cfg.reversed_dir / f"{target_func}.c"
                        if out_path.exists():
                            skipped += 1
                            continue
                        from rebrew.utils import atomic_write_text as _awt

                        # Preserve BinSync's prototype when present (keeps calling convention / args);
                        # otherwise synthesize a minimal void stub.  The SIZE comes from the
                        # catalog canonical size, not the compiled body.
                        bs_proto = bs_entry.get("prototype", "").strip()
                        if bs_proto and bs_proto.endswith(";"):
                            bs_proto = bs_proto[:-1].strip()
                        body_proto = bs_proto if bs_proto else f"void {target_func}(void)"
                        # Marker line only — STATUS/SIZE/NOTE are metadata-owned
                        # keys and go to rebrew-function.toml (inline forms are
                        # deprecated: lint W019 flags them).
                        stub = (
                            f"// FUNCTION: {cfg.marker or 'SERVER'} 0x{va:08x}\n{body_proto} {{}}\n"
                        )
                        _awt(out_path, stub, encoding="utf-8")
                        # Route the volatile fields through the canonical metadata
                        # writers (STATUS via the promotion gate).
                        mod = cfg.marker or "SERVER"
                        from rebrew.metadata import set_field, update_source_status

                        update_source_status(cfg.metadata_dir, "STUB", mod, va)
                        if size_hint:
                            set_field(cfg.metadata_dir, va, "size", size_hint, mod)
                        set_field(
                            cfg.metadata_dir,
                            va,
                            "note",
                            f"imported from BinSync as {bs_name}",
                            mod,
                        )
                        applied_names += 1
                    except Exception:  # noqa: BLE001
                        log.debug("stub write failed for VA 0x%x", va, exc_info=True)
                        skipped += 1
                    continue
                # Not creating — surface as proposed_missing
                proposed.append(
                    {
                        "va": f"0x{va:08x}",
                        "field": "new_function",
                        "local": "",
                        "binsync": bs_name,
                        "action": "new BinSync function not in catalog annotations (use --create-missing)",
                    }
                )
            skipped += 1
            continue

        local_name = getattr(local, "symbol", "") or getattr(local, "name", "") or ""
        raw_proto = getattr(local, "prototype", "") or ""
        # BinSync [header].type stores signature without body; local prototype may have body
        from rebrew.binsync_export import _strip_body as _sb  # local import to avoid cycle

        local_proto = _sb(raw_proto) if raw_proto else ""
        local_filepath = getattr(local, "filepath", "")

        # Resolve BinSync name to a local symbol form (strip cdecl prefix for comparison)
        # BinSync names are typically "_foo" (cdecl) — local symbol is also "_foo"
        bs_stripped = _strip_cdecl_prefix(bs_name) if bs_name.startswith("_") else bs_name
        local_stripped = (
            _strip_cdecl_prefix(local_name) if local_name.startswith("_") else local_name
        )

        # Prototype import (independent of name)
        if bs_proto and bs_proto != local_proto:
            if dry_run:
                proposed.append(
                    {
                        "va": f"0x{va:08x}",
                        "field": "prototype",
                        "local": local_proto,
                        "binsync": bs_proto,
                    }
                )
            elif not json_output:
                console.print(f"  Would update prototype 0x{va:08x} (dry-run)")
            if not dry_run:
                try:
                    from rebrew.annotation import update_annotation_key as _uak

                    fp = Path(cfg.reversed_dir) / local_filepath if local_filepath else None
                    if fp is not None and fp.exists():
                        _uak(fp, va, "PROTOTYPE", bs_proto, metadata_dir=cfg.metadata_dir)
                        applied_protos += 1
                    else:
                        # No file to write — record but can't apply
                        skipped += 1
                except Exception:
                    log.debug("prototype apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            else:
                applied_protos += 1

        if not bs_name or not _is_meaningful(bs_name):
            continue

        # If local already has same meaningful name (ignoring _ prefix), skip
        if bs_stripped == local_stripped:
            continue

        # If local is generic and BinSync is meaningful → safe to apply
        if not _is_meaningful(local_name):
            if dry_run:
                proposed.append(
                    {"va": f"0x{va:08x}", "field": "name", "local": local_name, "binsync": bs_name}
                )
            if not dry_run:
                try:
                    from rebrew.rename import rename_function_everywhere as _rename

                    fp = Path(cfg.reversed_dir) / local_filepath if local_filepath else None
                    if fp is None or not fp.exists():
                        skipped += 1
                        continue
                    old_name = getattr(local, "name", "") or ""
                    old_sym = getattr(local, "symbol", "") or old_name
                    target_func = bs_stripped
                    # Validate target name
                    if not target_func.isidentifier():
                        skipped += 1
                        continue
                    _rename(
                        cfg=cfg,
                        filepath=fp,
                        old_name=old_name,
                        old_sym=old_sym,
                        target_func=target_func,
                        rename_file=True,
                        dry_run=False,
                    )
                    applied_names += 1
                except Exception:
                    log.debug("rename apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            else:
                applied_names += 1
            continue

        # Both meaningful and different → conflict
        conflicts.append(
            {
                "va": f"0x{va:08x}",
                "local": local_name,
                "binsync": bs_name,
                "filepath": str(local_filepath),
            }
        )
        if accept_binsync:
            if dry_run:
                proposed.append(
                    {
                        "va": f"0x{va:08x}",
                        "field": "name",
                        "local": local_name,
                        "binsync": bs_name,
                        "action": "conflict (accept-binsync)",
                    }
                )
            else:
                try:
                    from rebrew.rename import rename_function_everywhere as _rename2

                    fp = Path(cfg.reversed_dir) / local_filepath if local_filepath else None
                    if fp is None or not fp.exists():
                        skipped += 1
                        continue
                    old_name = getattr(local, "name", "") or ""
                    old_sym = getattr(local, "symbol", "") or old_name
                    target_func = bs_stripped
                    if not target_func.isidentifier():
                        skipped += 1
                        continue
                    _rename2(
                        cfg=cfg,
                        filepath=fp,
                        old_name=old_name,
                        old_sym=old_sym,
                        target_func=target_func,
                        rename_file=True,
                        dry_run=False,
                    )
                    applied_names += 1
                except Exception:
                    log.debug("rename apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            continue
        if accept_local:
            if not dry_run:
                try:
                    from rebrew.annotation import update_annotation_key as _uak2

                    fp = Path(cfg.reversed_dir) / local_filepath if local_filepath else None
                    if fp is not None and fp.exists():
                        _uak2(fp, va, "GHIDRA", bs_name, metadata_dir=cfg.metadata_dir)
                except Exception:
                    log.debug("GHIDRA annotation apply failed for VA 0x%x", va, exc_info=True)
                    pass
            proposed.append(
                {
                    "va": f"0x{va:08x}",
                    "field": "GHIDRA",
                    "local": local_name,
                    "binsync": bs_name,
                    "action": "keep local (accept-local)",
                }
            )
            continue
        # No resolution flag → report conflict, no write
        if not json_output and not dry_run:
            console.print(f"  CONFLICT 0x{va:08x}: local={local_name!r} vs binsync={bs_name!r}")

    # --- Global names ---
    for va, bs_entry in sorted(globals_by_va.items()):
        bs_name = bs_entry.get("name", "")
        if not bs_name or not _is_meaningful(bs_name):
            continue
        if va in funcs_by_va:
            continue  # already handled as function
        local = local_by_va.get(va)
        if local is not None and module is not None and getattr(local, "module", "") != module:
            skipped += 1
            continue
        # For DATA/GLOBAL, update rebrew-data.toml
        if local is not None:
            local_name = getattr(local, "name", "") or getattr(local, "symbol", "") or ""
            if local_name == bs_name:
                continue
            if dry_run:
                proposed.append(
                    {
                        "va": f"0x{va:08x}",
                        "field": "global_name",
                        "local": local_name,
                        "binsync": bs_name,
                    }
                )
            if not dry_run:
                try:
                    from rebrew.data_metadata import set_data_field as _sdf

                    mod = getattr(local, "module", "") or "SERVER"
                    _sdf(cfg.metadata_dir, va, "name", bs_name, mod)
                    applied_globals += 1
                except Exception:
                    log.debug("global name apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            else:
                applied_globals += 1
        else:
            # No local DATA entry at this VA — still create a data metadata entry
            # so the global can be surfaced (module unknown → use marker or SERVER)
            if dry_run:
                proposed.append(
                    {"va": f"0x{va:08x}", "field": "global_name", "local": "", "binsync": bs_name}
                )
            if not dry_run:
                try:
                    from rebrew.data_metadata import set_data_field as _sdf2

                    mod = module or getattr(cfg, "marker", "") or "SERVER"
                    _sdf2(cfg.metadata_dir, va, "name", bs_name, mod)
                    applied_globals += 1
                except Exception:
                    log.debug("global name apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            else:
                applied_globals += 1

    # --- Output ---
    if json_output:
        result: dict[str, object] = {
            "state_dir": str(state_dir),
            "dry_run": dry_run,
            "applied_names": applied_names,
            "applied_prototypes": applied_protos,
            "applied_globals": applied_globals,
            "conflicts": len(conflicts),
            "skipped": skipped,
        }
        if proposed:
            result["proposed"] = proposed
        if conflicts:
            result["conflict_details"] = conflicts
        if module is not None:
            result["module"] = module
        json_print(result)
        if conflicts and not accept_binsync and not accept_local:
            raise typer.Exit(code=1)
        return

    if dry_run:
        if proposed or conflicts:
            console.print(
                f"[dim]Would apply {len(proposed)} change(s), {len(conflicts)} conflict(s)[/dim]"
            )
            for p in proposed[:20]:
                console.print(
                    f"  would update {p.get('va')} {p.get('field')}: {p.get('local')!r} -> {p.get('binsync')!r}"
                )
            if len(proposed) > 20:
                console.print(f"  ... and {len(proposed) - 20} more")
            for c in conflicts[:10]:
                console.print(f"  CONFLICT {c['va']}: {c['local']!r} vs {c['binsync']!r}")
        else:
            console.print("[green]No changes to import (already in sync or all generic).[/green]")
        if conflicts and not accept_binsync and not accept_local:
            raise typer.Exit(code=1)
        return

    # Non-dry-run, non-json summary
    if applied_names or applied_protos or applied_globals:
        console.print(
            f"[green]Imported[/green] {applied_names} name(s), {applied_protos} prototype(s), "
            f"{applied_globals} global(s) from [cyan]{state_dir}[/cyan]"
        )
    if conflicts:
        if accept_binsync or accept_local:
            mode = "accept-binsync" if accept_binsync else "accept-local"
            console.print(f"[dim]{len(conflicts)} conflict(s) resolved via --{mode}[/dim]")
        else:
            console.print(
                f"[yellow]{len(conflicts)} conflict(s)[/yellow] — re-run with "
                "[cyan]--accept-binsync[/cyan] or [cyan]--accept-local[/cyan] to resolve"
            )
            raise typer.Exit(code=1)
    if not applied_names and not applied_protos and not applied_globals and not conflicts:
        console.print("[green]Already in sync — nothing to import.[/green]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
