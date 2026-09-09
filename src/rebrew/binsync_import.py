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
from typing import Any

import typer
from rich.console import Console

from rebrew.binsync_state import (
    index_local_and_catalog,
    load_binsync_state,
    load_binsync_structs,
)
from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.config import ProjectConfig
from rebrew.naming import avoid_windows_reserved
from rebrew.utils import strip_body

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


def _global_type_size_drift(local: Any, bs_entry: dict[str, str]) -> bool:
    """True when BinSync's global type/size differs from the local entry."""
    bs_type = (bs_entry.get("type") or "").strip()
    if bs_type and bs_type != str(getattr(local, "type", "") or "").strip():
        return True
    bs_size = (bs_entry.get("size") or "").strip()
    if bs_size:
        try:
            if int(bs_size, 0) != int(getattr(local, "size", 0) or 0):
                return True
        except (TypeError, ValueError):
            pass
    return False


def _apply_global_type_size(
    metadata_dir: Path, va: int, module: str, local: Any, bs_entry: dict[str, str]
) -> None:
    """Write BinSync global type/size into rebrew-data.toml when they differ."""
    from rebrew.data_metadata import set_data_field

    bs_type = (bs_entry.get("type") or "").strip()
    if bs_type and bs_type != str(getattr(local, "type", "") or "").strip():
        set_data_field(metadata_dir, va, "type", bs_type, module)
    bs_size = (bs_entry.get("size") or "").strip()
    if bs_size:
        try:
            if int(bs_size, 0) != int(getattr(local, "size", 0) or 0):
                set_data_field(metadata_dir, va, "size", int(bs_size, 0), module)
        except (TypeError, ValueError):
            pass


def _strip_cdecl_prefix(name: str) -> str:
    return name[1:] if name.startswith("_") else name


def _normalize_prototype(proto: str) -> str:
    """Canonicalize a prototype for comparison: collapse whitespace, drop trailing semicolon."""
    text = " ".join(proto.strip().split())
    if text.endswith(";"):
        text = text[:-1].strip()
    return re.sub(r"\s*([(),;*])\s*", r"\1", text)


def _apply_binsync_func_name(
    cfg: Any, local: Any, bs_name: str, local_filepath: str | None
) -> bool:
    """Rename the local function *local* to the BinSync name, everywhere.

    Returns False (nothing written) when the source file is missing or the
    BinSync name is not a valid identifier.
    """
    from rebrew.rename_ops import rename_function_everywhere

    if not local_filepath:
        return False
    fp = Path(cfg.reversed_dir) / local_filepath
    try:
        if not fp.resolve().is_relative_to(Path(cfg.reversed_dir).resolve()):
            return False
    except (OSError, ValueError):
        return False
    if not fp.exists():
        return False
    old_name = getattr(local, "name", "") or ""
    old_sym = getattr(local, "symbol", "") or old_name
    if not bs_name.isidentifier():
        return False
    rename_function_everywhere(
        cfg=cfg,
        filepath=fp,
        old_name=old_name,
        old_sym=old_sym,
        target_func=bs_name,
        rename_file=True,
        dry_run=False,
    )
    return True


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

    try:
        resolved = state_dir.resolve()
    except OSError as exc:
        error_exit(f"Cannot resolve state directory {state_dir}: {exc}", json_mode=json_output)
    if not resolved.exists():
        error_exit(f"State directory not found: {state_dir}", json_mode=json_output)
    if not resolved.is_dir():
        error_exit(f"Not a directory: {state_dir}", json_mode=json_output)
    state_dir = resolved

    cfg = require_config(target=target, json_mode=json_output)

    result = import_state(
        cfg,
        state_dir,
        dry_run=dry_run,
        json_output=json_output,
        module=module,
        accept_binsync=accept_binsync,
        accept_local=accept_local,
        create_missing=create_missing,
    )

    # --- Output ---
    _print_import_result(result, json_output=json_output, dry_run=dry_run)
    return


def import_state(
    cfg: ProjectConfig,
    state_dir: Path,
    *,
    dry_run: bool,
    json_output: bool,
    module: str | None = None,
    accept_binsync: bool = False,
    accept_local: bool = False,
    create_missing: bool = False,
) -> dict[str, object]:
    """Import a BinSync state directory into rebrew metadata (programmatic).

    Returns the result dict (counts plus ``touched_vas`` — the VAs the import
    applied names/prototypes/globals to or created stubs for, so callers like
    ``rebrew sync --pull --create-functions`` can push them to Ghidra).
    """
    funcs_by_va, globals_by_va = load_binsync_state(state_dir)
    structs_by_name = load_binsync_structs(state_dir)

    if not funcs_by_va and not globals_by_va and not structs_by_name:
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
    applied_structs = 0
    applied_notes = 0
    skipped = 0
    touched_vas: list[int] = []

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
                        # Filename guard: ``aux`` is a legal C identifier but a
                        # reserved device basename on Windows (see naming.py).
                        out_path = cfg.reversed_dir / f"{avoid_windows_reserved(target_func)}.c"
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
                        # keys and go to rebrew-functions.toml (inline forms are
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
                        touched_vas.append(va)
                    except Exception:
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
        local_proto = strip_body(raw_proto) if raw_proto else ""
        local_filepath = getattr(local, "filepath", "")

        # Resolve BinSync name to a local symbol form (strip cdecl prefix for comparison)
        # BinSync names are typically "_foo" (cdecl) — local symbol is also "_foo"
        bs_stripped = _strip_cdecl_prefix(bs_name) if bs_name.startswith("_") else bs_name
        local_stripped = (
            _strip_cdecl_prefix(local_name) if local_name.startswith("_") else local_name
        )

        # Prototype import (independent of name; whitespace-normalized compare).
        # A differing local prototype is a conflict like a differing name:
        # --accept-binsync overwrites, --accept-local keeps local, otherwise
        # reported and skipped.  Empty local applies cleanly either way.
        if bs_proto and _normalize_prototype(bs_proto) != _normalize_prototype(local_proto):
            if local_proto and not accept_binsync:
                conflicts.append(
                    {
                        "va": f"0x{va:08x}",
                        "field": "prototype",
                        "local": local_proto,
                        "binsync": bs_proto,
                    }
                )
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
                    console.print(f"  Conflict prototype 0x{va:08x} (use --accept-binsync)")
                skipped += 1
                continue
            if dry_run:
                proposed.append(
                    {
                        "va": f"0x{va:08x}",
                        "field": "prototype",
                        "local": local_proto,
                        "binsync": bs_proto,
                    }
                )
                if not json_output:
                    # Was an `elif` to the dry_run branch — real runs printed
                    # "(dry-run)" while actually writing (sync-review F2).
                    console.print(f"  Would update prototype 0x{va:08x} (dry-run)")
            elif not json_output:
                console.print(f"  Updating prototype 0x{va:08x}")
            if not dry_run:
                try:
                    from rebrew.annotation import update_annotation_key as _uak

                    if not local_filepath:
                        skipped += 1
                    else:
                        fp = Path(cfg.reversed_dir) / local_filepath
                        try:
                            inside = fp.resolve().is_relative_to(Path(cfg.reversed_dir).resolve())
                        except (OSError, ValueError):
                            inside = False
                        if not inside or not fp.exists():
                            skipped += 1
                        else:
                            _uak(fp, va, "PROTOTYPE", bs_proto, metadata_dir=cfg.metadata_dir)
                            applied_protos += 1
                            touched_vas.append(va)
                except Exception:
                    log.debug("prototype apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            elif dry_run:
                applied_protos += 1

        # Note import from [comments] (independent of name/prototype)
        bs_note = bs_entry.get("note", "")
        if bs_note:
            from rebrew.metadata import get_entry

            local_mod = getattr(local, "module", "") or "SERVER"
            local_note = str(get_entry(cfg.metadata_dir, va, local_mod).get("note") or "")
            if local_note.strip() != bs_note.strip():
                if dry_run:
                    proposed.append(
                        {
                            "va": f"0x{va:08x}",
                            "field": "note",
                            "local": local_note,
                            "binsync": bs_note,
                        }
                    )
                    applied_notes += 1
                else:
                    try:
                        from rebrew.metadata import update_field

                        update_field(cfg.metadata_dir, va, "note", bs_note, local_mod)
                        applied_notes += 1
                        touched_vas.append(va)
                    except Exception:
                        log.debug("note apply failed for VA 0x%x", va, exc_info=True)
                        skipped += 1

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
                applied_names += 1
            else:
                try:
                    if _apply_binsync_func_name(cfg, local, bs_stripped, local_filepath):
                        applied_names += 1
                        touched_vas.append(va)
                    else:
                        skipped += 1
                except Exception:
                    log.debug("rename apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
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
                    if _apply_binsync_func_name(cfg, local, bs_stripped, local_filepath):
                        applied_names += 1
                        touched_vas.append(va)
                    else:
                        skipped += 1
                except Exception:
                    log.debug("rename apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            continue
        if accept_local:
            if not dry_run:
                try:
                    from rebrew.annotation import update_annotation_key as _uak2

                    if local_filepath:
                        fp = Path(cfg.reversed_dir) / local_filepath
                        try:
                            inside = fp.resolve().is_relative_to(Path(cfg.reversed_dir).resolve())
                        except (OSError, ValueError):
                            inside = False
                        if inside and fp.exists():
                            _uak2(fp, va, "GHIDRA", bs_name, metadata_dir=cfg.metadata_dir)
                except Exception:
                    log.debug("GHIDRA annotation apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
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
            if local_name.strip() == bs_name.strip() and not _global_type_size_drift(
                local, bs_entry
            ):
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
                    _apply_global_type_size(cfg.metadata_dir, va, mod, local, bs_entry)
                    applied_globals += 1
                    touched_vas.append(va)
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
                    touched_vas.append(va)
                except Exception:
                    log.debug("global name apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            else:
                applied_globals += 1

    # --- Structs: write unknown BinSync definitions into a local header ---
    if structs_by_name:
        applied_structs = _import_structs(cfg, structs_by_name, dry_run=dry_run, proposed=proposed)

    return {
        "state_dir": str(state_dir),
        "dry_run": dry_run,
        "applied_names": applied_names,
        "applied_prototypes": applied_protos,
        "applied_globals": applied_globals,
        "applied_structs": applied_structs,
        "applied_notes": applied_notes,
        "conflicts": len(conflicts),
        "skipped": skipped,
        "touched_vas": sorted(set(touched_vas)),
        "proposed": proposed,
        "conflict_details": conflicts,
        "module": module,
        "accept_binsync": accept_binsync,
        "accept_local": accept_local,
    }


def _import_structs(
    cfg: ProjectConfig,
    structs_by_name: dict[str, dict[str, object]],
    *,
    dry_run: bool,
    proposed: list[dict[str, str]],
) -> int:
    """Write unknown BinSync struct definitions into ``binsync_types.h``.

    Only structs with no local definition (by name, across headers and
    sources) are written; known names are skipped, never overwritten.
    Returns the applied count (dry-run counts without writing).
    """
    from rebrew.struct_parser import extract_structs_from_file

    local_names: set[str] = set()
    reversed_dir = Path(cfg.reversed_dir)
    try:
        header_files = list(reversed_dir.rglob("*.h"))
    except OSError:
        header_files = []
    try:
        from rebrew.sources import iter_sources

        source_files = list(iter_sources(reversed_dir, cfg))
    except OSError:
        source_files = []
    for path in header_files + source_files:
        try:
            from rebrew.types import parse_structs

            for typedef_text in extract_structs_from_file(path):
                for found in parse_structs(typedef_text):
                    local_names.add(found)
        except OSError:
            continue
    new = {name: entry for name, entry in structs_by_name.items() if name not in local_names}
    if not new:
        return 0
    if dry_run:
        for name in sorted(new):
            proposed.append(
                {"struct": name, "field": "struct_definition", "local": "", "binsync": name}
            )
        return len(new)
    header = reversed_dir / "binsync_types.h"
    try:
        existing = header.read_text(encoding="utf-8") if header.exists() else ""
    except OSError:
        existing = ""
    blocks = [existing] if existing and not existing.endswith("\n\n") else [existing]
    if not blocks[0]:
        blocks = [
            "/* binsync_types.h - struct definitions imported from BinSync.\n * Regenerate/extend via: rebrew binsync-import\n */\n\n"
        ]
    for name in sorted(new):
        definition = str(new[name].get("definition") or "").strip()
        if not definition:
            fields = new[name].get("fields")
            if isinstance(fields, dict) and fields:
                lines = [
                    f"\t{str(f.get('type', 'int'))} {fname};"
                    for fname, f in fields.items()
                    if isinstance(f, dict)
                ]
                definition = f"typedef struct {name}_s {{\n" + "\n".join(lines) + f"\n}} {name};"
        if not definition:
            continue
        if name not in existing:
            blocks.append(definition + "\n\n")
    from rebrew.utils import atomic_write_text

    atomic_write_text(header, "".join(blocks), encoding="utf-8")
    return len(new)


def _print_import_result(result: dict[str, object], *, json_output: bool, dry_run: bool) -> None:
    """Render an :func:`import_state` result (the CLI summary/exit path)."""
    from typing import cast

    state_dir = str(result["state_dir"])
    applied_names = int(cast(int, result["applied_names"]))
    applied_protos = int(cast(int, result["applied_prototypes"]))
    applied_globals = int(cast(int, result["applied_globals"]))
    applied_structs = int(cast(int, result.get("applied_structs", 0)))
    applied_notes = int(cast(int, result.get("applied_notes", 0)))
    conflicts = int(cast(int, result["conflicts"]))
    proposed = list(cast(list[Any], result.get("proposed") or []))
    conflict_details = list(cast(list[Any], result.get("conflict_details") or []))
    module = result.get("module")
    accept_binsync = bool(result.get("accept_binsync"))
    accept_local = bool(result.get("accept_local"))
    if json_output:
        payload: dict[str, object] = {
            "state_dir": state_dir,
            "dry_run": dry_run,
            "applied_names": applied_names,
            "applied_prototypes": applied_protos,
            "applied_globals": applied_globals,
            "applied_structs": applied_structs,
            "applied_notes": applied_notes,
            "conflicts": conflicts,
            "skipped": int(cast(int, result.get("skipped", 0))),
        }
        if proposed:
            payload["proposed"] = proposed
        if conflict_details:
            payload["conflict_details"] = conflict_details
        if module is not None:
            payload["module"] = module
        json_print(payload)
        if conflicts and not accept_binsync and not accept_local:
            raise typer.Exit(code=1)
        return

    if dry_run:
        if proposed or conflict_details:
            console.print(
                f"[dim]Would apply {len(proposed)} change(s), {len(conflict_details)} conflict(s)[/dim]"
            )
            for p in proposed[:20]:
                console.print(
                    f"  would update {p.get('va')} {p.get('field')}: {p.get('local')!r} -> {p.get('binsync')!r}"
                )
            if len(proposed) > 20:
                console.print(f"  ... and {len(proposed) - 20} more")
            for c in conflict_details[:10]:
                console.print(f"  CONFLICT {c['va']}: {c['local']!r} vs {c['binsync']!r}")
        else:
            console.print("[green]No changes to import (already in sync or all generic).[/green]")
        if conflicts and not accept_binsync and not accept_local:
            raise typer.Exit(code=1)
        return

    # Non-dry-run, non-json summary
    if applied_names or applied_protos or applied_globals or applied_structs:
        console.print(
            f"[green]Imported[/green] {applied_names} name(s), {applied_protos} prototype(s), "
            f"{applied_globals} global(s), {applied_structs} struct(s) "
            f"from [cyan]{state_dir}[/cyan]"
        )
    if conflicts:
        if accept_binsync or accept_local:
            mode = "accept-binsync" if accept_binsync else "accept-local"
            console.print(f"[dim]{conflicts} conflict(s) resolved via --{mode}[/dim]")
        else:
            console.print(
                f"[yellow]{conflicts} conflict(s)[/yellow] — re-run with "
                "[cyan]--accept-binsync[/cyan] or [cyan]--accept-local[/cyan] to resolve"
            )
            raise typer.Exit(code=1)
    if (
        not applied_names
        and not applied_protos
        and not applied_globals
        and not applied_structs
        and not conflicts
    ):
        console.print("[green]Already in sync — nothing to import.[/green]")


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
