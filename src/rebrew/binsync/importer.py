"""importer.py — Import a BinSync state directory into rebrew metadata.

Reads a BinSync state directory (as produced by ``rebrew binsync export`` or
any BinSync-aware decompiler) and offers to apply function renames,
prototype updates, and global names back into the rebrew project.

This is the inverse of :mod:`rebrew.binsync.export`; both read and write the
BinSync state through :mod:`rebrew.binsync.serial` (declib, the ``binsync``
extra).  Conflict handling mirrors :mod:`rebrew.ghidra.commands`
(``--accept-binsync`` / ``--accept-local``).

Typical flow::

    rebrew binsync export ./state          # team member renames in IDA
    rebrew binsync import ./state --dry-run
    rebrew binsync import ./state --accept-binsync

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

from rebrew.binsync.state import (
    acknowledge_sync,
    index_local_and_catalog,
    load_binsync_comments,
    load_binsync_enums,
    load_binsync_state,
    load_binsync_structs,
    load_binsync_typedefs,
    load_sync_baseline,
    local_sync_records,
    module_predicate,
    normalize_prototype,
    prepare_sync_import,
    record_sync_origins,
    remote_sync_records,
    result_count,
    result_paths,
    result_rows,
    sync_action,
    sync_health,
    sync_health_messages,
    sync_origin,
    sync_value_hash,
)
from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
    run_standalone,
)
from rebrew.config import ProjectConfig, module_marker
from rebrew.naming import avoid_windows_reserved
from rebrew.utils import (
    c_comment_safe,
    fold_ident,
    is_safe_c_ident,
    preset_module_key,
    strip_body,
)

log = logging.getLogger(__name__)

#: BinSync state is written by collaborators.  A prototype is one declarator
#: line, so a body, statement end, comment, preprocessor, or control character
#: in it is refused before it is spliced into a ``.c`` file or PROTOTYPE.
_UNSAFE_PROTOTYPE_RE = re.compile(r"[{};#\x00-\x08\x0a-\x1f\x7f]|/\*|\*/|//")

#: A block comment, replaced by a space before the preprocessor-line test.
_C_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

#: A field ``type`` value a synthesized struct member may carry.  BinSync
#: state is collaborator-written, and the value is interpolated straight
#: into the header body, so a member declared ``int; int evil(`` would
#: otherwise compile as the next build's code.
_C_TYPE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_ ]*\*?\Z")

app = typer.Typer(
    help="Import a BinSync state directory into rebrew metadata.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync import ./state --dry-run · · · Preview without writing\n\n"
        "  rebrew binsync import ./state --accept-binsync · Accept BinSync names\n\n"
        "  rebrew binsync import ./state --accept-local · · Keep local, record provenance\n\n"
        "  rebrew binsync import ./state --module SERVER · Only import one module\n\n"
        "[dim]Reads functions/*.toml, global_vars.toml, and structs/*.toml from a BinSync\n"
        "state directory and applies names/prototypes/globals back to rebrew metadata.[/dim]"
    ),
)


# Generic auto-names that should not overwrite a meaningful rename.
_GENERIC_NAME_RE = re.compile(r"^_?(func_|FUN_)[0-9a-fA-F]+(@\d+)?$")
_GHIDRA_GENERIC_RE = re.compile(r"^(FUN_|DAT_|switchdata|thunk_)")
# Our own synthetic placeholder for DATA/GLOBAL entries with missing declarations
_PLACEHOLDER_GLOBAL_RE = re.compile(r"^g_[0-9a-fA-F]{4,8}$")


def resolve_state_dir(state_dir: Path, *, json_mode: bool) -> Path:
    """Resolve *state_dir*; abort when it is not an existing directory."""
    try:
        resolved = state_dir.resolve()
    except OSError as exc:
        error_exit(f"Cannot resolve state directory {state_dir}: {exc}", json_mode=json_mode)
    if not resolved.exists():
        error_exit(f"State directory not found: {state_dir}", json_mode=json_mode)
    if not resolved.is_dir():
        error_exit(f"Not a directory: {state_dir}", json_mode=json_mode)
    return resolved


def is_meaningful(name: str) -> bool:
    """Return True when *name* looks user-assigned rather than an auto-label.

    Shared by import, diff, and overlay so placeholder names
    (``func_``/``FUN_``/``DAT_``/``g_<hex>``) are treated consistently.
    """
    return bool(name) and not (
        _GENERIC_NAME_RE.match(name)
        or _GHIDRA_GENERIC_RE.match(name)
        or _PLACEHOLDER_GLOBAL_RE.match(name)
    )


def _global_field_updates(local: Any, bs_entry: dict[str, str]) -> list[tuple[str, str | int]]:
    """Return ``(field, value)`` pairs where BinSync differs from *local*.

    Shared by the drift probe and the writer so a new field cannot be checked
    on one side and missed on the other.
    """
    updates: list[tuple[str, str | int]] = []
    bs_type = (bs_entry.get("type") or "").strip()
    if bs_type and bs_type != str(getattr(local, "type", "") or "").strip():
        updates.append(("type", bs_type))
    bs_size = (bs_entry.get("size") or "").strip()
    if bs_size:
        try:
            size_val = int(bs_size, 0)
        except ValueError:
            # bs_size comes from the remote state, which is untrusted.  An
            # unparsable value is not "no drift": reporting none would let the
            # global be counted as synced while its SIZE stays stale, and every
            # later byte comparison measures against the wrong length.
            logging.getLogger(__name__).warning(
                "ignoring unparsable BinSync size %r: expected an integer (0x/0o/0b prefixed "
                "or decimal)",
                bs_size,
            )
        else:
            local_size = getattr(local, "size", 0) or 0
            try:
                local_val = int(local_size)
            except (TypeError, ValueError):
                local_val = -1
            if size_val != local_val:
                updates.append(("size", size_val))
    bs_section = (bs_entry.get("section") or "").strip()
    if bs_section and bs_section != str(getattr(local, "section", "") or "").strip():
        updates.append(("section", bs_section))
    return updates


def _apply_global_type_size(
    metadata_dir: Path,
    va: int,
    module: str,
    local: Any,
    bs_entry: dict[str, str],
    *,
    origin: dict[str, str] | None = None,
) -> None:
    """Write BinSync global type/size/section into rebrew-data.toml when they differ."""
    from rebrew.data_metadata import set_data_fields_batch

    fields: dict[str, Any] = dict(_global_field_updates(local, bs_entry))
    fields["name"] = bs_entry["name"]
    if origin:
        from rebrew.data_metadata import get_data_entry

        entry = get_data_entry(metadata_dir, va, module)
        origins = dict(entry.get("origins") or {})
        for field, value in fields.items():
            if entry.get(field) != value:
                origins[field] = {
                    **origin,
                    "value_hash": sync_value_hash(field, value, kind="global"),
                }
        fields["origins"] = origins
    set_data_fields_batch(
        metadata_dir,
        [{"module": module, "va": va, "fields": fields, "updated_by": "binsync-import"}],
    )


def strip_cdecl_prefix(name: str) -> str:
    """Drop the MSVC ``_`` decoration BinSync records (``_Foo`` -> ``Foo``)."""
    return name[1:] if name.startswith("_") else name


def _inside_project(fp: Path, cfg: Any) -> bool:
    """True when *fp* is a project source (reversed dir or shared tree).

    Pull writes renames/prototypes/markers into source files; the old
    reversed-only containment silently skipped every shared file
    (``../shared/f.c`` resolves outside ``reversed_dir``).
    """
    try:
        resolved = fp.resolve()
    except (OSError, ValueError):
        return False
    for root in (getattr(cfg, "reversed_dir", None), getattr(cfg, "shared_dir", None)):
        if root is None:
            continue
        try:
            if resolved.is_relative_to(Path(root).resolve()):
                return True
        except (OSError, ValueError):
            continue
    return False


def is_safe_prototype(proto: str) -> bool:
    """Whether a BinSync *proto* (trailing ``;`` allowed) is a bare declarator.

    ASCII only: a declarator naming a non-ASCII identifier (``int café(void)``)
    is refused for the same reason a body is, because it reaches a ``.c`` file
    that the next build compiles.
    """
    text = proto.strip()
    if text.endswith(";"):
        text = text[:-1]
    if not text.isascii():
        return False
    return not _UNSAFE_PROTOTYPE_RE.search(text)


def normalize_stack_vars(stack_vars: Any) -> dict[str, dict[str, Any]]:
    """Normalize a BinSync ``stack_vars`` mapping to ``{offset: {name, type, size}}``.

    Shared by the import and overlay paths — frame offsets are
    address-independent, so both apply the source's variables unchanged.
    """
    if not isinstance(stack_vars, dict) or not stack_vars:
        return {}
    return {
        str(offset): {
            "name": str(value.get("name") or ""),
            "type": str(value.get("type") or ""),
            "size": int(value.get("size") or 0),
        }
        for offset, value in stack_vars.items()
        if isinstance(value, dict)
    }


def apply_binsync_func_name(cfg: Any, local: Any, bs_name: str, local_filepath: str | None) -> bool:
    """Rename the local function *local* to the BinSync name, everywhere.

    Returns False (nothing written) when the source file is missing or the
    BinSync name is not a valid identifier, and also when the rename landed
    on the definition but left a call site behind: reporting True there would
    tell the drift report the name is in sync while the tree no longer builds.
    """
    from rebrew.rename_ops import RenameError, rename_function_everywhere

    if not local_filepath:
        return False
    fp = Path(cfg.reversed_dir) / local_filepath
    if not _inside_project(fp, cfg):
        return False
    if not fp.exists():
        return False
    old_name = getattr(local, "name", "") or ""
    old_sym = getattr(local, "symbol", "") or old_name
    if not is_safe_c_ident(bs_name):
        return False
    try:
        rename_function_everywhere(
            cfg=cfg,
            filepath=fp,
            old_name=old_name,
            old_sym=old_sym,
            target_func=bs_name,
            rename_file=True,
            dry_run=False,
        )
    except RenameError:
        log.exception("binsync rename of %s left stale call sites", local_filepath)
        return False
    return True


def apply_binsync_prototype(cfg: Any, local: Any, prototype: str, filepath: str) -> bool:
    """Apply a received prototype to the C definition, the canonical signature source."""
    from rebrew.c_parser import replace_function_prototype
    from rebrew.utils import atomic_write_text, read_source_text

    path = Path(cfg.reversed_dir) / filepath
    if not _inside_project(path, cfg) or not is_safe_prototype(prototype):
        return False
    text, encoding = read_source_text(path)
    name = str(getattr(local, "name", "") or strip_cdecl_prefix(getattr(local, "symbol", "")))
    updated = replace_function_prototype(text, name, prototype)
    if updated == text:
        return False
    atomic_write_text(path, updated, encoding=encoding)
    return True


def _entry_module(cfg: Any, local: Any = None) -> str:
    """Module for a metadata write.

    The local entry's module wins. Otherwise the project marker
    (:func:`rebrew.config.module_marker`). A hardcoded ``SERVER`` would
    store the row under another project's module when this one has none.
    Empty means the caller must skip the write.
    """
    named = ""
    if local is not None:
        named = str(getattr(local, "module", "") or "").strip()
    if named:
        return named
    return module_marker(cfg)


def _stub_text(cfg: Any, va: int, bs_name: str, bs_proto: str) -> tuple[Path, str, str]:
    """``(path, source, module)`` of the stub ``--create-missing`` would write."""
    bs_stripped = strip_cdecl_prefix(bs_name)
    target_func = bs_stripped if is_safe_c_ident(bs_stripped) else f"func_{va:08x}"
    mod = module_marker(cfg)
    if not mod:
        raise ValueError(
            "cannot create a stub without a module marker "
            "(set [targets.<name>].marker, or use a target name with identifier characters)"
        )
    proto = (bs_proto or "").strip()
    if proto.endswith(";"):
        proto = proto[:-1].strip()
    body = proto if proto else f"void {target_func}(void)"
    text = f"{body} {{}}\n"
    path = Path(cfg.reversed_dir) / f"{avoid_windows_reserved(target_func)}.c"
    return path, text, mod


def _inventory_size(cfg: Any, va: int) -> int:
    """Catalog size for *va*, or 0 when the inventory has none."""
    from rebrew.catalog import cached_function_list

    for func in cached_function_list(cfg):
        try:
            if int(func.get("va", -1)) == va:
                return int(func.get("size") or 0)
        except (TypeError, ValueError):
            continue
    return 0


def _queue_stub_identity(
    rows: list[dict[str, Any]],
    *,
    cfg: Any,
    path: Path,
    module: str,
    va: int,
    name: str,
    proto: str,
) -> None:
    """Queue the identity row for a stub file. STATUS is queued separately."""
    from rebrew.annotation import derive_c_symbol
    from rebrew.metadata import identity_file

    rows.append(
        {
            "module": module,
            "va": va,
            "identity": {
                "file": identity_file(path, cfg.metadata_dir),
                "symbol": derive_c_symbol(name, proto),
                "name": name,
                "marker_type": "FUNCTION",
            },
            "fields": {},
        }
    )


def _queue_stub_metadata(
    statuses: list[dict[str, Any]],
    field_updates: list[dict[str, Any]],
    *,
    module: str,
    va: int,
    bs_name: str,
    size_hint: int,
) -> None:
    """Record the STATUS/SIZE/NOTE a created stub still needs."""
    statuses.append(
        {
            "module": module,
            "va": va,
            "new_status": "STUB",
            "updated_by": "binsync-import",
        }
    )
    fields: dict[str, Any] = {"note": f"imported from BinSync as {bs_name}"}
    if size_hint:
        fields["size"] = size_hint
    field_updates.append({"module": module, "va": va, "fields": fields})


def _try_apply_binsync_name(
    cfg: Any, local: Any, bs_name: str, local_filepath: str | None, va: int
) -> bool:
    """Apply a BinSync rename. False when nothing was written."""
    try:
        return apply_binsync_func_name(cfg, local, bs_name, local_filepath)
    except Exception:
        log.warning("rename apply failed for VA 0x%x", va, exc_info=True)
        return False


@app.callback(invoke_without_command=True)
def main(
    state_dir: Path = typer.Argument(..., help="BinSync state directory to import"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
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
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Import a BinSync state directory into rebrew metadata."""
    if accept_binsync and accept_local:
        error_exit(
            "--accept-binsync and --accept-local are mutually exclusive", json_mode=json_output
        )

    state_dir = resolve_state_dir(state_dir, json_mode=json_output)

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

    print_import_result(result, json_output=json_output, dry_run=dry_run)


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
    ``rebrew sync pull --create-functions`` can push them to Ghidra).
    """
    wanted_module = preset_module_key(module) if module else None
    module_selected = module_predicate(wanted_module)

    funcs_by_va, globals_by_va = load_binsync_state(state_dir)
    structs_by_name = load_binsync_structs(state_dir)
    enums_by_name = load_binsync_enums(state_dir)
    typedefs_by_name = load_binsync_typedefs(state_dir)
    comments_by_addr = load_binsync_comments(state_dir)

    if (
        not funcs_by_va
        and not globals_by_va
        and not structs_by_name
        and not enums_by_name
        and not typedefs_by_name
        and not comments_by_addr
    ):
        error_exit(f"No BinSync data found in {state_dir}", json_mode=json_output)

    local_by_va, catalog_sizes = index_local_and_catalog(cfg)
    before_sync = local_sync_records(cfg, list(local_by_va.values()))
    incoming_sync = remote_sync_records(cfg, state_dir, funcs_by_va, globals_by_va, before_sync)
    health = sync_health(cfg, state_dir, before_sync, incoming_sync)
    funcs_by_va, globals_by_va, remote_changes, sync_conflicts = prepare_sync_import(
        cfg,
        state_dir,
        before_sync,
        incoming_sync,
        funcs_by_va,
        globals_by_va,
        accept_binsync=accept_binsync,
        accept_local=accept_local,
    )
    function_fields: dict[tuple[str, int], dict[str, Any]] = {}
    origin = sync_origin(state_dir)

    # Also collect scan for module routing of globals that have no direct annotation
    # (DATA entries are in local_by_va; unannotated externs are not — but those
    # can't be imported meaningfully anyway)

    proposed: list[dict[str, str]] = []  # for dry-run / json
    conflicts: list[dict[str, str]] = list(sync_conflicts)
    applied_names = 0
    applied_protos = 0
    applied_globals = 0
    applied_structs = 0
    applied_enums = 0
    applied_typedefs = 0
    applied_locals = 0
    applied_comments = 0
    applied_notes = 0
    skipped = 0
    touched_vas: list[int] = []
    marker_writes_failed: list[str] = []
    stub_statuses: list[dict[str, Any]] = []
    stub_field_updates: list[dict[str, Any]] = []
    stub_identities: list[dict[str, Any]] = []

    # --- Function names + prototypes ---
    for va, bs_entry in sorted(funcs_by_va.items()):
        bs_name = bs_entry.get("name", "")
        bs_proto = bs_entry.get("prototype", "")
        if bs_proto and not is_safe_prototype(bs_proto):
            log.warning("ignoring unsafe BinSync prototype for VA 0x%x: %r", va, bs_proto)
            bs_proto = ""

        # Module filter: only import entries whose local module matches filter
        local = local_by_va.get(va)
        if local is not None and not module_selected(getattr(local, "module", "")):
            skipped += 1
            continue

        # If no local function at this VA, distinguish catalog-known vs
        # truly unknown.  Catalog-known + BinSync-known can become stubs;
        # unknown is just skipped.
        if local is None:
            if va in catalog_sizes and is_meaningful(bs_name) and bs_name.strip():
                # Surface as proposed_missing; optionally create a stub
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
                        size_hint = catalog_sizes.get(va, 0)
                        out_path, stub, mod = _stub_text(cfg, va, bs_name, bs_proto)
                        if out_path.exists():
                            # Not this VA's annotation (that case is repaired
                            # below, once the scanner has seen the marker).
                            # A different file at the stub's path is the user's.
                            skipped += 1
                            continue
                        from rebrew.utils import atomic_write_text as _awt

                        # Pure C. Identity, STATUS, and NOTE land in
                        # rebrew-functions.toml after the loop. A failed
                        # metadata write leaves the new source for the next
                        # import, which repairs a stub whose STATUS is missing.
                        _awt(out_path, stub, encoding="utf-8")
                        _queue_stub_identity(
                            stub_identities,
                            cfg=cfg,
                            path=out_path,
                            module=mod,
                            va=va,
                            name=out_path.stem,
                            proto=bs_proto or "",
                        )
                        _queue_stub_metadata(
                            stub_statuses,
                            stub_field_updates,
                            module=mod,
                            va=va,
                            bs_name=bs_name,
                            size_hint=size_hint,
                        )
                        applied_names += 1
                        touched_vas.append(va)
                    except Exception:
                        log.warning("stub write failed for VA 0x%x", va, exc_info=True)
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

        # A previous --create-missing wrote this exact stub and died before
        # STATUS.  The marker makes it a local function, so the create path
        # above will not run again; finish the metadata instead of leaving
        # the function unstamped forever.
        if create_missing and not dry_run:
            out_path, stub, mod = _stub_text(cfg, va, bs_name, bs_proto)
            try:
                unfinished = out_path.is_file() and out_path.read_bytes() == stub.encode("utf-8")
            except OSError as exc:
                log.warning("Cannot read stub %s for VA 0x%x: %s", out_path, va, exc)
                unfinished = False
            if unfinished:
                from rebrew.metadata import get_entry

                if not get_entry(cfg.metadata_dir, va, mod).get("status"):
                    size_hint = int(getattr(local, "size", 0) or 0)
                    if size_hint <= 0:
                        size_hint = _inventory_size(cfg, va)
                    _queue_stub_identity(
                        stub_identities,
                        cfg=cfg,
                        path=out_path,
                        module=mod,
                        va=va,
                        name=out_path.stem,
                        proto=bs_proto or "",
                    )
                    _queue_stub_metadata(
                        stub_statuses,
                        stub_field_updates,
                        module=mod,
                        va=va,
                        bs_name=bs_name,
                        size_hint=size_hint,
                    )
                    applied_names += 1
                    touched_vas.append(va)

        local_name = getattr(local, "symbol", "") or getattr(local, "name", "") or ""
        raw_proto = getattr(local, "prototype", "") or ""
        # BinSync [header].type stores signature without body; local prototype may have body
        local_proto = strip_body(raw_proto) if raw_proto else ""
        local_filepath = getattr(local, "filepath", "")

        # Resolve BinSync name to a local symbol form (strip cdecl prefix for comparison)
        # BinSync names are typically "_foo" (cdecl) — local symbol is also "_foo"
        bs_stripped = strip_cdecl_prefix(bs_name)
        local_stripped = strip_cdecl_prefix(local_name)

        # Prototype import (independent of name; whitespace-normalized compare).
        # A differing local prototype is a conflict like a differing name:
        # --accept-binsync overwrites, --accept-local keeps local, otherwise
        # reported and skipped.  Empty local applies cleanly either way.
        if bs_proto and normalize_prototype(bs_proto) != normalize_prototype(local_proto):
            if local_proto and not accept_binsync and (va, "prototype") not in remote_changes:
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
                    # "(dry-run)" while actually writing.
                    console.print(f"  Would update prototype 0x{va:08x} (dry-run)")
            elif not json_output:
                console.print(f"  Updating prototype 0x{va:08x}")
            if not dry_run:
                try:
                    if not local_filepath:
                        skipped += 1
                    else:
                        fp = Path(cfg.reversed_dir) / local_filepath
                        if not _inside_project(fp, cfg) or not fp.exists():
                            skipped += 1
                        else:
                            if not apply_binsync_prototype(cfg, local, bs_proto, local_filepath):
                                skipped += 1
                                continue
                            applied_protos += 1
                            touched_vas.append(va)
                except Exception:
                    log.warning("prototype apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1
            elif dry_run:
                applied_protos += 1

        # Note import from [comments] (independent of name/prototype)
        bs_note = bs_entry.get("note", "")
        if bs_note or ("note" in bs_entry and (va, "note") in remote_changes):
            from rebrew.metadata import get_entry

            local_mod = _entry_module(cfg, local)
            if not local_mod:
                log.warning("skipping note for VA 0x%x: no module marker", va)
                skipped += 1
            else:
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
                            function_fields.setdefault((local_mod, va), {})["note"] = bs_note
                            applied_notes += 1
                            touched_vas.append(va)
                        except Exception:
                            log.warning("note apply failed for VA 0x%x", va, exc_info=True)
                            skipped += 1

        if not bs_name or not is_meaningful(bs_name):
            continue

        # If local already has same meaningful name (ignoring _ prefix), skip.
        # fold_ident as well: the state file is written on one machine and read
        # on another, so the same symbol arrives NFC from Windows and NFD from
        # a macOS volume.  A byte comparison calls that a rename conflict and
        # --accept-binsync rewrites every occurrence to the other spelling.
        if fold_ident(bs_stripped) == fold_ident(local_stripped):
            continue

        # If local is generic and BinSync is meaningful → safe to apply
        if not is_meaningful(local_name) or (va, "name") in remote_changes:
            if dry_run:
                proposed.append(
                    {"va": f"0x{va:08x}", "field": "name", "local": local_name, "binsync": bs_name}
                )
                applied_names += 1
            elif _try_apply_binsync_name(cfg, local, bs_stripped, local_filepath, va):
                applied_names += 1
                touched_vas.append(va)
            else:
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
                applied_names += 1
            elif _try_apply_binsync_name(cfg, local, bs_stripped, local_filepath, va):
                applied_names += 1
                touched_vas.append(va)
            else:
                skipped += 1
            continue
        if accept_local:
            if not dry_run:
                try:
                    if local_filepath:
                        fp = Path(cfg.reversed_dir) / local_filepath
                        if _inside_project(fp, cfg) and fp.exists():
                            from rebrew.metadata import get_entry, set_fields

                            origins = dict(
                                get_entry(cfg.metadata_dir, va, _entry_module(cfg, local)).get(
                                    "origins"
                                )
                                or {}
                            )
                            origins["ghidra"] = {
                                **origin,
                                "value_hash": sync_value_hash("ghidra", bs_name),
                            }
                            set_fields(
                                cfg.metadata_dir,
                                va,
                                {"ghidra": bs_name, "origins": origins},
                                module=_entry_module(cfg, local),
                                updated_by="binsync-import",
                            )
                        else:
                            # Mirrors the prototype branch: a GHIDRA field that
                            # was never written is a skipped row, not a
                            # deliberate "keep local" decision.
                            log.warning(
                                "no local file for VA 0x%x, GHIDRA name not applied (%r)",
                                va,
                                local_filepath,
                            )
                            skipped += 1
                    else:
                        log.warning("VA 0x%x has no local file, GHIDRA name not applied", va)
                        skipped += 1
                except Exception:
                    log.warning("GHIDRA annotation apply failed for VA 0x%x", va, exc_info=True)
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

    if stub_identities or stub_statuses:
        from rebrew.metadata import record_migrated_markers, update_statuses_batch

        if stub_identities:
            record_migrated_markers(cfg.metadata_dir, stub_identities)
        if stub_statuses:
            for update, fields in zip(stub_statuses, stub_field_updates, strict=True):
                update["fields"] = fields["fields"]
            update_statuses_batch(cfg.metadata_dir, stub_statuses)

    # --- Global names ---
    for va, bs_entry in sorted(globals_by_va.items()):
        bs_name = bs_entry.get("name", "")
        if not bs_name or not is_meaningful(bs_name):
            continue
        if va in funcs_by_va:
            continue  # already handled as function
        local = local_by_va.get(va)
        if local is not None and not module_selected(getattr(local, "module", "")):
            skipped += 1
            continue
        # For DATA/GLOBAL, update rebrew-data.toml
        if local is not None:
            local_name = getattr(local, "name", "") or getattr(local, "symbol", "") or ""
            # fold_ident, like the function-name path above: a state written on
            # Windows and a source checked out on macOS spell one DATA symbol
            # two ways, and that is not a rename.
            if fold_ident(local_name.strip()) == fold_ident(bs_name.strip()) and not (
                _global_field_updates(local, bs_entry)
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
                mod = _entry_module(cfg, local)
                if not mod:
                    log.warning("skipping global name for VA 0x%x: no module marker", va)
                    skipped += 1
                else:
                    try:
                        _apply_global_type_size(
                            cfg.metadata_dir, va, mod, local, bs_entry, origin=origin
                        )
                        applied_globals += 1
                        touched_vas.append(va)
                    except Exception:
                        log.warning("global name apply failed for VA 0x%x", va, exc_info=True)
                        skipped += 1
            else:
                applied_globals += 1
        else:
            # No local DATA entry at this VA — still create a data metadata
            # entry under the active module filter or the project marker.
            if dry_run:
                proposed.append(
                    {"va": f"0x{va:08x}", "field": "global_name", "local": "", "binsync": bs_name}
                )
            if not dry_run:
                mod = wanted_module or module_marker(cfg)
                if not mod:
                    log.warning("skipping global name for VA 0x%x: no module marker", va)
                    skipped += 1
                else:
                    try:
                        _apply_global_type_size(
                            cfg.metadata_dir, va, mod, None, bs_entry, origin=origin
                        )
                        applied_globals += 1
                        touched_vas.append(va)
                    except Exception:
                        log.warning("global name apply failed for VA 0x%x", va, exc_info=True)
                        skipped += 1
            else:
                applied_globals += 1

    # Type definitions use the same baseline and conflict decisions as symbols.
    type_updates: dict[str, set[str]] = {"struct": set(), "enum": set(), "typedef": set()}
    baseline = load_sync_baseline(cfg, state_dir)
    for kind, definitions in (
        ("struct", structs_by_name),
        ("enum", enums_by_name),
        ("typedef", typedefs_by_name),
    ):
        for name in list(definitions):
            key = f"{kind}.{name}"
            action = sync_action(
                "definition",
                before_sync.get(key, {}).get("definition"),
                incoming_sync.get(key, {}).get("definition"),
                baseline.get(key, {}),
            )
            if action in {"same", "push"} or (action == "conflict" and accept_local):
                definitions.pop(name)
            elif action == "conflict" and not accept_binsync:
                conflicts.append(
                    {
                        "field": "definition",
                        "type": name,
                        "local": str(before_sync[key]),
                        "binsync": str(incoming_sync[key]),
                    }
                )
                definitions.pop(name)
            elif action == "pull" or (key in before_sync and accept_binsync):
                type_updates[kind].add(name)

    # --- Structs / enums / typedefs: unknown definitions into a local header ---
    if structs_by_name:
        applied_structs = import_type_definitions(
            cfg,
            structs_by_name,
            dry_run=dry_run,
            proposed=proposed,
            update_names=type_updates["struct"],
        )
    if enums_by_name:
        applied_enums = import_type_definitions(
            cfg,
            enums_by_name,
            dry_run=dry_run,
            proposed=proposed,
            update_names=type_updates["enum"],
        )
    if typedefs_by_name:
        applied_typedefs = import_type_definitions(
            cfg,
            typedefs_by_name,
            dry_run=dry_run,
            proposed=proposed,
            update_names=type_updates["typedef"],
        )

    # --- LOCALS / COMMENTS: declib stack vars + per-instruction comments ---

    for va, bs_entry in sorted(funcs_by_va.items()):
        local = local_by_va.get(va)
        if local is None:
            continue
        if not module_selected(getattr(local, "module", "")):
            continue
        local_mod = _entry_module(cfg, local)
        if not local_mod:
            log.warning("skipping locals for VA 0x%x: no module marker", va)
            skipped += 1
            continue

        normalized = normalize_stack_vars(bs_entry.get("stack_vars"))
        if normalized:
            if dry_run:
                proposed.append(
                    {
                        "va": f"0x{va:08x}",
                        "field": "locals",
                        "local": "",
                        "binsync": str(len(normalized)),
                    }
                )
                applied_locals += 1
            else:
                try:
                    function_fields.setdefault((local_mod, va), {})["locals"] = normalized
                    applied_locals += 1
                    touched_vas.append(va)
                except Exception:
                    log.warning("locals apply failed for VA 0x%x", va, exc_info=True)
                    skipped += 1

    # Per-instruction comments: the metadata COMMENTS store is lossless, and a
    # comment inside its owning function's range also gets a source marker.
    for va, entry in funcs_by_va.items():
        original = incoming_sync.get(
            next(
                (
                    k
                    for k in incoming_sync
                    if k.startswith("function.") and k.endswith(f".0x{va:x}")
                ),
                "",
            ),
            {},
        )
        if "comments" in original and "comments" not in entry:
            comments_by_addr = {
                a: c for a, c in comments_by_addr.items() if c.get("func_addr") != va
            }
    comments_by_func, source_markers = _route_comments(comments_by_addr, local_by_va, module)
    for owner_va in sorted(comments_by_func):
        func_comments = comments_by_func[owner_va]
        owner = local_by_va.get(owner_va)
        owner_mod = _entry_module(cfg, owner)
        if not owner_mod:
            log.warning("skipping comments for VA 0x%x: no module marker", owner_va)
            skipped += 1
        elif dry_run:
            proposed.append(
                {
                    "va": f"0x{owner_va:08x}",
                    "field": "comments",
                    "local": "",
                    "binsync": str(len(func_comments)),
                }
            )
            applied_comments += len(func_comments)
        else:
            try:
                function_fields.setdefault((owner_mod, owner_va), {})["comments"] = func_comments
                applied_comments += len(func_comments)
                touched_vas.append(owner_va)
            except Exception:
                log.warning("comments apply failed for VA 0x%x", owner_va, exc_info=True)
                skipped += 1

        markers = source_markers.get(owner_va)
        filepath = getattr(owner, "filepath", "") if owner is not None else ""
        marker_path = Path(cfg.reversed_dir) / filepath if filepath else None
        if markers and marker_path is not None and not dry_run:
            from rebrew.binsync.state import write_analysis_markers

            if not _inside_project(marker_path, cfg):
                # The same containment the rename, prototype, and comment
                # writes get: a filepath that resolves outside the project
                # never names a file to write.
                marker_writes_failed.append(filepath)
                log.warning("ANALYSIS marker write refused, outside project: %s", filepath)
                skipped += 1
            else:
                try:
                    write_analysis_markers(marker_path, markers)
                except OSError:
                    # The comments metadata entry is already written, so a later
                    # re-import treats it as done and never repairs the source
                    # marker.  Report the failure instead of counting the comment
                    # as fully applied.
                    marker_writes_failed.append(filepath)
                    log.warning("ANALYSIS marker write failed for %s", filepath, exc_info=True)

    if not dry_run:
        from rebrew.metadata import set_fields_batch

        set_fields_batch(
            cfg.metadata_dir,
            [
                {"module": mod, "va": va, "fields": fields, "updated_by": "binsync-import"}
                for (mod, va), fields in function_fields.items()
            ],
        )
        after_sync = local_sync_records(cfg)
        if wanted_module is not None:
            after_sync = {
                k: v
                for k, v in after_sync.items()
                if k.split(".", 1)[0] not in {"function", "global"}
                or k.split(".", 1)[1].rsplit(".", 1)[0] == wanted_module
            }
        record_sync_origins(cfg, state_dir, before_sync, after_sync, incoming_sync)
        if marker_writes_failed:
            # A source-marker failure is not an acknowledged comment sync.
            for key in incoming_sync:
                incoming_sync[key].pop("comments", None)
        acknowledge_sync(cfg, state_dir, after_sync, incoming_sync)
        health = sync_health(
            cfg, state_dir, after_sync, remote_sync_records(cfg, state_dir, local=after_sync)
        )

    return {
        "state_dir": str(state_dir),
        "dry_run": dry_run,
        "applied_names": applied_names,
        "applied_prototypes": applied_protos,
        "applied_globals": applied_globals,
        "applied_structs": applied_structs,
        "applied_enums": applied_enums,
        "applied_typedefs": applied_typedefs,
        "applied_locals": applied_locals,
        "applied_comments": applied_comments,
        "applied_notes": applied_notes,
        "conflicts": len(conflicts),
        "skipped": skipped,
        "marker_writes_failed": sorted(marker_writes_failed),
        "touched_vas": sorted(set(touched_vas)),
        "proposed": proposed,
        "conflict_details": conflicts,
        "module": wanted_module,
        "accept_binsync": accept_binsync,
        "accept_local": accept_local,
        "health": health,
    }


def _route_comments(
    comments_by_addr: dict[int, dict[str, Any]],
    local_by_va: dict[int, object],
    module: str | None,
) -> tuple[dict[int, dict[str, dict[str, Any]]], dict[int, dict[int, str]]]:
    """Route imported per-instruction comments to their owning local function.

    Returns ``(by_func, source_markers)``: metadata entries keyed by owning VA
    (hex-addr subkeys) and, for comments whose address falls inside the owner's
    range, the text to write as a source marker.
    """
    from rebrew.binsync.state import containing_va

    ranges = [(va, int(getattr(ann, "size", 0) or 0)) for va, ann in local_by_va.items()]
    by_func: dict[int, dict[str, dict[str, Any]]] = {}
    markers: dict[int, dict[int, str]] = {}
    for addr, comment in comments_by_addr.items():
        text = str(comment.get("comment") or "")
        if text.startswith(("[rebrew:note]", "[rebrew:ghidra]")):
            continue
        owner = containing_va(ranges, addr)
        if owner is None:
            candidate = comment.get("func_addr")
            if not isinstance(candidate, int) or candidate not in local_by_va:
                continue
            owner = candidate
        ann = local_by_va.get(owner)
        if module is not None and preset_module_key(getattr(ann, "module", "")) != (
            preset_module_key(module)
        ):
            continue
        by_func.setdefault(owner, {})[f"0x{addr:08x}"] = {"comment": text, "func_addr": owner}
        size = int(getattr(ann, "size", 0) or 0)
        if size and owner <= addr < owner + size:
            markers.setdefault(owner, {})[addr] = text
    return by_func, markers


def _definition_files(cfg: ProjectConfig) -> list[Path]:
    """Local header + source files scanned for known type names.

    Headers include the shared tree: a struct in ``src/shared`` is already
    defined for every target, and missing it re-imports a duplicate into
    ``binsync_types.h``.  Sources already arrive shared-aware via
    :func:`rebrew.sources.iter_sources`.
    """
    reversed_dir = Path(cfg.reversed_dir)
    try:
        header_files = list(reversed_dir.rglob("*.h"))
    except OSError as exc:
        log.warning("cannot scan headers under %s: %s", reversed_dir, exc)
        header_files = []
    shared_dir = getattr(cfg, "shared_dir", None)
    if shared_dir is not None:
        try:
            shared = Path(shared_dir)
            if shared.resolve() != reversed_dir.resolve() and shared.is_dir():
                seen = {p.resolve() for p in header_files}
                header_files.extend(p for p in shared.rglob("*.h") if p.resolve() not in seen)
        except OSError as exc:
            # Dropping the shared headers re-imports their types as duplicates.
            log.warning("cannot scan shared headers under %s: %s", shared_dir, exc)
    try:
        from rebrew.sources import iter_sources

        source_files = list(iter_sources(reversed_dir, cfg))
    except OSError as exc:
        log.warning("cannot enumerate sources under %s: %s", reversed_dir, exc)
        source_files = []
    return header_files + source_files


def _local_type_names(cfg: ProjectConfig) -> set[str]:
    """Names of type definitions already present in the local tree."""
    from rebrew.struct_parser import (
        extract_enums_from_file,
        extract_structs_from_file,
        extract_type_definitions,
    )
    from rebrew.types import parse_structs

    names: set[str] = set()
    for path in _definition_files(cfg):
        try:
            for text in extract_structs_from_file(path):
                names.update(parse_structs(text))
            for text in extract_enums_from_file(path):
                match = re.search(r"\}\s*([A-Za-z_]\w*)\s*;", text) or re.search(
                    r"enum\s+([A-Za-z_]\w*)\s*\{", text
                )
                if match:
                    names.add(match.group(1))
            for text in extract_type_definitions(path):
                identifiers = re.findall(r"[A-Za-z_]\w*", text.rstrip().rstrip(";"))
                if identifiers:
                    names.add(identifiers[-1])
        except OSError:
            continue
    return names


def _definition_kind(entry: dict[str, object]) -> str:
    """``"enum"`` / ``"typedef"`` / ``"struct"`` from the entry's shape."""
    if "members" in entry:
        return "enum"
    if str(entry.get("type") or "").strip():
        return "typedef"
    return "struct"


def _definition_text(name: str, entry: dict[str, object]) -> str:
    """Raw definition text, synthesizing one from fields when absent.

    Synthesized member and field names must be C identifiers.  A BinSync
    key is collaborator-written text and may spell one ``café`` or ``日本``,
    which MSVC rejects in the header every later build reads, so an
    unusable name yields no text and nothing lands.
    """
    if not is_safe_c_ident(name):
        return ""
    definition = str(entry.get("definition") or "").strip()
    if definition:
        return definition
    members = entry.get("members")
    if isinstance(members, dict) and members:
        lines = [
            f"\t{member} = {value},"
            for member, value in members.items()
            if is_safe_c_ident(str(member))
        ]
        if not lines:
            return ""
        return "typedef enum {\n" + "\n".join(lines) + f"\n}} {name};"
    fields = entry.get("fields")
    if isinstance(fields, dict) and fields:
        lines = [
            f"\t{f.get('type', 'int')!s} {fname};"
            for fname, f in fields.items()
            if isinstance(f, dict)
            and is_safe_c_ident(str(fname))
            and _C_TYPE_RE.match(str(f.get("type", "int")))
        ]
        if not lines:
            return ""
        return f"typedef struct {name}_s {{\n" + "\n".join(lines) + f"\n}} {name};"
    return ""


def _has_preprocessor_line(definition: str) -> bool:
    """Whether *definition* carries a preprocessor directive.

    The test runs on the text with comments removed because that is what the
    preprocessor sees: ``/*x*/ #define FOO 1`` is a directive even though the
    ``#`` is not the first character of the line.
    """
    stripped = _C_COMMENT_RE.sub(" ", definition)
    stripped = re.sub(r"//[^\n]*", " ", stripped)
    return bool(re.search(r"^[ \t\f\v]*#", stripped, re.MULTILINE))


def _definition_is_valid(definition: str, name: str, entry: dict[str, object]) -> bool:
    """Whether *definition* is a complete, non-breaking declaration for *name*."""
    from rebrew.types import parse_structs

    # Shared state must not smuggle preprocessor lines into binsync_types.h.
    if _has_preprocessor_line(definition):
        return False

    # A C declaration is ASCII and its tag is an identifier.  A definition
    # spelling a member ``café`` parses as a struct yet fails every later
    # compile, so it takes the UNPARSED-comment path with the rest.
    if not is_safe_c_ident(name) or not definition.isascii():
        return False

    if name in parse_structs(definition):
        return True
    kind = _definition_kind(entry)
    text = definition.strip()
    if kind == "enum":
        return bool(re.search(r"\benum\b", text)) and "{" in text and text.endswith(";")
    if kind == "typedef":
        return text.startswith("typedef") and text.endswith(";")
    return False


def import_type_definitions(
    cfg: ProjectConfig,
    definitions: dict[str, dict[str, object]],
    *,
    dry_run: bool,
    proposed: list[dict[str, str]],
    update_names: set[str] | None = None,
) -> int:
    """Write unknown BinSync type definitions into ``binsync_types.h``.

    Handles structs, enums, and typedefs: a name already defined locally
    (across headers and sources) is skipped, never overwritten.  Each new
    definition is validated through the shared type model; an unparseable one
    imports as a comment instead of compile-breaking code.  Returns the
    applied count (dry-run counts without writing).
    """
    local_names = _local_type_names(cfg)
    rewritten = 0
    if update_names:
        from rebrew.struct_parser import replace_type_definition
        from rebrew.utils import atomic_write_text, read_source_text

        edits: dict[Path, tuple[str, str]] = {}
        for name in sorted(update_names):
            definition = _definition_text(name, definitions[name])
            if not _definition_is_valid(definition, name, definitions[name]):
                log.warning("refusing invalid replacement type %s", name)
                continue
            candidates: list[tuple[Path, str, str]] = []
            for path in _definition_files(cfg):
                try:
                    text, encoding = edits.get(path) or read_source_text(path)
                    replacement = replace_type_definition(text, name, definition)
                except ValueError:
                    continue
                if replacement != text:
                    candidates.append((path, replacement, encoding))
            if len(candidates) != 1:
                log.warning(
                    "cannot replace type %s unambiguously (%d definitions)", name, len(candidates)
                )
                continue
            path, replacement, encoding = candidates[0]
            if dry_run:
                proposed.append(
                    {
                        "field": "type_definition",
                        "type": name,
                        "local": "existing",
                        "binsync": name,
                        "action": "update",
                    }
                )
            else:
                edits[path] = (replacement, encoding)
            rewritten += 1
        if not dry_run:
            for path, (text, encoding) in edits.items():
                atomic_write_text(path, text, encoding=encoding)
    new = {name: entry for name, entry in definitions.items() if name not in local_names}
    if not new:
        return rewritten
    if dry_run:
        for name in sorted(new):
            kind = _definition_kind(new[name])
            proposed.append(
                {kind: name, "field": f"{kind}_definition", "local": "", "binsync": name}
            )
        return rewritten + len(new)
    from rebrew.utils import atomic_write_text, read_source_text

    reversed_dir = Path(cfg.reversed_dir)
    header = reversed_dir / "binsync_types.h"
    try:
        existing, header_encoding = read_source_text(header)
    except FileNotFoundError:
        existing, header_encoding = "", "utf-8"
    blocks = [
        existing
        or "/* binsync_types.h - type definitions imported from BinSync.\n"
        " * Regenerate/extend via: rebrew binsync import\n */\n\n"
    ]
    written = 0
    # ``landed`` includes blocks appended in this call so two keys that emit
    # the same text cannot both land.  The name check stays against the file
    # as read: a later key must not be dropped just because its spelling
    # occurs inside a definition written earlier in this batch.
    landed = existing
    for name in sorted(new):
        definition = _definition_text(name, new[name])
        if not definition:
            continue
        if not _definition_is_valid(definition, name, new[name]):
            # ASCII escapes, not the raw text: the header is written in the
            # project's source encoding, where the lenient write turns a code
            # point it lacks into `?`, and a collaborator-written identifier
            # must not reach the header verbatim even as a comment.
            inert = c_comment_safe(definition).encode("ascii", "backslashreplace").decode("ascii")
            definition = f"/* UNPARSED from BinSync (no known layout):\n{inert}\n*/"
        # The BinSync key is not a safe dedup token: an UNPARSED comment and a
        # definition whose declared name differs from the key never contain it,
        # so a key search appended a fresh copy on every import.  The
        # definition text is what actually lands in the header.
        if name in existing or definition.strip() in landed:
            continue
        block = definition + "\n\n"
        blocks.append(block)
        landed += block
        written += 1

    if written == 0:
        return rewritten
    atomic_write_text(header, "".join(blocks), encoding=header_encoding, lenient=True)
    return rewritten + written


def print_import_result(result: dict[str, object], *, json_output: bool, dry_run: bool) -> None:
    """Render an :func:`import_state` result (the CLI summary/exit path)."""
    state_dir = str(result["state_dir"])
    applied_names = result_count(result, "applied_names")
    applied_protos = result_count(result, "applied_prototypes")
    applied_globals = result_count(result, "applied_globals")
    applied_structs = result_count(result, "applied_structs")
    applied_enums = result_count(result, "applied_enums")
    applied_typedefs = result_count(result, "applied_typedefs")
    applied_locals = result_count(result, "applied_locals")
    applied_comments = result_count(result, "applied_comments")
    applied_notes = result_count(result, "applied_notes")
    conflicts = result_count(result, "conflicts")
    proposed = result_rows(result, "proposed")
    conflict_details = result_rows(result, "conflict_details")
    marker_writes_failed = result_paths(result, "marker_writes_failed")
    module = result.get("module")
    accept_binsync = bool(result.get("accept_binsync"))
    accept_local = bool(result.get("accept_local"))
    applied_counts = (
        applied_names,
        applied_protos,
        applied_globals,
        applied_structs,
        applied_enums,
        applied_typedefs,
        applied_locals,
        applied_comments,
        applied_notes,
    )
    if json_output:
        payload: dict[str, object] = {
            "state_dir": state_dir,
            "dry_run": dry_run,
            "applied_names": applied_names,
            "applied_prototypes": applied_protos,
            "applied_globals": applied_globals,
            "applied_structs": applied_structs,
            "applied_enums": applied_enums,
            "applied_typedefs": applied_typedefs,
            "applied_locals": applied_locals,
            "applied_comments": applied_comments,
            "applied_notes": applied_notes,
            "health": result.get("health", {}),
            "conflicts": conflicts,
            "skipped": result_count(result, "skipped"),
        }
        if marker_writes_failed:
            payload["marker_writes_failed"] = marker_writes_failed
        if proposed:
            payload["proposed"] = proposed
        if conflict_details:
            payload["conflict_details"] = conflict_details
        if module is not None:
            payload["module"] = module
        json_print(payload)
        if conflicts and not accept_binsync and not accept_local:
            raise typer.Exit(code=EXIT_MISMATCH)
        return

    health = result.get("health", {})
    if isinstance(health, dict):
        for message in sync_health_messages(health):
            console.print(message, markup=False)
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
            raise typer.Exit(code=EXIT_MISMATCH)
        return

    # Non-dry-run, non-json summary
    if any(applied_counts):
        console.print(
            f"[green]Imported[/green] {applied_names} name(s), {applied_protos} prototype(s), "
            f"{applied_globals} global(s), {applied_structs} struct(s), "
            f"{applied_enums} enum(s), {applied_typedefs} typedef(s), "
            f"{applied_locals} locals, {applied_comments} comment(s), {applied_notes} note(s) "
            f"from [cyan]{state_dir}[/cyan]"
        )
    if marker_writes_failed:
        # The comment metadata landed; the // ANALYSIS: markers in the source
        # did not.  A re-import will not retry them, so name the files.
        console.print(
            f"[yellow]ANALYSIS marker write failed for {len(marker_writes_failed)} file(s):[/yellow] "
            + ", ".join(marker_writes_failed[:10])
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
            raise typer.Exit(code=EXIT_MISMATCH)
    if not any(applied_counts) and not conflicts:
        if isinstance(health, dict) and any(health.get("pending", {}).values()):
            console.print("No changes imported; pending sync decisions remain.")
        else:
            console.print("[green]Already in sync — nothing to import.[/green]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_standalone(main)


if __name__ == "__main__":
    main_entry()
