"""rename.py - Rename a function, global, type or struct member across the project.

Plans the whole rename (source edits by file and line, metadata rows, file
move) through :mod:`rebrew.rename_ops`, prints it, and writes it unless
``--dry-run``. Renames are syntax-aware: string literals are never rewritten,
comments only with ``--comments``.
"""

lazy import unicodedata
lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import (
    EXIT_ERROR,
    EXPECTED_DIGEST_HELP,
    TargetOption,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
)
lazy from rebrew.catalog import scan_reversed_dir
lazy from rebrew.rename_ops import (
    KIND_DATA,
    KIND_FUNCTION,
    RenameError,
    RenamePlan,
    Selection,
    apply_rename_plan,
    is_valid_new_name,
    plan_field_rename,
    plan_function_reference_binding,
    plan_header_row_rename,
    plan_symbol_rename,
    plan_type_rename,
    redecorated_symbol,
    rename_source_name,
)
lazy from rebrew.sources import contained_path, source_roots
lazy from rebrew.utils import rel_display_path

#: Offending sources named in a rename failure, one line each.
_RENAME_FAILURE_FILE_LIMIT = 10


def _rename_failure(exc: RenameError, root: Path | None = None) -> str:
    """*exc*'s message plus the sources it names, relative to *root*."""
    if not exc.files:
        return str(exc)
    shown = ", ".join(rel_display_path(f, root) for f in exc.files[:_RENAME_FAILURE_FILE_LIMIT])
    if len(exc.files) > _RENAME_FAILURE_FILE_LIMIT:
        shown += f", and {len(exc.files) - _RENAME_FAILURE_FILE_LIMIT} more"
    return f"{exc}\n  files: {shown}"


_INVALID_NAME = (
    "'{name}' is not a valid C identifier: use letters, digits, and underscores "
    "(not starting with a digit, not a C keyword)."
)
_DUPLICATE = (
    "'{name}' is already used by {where}; renaming would create a duplicate symbol. "
    "Pick a different name."
)

app = typer.Typer(
    help="Rename a function, global, type or struct member and update every reference.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source rename old_func new_func  # Rename function\n\n"
        "  rebrew source rename SERVER.0x10003da0 new_func  # Rename one identity\n\n"
        "  # Bound shared rows\n"
        "  rebrew source rename GOLD.0x405000 new_func --shared-definition\n\n"
        "  rebrew source rename gm_Init gm_Kill --all-modules  # Shared definition\n\n"
        "  rebrew source rename g_old g_new --data  # Rename a global\n\n"
        "  rebrew source rename OldType NewType --type  # Rename a type\n\n"
        "  rebrew source rename Rec.old_member new --field  # Rename a member\n\n"
        "[dim]A name without a row in this target renames the source symbol and the rows of other modules bound to it. String literals are never rewritten; comments only with --comments. Preview with --dry-run.[/dim]"
    ),
)


def _parse_identity(ident: str) -> tuple[str, int] | None:
    """``MODULE.0xVA`` → ``(MODULE, VA)``."""
    module, sep, va_text = ident.rpartition(".")
    if not sep or not module or not va_text.lower().startswith("0x"):
        return None
    try:
        return module, int(va_text, 16)
    except ValueError:
        return None


def _row_source(cfg: Any, stored: str) -> Path | None:
    """The source a row's ``file`` names (relative to the metadata root), or None if it escapes.

    A row path that does not exist under the metadata root is retried under
    ``reversed_dir`` (an inline marker's scan path).
    """
    roots = source_roots(cfg)
    first = contained_path((Path(cfg.metadata_dir), *roots), stored)
    if first is not None and first.is_file():
        return first
    return contained_path(roots, stored) or first


def _parse_va(ident: str) -> int | None:
    if not ident.lower().startswith("0x"):
        return None
    try:
        return int(ident, 16)
    except ValueError:
        return None


@app.callback(invoke_without_command=True)
def main(
    target_ident: str = typer.Argument(
        ...,
        metavar="old_name",
        help=(
            "Old name: function name, symbol, file, VA or MODULE.0xVA; a global with "
            "--data; a type with --type; STRUCT.MEMBER with --field"
        ),
    ),
    new_name: str = typer.Argument(
        ..., help="New name, or MODULE.0xVA to bind function references"
    ),
    new_file: str | None = typer.Option(None, "--file", help="New filename"),
    data: bool = typer.Option(
        False,
        "--data",
        help="Rename a global (data row, definition, declarations, uses); excludes --type and --field",
    ),
    type_rename: bool = typer.Option(
        False,
        "--type",
        help="Rename a struct/union/enum tag or typedef name; excludes --data and --field",
    ),
    field_rename: bool = typer.Option(
        False,
        "--field",
        help="Rename a struct/union member given as STRUCT.MEMBER; excludes --data and --type",
    ),
    all_modules: bool = typer.Option(
        False,
        "--all-modules",
        help=(
            "Rename every module's rows of this definition, and every other definition of the name"
        ),
    ),
    shared_definition: bool = typer.Option(
        False,
        "--shared-definition",
        help="Rename every function row bound to one definition; requires MODULE.0xVA; excludes --all-modules, --data, --type, and --field",
    ),
    reference_owner: list[str] | None = typer.Option(
        None,
        "--reference-owner",
        help="Reviewed owner for all references in a project-relative FILE=MODULE.0xVA; requires --shared-definition",
    ),
    preserve_reference_file: list[str] | None = typer.Option(
        None,
        "--preserve-reference",
        help="Leave references in a reviewed file unchanged; requires --shared-definition",
    ),
    pending_owner: list[str] | None = typer.Option(
        None, "--pending-owner", help="Prospective target identity for a reviewed FILE=MODULE.0xVA"
    ),
    expected_digest: str | None = typer.Option(
        None,
        "--expected-digest",
        help=EXPECTED_DIGEST_HELP,
    ),
    comments: bool = typer.Option(
        False, "--comments", help="Also rewrite whole-word occurrences inside comments"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rename a function, global, type or struct member and update every reference."""
    cfg = require_config(target=target, json_mode=json_output)
    reference_owner = option_default(reference_owner, None) or []
    preserve_reference_file = option_default(preserve_reference_file, None) or []
    pending_owner = option_default(pending_owner, None) or []
    reviewed_references = reference_owner or preserve_reference_file or pending_owner
    expected_digest = option_default(expected_digest, None)
    binding = _parse_identity(new_name) if not (data or type_rename or field_rename) else None
    if (reviewed_references or (expected_digest and binding is None)) and not shared_definition:
        error_exit(
            "reference selections and --expected-digest require --shared-definition",
            json_mode=json_output,
        )
    if reviewed_references and not dry_run and not expected_digest:
        error_exit(
            "review reference selections with --dry-run, then apply with --expected-digest",
            json_mode=json_output,
        )
    if shared_definition and (
        all_modules or data or type_rename or field_rename or _parse_identity(target_ident) is None
    ):
        error_exit(
            "--shared-definition requires a function MODULE.0xVA and is exclusive with "
            "--all-modules, --data, --type and --field",
            json_mode=json_output,
        )
    if sum((data, type_rename, field_rename)) > 1:
        error_exit("--data, --type and --field are exclusive", json_mode=json_output)
    if new_file is not None and (data or type_rename or field_rename):
        error_exit(
            "--file renames a function's source file; it does not apply here",
            json_mode=json_output,
            code=EXIT_ERROR,
        )
    if binding and (new_file is not None or all_modules or shared_definition):
        error_exit("reference binding does not rename files or identities", json_mode=json_output)
    identity = None if (data or type_rename or field_rename) else _parse_identity(target_ident)
    header_plan: RenamePlan | None = None
    if binding is None and identity is not None and new_file is None:
        try:
            header_plan = plan_header_row_rename(cfg, identity[0], identity[1], new_name)
        except ValueError as exc:
            error_exit(str(exc), json_mode=json_output)
        except RenameError as exc:
            error_exit(_rename_failure(exc, getattr(cfg, "root", None)), json_mode=json_output)
    if reviewed_references and header_plan is not None:
        error_exit(
            "reference ownership requires a source-defined function, not a header identity",
            json_mode=json_output,
        )
    if binding is None and header_plan is None and not is_valid_new_name(new_name):
        error_exit(_INVALID_NAME.format(name=new_name), json_mode=json_output)

    extra: dict[str, Any] = {}
    try:
        if binding:
            module, va = binding
            plan = plan_function_reference_binding(
                cfg, target_ident, Selection(KIND_FUNCTION, module, va), comments=comments
            )
            extra = {"module": module, "va": va, "reference_binding": True}
        elif header_plan is not None:
            plan = header_plan
        elif type_rename:
            plan = plan_type_rename(cfg, target_ident, new_name, comments=comments)
        elif field_rename:
            record, sep, member = target_ident.rpartition(".")
            if not sep or not record or not member:
                error_exit("--field takes STRUCT.MEMBER", json_mode=json_output)
            plan = plan_field_rename(cfg, record, member, new_name, comments=comments)
        elif data:
            plan, extra = _plan_data(
                cfg, target_ident, new_name, all_modules, comments, dry_run, json_output
            )
        else:
            plan, extra = _plan_function(
                cfg,
                target_ident,
                new_name,
                new_file,
                all_modules,
                comments,
                dry_run,
                json_output,
                shared_definition=shared_definition,
                reference_owners=_parse_reference_owners(cfg, reference_owner),
                preserved_references=_parse_preserved_references(cfg, preserve_reference_file),
                pending_owners=_parse_reference_owners(cfg, pending_owner, "--pending-owner"),
            )
    except (FileExistsError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    except RenameError as exc:
        error_exit(_rename_failure(exc, getattr(cfg, "root", None)), json_mode=json_output)

    updated = len(plan.files)
    if expected_digest is not None and expected_digest != plan.input_digest:
        error_exit(
            "rename inputs or ownership decisions changed; review a new preview",
            json_mode=json_output,
        )
    if not dry_run:
        try:
            updated = apply_rename_plan(cfg, plan)
        except RenameError as exc:
            error_exit(_rename_failure(exc, getattr(cfg, "root", None)), json_mode=json_output)
    _report(cfg, plan, extra, updated, dry_run, json_output)


def _report(
    cfg: Any,
    plan: RenamePlan,
    extra: dict[str, Any],
    updated: int,
    dry_run: bool,
    json_output: bool,
) -> None:
    root = getattr(cfg, "root", None)
    if json_output:
        json_print({**plan.as_dict(root), **extra, "files_updated": updated, "dry_run": dry_run})
        return
    verb = "Would rename" if dry_run else "Renamed"
    console.print(
        f"{'[dim]Dry run:[/dim] ' if dry_run else ''}{verb} {plan.old_name} → {plan.new_name}"
    )
    for change in plan.files:
        shown = rel_display_path(change.path, root)
        for edit in change.edits:
            console.print(f"  {shown}:{edit.line}:{edit.column} [dim]{edit.role}[/dim]")
    for row in plan.rows:
        fields = ", ".join(f"{k} {row.old.get(k, '')!s} → {v!s}" for k, v in row.new.items())
        console.print(f"  {row.store} row {row.module}.0x{row.va:08x}: {fields}")
    if plan.move is not None:
        console.print(
            f"  move {rel_display_path(plan.move[0], root)} → {rel_display_path(plan.move[1], root)}"
        )
    for note in plan.notes:
        console.print(f"  [yellow]note:[/yellow] {note}")
    for path, owner in sorted(plan.reference_owners.items()):
        console.print(
            f"  reviewed references {rel_display_path(path, root)} → {owner.module}.0x{owner.va:08x}"
        )
    for path in sorted(plan.preserved_references):
        console.print(f"  preserved references {rel_display_path(path, root)}")
    for path, owner in sorted(plan.pending_owners.items()):
        console.print(
            f"  pending owner {rel_display_path(path, root)} → {owner.module}.0x{owner.va:08x}"
        )
    if plan.input_hashes:
        console.print(f"  input digest: {plan.input_digest}")
    if dry_run:
        console.print(f"[dim]Would update {updated} files.[/dim]")
    else:
        console.print(f"Updated {updated} files.")
        console.print("[green]Done![/green]")


def _parse_reference_owners(
    cfg: Any, values: list[str], option: str = "--reference-owner"
) -> dict[Path, Selection]:
    owners = {}
    root = Path(getattr(cfg, "root", None) or cfg.reversed_dir)
    for value in values:
        file, sep, ident = value.rpartition("=")
        identity = _parse_identity(ident)
        if not sep or not file or identity is None:
            raise ValueError(f"{option} takes FILE=MODULE.0xVA")
        path = Path(file)
        path = (path if path.is_absolute() else root / path).resolve()
        if path in owners:
            raise ValueError(f"duplicate {option} selection: {file}")
        owners[path] = Selection(KIND_FUNCTION, *identity)
    return owners


def _parse_preserved_references(cfg: Any, values: list[str]) -> set[Path]:
    root = Path(getattr(cfg, "root", None) or cfg.reversed_dir)
    paths = [
        (Path(value) if Path(value).is_absolute() else root / value).resolve() for value in values
    ]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate preserved reference file")
    return set(paths)


def _check_scan_collision(
    entries: list[Any],
    skip: Any,
    new_name: str,
    json_output: bool,
    allow_other_module: bool = False,
) -> None:
    """Refuse a new name an active-target annotation already uses (decorated or not).

    *allow_other_module* ignores annotations of other targets: with
    ``--shared-definition`` their bodies sit behind that target's define in the
    same file, so the name is not a duplicate symbol in this image.
    """
    own_module = getattr(skip, "module", "") or ""
    for e in entries:
        if e is skip:
            continue
        if allow_other_module and (getattr(e, "module", "") or "") != own_module:
            continue
        name = getattr(e, "name", "") or ""
        symbol = getattr(e, "symbol", "") or ""
        if (
            name == new_name
            or symbol in (new_name, f"_{new_name}")
            # stdcall `_name@N`, vectorcall `name@@N`, fastcall `@name@N`.
            or symbol.startswith((f"_{new_name}@", f"{new_name}@@", f"@{new_name}@"))
        ):
            error_exit(
                _DUPLICATE.format(name=new_name, where=getattr(e, "filepath", "?")),
                json_mode=json_output,
            )


def _plan_function(
    cfg: Any,
    target_ident: str,
    new_name: str,
    new_file: str | None,
    all_modules: bool,
    comments: bool,
    dry_run: bool,
    json_output: bool,
    *,
    shared_definition: bool = False,
    reference_owners: dict[Path, Selection] | None = None,
    preserved_references: set[Path] | None = None,
    pending_owners: dict[Path, Selection] | None = None,
) -> tuple[RenamePlan, dict[str, Any]]:
    """Resolve the function identity, then plan its rename."""
    from rebrew.metadata.functions import get_entry

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    identity = _parse_identity(target_ident)
    if identity is not None:
        module, va = identity
        row = get_entry(cfg.metadata_dir, va, module)
        if not row:
            error_exit(f"Could not find function row {target_ident}", json_mode=json_output)
        old_name, old_sym = str(row.get("name") or ""), str(row.get("symbol") or "")
        stored = str(row.get("file") or "")
        if not stored:
            error_exit(
                f"function row {target_ident} has no source binding",
                hint="Register a reviewed source definition with rebrew source register "
                "before renaming this identity.",
                json_mode=json_output,
            )
        filepath = _row_source(cfg, stored)
        if filepath is None:
            error_exit(f"function file escapes the source roots: {stored!r}", json_mode=json_output)
        selected = Selection(KIND_FUNCTION, module, va)
        match = None
    else:
        matches = _match_functions(cfg, entries, target_ident)
        if len(matches) > 1:
            error_exit(
                f"Found {len(matches)} matches for '{target_ident}'. Be more specific.",
                json_mode=json_output,
            )
        if not matches:
            return _plan_source_level(
                cfg, entries, target_ident, new_name, all_modules, comments, dry_run, json_output
            )
        match = matches[0]
        old_name = getattr(match, "name", "") or ""
        old_sym = getattr(match, "symbol", "") or old_name
        rel = getattr(match, "filepath", "")
        va = getattr(match, "va", 0)
        module = getattr(match, "module", "") or getattr(cfg, "module", "")
        try:
            filepath = (Path(cfg.reversed_dir) / rel).resolve()
            filepath.relative_to(Path(cfg.reversed_dir).resolve())
        except ValueError, OSError, TypeError:
            error_exit(f"function file escapes reversed_dir: {rel!r}", json_mode=json_output)
        selected = Selection(KIND_FUNCTION, module, va)
    # A library header alias can share the compiled definition's native identity.
    others = [
        entry
        for entry in entries
        if (getattr(entry, "module", ""), getattr(entry, "va", 0)) != (selected.module, selected.va)
    ]
    _check_scan_collision(
        others, match, new_name, json_output, allow_other_module=shared_definition
    )
    actual_old = rename_source_name(old_name, old_sym)
    plan = plan_symbol_rename(
        cfg,
        actual_old,
        new_name,
        store=KIND_FUNCTION,
        selected=selected,
        definition_file=filepath,
        all_modules=all_modules,
        comments=comments,
        require_ack=not shared_definition,
        allow_counterpart_name=shared_definition,
        rename_file=True,
        new_filename=new_file,
        dry_run=dry_run,
        reference_owners=reference_owners,
        preserved_references=preserved_references,
        pending_owners=pending_owners,
        guarded=shared_definition,
    )
    return plan, {
        "module": selected.module,
        "va": f"0x{selected.va:08x}",
        "new_symbol": redecorated_symbol(old_sym or actual_old, new_name, underscore=True),
    }


def _plan_source_level(
    cfg: Any,
    entries: list[Any],
    old_name: str,
    new_name: str,
    all_modules: bool,
    comments: bool,
    dry_run: bool,
    json_output: bool,
) -> tuple[RenamePlan, dict[str, Any]]:
    """Rename a source symbol this target has no row for."""
    if not is_valid_new_name(old_name) or _parse_va(old_name) is not None:
        error_exit(f"Could not find function matching '{old_name}'", json_mode=json_output)
    plan = plan_symbol_rename(
        cfg,
        old_name,
        new_name,
        store=KIND_FUNCTION,
        all_modules=all_modules,
        comments=comments,
        dry_run=dry_run,
    )
    if not plan.files:
        error_exit(f"Could not find function matching '{old_name}'", json_mode=json_output)
    return plan, {"module": None, "va": None}


def _match_functions(cfg: Any, entries: list[Any], target_ident: str) -> list[Any]:
    """Active-target annotations that *target_ident* names (name, symbol, file, VA)."""
    va_ident = _parse_va(target_ident)
    try:
        rev_rel = Path(cfg.reversed_dir).relative_to(cfg.root)
    except ValueError, TypeError, AttributeError:
        rev_rel = Path(cfg.reversed_dir)
    target_norm = unicodedata.normalize("NFC", target_ident)
    matches = []
    for e in entries:
        if getattr(e, "is_data", False):
            continue
        name = getattr(e, "name", "") or ""
        sym = getattr(e, "symbol", "") or ""
        fp = str(getattr(e, "filepath", "") or "")
        va = getattr(e, "va", 0)
        forms = {name, sym, fp, Path(fp).name, f"0x{va:x}", f"0x{va:X}", str(va)}
        if fp:
            root = Path(getattr(cfg, "root", None) or "")
            forms |= {
                (rev_rel / fp).as_posix(),
                str(rev_rel / fp),
                str((root / rev_rel / fp).resolve()),
            }
        if target_norm in {unicodedata.normalize("NFC", f) for f in forms if f} or (
            va_ident is not None and va == va_ident
        ):
            matches.append(e)
    return matches


def _plan_data(
    cfg: Any,
    target_ident: str,
    new_name: str,
    all_modules: bool,
    comments: bool,
    dry_run: bool,
    json_output: bool,
) -> tuple[RenamePlan, dict[str, Any]]:
    """Resolve the data identity (row or source global), then plan its rename."""
    from rebrew.metadata.data import load_data_metadata
    from rebrew.utils import preset_module_key

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    rows = load_data_metadata(cfg.metadata_dir)
    scan_files = {
        (getattr(e, "module", "") or "", getattr(e, "va", 0)): getattr(e, "filepath", "")
        for e in entries
        if getattr(e, "is_data", False)
    }
    identity = _parse_identity(target_ident)
    va_ident = _parse_va(target_ident)
    target_norm = unicodedata.normalize("NFC", target_ident)
    target_module_name = preset_module_key(getattr(cfg, "module", "") or "")

    def named(key: tuple[str, int], row: dict[str, Any]) -> bool:
        if identity is not None:
            return (preset_module_key(key[0]), key[1]) == (
                preset_module_key(identity[0]),
                identity[1],
            )
        stored = unicodedata.normalize("NFC", str(row.get("name") or ""))
        return target_norm == stored or (va_ident is not None and key[1] == va_ident)

    candidates = [key for key, row in rows.items() if named(key, row)]
    own = [key for key in candidates if preset_module_key(key[0]) == target_module_name]
    picked = own or candidates
    if len(picked) > 1:
        listed = ", ".join(f"{m}.0x{v:08x}" for m, v in picked)
        error_exit(
            f"Found {len(picked)} matches for '{target_ident}' ({listed}). Be more specific: "
            "pass MODULE.0xVA.",
            json_mode=json_output,
        )
    data_scan = [e for e in entries if getattr(e, "is_data", False)]
    if not picked:
        if identity is not None or va_ident is not None:
            error_exit(
                f"Could not find DATA/GLOBAL matching '{target_ident}'", json_mode=json_output
            )
        _check_scan_collision(entries, None, new_name, json_output)
        plan = plan_symbol_rename(
            cfg, target_ident, new_name, store=KIND_DATA, all_modules=all_modules, comments=comments
        )
        if not plan.files:
            error_exit(
                f"Could not find DATA/GLOBAL matching '{target_ident}'", json_mode=json_output
            )
        return plan, {"module": None, "va": None}
    module, va = picked[0]
    row = rows[(module, va)]
    old_name = str(row.get("name") or "")
    if not old_name:
        error_exit(
            f"DATA/GLOBAL 0x{va:x} has no name in rebrew-data.toml — name it first "
            "(rebrew data list --json), then rename.",
            json_mode=json_output,
        )
    stored = str(row.get("file") or "")
    filepath: Path | None = None
    if stored:
        filepath = _row_source(cfg, stored)
    elif scan_files.get((module, va)):
        stored = str(scan_files[(module, va)])
        filepath = contained_path(source_roots(cfg), stored)
    if stored and filepath is None:
        error_exit(f"function file escapes the source roots: {stored!r}", json_mode=json_output)
    skip = next(
        (e for e in data_scan if (getattr(e, "module", ""), getattr(e, "va", 0)) == (module, va)),
        None,
    )
    _check_scan_collision(entries, skip, new_name, json_output)
    plan = plan_symbol_rename(
        cfg,
        old_name,
        new_name,
        store=KIND_DATA,
        selected=Selection(KIND_DATA, module, va),
        definition_file=filepath if filepath is not None and filepath.is_file() else None,
        all_modules=all_modules,
        comments=comments,
        dry_run=dry_run,
    )
    return plan, {"module": module, "va": f"0x{va:08x}"}


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
