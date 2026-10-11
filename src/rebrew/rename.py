"""rename.py - Rename a function, global, type or struct member across the project.

Plans the whole rename (source edits by file and line, metadata rows, file
move) through :mod:`rebrew.rename_ops`, prints it, and writes it unless
``--dry-run``. Renames are syntax-aware: string literals are never rewritten,
comments only with ``--comments``.
"""

import unicodedata
from pathlib import Path
from typing import Any

import typer

from rebrew.catalog import scan_reversed_dir
from rebrew.cli import (
    EXIT_ERROR,
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
)
from rebrew.rename_ops import (
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
from rebrew.sources import contained_path, source_roots
from rebrew.utils import rel_display_path

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
        "  rebrew source rename old_func new_func · · · · · · · · · Rename function\n\n"
        "  rebrew source rename SERVER.0x10003da0 new_func · · · · Rename one identity\n\n"
        "  rebrew source rename gm_Init gm_Kill --all-modules · · · Shared definition\n\n"
        "  rebrew source rename g_old g_new --data · · · · · · · · Rename a global\n\n"
        "  rebrew source rename OldType NewType --type · · · · · · Rename a type\n\n"
        "  rebrew source rename Rec.old_member new --field · · · · Rename a member\n\n"
        "[dim]A name without a row in this target renames the source symbol and the rows "
        "of other modules bound to it. String literals are never rewritten; comments only "
        "with --comments. Preview with --dry-run.[/dim]"
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
        False, "--data", help="Rename a global (data row, definition, declarations, uses)"
    ),
    type_rename: bool = typer.Option(
        False, "--type", help="Rename a struct/union/enum tag or typedef name"
    ),
    field_rename: bool = typer.Option(
        False, "--field", help="Rename a struct/union member given as STRUCT.MEMBER"
    ),
    all_modules: bool = typer.Option(
        False,
        "--all-modules",
        help=(
            "Rename the rows of every module bound to the definition, and every other "
            "definition of the name"
        ),
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
    if sum((data, type_rename, field_rename)) > 1:
        error_exit("--data, --type and --field are exclusive", json_mode=json_output)
    if new_file is not None and (data or type_rename or field_rename):
        error_exit(
            "--file renames a function's source file; it does not apply here",
            json_mode=json_output,
            code=EXIT_ERROR,
        )
    binding = _parse_identity(new_name) if not (data or type_rename or field_rename) else None
    if binding and (new_file is not None or all_modules):
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
                cfg, target_ident, new_name, new_file, all_modules, comments, dry_run, json_output
            )
    except (FileExistsError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    except RenameError as exc:
        error_exit(_rename_failure(exc, getattr(cfg, "root", None)), json_mode=json_output)

    updated = len(plan.files)
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
    if dry_run:
        console.print(f"[dim]Would update {updated} files.[/dim]")
    else:
        console.print(f"Updated {updated} files.")
        console.print("[green]Done![/green]")


def _check_scan_collision(entries: list[Any], skip: Any, new_name: str, json_output: bool) -> None:
    """Refuse a new name an active-target annotation already uses (decorated or not)."""
    for e in entries:
        if e is skip:
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
) -> tuple[RenamePlan, dict[str, Any]]:
    """Resolve the function identity, then plan its rename."""
    from rebrew.metadata import get_entry

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    identity = _parse_identity(target_ident)
    if identity is not None:
        module, va = identity
        row = get_entry(cfg.metadata_dir, va, module)
        if not row:
            error_exit(f"Could not find function row {target_ident}", json_mode=json_output)
        old_name, old_sym = str(row.get("name") or ""), str(row.get("symbol") or "")
        stored = str(row.get("file") or "")
        filepath = _row_source(cfg, stored) if stored else None
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
        module = getattr(match, "module", "") or getattr(cfg, "marker", "")
        try:
            filepath = (Path(cfg.reversed_dir) / rel).resolve()
            filepath.relative_to(Path(cfg.reversed_dir).resolve())
        except (ValueError, OSError, TypeError):
            error_exit(f"function file escapes reversed_dir: {rel!r}", json_mode=json_output)
        selected = Selection(KIND_FUNCTION, module, va)
    _check_scan_collision(entries, match, new_name, json_output)
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
        rename_file=True,
        new_filename=new_file,
        dry_run=dry_run,
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
    _check_scan_collision(entries, None, new_name, json_output)
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
    except (ValueError, TypeError, AttributeError):
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
    from rebrew.data_metadata import load_data_metadata
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
    marker = preset_module_key(getattr(cfg, "marker", "") or "")

    def named(key: tuple[str, int], row: dict[str, Any]) -> bool:
        if identity is not None:
            return (preset_module_key(key[0]), key[1]) == (
                preset_module_key(identity[0]),
                identity[1],
            )
        stored = unicodedata.normalize("NFC", str(row.get("name") or ""))
        return target_norm == stored or (va_ident is not None and key[1] == va_ident)

    candidates = [key for key, row in rows.items() if named(key, row)]
    own = [key for key in candidates if preset_module_key(key[0]) == marker]
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
