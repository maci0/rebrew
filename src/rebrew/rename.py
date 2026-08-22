"""rename.py - Rename a function and update all cross-references.

Renames a function across the entire codebase: updates ``// FUNCTION:``,
``extern`` declarations, the C function definition, the source file name (optional),
and any other references discovered by scanning the reversed directory.
"""

import re
from pathlib import Path

import typer
from rich.console import Console

from rebrew.catalog import scan_reversed_dir
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    require_config,
)
from rebrew.rename_ops import _collect_matching_files, rename_function_everywhere
from rebrew.utils import rel_display_path

# C89 keywords cannot be used as function names; `str.isidentifier()` alone
# would let `if`, `int`, `struct`, ... through and generate uncompilable C.
_C_KEYWORDS = frozenset(
    {
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "int",
        "long",
        "register",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
    }
)

app = typer.Typer(
    help="Rename a function and update cross-references.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew rename old_func new_func · · · · · · Rename function\n\n"
        "  rebrew rename src/game/old.c new_func · · · Rename by file path\n\n"
        "  rebrew rename 0x10003da0 new_func · · · · · Rename by VA\n\n"
        "  rebrew rename old_func new_func --file new.c  Custom filename\n\n"
        "[dim]Updates FUNCTION markers, function definitions, extern "
        "declarations, and optionally renames the source file.[/dim]\n\n"
        "[dim]Note: macros and string literals are NOT rewritten — "
        "`grep` for the old name afterwards if you suspect any.[/dim]"
    ),
)
console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def main(
    target_ident: str = typer.Argument(..., help="Old function name, file path, or VA"),
    new_name: str = typer.Argument(..., help="New function name"),
    new_file: str | None = typer.Option(None, "--file", help="New filename"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rename a function and update all cross-references."""
    cfg = require_config(target=target, json_mode=json_output)

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    # Normalize a hex VA identifier once (functions.txt writes zero-padded
    # 0x000100a0; other tools accept both — rename must too).
    va_ident: int | None = None
    if target_ident.lower().startswith("0x"):
        try:
            va_ident = int(target_ident, 16)
        except ValueError:
            va_ident = None
    matches = []
    for e in entries:
        name = getattr(e, "name", "")
        sym = getattr(e, "symbol", "")
        fp = getattr(e, "filepath", "")
        va = getattr(e, "va", 0)

        va_str = f"0x{va:x}"
        va_str_upper = f"0x{va:X}"
        # filepath is stored relative to reversed_dir ("add3.c"); also accept
        # the project-root-relative form the help documents
        # ("src/game/old.c") and the absolute path.
        proj_rel = ""
        abs_path = ""
        if fp:
            # reversed_dir may be absolute (require_config) or project-
            # relative (load_config) — normalize to the root-relative form
            # the help documents ("src/game/old.c").
            try:
                rev_rel = Path(cfg.reversed_dir).relative_to(cfg.root)
            except (ValueError, TypeError):
                rev_rel = Path(cfg.reversed_dir)
            proj_rel = str(rev_rel / fp)
            try:
                abs_path = str((cfg.root / rev_rel / fp).resolve())
            except (OSError, TypeError):
                abs_path = ""
        if target_ident in (
            name,
            sym,
            str(fp),
            Path(str(fp)).name,
            proj_rel,
            abs_path,
            va_str,
            va_str_upper,
            str(va),
        ) or (va_ident is not None and va == va_ident):
            matches.append(e)

    if not matches:
        error_exit(f"Could not find function matching '{target_ident}'", json_mode=json_output)

    if len(matches) > 1:
        error_exit(
            f"Found {len(matches)} matches for '{target_ident}'. Be more specific.",
            json_mode=json_output,
        )

    match = matches[0]
    old_name = getattr(match, "name", "")
    old_sym = getattr(match, "symbol", "")
    old_fp = getattr(match, "filepath", "")
    va = getattr(match, "va", 0)

    if not old_sym:
        old_sym = old_name

    actual_old_name = old_sym.lstrip("_") if old_sym.startswith("_") else old_name
    actual_old_name = re.sub(r"@\d+$", "", actual_old_name)

    target_func = new_name
    if not target_func.isidentifier() or target_func in _C_KEYWORDS:
        error_exit(
            f"'{target_func}' is not a valid C identifier — use letters, digits, "
            f"and underscores (not starting with a digit, not a C keyword).",
            json_mode=json_output,
        )

    # Guard: renaming onto an existing function/global's symbol would create a
    # duplicate definition (same name in two files → symbol collisions at
    # compile/compare time). Reject before any write.
    target_sym_variants = {target_func, f"_{target_func}"}
    for e in entries:
        if e is match:
            continue
        e_name = getattr(e, "name", "") or ""
        e_sym = getattr(e, "symbol", "") or ""
        if (
            e_name == target_func
            or e_sym in target_sym_variants
            or e_sym.startswith(f"_{target_func}@")  # __stdcall decoration
        ):
            error_exit(
                f"'{target_func}' is already used by {getattr(e, 'filepath', '?')} — "
                f"renaming would create a duplicate symbol. Pick a different name.",
                json_mode=json_output,
            )

    filepath = cfg.reversed_dir / old_fp

    if not json_output:
        if dry_run:
            console.print(f"[dim]Dry run:[/dim] Would rename {actual_old_name} → {target_func}")
        else:
            console.print(f"Renaming {actual_old_name} to {target_func}...")

    try:
        updated = rename_function_everywhere(
            cfg=cfg,
            filepath=filepath,
            old_name=old_name,
            old_sym=old_sym,
            target_func=target_func,
            rename_file=True,
            new_filename=new_file,
            dry_run=dry_run,
        )
    except FileExistsError as exc:
        error_exit(str(exc), json_mode=json_output)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)

    if json_output:
        json_print(
            {
                "old_name": actual_old_name,
                "new_name": target_func,
                "new_symbol": f"_{new_name}",
                "va": f"0x{va:08x}",
                "files_updated": updated,
                "dry_run": dry_run,
            }
        )
    else:
        if dry_run:
            console.print(f"[dim]Would update cross-references in {updated} files:[/dim]")
            pattern = re.compile(r"\b" + re.escape(actual_old_name) + r"\b")
            for p in _collect_matching_files(cfg, filepath, pattern):
                console.print(f"  [dim]- {rel_display_path(p, cfg.root)}[/dim]")
        else:
            console.print(f"Updated cross-references in {updated} files.")
        console.print("[green]Done![/green]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
