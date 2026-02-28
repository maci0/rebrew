"""rename.py - Rename a function and update all cross-references.

Renames a function across the entire codebase: updates ``// FUNCTION:``,
``// SYMBOL:``, ``extern`` declarations, the source file name (optional),
and any other references discovered by scanning the reversed directory.
"""

import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import update_annotation_key
from rebrew.catalog import scan_reversed_dir
from rebrew.cli import TargetOption, error_exit, get_config, iter_sources

app = typer.Typer(
    help="Rename a function and update cross-references.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew rename old_func new_func                  Rename function

rebrew rename src/game/old.c new_func            Rename by file path

rebrew rename 0x10003da0 new_func                Rename by VA

rebrew rename old_func new_func --symbol _New    Custom SYMBOL annotation

rebrew rename old_func new_func --file new.c     Custom filename

[dim]Updates FUNCTION/SYMBOL annotations, function definitions, extern
declarations, and optionally renames the source file.[/dim]""",
)
console = Console()


def rename_function_everywhere(
    cfg: Any,
    filepath: Path,
    va: int,
    old_name: str,
    old_sym: str,
    target_func: str,
    target_sym: str,
    rename_file: bool = True,
    new_filename: str | None = None,
    dry_run: bool = False,
) -> int:
    """Perform a full cross-reference rename. Returns number of files modified."""

    actual_old_name = old_sym.lstrip("_") if old_sym.startswith("_") else old_name
    updated_files = 0

    if dry_run:
        return 1  # Just a fake count

    # 1. Update SYMBOL annotation
    if update_annotation_key(filepath, va, "SYMBOL", target_sym):
        pass  # updated

    # 2. Update function definition & calls in file
    try:
        content = filepath.read_text(encoding="utf-8")
        # Replace occurrences of actual_old_name
        # Match whole words to avoid partial matches
        new_content = re.sub(r"\b" + re.escape(actual_old_name) + r"\b", target_func, content)
        if new_content != content:
            filepath.write_text(new_content, encoding="utf-8")
            updated_files += 1
    except OSError:
        pass

    # 3. Find and update externs across all files
    for src_file in iter_sources(cfg.reversed_dir, cfg):
        if src_file == filepath:
            continue

        try:
            content = src_file.read_text(encoding="utf-8")
            new_content = re.sub(r"\b" + re.escape(actual_old_name) + r"\b", target_func, content)
            if new_content != content:
                src_file.write_text(new_content, encoding="utf-8")
                updated_files += 1
        except OSError:
            pass

    # 4. Rename file if needed
    if rename_file:
        if new_filename:
            if not new_filename.endswith(filepath.suffix):
                new_filename = new_filename + filepath.suffix
            target_file = cfg.reversed_dir / new_filename
        else:
            stem = filepath.stem
            if stem in (actual_old_name, old_sym):
                target_file = filepath.with_name(f"{target_func}{filepath.suffix}")
            else:
                target_file = filepath

        if target_file != filepath:
            if target_file.exists():
                raise FileExistsError(
                    f"Cannot rename {filepath.name} → {target_file.name}: "
                    f"target already exists (different VA). "
                    f"Use --file to pick a different filename."
                )
            filepath.rename(target_file)

    return updated_files


@app.callback(invoke_without_command=True)
def main(
    target_ident: str = typer.Argument(..., help="Old function name, file path, or VA"),
    new_name: str = typer.Argument(..., help="New function name"),
    symbol: str | None = typer.Option(
        None, "--symbol", help="New SYMBOL annotation (default: _new_name)"
    ),
    new_file: str | None = typer.Option(None, "--file", help="New filename"),
    target: str | None = TargetOption,
) -> None:
    """Rename a function and update all cross-references."""
    cfg = get_config(target=target)

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    matches = []
    for e in entries:
        name = getattr(e, "name", "")
        sym = getattr(e, "symbol", "")
        fp = getattr(e, "filepath", "")
        va = getattr(e, "va", 0)

        va_str = f"0x{va:x}"
        va_str_upper = f"0x{va:X}"
        if target_ident in (name, sym, str(fp), Path(str(fp)).name, va_str, va_str_upper, str(va)):
            matches.append(e)

    if not matches:
        error_exit(f"Could not find function matching '{target_ident}'")

    if len(matches) > 1:
        error_exit(f"Found {len(matches)} matches for '{target_ident}'. Be more specific.")

    match = matches[0]
    old_name = getattr(match, "name", "")
    old_sym = getattr(match, "symbol", "")
    old_fp = getattr(match, "filepath", "")
    va = getattr(match, "va", 0)

    if not old_sym:
        old_sym = old_name

    actual_old_name = old_sym.lstrip("_") if old_sym.startswith("_") else old_name

    target_sym = symbol if symbol else f"_{new_name}"
    target_func = new_name

    filepath = cfg.reversed_dir / old_fp

    console.print(f"Renaming {actual_old_name} to {target_func}...")

    try:
        updated = rename_function_everywhere(
            cfg=cfg,
            filepath=filepath,
            va=va,
            old_name=old_name,
            old_sym=old_sym,
            target_func=target_func,
            target_sym=target_sym,
            rename_file=True,
            new_filename=new_file,
        )
    except FileExistsError as exc:
        error_exit(str(exc))

    console.print(f"Updated cross-references in {updated} files.")
    console.print("[green]Done![/green]")


def main_entry() -> None:
    """Package entry point for ``rebrew-rename``."""
    app()
