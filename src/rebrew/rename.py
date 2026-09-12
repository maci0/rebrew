"""rename.py - Rename a function and update all cross-references.

Renames a function across the entire codebase: updates ``// FUNCTION:``,
``extern`` declarations, the C function definition, the source file name (optional),
and any other references discovered by scanning the reversed directory.
"""

import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.catalog import scan_reversed_dir
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    require_config,
)
from rebrew.rename_ops import (
    collect_matching_files,
    rename_function_everywhere,
    substitute_name,
)
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
    data: bool = typer.Option(
        False,
        "--data",
        help="Rename a DATA/GLOBAL symbol instead of a function (no file rename)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rename a function and update all cross-references."""
    cfg = require_config(target=target, json_mode=json_output)

    if data:
        _rename_data(cfg, target_ident, new_name, dry_run, json_output)
        return

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

    # Exactly one leading underscore (MSVC's cdecl decoration): a function
    # genuinely named `_foo` carries `__foo`, and `lstrip("_")` searched for
    # `foo` — renaming an unrelated function instead of this one.
    actual_old_name = old_sym.removeprefix("_") if old_sym.startswith("_") else old_name
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
            for p in collect_matching_files(cfg, filepath, pattern):
                console.print(f"  [dim]- {rel_display_path(p, cfg.root)}[/dim]")
        else:
            console.print(f"Updated cross-references in {updated} files.")
        console.print("[green]Done![/green]")


def _rename_data(
    cfg: Any, target_ident: str, new_name: str, dry_run: bool, json_output: bool
) -> None:
    """Rename a DATA/GLOBAL symbol: metadata name + declaration + references.

    No file rename (data symbols don't own files) and no STATUS semantics
    (data verdicts are VERIFIED/DRIFT, unaffected by a label change).
    """
    from rebrew.data_metadata import get_data_entry, load_data_metadata, set_data_field

    if not new_name.isidentifier() or new_name in _C_KEYWORDS:
        error_exit(
            f"'{new_name}' is not a valid C identifier — use letters, digits, "
            "and underscores (not starting with a digit, not a C keyword).",
            json_mode=json_output,
        )

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    data_entries = [e for e in entries if getattr(e, "marker_type", "") in ("DATA", "GLOBAL")]

    va_ident: int | None = None
    if target_ident.lower().startswith("0x"):
        try:
            va_ident = int(target_ident, 16)
        except ValueError:
            va_ident = None
    matches = []
    for e in data_entries:
        va = getattr(e, "va", 0)
        fp = getattr(e, "filepath", "")
        stored_name = str(
            get_data_entry(cfg.metadata_dir, va, getattr(e, "module", "") or "").get("name") or ""
        )
        if target_ident in (stored_name, f"0x{va:x}", f"0x{va:X}", str(va), str(fp)) or (
            va_ident is not None and va == va_ident
        ):
            matches.append(e)
    # Metadata-only entry: the VA has a name in rebrew-data.toml but no
    # marker in the tree (e.g. an $SG string constant referenced only by
    # address).  Rename the metadata name; references are rewritten by the
    # old-name pattern when the old name occurs in sources, if it occurs
    # nowhere the rename is metadata-only.
    metadata_only: tuple[int, str] | None = None
    if not matches:
        metadata = load_data_metadata(cfg.metadata_dir)
        for (module, va), fields in metadata.items():
            stored_name = str(fields.get("name") or "")
            if not stored_name:
                continue
            if target_ident in (stored_name, f"0x{va:x}", f"0x{va:X}", str(va)) or (
                va_ident is not None and va == va_ident
            ):
                if metadata_only is not None:
                    error_exit(
                        f"Found multiple metadata matches for '{target_ident}'. Be more specific.",
                        json_mode=json_output,
                    )
                metadata_only = (va, module)
    if not matches and metadata_only is None:
        error_exit(f"Could not find DATA/GLOBAL matching '{target_ident}'", json_mode=json_output)
    if len(matches) > 1:
        error_exit(
            f"Found {len(matches)} matches for '{target_ident}'. Be more specific.",
            json_mode=json_output,
        )
    if metadata_only is not None:
        va, module = metadata_only
        old_name = str(get_data_entry(cfg.metadata_dir, va, module).get("name") or "")
        _rename_metadata_only(cfg, va, module, old_name, new_name, dry_run, json_output)
        return
    match = matches[0]
    va = getattr(match, "va", 0)
    module = getattr(match, "module", "") or ""
    old_fp = getattr(match, "filepath", "")
    old_name = str(get_data_entry(cfg.metadata_dir, va, module).get("name") or "")
    if not old_name:
        error_exit(
            f"DATA/GLOBAL 0x{va:x} has no name in rebrew-data.toml — "
            "name it first (rebrew data --json), then rename.",
            json_mode=json_output,
        )

    # Collision guard: the linker sees one namespace — refuse when any
    # function or data symbol already uses the new name (data names come
    # from the metadata store, not the annotation).
    for e in entries:
        if e is match:
            continue
        if getattr(e, "name", "") == new_name or getattr(e, "symbol", "") in (
            new_name,
            f"_{new_name}",
        ):
            error_exit(
                f"'{new_name}' is already used by {getattr(e, 'filepath', '?')} — "
                "renaming would create a duplicate symbol. Pick a different name.",
                json_mode=json_output,
            )
        if getattr(e, "marker_type", "") in ("DATA", "GLOBAL"):
            other = str(
                get_data_entry(
                    cfg.metadata_dir, getattr(e, "va", 0), getattr(e, "module", "") or ""
                ).get("name")
                or ""
            )
            if other == new_name:
                error_exit(
                    f"'{new_name}' is already used by {getattr(e, 'filepath', '?')} — "
                    "renaming would create a duplicate symbol. Pick a different name.",
                    json_mode=json_output,
                )

    # `_name_pattern`, not a bare `\b...\b`: `\b` never matches before a leading
    # `$`, so a `$SG…` data name matched nothing while the metadata was renamed
    # anyway (the tool still reported success).
    pattern = _name_pattern(old_name)
    if not old_fp:
        error_exit(
            f"DATA/GLOBAL '{old_name}' has no source file — cannot rewrite references.",
            json_mode=json_output,
        )
    filepath = cfg.reversed_dir / old_fp
    files = collect_matching_files(cfg, filepath, pattern)
    if dry_run:
        if json_output:
            json_print(
                {
                    "old_name": old_name,
                    "new_name": new_name,
                    "va": f"0x{va:08x}",
                    "files_updated": len(files),
                    "dry_run": True,
                }
            )
        else:
            console.print(f"[dim]Dry run:[/dim] Would rename {old_name} → {new_name}")
            for p in files:
                console.print(f"  [dim]- {rel_display_path(p, cfg.root)}[/dim]")
        return

    from rebrew.utils import atomic_write_text, read_source_text

    updated = 0
    for src in files:
        try:
            content, encoding = read_source_text(src)
        except OSError:
            continue
        new_content = substitute_name(_name_pattern(old_name), new_name, content)
        if new_content != content:
            try:
                atomic_write_text(src, new_content, encoding=encoding)
                updated += 1
            except (OSError, UnicodeEncodeError):
                # An undefined byte in the source's encoding (e.g. CP1252 0x81
                # read back with errors="replace" as U+FFFD) makes the write
                # raise UnicodeEncodeError; catching only OSError let it escape
                # as a traceback mid-rename.
                error_exit(f"Cannot write {src}", json_mode=json_output)
    # `old_name` came from this same store (see above), so there is no
    # source-vs-metadata disagreement to resolve here — the field is renamed
    # unconditionally after the cross-references were rewritten.
    set_data_field(cfg.metadata_dir, va, "name", new_name, module)
    if json_output:
        json_print(
            {
                "old_name": old_name,
                "new_name": new_name,
                "va": f"0x{va:08x}",
                "files_updated": updated,
                "dry_run": False,
            }
        )
    else:
        console.print(f"Updated cross-references in {updated} files.")
        console.print("[green]Done![/green]")


def _rename_metadata_only(
    cfg: Any, va: int, module: str, old_name: str, new_name: str, dry_run: bool, json_output: bool
) -> None:
    """Rename a metadata-only DATA entry (no marker in the tree).

    Writes the new name to rebrew-data.toml and rewrites occurrences of the
    old name across the reversed sources when any exist (e.g. an address
    comment or a use site); a name that occurs nowhere is a pure metadata
    rename.  The metadata collision guard from the marker path applies.
    """
    from rebrew.data_metadata import set_data_field
    from rebrew.sources import iter_sources
    from rebrew.utils import atomic_write_text, read_source_text

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    for e in entries:
        if e is not None and getattr(e, "name", "") == new_name:
            error_exit(
                f"'{new_name}' is already used by {getattr(e, 'filepath', '?')} — "
                "renaming would create a duplicate symbol. Pick a different name.",
                json_mode=json_output,
            )
    try:
        from rebrew.data_metadata import load_data_metadata

        for (mod, _va), fields in load_data_metadata(cfg.metadata_dir).items():
            if (mod, _va) != (module, va) and str(fields.get("name") or "") == new_name:
                error_exit(
                    f"'{new_name}' is already used by DATA/GLOBAL 0x{_va:x} — "
                    "renaming would create a duplicate symbol. Pick a different name.",
                    json_mode=json_output,
                )
    except OSError:
        pass

    pattern = _name_pattern(old_name)
    files: list[Path] = []
    for src in iter_sources(cfg.reversed_dir, cfg):
        try:
            text, _ = read_source_text(src)
        except (OSError, UnicodeDecodeError):
            continue
        if pattern.search(text):
            files.append(src)

    if dry_run:
        if json_output:
            json_print(
                {
                    "old_name": old_name,
                    "new_name": new_name,
                    "va": f"0x{va:08x}",
                    "files_updated": len(files),
                    "metadata_only": True,
                    "dry_run": True,
                }
            )
        else:
            console.print(
                f"[dim]Dry run:[/dim] Would rename {old_name} → {new_name} (metadata-only)"
            )
            for p in files:
                console.print(f"  [dim]- {rel_display_path(p, cfg.root)}[/dim]")
        return

    updated = 0
    for src in files:
        try:
            content, encoding = read_source_text(src)
        except OSError:
            continue
        new_content = pattern.sub(lambda _m: new_name, content)
        if new_content != content:
            try:
                atomic_write_text(src, new_content, encoding=encoding)
                updated += 1
            except OSError:
                error_exit(f"Cannot write {src}", json_mode=json_output)
    set_data_field(cfg.metadata_dir, va, "name", new_name, module)
    if json_output:
        json_print(
            {
                "old_name": old_name,
                "new_name": new_name,
                "va": f"0x{va:08x}",
                "files_updated": updated,
                "metadata_only": True,
                "dry_run": False,
            }
        )
    else:
        console.print(f"Updated cross-references in {updated} files.")
        console.print("[green]Done![/green]")


def _name_pattern(old_name: str) -> re.Pattern[str]:
    """Word-boundary pattern for *old_name*, tolerant of non-word lead chars.

    ``\\b`` never matches before a leading ``$`` (``$SG123``), so compiler-
    emitted names would silently miss every occurrence.  A lookbehind covers
    both cases: the char before must not be a word char or ``$``.
    """
    return re.compile(r"(?<![\w$])" + re.escape(old_name) + r"\b")


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
