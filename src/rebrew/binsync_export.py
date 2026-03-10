"""binsync_export.py — Export rebrew annotations to a BinSync state directory.

Writes function metadata, global variables, and struct placeholders in
BinSync's TOML layout so any BinSync-aware decompiler plugin can import the
project's reverse-engineering artifacts.

Layout produced::

    <outdir>/
        functions/
            <hex>.toml   -- one per function annotation
        global_vars.toml -- DATA/GLOBAL annotations
        structs/
            <name>.toml  -- one per struct annotation

Rebrew-specific fields (STATUS, CFLAGS) have no BinSync counterpart, so they
are stored as structured comments at the function VA::

    [rebrew] STATUS=EXACT CFLAGS=/O1 /Gd
"""

from __future__ import annotations

from pathlib import Path

import tomlkit
import typer
from rich.console import Console

from rebrew.catalog.loaders import scan_reversed_dir
from rebrew.cli import TargetOption, error_exit, json_print, require_config

app = typer.Typer(
    help="Export rebrew annotations to a BinSync state directory.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync-export ./binsync_state · · · · · · Export all annotations\n\n"
        "  rebrew binsync-export ./state --dry-run · · · · · Preview without writing\n\n"
        "  rebrew binsync-export ./state --json · · · · · · · Machine-readable output\n\n"
        "[dim]Produces BinSync-compatible TOML layout: functions/, global_vars.toml. "
        "Rebrew-specific metadata (STATUS, CFLAGS) is preserved in [rebrew] comments.[/dim]"
    ),
)

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rebrew_comment(status: str, cflags: str) -> str:
    """Build the ``[rebrew] STATUS=… CFLAGS=…`` metadata comment string."""
    parts = []
    if status:
        parts.append(f"STATUS={status}")
    if cflags:
        parts.append(f"CFLAGS={cflags}")
    return f"[rebrew] {' '.join(parts)}" if parts else ""


def _strip_body(prototype: str) -> str:
    """Return the function signature without the body (everything before ``{``).

    ``annotation.prototype`` includes the full C definition including its body.
    BinSync's ``[header].type`` expects only the declaration/signature line.
    """
    brace = prototype.find("{")
    return prototype[:brace].strip() if brace != -1 else prototype.strip()


def _write_function_toml(
    path: Path,
    *,
    name: str,
    va: int,
    size: int,
    prototype: str,
    status: str,
    cflags: str,
    note: str,
    ghidra: str,
) -> None:
    """Serialise one function's metadata to a BinSync function TOML file."""
    doc = tomlkit.document()

    # [info] — identity
    info = tomlkit.table()
    info["name"] = name
    info["addr"] = va
    if size > 0:
        info["size"] = size
    doc["info"] = info

    # [header] — C-level type/prototype (signature only, no body)
    sig = _strip_body(prototype) if prototype else ""
    if sig:
        header = tomlkit.table()
        header["type"] = sig
        doc["header"] = header

    # [comments] — rebrew metadata + analyst notes
    # BinSync uses integer keys (addresses) mapped to comment strings.
    comments: dict[int, str] = {}

    rebrew_meta = _rebrew_comment(status, cflags)
    if rebrew_meta:
        comments[va] = rebrew_meta

    if note:
        comments[va + 1] = f"[rebrew:note] {note}"

    # Only include the ghidra name if it differs from the exported symbol name
    if ghidra and ghidra != name:
        comments[va + 2] = f"[rebrew:ghidra] {ghidra}"

    if comments:
        tbl = tomlkit.table()
        for addr, text in sorted(comments.items()):
            tbl[str(addr)] = text
        doc["comments"] = tbl

    path.write_text(tomlkit.dumps(doc), encoding="utf-8")


def _write_global_vars_toml(path: Path, globals_list: list[tuple[int, str, int]]) -> None:
    """Write global_vars.toml from (va, name, size) triples."""
    doc = tomlkit.document()
    for va, name, size in sorted(globals_list):
        entry = tomlkit.table()
        entry["name"] = name
        entry["addr"] = va
        if size > 0:
            entry["size"] = size
        entry["type"] = "char"  # placeholder; real type not available without parsing
        doc[str(va)] = entry
    path.write_text(tomlkit.dumps(doc), encoding="utf-8")


def _write_struct_toml(path: Path, name: str) -> None:
    """Write a minimal BinSync struct placeholder TOML."""
    doc = tomlkit.document()
    info = tomlkit.table()
    info["name"] = name
    doc["info"] = info
    path.write_text(tomlkit.dumps(doc), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    outdir: Path = typer.Argument(..., help="Output directory for the BinSync state"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Export rebrew annotations to a BinSync state directory.

    Produces a ``functions/`` tree, ``global_vars.toml``, and ``structs/``
    placeholders compatible with BinSync's TOML state format.
    """
    cfg = require_config(target=target, json_mode=json_output)

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    if not entries:
        error_exit("No annotations found.", json_mode=json_output)

    # Partition annotations
    func_entries = [e for e in entries if e.marker_type not in ("GLOBAL", "DATA")]
    global_entries = [e for e in entries if e.marker_type in ("GLOBAL", "DATA")]

    # Collect global vars
    globals_list: list[tuple[int, str, int]] = []
    for e in global_entries:
        gname = e.symbol or e.name or f"g_{e.va:08x}"
        globals_list.append((e.va, gname, e.size))

    # Collect struct names from annotations that have a struct field
    struct_names: set[str] = set()
    for e in func_entries:
        if e.struct:
            struct_names.add(e.struct)

    if not dry_run:
        funcs_dir = outdir / "functions"
        funcs_dir.mkdir(parents=True, exist_ok=True)
        structs_dir = outdir / "structs"
        if struct_names:
            structs_dir.mkdir(parents=True, exist_ok=True)

    written_funcs: list[str] = []
    for entry in func_entries:
        va = entry.va
        name = entry.symbol or entry.name or f"func_{va:08x}"

        func_path = outdir / "functions" / f"{va:08x}.toml"
        if not dry_run:
            _write_function_toml(
                func_path,
                name=name,
                va=va,
                size=entry.size,
                prototype=entry.prototype,
                status=entry.status,
                cflags=entry.cflags,
                note=entry.note,
                ghidra=entry.ghidra,
            )
        written_funcs.append(str(func_path))

    written_globals = ""
    if globals_list:
        global_path = outdir / "global_vars.toml"
        if not dry_run:
            _write_global_vars_toml(global_path, globals_list)
        written_globals = str(global_path)

    written_structs: list[str] = []
    for sname in sorted(struct_names):
        spath = outdir / "structs" / f"{sname}.toml"
        if not dry_run:
            _write_struct_toml(spath, sname)
        written_structs.append(str(spath))

    # --- Output ---
    if json_output:
        result: dict[str, object] = {
            "outdir": str(outdir),
            "dry_run": dry_run,
            "functions": len(written_funcs),
            "globals": len(globals_list),
            "structs": len(written_structs),
            "function_files": written_funcs,
            "global_vars_file": written_globals or None,
            "struct_files": written_structs,
        }
        json_print(result)
    else:
        action = "[dim]would write[/dim]" if dry_run else "Wrote"
        console.print(
            f"{action} [bold]{len(written_funcs)}[/bold] functions, "
            f"[bold]{len(globals_list)}[/bold] globals, "
            f"[bold]{len(written_structs)}[/bold] structs "
            f"to [cyan]{outdir}[/cyan]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
