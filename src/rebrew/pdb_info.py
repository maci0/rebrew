"""rebrew binary pdb show — extract compiler version, flags, and function names from a PDB.

When a target binary ships a sibling ``.pdb``, the PDB's debug info is the
most authoritative offline source of the *exact* build configuration:

- ``S_COMPILE3`` record — compiler frontend/backend versions and the record's
  ``flags`` field.  llvm-pdbutil prints that field as *symbolic* switches
  (``none``, or ``sdl | pgo | ltcg``) — it is a CodeView bitmask
  (``CompileSym3Flags``), not a command line; only tokens that look like
  compiler options (``/O1``, ``-MT``) count as CFLAGS candidates, and
  ``rebrew binary pdb import-cflags`` refuses to write a symbolic switch list into the config.
- ``S_GPROC32``/``S_LPROC32`` records — function names (and best-effort
  addresses/sizes) for the discovery inventory.
- module list — a ``.zig-cache`` path identifies a Zig build.

Parsing goes through ``llvm-pdbutil`` (LLVM's PDB dumper).  Note llvm-pdbutil
supports PDB 7.0+ (VC7+ and modern compilers); classic VC2–6 PDBs are a
different format it cannot read, and it has a known crash on some VC7 PDBs —
both are handled gracefully (reported as unsupported, never an exception).

Usage::

    rebrew binary pdb show original/game.exe
    rebrew binary pdb import-cflags game.exe # set [compiler] cflags from S_COMPILE3
"""

from __future__ import annotations

import logging
from pathlib import Path

import typer
lazy import tomlkit

from rebrew.formats.pdb import (
    PdbInfo,
    parse_compile3,
    parse_procs,
)
from rebrew.formats.pdb import (
    extract_pdb_info as _extract_pdb_info,
)
lazy from rebrew.cli import console, error_exit, json_print, untrusted_ident
lazy from rebrew.utils import run_process_group

_parse_compile3 = parse_compile3
_parse_procs = parse_procs

log = logging.getLogger(__name__)

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  # Report compiler version, flags, names\n"
    "  rebrew binary pdb show original/game.exe\n\n"
    "  # Record the flags in the metadata\n"
    "  rebrew binary pdb import-cflags original/game.exe\n\n"
    "  # Plan the write, change nothing\n"
    "  rebrew binary pdb import-cflags game.exe --dry-run --json\n"
)


app = typer.Typer(
    help="Extract compiler version, flags, and function names from a PDB.",
    epilog=_EPILOG,
)


def extract_pdb_info(binary: Path) -> PdbInfo | None:
    """Extract PDB facts for *binary*; None when no PDB or no usable tooling."""
    return _extract_pdb_info(binary, runner=run_process_group)


def inspect_pdb(
    binary: str, write_cflags: bool = False, dry_run: bool = False, json_output: bool = False
) -> None:
    """Report compiler version, flags, and function names from the PDB."""
    bin_path = Path(binary)
    if not bin_path.exists():
        msg = f"binary not found: {bin_path}"
        error_exit(msg, json_mode=json_output)

    info = extract_pdb_info(bin_path)
    if info is None:
        error_exit("no sibling .pdb found", json_mode=json_output)

    payload = {
        "pdb": str(info.pdb),
        "toolchain": info.toolchain or "unknown",
        "frontend": info.frontend,
        "backend": info.backend,
        "flags": info.flags,
        "function_count": len(info.functions),
        "functions": info.functions[:20],
        "error": info.error,
    }

    if write_cflags and info.flags and not info.error:
        # The S_COMPILE3 `flags` field is a symbolic CodeView bitmask list
        # ("sdl | pgo | ltcg"), not a command line: writing it as CFLAGS put
        # junk options into [compiler] and broke every later compile.  Only
        # option-looking tokens are CFLAGS candidates.
        candidates = [f for f in info.flags if f.startswith(("/", "-"))]
        cfg_path = Path("rebrew-project.toml")
        if not candidates:
            payload["cflags_write"] = (
                "skipped: S_COMPILE3 flags are compiler switches "
                f"({' | '.join(info.flags)}), not command-line CFLAGS"
            )
        elif not cfg_path.exists():
            payload["cflags_write"] = "skipped: no rebrew-project.toml in cwd"
        elif dry_run:
            payload["cflags_write"] = "dry-run: " + " ".join(candidates)
        else:
            from rebrew.cfg import load_toml, save_toml

            doc, toml_path = load_toml(cfg_path.parent, json_mode=json_output)
            comp = doc.get("compiler")
            if comp is None:
                comp = tomlkit.table()
                doc["compiler"] = comp
            if isinstance(comp, dict):
                comp["cflags"] = " ".join(candidates)
                save_toml(doc, toml_path, json_mode=json_output)
                payload["cflags_write"] = " ".join(candidates)
            else:
                payload["cflags_write"] = "skipped: [compiler] is not a table"

    if json_output:
        json_print(payload)
    else:
        console.print(f"[bold]PDB:[/bold] {untrusted_ident(info.pdb.name)}")
        console.print(f"  toolchain: {info.toolchain or 'unknown'}")
        if info.frontend:
            console.print(
                f"  compiler: frontend {untrusted_ident(info.frontend)} "
                f"/ backend {untrusted_ident(info.backend)}"
            )
        if info.flags:
            console.print(
                f"  flags: [green]{untrusted_ident(' '.join(info.flags))}[/green] (candidate CFLAGS)"
            )
        console.print(f"  functions: {len(info.functions)}")
        for fn in info.functions[:10]:
            console.print(f"    - {untrusted_ident(fn['name'])}")
        if info.error:
            console.print(f"  [yellow]{info.error}[/yellow]")
        if "cflags_write" in payload:
            console.print(f"  cflags write: {untrusted_ident(payload['cflags_write'])}")


@app.command(
    "show",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binary pdb show original/game.exe --json\n\n"
        "Reads the binary and its sibling PDB to report compiler and function evidence."
    ),
)
def show(
    binary: str = typer.Argument(
        ...,
        help="Path to the binary whose sibling .pdb to read",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show PDB compiler evidence and function names."""
    inspect_pdb(binary=binary, json_output=json_output)


@app.command(
    "import-cflags",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binary pdb import-cflags original/game.exe --dry-run --json\n\n"
        "Previews verified PDB command-line flags before recording them in function metadata."
    ),
)
def import_cflags(
    binary: str = typer.Argument(
        ...,
        help="Path to the binary whose sibling .pdb to read",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Import verified command-line flags from PDB evidence."""
    inspect_pdb(binary=binary, dry_run=dry_run, json_output=json_output, write_cflags=True)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
