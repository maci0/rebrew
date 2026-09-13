"""imports.py — Import-table symbol recovery (library identification).

Parses an import table via LIEF — a PE's DLL name → API name → IAT slot VA, or
an ELF's DT_NEEDED libraries and undefined dynamic symbols — and detects the
classic MSVC import stubs in ``.text``: ``jmp dword ptr [iat]`` sequences
(``FF 25 <va>``).  Together these name the library functions a target binary
imports — the first half of the "library identification" pass (the FLIRT half
lives in :mod:`rebrew.flirt` and needs ``.sig`` files).

Usage:
    rebrew imports [binary]
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import EXIT_ERROR, TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)


def parse_imports(binary_path: Path) -> list[dict[str, Any]]:
    """Parse the import table of *binary_path* — the PE import table or the
    ELF dynamic imports via LIEF, or the 16-bit NE module/name imports via the
    native NE loader.

    Returns a list of ``{"dll": str, "name": str, "iat_va": int, "ordinal":
    int | None}`` records, one per imported API (``name`` is
    ``ordinal_<N>`` and ``ordinal`` is N for a PE import by ordinal), or one
    per referenced module with an empty ``name`` when a 16-bit NE carries no
    classic import table, or for an ELF's DT_NEEDED library entries, which
    precede its symbols.  ``iat_va`` is 0 for NE imports (Win16 uses
    per-segment thunks, not an IAT).  Empty list for unrecognized files or
    parse failures.
    """
    from rebrew.binary_loader import is_ne, load_binary

    if is_ne(binary_path):
        try:
            info = load_binary(binary_path)
        except (OSError, KeyError, ValueError):
            return []
        ne_out: list[dict[str, Any]] = []
        for mod in getattr(info, "ne_imports", []) or []:
            if mod.imports:
                for imp in mod.imports:
                    name = imp.name if imp.name is not None else f"ordinal_{imp.ordinal}"
                    ne_out.append({"dll": mod.module, "name": name, "iat_va": 0})
            else:
                # Module reference with no per-API detail (many Win16 binaries
                # carry no classic import table) — still report the module so
                # the DLL set is visible.
                ne_out.append({"dll": mod.module, "name": "", "iat_va": 0})
        return ne_out

    import lief

    if lief.is_elf(str(binary_path)):
        try:
            elf = lief.ELF.parse(str(binary_path))
        except Exception:  # best-effort symbol recovery: LIEF raises on a malformed image
            return []
        return [] if elf is None else elf_import_records(elf)

    try:
        pe = lief.PE.parse(str(binary_path))
    except Exception:  # best-effort symbol recovery
        return []
    if pe is None:
        return []
    imagebase = int(pe.optional_header.imagebase)
    out: list[dict[str, Any]] = []
    for entry in pe.imports:
        for fn in entry.entries:
            # An ordinal-only import (MFC's DLLs import by ordinal almost
            # exclusively) has no name in the hint/name table; naming it
            # ``ordinal_<N>`` keeps the IAT slot visible instead of dropping
            # it, and ``ordinal`` lets callers re-derive the linker's
            # ``__imp_<dll>_ord<N>`` spelling.  0 means a named import.
            ordinal = int(getattr(fn, "ordinal", 0) or 0)
            out.append(
                {
                    "dll": str(entry.name),
                    "name": str(fn.name) if fn.name else f"ordinal_{ordinal}",
                    "iat_va": int(fn.iat_address) + imagebase,
                    "ordinal": ordinal or None,
                }
            )
    return out


def elf_import_records(elf: Any) -> list[dict[str, Any]]:
    """Build the import records of a parsed LIEF ELF binary.

    One record per DT_NEEDED library in declaration order (``name`` empty, the
    module reference), then one per undefined dynamic symbol.  A symbol's
    ``dll`` is the library whose version requirement covers the version the
    symbol asks for; an image that declares none for a symbol leaves it
    unattributed rather than guessing, because DT_NEEDED names the libraries
    but never says which of them exports which symbol.
    """
    import lief

    libraries = [
        str(entry.name)
        for entry in elf.dynamic_entries
        if entry.tag == lief.ELF.DynamicEntry.TAG.NEEDED
    ]
    out: list[dict[str, Any]] = [{"dll": library, "name": "", "iat_va": 0} for library in libraries]
    slots = _elf_import_slots(elf)
    versions = _elf_version_libraries(elf)
    for symbol in elf.imported_symbols:
        name = str(symbol.name or "")
        if not name:
            continue
        out.append(
            {
                "dll": versions.get(_elf_symbol_version(symbol), ""),
                "name": name,
                "iat_va": slots.get(name, 0),
            }
        )
    return out


def _elf_symbol_version(symbol: Any) -> str:
    """The version name an ELF symbol requires, or ``""`` when it requires none."""
    version = getattr(symbol, "symbol_version", None)
    if version is None or not getattr(version, "has_auxiliary_version", False):
        return ""
    auxiliary = getattr(version, "symbol_version_auxiliary", None)
    return str(getattr(auxiliary, "name", "") or "")


def _elf_version_libraries(elf: Any) -> dict[str, str]:
    """Map every declared version name to the library that declares it.

    ``.gnu.version_r`` groups its version names by library, the only place an
    image states which library a versioned symbol comes from.
    """
    out: dict[str, str] = {}
    for requirement in getattr(elf, "symbols_version_requirement", None) or []:
        library = str(getattr(requirement, "name", "") or "")
        try:
            version_names = [str(aux.name or "") for aux in requirement.get_auxiliary_symbols()]
        except Exception:  # a malformed version table must not cost the whole import list
            continue
        for version_name in version_names:
            if version_name:
                out.setdefault(version_name, library)
    return out


def _elf_import_slots(elf: Any) -> dict[str, int]:
    """Map each imported symbol to the lowest address a relocation references it at.

    A dynamic image resolves an imported symbol through one GOT (or PLT) slot
    per reference; the lowest address is the slot an xref will reach, and the
    address is link-time, so a PIE's values are image-relative.
    """
    out: dict[str, int] = {}
    for relocation in getattr(elf, "relocations", None) or []:
        if not getattr(relocation, "has_symbol", False):
            continue
        name = str(relocation.symbol.name or "")
        if not name:
            continue
        address = int(relocation.address)
        if name not in out or address < out[name]:
            out[name] = address
    return out


def parse_import_table(binary_path: Path) -> dict[int, str]:
    """Return ``{iat_va: api_name}`` for *binary_path* (convenience view)."""
    return {rec["iat_va"]: rec["name"] for rec in parse_imports(binary_path)}


def find_import_stubs(binary_path: Path) -> dict[int, str]:
    """Detect ``jmp dword ptr [iat]`` import stubs in ``.text``.

    Returns ``{stub_va: api_name}`` for every ``FF 25 <iat_va>`` sequence
    whose target matches the import table.  These stubs are what the linker
    generates for each imported API, so the VA maps 1:1 to a function.
    """
    table = parse_import_table(binary_path)
    if not table:
        return {}
    from rebrew.binary_loader import load_binary

    try:
        info = load_binary(binary_path)
    except (OSError, KeyError, ValueError):
        return {}
    text = info.sections.get(".text")
    if text is None:
        return {}
    blob = info.data[text.file_offset : text.file_offset + text.size]
    stubs: dict[int, str] = {}
    for i in range(len(blob) - 5):
        if blob[i] != 0xFF or blob[i + 1] != 0x25:
            continue
        target = struct.unpack("<I", blob[i + 2 : i + 6])[0]
        name = table.get(target)
        if name is not None:
            stubs[text.va + i] = name
    return stubs


def imports_payload(
    binary_path: Path,
    stubs: dict[int, str] | None = None,
) -> dict[str, Any]:
    """Build the ``--json`` payload for ``rebrew imports``.

    Combines :func:`parse_imports` with the ``jmp dword ptr [iat]`` stub map
    *stubs* (computed via :func:`find_import_stubs` when omitted) into the
    exact object ``rebrew imports --json`` prints: one record per imported API
    with a hex ``iat_va`` string, and one stub record per detected import
    thunk with a hex ``va`` string.  An unrecognized or unparseable binary
    yields empty ``imports`` / ``stubs`` lists, never an exception.
    """
    if stubs is None:
        stubs = find_import_stubs(binary_path)
    return {
        "binary": str(binary_path),
        "imports": [
            {
                "dll": i["dll"],
                "name": i["name"],
                "iat_va": f"0x{i['iat_va']:08x}",
            }
            for i in parse_imports(binary_path)
        ],
        # Stub VAs as hex strings (matching every other rebrew JSON)
        # instead of decimal stringified dict keys.
        "stubs": [{"va": f"0x{va:08x}", "name": name} for va, name in sorted(stubs.items())],
    }


def mark_import_stubs(
    cfg: Any,
    stubs: dict[int, str],
    *,
    dry_run: bool = False,
) -> int:
    """Write ``// LIBRARY: <marker> 0xVA`` annotations for import stubs.

    Appends to ``<reversed_dir>/library_imports.h`` (created if missing),
    skipping VAs that already carry an annotation.  Returns the number of
    NEW annotations written.  Completes the library-identification loop:
    import stubs detected in .text become LIBRARY functions that
    ``rebrew crt-match`` can then attribute to CRT sources.
    """
    marker = getattr(cfg, "marker", "") or getattr(cfg, "target_name", "GAME")
    out_file = Path(cfg.reversed_dir) / "library_imports.h"
    existing = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else ""

    blocks: list[str] = []
    for va in sorted(stubs):
        if f"0x{va:08X}".upper() in existing.upper():
            continue
        blocks.append(f"// LIBRARY: {marker} 0x{va:08X}\n// {stubs[va]}\n")
    if not blocks:
        console.print("No new import stubs to annotate.")
        return 0

    if dry_run:
        console.print(
            f"[dim]Dry run:[/dim] would add {len(blocks)} LIBRARY annotation(s) to {out_file.name}:"
        )
        for block in blocks:
            console.print(f"  [dim]{block.strip()}[/]")
        return len(blocks)

    # The banner is written once, on creation; re-runs only append new blocks.
    body = "\n".join(blocks)
    if existing.strip():
        text = existing.rstrip("\n") + "\n\n" + body
    else:
        text = "/* Auto-generated by rebrew imports --mark. DO NOT EDIT. */\n\n" + body
    from rebrew.utils import atomic_write_text

    atomic_write_text(out_file, text, encoding="utf-8")
    console.print(f"[green]Annotated {len(blocks)} import stub(s) in {out_file.name}[/green]")
    return len(blocks)


app = typer.Typer(
    help="List import-table symbols (PE IAT, ELF dynamic imports, or 16-bit NE modules) and detect import stubs.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew imports · · · · · · · · · · · · Use the project's target binary\n\n"
        "  rebrew imports original/game.exe · · · Scan a specific binary\n\n"
        "  rebrew imports game.exe --json · · · Machine-readable output\n\n"
        "[bold]What it shows:[/bold]\n\n"
        "  IAT VA · · · · · · · · Virtual address of the imported function slot\n\n"
        "  API name · · · · · · · e.g. MessageBoxA (from KERNEL32.dll)\n\n"
        "  Import stubs · · · · · jmp dword ptr [iat] functions in .text\n\n"
        "[dim]Part of the library-identification workflow: pair with rebrew flirt "
        "(FLIRT signatures) to name statically-linked CRT/zlib functions.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    binary: Path | None = typer.Argument(None, help="Binary path (default: project target)"),
    mark: bool = typer.Option(
        False, "--mark", help="Write LIBRARY annotations for detected import stubs"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Scan a binary's import table and report its imported APIs."""
    cfg: Any = None
    if binary is None or mark:
        cfg = require_config(target=target, json_mode=json_output)
    if binary is None:
        binary = cfg.target_binary
        if not binary.exists():
            error_exit(f"target binary missing: {binary}", json_mode=json_output, code=2)
    if not binary.exists():
        error_exit(f"binary not found: {binary}", json_mode=json_output)

    imports = parse_imports(binary)
    stubs = find_import_stubs(binary)

    if mark:
        if json_output:
            # --mark writes annotations; --json promises machine output that
            # mark_import_stubs does not produce.  Refuse the combination
            # instead of silently dropping --json.
            error_exit(
                "--mark writes annotations and is not JSON-output compatible; "
                "use --json alone to list imports, or --mark alone to write.",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
        mark_import_stubs(cfg, stubs, dry_run=dry_run)
        return

    if json_output:
        json_print(imports_payload(binary, stubs))
        return

    if dry_run:
        console.print("[dim]--dry-run only applies with --mark; nothing to preview.[/dim]")

    if not imports:
        console.print(f"[yellow]No import table found in {binary}.[/]")
        return
    console.print(f"[bold]{len(imports)}[/] imported APIs from [bold]{binary}[/]:")
    for rec in sorted(imports, key=lambda r: r["iat_va"]):
        if rec["name"]:
            console.print(f"  0x{rec['iat_va']:08x}  {rec['name']:30s}  {rec['dll']}")
        else:
            # Module-level record: a 16-bit NE without a classic import table,
            # or an ELF library no versioned symbol was attributed to.
            console.print(f"  [dim]0x00000000  {rec['dll']:30s} (module reference)[/dim]")
    if stubs:
        console.print(f"\n[bold]{len(stubs)}[/] import stubs found in .text:")
        for va, name in sorted(stubs.items()):
            console.print(f"  0x{va:08x}  jmp [{name}]")


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
