"""switch.py — jump-table switch dispatch decoding.

MSVC compiles ``switch`` statements on 32-bit x86 into a bounds-checked
indirect jump::

    cmp  ecx, 0xb            ; index bounds check
    ja   default
    jmp  dword ptr [edx*4 + 0x1031240]   ; dispatch table

The 32-bit entries at ``0x1031240 + index*4`` are the case-handler
addresses.  ``rebrew binary switches <va>`` locates these dispatches inside a
function and prints the case table — index → handler VA → known function
name — so a jump-table function's structure is visible before writing a
single line of C (the "jump-table switch" category of functions that
manual decompilation has to untangle by hand).

Detection is pattern-based (indirect ``jmp`` through a scaled register
against a table address) and best-effort: functions with no such dispatch
yield an empty result, and unresolvable entries are shown as raw VAs.
"""

from __future__ import annotations

import logging
lazy from typing import Any

import typer

from rebrew.cli import (
    EXIT_OK,
    TargetOption,
    all_items_option,
    console,
    error_exit,
    json_print,
    require_config,
)
lazy from rebrew.jump_table import BOUND_WINDOW, MAX_TABLE_ENTRIES, dispatch_operand, index_bound
lazy from rebrew.utils import TerminalTable, parse_int_literal, untrusted_ident

#: TerminalTable rows shown in the human table before collapsing the rest.
_MAX_TABLE_ROWS = 24


def find_switches(cfg: Any, va: int, window: int = 512) -> list[dict[str, Any]]:
    """Locate jump-table dispatches in the function at *va*.

    Returns a list of dispatch dicts::

        {
            "jmp_va": 0x1031217,        # address of the indirect jmp
            "index_reg": "edx",         # scaled index register
            "table_va": 0x1031240,      # dispatch table address
            "bounds": 0xb,              # max index (cmp reg, N), or None
            "cases": [(0, 0x103121d), ...],  # (index, handler_va)
            "entries": 12,              # table entries read
            "entry_width": 4,           # table entry size in bytes
        }

    Best-effort: empty list when the window has no indirect dispatch.

    The disassembler mode and entry width follow the target arch: 16-bit
    targets decode in 16-bit mode with 2-byte entries, 64-bit targets in
    64-bit mode with 8-byte entries, anything else (or an unknown arch) in
    32-bit mode with 4-byte entries.  16-bit dispatches have no scaled
    index (no SIB byte) — the entry count comes from the bounds check only.
    """
    from rebrew.formats.binary_loader import extract_raw_bytes

    try:
        raw = extract_raw_bytes(cfg.target_binary, va, window)
    except Exception:  # missing/unreadable binary → no dispatch
        logging.getLogger(__name__).debug(
            "switch dispatch read failed at 0x%x from %s",
            va,
            cfg.target_binary,
            exc_info=True,
        )
        return []
    if not raw:
        return []

    import capstone

    from rebrew.analysis import capstone_handle

    arch = str(getattr(cfg, "arch", "") or "")
    if arch == "x86_16":
        cs_mode, entry_width = capstone.CS_MODE_16, 2
    elif arch == "x86_64":
        cs_mode, entry_width = capstone.CS_MODE_64, 8
    else:
        cs_mode, entry_width = capstone.CS_MODE_32, 4
    # ``--all`` calls this once per function; a fresh ``Cs`` per function
    # costs more than decoding the 512-byte window it scans.
    insns = list(capstone_handle(capstone.CS_ARCH_X86, cs_mode).disasm(raw, va))
    if not insns:
        return []

    results: list[dict[str, Any]] = []
    for idx, insn in enumerate(insns):
        if insn.mnemonic != "jmp":
            continue
        operand = dispatch_operand(insn.op_str, entry_width)
        if operand is None:
            continue
        index_reg, table_va = operand
        bounds = index_bound(insns[max(0, idx - BOUND_WINDOW) : idx], index_reg)
        cases = _read_table(cfg, table_va, bounds, entry_width)
        results.append(
            {
                "jmp_va": insn.address,
                "index_reg": index_reg,
                "table_va": table_va,
                "bounds": bounds,
                "cases": cases,
                "entries": len(cases),
                "entry_width": entry_width,
            }
        )
    return results


def _dispatch_operand(index_reg: str | None, table_va: int, entry_width: int) -> str:
    """Render the dispatch operand as decoded, for the human header.

    The width/scale follow the target arch: a 64-bit target reads a qword
    table with a *8 scale, a 16-bit dispatch has no SIB byte (base-only, no
    scale; the index is doubled into the base beforehand), everything else is
    dword with *4.  Printing a fixed ``dword ... *4`` claimed a scale the tool
    had not read on 64-bit and 16-bit targets.
    """
    if entry_width == 8:
        return f"qword ptr [{index_reg}*8 + 0x{table_va:08x}]"
    if entry_width == 2:
        return f"word ptr [{index_reg} + 0x{table_va:08x}]"
    return f"dword ptr [{index_reg}*4 + 0x{table_va:08x}]"


def _read_table(
    cfg: Any, table_va: int, bounds: int | None, entry_width: int = 4
) -> list[tuple[int, int]]:
    """Read the dispatch table entries as ``(index, target_va)`` pairs.

    The entry count is the bounds-check max index + 1 when known, else the
    table is walked until a target lands outside the image (with a safety
    cap).  Returns ``[]`` when the table cannot be read.
    """
    from rebrew.formats.binary_loader import extract_raw_bytes, load_binary

    count = (bounds + 1) if bounds is not None else MAX_TABLE_ENTRIES
    count = max(1, min(count, MAX_TABLE_ENTRIES))
    raw = extract_raw_bytes(cfg.target_binary, table_va, count * entry_width)
    if raw is None or len(raw) < entry_width:
        return []
    import struct

    try:
        info = load_binary(cfg.target_binary)
    except Exception:  # unreadable binary → no table
        logging.getLogger(__name__).debug(
            "switch table load failed for %s", cfg.target_binary, exc_info=True
        )
        return []

    # x86 tables are little-endian, but read the image's own byte order (via
    # arch_byte_order, the same helper data_scan/registry use) so a big-endian
    # image is not byte-reversed.  The arch comes from the image; fall back to
    # the cfg arch, then little-endian (x86 default).
    from rebrew.config import arch_byte_order

    image_arch = str(getattr(info, "arch", "") or "") or str(getattr(cfg, "arch", "") or "")
    image_endian = getattr(info, "endian", "") or ""
    order = arch_byte_order(image_arch, image_endian)
    fmt_char = {2: "H", 4: "I", 8: "Q"}.get(entry_width, "I")
    fmt = f"{order}{fmt_char}"

    entries: list[tuple[int, int]] = []
    for i in range(count):
        off = i * entry_width
        if off + entry_width > len(raw):
            break
        target = struct.unpack_from(fmt, raw, off)[0]
        # Every dispatch entry points into the image (a case handler) —
        # stop at the first that doesn't.  The bounds check is an upper
        # bound; the real table may be shorter (sparse/misread bounds).
        # With a known bound, an invalid leading slot is NOT the end of the
        # table: MSVC's memcpy/memmove byte-tail tables leave slot 0 unused
        # (the alignment guard makes the index >= 1), so it holds leftover
        # bytes that overlap the preceding jmp — skip invalid entries and
        # keep the valid ones at their true indices.
        if not _va_in_image(info, target):
            if bounds is not None:
                continue
            break
        entries.append((i, target))
    return entries


def _va_in_image(info: Any, va: int) -> bool:
    """True when *va* falls inside any section of the binary.

    Containment uses the virtual size (the mapped extent); the raw size is
    the fallback when a section reports no virtual size.
    """
    for section in info.sections.values():
        extent = section.size or section.raw_size
        if section.va <= va < section.va + extent:
            return True
    return False


def _resolve_name(cfg: Any, va: int, func_lookup: dict[int, tuple[str, str]] | None = None) -> str:
    """Function-list / registry name for *va*, or ``""``.

    Building the lookup scans the whole source tree, so callers resolving
    many addresses pass a shared *func_lookup* instead of paying one tree
    scan per address."""
    try:
        if func_lookup is None:
            from rebrew.asm import build_function_lookup

            func_lookup = build_function_lookup(cfg)
        name, _status = func_lookup.get(va, ("", ""))
        return name
    except Exception:  # best-effort naming
        logging.getLogger(__name__).debug("function name lookup failed for 0x%x", va, exc_info=True)
        return ""


app = typer.Typer(
    help="Decode jump-table switch dispatches in a function (case → handler map).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binary switches 0x10311e0  # Show all switch dispatches\n\n"
        "  rebrew binary switches 0x10311e0 --json  # Machine-readable case tables\n\n"
        "  rebrew binary switches 0x10311e0 --window 1024  # Wider disassembly window\n"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    va: str | None = typer.Argument(None, help="Function VA in hex (omit with --all)"),
    window: int = typer.Option(512, "--window", help="Disassembly window size"),
    all_functions: bool = all_items_option("function-list entry"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Decode jump-table switches in the function at VA (or scan all with --all)."""
    cfg = require_config(target=target, json_mode=json_output)
    from rebrew.cli import parse_va

    if all_functions:
        _scan_all(cfg, window, json_output)
        return

    if va is None:
        error_exit(
            "Specify a function VA (e.g. rebrew binary switches 0x10311e0) or --all to scan every function.",
            json_mode=json_output,
        )
    va_int = parse_va(va, json_mode=json_output)
    if not cfg.target_binary.exists():
        error_exit(f"Binary not found at {cfg.target_binary}", json_mode=json_output)

    switches = find_switches(cfg, va_int, window=window)
    if json_output:
        json_print({"va": f"0x{va_int:08x}", "switches": switches})
        return

    if not switches:
        console.print(
            f"[yellow]No jump-table dispatch found in the first {window} bytes "
            f"at 0x{va_int:08x}.[/]"
        )
        raise typer.Exit(code=EXIT_OK)

    # One shared lookup for every handler row — a tree scan per row would
    # dominate the command's runtime on large projects.
    from rebrew.asm import build_function_lookup

    try:
        func_lookup: dict[int, tuple[str, str]] | None = build_function_lookup(cfg)
    except Exception:  # best-effort naming
        logging.getLogger(__name__).debug(
            "function lookup build failed; handler names unresolved", exc_info=True
        )
        func_lookup = None

    for sw in switches:
        # The operand's `[...]` would otherwise be parsed as Rich markup and
        # swallowed, so the header showed only "jmp dword ptr".
        from rich.markup import escape

        operand = _dispatch_operand(sw["index_reg"], sw["table_va"], sw["entry_width"])
        console.print(f"[bold]Dispatch @ 0x{sw['jmp_va']:08x}:[/] jmp {escape(operand)}")
        if sw["bounds"] is not None:
            console.print(f"  bounds: index <= 0x{sw['bounds']:x} ({sw['entries']} entries)")
        table = TerminalTable(show_header=True, header_style="bold")
        table.add_column("Case", justify="right")
        table.add_column("Handler VA", style="cyan")
        table.add_column("Function", style="magenta")
        for shown, (index, handler_va) in enumerate(sw["cases"]):
            if shown >= _MAX_TABLE_ROWS:
                table.add_row("...", "", f"{len(sw['cases']) - shown} more")
                break
            name = _resolve_name(cfg, handler_va, func_lookup)
            table.add_row(f"{index}", f"0x{handler_va:08x}", untrusted_ident(name))
        console.print(table)


def _scan_all(cfg: Any, window: int, json_output: bool) -> None:
    """Scan every discovery entry and report those containing dispatches.

    Recon pass for the "which of my remaining functions are switch
    dispatches?" question — each function is disassembled up to *window*
    bytes and checked for an indirect jump-table jmp.
    """
    from rebrew.catalog import cached_function_list

    funcs = cached_function_list(cfg)
    if not funcs:
        error_exit(
            "No function inventory (needed for --all) — run `rebrew intake` or "
            "`rebrew binary functions` first",
            json_mode=json_output,
        )

    found: list[dict[str, Any]] = []
    for func in funcs:
        va = func.get("va")
        if not va:
            continue
        try:
            # int(x, 0) accepts 0x-prefixed hex AND decimal strings — a
            # decimal string ("4198400") forced through base 16 scanned the
            # wrong address (68 MB instead of 0x401000).
            va_int = parse_int_literal(str(va))
        except ValueError:
            continue
        switches = find_switches(cfg, va_int, window=window)
        if switches:
            name = func.get("name") or f"fcn.{va_int:08x}"
            found.append(
                {
                    "va": f"0x{va_int:08x}",
                    "name": name,
                    "dispatches": len(switches),
                    "cases": sum(s["entries"] for s in switches),
                }
            )

    if json_output:
        json_print({"scanned": "all", "with_dispatches": found})
        return

    if not found:
        console.print("[yellow]No function-list entry has a jump-table dispatch.[/]")
        raise typer.Exit(code=EXIT_OK)
    console.print(f"[bold]{len(found)} function(s) with jump-table dispatches:[/]")
    table = TerminalTable()
    for label in ("VA", "Function", "Dispatches", "Cases", "Inspect"):
        table.add_column(label)
    for f in sorted(found, key=lambda x: -x["dispatches"]):
        table.add_row(
            f"[cyan]{f['va']}[/]",
            untrusted_ident(f["name"]),
            str(f["dispatches"]),
            str(f["cases"]),
            f"rebrew binary switches {f['va']}",
        )
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
