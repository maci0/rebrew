"""switch.py — jump-table switch dispatch decoding.

MSVC compiles ``switch`` statements on 32-bit x86 into a bounds-checked
indirect jump::

    cmp  ecx, 0xb            ; index bounds check
    ja   default
    jmp  dword ptr [edx*4 + 0x1031240]   ; dispatch table

The 32-bit entries at ``0x1031240 + index*4`` are the case-handler
addresses.  ``rebrew switch <va>`` locates these dispatches inside a
function and prints the case table — index → handler VA → known function
name — so a jump-table function's structure is visible before writing a
single line of C (the "jump-table switch" category of functions that
manual decompilation has to untangle by hand).

Detection is pattern-based (indirect ``jmp`` through a scaled register
against a table address) and best-effort: functions with no such dispatch
yield an empty result, and unresolvable entries are shown as raw VAs.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

#: Maximum table entries to read (the bounds-check count normally bounds it;
#: this is a safety cap against misreading a data region as a giant table).
_MAX_TABLE_ENTRIES = 256

#: Table rows shown in the human table before collapsing the rest.
_MAX_TABLE_ROWS = 24

#: ``jmp dword ptr [edx*4 + 0x12345678]`` — capstone renders the scaled
#: index before the base for ``[base + index*4]`` operands.
_INDIRECT_JMP_RE = re.compile(r"dword ptr \[([a-z0-9]+)\s*\*\s*4\s*\+\s*0x([0-9a-fA-F]+)\]")

#: ``cmp ecx, 0xb`` — the bounds check preceding the dispatch.
_CMP_IMM_RE = re.compile(r"([a-z0-9]+),\s*(?:0x)?([0-9a-fA-F]+)")

#: ``and eax, 3`` — a register-index mask used as a bounds check by MSVC's
#: memcpy/memmove byte-tail dispatches (``and reg, N; jmp [reg*4 + table]``).
_MASK_RE = re.compile(r"^(eax|ecx|edx|esi|edi|ebx),\s*(?:0x)?([0-9a-fA-F]+)$")


def _is_index_mask(value: int) -> bool:
    """True when *value* is a power-of-two-minus-1 (1, 3, 7, 15, ...).

    A register index mask bounds a jump-table index; a non-mask ``and reg, N``
    (e.g. a flag test like ``and eax, 0x40``) must not be read as a bound.
    """
    return value >= 1 and (value & (value + 1)) == 0


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
        }

    Best-effort: empty list when the window has no indirect dispatch.
    """
    from rebrew.binary_loader import extract_raw_bytes

    try:
        raw = extract_raw_bytes(cfg.target_binary, va, window)
    except Exception:  # missing/unreadable binary → no dispatch
        return []
    if not raw:
        return []

    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = False
    insns = list(md.disasm(raw, va))
    if not insns:
        return []

    results: list[dict[str, Any]] = []
    for idx, insn in enumerate(insns):
        if insn.mnemonic != "jmp":
            continue
        m = _INDIRECT_JMP_RE.search(insn.op_str)
        if m is None:
            continue
        index_reg = m.group(1)
        table_va = int(m.group(2), 16)

        # Bounds check: the nearest preceding `cmp reg, N` with a small
        # immediate.  The index register often differs (MSVC copies the
        # index into the scaled register between the cmp and the jmp), so
        # any register is accepted; a large immediate (an address compare,
        # not a switch bound) is rejected.  MSVC's memcpy/memmove byte-tail
        # dispatches bound the index with `and reg, mask` instead — recognize
        # a power-of-two-minus-1 mask on the index register as a bound too.
        bounds: int | None = None
        for prev in insns[max(0, idx - 8) : idx]:
            if prev.mnemonic == "cmp":
                cm = _CMP_IMM_RE.search(prev.op_str)
                if cm is None:
                    continue
                try:
                    value = int(cm.group(2), 16)
                except ValueError:
                    continue
                if 0 <= value <= 0xFFFF:
                    bounds = value
                    break
            elif prev.mnemonic == "and":
                am = _MASK_RE.match(prev.op_str)
                if am is None or am.group(1) != index_reg:
                    continue
                try:
                    value = int(am.group(2), 16)
                except ValueError:
                    continue
                if _is_index_mask(value):
                    bounds = value
                    break

        cases = _read_table(cfg, table_va, bounds)
        results.append(
            {
                "jmp_va": insn.address,
                "index_reg": index_reg,
                "table_va": table_va,
                "bounds": bounds,
                "cases": cases,
                "entries": len(cases),
            }
        )
    return results


def _read_table(cfg: Any, table_va: int, bounds: int | None) -> list[tuple[int, int]]:
    """Read the dispatch table entries as ``(index, target_va)`` pairs.

    The entry count is the bounds-check max index + 1 when known, else the
    table is walked until a target lands outside the image (with a safety
    cap).  Returns ``[]`` when the table cannot be read.
    """
    from rebrew.binary_loader import extract_raw_bytes, load_binary

    count = (bounds + 1) if bounds is not None else _MAX_TABLE_ENTRIES
    count = max(1, min(count, _MAX_TABLE_ENTRIES))
    raw = extract_raw_bytes(cfg.target_binary, table_va, count * 4)
    if raw is None or len(raw) < 4:
        return []
    import struct

    try:
        info = load_binary(cfg.target_binary)
    except Exception:  # unreadable binary → no table
        return []

    entries: list[tuple[int, int]] = []
    for i in range(count):
        off = i * 4
        if off + 4 > len(raw):
            break
        target = struct.unpack_from("<I", raw, off)[0]
        if target == 0:
            break
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
    """True when *va* falls inside any section of the binary."""
    for section in info.sections.values():
        if section.va <= va < section.va + section.raw_size:
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
        return ""


app = typer.Typer(
    help="Decode jump-table switch dispatches in a function (case → handler map).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Example:[/bold]\n\n"
        "  rebrew switch 0x10311e0 · · · · · · · · · Show all switch dispatches\n\n"
        "  rebrew switch 0x10311e0 --json · · · · · · Machine-readable case tables\n\n"
        "  rebrew switch 0x10311e0 --window 1024 · · Wider disassembly window\n"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    va: str | None = typer.Argument(None, help="Function VA in hex (omit with --all)"),
    window: int = typer.Option(512, "--window", help="Disassembly window size"),
    all_functions: bool = typer.Option(
        False, "--all", help="Scan every function-list entry (report those with dispatches)"
    ),
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
            "Specify a function VA (e.g. rebrew switch 0x10311e0) or --all to scan every function.",
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
        raise typer.Exit(0)

    # One shared lookup for every handler row — a tree scan per row would
    # dominate the command's runtime on large projects.
    from rebrew.asm import build_function_lookup

    try:
        func_lookup: dict[int, tuple[str, str]] | None = build_function_lookup(cfg)
    except Exception:  # best-effort naming
        func_lookup = None

    for sw in switches:
        console.print(
            f"[bold]Dispatch @ 0x{sw['jmp_va']:08x}:[/] "
            f"jmp dword ptr [{sw['index_reg']}*4 + 0x{sw['table_va']:08x}]"
        )
        if sw["bounds"] is not None:
            console.print(f"  bounds: index <= 0x{sw['bounds']:x} ({sw['entries']} entries)")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Case", justify="right")
        table.add_column("Handler VA", style="cyan")
        table.add_column("Function", style="magenta")
        for shown, (index, handler_va) in enumerate(sw["cases"]):
            if shown >= _MAX_TABLE_ROWS:
                table.add_row("...", "", f"{len(sw['cases']) - shown} more")
                break
            name = _resolve_name(cfg, handler_va, func_lookup)
            table.add_row(f"{index}", f"0x{handler_va:08x}", name)
        console.print(table)


def _scan_all(cfg: Any, window: int, json_output: bool) -> None:
    """Scan every function-list entry and report those containing dispatches.

    Recon pass for the "which of my remaining functions are switch
    dispatches?" question — each function is disassembled up to *window*
    bytes and checked for an indirect jump-table jmp.
    """
    from rebrew.catalog import parse_function_list

    func_list_path = getattr(cfg, "function_list", "")
    if not func_list_path or not Path(func_list_path).is_file():
        error_exit(
            f"Function list not found at {func_list_path} (needed for --all)",
            json_mode=json_output,
        )

    found: list[dict[str, Any]] = []
    for func in parse_function_list(Path(func_list_path)):
        va = func.get("va") if isinstance(func, dict) else getattr(func, "va", None)
        if not va:
            continue
        try:
            # int(x, 0) accepts 0x-prefixed hex AND decimal strings — a
            # decimal string ("4198400") forced through base 16 scanned the
            # wrong address (68 MB instead of 0x401000).
            va_int = int(str(va), 0)
        except ValueError:
            continue
        switches = find_switches(cfg, va_int, window=window)
        if switches:
            name = (
                func.get("name") if isinstance(func, dict) else getattr(func, "name", "")
            ) or f"fcn.{va_int:08x}"
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
        raise typer.Exit(0)
    console.print(f"[bold]{len(found)} function(s) with jump-table dispatches:[/]")
    for f in sorted(found, key=lambda x: -x["dispatches"]):
        console.print(
            f"  [cyan]{f['va']}[/] {f['name']:<24s} "
            f"{f['dispatches']} dispatch(es), {f['cases']} case(s) — "
            f"rebrew switch {f['va']}"
        )


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
