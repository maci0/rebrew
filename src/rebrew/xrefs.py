"""xrefs.py — Cross-reference explorer: who references a given address.

Scans the binary's code sections via :func:`rebrew.analysis.scan_references`
for absolute references pointing at a target VA and reports each one: the
referencing instruction's address, its kind (``call`` / ``jmp`` / ``push`` /
``iat_call`` / ...), and the disassembled instruction text.  When the target
is an import-table slot, the imported API name is resolved and shown
prominently.

Usage:
    rebrew xrefs <va> [binary]
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.analysis import Xref, iter_instructions, scan_references
from rebrew.binary_loader import BinaryInfo, load_binary
from rebrew.cli import EXIT_ERROR, TargetOption, error_exit, json_print, parse_va, require_config
from rebrew.imports import parse_import_table

console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _looks_like_va(arg: str) -> bool:
    """True when *arg* reads as a hex/int address rather than a file path.

    Used to disambiguate ``rebrew xrefs <va> [binary]`` positionals — a VA
    is ``0x...`` hex or a bare integer, never a path with a dot extension.
    """
    a = arg.strip()
    if a.lower().startswith("0x") or a.lower().startswith("-0x"):
        return True
    if not a or any(ch in a for ch in "/\\."):
        return False
    try:
        int(a, 16)
        return True
    except ValueError:
        return False


def _insn_text_by_va(info: BinaryInfo) -> dict[int, str]:
    """Map instruction VA -> disassembly text for the ``.text`` section.

    Disassembles the section once; VAs not covered (e.g. a missing section)
    simply have no entry, so callers can render a blank cell / null.
    """
    text = info.sections.get(".text")
    if text is None:
        return {}
    return {
        insn.va: f"{insn.mnemonic} {insn.op_str}".strip()
        for insn in iter_instructions(info, text.va, text.size)
    }


def _payload(
    target_va: int,
    import_name: str | None,
    refs: list[Xref],
    insns: dict[int, str],
) -> dict[str, Any]:
    """Build the machine-readable result dict for ``--json`` output."""
    return {
        "target": target_va,
        "import_name": import_name,
        "count": len(refs),
        "refs": [
            {"kind": xref.kind, "from_va": xref.from_va, "instruction": insns.get(xref.from_va)}
            for xref in refs
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Show cross-references to a target address.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew xrefs 0x401000 · · · · · · Who references 0x00401000\n\n"
        "  rebrew xrefs 0x401000 --kind call · Only direct calls\n\n"
        "  rebrew xrefs 0x401000 --json · · · · Machine-readable output\n"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    va: str = typer.Argument(..., help="Target address (hex or int)"),
    binary: Path | None = typer.Argument(None, help="Binary path (default: project target)"),
    kind: list[str] = typer.Option(None, "--kind", help="Only show this ref kind (repeatable)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Show every reference to *va* in the binary's code sections."""
    # Typer binds positionals in declaration order, so `rebrew xrefs <va>`
    # (the documented primary usage) previously landed on `binary` and left
    # `va` missing.  With va-first this works; a legacy binary-first call
    # (`rebrew xrefs game.exe 0x1000`) is detected by the leading arg not
    # looking like a VA and swapped.
    if not _looks_like_va(va) and binary is not None and _looks_like_va(str(binary)):
        va, binary = str(binary), Path(va)
    target_va = parse_va(va, json_mode=json_output)

    if binary is None:
        cfg = require_config(target=target, json_mode=json_output)
        binary = cfg.target_binary
        if not binary.exists():
            error_exit(f"target binary missing: {binary}", json_mode=json_output, code=2)
    if not binary.exists():
        error_exit(f"binary not found: {binary}", json_mode=json_output)

    try:
        info = load_binary(binary)
    except (OSError, ValueError) as exc:
        error_exit(f"failed to load binary {binary}: {exc}", json_mode=json_output, code=EXIT_ERROR)

    refs = scan_references(info, target_va=target_va)
    if kind:
        refs = [ref for ref in refs if ref.kind in kind]
    import_name = parse_import_table(binary).get(target_va)
    insns = _insn_text_by_va(info)

    if not refs:
        if json_output:
            json_print(_payload(target_va, import_name, refs, insns))
        else:
            console.print(f"no references to 0x{target_va:08X}")
        return

    if json_output:
        json_print(_payload(target_va, import_name, refs, insns))
        return

    console.print(f"[bold]{len(refs)}[/] references to [bold]0x{target_va:08X}[/]:")
    if import_name is not None:
        console.print(f"[bold]target is import:[/bold] {import_name}")
    counts = Counter(ref.kind for ref in refs)
    for ref_kind in sorted(counts):
        console.print(f"  [bold]{ref_kind}[/]: {counts[ref_kind]}")
    table = Table(title=f"xrefs to 0x{target_va:08X}")
    table.add_column("from_va", justify="right")
    table.add_column("kind")
    table.add_column("instruction")
    for ref in refs:  # scan_references already sorts by (from_va, to_va)
        table.add_row(f"0x{ref.from_va:08X}", ref.kind, insns.get(ref.from_va, ""))
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
