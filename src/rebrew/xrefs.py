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
from collections.abc import Sequence
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


#: Minimum length for a prefix-less all-letter hex token to read as a VA.
#: Shorter all-letter tokens (``dead``, ``beef``, ``face``) read as plain
#: words/names; a full 32-bit width (``deadbeef``) reads as an address.
_MIN_BARE_HEX_LETTERS = 8


def _looks_like_va(arg: str) -> bool:
    """True when *arg* reads as a hex/int address rather than a file path.

    Used to disambiguate ``rebrew xrefs <va> [binary]`` positionals — a VA
    is ``0x...`` hex or a prefix-less number with at least one digit
    (``401000``, ``1dead``), never a path or a bare word.  A bare word
    like ``dead`` parses as hex but is far likelier a name/path, so only
    a full-width all-letter token (``deadbeef``) still counts as a VA.
    """
    a = arg.strip()
    if a.lower().startswith("0x") or a.lower().startswith("-0x"):
        return True
    if not a or any(ch in a for ch in "/\\."):
        return False
    low = a.lower()
    if low.startswith("+") or low.startswith("-"):
        low = low[1:]
        if not low:
            return False
    if not low or any(ch not in "0123456789abcdef" for ch in low):
        return False
    if any(ch.isdigit() for ch in low):
        return True
    return len(low) >= _MIN_BARE_HEX_LETTERS


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


def build_xrefs_payload(
    binary: Path,
    target_va: int,
    kinds: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Build the cross-reference payload for *target_va* in *binary*.

    The same object the ``rebrew xrefs`` callback prints under ``--json``:
    the target VA, the import-table name when the target is an IAT slot, and
    one ``{kind, from_va, instruction}`` record per reference, optionally
    narrowed to *kinds*.  An empty reference list is a valid result.

    Raises:
        OSError: The binary cannot be read.
        ValueError: The binary cannot be parsed.
    """
    info = load_binary(binary)
    refs = scan_references(info, target_va=target_va)
    if kinds:
        refs = [ref for ref in refs if ref.kind in kinds]
    return _payload(
        target_va,
        parse_import_table(binary).get(target_va),
        refs,
        _insn_text_by_va(info),
    )


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
        payload = build_xrefs_payload(binary, target_va, kind)
    except (OSError, ValueError) as exc:
        error_exit(f"failed to load binary {binary}: {exc}", json_mode=json_output, code=EXIT_ERROR)

    if json_output:
        json_print(payload)
        return

    refs = payload["refs"]
    if not refs:
        console.print(f"no references to 0x{target_va:08X}")
        return

    console.print(f"[bold]{len(refs)}[/] references to [bold]0x{target_va:08X}[/]:")
    import_name = payload["import_name"]
    if import_name is not None:
        console.print(f"[bold]target is import:[/bold] {import_name}")
    counts = Counter(ref["kind"] for ref in refs)
    for ref_kind in sorted(counts):
        console.print(f"  [bold]{ref_kind}[/]: {counts[ref_kind]}")
    table = Table(title=f"xrefs to 0x{target_va:08X}")
    table.add_column("from_va", justify="right")
    table.add_column("kind")
    table.add_column("instruction")
    for ref in refs:  # build_xrefs_payload keeps scan_references' (from_va, to_va) order
        table.add_row(f"0x{ref['from_va']:08X}", ref["kind"], ref["instruction"] or "")
    console.print(table)


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
