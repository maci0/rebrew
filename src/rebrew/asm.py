#!/usr/bin/env python3
"""Dump assembly bytes for a function from the target binary.

Usage:
    rebrew-asm 0x10003ca0 --size 77
    rebrew-asm --va 0x10003ca0 --size 77
"""

import json
import sys
from pathlib import Path

import typer

from rebrew.annotation import parse_c_file
from rebrew.catalog import load_ghidra_functions
from rebrew.cli import TargetOption, get_config, iter_sources
from rebrew.config import ProjectConfig

_EPILOG = """\
[bold]Examples:[/bold]
  rebrew-asm 0x10003ca0                     Disassemble 32 bytes (default)
  rebrew-asm 0x10003ca0 --size 77           Disassemble 77 bytes
  rebrew-asm --va 0x10003ca0 --size 128     Using named option
  rebrew-asm 0x10003ca0 --no-annotate       Skip call/jmp name annotations
  rebrew-asm 0x10003ca0 -t server.dll       Use alternate target
  rebrew-asm 0x10003ca0 --size 77 --json    Machine-readable JSON output

[dim]Uses capstone for x86 disassembly with call/jmp annotation.
Falls back to hex dump if capstone is not installed.
Reads binary path and architecture from rebrew.toml.[/dim]"""

app = typer.Typer(
    help="Dump hex/asm for a function from the target binary.",
    rich_markup_mode="rich",
)


def build_function_lookup(cfg: ProjectConfig) -> dict[int, tuple[str, str]]:
    """Build a VA -> (name, status) lookup from Ghidra JSON and existing .c files.

    Returns dict mapping VA int -> (display_name, status_string).
    Status is one of: EXACT, RELOC, MATCHING, STUB, or '' for Ghidra-only.
    """
    lookup: dict[int, tuple[str, str]] = {}

    # Load Ghidra function names
    ghidra_json = cfg.reversed_dir / "ghidra_functions.json"
    ghidra_funcs = load_ghidra_functions(ghidra_json)
    for func in ghidra_funcs:
        va = func.get("va")
        name = func.get("ghidra_name", "")
        if va is not None and name:
            lookup[va] = (name, "")

    # Override with names from existing source files (more accurate)
    src_dir = Path(cfg.reversed_dir)
    if src_dir.is_dir():
        for cfile in iter_sources(src_dir, cfg):
            try:
                entry = parse_c_file(cfile)
                if not entry:
                    continue

                va = entry.va
                status = entry.status
                symbol = entry.symbol.lstrip("_")

                display = symbol or cfile.stem
                lookup[va] = (display, status)
            except (OSError, KeyError, ValueError, TypeError):
                continue

    return lookup


@app.command(epilog=_EPILOG)
def main(
    va_hex: str | None = typer.Argument(None, help="Function VA in hex"),
    va: str | None = typer.Option(None, "--va", help="Function VA in hex"),
    size: int = typer.Option(32, help="Function size in bytes"),
    annotate: bool = typer.Option(
        True, "--annotate/--no-annotate", help="Annotate calls with known function names"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Dump hex/asm for a function from the target binary."""
    va_str = va or va_hex
    if not va_str:
        if json_output:
            print(
                json.dumps({"error": "Specify VA as a positional argument or via --va"}, indent=2)
            )
        else:
            print("Error: Specify VA as a positional argument or via --va", file=sys.stderr)
        raise typer.Exit(code=1)

    cfg = get_config(target=target)
    bin_path = cfg.target_binary

    if not bin_path.exists():
        if json_output:
            print(json.dumps({"error": f"Binary not found at {bin_path}"}, indent=2))
        else:
            print(f"Error: Binary not found at {bin_path}", file=sys.stderr)
        raise typer.Exit(code=1)

    try:
        va_int = int(va_str, 16)
    except ValueError:
        msg = f"Invalid hex VA: {va_str}"
        if json_output:
            print(json.dumps({"error": msg}, indent=2))
        else:
            print(f"Error: {msg}", file=sys.stderr)
        raise typer.Exit(code=1)

    # Build function name lookup for call annotation (skip in JSON mode)
    func_lookup: dict[int, tuple[str, str]] = {}
    if annotate and not json_output:
        func_lookup = build_function_lookup(cfg)

    # Read the bytes from the binary using config's PE-aware offset calculation
    try:
        data = cfg.extract_dll_bytes(va_int, size)

        # Try capstone disassembly
        try:
            from capstone import Cs

            md = Cs(cfg.capstone_arch, cfg.capstone_mode)
            md.detail = False
            insn_list = list(md.disasm(data, va_int))

            if json_output:
                instructions = []
                for insn in insn_list:
                    instructions.append(
                        {
                            "address": f"0x{insn.address:08x}",
                            "bytes": insn.bytes.hex(),
                            "mnemonic": insn.mnemonic,
                            "operands": insn.op_str,
                        }
                    )
                print(
                    json.dumps(
                        {
                            "va": f"0x{va_int:08x}",
                            "size": len(data),
                            "instruction_count": len(insn_list),
                            "instructions": instructions,
                        },
                        indent=2,
                    )
                )
                return

            print(f"Dumping 0x{va_int:08x} ({len(data)} bytes) from {bin_path.name}:")
            print()
            for insn in insn_list:
                hex_bytes = insn.bytes.hex()
                line = (
                    f"  0x{insn.address:08x}:  {hex_bytes:<20s}  {insn.mnemonic:<8s} {insn.op_str}"
                )

                # Annotate call/jmp targets with known function names
                if annotate and insn.mnemonic in ("call", "jmp") and insn.op_str.startswith("0x"):
                    try:
                        target_va = int(insn.op_str, 16)
                        if target_va in func_lookup:
                            name, status = func_lookup[target_va]
                            tag = f" ({status})" if status else ""
                            line += f"  ; {name}{tag}"
                    except ValueError:
                        pass

                print(line)
        except ImportError:
            if json_output:
                print(json.dumps({"error": "capstone not installed"}, indent=2))
                raise typer.Exit(code=1)
            # Fallback to hex dump if capstone not available
            print("(capstone not installed, showing hex dump)")
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"  0x{va_int + i:08x}:  {hex_str:<48s}  {ascii_str}")
    except (OSError, KeyError, ValueError, TypeError) as e:
        if json_output:
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        raise typer.Exit(code=1)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
