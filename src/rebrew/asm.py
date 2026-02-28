"""Dump assembly bytes for a function from the target binary.

Usage:
    rebrew asm 0x10003ca0 --size 77
    rebrew asm --va 0x10003ca0 --size 77
"""

from pathlib import Path

import typer

from rebrew.annotation import parse_c_file_multi
from rebrew.catalog import load_ghidra_functions
from rebrew.cli import TargetOption, error_exit, get_config, iter_sources, json_print, parse_va
from rebrew.config import ProjectConfig

_EPILOG = """\
[bold]Examples:[/bold]

rebrew asm 0x10003ca0                     Disassemble 32 bytes (default)

rebrew asm 0x10003ca0 --size 77           Disassemble 77 bytes

rebrew asm --va 0x10003ca0 --size 128     Using named option

rebrew asm 0x10003ca0 --no-annotate       Skip call/jmp name annotations

rebrew asm 0x10003ca0 -t server.dll       Use alternate target

rebrew asm 0x10003ca0 --size 77 --json    Machine-readable JSON output

[dim]Uses capstone for x86 disassembly with call/jmp annotation.
Falls back to hex dump if capstone is not installed.
Reads binary path and architecture from rebrew-project.toml.[/dim]"""

app = typer.Typer(
    help="Dump hex/asm for a function from the target binary.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
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
        if isinstance(va, int) and isinstance(name, str) and name:
            lookup[va] = (name, "")

    # Override with names from existing source files (more accurate)
    src_dir = Path(cfg.reversed_dir)
    if src_dir.is_dir():
        for cfile in iter_sources(src_dir, cfg):
            try:
                entries = parse_c_file_multi(cfile, target_name=cfg.marker if cfg else None)
                if not entries:
                    continue

                for entry in entries:
                    va = entry.va
                    status = entry.status
                    symbol = (entry.symbol or "").lstrip("_")
                    display = symbol or cfile.stem
                    lookup[va] = (display, status)
            except (OSError, KeyError, ValueError, TypeError):
                continue

    return lookup


@app.callback(invoke_without_command=True)
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
    """Disassemble bytes at a VA and optionally annotate known branch targets.

    The command extracts raw bytes from the configured target binary, attempts
    capstone disassembly, and prints either readable assembly or structured JSON.
    In text mode, call/jump targets can be annotated with names/statuses from
    ``ghidra_functions.json`` and source annotations for faster triage.

    Args:
        va_hex: Optional positional VA in hexadecimal form.
        va: Optional named VA in hexadecimal form (same as ``va_hex``).
        size: Byte length to extract and disassemble.
        annotate: Include call/jmp name/status comments in text output.
        json_output: Emit machine-readable JSON output.
        target: Optional target profile name from ``rebrew-project.toml``.
    """
    va_str = va or va_hex
    if not va_str:
        error_exit("Specify VA as a positional argument or via --va", json_mode=json_output)

    cfg = get_config(target=target)
    bin_path = cfg.target_binary

    if size <= 0:
        msg = f"Size must be > 0 (got {size})"
        error_exit(msg, json_mode=json_output)

    if not bin_path.exists():
        error_exit(f"Binary not found at {bin_path}", json_mode=json_output)

    va_int = parse_va(va_str, json_mode=json_output)

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
                json_print(
                    {
                        "va": f"0x{va_int:08x}",
                        "size": len(data),
                        "instruction_count": len(insn_list),
                        "instructions": instructions,
                    }
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
                error_exit("capstone not installed", json_mode=True)
            # Fallback to hex dump if capstone not available
            print("(capstone not installed, showing hex dump)")
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"  0x{va_int + i:08x}:  {hex_str:<48s}  {ascii_str}")
    except (OSError, KeyError, ValueError, TypeError) as e:
        error_exit(str(e), json_mode=json_output)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
