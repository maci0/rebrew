"""extract.py - Extract and disassemble functions from the target binary.

Reads a function list (functions.txt or .json), auto-detects already-reversed VAs from
the projects src directory, and lets you list/extract/batch the remaining
candidates.

Usage:
    rebrew extract list                # List un-reversed candidates
    rebrew extract extract 0x10001860  # Extract + disasm one VA
    rebrew extract batch 20            # Extract first 20 smallest
    rebrew extract batch 20 --start 10 # Offset into sorted list
"""

import json
from pathlib import Path
from typing import Any, cast

import typer

from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
from rebrew.catalog import parse_function_list, scan_reversed_dir
from rebrew.cli import TargetOption, error_exit, get_config, json_print, parse_va
from rebrew.config import ProjectConfig

# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------


def load_target_binary(bin_path: Path) -> BinaryInfo:
    """Load binary and return BinaryInfo."""
    return load_binary(bin_path)


def extract_bytes(binary_info: BinaryInfo, va: int, size: int) -> bytes:
    """Extract raw bytes from binary at given VA."""
    data = extract_bytes_at_va(binary_info, va, size)
    return data if data is not None else b""


# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------


def disasm(code_bytes: bytes, va: int, cfg: ProjectConfig | None = None) -> str:
    """Disassemble using capstone and return formatted string."""
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ImportError as e:
        raise RuntimeError("capstone not installed") from e

    arch = cfg.capstone_arch if cfg else CS_ARCH_X86
    mode = cfg.capstone_mode if cfg else CS_MODE_32
    md = Cs(arch, mode)
    lines = []
    for insn in md.disasm(code_bytes, va):
        hex_bytes = insn.bytes.hex()
        lines.append(f"  {insn.address:08X}  {hex_bytes:20s}  {insn.mnemonic:6s} {insn.op_str}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Auto-detect reversed VAs
# ---------------------------------------------------------------------------


def detect_reversed_vas(src_dir: Path, cfg: ProjectConfig | None = None) -> set[int]:
    """Scan the reversed source directory for annotation headers and return set of VAs."""
    if not src_dir.exists():
        return set()
    return {
        entry.va
        for entry in scan_reversed_dir(src_dir, cfg=cfg)
        if entry.marker_type not in ("GLOBAL", "DATA")
    }


# ---------------------------------------------------------------------------
# Load function list
# ---------------------------------------------------------------------------


def load_functions(cfg: ProjectConfig) -> list[dict[str, int | str]]:
    """Load function list from functions.txt (preferred) or .json."""
    txt_path = cfg.function_list
    json_path = txt_path.with_suffix(".json")

    if txt_path.exists():
        raw_funcs = cast(list[dict[str, Any]], parse_function_list(txt_path))
        return [
            {"va": int(fn["va"]), "size": int(fn["size"]), "name": str(fn["name"])}
            for fn in raw_funcs
        ]

    if json_path.exists():
        with json_path.open(encoding="utf-8") as f:
            raw = cast(list[dict[str, Any]], json.load(f))
        return [
            {
                "va": int(fn["offset"]),
                "size": int(fn.get("realsz", fn.get("size", 0))),
                "name": str(fn["name"]),
            }
            for fn in raw
        ]

    error_exit(f"No function list found at {txt_path} or {json_path}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_list(candidates: list[tuple[int, int, str]]) -> None:
    """List candidate functions."""
    print(f"Candidates: {len(candidates)} (sorted by size)")
    for i, (va, size, name) in enumerate(candidates):
        print(f"  {i:3d}  0x{va:08X}  {size:5d}B  {name}")


def cmd_extract(
    binary_info: BinaryInfo,
    candidates: list[tuple[int, int, str]],
    target_va: int,
    bin_dir: Path,
    cfg: ProjectConfig | None = None,
    *,
    json_output: bool = False,
) -> None:
    """Extract and disassemble a single function."""
    for va, size, name in candidates:
        if va == target_va:
            code = extract_bytes(binary_info, va, size)
            if code == b"":
                msg = f"Failed to extract bytes at VA 0x{va:08X}"
                if json_output:
                    json_print({"status": "ERROR", "error": msg})
                else:
                    typer.echo(msg, err=True)
                return
            try:
                asm_text = disasm(code, va, cfg=cfg)
            except RuntimeError as e:
                if json_output:
                    json_print({"status": "ERROR", "error": str(e)})
                else:
                    typer.echo(f"ERROR: {e}", err=True)
                return

            # Save .bin
            bin_dir.mkdir(parents=True, exist_ok=True)
            bin_path = bin_dir / f"func_0x{va:08X}.bin"
            bin_path.write_bytes(code)

            if json_output:
                json_print(
                    {
                        "status": "OK",
                        "name": name,
                        "va": f"0x{va:08x}",
                        "size": len(code),
                        "hex": code.hex(),
                        "asm": asm_text,
                        "bin_path": str(bin_path),
                    }
                )
                return

            print(f"=== {name} @ 0x{va:08X}, {len(code)} bytes ===")
            print(f"Hex: {code.hex()}")
            print()
            print(asm_text)
            print(f"\nSaved to {bin_path}")
            return
    if json_output:
        json_print(
            {"status": "ERROR", "error": f"VA 0x{target_va:08X} not found in candidate list"}
        )
        return
    print(f"VA 0x{target_va:08X} not found in candidate list")


def cmd_batch(
    binary_info: BinaryInfo,
    candidates: list[tuple[int, int, str]],
    count: int,
    start: int,
    bin_dir: Path,
    cfg: ProjectConfig | None = None,
    *,
    json_output: bool = False,
) -> None:
    """Extract and disassemble a batch of functions."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    batch = candidates[start : start + count]
    items: list[dict[str, str | int]] = []
    for va, size, name in batch:
        code = extract_bytes(binary_info, va, size)
        if code == b"":
            if json_output:
                items.append(
                    {
                        "status": "ERROR",
                        "name": name,
                        "va": f"0x{va:08x}",
                        "size": size,
                        "error": "Failed to extract bytes",
                    }
                )
                continue
            typer.echo(f"ERROR: Failed to extract bytes at VA 0x{va:08X}", err=True)
            continue

        try:
            asm_text = disasm(code, va, cfg=cfg)
        except RuntimeError as e:
            if json_output:
                items.append(
                    {
                        "status": "ERROR",
                        "name": name,
                        "va": f"0x{va:08x}",
                        "size": size,
                        "error": str(e),
                    }
                )
                continue
            typer.echo(f"ERROR: {e}", err=True)
            return

        bin_path = bin_dir / f"func_0x{va:08X}.bin"
        bin_path.write_bytes(code)

        if json_output:
            items.append(
                {
                    "status": "OK",
                    "name": name,
                    "va": f"0x{va:08x}",
                    "size": len(code),
                    "hex": code.hex(),
                    "asm": asm_text,
                    "bin_path": str(bin_path),
                }
            )
            continue

        print(f"\n{'=' * 60}")
        print(f"=== {name} @ 0x{va:08X}, {len(code)} bytes ===")
        print(f"{'=' * 60}")
        print(f"Hex: {code.hex()}")
        print()
        print(asm_text)

    if json_output:
        json_print(
            {
                "count": len(items),
                "start": start,
                "requested": count,
                "results": items,
            }
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Extract and disassemble functions from the target binary.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew extract list                       List un-reversed candidates

rebrew extract extract 0x10001860         Extract + disassemble one VA

rebrew extract batch 20                   Extract first 20 smallest

rebrew extract batch 20 --start 10        Offset into sorted list

[dim]Reads function list from functions.txt or .json and auto-detects
already-reversed VAs. Outputs .bin and .asm files to the configured bin_dir.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    command: str = typer.Argument(help="Command: list, extract, or batch"),
    batch_target: str | None = typer.Argument(
        None, help="VA (hex) for extract, or count for batch"
    ),
    exe: Path | None = typer.Option(None, help="Path to DLL/EXE (default: from config)"),
    start: int = typer.Option(0, help="Start offset for batch mode"),
    min_size: int = typer.Option(8, help="Minimum function size"),
    max_size: int = typer.Option(50000, help="Maximum function size"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """List and extract unreversed function candidates from configured binary metadata.

    This command reads the configured function list, removes already-reversed VAs
    discovered from source annotations, and then performs one of three actions:
    ``list`` candidates, ``extract`` a single VA, or ``batch`` extract a range.

    ``--json`` is supported for all commands and emits structured payloads suitable
    for automation consumers.

    Args:
        command: One of ``list``, ``extract``, or ``batch``.
        batch_target: VA (hex) for ``extract`` or count for ``batch``.
        exe: Optional binary path override.
        start: Start offset into sorted candidates for batch mode.
        min_size: Minimum function size to include.
        max_size: Maximum function size to include.
        json_output: Emit machine-readable JSON output.
        target: Optional target profile from ``rebrew-project.toml``.
    """
    cfg = get_config(target=target)

    exe_path = exe or cfg.target_binary
    src_dir = cfg.reversed_dir
    bin_dir = cfg.bin_dir

    # Load functions
    funcs = load_functions(cfg)

    # Auto-detect already-reversed VAs
    reversed_vas = detect_reversed_vas(src_dir, cfg=cfg)
    if not json_output:
        typer.echo(f"Found {len(reversed_vas)} already-reversed functions", err=True)

    # Filter candidates — cast dict values to expected types for type safety
    candidates: list[tuple[int, int, str]] = []
    for fn in funcs:
        va = int(fn["va"])
        size = int(fn["size"])
        name = str(fn["name"])

        if va in reversed_vas:
            continue
        if size < min_size or size > max_size:
            continue

        candidates.append((va, size, name))

    candidates.sort(key=lambda x: x[1])  # Sort by size

    if command == "list":
        if json_output:
            items = [{"va": f"0x{va:08x}", "size": sz, "name": nm} for va, sz, nm in candidates]
            json_print({"count": len(candidates), "candidates": items})
            return
        cmd_list(candidates)
    elif command == "extract":
        if not batch_target:
            msg = "extract requires a VA argument (e.g. 0x10001860)"
            error_exit(msg, json_mode=json_output)
        binary_info = load_target_binary(exe_path)
        target_va = parse_va(batch_target, json_mode=json_output)
        cmd_extract(binary_info, candidates, target_va, bin_dir, cfg=cfg, json_output=json_output)
    elif command == "batch":
        try:
            count = int(batch_target) if batch_target else 20
        except ValueError:
            msg = f"Invalid count '{batch_target}'"
            error_exit(msg, json_mode=json_output)
        binary_info = load_target_binary(exe_path)
        cmd_batch(binary_info, candidates, count, start, bin_dir, cfg=cfg, json_output=json_output)
    else:
        msg = f"Unknown command '{command}'. Use list, extract, or batch."
        error_exit(msg, json_mode=json_output)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
