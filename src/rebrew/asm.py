"""asm.py – Disassemble and export function bytes from the target binary.

Two output formats controlled by ``--format``:

* ``hex``  (default) — capstone disassembly with hex dump and optional call
  annotation.  Suitable for quick interactive triage.

* ``nasm`` — NASM-reassembleable source with round-trip verification.
  Round-trip guarantee: ``nasm -f bin output.asm`` → byte-identical to original.
  Instructions NASM encodes differently are replaced with ``db`` directives.

Usage:
    rebrew asm 0x10003ca0 --size 77
    rebrew asm --va 0x10003ca0 --size 77 --format nasm -o func.asm
    rebrew asm --va 0x10003ca0 --size 77 --format nasm --inline-c -o func.c
    rebrew asm --all --out-dir output/asm/ --format nasm
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi
from rebrew.binary_loader import extract_raw_bytes
from rebrew.catalog import load_function_structure
from rebrew.cli import (
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    parse_va,
    require_config,
    target_marker,
)
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Shared disassembly helper
# ---------------------------------------------------------------------------


def disasm_bytes(code_bytes: bytes, va: int, cfg: ProjectConfig | None = None) -> str:
    """Disassemble *code_bytes* starting at *va* and return a formatted string.

    Each line: ``  {address:08X}  {hex_bytes:20s}  {mnemonic:6s} {operands}``

    Uses ``cfg.capstone_arch``/``cfg.capstone_mode`` when *cfg* is provided;
    falls back to 32-bit x86.

    Shared by :mod:`rebrew.extract` and any other module that needs a quick
    human-readable disassembly representation without the full hex-mode output
    of :func:`_run_hex_mode`.
    """
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ImportError as exc:
        raise RuntimeError("capstone not installed") from exc

    arch = cfg.capstone_arch if cfg is not None else CS_ARCH_X86
    mode = cfg.capstone_mode if cfg is not None else CS_MODE_32
    md = Cs(arch, mode)
    lines = []
    for insn in md.disasm(code_bytes, va):
        hex_bytes = insn.bytes.hex()
        lines.append(f"  {insn.address:08X}  {hex_bytes:20s}  {insn.mnemonic:6s} {insn.op_str}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Hex / capstone mode helpers (former asm.py)
# ---------------------------------------------------------------------------


def build_function_lookup(cfg: ProjectConfig) -> dict[int, tuple[str, str]]:
    """Build a VA → (name, status) lookup from Ghidra JSON and existing .c files."""
    lookup: dict[int, tuple[str, str]] = {}

    ghidra_json = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON
    ghidra_funcs = load_function_structure(ghidra_json)
    for func in ghidra_funcs:
        if func.va and func.name:
            lookup[func.va] = (func.name, "")

    src_dir = Path(cfg.reversed_dir)
    if src_dir.is_dir():
        for cfile in iter_sources(src_dir, cfg):
            try:
                entries = parse_c_file_multi(cfile, target_name=target_marker(cfg))
                for entry in entries:
                    symbol = (entry.symbol or "").lstrip("_")
                    display = symbol or cfile.stem
                    lookup[entry.va] = (display, entry.status)
            except (OSError, KeyError, ValueError, TypeError):
                continue

    return lookup


def _run_hex_mode(
    va_int: int,
    size: int,
    cfg: ProjectConfig,
    annotate: bool,
    json_output: bool,
) -> None:
    """Capstone hex-dump disassembly (former asm.py behaviour)."""
    bin_path = cfg.target_binary
    if not bin_path.exists():
        error_exit(f"Binary not found at {bin_path}", json_mode=json_output)

    func_lookup: dict[int, tuple[str, str]] = {}
    if annotate and not json_output:
        func_lookup = build_function_lookup(cfg)

    try:
        data = extract_raw_bytes(cfg.target_binary, va_int, size)
        try:
            from capstone import Cs

            md = Cs(cfg.capstone_arch, cfg.capstone_mode)
            md.detail = False
            insn_list = list(md.disasm(data, va_int))

            if json_output:
                json_print(
                    {
                        "va": f"0x{va_int:08x}",
                        "size": len(data),
                        "instruction_count": len(insn_list),
                        "instructions": [
                            {
                                "address": f"0x{insn.address:08x}",
                                "bytes": insn.bytes.hex(),
                                "mnemonic": insn.mnemonic,
                                "operands": insn.op_str,
                            }
                            for insn in insn_list
                        ],
                    }
                )
                return

            console.print(
                f"Dumping [cyan]0x{va_int:08x}[/] ({len(data)} bytes) from {bin_path.name}:"
            )
            console.print()
            for insn in insn_list:
                hex_bytes = insn.bytes.hex()
                line = (
                    f"  0x{insn.address:08x}:  {hex_bytes:<20s}  {insn.mnemonic:<8s} {insn.op_str}"
                )
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
            console.print("[yellow](capstone not installed, showing hex dump)[/]")
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"  0x{va_int + i:08x}:  {hex_str:<48s}  {ascii_str}")

    except (OSError, KeyError, ValueError, TypeError) as e:
        error_exit(str(e), json_mode=json_output)


# ---------------------------------------------------------------------------
# NASM mode helpers (former nasm.py)
# ---------------------------------------------------------------------------


def extract_from_bin(bin_path: Path) -> bytes:
    """Load raw bytes from a binary blob file."""
    return bin_path.read_bytes()


def _get_capstone_x86() -> tuple[int, int, int, Any]:
    """Import capstone x86 constants/classes lazily."""
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_INTEL, Cs
    except ImportError as e:
        raise RuntimeError("capstone required. Install: pip install capstone") from e
    return CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_INTEL, Cs


def capstone_to_nasm(mnemonic: str, op_str: str) -> str:
    """Convert capstone Intel syntax to NASM-compatible syntax."""
    line = f"{mnemonic} {op_str}".strip() if op_str else mnemonic
    line = line.replace("ptr ", "")
    return line


def disassemble_to_nasm(
    code: bytes,
    base_va: int,
    label: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Disassemble bytes to NASM source with round-trip verification."""
    cs_arch_x86, cs_mode_32, cs_opt_syntax_intel, cs_cls = _get_capstone_x86()
    md = cs_cls(cs_arch_x86, cs_mode_32)
    md.syntax = cs_opt_syntax_intel
    md.detail = False

    instructions = list(md.disasm(code, base_va))
    total_insns = len(instructions)

    safe_label = None
    if label:
        safe_label = re.sub(r"[^a-zA-Z0-9_]", "_", label.lstrip("_"))
        if not safe_label or not safe_label[0].isalpha():
            safe_label = "func_" + safe_label

    insn_data = []
    for insn in instructions:
        nasm_text = capstone_to_nasm(insn.mnemonic, insn.op_str)
        insn_data.append(
            {
                "addr": insn.address,
                "raw": bytes(insn.bytes),
                "nasm": nasm_text,
                "offset": insn.address - base_va,
                "size": len(insn.bytes),
            }
        )

    covered = sum(i["size"] for i in insn_data)
    trailing = code[covered:] if covered < len(code) else b""

    pass1_lines = _build_nasm_lines(insn_data, base_va, safe_label, trailing, set())
    pass1_src = "\n".join(pass1_lines)
    pass1_bin = _run_nasm(pass1_src)

    bad_indices: set[int] = set()
    if pass1_bin is not None and len(pass1_bin) == len(code):
        for idx, entry in enumerate(insn_data):
            off = entry["offset"]
            sz = entry["size"]
            if pass1_bin[off : off + sz] != entry["raw"]:
                bad_indices.add(idx)
    else:
        bad_indices = _find_bad_instructions_individually(insn_data, base_va, code)

    final_lines = (
        _build_nasm_lines(insn_data, base_va, safe_label, trailing, bad_indices)
        if bad_indices
        else pass1_lines
    )

    db_fallbacks = len(bad_indices)
    nasm_ok = total_insns - db_fallbacks

    stats = {
        "total_instructions": total_insns,
        "nasm_ok": nasm_ok,
        "db_fallbacks": db_fallbacks,
        "pct_nasm": (nasm_ok / total_insns * 100) if total_insns else 0,
        "total_bytes": len(code),
        "base_va": base_va,
    }

    return "\n".join(final_lines), stats


def _find_bad_instructions_individually(
    insn_data: list[dict[str, Any]],
    base_va: int,
    code: bytes,
) -> set[int]:
    """Test each instruction by embedding it in a db-padded file."""
    bad: set[int] = set()
    total_insn_size = sum(e["size"] for e in insn_data)
    trailing = code[total_insn_size:]
    for idx, entry in enumerate(insn_data):
        src_lines = ["bits 32", f"org 0x{base_va:08X}"]
        for j, e in enumerate(insn_data):
            if j == idx:
                src_lines.append(e["nasm"])
            else:
                db_hex = ", ".join(f"0x{b:02X}" for b in e["raw"])
                src_lines.append(f"db {db_hex}")
        if trailing:
            db_hex = ", ".join(f"0x{b:02X}" for b in trailing)
            src_lines.append(f"db {db_hex}")
        result = _run_nasm("\n".join(src_lines))
        if result is None or len(result) != len(code):
            bad.add(idx)
            continue
        off = entry["offset"]
        sz = entry["size"]
        if result[off : off + sz] != entry["raw"]:
            bad.add(idx)
    return bad


def _build_nasm_lines(
    insn_data: list[dict[str, Any]],
    base_va: int,
    safe_label: str | None,
    trailing: bytes,
    db_indices: set[int],
) -> list[str]:
    lines: list[str] = []
    lines.append("bits 32")
    lines.append(f"org 0x{base_va:08X}")
    lines.append("")
    if safe_label:
        lines.append(f"{safe_label}:")
    for idx, entry in enumerate(insn_data):
        addr = entry["addr"]
        raw = entry["raw"]
        nasm_text = entry["nasm"]
        if idx in db_indices:
            db_hex = ", ".join(f"0x{b:02X}" for b in raw)
            lines.append(f"    db {db_hex:40s} ; {addr:08X}  {nasm_text}")
        else:
            lines.append(f"    {nasm_text:40s} ; {addr:08X}  {raw.hex()}")
    if trailing:
        db_hex = ", ".join(f"0x{b:02X}" for b in trailing)
        lines.append(f"    db {db_hex}  ; trailing data")
    lines.append("")
    return lines


def generate_inline_c(
    nasm_src: str,
    cfg: ProjectConfig,
    va: int,
    size: int,
    symbol: str | None,
) -> str:
    """Generate a C file with inline assembly using rebrew annotations."""
    cflags = cfg.base_cflags or "/O2 /Gd"
    marker = cfg.marker if cfg.marker else "TARGET"
    sym = symbol or f"_func_{va:08x}"
    func_name = sym.lstrip("_")

    lines: list[str] = []
    lines.append(f"// FUNCTION: {marker} 0x{va:08x}")
    lines.append(f"// CFLAGS: {cflags}")
    lines.append("")
    lines.append(f"void __declspec(naked) {func_name}(void)")
    lines.append("{")

    is_gcc = "clang" in cfg.compiler_profile.lower() or "gcc" in cfg.compiler_profile.lower()

    if is_gcc:
        lines.append("    __asm__(")
        for line in nasm_src.splitlines():
            line = line.strip()
            if (
                not line
                or line.startswith("bits 32")
                or line.startswith("org")
                or line.endswith(":")
            ):
                continue
            lines.append(f'        "{line}\\n"')
        lines.append("    );")
    else:
        lines.append("    __asm {")
        for line in nasm_src.splitlines():
            line = line.strip()
            if (
                not line
                or line.startswith("bits 32")
                or line.startswith("org")
                or line.endswith(":")
            ):
                continue
            if ";" in line:
                line = line.split(";", 1)[0].strip()
            if line.startswith("db "):
                bytes_str = line[3:].strip()
                for b in bytes_str.split(","):
                    b = b.strip()
                    if b:
                        lines.append(f"        _emit {b}")
            else:
                lines.append(f"        {line}")
        lines.append("    }")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _run_nasm(source: str) -> bytes | None:
    """Run nasm on source text, return binary output or None."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        asm_path = tmp / "input.asm"
        bin_path = tmp / "output.bin"
        asm_path.write_text(source, encoding="utf-8")
        try:
            r = subprocess.run(
                ["nasm", "-f", "bin", "-o", str(bin_path), str(asm_path)],
                capture_output=True,
                timeout=5,
            )
            if r.returncode != 0:
                return None
            if bin_path.exists():
                return bin_path.read_bytes()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None


def verify_roundtrip(nasm_source: str, original_bytes: bytes) -> tuple[bool, str]:
    """Assemble NASM source and verify it matches original bytes exactly."""
    result = _run_nasm(nasm_source)
    if result is None:
        return False, "NASM assembly failed"
    if result == original_bytes:
        return True, f"PASS: {len(original_bytes)} bytes identical"
    if len(result) != len(original_bytes):
        return False, f"FAIL: size mismatch (nasm={len(result)}, original={len(original_bytes)})"
    diffs = [i for i in range(len(original_bytes)) if result[i] != original_bytes[i]]
    return False, f"FAIL: {len(diffs)} byte diffs at offsets {diffs[:10]}"


def _parse_annotations(filepath: Path) -> list[dict[str, Any]]:
    """Parse reccmp-style annotations from a reversed .c file."""
    entries = parse_c_file_multi(filepath)
    results: list[dict[str, Any]] = []
    for entry in entries:
        if entry.status not in ("EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "PROVEN", "STUB"):
            continue
        if not entry.size:
            continue
        results.append(
            {
                "va": entry.va,
                "size": entry.size,
                "symbol": entry.symbol,
                "status": entry.status,
                "filepath": filepath,
            }
        )
    return results


def batch_extract_nasm(
    cfg: ProjectConfig,
    out_dir: Path,
    verify_flag: bool = False,
    stubs_only: bool = False,
) -> None:
    """Extract NASM for all annotated functions in reversed_dir."""
    reversed_dir = cfg.reversed_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    entries = []
    for cfile in iter_sources(reversed_dir, cfg):
        for info in _parse_annotations(cfile):
            if info["size"] < 6:
                continue
            if stubs_only and info["status"] != "STUB":
                continue
            entries.append(info)

    entries.sort(key=lambda x: x["va"])
    total = len(entries)
    ok = 0
    fail = 0

    for i, entry in enumerate(entries, 1):
        va = entry["va"]
        size = entry["size"]
        symbol = entry["symbol"] or f"func_{va:08x}"
        stem = entry["filepath"].name

        try:
            code = extract_raw_bytes(cfg.target_binary, va, size)
            if code is None:
                raise ValueError("VA not in any section")
        except (OSError, KeyError, ValueError) as e:
            console.print(f"  \\[{i}/{total}] {stem}: [yellow]SKIP[/] (extraction error: {e})")
            continue

        nasm_src, stats = disassemble_to_nasm(code, va, symbol)
        out_file = out_dir / f"{stem}.asm"
        out_file.write_text(nasm_src, encoding="utf-8")

        if verify_flag:
            passed, msg = verify_roundtrip(nasm_src, code)
            status = "PASS" if passed else f"FAIL ({msg})"
            if passed:
                ok += 1
            else:
                fail += 1
        else:
            status = "OK"
            ok += 1

        pct = stats["pct_nasm"]
        db = stats["db_fallbacks"]
        console.print(
            f"  \\[{i}/{total}] {stem:40s} {size:4d}B  nasm={pct:5.1f}% db={db:2d}  {status}"
        )

    console.print(f"\nDone: [green]{ok} ok[/], [red]{fail} failed[/], {total} total")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = """\
[bold]Examples:[/bold]

rebrew asm 0x10003ca0 --size 77             Disassemble (hex format, default)

rebrew asm --va 0x10003ca0 --size 77        Using named option

rebrew asm 0x10003ca0 --no-annotate         Skip call/jmp name annotations

rebrew asm --va 0x10003ca0 --size 77 --format nasm        NASM output

rebrew asm --va 0x10003ca0 --size 77 --format nasm --verify  Verify round-trip

rebrew asm --va 0x10003ca0 --size 77 --format nasm --inline-c -o f.c  Inline C

rebrew asm --all --out-dir output/asm/ --format nasm      Batch NASM extract

rebrew asm 0x10003ca0 --size 77 --json                    JSON output

[bold]Formats:[/bold]

hex    Capstone disassembly with hex dump and call annotation (default)

nasm   NASM-reassembleable source with optional round-trip verification

[dim]Uses capstone for x86 disassembly. Reads binary and arch from rebrew-project.toml.[/dim]"""

app = typer.Typer(
    help="Disassemble a function from the target binary (hex dump or NASM source).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    va_hex: str | None = typer.Argument(None, help="Function VA in hex"),
    va: str | None = typer.Option(None, "--va", help="Function VA in hex"),
    size: int | None = typer.Option(None, help="Function size in bytes"),
    fmt: str = typer.Option("hex", "--format", "-f", help="Output format: hex, nasm"),
    annotate: bool = typer.Option(
        True, "--annotate/--no-annotate", help="(hex) Annotate calls with known function names"
    ),
    # nasm-specific options
    bin_file: Path | None = typer.Option(None, "--bin", help="(nasm) Raw .bin file"),
    label: str | None = typer.Option(None, help="(nasm) Label name for the function"),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output file (default: stdout)"
    ),
    verify: bool = typer.Option(False, help="(nasm) Verify round-trip: assemble and compare"),
    stats: bool = typer.Option(False, help="(nasm) Print stats only, no ASM output"),
    inline_c: bool = typer.Option(
        False, "--inline-c", help="(nasm) Output a C file with inline ASM"
    ),
    extract_all: bool = typer.Option(False, "--all", help="(nasm) Batch extract all functions"),
    batch_stubs: bool = typer.Option(
        False, "--batch-stubs", help="(nasm) Batch: STUB functions only"
    ),
    out_dir: Path | None = typer.Option(None, "--out-dir", help="(nasm) Output dir for batch mode"),
    base_va: str = typer.Option("0", help="(nasm) Base VA for --bin files"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Disassemble a function from the target binary."""
    cfg = require_config(target=target, json_mode=json_output)

    if fmt not in ("hex", "nasm"):
        error_exit("--format must be 'hex' or 'nasm'", json_mode=json_output)

    # --- NASM batch modes ---
    if fmt == "nasm" and (extract_all or batch_stubs):
        batch_out_dir = out_dir or Path("output/asm")
        try:
            batch_extract_nasm(cfg, batch_out_dir, verify_flag=verify, stubs_only=batch_stubs)
        except RuntimeError as e:
            error_exit(str(e), json_mode=json_output)
        return

    # --- Resolve VA ---
    va_str = va or va_hex
    if not va_str and not bin_file:
        error_exit(
            "Specify VA as a positional argument, --va HEX, or --bin FILE", json_mode=json_output
        )

    effective_size = size or 32

    # --- hex format ---
    if fmt == "hex":
        if not va_str:
            error_exit("--format hex requires a VA (positional or --va)", json_mode=json_output)
        va_int = parse_va(va_str, json_mode=json_output)
        _run_hex_mode(va_int, effective_size, cfg, annotate, json_output)
        return

    # --- nasm format ---
    if bin_file:
        code = extract_from_bin(bin_file)
        computed_base_va = parse_va(base_va)
        computed_label = label or bin_file.stem
    elif va_str and effective_size:
        computed_va = parse_va(va_str)
        code = extract_raw_bytes(cfg.target_binary, computed_va, effective_size)
        if code is None:
            error_exit(f"Could not extract {effective_size} bytes at VA 0x{computed_va:08X}")
        computed_base_va = computed_va
        computed_label = label or f"func_{computed_va:08X}"
    else:
        error_exit(
            "Specify --va HEX --size N or --bin FILE for --format nasm", json_mode=json_output
        )

    try:
        nasm_src, run_stats = disassemble_to_nasm(code, computed_base_va, computed_label)
    except RuntimeError as e:
        error_exit(str(e))

    if inline_c:
        out_src = generate_inline_c(nasm_src, cfg, computed_base_va, len(code), computed_label)
    else:
        out_src = nasm_src

    if stats or json_output:
        result: dict[str, Any] = {
            "function": computed_label,
            "base_va": f"0x{run_stats['base_va']:08X}",
            "total_bytes": run_stats["total_bytes"],
            "total_instructions": run_stats["total_instructions"],
            "nasm_ok": run_stats["nasm_ok"],
            "pct_nasm": round(run_stats["pct_nasm"], 1),
            "db_fallbacks": run_stats["db_fallbacks"],
        }
        if verify:
            passed, msg = verify_roundtrip(nasm_src, code)
            result["roundtrip_pass"] = passed
            result["roundtrip_message"] = msg
        if json_output:
            json_print(result)
        else:
            console.print(f"[bold]Function:[/] {computed_label}")
            console.print(f"  Base VA: [cyan]0x{run_stats['base_va']:08X}[/]")
            console.print(f"  Size: {run_stats['total_bytes']} bytes")
            console.print(f"  Instructions: {run_stats['total_instructions']}")
            console.print(
                f"  NASM-compatible: {run_stats['nasm_ok']} ({run_stats['pct_nasm']:.1f}%)"
            )
            console.print(f"  db fallbacks: {run_stats['db_fallbacks']}")
        return

    if output:
        output.write_text(out_src, encoding="utf-8")
        console.print(f"Written to {output}")
    else:
        print(out_src)

    if verify:
        _, msg = verify_roundtrip(nasm_src, code)
        console.print(f"\nRound-trip verification: {msg}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
