#!/usr/bin/env python3
"""Extract function bytes from PE and produce NASM-reassembleable ASM.

Round-trip guarantee: nasm -f bin output.asm → byte-identical to original.

When NASM encodes an instruction differently from the original binary
(e.g., mov ebp, esp as 89 E5 vs 8B EC), the tool falls back to raw
`db` directives to preserve exact bytes.

Usage:
    # Single function from PE
    rebrew nasm --va 0x10003ca0 --size 77

    # Batch: all matched functions from reversed_dir
    rebrew nasm --batch --out-dir output/nasm/

    # Verify round-trip (assemble and compare)
    rebrew nasm --va 0x10003ca0 --size 77 --verify
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import parse_c_file
from rebrew.cli import TargetOption, get_config

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_INTEL, Cs
except ImportError:
    print("ERROR: capstone required. Install: pip install capstone", file=sys.stderr)
    raise typer.Exit(code=1) from None


def extract_from_bin(bin_path: Path) -> bytes:
    return bin_path.read_bytes()


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
    """Disassemble bytes to NASM source with round-trip verification.

    Two-pass approach:
    1. Disassemble all instructions, emit as NASM, assemble entire file
    2. Compare assembled output byte-by-byte against original
    3. Replace only mismatching instructions with db directives
    4. Verify final output assembles to identical bytes
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.syntax = CS_OPT_SYNTAX_INTEL
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

    if bad_indices:
        final_lines = _build_nasm_lines(
            insn_data,
            base_va,
            safe_label,
            trailing,
            bad_indices,
        )
    else:
        final_lines = pass1_lines

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
    """Per-instruction fallback: test each instruction by embedding it in a
    db-padded file at its correct offset, then checking its bytes."""
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


def _run_nasm(source: str) -> bytes | None:
    """Run nasm on source text, return binary output or None.

    Uses a TemporaryDirectory so that both the .asm input and .bin output
    are cleaned up automatically — even if the process is killed mid-run.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        asm_path = os.path.join(tmpdir, "input.asm")
        bin_path = os.path.join(tmpdir, "output.bin")
        with open(asm_path, "w", encoding="utf-8") as f:
            f.write(source)
        try:
            r = subprocess.run(
                ["nasm", "-f", "bin", "-o", bin_path, asm_path],
                capture_output=True,
                timeout=5,
            )
            if r.returncode != 0:
                return None
            if os.path.exists(bin_path):
                with open(bin_path, "rb") as fout:
                    return fout.read()
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
        return False, (f"FAIL: size mismatch (nasm={len(result)}, original={len(original_bytes)})")
    diffs = []
    for i in range(len(original_bytes)):
        if result[i] != original_bytes[i]:
            diffs.append(i)
    return False, (f"FAIL: {len(diffs)} byte diffs at offsets {diffs[:10]}")


def _parse_annotations(filepath: Path) -> dict[str, Any] | None:
    """Parse reccmp-style annotations from a reversed .c file.

    Uses the canonical parser from rebrew.annotation.parse_c_file,
    then slims the result to the fields batch_extract needs.
    """
    entry = parse_c_file(filepath)
    if entry is None:
        return None

    status = entry["status"]
    if status not in ("EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB"):
        return None

    size = entry["size"]
    if not size:
        return None

    return {
        "va": entry["va"],
        "size": size,
        "symbol": entry["symbol"],
        "status": status,
        "filepath": filepath,
    }


def batch_extract(
    cfg: Any,
    out_dir: Path,
    verify_flag: bool = False,
    stubs_only: bool = False,
) -> None:
    """Extract NASM for all annotated functions in reversed_dir."""
    reversed_dir = cfg.reversed_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    from rebrew.cli import iter_sources

    entries = []
    for cfile in iter_sources(reversed_dir, cfg):
        info = _parse_annotations(cfile)
        if info is None:
            continue
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
        stem = entry["filepath"].stem

        try:
            code = cfg.extract_dll_bytes(va, size)
            if code is None:
                raise ValueError("VA not in any section")
        except (OSError, KeyError, ValueError) as e:
            print(f"  [{i}/{total}] {stem}: SKIP (extraction error: {e})", file=sys.stderr)
            continue

        nasm_src, stats = disassemble_to_nasm(code, va, symbol)

        out_file = out_dir / f"{stem}.asm"
        out_file.write_text(nasm_src, encoding="utf-8")

        status = "OK"
        if verify_flag:
            passed, msg = verify_roundtrip(nasm_src, code)
            status = "PASS" if passed else f"FAIL ({msg})"
            if passed:
                ok += 1
            else:
                fail += 1
        else:
            ok += 1

        pct = stats["pct_nasm"]
        db = stats["db_fallbacks"]
        print(
            f"  [{i}/{total}] {stem:40s} {size:4d}B  nasm={pct:5.1f}% db={db:2d}  {status}",
            file=sys.stderr,
        )

    print(f"\nDone: {ok} ok, {fail} failed, {total} total", file=sys.stderr)


app = typer.Typer(
    help="Extract function bytes from PE and produce NASM-reassembleable ASM.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]
  rebrew-nasm 0x10003da0                         Extract and disassemble one function
  rebrew-nasm 0x10003da0 --size 128              Specify function size
  rebrew-nasm 0x10003da0 -o func.asm             Write NASM output to file
  rebrew-nasm 0x10003da0 --raw                   Output raw bytes only

[bold]How it works:[/bold]
  Extracts raw bytes at the given VA from the PE binary, disassembles
  them with capstone, and emits NASM-syntax assembly with relocations
  annotated so the output can be reassembled with 'nasm'.

[dim]Useful for understanding compiler output and verifying relocation
patterns. Requires capstone and rebrew.toml.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    exe: Path | None = typer.Option(None, help="PE executable (default: from config)"),
    va: str | None = typer.Option(None, help="Virtual address (hex)"),
    size: int | None = typer.Option(None, help="Function size in bytes"),
    bin: Path | None = typer.Option(None, help="Raw .bin file"),
    label: str | None = typer.Option(None, help="Label name for the function"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Output .asm file (default: stdout)"),
    verify: bool = typer.Option(
        False, help="Verify round-trip: assemble output and compare to original"
    ),
    stats: bool = typer.Option(False, help="Print stats only (no ASM output)"),
    batch: bool = typer.Option(False, help="Batch mode: extract all functions from reversed_dir"),
    batch_stubs: bool = typer.Option(False, help="Batch mode: extract only STUB functions"),
    out_dir: Path | None = typer.Option(
        None, help="Output directory for batch mode (default: output/nasm/)"
    ),
    base_va: str = typer.Option("0", help="Base VA for .bin files (default: 0)"),
    target: str | None = TargetOption,
) -> None:
    """Extract function bytes from PE and produce NASM-reassembleable ASM."""
    cfg = get_config(target=target)

    if batch or batch_stubs:
        batch_out_dir = out_dir or Path("output/nasm")
        batch_extract(
            cfg,
            batch_out_dir,
            verify_flag=verify,
            stubs_only=batch_stubs,
        )
        return

    if bin:
        code = extract_from_bin(bin)
        computed_base_va = int(base_va, 16)
        computed_label = label or bin.stem
    elif va and size:
        computed_va = int(va, 16)
        code = cfg.extract_dll_bytes(computed_va, size)
        if code is None:
            print(
                f"Error: could not extract {size} bytes at VA 0x{computed_va:08X}", file=sys.stderr
            )
            raise typer.Exit(code=1)
        computed_base_va = computed_va
        computed_label = label or f"func_{computed_va:08X}"
    else:
        print("ERROR: Specify either --bin FILE or --va HEX --size N", file=sys.stderr)
        raise typer.Exit(code=1)

    nasm_src, run_stats = disassemble_to_nasm(code, computed_base_va, computed_label)

    if stats:
        print(f"Function: {computed_label}")
        print(f"  Base VA: 0x{run_stats['base_va']:08X}")
        print(f"  Size: {run_stats['total_bytes']} bytes")
        print(f"  Instructions: {run_stats['total_instructions']}")
        print(f"  NASM-compatible: {run_stats['nasm_ok']} ({run_stats['pct_nasm']:.1f}%)")
        print(f"  db fallbacks: {run_stats['db_fallbacks']}")
        return

    if out:
        out.write_text(nasm_src, encoding="utf-8")
        print(f"Written to {out}")
    else:
        print(nasm_src)

    if verify:
        _, msg = verify_roundtrip(nasm_src, code)
        print(f"\nRound-trip verification: {msg}")


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
