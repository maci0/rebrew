#!/usr/bin/env python3
"""Extract function bytes from PE and produce NASM-reassembleable ASM.

Round-trip guarantee: nasm -f bin output.asm → byte-identical to original.

When NASM encodes an instruction differently from the original binary
(e.g., mov ebp, esp as 89 E5 vs 8B EC), the tool falls back to raw
`db` directives to preserve exact bytes.

Usage:
    # Single function from PE
    uv run python nasm_extract.py --exe original/Server/server.dll --va 0x10003ca0 --size 77

    # Batch: all matched functions from server_dll/*.c
    uv run python tools/nasm_extract.py --batch --out-dir output/nasm/

    # Verify round-trip (assemble and compare)
    uv run python nasm_extract.py --exe original/Server/server.dll --va 0x10003ca0 --size 77 --verify

    # Show stats only
    uv run python nasm_extract.py --exe original/Server/server.dll --va 0x10003ca0 --size 77 --stats
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import pefile
except ImportError:
    pefile = None

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_INTEL, Cs
except ImportError:
    print("ERROR: capstone required. Install: pip install capstone", file=sys.stderr)
    sys.exit(1)

# SCRIPT_DIR removed — use load_config()
# PROJECT_ROOT removed — use cfg.root

try:
    from rebrew.config import cfg as _cfg
    DLL_PATH = _cfg.target_binary
    IMAGE_BASE = _cfg.image_base
    TEXT_VA = _cfg.text_va
    TEXT_RAW = _cfg.text_raw_offset
except Exception:
    DLL_PATH = PROJECT_ROOT / "original" / "Server" / "server.dll"
    IMAGE_BASE = 0x10000000
    TEXT_VA = 0x10001000
    TEXT_RAW = 0x1000


def va_to_offset(va: int) -> int:
    return va - TEXT_VA + TEXT_RAW


def extract_from_pe(exe_path: Path, va: int, size: int) -> bytes:
    with open(exe_path, "rb") as f:
        f.seek(va_to_offset(va))
        return f.read(size)


def extract_from_bin(bin_path: Path) -> bytes:
    return bin_path.read_bytes()


def capstone_to_nasm(mnemonic: str, op_str: str) -> str:
    """Convert capstone Intel syntax to NASM-compatible syntax."""
    line = f"{mnemonic} {op_str}".strip() if op_str else mnemonic

    line = line.replace("ptr ", "")

    line = re.sub(r"\b0x([0-9a-fA-F]+)\b", r"0x\1", line)

    return line


def disassemble_to_nasm(
    code: bytes,
    base_va: int,
    label: Optional[str] = None,
) -> Tuple[str, Dict]:
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

    bad_indices: set = set()
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
    insn_data: List[Dict],
    base_va: int,
    code: bytes,
) -> set:
    """Per-instruction fallback: test each instruction by embedding it in a
    db-padded file at its correct offset, then checking its bytes."""
    bad = set()
    for idx, entry in enumerate(insn_data):
        src_lines = [f"bits 32", f"org 0x{base_va:08X}"]
        for j, e in enumerate(insn_data):
            if j == idx:
                src_lines.append(e["nasm"])
            else:
                db_hex = ", ".join(f"0x{b:02X}" for b in e["raw"])
                src_lines.append(f"db {db_hex}")
        trailing = code[sum(e["size"] for e in insn_data) :]
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
    insn_data: List[Dict],
    base_va: int,
    safe_label: Optional[str],
    trailing: bytes,
    db_indices: set,
) -> List[str]:
    lines: List[str] = []
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


def _run_nasm(source: str) -> Optional[bytes]:
    """Run nasm on source text, return binary output or None."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".asm", delete=False) as f:
        f.write(source)
        asm_path = f.name

    bin_path = asm_path + ".bin"
    try:
        r = subprocess.run(
            ["nasm", "-f", "bin", "-o", bin_path, asm_path],
            capture_output=True,
            timeout=5,
        )
        if r.returncode != 0:
            return None
        if os.path.exists(bin_path):
            with open(bin_path, "rb") as f:
                return f.read()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    finally:
        for p in (asm_path, bin_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def verify_roundtrip(nasm_source: str, original_bytes: bytes) -> Tuple[bool, str]:
    """Assemble NASM source and verify it matches original bytes exactly."""
    result = _run_nasm(nasm_source)
    if result is None:
        return False, "NASM assembly failed"
    if result == original_bytes:
        return True, f"PASS: {len(original_bytes)} bytes identical"
    if len(result) != len(original_bytes):
        return False, (
            f"FAIL: size mismatch (nasm={len(result)}, original={len(original_bytes)})"
        )
    diffs = []
    for i in range(len(original_bytes)):
        if result[i] != original_bytes[i]:
            diffs.append(i)
    return False, (f"FAIL: {len(diffs)} byte diffs at offsets {diffs[:10]}")


def parse_annotations(filepath: Path) -> Optional[Dict]:
    """Parse reccmp-style annotations from a reversed .c file."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    va = None
    kv: Dict[str, str] = {}

    for line in text.split("\n")[:20]:
        m = re.match(
            r"//\s*(?:FUNCTION|LIBRARY|STUB):\s*SERVER\s+(0x[0-9a-fA-F]+)",
            line.strip(),
        )
        if m:
            va = m.group(1)
            continue
        m2 = re.match(r"//\s*(\w+):\s*(.*)", line.strip())
        if m2:
            kv[m2.group(1).upper()] = m2.group(2).strip()

    if va is None:
        return None

    status = kv.get("STATUS", "")
    if status not in ("EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB"):
        return None

    size_str = kv.get("SIZE", "0")
    try:
        size = int(size_str)
    except ValueError:
        return None

    return {
        "va": int(va, 16),
        "size": size,
        "symbol": kv.get("SYMBOL", ""),
        "status": status,
        "filepath": filepath,
    }


def batch_extract(
    exe_path: Path,
    out_dir: Path,
    verify: bool = False,
    stubs_only: bool = False,
) -> None:
    """Extract NASM for all annotated functions in server_dll/*.c."""
    try:
        from rebrew.config import cfg as _cfg
        reversed_dir = _cfg.reversed_dir
    except Exception:
        reversed_dir = PROJECT_ROOT / "src" / "server_dll"
    out_dir.mkdir(parents=True, exist_ok=True)

    entries = []
    for cfile in sorted(reversed_dir.glob("*.c")):
        info = parse_annotations(cfile)
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
            code = extract_from_pe(exe_path, va, size)
        except Exception as e:
            print(f"  [{i}/{total}] {stem}: SKIP (extraction error: {e})")
            continue

        nasm_src, stats = disassemble_to_nasm(code, va, symbol)

        out_file = out_dir / f"{stem}.asm"
        out_file.write_text(nasm_src, encoding="utf-8")

        status = "OK"
        if verify:
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
            f"  [{i}/{total}] {stem:40s} {size:4d}B  "
            f"nasm={pct:5.1f}% db={db:2d}  {status}"
        )

    print(f"\nDone: {ok} ok, {fail} failed, {total} total")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract function bytes to NASM-reassembleable ASM"
    )
    parser.add_argument(
        "--exe", help="PE executable (default: original/Server/server.dll)"
    )
    parser.add_argument("--va", help="Virtual address (hex)")
    parser.add_argument("--size", type=int, help="Function size in bytes")
    parser.add_argument("--bin", help="Raw .bin file")
    parser.add_argument("--label", help="Label name for the function")
    parser.add_argument("--out", "-o", help="Output .asm file (default: stdout)")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify round-trip: assemble output and compare to original",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print stats only (no ASM output)",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Batch mode: extract all functions from server_dll/*.c",
    )
    parser.add_argument(
        "--batch-stubs",
        action="store_true",
        help="Batch mode: extract only STUB functions",
    )
    parser.add_argument(
        "--out-dir",
        help="Output directory for batch mode (default: output/nasm/)",
    )
    parser.add_argument(
        "--base-va",
        type=lambda x: int(x, 16),
        default=0,
        help="Base VA for .bin files (default: 0)",
    )
    args = parser.parse_args()

    if args.batch or args.batch_stubs:
        exe_path = Path(args.exe) if args.exe else DLL_PATH
        out_dir = Path(args.out_dir) if args.out_dir else Path("output/nasm")
        batch_extract(
            exe_path,
            out_dir,
            verify=args.verify,
            stubs_only=args.batch_stubs,
        )
        return

    if args.bin:
        code = extract_from_bin(Path(args.bin))
        base_va = args.base_va
        label = args.label or Path(args.bin).stem
    elif args.va and args.size:
        exe_path = Path(args.exe) if args.exe else DLL_PATH
        va = int(args.va, 16)
        code = extract_from_pe(exe_path, va, args.size)
        base_va = va
        label = args.label or f"func_{va:08X}"
    else:
        parser.error("Specify --bin FILE or --va HEX --size N")
        return

    nasm_src, stats = disassemble_to_nasm(code, base_va, label)

    if args.stats:
        print(f"Function: {label}")
        print(f"  Base VA: 0x{stats['base_va']:08X}")
        print(f"  Size: {stats['total_bytes']} bytes")
        print(f"  Instructions: {stats['total_instructions']}")
        print(f"  NASM-compatible: {stats['nasm_ok']} ({stats['pct_nasm']:.1f}%)")
        print(f"  db fallbacks: {stats['db_fallbacks']}")
        return

    if args.verify:
        passed, msg = verify_roundtrip(nasm_src, code)
        if not passed:
            print(f"VERIFICATION FAILED: {msg}", file=sys.stderr)

    if args.out:
        Path(args.out).write_text(nasm_src, encoding="utf-8")
        print(f"Written to {args.out}")
        passed, msg = verify_roundtrip(nasm_src, code)
        print(f"Round-trip: {msg}")
    else:
        print(nasm_src)

    if args.verify:
        passed, msg = verify_roundtrip(nasm_src, code)
        print(f"\nRound-trip verification: {msg}")


if __name__ == "__main__":
    main()
