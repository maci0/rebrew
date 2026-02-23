#!/usr/bin/env python3
"""Run FLIRT signature matching against functions in the target binary.
Usage: rebrew-flirt [sig_dir]
"""

import glob
import os
import sys
from pathlib import Path

from rebrew.binary_loader import load_binary

try:
    import flirt
except ImportError:
    print("ERROR: flirt module not found. Run 'uv sync' to install dependencies.")
    sys.exit(1)

import typer

from rebrew.cli import TargetOption, get_config


def extract_all_functions(exe_path: str) -> dict[int, bytes]:
    """Extract standard functions based on the text section for simple pattern matching."""
    info = load_binary(exe_path)
    if ".text" not in info.sections and "__text" not in info.sections:
        return {}
    return {}

def load_signatures(sig_dir: str):
    print(f"Loading signatures from {sig_dir}...")
    sigs = []

    if not os.path.exists(sig_dir):
        print(f"Signature directory {sig_dir} not found.")
        return []

    for file in glob.glob(os.path.join(sig_dir, "*.sig")) + glob.glob(os.path.join(sig_dir, "*.pat")):
        try:
            with open(file, "rb") as f:
                content = f.read()
            if file.endswith('.sig'):
                parsed = flirt.parse_sig(content)
            else:
                parsed = flirt.parse_pat(content.decode('utf-8', errors='ignore'))
            sigs.extend(parsed)
            print(f"Loaded {len(parsed)} signatures from {os.path.basename(file)}")
        except Exception as e:
            print(f"Error loading {file}: {e}")

    return sigs

def find_func_size(code_data, offset):
    """Estimate function size by scanning for common end patterns."""
    # Look for ret (0xC3), ret imm16 (0xC2), or int3 padding (0xCC)
    max_scan = min(4096, len(code_data) - offset)
    for i in range(offset, offset + max_scan):
        b = code_data[i]
        if b == 0xC3:  # ret
            return i - offset + 1
        if b == 0xC2 and i + 2 < len(code_data):  # ret imm16
            return i - offset + 3
    return max_scan


app = typer.Typer(help="FLIRT signature scanner for binaries")

@app.callback(invoke_without_command=True)
def main(
    sig_dir: Path | None = typer.Argument(None, help="Directory containing .sig/.pat files"),
    exe: Path | None = typer.Option(None, help="Target PE file (default: from config)"),
    min_size: int = typer.Option(16, help="Minimum function size in bytes to report (default: 16)"),
    target: str | None = TargetOption,
):
    """FLIRT signature scanner for binaries"""
    cfg = get_config(target=target)

    final_sig_dir = sig_dir or (cfg.root / "flirt_sigs")
    final_exe = exe or cfg.target_binary

    # 1. Load FLIRT signatures
    sigs = load_signatures(str(final_sig_dir))
    if not sigs:
        print("No signatures loaded. Please provide a directory containing .sig or .pat files.")
        return

    print("Compiling FLIRT matching engine...")
    matcher = flirt.compile(sigs)

    # 2. Extract function bytes from binary
    print(f"Analyzing {final_exe}...")
    info = load_binary(final_exe)

    # Find the text section (PE: .text, Mach-O: __text)
    text_name = ".text" if ".text" in info.sections else "__text"
    if text_name not in info.sections:
        print("Could not find .text section.")
        return

    text_sec = info.sections[text_name]
    code_data = info.data[text_sec.file_offset : text_sec.file_offset + text_sec.raw_size]
    base_va = text_sec.va

    print(f"Searching for signature matches in {len(code_data)} bytes "
          f"(min function size: {min_size}B)...")

    found = 0
    skipped = 0
    stride = 16  # standard function alignment
    max_ambiguous = 3  # if more unique names match, it's noise

    for offset in range(0, len(code_data) - 32, stride):
        # Estimate the function size at this offset
        func_size = find_func_size(code_data, offset)
        if func_size < min_size:
            continue

        matches = matcher.match(code_data[offset:offset + 1024])
        if matches:
            va = base_va + offset
            names = []
            for m in matches:
                for n in m.names:
                    # n is (name, type, offset) tuple
                    label = n[0] if isinstance(n, tuple) else str(n)
                    if label and label not in names:
                        names.append(label)
            if not names:
                continue
            if len(names) > max_ambiguous:
                skipped += 1
                continue
            print(f"[+] 0x{va:08x} ({func_size:4d}B): {', '.join(names)}")
            found += 1

    print(f"\nTotal matches found: {found}")
    if skipped:
        print(f"Skipped {skipped} ambiguous matches (>{max_ambiguous} candidate names)")

def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
