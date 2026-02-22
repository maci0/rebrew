#!/usr/bin/env python3
"""Run FLIRT signature matching against functions in the target DLL.
Usage: uv run python tools/identify_libs.py [sig_dir]
"""

import os
import sys
import glob
import pefile
from typing import List, Tuple
from collections import defaultdict

try:
    import flirt
except ImportError:
    print("ERROR: flirt module not found. Run 'uv sync' to install dependencies.")
    sys.exit(1)

# SCRIPT_DIR removed — use load_config()
# PROJECT_ROOT removed — use cfg.root
DLL_PATH = os.path.join(PROJECT_ROOT, "original", "Server", "server.dll")

def extract_all_functions(exe_path: str) -> dict[int, bytes]:
    """Extract standard functions based on the text section for simple pattern matching."""
    pe = pefile.PE(exe_path)
    text_section = None
    for section in pe.sections:
        if b".text" in section.Name:
            text_section = section
            break
            
    if not text_section:
        return {}
        
    base_addr = pe.OPTIONAL_HEADER.ImageBase
    start_va = base_addr + text_section.VirtualAddress
    # We don't have perfect boundaries without IDA, so we just grab chunks
    # This is a naive heuristic specifically for the scanner. 
    # Realistically we'd use the `next_work.py` list if available, but for now we'll 
    # scan at known VA boundaries if we have them, or just let 'flirt' scan chunks
    
    # Actually, a better approach for the script: 
    # Let's import the `next_work.py` logic to get the VAs we need to check, 
    # or just read the whole text section and search.
    # We will grab all VAs from src/server_dll/*.c if they exist, or use a list.
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


def main():
    import argparse
    parser = argparse.ArgumentParser(description="FLIRT signature scanner for PE binaries")
    parser.add_argument("sig_dir", nargs="?", default=os.path.join(PROJECT_ROOT, "flirt_sigs"),
                        help="Directory containing .sig/.pat files")
    parser.add_argument("--exe", default=DLL_PATH, help="Target PE file")
    parser.add_argument("--min-size", type=int, default=16,
                        help="Minimum function size in bytes to report (default: 16)")
    args = parser.parse_args()

    # 1. Load FLIRT signatures
    sigs = load_signatures(args.sig_dir)
    if not sigs:
        print("No signatures loaded. Please provide a directory containing .sig or .pat files.")
        return
        
    print("Compiling FLIRT matching engine...")
    matcher = flirt.compile(sigs)
    
    # 2. Extract function bytes from DLL
    print(f"Analyzing {args.exe}...")
    pe = pefile.PE(args.exe)
    text_section = next((s for s in pe.sections if b".text" in s.Name), None)
    if not text_section:
        print("Could not find .text section.")
        return
        
    code_data = text_section.get_data()
    base_va = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress
    
    print(f"Searching for signature matches in {len(code_data)} bytes "
          f"(min function size: {args.min_size}B)...")
    
    found = 0
    skipped = 0
    stride = 16  # standard function alignment
    max_ambiguous = 3  # if more unique names match, it's noise
    
    for offset in range(0, len(code_data) - 32, stride):
        # Estimate the function size at this offset
        func_size = find_func_size(code_data, offset)
        if func_size < args.min_size:
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

if __name__ == "__main__":
    main()
