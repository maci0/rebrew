#!/usr/bin/env python3
"""gen_skeleton.py - Generate .c skeleton file for an uncovered function.

Given a VA address, generates a properly annotated .c file skeleton with:
- reccmp-style annotations (FUNCTION/LIBRARY marker, STATUS, ORIGIN, SIZE, CFLAGS, SYMBOL)
- Placeholder function body
- The exact test_func.py command to verify it

Usage:
    python tools/gen_skeleton.py 0x10003da0                    # Auto-detect origin
    python tools/gen_skeleton.py 0x10003da0 --origin GAME      # Force origin
    python tools/gen_skeleton.py 0x10003da0 --name my_func     # Custom name
    python tools/gen_skeleton.py 0x10003da0 --output path.c    # Custom output path
    python tools/gen_skeleton.py --list                        # List all uncovered functions
    python tools/gen_skeleton.py --list --origin GAME          # List uncovered GAME functions
"""

import typer
from typing import Optional
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

# SCRIPT_DIR removed — use load_config()
# PROJECT_ROOT removed — use cfg.root

try:
    from rebrew.config import cfg as _cfg
    SRC_DIR = str(_cfg.reversed_dir)
    GHIDRA_JSON = os.path.join(SRC_DIR, "ghidra_functions.json")
except Exception:
    SRC_DIR = os.path.join(PROJECT_ROOT, "src", "server_dll")
    GHIDRA_JSON = os.path.join(SRC_DIR, "ghidra_functions.json")

# Address ranges for origin detection
# GAME code: 0x10001000 - 0x10018fff (approx)
# CRT/MSVCRT: 0x10019000+ (higher addresses, CRT library code)
# ZLIB: identified by known function list
GAME_RANGE_END = 0x10019000

# Known ASM builtins that cannot be matched from C source
ASM_BUILTINS = {
    "memset",
    "strcmp",
    "strstr",
    "strchr",
    "strlen",
    "strncpy",
    "strpbrk",
    "strcspn",
    "__local_unwind2",
    "__aulldiv",
    "__aullrem",
    "__alloca_probe",
    "_chkstk",
    "__except_handler3",
}

# Known zlib function VAs (from AGENTS.md)
ZLIB_VAS = {
    0x10001000,  # adler32
    0x10001330,  # deflateInit2_
    0x10001530,  # init_stream
    0x10001860,  # copy_fields
    0x10001890,  # inflate helper
    0x100057C0,  # inflateInit2_
    0x100058D0,  # inflate
    0x10004BC0,  # inflate_codes
    0x10005390,  # inflate_fast
    0x100015B0,  # inflate_blocks
    0x10005D00,  # inflate_trees_bits
    0x10005DB0,  # huft_build
    0x10006280,  # inflate_trees_dynamic
    0x10006EC0,  # zlib tree helper
    0x10006FB0,  # inflate helper
    0x10007050,  # inflate helper
    0x100092E0,  # zcalloc
    0x10009300,  # zcfree
}

# Default cflags by origin
DEFAULT_CFLAGS = {
    "GAME": "/O2 /Gd",
    "MSVCRT": "/O1",
    "ZLIB": "/O2",
}

# Marker type by origin
MARKER_TYPE = {
    "GAME": "FUNCTION",
    "MSVCRT": "LIBRARY",
    "ZLIB": "LIBRARY",
}


def load_ghidra_functions() -> List[dict]:
    """Load Ghidra function list."""
    if not os.path.exists(GHIDRA_JSON):
        print(
            f"ERROR: {GHIDRA_JSON} not found. Run: uv run python tools/validate.py --export-ghidra",
            file=sys.stderr,
        )
        sys.exit(1)
    with open(GHIDRA_JSON) as f:
        return json.load(f)


def load_existing_vas() -> Dict[int, str]:
    """Load VAs already covered by .c files. Returns {va: filename}."""
    existing = {}
    for fname in os.listdir(SRC_DIR):
        if not fname.endswith(".c"):
            continue
        filepath = os.path.join(SRC_DIR, fname)
        with open(filepath) as f:
            content = f.read(512)  # Only need the header
        m = re.search(
            r"(?:FUNCTION|LIBRARY|STUB):\s*SERVER\s+(0x[0-9a-fA-F]+)", content
        )
        if m:
            existing[int(m.group(1), 16)] = fname
    return existing


def detect_origin(va: int, ghidra_name: str) -> str:
    """Detect function origin based on VA and name."""
    if va in ZLIB_VAS:
        return "ZLIB"
    if va >= GAME_RANGE_END:
        return "MSVCRT"
    # Some CRT functions can appear in low addresses too
    if ghidra_name.startswith("__") or ghidra_name.startswith("_crt"):
        return "MSVCRT"
    return "GAME"


def sanitize_name(ghidra_name: str) -> str:
    """Convert Ghidra name to a safe C filename prefix."""
    # Strip FUN_ prefix
    name = ghidra_name
    if name.startswith("FUN_"):
        # Use the address as the name
        return "func_" + name[4:].lower()
    # Clean up special chars
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    return name


def make_filename(
    va: int, ghidra_name: str, origin: str, custom_name: Optional[str] = None
) -> str:
    """Generate the .c filename following project naming conventions."""
    if custom_name:
        base = custom_name
    elif ghidra_name.startswith("FUN_"):
        base = "func_" + ghidra_name[4:].lower()
    else:
        base = sanitize_name(ghidra_name)

    # Apply origin prefix convention
    prefix_map = {"GAME": "game_", "MSVCRT": "crt_", "ZLIB": "zlib_"}
    prefix = prefix_map.get(origin, "")

    # Don't double-prefix
    if not base.startswith(prefix) and not base.startswith("func_"):
        base = prefix + base

    return base + ".c"


def generate_skeleton(
    va: int, size: int, ghidra_name: str, origin: str, custom_name: Optional[str] = None
) -> str:
    """Generate the .c file content."""
    marker = MARKER_TYPE.get(origin, "FUNCTION")
    cflags = DEFAULT_CFLAGS.get(origin, "/O2 /Gd")

    # Determine symbol name
    if custom_name:
        symbol = "_" + custom_name
    elif ghidra_name.startswith("FUN_"):
        symbol = "_" + sanitize_name(ghidra_name)
    else:
        symbol = "_" + sanitize_name(ghidra_name)

    # Generate function name (without leading underscore for C)
    func_name = symbol.lstrip("_")

    lines = []
    lines.append(f"// {marker}: SERVER 0x{va:08x}")
    lines.append(f"// STATUS: STUB")
    lines.append(f"// BLOCKER: initial decompilation - needs analysis")
    lines.append(f"// ORIGIN: {origin}")
    lines.append(f"// SIZE: {size}")
    lines.append(f"// CFLAGS: {cflags}")
    lines.append(f"// SYMBOL: {symbol}")
    lines.append(f"")

    if origin == "GAME":
        lines.append(
            f"/* TODO: Add extern declarations for globals and called functions */"
        )
        lines.append(f"")
        lines.append(f"int __cdecl {func_name}(void)")
        lines.append(f"{{")
        lines.append(f"    /* TODO: Implement based on Ghidra decompilation */")
        lines.append(f"    /* Ghidra name: {ghidra_name} */")
        lines.append(f"    return 0;")
        lines.append(f"}}")
    elif origin == "MSVCRT":
        lines.append(
            f"/* CRT function - check tools/MSVC600/VC98/CRT/SRC/ for original source */"
        )
        lines.append(
            f"/* Also check: https://github.com/shihyu/learn_c/tree/master/vc_lib_src/src */"
        )
        lines.append(f"")
        lines.append(f"int __cdecl {func_name}(void)")
        lines.append(f"{{")
        lines.append(f"    /* TODO: Implement from CRT source */")
        lines.append(f"    /* Ghidra name: {ghidra_name} */")
        lines.append(f"    return 0;")
        lines.append(f"}}")
    elif origin == "ZLIB":
        lines.append(
            f"/* zlib 1.1.3 function - check references/zlib-1.1.3/ for original source */"
        )
        lines.append(f"")
        lines.append(f"int __cdecl {func_name}(void)")
        lines.append(f"{{")
        lines.append(f"    /* TODO: Implement from zlib 1.1.3 source */")
        lines.append(f"    /* Ghidra name: {ghidra_name} */")
        lines.append(f"    return 0;")
        lines.append(f"}}")

    lines.append(f"")

    return "\n".join(lines)


def generate_test_command(
    filepath: str, symbol: str, va: int, size: int, cflags: str
) -> str:
    """Generate the exact test_func.py command to verify this function."""
    return (
        f"uv run python tools/test_func.py {filepath} {symbol} "
        f'--va 0x{va:08x} --size {size} --cflags "{cflags}"'
    )


def generate_diff_command(
    filepath: str, symbol: str, va: int, size: int, cflags: str
) -> str:
    """Generate the matcher.py diff command."""
    return (
        f"uv run python tools/matcher.py "
        f'--cl "wine tools/MSVC600/VC98/Bin/CL.EXE" '
        f'--inc "tools/MSVC600/VC98/Include" '
        f'--cflags "/nologo /c /MT {cflags}" '
        f"--compare-obj "
        f"--diff-only {filepath} "
        f"--target-exe original/Server/server.dll "
        f"--target-va 0x{va:08x} --target-size {size} "
        f'--symbol "{symbol}" --seed-c {filepath}'
    )


def list_uncovered(
    ghidra_funcs: List[dict],
    existing_vas: Dict[int, str],
    origin_filter: Optional[str] = None,
    min_size: int = 10,
    max_size: int = 9999,
) -> List[Tuple[int, int, str, str]]:
    """List uncovered functions. Returns [(va, size, ghidra_name, origin)]."""
    uncovered = []
    for func in ghidra_funcs:
        va = func["va"]
        size = func["size"]
        name = func.get("ghidra_name", f"FUN_{va:08x}")

        if va in existing_vas:
            continue
        if size < min_size or size > max_size:
            continue
        if name in ASM_BUILTINS:
            continue

        origin = detect_origin(va, name)
        if origin_filter and origin != origin_filter:
            continue

        uncovered.append((va, size, name, origin))

    uncovered.sort(key=lambda x: x[1])  # Sort by size
    return uncovered


app = typer.Typer(help="Generate .c skeleton files for uncovered server.dll functions.")


@app.command()
def main(
    va: Optional[str] = typer.Argument(None, help="Function VA in hex (e.g. 0x10003da0)"),
    name: Optional[str] = typer.Option(None, help="Custom function name"),
    origin: Optional[str] = typer.Option(None, help="Force origin type (GAME, MSVCRT, ZLIB)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    list_mode: bool = typer.Option(False, "--list", help="List uncovered functions"),
    batch: Optional[int] = typer.Option(None, help="Generate N skeletons (smallest first)"),
    min_size: int = typer.Option(10, help="Minimum function size"),
    max_size: int = typer.Option(9999, help="Maximum function size"),
    force: bool = typer.Option(False, help="Overwrite existing files"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target from rebrew.toml"),
):
    """Generate .c skeleton files for uncovered server.dll functions."""
    args = type("Args", (), {
        "va": va, "name": name, "origin": origin, "output": output,
        "list": list_mode, "batch": batch, "min_size": min_size,
        "max_size": max_size, "force": force,
    })()

    ghidra_funcs = load_ghidra_functions()
    existing_vas = load_existing_vas()

    # --list mode
    if args.list:
        uncovered = list_uncovered(
            ghidra_funcs, existing_vas, args.origin, args.min_size, args.max_size
        )
        if not uncovered:
            print("No uncovered functions found matching criteria.")
            return

        print(f"Uncovered functions: {len(uncovered)}")
        print(f"{'VA':>12s}  {'Size':>5s}  {'Origin':>6s}  {'Name'}")
        print(f"{'---':>12s}  {'---':>5s}  {'---':>6s}  {'---'}")
        for va, size, name, origin in uncovered:
            print(f"  0x{va:08x}  {size:4d}B  {origin:>6s}  {name}")

        # Summary
        by_origin = {}
        for _, _, _, origin in uncovered:
            by_origin[origin] = by_origin.get(origin, 0) + 1
        print(
            f"\nBy origin: {', '.join(f'{k}: {v}' for k, v in sorted(by_origin.items()))}"
        )
        return

    # --batch mode
    if args.batch:
        uncovered = list_uncovered(
            ghidra_funcs, existing_vas, args.origin, args.min_size, args.max_size
        )
        if not uncovered:
            print("No uncovered functions found matching criteria.")
            return

        count = min(args.batch, len(uncovered))
        created = []
        for va, size, name, origin in uncovered[:count]:
            filename = make_filename(va, name, origin)
            filepath = os.path.join(SRC_DIR, filename)
            rel_path = os.path.relpath(filepath, PROJECT_ROOT)

            if os.path.exists(filepath) and not args.force:
                print(f"SKIP: {rel_path} (already exists)")
                continue

            content = generate_skeleton(va, size, name, origin)
            with open(filepath, "w") as f:
                f.write(content)

            symbol = "_" + sanitize_name(name)
            cflags = DEFAULT_CFLAGS.get(origin, "/O2 /Gd")
            test_cmd = generate_test_command(rel_path, symbol, va, size, cflags)

            print(f"CREATED: {rel_path} ({size}B, {origin})")
            print(f"  TEST: {test_cmd}")
            created.append(rel_path)

        print(f"\nCreated {len(created)} skeleton files.")
        return

    # Single VA mode
    if not args.va:
        parser.print_help()
        sys.exit(1)

    va = int(args.va, 16)

    # Find in Ghidra functions
    ghidra_entry = None
    for func in ghidra_funcs:
        if func["va"] == va:
            ghidra_entry = func
            break

    if not ghidra_entry:
        print(
            f"ERROR: VA 0x{va:08x} not found in ghidra_functions.json", file=sys.stderr
        )
        sys.exit(1)

    size = ghidra_entry["size"]
    ghidra_name = ghidra_entry.get("ghidra_name", f"FUN_{va:08x}")

    # Check if already covered
    if va in existing_vas and not args.force:
        print(f"Already covered by: {existing_vas[va]}")
        print(f"Use --force to overwrite.")
        sys.exit(0)

    origin = args.origin or detect_origin(va, ghidra_name)
    filename = make_filename(va, ghidra_name, origin, args.name)
    filepath = args.output or os.path.join(SRC_DIR, filename)
    rel_path = os.path.relpath(filepath, PROJECT_ROOT)

    content = generate_skeleton(va, size, ghidra_name, origin, args.name)
    with open(filepath, "w") as f:
        f.write(content)

    # Compute test commands
    if args.name:
        symbol = "_" + args.name
    else:
        symbol = "_" + sanitize_name(ghidra_name)
    cflags = DEFAULT_CFLAGS.get(origin, "/O2 /Gd")

    print(f"Created: {rel_path}")
    print(f"  VA:     0x{va:08x}")
    print(f"  Size:   {size}B")
    print(f"  Origin: {origin}")
    print(f"  Symbol: {symbol}")
    print()
    print(f"Test command:")
    print(f"  {generate_test_command(rel_path, symbol, va, size, cflags)}")
    print()
    print(f"Diff command:")
    print(f"  {generate_diff_command(rel_path, symbol, va, size, cflags)}")
    print()
    print(f"Next steps:")
    print(f"  1. Get Ghidra decompilation for 0x{va:08x}")
    print(f"  2. Replace the TODO placeholder with actual C89 code")
    print(
        f"  3. Ensure C89 compliance: vars at block top, no // comments in body, no for(int ...)"
    )
    print(f"  4. Run the test command above to check match")
    print(f"  5. Update STATUS from STUB to EXACT/RELOC/MATCHING based on result")
    print(f"  6. If MATCHING, add BLOCKER annotation explaining the difference")


if __name__ == "__main__":
    app()
