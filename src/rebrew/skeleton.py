#!/usr/bin/env python3
"""skeleton.py - Generate .c skeleton file for an uncovered function.

Given a VA address, generates a properly annotated .c file skeleton with:
- reccmp-style annotations (FUNCTION/LIBRARY marker, STATUS, ORIGIN, SIZE, CFLAGS, SYMBOL)
- A placeholder function body
- The exact rebrew-test command to verify it

Usage:
    rebrew-skeleton 0x10003da0                    # Auto-detect origin
    rebrew-skeleton 0x10003da0 --origin GAME      # Force origin
    rebrew-skeleton 0x10003da0 --name my_func     # Custom name
    rebrew-skeleton 0x10003da0 --output path.c    # Custom output path
    rebrew-skeleton --list                        # List all uncovered functions
    rebrew-skeleton --list --origin GAME          # List uncovered GAME functions
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import parse_c_file
from rebrew.cli import TargetOption, get_config

# Address ranges and metadata are now loaded from cfg
MARKER_TYPE = {
    "GAME": "FUNCTION",
    "MSVCRT": "LIBRARY",
    "ZLIB": "LIBRARY",
}


def load_ghidra_functions(ghidra_json: str) -> list[dict]:
    """Load Ghidra function list."""
    if not os.path.exists(ghidra_json):
        print(
            f"ERROR: {ghidra_json} not found. Run: uv run python tools/validate.py --export-ghidra",
            file=sys.stderr,
        )
        sys.exit(1)
    with open(ghidra_json) as f:
        return json.load(f)


def load_existing_vas(src_dir: str) -> dict[int, str]:
    """Load VAs already covered by .c files. Returns {va: filename}."""
    existing = {}
    for cfile in Path(src_dir).glob("*.c"):
        entry = parse_c_file(cfile)
        if entry:
            existing[entry.va] = Path(entry.filepath).name
    return existing


def detect_origin(cfg: Any, va: int, ghidra_name: str) -> str:
    """Detect function origin based on VA and name."""
    zlib_vas = set(cfg.zlib_vas or [])
    if va in zlib_vas:
        return "ZLIB"
    if va >= (cfg.game_range_end or 0x1000b460):
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
    va: int, ghidra_name: str, origin: str, custom_name: str | None = None
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
    cfg: Any, va: int, size: int, ghidra_name: str, origin: str, custom_name: str | None = None
) -> str:
    """Generate the .c file content."""
    marker = MARKER_TYPE.get(origin, "FUNCTION")
    cflags = cfg.cflags_presets.get(origin, "/O2 /Gd")

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
    lines.append(f"// {marker}: {cfg.marker} 0x{va:08x}")
    lines.append("// STATUS: STUB")
    lines.append("// BLOCKER: initial decompilation - needs analysis")
    lines.append(f"// ORIGIN: {origin}")
    lines.append(f"// SIZE: {size}")
    lines.append(f"// CFLAGS: {cflags}")
    lines.append(f"// SYMBOL: {symbol}")
    lines.append("")

    if origin == "GAME":
        lines.append(
            "/* TODO: Add extern declarations for globals and called functions */"
        )
        lines.append("")
        lines.append(f"int __cdecl {func_name}(void)")
        lines.append("{")
        lines.append("    /* TODO: Implement based on Ghidra decompilation */")
        lines.append(f"    /* Ghidra name: {ghidra_name} */")
        lines.append("    return 0;")
        lines.append("}")
    elif origin == "MSVCRT":
        lines.append(
            "/* CRT function - check tools/MSVC600/VC98/CRT/SRC/ for original source */"
        )
        lines.append(
            "/* Also check: https://github.com/shihyu/learn_c/tree/master/vc_lib_src/src */"
        )
        lines.append("")
        lines.append(f"int __cdecl {func_name}(void)")
        lines.append("{")
        lines.append("    /* TODO: Implement from CRT source */")
        lines.append(f"    /* Ghidra name: {ghidra_name} */")
        lines.append("    return 0;")
        lines.append("}")
    elif origin == "ZLIB":
        lines.append(
            "/* zlib 1.1.3 function - check references/zlib-1.1.3/ for original source */"
        )
        lines.append("")
        lines.append(f"int __cdecl {func_name}(void)")
        lines.append("{")
        lines.append("    /* TODO: Implement from zlib 1.1.3 source */")
        lines.append(f"    /* Ghidra name: {ghidra_name} */")
        lines.append("    return 0;")
        lines.append("}")

    lines.append("")

    return "\n".join(lines)


def generate_test_command(
    filepath: str, symbol: str, va: int, size: int, cflags: str
) -> str:
    """Generate the rebrew-test command to verify this function."""
    return (
        f"rebrew-test {filepath} {symbol} "
        f'--va 0x{va:08x} --size {size} --cflags "{cflags}"'
    )


def generate_diff_command(
    cfg: Any, filepath: str, symbol: str, va: int, size: int, cflags: str
) -> str:
    """Generate the rebrew-match diff command."""
    return (
        f'rebrew-match {filepath} --diff-only --symbol "{symbol}" '
        f'--cflags "{cflags}"'
    )


def list_uncovered(
    ghidra_funcs: list[dict],
    existing_vas: dict[int, str],
    cfg: Any,
    origin_filter: str | None = None,
    min_size: int = 10,
    max_size: int = 9999,
) -> list[tuple[int, int, str, str]]:
    """List uncovered functions. Returns [(va, size, ghidra_name, origin)]."""
    uncovered = []
    ignored_symbols = set(cfg.ignored_symbols or [])
    for func in ghidra_funcs:
        va = func["va"]
        size = func["size"]
        name = func.get("ghidra_name", f"FUN_{va:08x}")

        if va in existing_vas:
            continue
        if size < min_size or size > max_size:
            continue
        if name in ignored_symbols:
            continue

        origin = detect_origin(cfg, va, name)
        if origin_filter and origin != origin_filter:
            continue

        uncovered.append((va, size, name, origin))

    uncovered.sort(key=lambda x: x[1])  # Sort by size
    return uncovered


app = typer.Typer(
    help="Generate .c skeleton files for uncovered functions in the target binary.",
)


@app.command()
def main(
    va_arg: str | None = typer.Argument(None, help="Function VA in hex (e.g. 0x10003da0)"),
    va: str | None = typer.Option(None, "--va", help="Function VA in hex"),
    name: str | None = typer.Option(None, help="Custom function name"),
    origin: str | None = typer.Option(None, help="Force origin type (GAME, MSVCRT, ZLIB)"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    list_mode: bool = typer.Option(False, "--list", help="List uncovered functions"),
    batch: int | None = typer.Option(None, help="Generate N skeletons (smallest first)"),
    min_size: int = typer.Option(10, help="Minimum function size"),
    max_size: int = typer.Option(9999, help="Maximum function size"),
    force: bool = typer.Option(False, help="Overwrite existing files"),
    target: str | None = TargetOption,
):
    """Generate .c skeleton files for uncovered target binary functions."""
    va_str = va or va_arg
    cfg = get_config(target=target)
    src_dir = cfg.reversed_dir
    root = cfg.root

    ghidra_json = src_dir / "ghidra_functions.json"
    ghidra_funcs = load_ghidra_functions(ghidra_json)
    existing_vas = load_existing_vas(src_dir)

    # --list mode
    if list_mode:
        uncovered = list_uncovered(
            ghidra_funcs, existing_vas, cfg, origin, min_size, max_size
        )
        if not uncovered:
            print("No uncovered functions found matching criteria.")
            return

        print(f"Uncovered functions: {len(uncovered)}")
        print(f"{'VA':>12s}  {'Size':>5s}  {'Origin':>6s}  {'Name'}")
        print(f"{'---':>12s}  {'---':>5s}  {'---':>6s}  {'---'}")
        for va_val, size_val, name_val, origin_val in uncovered:
            print(f"  0x{va_val:08x}  {size_val:4d}B  {origin_val:>6s}  {name_val}")

        # Summary
        by_origin = {}
        for _, _, _, origin_val in uncovered:
            by_origin[origin_val] = by_origin.get(origin_val, 0) + 1
        print(
            f"\nBy origin: {', '.join(f'{k}: {v}' for k, v in sorted(by_origin.items()))}"
        )
        return

    # --batch mode
    if batch:
        uncovered = list_uncovered(
            ghidra_funcs, existing_vas, cfg, origin, min_size, max_size
        )
        if not uncovered:
            print("No uncovered functions found matching criteria.")
            return

        count = min(batch, len(uncovered))
        created = []
        for va_val, size_val, name_val, origin_val in uncovered[:count]:
            filename = make_filename(va_val, name_val, origin_val)
            filepath = src_dir / filename
            rel_path = filepath.relative_to(root)

            if filepath.exists() and not force:
                print(f"SKIP: {rel_path} (already exists)")
                continue

            content = generate_skeleton(cfg, va_val, size_val, name_val, origin_val)
            filepath.write_text(content, encoding="utf-8")

            symbol_val = "_" + sanitize_name(name_val)
            cflags_val = cfg.cflags_presets.get(origin_val, "/O2 /Gd")
            test_cmd = generate_test_command(str(rel_path), symbol_val, va_val, size_val, cflags_val)

            print(f"CREATED: {rel_path} ({size_val}B, {origin_val})")
            print(f"  TEST: {test_cmd}")
            created.append(rel_path)

        print(f"\nCreated {len(created)} skeleton files.")
        return

    # Single VA mode
    if not va_str:
        print("Error: VA required for single mode.")
        sys.exit(1)

    va_int = int(va_str, 16)

    # Find in Ghidra functions
    ghidra_entry = None
    for func in ghidra_funcs:
        if func["va"] == va_int:
            ghidra_entry = func
            break

    if not ghidra_entry:
        print(
            f"ERROR: VA 0x{va_int:08x} not found in ghidra_functions.json", file=sys.stderr
        )
        sys.exit(1)

    size = ghidra_entry["size"]
    ghidra_name = ghidra_entry.get("ghidra_name", f"FUN_{va_int:08x}")

    # Check if already covered
    if va_int in existing_vas and not force:
        print(f"Already covered by: {existing_vas[va_int]}")
        print("Use --force to overwrite.")
        sys.exit(0)

    origin_val = origin or detect_origin(cfg, va_int, ghidra_name)
    filename_val = make_filename(va_int, ghidra_name, origin_val, name)
    filepath_val = Path(output) if output else src_dir / filename_val
    rel_path_val = filepath_val.relative_to(root)

    content_val = generate_skeleton(cfg, va_int, size, ghidra_name, origin_val, name)
    filepath_val.write_text(content_val, encoding="utf-8")

    # Compute test commands
    symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
    cflags_val = cfg.cflags_presets.get(origin_val, "/O2 /Gd")

    print(f"Created: {rel_path_val}")
    print(f"  VA:     0x{va_int:08x}")
    print(f"  Size:   {size}B")
    print(f"  Origin: {origin_val}")
    print(f"  Symbol: {symbol_val}")
    print()
    print("Test command:")
    print(f"  {generate_test_command(str(rel_path_val), symbol_val, va_int, size, cflags_val)}")
    print()
    print("Diff command:")
    print(f"  {generate_diff_command(cfg, str(rel_path_val), symbol_val, va_int, size, cflags_val)}")
    print()
    print("Next steps:")
    print(f"  1. Get Ghidra decompilation for 0x{va_int:08x}")
    print("  2. Replace the TODO placeholder with actual C89 code")
    print(
        "  3. Ensure C89 compliance: vars at block top, no // comments in body, no for(int ...)"
    )
    print("  4. Run the test command above to check match")
    print("  5. Update STATUS from STUB to EXACT/RELOC/MATCHING based on result")
    print("  6. If MATCHING, add BLOCKER annotation explaining the difference")


def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
