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
import sys
from pathlib import Path
from typing import Any

import jinja2
import typer

from rebrew.annotation import (
    marker_for_origin,
)
from rebrew.catalog import load_ghidra_functions
from rebrew.cli import TargetOption, get_config
from rebrew.decompiler import fetch_decompilation
from rebrew.naming import (
    detect_origin,
    load_existing_vas,
    make_filename,
    sanitize_name,
)

# Default skeleton TODO text per origin (used when cfg.origin_todos is empty)
_DEFAULT_ORIGIN_TODOS: dict[str, str] = {
    "GAME": "Implement based on Ghidra decompilation",
    "MSVCRT": "Implement from CRT source",
    "ZLIB": "Implement from zlib 1.1.3 source",
}

# Default skeleton preamble comments per origin (used when cfg.origin_comments is empty)
_DEFAULT_ORIGIN_COMMENTS: dict[str, str] = {
    "GAME": "TODO: Add extern declarations for globals and called functions",
    "MSVCRT": (
        "CRT function - check tools/MSVC600/VC98/CRT/SRC/ for original source\n"
        "Also check: https://github.com/shihyu/learn_c/tree/master/vc_lib_src/src"
    ),
    "ZLIB": "zlib 1.1.3 function - check references/zlib-1.1.3/ for original source",
}

_SKELETON_TEMPLATE = jinja2.Template(
    """\
// {{ marker }}: {{ cfg_marker }} 0x{{ '%08x' % va }}
// STATUS: STUB
// BLOCKER: initial decompilation - needs analysis
// ORIGIN: {{ origin }}
// SIZE: {{ size }}
// CFLAGS: {{ cflags }}
// SYMBOL: {{ symbol }}

{% if origin_comment -%}
/* {{ origin_comment }} */
{% endif %}
{% if decomp_code -%}
/* === Decompilation ({{ decomp_backend }}) === */
{{ decomp_code }}
/* === End decompilation === */
{% else -%}
int __cdecl {{ func_name }}(void)
{
    /* TODO: {{ todo }} */
    /* Ghidra name: {{ ghidra_name }} */
    return 0;
}
{% endif %}
""",
    keep_trailing_newline=True,
)

_ANNOTATION_BLOCK_TEMPLATE = jinja2.Template(
    """\
// {{ marker }}: {{ cfg_marker }} 0x{{ '%08x' % va }}
// STATUS: STUB
// BLOCKER: initial decompilation - needs analysis
// ORIGIN: {{ origin }}
// SIZE: {{ size }}
// CFLAGS: {{ cflags }}
// SYMBOL: {{ symbol }}

{% if decomp_code -%}
/* === Decompilation ({{ decomp_backend }}) === */
{{ decomp_code }}
/* === End decompilation === */
{% else -%}
int __cdecl {{ func_name }}(void)
{
    /* TODO: Implement — Ghidra name: {{ ghidra_name }} */
    return 0;
}
{% endif %}
""",
    keep_trailing_newline=True,
)


def generate_skeleton(
    cfg: Any,
    va: int,
    size: int,
    ghidra_name: str,
    origin: str,
    custom_name: str | None = None,
    decomp_code: str | None = None,
    decomp_backend: str = "",
) -> str:
    """Generate the .c file content.

    Args:
        decomp_code: Optional decompilation output to embed as a comment block.
        decomp_backend: Name of the decompiler backend (for the header comment).
    """
    # Derive marker from origin (FUNCTION vs LIBRARY). We pass "MATCHED" as status
    # so that marker_for_origin picks FUNCTION/LIBRARY rather than STUB — the template
    # writes STATUS: STUB on its own annotation line.
    lib_origins = getattr(cfg, "library_origins", None) or None
    marker = marker_for_origin(origin, "MATCHED", lib_origins)
    cflags = getattr(cfg, "cflags_presets", {}).get(origin, "/O2 /Gd")

    # Determine symbol name
    symbol = "_" + custom_name if custom_name else "_" + sanitize_name(ghidra_name)
    func_name = symbol.lstrip("_")

    cfg_todos = getattr(cfg, "origin_todos", None) or {}
    if cfg_todos:
        todo = cfg_todos.get(origin, "Implement function")
    else:
        todo = _DEFAULT_ORIGIN_TODOS.get(origin, "Implement function")

    cfg_comments = getattr(cfg, "origin_comments", None) or {}
    if cfg_comments:
        origin_comment = cfg_comments.get(origin, "")
    else:
        origin_comment = _DEFAULT_ORIGIN_COMMENTS.get(origin, "")

    return _SKELETON_TEMPLATE.render(
        marker=marker,
        cfg_marker=cfg.marker,
        va=va,
        origin=origin,
        size=size,
        cflags=cflags,
        symbol=symbol,
        func_name=func_name,
        ghidra_name=ghidra_name,
        decomp_code=decomp_code,
        decomp_backend=decomp_backend or "decompiler",
        todo=todo,
        origin_comment=origin_comment,
    )


def generate_annotation_block(
    cfg: Any,
    va: int,
    size: int,
    ghidra_name: str,
    origin: str,
    custom_name: str | None = None,
    decomp_code: str | None = None,
    decomp_backend: str = "",
) -> str:
    """Generate an annotation block + stub body for appending to an existing file.

    Unlike generate_skeleton(), this omits origin-specific preamble comments
    and produces a compact block suitable for appending after existing code.
    """
    lib_origins = getattr(cfg, "library_origins", None) or None
    marker = marker_for_origin(origin, "MATCHED", lib_origins)
    cflags = getattr(cfg, "cflags_presets", {}).get(origin, "/O2 /Gd")

    symbol = "_" + custom_name if custom_name else "_" + sanitize_name(ghidra_name)
    func_name = symbol.lstrip("_")

    return _ANNOTATION_BLOCK_TEMPLATE.render(
        marker=marker,
        cfg_marker=cfg.marker,
        va=va,
        origin=origin,
        size=size,
        cflags=cflags,
        symbol=symbol,
        func_name=func_name,
        ghidra_name=ghidra_name,
        decomp_code=decomp_code,
        decomp_backend=decomp_backend or "decompiler",
    )


def generate_test_command(filepath: str, symbol: str, va: int, size: int, cflags: str) -> str:
    """Generate the rebrew-test command to verify this function."""
    return f'rebrew-test {filepath} {symbol} --va 0x{va:08x} --size {size} --cflags "{cflags}"'


def generate_diff_command(
    cfg: Any, filepath: str, symbol: str, va: int, size: int, cflags: str
) -> str:
    """Generate the rebrew-match diff command."""
    return f'rebrew-match {filepath} --diff-only --symbol "{symbol}" --cflags "{cflags}"'


def list_uncovered(
    ghidra_funcs: list[dict[str, Any]],
    existing_vas: dict[int, str],
    cfg: Any,
    origin_filter: str | None = None,
    min_size: int = 10,
    max_size: int = 9999,
) -> list[tuple[int, int, str, str]]:
    """List uncovered functions. Returns [(va, size, ghidra_name, origin)]."""
    uncovered: list[tuple[int, int, str, str]] = []
    ignored_symbols = set(getattr(cfg, "ignored_symbols", None) or [])
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

        origin = detect_origin(va, name, cfg)
        if origin_filter and origin != origin_filter:
            continue

        uncovered.append((va, size, name, origin))

    uncovered.sort(key=lambda x: x[1])  # Sort by size
    return uncovered


_EPILOG = """\
[bold]Examples:[/bold]
  rebrew-skeleton 0x10003da0                     Generate skeleton for one function
  rebrew-skeleton 0x10003da0 --name my_func      Custom function name
  rebrew-skeleton 0x10003da0 --origin MSVCRT      Set origin (default: auto-detect)
  rebrew-skeleton 0x10003da0 --append crt_env.c  Append to existing multi-function file
  rebrew-skeleton --batch 10                     Generate 10 skeletons at once
  rebrew-skeleton --batch 10 --origin GAME       Batch, filtered by origin
  rebrew-skeleton --list                         List uncovered functions
  rebrew-skeleton --list --origin ZLIB           List uncovered ZLIB functions

[bold]What it creates:[/bold]
  A .c file with reccmp-style annotations (FUNCTION, STATUS, ORIGIN, SIZE,
  CFLAGS, SYMBOL) and a placeholder function body. The file is placed in the
  configured reversed_dir with the function name as filename.

  With --append, the annotation block is appended to an existing .c file,
  enabling multi-function compilation units where related functions share a file.

[dim]Reads ghidra_functions.json and existing .c files to determine what's uncovered.
Uses rebrew.toml for compiler flags and origin presets.[/dim]"""

app = typer.Typer(
    help="Generate .c skeleton files for uncovered functions in the target binary.",
    rich_markup_mode="rich",
)


@app.command(epilog=_EPILOG)
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
    append: str | None = typer.Option(
        None,
        "--append",
        help="Append function to an existing .c file (multi-function file)",
    ),
    decomp: bool = typer.Option(
        False, "--decomp", "--decompile", help="Embed decompilation in skeleton"
    ),
    decomp_backend: str = typer.Option(
        "auto",
        "--decomp-backend",
        help="Decompiler backend: auto, r2ghidra, r2dec, ghidra",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate .c skeleton files for uncovered target binary functions."""
    va_str = va or va_arg
    cfg = get_config(target=target)
    src_dir = cfg.reversed_dir
    root = cfg.root

    ghidra_json = src_dir / "ghidra_functions.json"
    ghidra_funcs = load_ghidra_functions(ghidra_json)
    existing_vas = load_existing_vas(src_dir, cfg=cfg)

    # --list mode
    if list_mode:
        uncovered = list_uncovered(ghidra_funcs, existing_vas, cfg, origin, min_size, max_size)
        if not uncovered:
            print("No uncovered functions found matching criteria.")
            return

        print(f"Uncovered functions: {len(uncovered)}")
        print(f"{'VA':>12s}  {'Size':>5s}  {'Origin':>6s}  {'Name'}")
        print(f"{'---':>12s}  {'---':>5s}  {'---':>6s}  {'---'}")
        for va_val, size_val, name_val, origin_val in uncovered:
            print(f"  0x{va_val:08x}  {size_val:4d}B  {origin_val:>6s}  {name_val}")

        # Summary
        by_origin: dict[str, int] = {}
        for _, _, _, origin_val in uncovered:
            by_origin[origin_val] = by_origin.get(origin_val, 0) + 1
        print(f"\nBy origin: {', '.join(f'{k}: {v}' for k, v in sorted(by_origin.items()))}")
        return

    # --batch mode
    if batch:
        uncovered = list_uncovered(ghidra_funcs, existing_vas, cfg, origin, min_size, max_size)
        if not uncovered:
            print("No uncovered functions found matching criteria.")
            return

        count = min(batch, len(uncovered))
        created = []
        for va_val, size_val, name_val, origin_val in uncovered[:count]:
            filename = make_filename(va_val, name_val, origin_val, cfg=cfg)
            filepath = src_dir / filename
            rel_path = filepath.relative_to(root)

            if filepath.exists() and not force:
                print(f"SKIP: {rel_path} (already exists)", file=sys.stderr)
                continue

            d_code = None
            d_backend = ""
            if decomp:
                d_code, d_backend = fetch_decompilation(
                    decomp_backend, cfg.target_binary, va_val, cfg.root
                )
            content = generate_skeleton(
                cfg,
                va_val,
                size_val,
                name_val,
                origin_val,
                decomp_code=d_code,
                decomp_backend=d_backend,
            )
            filepath.write_text(content, encoding="utf-8")

            symbol_val = "_" + sanitize_name(name_val)
            cflags_val = getattr(cfg, "cflags_presets", {}).get(origin_val, "/O2 /Gd")
            test_cmd = generate_test_command(
                str(rel_path), symbol_val, va_val, size_val, cflags_val
            )

            print(f"CREATED: {rel_path} ({size_val}B, {origin_val})", file=sys.stderr)
            print(f"  TEST: {test_cmd}", file=sys.stderr)
            created.append(
                {
                    "file": str(rel_path),
                    "va": f"0x{va_val:08x}",
                    "size": size_val,
                    "origin": origin_val,
                    "symbol": symbol_val,
                    "test_command": test_cmd,
                }
            )

        if json_output:
            print(json.dumps({"created": created, "count": len(created)}, indent=2))
        else:
            print(f"\nCreated {len(created)} skeleton files.", file=sys.stderr)
        return

    # Single VA mode
    if not va_str:
        print("Error: VA required for single mode.", file=sys.stderr)
        raise typer.Exit(code=1)

    try:
        va_int = int(va_str, 16)
    except ValueError:
        print(f"Error: Invalid hex VA: {va_str}", file=sys.stderr)
        raise typer.Exit(code=1)

    # Find in Ghidra functions
    ghidra_entry = None
    for func in ghidra_funcs:
        if func["va"] == va_int:
            ghidra_entry = func
            break

    if not ghidra_entry:
        print(f"ERROR: VA 0x{va_int:08x} not found in ghidra_functions.json", file=sys.stderr)
        raise typer.Exit(code=1)

    size = ghidra_entry["size"]
    ghidra_name = ghidra_entry.get("ghidra_name", f"FUN_{va_int:08x}")

    # Check if already covered
    if va_int in existing_vas and not force and not append:
        print(f"Already covered by: {existing_vas[va_int]}")
        print("Use --force to overwrite.")
        raise typer.Exit(code=0)

    origin_val = origin or detect_origin(va_int, ghidra_name, cfg)

    # --append mode: add annotation block to an existing file
    if append:
        append_path = Path(append)
        if not append_path.is_absolute():
            append_path = src_dir / append_path
        if not append_path.exists():
            print(f"ERROR: --append target does not exist: {append_path}", file=sys.stderr)
            raise typer.Exit(code=1)

        decomp_code_val = None
        decomp_backend_name = ""
        if decomp:
            decomp_code_val, decomp_backend_name = fetch_decompilation(
                decomp_backend, cfg.target_binary, va_int, cfg.root
            )

        block = generate_annotation_block(
            cfg,
            va_int,
            size,
            ghidra_name,
            origin_val,
            name,
            decomp_code=decomp_code_val,
            decomp_backend=decomp_backend_name,
        )

        # Ensure there's a blank line separator before the new block
        existing_text = append_path.read_text(encoding="utf-8")
        separator = (
            ""
            if existing_text.endswith("\n\n")
            else "\n"
            if existing_text.endswith("\n")
            else "\n\n"
        )
        append_path.write_text(existing_text + separator + block, encoding="utf-8")

        rel_path_val = append_path.relative_to(root)
        symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
        print(f"APPENDED to {rel_path_val}:", file=sys.stderr)
        print(f"  VA:     0x{va_int:08x}", file=sys.stderr)
        print(f"  Size:   {size}B", file=sys.stderr)
        print(f"  Symbol: {symbol_val}", file=sys.stderr)
        print(file=sys.stderr)
        print("Test all functions in this file:", file=sys.stderr)
        print(f"  rebrew-test {rel_path_val}", file=sys.stderr)
        if json_output:
            print(
                json.dumps(
                    {
                        "action": "appended",
                        "file": str(rel_path_val),
                        "va": f"0x{va_int:08x}",
                        "size": size,
                        "origin": origin_val,
                        "symbol": symbol_val,
                        "test_command": f"rebrew-test {rel_path_val}",
                    },
                    indent=2,
                )
            )
        return

    filename_val = make_filename(va_int, ghidra_name, origin_val, name, cfg=cfg)
    filepath_val = Path(output) if output else src_dir / filename_val
    rel_path_val = filepath_val.relative_to(root)

    decomp_code_val = None
    decomp_backend_name = ""
    if decomp:
        decomp_code_val, decomp_backend_name = fetch_decompilation(
            decomp_backend, cfg.target_binary, va_int, cfg.root
        )
        if decomp_code_val:
            print(f"  Decompiler: {decomp_backend_name}", file=sys.stderr)
        else:
            print("  Decompiler: no output (backend unavailable or failed)", file=sys.stderr)

    content_val = generate_skeleton(
        cfg,
        va_int,
        size,
        ghidra_name,
        origin_val,
        name,
        decomp_code=decomp_code_val,
        decomp_backend=decomp_backend_name,
    )
    filepath_val.write_text(content_val, encoding="utf-8")

    # Compute test commands
    symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
    cflags_val = getattr(cfg, "cflags_presets", {}).get(origin_val, "/O2 /Gd")

    test_cmd = generate_test_command(str(rel_path_val), symbol_val, va_int, size, cflags_val)
    diff_cmd = generate_diff_command(cfg, str(rel_path_val), symbol_val, va_int, size, cflags_val)

    if json_output:
        print(
            json.dumps(
                {
                    "action": "created",
                    "file": str(rel_path_val),
                    "va": f"0x{va_int:08x}",
                    "size": size,
                    "origin": origin_val,
                    "symbol": symbol_val,
                    "test_command": test_cmd,
                    "diff_command": diff_cmd,
                },
                indent=2,
            )
        )
    else:
        print(f"Created: {rel_path_val}", file=sys.stderr)
        print(f"  VA:     0x{va_int:08x}", file=sys.stderr)
        print(f"  Size:   {size}B", file=sys.stderr)
        print(f"  Origin: {origin_val}", file=sys.stderr)
        print(f"  Symbol: {symbol_val}", file=sys.stderr)
        print(file=sys.stderr)
        print("Test command:", file=sys.stderr)
        print(f"  {test_cmd}", file=sys.stderr)
        print(file=sys.stderr)
        print("Diff command:", file=sys.stderr)
        print(f"  {diff_cmd}", file=sys.stderr)
        print(file=sys.stderr)
        print("Next steps:", file=sys.stderr)
        print(f"  1. Get Ghidra decompilation for 0x{va_int:08x}", file=sys.stderr)
        print("  2. Replace the TODO placeholder with actual C89 code", file=sys.stderr)
        print(
            "  3. Ensure C89 compliance: vars at block top, no // comments in body, no for(int ...)",
            file=sys.stderr,
        )
        print("  4. Run the test command above to check match", file=sys.stderr)
        print(
            "  5. Update STATUS from STUB to EXACT/RELOC/MATCHING based on result", file=sys.stderr
        )
        print("  6. If MATCHING, add BLOCKER annotation explaining the difference", file=sys.stderr)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
