"""skeleton.py - Generate .c skeleton file for an uncovered function.

Given a VA address, generates a properly annotated .c file skeleton with:
- reccmp-style marker line (FUNCTION/LIBRARY/STUB:  MODULE 0xVA)
- A placeholder function body
- The exact rebrew test command to verify it

All volatile metadata (STATUS, SIZE, CFLAGS, BLOCKER) is written to the
``rebrew-function.toml`` sidecar by this generator, not into the .c file.

Usage:
    rebrew skeleton 0x10003da0                    # Auto-detect origin
    rebrew skeleton 0x10003da0 --origin GAME      # Force origin
    rebrew skeleton 0x10003da0 --name my_func     # Custom name
    rebrew skeleton 0x10003da0 --output path.c    # Custom output path
    rebrew skeleton --list                        # List all uncovered functions
    rebrew skeleton --list --origin GAME          # List uncovered GAME functions
"""

import importlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rebrew.catalog.models import FunctionEntry

import httpx
import jinja2
import typer
from rich.console import Console

from rebrew.annotation import (
    marker_for_module,
    parse_c_file_multi,
)
from rebrew.catalog import load_function_structure
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    rel_display_path,
    require_config,
    target_marker,
)
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.decompiler import fetch_decompilation
from rebrew.naming import (
    load_existing_vas,
    make_filename,
    sanitize_name,
)
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

_SKELETON_TEMPLATE = jinja2.Template(
    """\
// {{ marker }}: {{ cfg_marker }} 0x{{ '%08x' % va }}

{% if origin_comment -%}
/* {{ origin_comment }} */
{% endif %}
{% if xref_context -%}
{{ xref_context }}
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

{% if xref_context -%}
{{ xref_context }}
{% endif %}
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
    cfg: ProjectConfig,
    va: int,
    size: int,
    ghidra_name: str,
    module: str = "",
    custom_name: str | None = None,
    xref_context: str | None = None,
    decomp_code: str | None = None,
    decomp_backend: str = "",
) -> str:
    """Generate the .c file content.

    Args:
        cfg: Project configuration containing settings and marker rules.
        va: Virtual address of the target function.
        size: Size of the function in bytes.
        ghidra_name: Name of the function imported from Ghidra.
        module: Module name used for the marker line.
        custom_name: Optional override name for the function.
        xref_context: Optional string containing fetched caller cross-references.
        decomp_code: Optional decompilation output to embed as a comment block.
        decomp_backend: Name of the decompiler backend (for the header comment).

    """
    lib_modules = cfg.library_modules or set()
    marker = marker_for_module(module, "MATCHED", lib_modules)
    cflags = cfg.base_cflags or "/O2 /Gd"

    # Determine symbol name
    symbol = "_" + custom_name if custom_name else "_" + sanitize_name(ghidra_name)
    func_name = symbol.lstrip("_")

    todo = "Implement based on Ghidra decompilation"
    origin_comment = ""

    return _SKELETON_TEMPLATE.render(
        marker=marker,
        cfg_marker=cfg.marker,
        va=va,
        origin_comment=origin_comment,
        size=size,
        cflags=cflags,
        symbol=symbol,
        func_name=func_name,
        ghidra_name=ghidra_name,
        xref_context=xref_context,
        decomp_code=decomp_code,
        decomp_backend=decomp_backend or "decompiler",
        todo=todo,
    )


def generate_annotation_block(
    cfg: ProjectConfig,
    va: int,
    size: int,
    ghidra_name: str,
    module: str = "",
    custom_name: str | None = None,
    xref_context: str | None = None,
    decomp_code: str | None = None,
    decomp_backend: str = "",
) -> str:
    """Generate an annotation block + stub body for appending to an existing file.

    Produces a compact block suitable for appending after existing code.
    """
    lib_modules = cfg.library_modules or set()
    marker = marker_for_module(module, "MATCHED", lib_modules)
    cflags = cfg.base_cflags or "/O2 /Gd"

    symbol = "_" + custom_name if custom_name else "_" + sanitize_name(ghidra_name)
    func_name = symbol.lstrip("_")

    return _ANNOTATION_BLOCK_TEMPLATE.render(
        marker=marker,
        cfg_marker=cfg.marker,
        va=va,
        size=size,
        cflags=cflags,
        symbol=symbol,
        func_name=func_name,
        ghidra_name=ghidra_name,
        xref_context=xref_context,
        decomp_code=decomp_code,
        decomp_backend=decomp_backend or "decompiler",
    )


def fetch_xref_context(
    endpoint: str,
    program_path: str,
    va: int,
    *,
    max_callers: int = 5,
) -> str | None:
    """Fetch cross-reference context from Ghidra via ReVa MCP.

    Calls find-cross-references to get callers, then get-decompilation
    on the top callers to provide calling context.

    Returns a formatted comment block string, or None if MCP is unavailable.
    """
    _sync_mod = importlib.import_module("rebrew.ghidra")
    _fetch_mcp_tool_raw = _sync_mod._fetch_mcp_tool_raw
    _init_mcp_session = _sync_mod._init_mcp_session

    try:
        with httpx.Client(timeout=30.0) as client:
            session_id = _init_mcp_session(client, endpoint)
            xrefs = _fetch_mcp_tool_raw(
                client,
                endpoint,
                "find-cross-references",
                {
                    "programPath": program_path,
                    "location": f"0x{va:08X}",
                    "direction": "to",
                    "includeFlow": True,
                    "includeData": True,
                    "includeContext": True,
                    "contextLines": 3,
                    "limit": max_callers * 2,
                },
                request_id=1,
                session_id=session_id,
            )

            if not isinstance(xrefs, dict):
                return None
            refs_raw = xrefs.get("referencesTo")
            if not isinstance(refs_raw, list) or not refs_raw:
                return None

            caller_rows: list[tuple[str, str, str]] = []
            seen_callers: set[tuple[str, str]] = set()
            data_rows: list[tuple[str, str, str]] = []
            for ref in refs_raw:
                if not isinstance(ref, dict):
                    continue
                from_address = ref.get("fromAddress")
                if not isinstance(from_address, str) or not from_address:
                    continue

                from_function = ref.get("fromFunction")
                from_symbol = ref.get("fromSymbol")
                function_name = "unknown"
                context = ""
                if isinstance(from_function, dict):
                    name_raw = from_function.get("name")
                    if isinstance(name_raw, str) and name_raw:
                        function_name = name_raw
                    context_raw = from_function.get("context")
                    if isinstance(context_raw, str):
                        context = context_raw.strip()
                if function_name == "unknown" and isinstance(from_symbol, dict):
                    name_raw = from_symbol.get("name")
                    if isinstance(name_raw, str) and name_raw:
                        function_name = name_raw

                if ref.get("isCall") is True:
                    key = (function_name, from_address)
                    if key in seen_callers:
                        continue
                    seen_callers.add(key)
                    caller_rows.append((function_name, from_address, context))
                    continue

                if ref.get("isData") is True:
                    ref_kind = ref.get("referenceType")
                    ref_type = ref_kind if isinstance(ref_kind, str) and ref_kind else "DATA"
                    data_rows.append((function_name, from_address, ref_type))

            if not caller_rows and not data_rows:
                return None

            callers = caller_rows[:max_callers]
            decomp_by_address: dict[str, str] = {}
            request_id = 2
            for _, caller_addr, _ in callers:
                decomp = _fetch_mcp_tool_raw(
                    client,
                    endpoint,
                    "get-decompilation",
                    {
                        "programPath": program_path,
                        "functionNameOrAddress": caller_addr,
                        "limit": 30,
                    },
                    request_id=request_id,
                    session_id=session_id,
                )
                request_id += 1

                decomp_text = ""
                if isinstance(decomp, str):
                    decomp_text = decomp.strip()
                elif isinstance(decomp, dict):
                    for d_key in ("decompilation", "text", "code"):
                        candidate = decomp.get(d_key)
                        if isinstance(candidate, str) and candidate.strip():
                            decomp_text = candidate.strip()
                            break
                if decomp_text:
                    decomp_by_address[caller_addr] = decomp_text

            lines: list[str] = [f"/* === Cross-references ({len(callers)} callers) ===", " *"]
            for idx, (caller_name, caller_addr, caller_context) in enumerate(callers, start=1):
                lines.append(f" * Caller {idx}: {caller_name} ({caller_addr})")
                if caller_context:
                    for ctx_line in caller_context.splitlines():
                        if ctx_line.strip():
                            lines.append(f" *   {ctx_line.strip()}")
                else:
                    lines.append(" *   (no call-site context)")
                lines.append(" *")

            if data_rows:
                lines.append(f" * Data references: {len(data_rows)}")
                for data_name, data_addr, data_type in data_rows:
                    lines.append(f" *   {data_name} ({data_addr}) [{data_type}]")
                lines.append(" *")

            for caller_name, caller_addr, _ in callers:
                ctext = decomp_by_address.get(caller_addr)
                if not ctext:
                    continue
                lines.append(f" * === Caller: {caller_name} ({caller_addr}) - decompilation ===")
                for dec_line in ctext.splitlines():
                    lines.append(f" * {dec_line}")
                lines.append(" *")

            lines.append(" * === End cross-references ===")
            lines.append(" */")
            return "\n".join(lines)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError):
        return None


def generate_test_command(filepath: str, symbol: str, va: int, size: int, cflags: str) -> str:
    """Generate the rebrew test command to verify this function."""
    return f'rebrew test {filepath} {symbol} --va 0x{va:08x} --size {size} --cflags "{cflags}"'


def generate_diff_command(
    cfg: ProjectConfig, filepath: str, symbol: str, va: int, size: int, cflags: str
) -> str:
    """Generate the rebrew match diff command."""
    return f'rebrew match {filepath} --diff-only --symbol "{symbol}" --cflags "{cflags}"'


def list_uncovered(
    ghidra_funcs: list["FunctionEntry"],
    existing_vas: dict[int, str],
    cfg: ProjectConfig,
    min_size: int = 10,
    max_size: int = 9999,
) -> list[tuple[int, int, str]]:
    """List uncovered functions. Returns [(va, size, ghidra_name)]."""
    uncovered: list[tuple[int, int, str]] = []
    ignored_syms = set(cfg.ignored_symbols or [])
    for func in ghidra_funcs:
        va = func.va
        size = func.size
        name = func.name if func.name else f"FUN_{va:08x}"

        if va in existing_vas:
            continue
        if size < min_size or size > max_size:
            continue
        if name in ignored_syms:
            continue

        uncovered.append((va, size, name))

    uncovered.sort(key=lambda x: x[1])  # Sort by size
    return uncovered


_EPILOG = """\
[bold]Examples:[/bold]

rebrew skeleton 0x10003da0                     Generate skeleton for one function

rebrew skeleton 0x10003da0 --name my_func      Custom function name

rebrew skeleton 0x10003da0 --origin MSVCRT      Set origin (default: auto-detect)

rebrew skeleton 0x10003da0 --append crt_env.c  Append to existing multi-function file

rebrew skeleton --batch 10                     Generate 10 skeletons at once

rebrew skeleton --batch 10 --origin GAME       Batch, filtered by origin

rebrew skeleton --list                         List uncovered functions

rebrew skeleton --list --origin ZLIB           List uncovered ZLIB functions

[bold]What it creates:[/bold]

A .c file with a single marker line (``// FUNCTION: MODULE 0xVA``) and a
placeholder function body.  All volatile metadata (STATUS, SIZE, CFLAGS,
BLOCKER) is written to the ``rebrew-function.toml`` sidecar alongside the
.c file, not into the file itself.

With --append, the annotation block is appended to an existing .c file,
enabling multi-function compilation units where related functions share a file.

[dim]Reads ghidra_functions.json and existing .c files to determine what's uncovered.
Uses rebrew-project.toml for compiler flags and origin presets.[/dim]"""

app = typer.Typer(
    help="Generate .c skeleton files for uncovered functions in the target binary.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    va_arg: str | None = typer.Argument(None, help="Function VA in hex (e.g. 0x10003da0)"),
    name: str | None = typer.Option(None, help="Custom function name"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    batch: int | None = typer.Option(None, help="Generate N skeletons (smallest first)"),
    min_size: int = typer.Option(10, help="Minimum function size"),
    max_size: int = typer.Option(9999, help="Maximum function size"),
    force: bool = typer.Option(False, help="Overwrite existing files"),
    append: str | None = typer.Option(
        None,
        "--append",
        help="Append function to an existing .c file (multi-function file)",
    ),
    decomp: bool = typer.Option(False, "--decomp", help="Embed decompilation in skeleton"),
    decomp_backend: str = typer.Option(
        "auto",
        "--decomp-backend",
        help="Decompiler backend: auto, r2ghidra, r2dec, ghidra",
    ),
    xrefs: bool = typer.Option(
        False,
        "--xrefs",
        help="Fetch cross-references from Ghidra and embed in skeleton",
    ),
    endpoint: str = typer.Option(
        "http://localhost:8080/mcp/message",
        help="ReVa MCP endpoint URL",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate .c skeleton files for uncovered target binary functions."""
    va_str = va_arg
    cfg = require_config(target=target, json_mode=json_output)
    src_dir = cfg.reversed_dir
    root = cfg.root

    ghidra_json = src_dir / FUNCTION_STRUCTURE_JSON
    ghidra_funcs = load_function_structure(ghidra_json)
    existing_vas = load_existing_vas(src_dir, cfg=cfg)

    # --batch mode
    if batch:
        uncovered = list_uncovered(ghidra_funcs, existing_vas, cfg, min_size, max_size)
        if not uncovered:
            console.print("No uncovered functions found matching criteria.")
            return

        count = min(batch, len(uncovered))
        created = []
        for va_val, size_val, name_val in uncovered[:count]:
            filename = make_filename(va_val, name_val, cfg=cfg)
            filepath = src_dir / filename
            rel_path = rel_display_path(filepath, root)

            if filepath.exists() and not force:
                console.print(f"[yellow]SKIP[/] {rel_path} (already exists)")
                continue

            d_code = None
            d_backend = ""
            xref_context_val = None
            if decomp:
                d_code, d_backend = fetch_decompilation(
                    decomp_backend,
                    cfg.target_binary,
                    va_val,
                    cfg.root,
                    endpoint=endpoint,
                )
            if xrefs:
                _sync_mod = importlib.import_module("rebrew.ghidra")
                _resolve = _sync_mod._resolve_program_path
                resolved_path = _resolve(cfg)
                xref_context_val = fetch_xref_context(
                    endpoint,
                    resolved_path,
                    va_val,
                )
                if xref_context_val:
                    console.print("  [dim]XREFs:[/] fetched caller context")
                else:
                    console.print("  [dim]XREFs:[/] unavailable (MCP unreachable or no callers)")
            content = generate_skeleton(
                cfg,
                va_val,
                size_val,
                name_val,
                xref_context=xref_context_val,
                decomp_code=d_code,
                decomp_backend=d_backend,
            )
            atomic_write_text(filepath, content, encoding="utf-8")

            symbol_val = "_" + sanitize_name(name_val)
            cflags_val = cfg.base_cflags or "/O2 /Gd"
            test_cmd = generate_test_command(rel_path, symbol_val, va_val, size_val, cflags_val)

            console.print(f"[bold green]CREATED[/] {rel_path} ({size_val}B)")
            console.print(f"  [dim]TEST:[/] {test_cmd}")
            created.append(
                {
                    "file": str(rel_path),
                    "va": f"0x{va_val:08x}",
                    "size": size_val,
                    "symbol": symbol_val,
                    "test_command": test_cmd,
                }
            )

        if json_output:
            json_print({"created": created, "count": len(created)})
        else:
            console.print(f"\n[bold]Created {len(created)} skeleton files.[/]")
        return

    # Single VA mode
    if not va_str:
        error_exit("VA required for single mode.", json_mode=json_output)

    va_int = parse_va(va_str, json_mode=json_output)

    # Find in Ghidra functions
    ghidra_entry = None
    for func in ghidra_funcs:
        if func.va == va_int:
            ghidra_entry = func
            break

    if not ghidra_entry:
        error_exit(f"VA 0x{va_int:08x} not found in ghidra_functions.json", json_mode=json_output)

    size = ghidra_entry.size

    ghidra_name = ghidra_entry.name if ghidra_entry.name else f"FUN_{va_int:08x}"

    # Check if already covered
    if va_int in existing_vas and not force and not append:
        console.print(f"Already covered by: {existing_vas[va_int]}")
        console.print("Use [cyan]--force[/] to overwrite.")
        raise typer.Exit(code=0)

    module_val = cfg.marker  # Use the project marker as module name

    # --append mode: add annotation block to an existing file
    if append:
        append_path = Path(append)
        if not append_path.is_absolute():
            append_path = src_dir / append_path
        if not append_path.exists():
            error_exit(f"--append target does not exist: {append_path}", json_mode=json_output)

        if not force:
            existing_in_file = parse_c_file_multi(
                append_path, target_name=target_marker(cfg), sidecar_dir=append_path.parent
            )
            for entry in existing_in_file:
                if entry.va == va_int:
                    console.print(
                        f"VA 0x{va_int:08x} already in {append_path.name}. "
                        f"Use [cyan]--force[/] to append anyway."
                    )
                    raise typer.Exit(code=0)

        decomp_code_val = None
        decomp_backend_name = ""
        xref_context_val = None
        if decomp:
            decomp_code_val, decomp_backend_name = fetch_decompilation(
                decomp_backend,
                cfg.target_binary,
                va_int,
                cfg.root,
                endpoint=endpoint,
            )
        if xrefs:
            _sync_mod = importlib.import_module("rebrew.ghidra")
            _resolve = _sync_mod._resolve_program_path
            resolved_path = _resolve(cfg)
            xref_context_val = fetch_xref_context(
                endpoint,
                resolved_path,
                va_int,
            )
            if xref_context_val:
                console.print("  [dim]XREFs:[/] fetched caller context")
            else:
                console.print("  [dim]XREFs:[/] unavailable (MCP unreachable or no callers)")

        block = generate_annotation_block(
            cfg,
            va_int,
            size,
            ghidra_name,
            module_val,
            name,
            xref_context=xref_context_val,
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
        atomic_write_text(append_path, existing_text + separator + block, encoding="utf-8")

        rel_path_val = rel_display_path(append_path, root)
        symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
        console.print(f"[bold green]APPENDED[/] to {rel_path_val}:")
        console.print(f"  VA:     [cyan]0x{va_int:08x}[/]")
        console.print(f"  Size:   {size}B")
        console.print(f"  Symbol: [magenta]{symbol_val}[/]")
        console.print()
        console.print("Test all functions in this file:")
        console.print(f"  [dim]rebrew test {rel_path_val}[/]")
        if json_output:
            json_print(
                {
                    "action": "appended",
                    "file": str(rel_path_val),
                    "va": f"0x{va_int:08x}",
                    "size": size,
                    "symbol": symbol_val,
                    "test_command": f"rebrew test {rel_path_val}",
                }
            )
        return

    filename_val = make_filename(va_int, ghidra_name, name, cfg=cfg)
    filepath_val = Path(output) if output else src_dir / filename_val
    rel_path_val = rel_display_path(filepath_val, root)

    decomp_code_val = None
    decomp_backend_name = ""
    xref_context_val = None
    if decomp:
        decomp_code_val, decomp_backend_name = fetch_decompilation(
            decomp_backend,
            cfg.target_binary,
            va_int,
            cfg.root,
            endpoint=endpoint,
        )
        if decomp_code_val:
            console.print(f"  [dim]Decompiler:[/] {decomp_backend_name}")
        else:
            console.print("  [dim]Decompiler:[/] no output (backend unavailable or failed)")
    if xrefs:
        _sync_mod = importlib.import_module("rebrew.ghidra")
        _resolve = _sync_mod._resolve_program_path
        resolved_path = _resolve(cfg)
        xref_context_val = fetch_xref_context(
            endpoint,
            resolved_path,
            va_int,
        )
        if xref_context_val:
            console.print("  [dim]XREFs:[/] fetched caller context")
        else:
            console.print("  [dim]XREFs:[/] unavailable (MCP unreachable or no callers)")

    content_val = generate_skeleton(
        cfg,
        va_int,
        size,
        ghidra_name,
        module_val,
        name,
        xref_context=xref_context_val,
        decomp_code=decomp_code_val,
        decomp_backend=decomp_backend_name,
    )
    atomic_write_text(filepath_val, content_val, encoding="utf-8")

    # Compute test commands
    symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
    cflags_val = cfg.base_cflags or "/O2 /Gd"

    test_cmd = generate_test_command(str(rel_path_val), symbol_val, va_int, size, cflags_val)
    diff_cmd = generate_diff_command(cfg, str(rel_path_val), symbol_val, va_int, size, cflags_val)

    if json_output:
        json_print(
            {
                "action": "created",
                "file": str(rel_path_val),
                "va": f"0x{va_int:08x}",
                "size": size,
                "symbol": symbol_val,
                "test_command": test_cmd,
                "diff_command": diff_cmd,
            }
        )
    else:
        console.print(f"[bold green]Created:[/] {rel_path_val}")
        console.print(f"  VA:     [cyan]0x{va_int:08x}[/]")
        console.print(f"  Size:   {size}B")
        console.print(f"  Symbol: [magenta]{symbol_val}[/]")
        console.print()
        console.print("[bold]Test command:[/]")
        console.print(f"  [dim]{test_cmd}[/]")
        console.print()
        console.print("[bold]Diff command:[/]")
        console.print(f"  [dim]{diff_cmd}[/]")
        console.print()
        console.print("[bold]Next steps:[/]")
        console.print(f"  1. Get Ghidra decompilation for [cyan]0x{va_int:08x}[/]")
        console.print("  2. Replace the TODO placeholder with actual C89 code")
        console.print(
            "  3. Ensure C89 compliance: vars at block top, no // comments in body, no for(int ...)"
        )
        console.print("  4. Run the test command above to check match")
        console.print("  5. Update STATUS from STUB to EXACT/RELOC/MATCHING based on result")
        console.print("  6. If MATCHING, add BLOCKER annotation explaining the difference")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
