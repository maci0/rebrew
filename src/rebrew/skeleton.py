"""skeleton.py - Generate .c skeleton file for an uncovered function.

Given a VA address, generates a properly annotated .c file skeleton with:
- reccmp-style marker line (FUNCTION/LIBRARY/STUB:  MODULE 0xVA)
- A placeholder function body
- Prints the exact rebrew test command to verify it

All volatile metadata (STATUS, SIZE, CFLAGS, BLOCKER) is written to the
``rebrew-function.toml`` metadata by this generator, not into the .c file.

Usage:
    rebrew skeleton 0x10003da0                    # Generate skeleton
    rebrew skeleton 0x10003da0 --name my_func     # Custom name
    rebrew skeleton 0x10003da0 --output path.c    # Custom output path
    rebrew skeleton --batch 10                    # Generate 10 skeletons at once
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rebrew.catalog import FunctionEntry

import httpx
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


def _render_annotation_block(
    marker: str,
    cfg_marker: str,
    va: int,
    xref_context: str | None,
    decomp_code: str | None,
    decomp_backend: str,
    func_name: str,
    ghidra_name: str,
    todo_text: str | None = None,
    decomp_body: bool = False,
) -> str:
    lines = [f"// {marker}: {cfg_marker} 0x{va:08x}\n"]
    if xref_context:
        lines.append(f"{xref_context}\n")
    if decomp_code and decomp_body:
        # Use the decompiled C as the implementation — a real GA seed, not a
        # comment.  Rename its function to the marker's name so the GA can
        # find the symbol in the compiled object.
        from rebrew.c_parser import extract_function_name_and_proto

        body = decomp_code.strip()
        result = extract_function_name_and_proto(body)
        if result and result[0] != func_name:
            body = body.replace(result[0], func_name, 1)
        lines.append(f"{body}\n")
    elif decomp_code:
        lines.append(f"/* === Decompilation ({decomp_backend}) === */\n")
        lines.append(f"{decomp_code}\n")
        lines.append("/* === End decompilation === */\n")
    else:
        lines.append(f"int __cdecl {func_name}(void)\n")
        lines.append("{\n")
        if todo_text:
            lines.append(f"    /* TODO: {todo_text} */\n")
            lines.append(f"    /* Ghidra name: {ghidra_name} */\n")
        else:
            lines.append(f"    /* TODO: Implement — Ghidra name: {ghidra_name} */\n")
        lines.append("    return 0;\n")
        lines.append("}\n")
    return "".join(lines)


def generate_skeleton(
    cfg: ProjectConfig,
    va: int,
    ghidra_name: str,
    module: str = "",
    custom_name: str | None = None,
    xref_context: str | None = None,
    decomp_code: str | None = None,
    decomp_backend: str = "",
    decomp_body: bool = False,
) -> str:
    """Generate the .c file content.

    Args:
        cfg: Project configuration containing settings and marker rules.
        va: Virtual address of the target function.
        ghidra_name: Name of the function imported from Ghidra.
        module: Module name used for the marker line.
        custom_name: Optional override name for the function.
        xref_context: Optional string containing fetched caller cross-references.
        decomp_code: Optional decompilation output to embed as a comment block.
        decomp_backend: Name of the decompiler backend (for the header comment).

    """
    lib_modules = cfg.library_modules or set()
    marker = marker_for_module(module, "RELOC", lib_modules)

    # Determine symbol name
    symbol = "_" + custom_name if custom_name else "_" + sanitize_name(ghidra_name)
    func_name = symbol.lstrip("_")

    todo = "Implement based on Ghidra decompilation"

    return _render_annotation_block(
        marker=marker,
        cfg_marker=cfg.marker,
        va=va,
        func_name=func_name,
        ghidra_name=ghidra_name,
        xref_context=xref_context,
        decomp_code=decomp_code,
        decomp_backend=decomp_backend or "decompiler",
        todo_text=todo,
        decomp_body=decomp_body,
    )


def generate_annotation_block(
    cfg: ProjectConfig,
    va: int,
    ghidra_name: str,
    module: str = "",
    custom_name: str | None = None,
    xref_context: str | None = None,
    decomp_code: str | None = None,
    decomp_backend: str = "",
    decomp_body: bool = False,
) -> str:
    """Generate an annotation block + stub body for appending to an existing file.

    Produces a compact block suitable for appending after existing code.
    """
    lib_modules = cfg.library_modules or set()
    marker = marker_for_module(module, "RELOC", lib_modules)

    symbol = "_" + custom_name if custom_name else "_" + sanitize_name(ghidra_name)
    func_name = symbol.lstrip("_")

    return _render_annotation_block(
        marker=marker,
        cfg_marker=cfg.marker,
        va=va,
        func_name=func_name,
        ghidra_name=ghidra_name,
        xref_context=xref_context,
        decomp_code=decomp_code,
        decomp_backend=decomp_backend or "decompiler",
        decomp_body=decomp_body,
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
    _sync_mod = importlib.import_module("rebrew.ghidra.client")
    _fetch_mcp_tool_raw = _sync_mod.fetch_mcp_tool_raw
    _init_mcp_session = _sync_mod.init_mcp_session

    try:
        with httpx.Client(timeout=_sync_mod.MCP_REQUEST_TIMEOUT_S) as client:
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
                    lines.extend(
                        f" *   {ctx_line.strip()}"
                        for ctx_line in caller_context.splitlines()
                        if ctx_line.strip()
                    )
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
                lines.extend(f" * {dec_line}" for dec_line in ctext.splitlines())
                lines.append(" *")

            lines.append(" * === End cross-references ===")
            lines.append(" */")
            return "\n".join(lines)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError):
        return None


def generate_test_command(filepath: str, symbol: str, va: int, size: int, cflags: str) -> str:
    """Generate the rebrew test command to verify this function."""
    return f'rebrew test {filepath} --symbol {symbol} --va 0x{va:08x} --size {size} --cflags "{cflags}"'


def generate_diff_command(filepath: str, symbol: str, cflags: str) -> str:
    """Generate the rebrew diff command for byte-level comparison."""
    return f'rebrew diff {filepath} --symbol "{symbol}" --cflags "{cflags}"'


def list_uncovered(
    ghidra_funcs: list[FunctionEntry],
    existing_vas: dict[int, str],
    cfg: ProjectConfig,
    min_size: int = 10,
    max_size: int = 9999,
) -> list[tuple[int, int, str]]:
    """List uncovered functions. Returns [(va, size, name)]."""
    ignored_syms = set(cfg.ignored_symbols or [])
    # Ghidra cache first (preferred sizes), then function-list-only functions
    # (r2/radare2) — the cache often misses recently added / CRT functions,
    # and batch mode must still be able to skeletonize them.
    funcs_by_va: dict[int, tuple[int, str]] = {}
    for func in ghidra_funcs:
        name = func.name if func.name else f"FUN_{func.va:08x}"
        funcs_by_va[func.va] = (func.size, name)
    func_list_path = getattr(cfg, "function_list", "")
    # ProjectConfig.function_list defaults to Path() — truthy and resolves to
    # "." — so guard on is_file(); never parse an unset/missing list.
    if func_list_path and Path(func_list_path).is_file():
        try:
            from rebrew.catalog.loaders import parse_function_list
            from rebrew.catalog.registry import build_function_registry

            reg = build_function_registry(
                parse_function_list(Path(func_list_path)),
                cfg,
                None,
                getattr(cfg, "target_binary", None),
            )
            for va, entry in reg.items():
                if entry["canonical_size"] <= 0 or va in funcs_by_va:
                    continue  # ghidra size wins on conflict
                funcs_by_va[va] = (
                    entry["canonical_size"],
                    entry.get("list_name") or entry.get("ghidra_name") or f"FUN_{va:08x}",
                )
        except (OSError, ValueError, KeyError):
            pass  # no usable function list — ghidra-only batch

    uncovered: list[tuple[int, int, str]] = []
    for va, (size, name) in funcs_by_va.items():
        if va in existing_vas:
            continue
        if size < min_size or size > max_size:
            continue
        if name in ignored_syms:
            continue

        uncovered.append((va, size, name))

    uncovered.sort(key=lambda x: x[1])  # Sort by size
    return uncovered


_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew skeleton 0x10003da0 · · · · · · · · Generate skeleton for one function\n\n"
    "  rebrew skeleton 0x10003da0 --name my_func · Custom function name\n\n"
    "  rebrew skeleton 0x10003da0 --append crt_env.c  Append to existing multi-function file\n\n"
    "  rebrew skeleton --batch 10 · · · · · · · · Generate 10 skeletons at once\n\n"
    "[bold]What it creates:[/bold]\n\n"
    "  A .c file with a FUNCTION marker and placeholder body. All volatile metadata "
    "(STATUS, SIZE, CFLAGS, BLOCKER) is written to rebrew-function.toml, not into "
    "the file itself. With --append, the marker block is appended to an existing "
    ".c file for multi-function compilation units.\n\n"
    "[dim]See also: 'rebrew todo' for a prioritized action list with ROI scoring. "
    "Reads ghidra_functions.json and existing .c files to determine what's uncovered.[/dim]"
)

app = typer.Typer(
    help="Generate .c skeleton files for uncovered functions in the target binary.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def _fetch_extras(
    cfg: ProjectConfig,
    va: int,
    decomp: bool,
    decomp_backend: str,
    xrefs: bool,
    endpoint: str,
) -> tuple[str | None, str, str | None]:
    """Fetch optional decompilation and cross-reference context for a VA.

    Returns (decomp_code, decomp_backend_name, xref_context).
    """
    d_code: str | None = None
    d_backend = ""
    xref_context_val: str | None = None
    if decomp:
        d_code, d_backend = fetch_decompilation(
            decomp_backend,
            cfg.target_binary,
            va,
            cfg.root,
            endpoint=endpoint,
        )
    if xrefs:
        _sync_mod = importlib.import_module("rebrew.ghidra.commands")
        _resolve = _sync_mod.resolve_program_path
        resolved_path = _resolve(cfg)
        xref_context_val = fetch_xref_context(
            endpoint,
            resolved_path,
            va,
        )
        if xref_context_val:
            console.print("  [dim]XREFs:[/] fetched caller context")
        else:
            console.print("  [dim]XREFs:[/] unavailable (MCP unreachable or no callers)")
    return d_code, d_backend, xref_context_val


def _run_batch_mode(
    cfg: ProjectConfig,
    ghidra_funcs: list[FunctionEntry],
    existing_vas: dict[int, str],
    batch: int,
    min_size: int,
    max_size: int,
    force: bool,
    decomp: bool,
    decomp_backend: str,
    xrefs: bool,
    endpoint: str,
    json_output: bool,
    dry_run: bool = False,
    decomp_body: bool = False,
) -> None:
    """Generate skeleton files in batch for the smallest uncovered functions."""
    root = cfg.root
    src_dir = cfg.reversed_dir
    uncovered = list_uncovered(ghidra_funcs, existing_vas, cfg, min_size, max_size)
    if not uncovered:
        if json_output:
            json_print(
                {
                    "action": "none",
                    "created": [],
                    "count": 0,
                    "dry_run": dry_run,
                    "message": "No uncovered functions found matching criteria.",
                }
            )
        else:
            console.print("No uncovered functions found matching criteria.")
        return

    count = min(batch, len(uncovered))
    created: list[dict[str, str | int]] = []
    for va_val, size_val, name_val in uncovered[:count]:
        filename = make_filename(va_val, name_val, cfg=cfg)
        filepath = src_dir / filename
        rel_path = rel_display_path(filepath, root)

        if filepath.exists() and not force:
            console.print(f"[yellow]SKIP[/] {rel_path} (already exists)")
            continue

        d_code, d_backend, xref_context_val = _fetch_extras(
            cfg,
            va_val,
            decomp,
            decomp_backend,
            xrefs,
            endpoint,
        )
        content = generate_skeleton(
            cfg,
            va_val,
            name_val,
            xref_context=xref_context_val,
            decomp_code=d_code,
            decomp_backend=d_backend,
            decomp_body=decomp_body,
        )
        if dry_run:
            console.print(f"[dim]Would create[/dim] {rel_path} ({size_val}B)")
        else:
            atomic_write_text(filepath, content, encoding="utf-8")
            _write_skeleton_metadata(cfg, va_val, size_val, cfg.marker)

        symbol_val = "_" + sanitize_name(name_val)
        # User-facing cflags only — base_cflags (/nologo /c /MT) are prepended by compile_to_obj.
        cflags_val = (getattr(cfg, "cflags", "") or "").strip() or "/O2 /Gd"
        test_cmd = generate_test_command(rel_path, symbol_val, va_val, size_val, cflags_val)

        if not dry_run:
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
        key = "would_create" if dry_run else "created"
        json_print(
            {
                "action": key,
                key: created,
                "count": len(created),
                "dry_run": dry_run,
            }
        )
    else:
        label = "Dry run:" if dry_run else "Created"
        console.print(f"\n[bold]{label} {len(created)} skeleton files.[/]")


def _write_skeleton_metadata(cfg: ProjectConfig, va_int: int, size: int, module_val: str) -> None:
    """Record SIZE for a freshly created skeleton when metadata lacks it.

    Without SIZE the function shows MISSING_SIZE and cannot be verified
    (rebrew test / verify need it to extract target bytes).  Only fills
    the gap — never overwrites an existing SIZE or touches STATUS.
    """
    from rebrew.metadata import get_entry, update_field

    existing = get_entry(cfg.metadata_dir, va_int, module_val)
    if "size" not in existing:
        update_field(cfg.metadata_dir, va_int, "size", size, module=module_val)


def _run_append_mode(
    cfg: ProjectConfig,
    va_int: int,
    size: int,
    ghidra_name: str,
    module_val: str,
    append: str,
    name: str | None,
    force: bool,
    decomp: bool,
    decomp_backend: str,
    xrefs: bool,
    endpoint: str,
    json_output: bool,
    dry_run: bool = False,
    decomp_body: bool = False,
) -> None:
    """Append a function annotation block to an existing .c file."""
    root = cfg.root
    src_dir = cfg.reversed_dir
    append_path = Path(append)
    if not append_path.is_absolute():
        append_path = src_dir / append_path
    if not append_path.exists():
        error_exit(f"--append target does not exist: {append_path}", json_mode=json_output)

    if not force:
        existing_in_file = parse_c_file_multi(
            append_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
        )
        for entry in existing_in_file:
            if entry.va == va_int:
                console.print(
                    f"VA 0x{va_int:08x} already in {append_path.name}. "
                    f"Use [cyan]--force[/] to append anyway."
                )
                raise typer.Exit(code=0)

    decomp_code_val, decomp_backend_name, xref_context_val = _fetch_extras(
        cfg,
        va_int,
        decomp,
        decomp_backend,
        xrefs,
        endpoint,
    )

    block = generate_annotation_block(
        cfg,
        va_int,
        ghidra_name,
        module_val,
        name,
        xref_context=xref_context_val,
        decomp_code=decomp_code_val,
        decomp_backend=decomp_backend_name,
        decomp_body=decomp_body,
    )

    # Ensure there's a blank line separator before the new block
    existing_text = append_path.read_text(encoding="utf-8")
    separator = (
        "" if existing_text.endswith("\n\n") else "\n" if existing_text.endswith("\n") else "\n\n"
    )
    if dry_run:
        console.print(f"[dim]Would append[/dim] to {rel_display_path(append_path, root)}")
    else:
        atomic_write_text(append_path, existing_text + separator + block, encoding="utf-8")
        _write_skeleton_metadata(cfg, va_int, size, module_val)

    rel_path_val = rel_display_path(append_path, root)
    symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
    if not dry_run:
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
                "action": "would_append" if dry_run else "appended",
                "dry_run": dry_run,
                "file": str(rel_path_val),
                "va": f"0x{va_int:08x}",
                "size": size,
                "symbol": symbol_val,
                "test_command": f"rebrew test {rel_path_val}",
            }
        )


def _run_single_va_mode(
    cfg: ProjectConfig,
    va_int: int,
    size: int,
    ghidra_name: str,
    module_val: str,
    name: str | None,
    output: str | None,
    decomp: bool,
    decomp_backend: str,
    xrefs: bool,
    endpoint: str,
    json_output: bool,
    dry_run: bool = False,
    decomp_body: bool = False,
) -> None:
    """Create a new single-function .c skeleton file."""
    root = cfg.root
    src_dir = cfg.reversed_dir
    filename_val = make_filename(va_int, ghidra_name, name, cfg=cfg)
    filepath_val = Path(output) if output else src_dir / filename_val
    rel_path_val = rel_display_path(filepath_val, root)

    decomp_code_val, decomp_backend_name, xref_context_val = _fetch_extras(
        cfg,
        va_int,
        decomp,
        decomp_backend,
        xrefs,
        endpoint,
    )
    if decomp and decomp_code_val:
        console.print(f"  [dim]Decompiler:[/] {decomp_backend_name}")
    elif decomp:
        console.print("  [dim]Decompiler:[/] no output (backend unavailable or failed)")

    content_val = generate_skeleton(
        cfg,
        va_int,
        ghidra_name,
        module_val,
        name,
        xref_context=xref_context_val,
        decomp_code=decomp_code_val,
        decomp_backend=decomp_backend_name,
        decomp_body=decomp_body,
    )
    if dry_run:
        console.print(f"[dim]Would create[/dim] {rel_path_val}")
    else:
        atomic_write_text(filepath_val, content_val, encoding="utf-8")
        _write_skeleton_metadata(cfg, va_int, size, module_val)

    # Compute test commands
    symbol_val = "_" + name if name else "_" + sanitize_name(ghidra_name)
    # User-facing cflags only — base_cflags (/nologo /c /MT) are prepended by compile_to_obj.
    cflags_val = (getattr(cfg, "cflags", "") or "").strip() or "/O2 /Gd"

    test_cmd = generate_test_command(str(rel_path_val), symbol_val, va_int, size, cflags_val)
    diff_cmd = generate_diff_command(str(rel_path_val), symbol_val, cflags_val)

    if json_output:
        json_print(
            {
                "action": "would_create" if dry_run else "created",
                "dry_run": dry_run,
                "file": str(rel_path_val),
                "va": f"0x{va_int:08x}",
                "size": size,
                "symbol": symbol_val,
                "test_command": test_cmd,
                "diff_command": diff_cmd,
            }
        )
    else:
        if not dry_run:
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
        console.print("  5. Run 'rebrew test' which auto-promotes STATUS based on result")
        console.print("  6. If NEAR_MATCHING, add BLOCKER metadata explaining the difference")


@app.callback(invoke_without_command=True)
def main(
    va: str | None = typer.Argument(None, help="Function VA in hex (e.g. 0x10003da0)"),
    name: str | None = typer.Option(None, "--name", help="Custom function name"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    batch: int | None = typer.Option(None, "--batch", help="Generate N skeletons (smallest first)"),
    min_size: int = typer.Option(10, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(9999, "--max-size", help="Maximum function size"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing files"),
    append: str | None = typer.Option(
        None,
        "--append",
        help="Append function to an existing .c file (multi-function file)",
    ),
    decomp: bool = typer.Option(False, "--decomp", help="Embed decompilation in skeleton"),
    decomp_body: bool = typer.Option(
        False,
        "--decomp-body",
        help="With --decomp: write the decompiled C as the function BODY (a real "
        "GA seed) instead of a comment block",
    ),
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
        "--endpoint",
        help="ReVa MCP endpoint URL",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate .c skeleton files for uncovered target binary functions."""
    va_str = va
    cfg = require_config(target=target, json_mode=json_output)
    src_dir = cfg.reversed_dir

    ghidra_json = src_dir / FUNCTION_STRUCTURE_JSON
    try:
        ghidra_funcs = load_function_structure(ghidra_json)
    except ValueError as exc:
        # Corrupt cache — exit with a clear error rather than a raw traceback.
        # (An empty/missing cache is handled by load_function_structure and
        # falls through to the function-list path below.)
        error_exit(f"Corrupt {FUNCTION_STRUCTURE_JSON}: {exc}", json_mode=json_output)
    existing_vas = load_existing_vas(src_dir, cfg=cfg)

    # --batch mode
    if batch:
        _run_batch_mode(
            cfg,
            ghidra_funcs,
            existing_vas,
            batch,
            min_size,
            max_size,
            force,
            decomp,
            decomp_backend,
            xrefs,
            endpoint,
            json_output,
            dry_run=dry_run,
        )
        return

    # Single VA or append — both require a VA argument
    if not va_str:
        error_exit("VA required for single mode.", json_mode=json_output)

    va_int = parse_va(va_str, json_mode=json_output)

    # Find in Ghidra functions
    ghidra_entry = None
    for func in ghidra_funcs:
        if func.va == va_int:
            ghidra_entry = func
            break

    size: int
    ghidra_name: str
    if ghidra_entry is not None:
        size = ghidra_entry.size
        ghidra_name = ghidra_entry.name if ghidra_entry.name else f"FUN_{va_int:08x}"
    else:
        # Fall back to the function list (r2/radare2) — many real functions
        # (e.g. recently added CRT ones) exist only there, not in the Ghidra
        # cache.  Use the registry's canonical size when available.
        from rebrew.catalog.loaders import parse_function_list
        from rebrew.catalog.registry import build_function_registry

        func_list_path = getattr(cfg, "function_list", "")
        try:
            list_funcs = (
                parse_function_list(Path(func_list_path))
                if func_list_path and Path(func_list_path).is_file()
                else []
            )
            reg_entry = build_function_registry(
                list_funcs,
                cfg,
                None,
                getattr(cfg, "target_binary", None),
            ).get(va_int)
        except (OSError, ValueError, KeyError):
            reg_entry = None  # no usable function list — fall through to not-found
        if reg_entry and reg_entry["canonical_size"] > 0:
            size = reg_entry["canonical_size"]
            ghidra_name = (
                reg_entry.get("list_name") or reg_entry.get("ghidra_name") or f"FUN_{va_int:08x}"
            )
        else:
            error_exit(
                f"VA 0x{va_int:08x} not found in {FUNCTION_STRUCTURE_JSON} or the function list",
                json_mode=json_output,
            )

    # Check if already covered
    if va_int in existing_vas and not force and not append:
        covered_by = existing_vas[va_int]
        if json_output:
            json_print(
                {
                    "action": "none",
                    "va": f"0x{va_int:08x}",
                    "covered_by": covered_by,
                    "message": "Already covered by an existing source file; use --force to overwrite.",
                }
            )
        else:
            console.print(f"Already covered by: {covered_by}")
            console.print("Use [cyan]--force[/] to overwrite.")
        raise typer.Exit(code=0)

    module_val = cfg.marker  # Use the project marker as module name

    # --append mode: add marker block to an existing file
    if append:
        _run_append_mode(
            cfg,
            va_int,
            size,
            ghidra_name,
            module_val,
            append,
            name,
            force,
            decomp,
            decomp_backend,
            xrefs,
            endpoint,
            json_output,
            dry_run=dry_run,
        )
        return

    # Default: single VA mode — create a new skeleton file
    _run_single_va_mode(
        cfg,
        va_int,
        size,
        ghidra_name,
        module_val,
        name,
        output,
        decomp,
        decomp_backend,
        xrefs,
        endpoint,
        json_output,
        dry_run=dry_run,
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
