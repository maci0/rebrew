"""depgraph.py - Function dependency graph visualization.

Builds a call graph from extern function declarations in reversed .c files,
then outputs it as Mermaid or DOT for visualization. Highlights reversed vs.
unreversed nodes and their match status.

Usage:
    rebrew graph                          # Mermaid output to stdout
    rebrew graph --format dot             # DOT output
    rebrew graph --focus FuncName         # Show only neighbours of FuncName
    rebrew graph --output graph.md        # Write to file
    rebrew graph --include-dispatch       # Fold dispatch-table edges into the graph
"""

import re
from pathlib import Path
from typing import Any, TypedDict

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi
from rebrew.cli import (
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    require_config,
    target_marker,
)
from rebrew.config import ProjectConfig

console = Console(stderr=True)

# Pre-compiled regex for graph node ID sanitization.
_NODE_ID_RE = re.compile(r"[^a-zA-Z0-9_]")

# Standard library / compiler intrinsics filtered out of the call graph to
# reduce visual noise — they show up in nearly every reversed function and
# rarely teach you anything about the program's own structure.
_NOISE_CALLEES: frozenset[str] = frozenset(
    {
        "memset",
        "memmove",
        "memcpy",
        "memcmp",
        "strlen",
        "strcmp",
        "strncmp",
        "strcpy",
        "strncpy",
        "strcat",
        "strchr",
        "strrchr",
        "strstr",
        "strpbrk",
        "strcspn",
        "sprintf",
        "printf",
        "fprintf",
        "sscanf",
        "malloc",
        "calloc",
        "realloc",
        "free",
        "rand",
        "srand",
        "abs",
        "atoi",
        "atof",
        "__ftol",
        "__CxxFrameHandler",
    }
)


class NodeInfo(TypedDict):
    """Type-safe node info for dependency graph nodes."""

    status: str
    va: int
    file: str


def _sanitize_id(name: str) -> str:
    """Sanitize a function name for use as a graph node ID."""
    base = _NODE_ID_RE.sub("_", name).strip("_")
    if not base:
        base = "node"
    checksum = f"{sum((i + 1) * ord(ch) for i, ch in enumerate(name)) & 0xFFFFFFFF:08x}"
    return f"n_{base}_{checksum}"


def _extract_callees(c_path: Path, text: str | None = None) -> list[str]:
    """Extract function names from extern declarations in a .c file.

    Callees in :data:`_NOISE_CALLEES` (libc / compiler intrinsics) are
    dropped to keep the graph readable.  When *text* is provided, the
    file is not re-read from disk.
    """
    if text is None:
        try:
            text = c_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

    from rebrew.c_parser import find_extern_function_names

    return [name for name in find_extern_function_names(text) if name not in _NOISE_CALLEES]


def build_graph(
    reversed_dir: Path,
    cfg: ProjectConfig | None = None,
    dispatch_tables: list[Any] | None = None,
) -> tuple[dict[str, NodeInfo], list[tuple[str, str]], list[tuple[str, str]]]:
    """Build a call graph from reversed source files.

    Args:
        reversed_dir: Directory containing reversed .c source files.
        cfg: Optional project configuration.
        dispatch_tables: Optional list of ``DispatchTable`` objects (from
            ``rebrew.data.find_dispatch_tables``).  When provided, a virtual
            ``dispatch_0x<VA>`` node is created per table and connected to each
            entry function target via dispatch edges.

    Returns:
        nodes: {func_name: {"status": str, "va": int, "file": str}}
        edges: [(caller_name, callee_name)]  — direct extern-call edges
        dispatch_edges: [(dispatch_node_name, callee_name)]  — indirect dispatch edges

    """
    nodes: dict[str, NodeInfo] = {}
    edges: list[tuple[str, str]] = []
    name_lookup: dict[str, str] = {}  # symbol -> display name
    # Store (cfile, display_name, cached_text) for edge extraction
    file_callers: list[tuple[Path, str, str]] = []

    # Single pass: collect all reversed functions and cache file text.
    # Uses parse_c_file_multi to capture every annotation in multi-function files.
    from rebrew.cli import rel_display_path

    # Cache file text so _extract_callees doesn't re-read from disk
    _file_text_cache: dict[Path, str] = {}

    for cfile in iter_sources(reversed_dir, cfg):
        rel_name = rel_display_path(cfile, reversed_dir)
        # Read file once and cache for both annotation parsing and callee extraction
        if cfile not in _file_text_cache:
            try:
                _file_text_cache[cfile] = cfile.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        for entry in parse_c_file_multi(
            cfile, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir if cfg else None
        ):
            if entry.marker_type in ("GLOBAL", "DATA"):
                continue

            # Use symbol without leading underscore as display name
            display = entry.symbol.lstrip("_") if entry.symbol else cfile.stem
            nodes[display] = {
                "status": entry.status,
                "va": entry.va,
                "file": rel_name,
            }
            # Map both the raw symbol and display name
            if entry.symbol:
                name_lookup[entry.symbol.lstrip("_")] = display
                name_lookup[entry.symbol] = display
            file_callers.append((cfile, display, _file_text_cache.get(cfile, "")))

    # Extract extern callees and build edges (reuses cached file text)
    for cfile, caller, cached_text in file_callers:
        callees = _extract_callees(cfile, text=cached_text)
        for callee in callees:
            callee_display = name_lookup.get(callee, callee)
            # Add unknown callee as an unreversed node
            if callee_display not in nodes:
                nodes[callee_display] = {
                    "status": "UNKNOWN",
                    "va": 0,
                    "file": "",
                }
            if caller != callee_display:  # no self-edges
                edges.append((caller, callee_display))

    # Build VA -> display-name reverse lookup for dispatch resolution
    va_lookup: dict[int, str] = {info["va"]: name for name, info in nodes.items() if info["va"]}

    dispatch_edges: list[tuple[str, str]] = []
    if dispatch_tables:
        for tbl in dispatch_tables:
            dispatch_node = f"dispatch_0x{tbl.va:08x}"
            # Register the virtual dispatch node
            nodes[dispatch_node] = {
                "status": "DISPATCH",
                "va": tbl.va,
                "file": "",
            }
            for entry in tbl.entries:
                # Resolve target VA to a known function name if possible
                target_name = va_lookup.get(entry.target_va)
                if target_name is None:
                    # Fall back to entry's resolved name or a VA-based placeholder
                    if entry.name:
                        target_name = entry.name.lstrip("_")
                    else:
                        target_name = f"fn_0x{entry.target_va:08x}"
                # Ensure target node exists
                if target_name not in nodes:
                    nodes[target_name] = {
                        "status": entry.status or "UNKNOWN",
                        "va": entry.target_va,
                        "file": "",
                    }
                dispatch_edges.append((dispatch_node, target_name))

    return nodes, edges, dispatch_edges


def _focus_graph(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
    focus: str,
    depth: int = 1,
    dispatch_edges: list[tuple[str, str]] | None = None,
) -> tuple[dict[str, NodeInfo], list[tuple[str, str]], list[tuple[str, str]]]:
    """Filter graph to only show neighbours of the focus node.

    Returns:
        filtered_nodes, filtered_edges, filtered_dispatch_edges
    """
    dispatch_edges = dispatch_edges or []
    all_edges = edges + dispatch_edges

    # Find focus node (case-insensitive partial match)
    focus_lower = focus.lower()
    focus_name = None
    # Prefer exact match, then fall back to partial match
    for name in nodes:
        if name.lower() == focus_lower:
            focus_name = name
            break
    if not focus_name:
        for name in nodes:
            if focus_lower in name.lower():
                focus_name = name
                break
    if not focus_name:
        return {}, [], []

    # Build undirected adjacency once so BFS is O(visited * avg_degree)
    # instead of O(depth * |edges|) — matters for large graphs / depth > 1.
    adj: dict[str, set[str]] = {}
    for a, b in all_edges:
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)

    # BFS to find neighbours within depth
    visited = {focus_name}
    frontier = {focus_name}
    for _ in range(depth):
        next_frontier: set[str] = set()
        for node in frontier:
            for neighbour in adj.get(node, ()):
                if neighbour not in visited:
                    next_frontier.add(neighbour)
                    visited.add(neighbour)
        frontier = next_frontier

    filtered_nodes = {k: v for k, v in nodes.items() if k in visited}
    filtered_edges = [(a, b) for a, b in edges if a in visited and b in visited]
    filtered_dispatch = [(a, b) for a, b in dispatch_edges if a in visited and b in visited]
    return filtered_nodes, filtered_edges, filtered_dispatch


def _status_style(status: str) -> str:
    """Return a mermaid node style class for the given status."""
    return {
        "EXACT": "exact",
        "RELOC": "reloc",
        "PROVEN": "exact",
        "NEAR_MATCHING": "matching",
        "STUB": "stub",
        "UNKNOWN": "unknown",
        "DISPATCH": "dispatch",
    }.get(status, "unknown")


def render_mermaid(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
    dispatch_edges: list[tuple[str, str]] | None = None,
) -> str:
    """Render graph as Mermaid flowchart markup.

    Direct call edges are rendered as solid arrows (``-->``).
    Dispatch-table edges (when *dispatch_edges* is provided) are rendered as
    dashed arrows (``..>``), matching Mermaid's linkStyle for indirect calls.
    """
    lines = ["graph LR"]

    # Style definitions
    lines.append("    classDef exact fill:#2ecc71,stroke:#27ae60,color:#fff")
    lines.append("    classDef reloc fill:#3498db,stroke:#2980b9,color:#fff")
    lines.append("    classDef matching fill:#f39c12,stroke:#e67e22,color:#fff")
    lines.append("    classDef stub fill:#e74c3c,stroke:#c0392b,color:#fff")
    lines.append("    classDef unknown fill:#95a5a6,stroke:#7f8c8d,color:#fff")
    lines.append("    classDef dispatch fill:#9b59b6,stroke:#8e44ad,color:#fff")
    lines.append("")

    # Deduplicate edges
    seen_edges: set[tuple[str, str]] = set()

    # Nodes
    for name, info in sorted(nodes.items()):
        nid = _sanitize_id(name)
        status = info["status"]
        label = name
        if status not in ("UNKNOWN", ""):
            label = f"{name} [{status}]"
        style = _status_style(status)
        lines.append(f'    {nid}["{label}"]:::{style}')

    lines.append("")

    # Direct call edges (solid)
    for caller, callee in edges:
        key = (_sanitize_id(caller), _sanitize_id(callee))
        if key not in seen_edges:
            seen_edges.add(key)
            lines.append(f"    {key[0]} --> {key[1]}")

    # Dispatch edges (dashed)
    for caller, callee in dispatch_edges or []:
        key = (_sanitize_id(caller), _sanitize_id(callee))
        if key not in seen_edges:
            seen_edges.add(key)
            lines.append(f"    {key[0]} ..> {key[1]}")

    return "\n".join(lines)


def render_dot(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
    dispatch_edges: list[tuple[str, str]] | None = None,
) -> str:
    """Render graph as Graphviz DOT format.

    Direct call edges are rendered as solid arrows.
    Dispatch-table edges (when *dispatch_edges* is provided) are rendered with
    ``style=dashed`` to visually distinguish indirect calls through dispatch tables.
    """
    lines = ["digraph G {", "    rankdir=LR;", "    node [shape=box, style=filled];", ""]

    color_map = {
        "EXACT": "#2ecc71",
        "RELOC": "#3498db",
        "PROVEN": "#2ecc71",
        "NEAR_MATCHING": "#f39c12",
        "STUB": "#e74c3c",
        "UNKNOWN": "#95a5a6",
        "DISPATCH": "#9b59b6",
    }

    for name, info in sorted(nodes.items()):
        nid = _sanitize_id(name)
        status = info["status"]
        color = color_map.get(status, "#95a5a6")
        font_color = "black" if status == "NEAR_MATCHING" else "white"
        label = f"{name}\\n[{status}]" if status not in ("UNKNOWN", "DISPATCH") else name
        lines.append(f'    {nid} [label="{label}", fillcolor="{color}", fontcolor="{font_color}"];')

    lines.append("")

    seen: set[tuple[str, str]] = set()
    for caller, callee in edges:
        key = (_sanitize_id(caller), _sanitize_id(callee))
        if key not in seen:
            seen.add(key)
            lines.append(f"    {key[0]} -> {key[1]};")

    # Dispatch edges — dashed to distinguish indirect calls
    for caller, callee in dispatch_edges or []:
        key = (_sanitize_id(caller), _sanitize_id(callee))
        if key not in seen:
            seen.add(key)
            lines.append(f"    {key[0]} -> {key[1]} [style=dashed];")

    lines.append("}")
    return "\n".join(lines)


def render_summary(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
    dispatch_edges: list[tuple[str, str]] | None = None,
) -> str:
    """Render a text summary of the graph statistics."""
    by_status: dict[str, int] = {}
    for info in nodes.values():
        s = info["status"]
        by_status[s] = by_status.get(s, 0) + 1

    total_reversed = sum(v for k, v in by_status.items() if k not in ("UNKNOWN", "DISPATCH"))
    total_unknown = by_status.get("UNKNOWN", 0)
    total_dispatch = by_status.get("DISPATCH", 0)

    lines = [
        f"Nodes: {len(nodes)} ({total_reversed} reversed, {total_unknown} unreversed"
        + (f", {total_dispatch} dispatch" if total_dispatch else "")
        + ")",
        f"Edges: {len(edges)}"
        + (f" direct, {len(dispatch_edges or [])} dispatch" if dispatch_edges else ""),
        "By status:",
    ]
    for status in ("EXACT", "RELOC", "PROVEN", "NEAR_MATCHING", "STUB", "UNKNOWN", "DISPATCH"):
        count = by_status.get(status, 0)
        if count:
            lines.append(f"  {status}: {count}")

    # Find leaf functions (no outgoing calls) that are reversed
    all_edges = edges + (dispatch_edges or [])
    callers = {e[0] for e in all_edges}
    callees = {e[1] for e in all_edges}
    leaves = [
        n
        for n in nodes
        if n not in callers and n in callees and nodes[n]["status"] not in ("UNKNOWN", "DISPATCH")
    ]
    if leaves:
        lines.append(f"\nLeaf functions (reversed, no outgoing calls): {len(leaves)}")
        lines.extend(f"  - {name} [{nodes[name]['status']}]" for name in sorted(leaves)[:10])
        if len(leaves) > 10:
            lines.append(f"  ... and {len(leaves) - 10} more")

    # Find blocking unreversed (called by many)
    callee_counts: dict[str, int] = {}
    for _, callee in all_edges:
        callee_info = nodes.get(callee)
        if callee_info and callee_info["status"] == "UNKNOWN":
            callee_counts[callee] = callee_counts.get(callee, 0) + 1
    if callee_counts:
        top_blockers = sorted(callee_counts.items(), key=lambda x: -x[1])[:10]
        lines.append("\nTop unreversed blockers (called by most):")
        for name, count in top_blockers:
            lines.append(f"  - {name}: called by {count} functions")

    return "\n".join(lines)


_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew graph · · · · · · · · · · · · · · Mermaid diagram of all functions\n\n"
    "  rebrew graph --format dot · · · · · · · · Graphviz DOT format\n\n"
    "  rebrew graph --format summary · · · · · · Text summary only\n\n"
    "  rebrew graph --focus _my_func --depth 2 · · Neighbourhood around one function\n\n"
    "  rebrew graph -o graph.md · · · · · · · · · Write output to file\n\n"
    "  rebrew graph --cu-map · · · · · · · · · · Compilation unit boundary map\n\n"
    "  rebrew graph --include-dispatch · · · · · Fold dispatch-table edges into the graph\n\n"
    "  rebrew graph --include-dispatch --min-table-len 5 · Require ≥5 entries per table\n\n"
    "[bold]Output formats:[/bold]\n\n"
    "  mermaid · · Mermaid flowchart (default; paste into docs)\n\n"
    "  dot · · · · Graphviz DOT (pipe to 'dot -Tpng')\n\n"
    "  summary · · Text breakdown by component\n\n"
    "[bold]Dispatch edges:[/bold]\n\n"
    "  --include-dispatch adds a virtual dispatch_0x<VA> node per detected dispatch\n"
    "  table and connects it to every function-pointer target. Edges are rendered as\n"
    "  dashed lines (Mermaid: '..>', DOT: style=dashed) to distinguish indirect calls.\n"
    "  --min-table-len and --max-pointer-stride mirror the matching options in\n"
    "  'rebrew data --dispatch' and control which tables are included.\n\n"
    "[dim]Scans reversed .c files for call targets to build the dependency graph. "
    "Uses annotations to determine function origins and status.[/dim]"
)

app = typer.Typer(
    help="Generate function dependency graph from reversed .c files.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    fmt: str = typer.Option(
        "mermaid", "--format", "-f", help="Output format: mermaid, dot, summary"
    ),
    focus: str | None = typer.Option(
        None, "--focus", help="Focus on a specific function and its neighbours"
    ),
    depth: int = typer.Option(1, "--depth", help="Neighbourhood depth for --focus"),
    cu_map: bool = typer.Option(False, "--cu-map", help="Show compilation unit boundary map"),
    include_dispatch: bool = typer.Option(
        False,
        "--include-dispatch",
        help=(
            "Augment the call graph with dispatch-table edges detected in the binary. "
            "Adds a virtual dispatch_0x<VA> node per table connected to all its "
            "function-pointer targets. Edges appear as dashed lines in mermaid/dot."
        ),
    ),
    min_table_len: int = typer.Option(
        3,
        "--min-table-len",
        help="Minimum entries to qualify as a dispatch table (--include-dispatch)",
    ),
    max_pointer_stride: int = typer.Option(
        4,
        "--max-pointer-stride",
        help="Maximum byte stride between pointer slots when scanning tables (--include-dispatch)",
    ),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file (default: stdout)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate function dependency graph from reversed .c files."""
    cfg = require_config(target=target, json_mode=json_output)

    if cu_map:
        from rebrew.cu_map import main as _cu_map_main

        _cu_map_main(json_output=json_output, target=target)
        return

    reversed_dir = cfg.reversed_dir

    # Optionally load dispatch tables from the binary
    dispatch_tables = None
    if include_dispatch:
        bin_path = cfg.target_binary
        if not bin_path or not bin_path.exists():
            error_exit(
                "--include-dispatch requires a target binary (target_binary not set or missing).",
                json_mode=json_output,
            )
        try:
            from rebrew.annotation import parse_c_file_multi
            from rebrew.binary_loader import load_binary
            from rebrew.cli import iter_sources, rel_display_path, target_marker
            from rebrew.data import find_dispatch_tables

            info = load_binary(bin_path)
            sec_dict = {
                name: {
                    "va": si.va,
                    "size": si.size,
                    "file_offset": si.file_offset,
                    "raw_size": si.raw_size,
                }
                for name, si in info.sections.items()
            }

            # Build known functions map from reversed source files
            known_functions: dict[int, dict[str, str]] = {}
            for cfile in iter_sources(reversed_dir, cfg):
                for entry in parse_c_file_multi(
                    cfile,
                    target_name=target_marker(cfg),
                    metadata_dir=cfg.metadata_dir,
                ):
                    if entry.va:
                        known_functions[entry.va] = {
                            "name": entry.name or rel_display_path(cfile, reversed_dir),
                            "status": entry.status,
                        }

            dispatch_tables = find_dispatch_tables(
                info.data,
                info.image_base,
                sec_dict,
                known_functions,
                min_entries=min_table_len,
                max_stride=max_pointer_stride,
            )
        except (ImportError, OSError, ValueError) as exc:
            error_exit(f"Failed to load dispatch tables: {exc}", json_mode=json_output)

    nodes, edges, dispatch_edges = build_graph(
        reversed_dir, cfg=cfg, dispatch_tables=dispatch_tables
    )

    if not nodes:
        error_exit("No functions found.", json_mode=json_output)

    if focus:
        nodes, edges, dispatch_edges = _focus_graph(nodes, edges, focus, depth, dispatch_edges)
        if not nodes:
            error_exit(f"No function matching '{focus}' found.", json_mode=json_output)

    if json_output:
        by_status: dict[str, int] = {}
        for node in nodes.values():
            s = node["status"]
            by_status[s] = by_status.get(s, 0) + 1
        json_print(
            {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "total_dispatch_edges": len(dispatch_edges),
                "by_status": by_status,
                "nodes": {
                    name: {
                        "status": info["status"],
                        "va": f"0x{info['va']:08x}" if info["va"] else "0x0",
                        "file": info["file"],
                    }
                    for name, info in sorted(nodes.items())
                },
                "edges": [{"caller": a, "callee": b} for a, b in edges],
                "dispatch_edges": [{"dispatch": a, "target": b} for a, b in dispatch_edges],
            }
        )
        return

    if fmt == "mermaid":
        result = render_mermaid(nodes, edges, dispatch_edges)
    elif fmt == "dot":
        result = render_dot(nodes, edges, dispatch_edges)
    elif fmt == "summary":
        result = render_summary(nodes, edges, dispatch_edges)
    else:
        error_exit(f"Unknown format: {fmt}. Use mermaid, dot, or summary.", json_mode=json_output)

    if output:
        Path(output).write_text(result + "\n", encoding="utf-8")
        console.print(f"Written to {output}")
    else:
        print(result)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
