"""depgraph.py - Function dependency graph visualization.

Builds a call graph from extern function declarations in reversed .c files,
then outputs it as Mermaid or DOT for visualization. Highlights reversed vs.
unreversed nodes and their match status.

Usage:
    rebrew graph                          # Mermaid output to stdout
    rebrew graph --format dot             # DOT output
    rebrew graph --origin GAME            # Filter to GAME functions
    rebrew graph --focus FuncName         # Show only neighbours of FuncName
    rebrew graph --output graph.md        # Write to file
"""

import re
import sys
from pathlib import Path
from typing import TypedDict

import typer

from rebrew.annotation import parse_c_file_multi
from rebrew.cli import TargetOption, get_config, iter_sources
from rebrew.config import ProjectConfig


class NodeInfo(TypedDict):
    """Type-safe node info for dependency graph nodes."""

    status: str
    origin: str
    va: int
    file: str


def _sanitize_id(name: str) -> str:
    """Sanitize a function name for use as a graph node ID."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", name)


# Pattern matching "extern <type> [<cc>] FuncName(...)"
# Captures the function name before the opening parenthesis.
_EXTERN_FUNC_RE = re.compile(
    r"^extern\s+"  # extern keyword
    r"[^(]+?"  # return type (non-greedy, anything except open paren)
    r"\b(\w+)"  # function name (last word before paren)
    r"\s*\(",  # opening paren
    re.MULTILINE,
)


def _extract_callees(c_path: Path) -> list[str]:
    """Extract function names from extern declarations in a .c file."""
    try:
        text = c_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    callees = []
    for m in _EXTERN_FUNC_RE.finditer(text):
        name = m.group(1)
        # Skip common noise: standard library, compiler intrinsics
        if name in (
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
        ):
            continue
        callees.append(name)
    return callees


def build_graph(
    reversed_dir: Path,
    origin_filter: str | None = None,
    cfg: ProjectConfig | None = None,
) -> tuple[dict[str, NodeInfo], list[tuple[str, str]]]:
    """Build a call graph from reversed source files.

    Returns:
        nodes: {func_name: {"status": str, "origin": str, "va": int, "file": str}}
        edges: [(caller_name, callee_name)]
    """
    nodes: dict[str, NodeInfo] = {}
    edges: list[tuple[str, str]] = []
    name_lookup: dict[str, str] = {}  # symbol -> display name
    # Store (cfile, display_name) for second-pass edge extraction
    file_callers: list[tuple[Path, str]] = []

    # Single pass: collect all reversed functions and prepare edge extraction.
    # Uses parse_c_file_multi to capture every annotation in multi-function files.
    from rebrew.cli import rel_display_path

    for cfile in iter_sources(reversed_dir, cfg):
        rel_name = rel_display_path(cfile, reversed_dir)
        for entry in parse_c_file_multi(cfile):
            if entry.marker_type in ("GLOBAL", "DATA"):
                continue
            if origin_filter and entry.origin != origin_filter:
                continue

            # Use symbol without leading underscore as display name
            display = entry.symbol.lstrip("_") if entry.symbol else cfile.stem
            nodes[display] = {
                "status": entry.status,
                "origin": entry.origin,
                "va": entry.va,
                "file": rel_name,
            }
            # Map both the raw symbol and display name
            if entry.symbol:
                name_lookup[entry.symbol.lstrip("_")] = display
                name_lookup[entry.symbol] = display
            file_callers.append((cfile, display))

    # Extract extern callees and build edges (uses cached file list)
    for cfile, caller in file_callers:
        callees = _extract_callees(cfile)
        for callee in callees:
            callee_display = name_lookup.get(callee, callee)
            # Add unknown callee as an unreversed node
            if callee_display not in nodes:
                nodes[callee_display] = {
                    "status": "UNKNOWN",
                    "origin": "",
                    "va": 0,
                    "file": "",
                }
            if caller != callee_display:  # no self-edges
                edges.append((caller, callee_display))

    return nodes, edges


def _focus_graph(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
    focus: str,
    depth: int = 1,
) -> tuple[dict[str, NodeInfo], list[tuple[str, str]]]:
    """Filter graph to only show neighbours of the focus node."""
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
        return {}, []

    # BFS to find neighbours within depth
    visited = {focus_name}
    frontier = {focus_name}
    for _ in range(depth):
        next_frontier: set[str] = set()
        for edge in edges:
            if edge[0] in frontier and edge[1] not in visited:
                next_frontier.add(edge[1])
                visited.add(edge[1])
            if edge[1] in frontier and edge[0] not in visited:
                next_frontier.add(edge[0])
                visited.add(edge[0])
        frontier = next_frontier

    filtered_nodes = {k: v for k, v in nodes.items() if k in visited}
    filtered_edges = [(a, b) for a, b in edges if a in visited and b in visited]
    return filtered_nodes, filtered_edges


def _status_style(status: str) -> str:
    """Return a mermaid node style class for the given status."""
    return {
        "EXACT": "exact",
        "RELOC": "reloc",
        "MATCHING": "matching",
        "MATCHING_RELOC": "matching",
        "STUB": "stub",
        "UNKNOWN": "unknown",
    }.get(status, "unknown")


def render_mermaid(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
) -> str:
    """Render graph as Mermaid flowchart markup."""
    lines = ["graph LR"]

    # Style definitions
    lines.append("    classDef exact fill:#2ecc71,stroke:#27ae60,color:#fff")
    lines.append("    classDef reloc fill:#3498db,stroke:#2980b9,color:#fff")
    lines.append("    classDef matching fill:#f39c12,stroke:#e67e22,color:#fff")
    lines.append("    classDef stub fill:#e74c3c,stroke:#c0392b,color:#fff")
    lines.append("    classDef unknown fill:#95a5a6,stroke:#7f8c8d,color:#fff")
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

    # Edges
    for caller, callee in edges:
        key = (_sanitize_id(caller), _sanitize_id(callee))
        if key not in seen_edges:
            seen_edges.add(key)
            lines.append(f"    {key[0]} --> {key[1]}")

    return "\n".join(lines)


def render_dot(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
) -> str:
    """Render graph as Graphviz DOT format."""
    lines = ["digraph G {", "    rankdir=LR;", "    node [shape=box, style=filled];", ""]

    color_map = {
        "EXACT": "#2ecc71",
        "RELOC": "#3498db",
        "MATCHING": "#f39c12",
        "STUB": "#e74c3c",
        "UNKNOWN": "#95a5a6",
    }

    for name, info in sorted(nodes.items()):
        nid = _sanitize_id(name)
        status = info["status"]
        color = color_map.get(status, "#95a5a6")
        font_color = "white" if status != "MATCHING" else "black"
        label = f"{name}\\n[{status}]" if status != "UNKNOWN" else name
        lines.append(f'    {nid} [label="{label}", fillcolor="{color}", fontcolor="{font_color}"];')

    lines.append("")

    seen: set[tuple[str, str]] = set()
    for caller, callee in edges:
        key = (_sanitize_id(caller), _sanitize_id(callee))
        if key not in seen:
            seen.add(key)
            lines.append(f"    {key[0]} -> {key[1]};")

    lines.append("}")
    return "\n".join(lines)


def render_summary(nodes: dict[str, NodeInfo], edges: list[tuple[str, str]]) -> str:
    """Render a text summary of the graph statistics."""
    by_status: dict[str, int] = {}
    for info in nodes.values():
        s = info["status"]
        by_status[s] = by_status.get(s, 0) + 1

    total_reversed = sum(v for k, v in by_status.items() if k != "UNKNOWN")
    total_unknown = by_status.get("UNKNOWN", 0)

    lines = [
        f"Nodes: {len(nodes)} ({total_reversed} reversed, {total_unknown} unreversed)",
        f"Edges: {len(edges)}",
        "By status:",
    ]
    for status in ("EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB", "UNKNOWN"):
        count = by_status.get(status, 0)
        if count:
            lines.append(f"  {status}: {count}")

    # Find leaf functions (no outgoing calls) that are reversed
    callers = {e[0] for e in edges}
    callees = {e[1] for e in edges}
    leaves = [
        n for n in nodes if n not in callers and n in callees and nodes[n]["status"] != "UNKNOWN"
    ]
    if leaves:
        lines.append(f"\nLeaf functions (reversed, no outgoing calls): {len(leaves)}")
        for name in sorted(leaves)[:10]:
            lines.append(f"  - {name} [{nodes[name]['status']}]")
        if len(leaves) > 10:
            lines.append(f"  ... and {len(leaves) - 10} more")

    # Find blocking unreversed (called by many)
    callee_counts: dict[str, int] = {}
    for _, callee in edges:
        if nodes.get(callee, {}).get("status") == "UNKNOWN":
            callee_counts[callee] = callee_counts.get(callee, 0) + 1
    if callee_counts:
        top_blockers = sorted(callee_counts.items(), key=lambda x: -x[1])[:10]
        lines.append("\nTop unreversed blockers (called by most):")
        for name, count in top_blockers:
            lines.append(f"  - {name}: called by {count} functions")

    return "\n".join(lines)


_EPILOG = """\
[bold]Examples:[/bold]
  rebrew graph                                  Mermaid diagram of all functions
  rebrew graph --format dot                     Graphviz DOT format
  rebrew graph --format summary                 Text summary only
  rebrew graph --origin GAME                    Only GAME-origin functions
  rebrew graph --focus _my_func --depth 2       Neighbourhood around one function
  rebrew graph -o graph.md                      Write output to file

[bold]Output formats:[/bold]
  mermaid    Mermaid flowchart (default; paste into docs)
  dot        Graphviz DOT (pipe to 'dot -Tpng')
  summary    Text breakdown by component

[dim]Scans reversed .c files for call targets to build the dependency graph.
Uses annotations to determine function origins and status.[/dim]"""

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
    origin_filter: str | None = typer.Option(
        None, "--origin", help="Filter by origin (GAME, MSVCRT, ZLIB)"
    ),
    focus: str | None = typer.Option(
        None, "--focus", help="Focus on a specific function and its neighbours"
    ),
    depth: int = typer.Option(1, "--depth", help="Neighbourhood depth for --focus"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file (default: stdout)"),
    target: str | None = TargetOption,
) -> None:
    """Generate function dependency graph from reversed .c files."""
    cfg = get_config(target=target)
    reversed_dir = cfg.reversed_dir

    nodes, edges = build_graph(reversed_dir, origin_filter, cfg=cfg)

    if not nodes:
        print("No functions found.", file=sys.stderr)
        raise typer.Exit(code=1)

    if focus:
        nodes, edges = _focus_graph(nodes, edges, focus, depth)
        if not nodes:
            print(f"No function matching '{focus}' found.", file=sys.stderr)
            raise typer.Exit(code=1)

    if fmt == "mermaid":
        result = render_mermaid(nodes, edges)
    elif fmt == "dot":
        result = render_dot(nodes, edges)
    elif fmt == "summary":
        result = render_summary(nodes, edges)
    else:
        print(f"Unknown format: {fmt}. Use mermaid, dot, or summary.", file=sys.stderr)
        raise typer.Exit(code=1)

    if output:
        Path(output).write_text(result + "\n", encoding="utf-8")
        print(f"Written to {output}", file=sys.stderr)
    else:
        print(result)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
