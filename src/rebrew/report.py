"""report.py - Static HTML documentation site for a decomp project.

Generates a self-contained (no external JS/CSS/CDN) static site into an
output directory with four pages:

- ``index.html``   — summary cards + full function table (name, VA, status,
  size, cflags), sorted by VA.
- ``strings.html`` — printable strings extracted from the binary's data
  sections (via :mod:`rebrew.analysis`) with per-string reference counts.
- ``imports.html`` — PE import table (dll, API, IAT slot) and detected
  ``jmp [IAT]`` import stubs.
- ``graph.html``   — the function call graph as embedded Mermaid source
  (from :mod:`rebrew.depgraph`) plus a plain-text adjacency fallback.

Every page degrades gracefully: missing binaries, missing data sections,
or call-graph failures produce a note inside the page instead of aborting
the whole report.

Usage:
    rebrew report                       # Write site to <output_dir>/report
    rebrew report --out site            # Write site to ./site
    rebrew report --json                # Machine-readable summary
"""

import html
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.analysis import StringEntry, Xref, iter_strings, string_refs
from rebrew.annotation import Annotation
from rebrew.binary_loader import load_binary
from rebrew.cli import (
    MIN_VALID_VA,
    TargetOption,
    iter_annotations,
    iter_sources,
    json_print,
    rel_display_path,
    require_config,
    target_marker,
)
from rebrew.config import ProjectConfig
from rebrew.depgraph import NodeInfo, build_graph, render_mermaid
from rebrew.imports import find_import_stubs, parse_imports
from rebrew.status import StatusReport, collect_status
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Shared HTML skeleton
# ---------------------------------------------------------------------------

# (href, nav label) for every page of the report site, in nav order.
_PAGES: list[tuple[str, str]] = [
    ("index.html", "Index"),
    ("strings.html", "Strings"),
    ("imports.html", "Imports"),
    ("graph.html", "Call graph"),
]

_CSS = """
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; background: #f5f6f8; color: #222; }
header { background: #1e293b; color: #fff; padding: 0.75rem 1.5rem;
         display: flex; align-items: baseline; gap: 2rem; }
header h1 { font-size: 1.05rem; margin: 0; }
nav a { color: #cbd5e1; text-decoration: none; margin-right: 1rem; }
nav a:hover { color: #fff; }
nav a.active { color: #fff; font-weight: 600; text-decoration: underline; }
main { max-width: 1100px; margin: 1.5rem auto; padding: 0 1.5rem; }
.cards { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
        padding: 0.9rem 1.1rem; min-width: 140px; }
.card .value { font-size: 1.5rem; font-weight: 700; }
.card .label { color: #64748b; font-size: 0.75rem; text-transform: uppercase;
               letter-spacing: 0.05em; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;
        margin-bottom: 1.5rem; }
th, td { text-align: left; padding: 0.5rem 0.75rem;
         border-bottom: 1px solid #eef2f7; font-size: 0.85rem; }
th { background: #f1f5f9; font-weight: 600; }
tr:last-child td { border-bottom: none; }
td.mono, code { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
.status-EXACT { color: #15803d; font-weight: 600; }
.status-RELOC { color: #0369a1; font-weight: 600; }
.status-PROVEN { color: #0e7490; font-weight: 600; }
.status-NEAR_MATCHING { color: #b45309; font-weight: 600; }
.status-STUB { color: #94a3b8; }
.status-UNKNOWN { color: #64748b; }
.note { background: #fff7ed; border: 1px solid #fed7aa; border-radius: 8px;
        padding: 0.9rem 1.1rem; color: #9a3412; margin-bottom: 1.5rem; }
pre.mermaid, pre.adjacency { background: #fff; border: 1px solid #e2e8f0;
        border-radius: 8px; padding: 1rem; overflow-x: auto;
        font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
        font-size: 0.8rem; line-height: 1.4; }
"""


def _nav_link(href: str, label: str, active: bool) -> str:
    """Render one navigation link (single-quoted attributes)."""
    cls = " class='active'" if active else ""
    return f"<a href='{href}'{cls}>{label}</a>"


def _page(title: str, target: str, active: str, body: str) -> str:
    """Wrap *body* in the shared page skeleton (inline CSS, no external assets)."""
    nav = "".join(_nav_link(href, label, href == active) for href, label in _PAGES)
    return (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
        "<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        f"<title>{html.escape(title)} - {html.escape(target)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n<body>\n"
        f"<header><h1>{html.escape(target)} - Rebrew report</h1><nav>{nav}</nav></header>\n"
        f"<main>\n{body}\n</main>\n"
        "</body>\n</html>\n"
    )


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


def _target_name(cfg: ProjectConfig) -> str:
    """Best-effort human-readable target name for page titles."""
    return getattr(cfg, "target_name", "") or getattr(cfg, "marker", "") or "rebrew"


def _display_name(ann: Annotation, src: Path) -> str:
    """Best display name for an annotation: C name, symbol, or file stem."""
    if ann.name:
        return ann.name
    if ann.symbol:
        return ann.symbol.lstrip("_")
    return src.stem


def _collect_functions(cfg: ProjectConfig) -> list[dict[str, Any]]:
    """Return per-function rows (name, va, status, size, cflags, blocker) sorted by VA.

    Mirrors the aggregation done by :func:`rebrew.status.collect_status` so
    the table stays consistent with the summary cards: same annotation source,
    same GLOBAL/DATA skip, same ``MIN_VALID_VA`` floor.  The blocker text
    (written by ``near-diag --fix-blocker`` / ``diff --fix-blocker``) comes
    from ``rebrew-function.toml`` metadata.
    """
    from rebrew.metadata import get_entry

    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return []
    functions: list[dict[str, Any]] = []
    sources = iter_sources(Path(reversed_dir), cfg)
    for src, annos in iter_annotations(
        sources,
        target=target_marker(cfg),
        metadata_dir=getattr(cfg, "metadata_dir", None),
    ):
        for ann in annos:
            if ann.marker_type in ("GLOBAL", "DATA"):
                continue
            if ann.va < MIN_VALID_VA:
                continue
            md = {}
            metadata_dir = getattr(cfg, "metadata_dir", None)
            if isinstance(metadata_dir, Path):
                md = get_entry(metadata_dir, ann.va, ann.module)
            functions.append(
                {
                    "name": _display_name(ann, src),
                    "va": ann.va,
                    "status": ann.status or "UNKNOWN",
                    "size": ann.size,
                    "cflags": ann.cflags,
                    "module": ann.module,
                    "file": rel_display_path(src, Path(reversed_dir)),
                    "blocker": md.get("blocker", ""),
                }
            )
    functions.sort(key=lambda fn: (fn["va"], fn["name"]))
    return functions


def _target_binary(cfg: ProjectConfig) -> Path | None:
    """Return the configured target binary path, or None when unset/missing."""
    binary = getattr(cfg, "target_binary", None)
    if binary is None:
        return None
    path = Path(binary)
    return path if path.exists() else None


# ---------------------------------------------------------------------------
# Page renderers
# ---------------------------------------------------------------------------


def _render_index(target: str, report: StatusReport, functions: list[dict[str, Any]]) -> str:
    """Render index.html: summary cards + full function table."""
    sc = report.status_counts
    matched = sc.get("EXACT", 0) + sc.get("RELOC", 0) + sc.get("PROVEN", 0)
    cards: list[tuple[str, str]] = [
        ("Total functions", str(report.total_functions)),
        ("Covered", f"{report.covered_functions} ({report.coverage_pct}%)"),
        ("Matched", f"{matched} ({report.matched_pct}%)"),
        ("NEAR_MATCHING", str(sc.get("NEAR_MATCHING", 0))),
        ("STUB", str(sc.get("STUB", 0))),
        ("Byte coverage", f"{report.byte_coverage_pct}%"),
    ]
    # Any non-standard statuses (MISMATCH, COMPILE_ERROR, ...) get their own card.
    standard = ("EXACT", "RELOC", "PROVEN", "NEAR_MATCHING", "STUB")
    cards.extend(
        (status, str(count)) for status, count in sorted(sc.items()) if status not in standard
    )

    card_html = "".join(
        "<div class='card'>"
        f"<div class='value'>{html.escape(value)}</div>"
        f"<div class='label'>{html.escape(label)}</div>"
        "</div>"
        for label, value in cards
    )

    if functions:
        rows = "".join(
            "<tr>"
            f"<td class='mono'>{html.escape(fn['name'])}</td>"
            f"<td class='mono'>0x{fn['va']:08x}</td>"
            f"<td class='status-{html.escape(fn['status'])}'>{html.escape(fn['status'])}</td>"
            f"<td class='mono'>{fn['size']}</td>"
            f"<td class='mono'>{html.escape(fn['cflags'])}</td>"
            f"<td class='blocker'>{html.escape(fn['blocker'])}</td>"
            "</tr>"
            for fn in functions
        )
        table = (
            "<table>"
            "<tr><th>Name</th><th>VA</th><th>Status</th><th>Size</th><th>CFLAGS</th>"
            "<th>Blocker</th></tr>"
            f"{rows}"
            "</table>"
        )
    else:
        table = "<p class='note'>No reversed functions found in the project.</p>"

    body = f"<h2>Function index</h2><div class='cards'>{card_html}</div>{table}"
    return _page("Function index", target, "index.html", body)


def _render_strings(cfg: ProjectConfig) -> str:
    """Render strings.html: printable strings from data sections + refs."""
    binary = _target_binary(cfg)
    if binary is None:
        return _page(
            "Strings",
            _target_name(cfg),
            "strings.html",
            "<p class='note'>Target binary not found - nothing to report.</p>",
        )
    try:
        info = load_binary(binary)
        strings = iter_strings(info, min_len=4)
    except (OSError, ValueError, RuntimeError):
        return _page(
            "Strings",
            _target_name(cfg),
            "strings.html",
            "<p class='note'>Failed to parse the target binary - nothing to report.</p>",
        )
    if not strings:
        data_sections = [n for n in (".rdata", ".data", ".rodata") if n in info.sections]
        if not data_sections:
            note = (
                "The target binary has no data sections (.rdata/.data/.rodata) - nothing to report."
            )
        else:
            note = f"No printable strings (min length 4) found in {', '.join(data_sections)}."
        return _page("Strings", _target_name(cfg), "strings.html", f"<p class='note'>{note}</p>")

    try:
        refs = string_refs(info, strings)
    except (OSError, ValueError, RuntimeError):
        refs = {}

    rows = "".join(_string_row(s, refs.get(s.va) or []) for s in strings)
    body = (
        "<p>Strings extracted from the binary's data sections (min length 4).</p>"
        "<table>"
        "<tr><th>VA</th><th>Section</th><th>Kind</th><th>Text</th>"
        "<th>Refs</th><th>Referenced from</th></tr>"
        f"{rows}"
        "</table>"
    )
    return _page("Strings", _target_name(cfg), "strings.html", body)


def _string_row(s: StringEntry, xrefs: list[Xref]) -> str:
    """Render one string table row with ref count and first referencing VAs."""
    text = s.text if len(s.text) <= 80 else s.text[:80] + "\u2026"
    first = ", ".join(f"0x{x.from_va:08x}" for x in xrefs[:5])
    if len(xrefs) > 5:
        first += f" (+{len(xrefs) - 5} more)"
    return (
        "<tr>"
        f"<td class='mono'>0x{s.va:08x}</td>"
        f"<td>{html.escape(s.section)}</td>"
        f"<td>{html.escape(s.kind)}</td>"
        f"<td class='mono'>{html.escape(text)}</td>"
        f"<td>{len(xrefs)}</td>"
        f"<td class='mono'>{html.escape(first) or '&mdash;'}</td>"
        "</tr>"
    )


def _render_imports(cfg: ProjectConfig) -> str:
    """Render imports.html: PE import table + jmp [IAT] stubs."""
    target = _target_name(cfg)
    binary = _target_binary(cfg)
    if binary is None:
        return _page(
            "Imports",
            target,
            "imports.html",
            "<p class='note'>Target binary not found - nothing to report.</p>",
        )
    imports: list[dict[str, Any]] = parse_imports(binary)
    stubs = find_import_stubs(binary)
    if not imports:
        return _page(
            "Imports",
            target,
            "imports.html",
            "<p class='note'>No import table found in the target binary - nothing to report.</p>",
        )

    rows = "".join(
        "<tr>"
        f"<td>{html.escape(rec['dll'])}</td>"
        f"<td class='mono'>{html.escape(rec['name'])}</td>"
        f"<td class='mono'>0x{rec['iat_va']:08x}</td>"
        "</tr>"
        for rec in sorted(imports, key=lambda r: r["iat_va"])
    )
    parts = [
        f"<p>{len(imports)} imported APIs.</p>",
        "<table><tr><th>DLL</th><th>Function</th><th>IAT slot</th></tr>",
        rows,
        "</table>",
    ]
    if stubs:
        stub_rows = "".join(
            f"<tr><td class='mono'>0x{va:08x}</td><td class='mono'>{html.escape(name)}</td></tr>"
            for va, name in sorted(stubs.items())
        )
        parts.extend(
            [
                "<h3>Import stubs (jmp [IAT])</h3>",
                "<table><tr><th>VA</th><th>API</th></tr>",
                stub_rows,
                "</table>",
            ]
        )
    return _page("Imports", target, "imports.html", "".join(parts))


def _render_graph(cfg: ProjectConfig) -> str:
    """Render graph.html: mermaid call graph + plain-text adjacency fallback.

    Call-graph generation is best-effort: any failure (malformed annotation
    blocks, unreadable sources, rendering errors) degrades to a note inside
    the page rather than aborting the whole report.
    """
    target = _target_name(cfg)
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return _page(
            "Call graph",
            target,
            "graph.html",
            "<p class='note'>No reversed source directory configured - call graph is empty.</p>",
        )
    try:
        nodes, edges, dispatch_edges = build_graph(Path(reversed_dir), cfg=cfg)
        # Stub-only projects (e.g. an intake'd NE target) have no source
        # edges — augment with the binary call graph when the target binary
        # is available so graph.html shows the real call structure.
        if not edges:
            bin_path = getattr(cfg, "target_binary", None)
            if bin_path and Path(bin_path).exists():
                try:
                    from rebrew.binary_loader import load_binary
                    from rebrew.depgraph import _binary_call_edges
                    from rebrew.ne_loader import enumerate_ne_functions

                    info = load_binary(bin_path)
                    if info.format == "ne":
                        ranges = [
                            (f.va, f.va + f.size, f"fcn_{f.va:08x}")
                            for f in enumerate_ne_functions(info)
                        ]
                        edges.extend(_binary_call_edges(info, ranges))
                except Exception:  # noqa: BLE001 — best-effort augmentation
                    pass
        mermaid = render_mermaid(nodes, edges, dispatch_edges)
    except Exception:  # noqa: BLE001 — best-effort graph; the report must not crash
        console.print(
            "[yellow]report:[/yellow] call graph generation failed - writing a placeholder graph.html"
        )
        return _page(
            "Call graph",
            target,
            "graph.html",
            "<p class='note'>Call graph generation failed. The other pages of this report are "
            "complete.</p>",
        )

    body = (
        "<p>Call graph over reversed functions. The mermaid source below renders in any "
        "mermaid-compatible viewer; the plain-text adjacency list is a fallback.</p>"
        "<h3>Mermaid</h3>"
        f"<pre class='mermaid'>{html.escape(mermaid)}</pre>"
        "<h3>Adjacency list</h3>"
        f"<pre class='adjacency'>{html.escape(_adjacency_list(nodes, edges, dispatch_edges))}</pre>"
    )
    return _page("Call graph", target, "graph.html", body)


def _adjacency_list(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
    dispatch_edges: list[tuple[str, str]],
) -> str:
    """Plain-text adjacency list over *nodes*: ``name [status] va -> callees``."""
    lines = [f"{len(nodes)} nodes, {len(edges)} direct edges, {len(dispatch_edges)} dispatch edges"]
    for name in sorted(nodes):
        info = nodes[name]
        status = info.get("status", "")
        va = info.get("va", 0)
        va_str = f"0x{va:08x}" if va else "-"
        callees = sorted(b for a, b in edges if a == name)
        dispatch = sorted(b for a, b in dispatch_edges if a == name)
        if not callees and not dispatch:
            lines.append(f"{name} [{status}] {va_str}")
            continue
        parts = [f"{name} [{status}] {va_str} ->", ", ".join(callees)]
        if dispatch:
            parts.append(f"(dispatch: {', '.join(dispatch)})")
        lines.append(" ".join(parts))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(cfg: ProjectConfig, out: Path) -> dict[str, Any]:
    """Generate the static HTML report site into *out*.

    Returns the machine-readable summary dict::

        {"out": str, "pages": [...], "summary": {totals...}}

    Every page is written even when its data source is missing or broken —
    such pages degrade to an explanatory note instead.
    """
    out.mkdir(parents=True, exist_ok=True)
    report = collect_status(cfg)
    functions = _collect_functions(cfg)
    target = _target_name(cfg)

    pages = [
        ("index.html", _render_index(target, report, functions)),
        ("strings.html", _render_strings(cfg)),
        ("imports.html", _render_imports(cfg)),
        ("graph.html", _render_graph(cfg)),
    ]
    for name, content in pages:
        atomic_write_text(out / name, content, encoding="utf-8")

    summary = {
        "total_functions": report.total_functions,
        "covered_functions": report.covered_functions,
        "coverage_pct": report.coverage_pct,
        "matched_pct": report.matched_pct,
        "byte_coverage_pct": report.byte_coverage_pct,
        "status_counts": report.status_counts,
    }
    return {"out": str(out), "pages": [name for name, _ in pages], "summary": summary}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew report · · · · · · · · · · · · · · Write site to <output_dir>/report\n\n"
    "  rebrew report --out site · · · · · · · · · Write site to ./site\n\n"
    "  rebrew report --json · · · · · · · · · · · Machine-readable summary\n\n"
    "[dim]Generates a self-contained static HTML site (function index, strings, "
    "imports, call graph) with all styling inlined — no external assets.[/dim]"
)

app = typer.Typer(
    help="Generate a static HTML documentation site for a decomp project.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    out: Path | None = typer.Option(
        None, "--out", help="Output directory (default: <output_dir>/report)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate a static HTML documentation site for a decomp project."""
    cfg = require_config(target=target, json_mode=json_output)

    if out is None:
        output_dir = getattr(cfg, "output_dir", None) or Path("output")
        out = Path(output_dir) / "report"

    result = generate_report(cfg, out)

    if json_output:
        json_print(result)
        return

    console.print(f"[bold green]Report written to:[/bold green] {out}")
    for page in result["pages"]:
        console.print(f"  [dim]{page}[/dim]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
