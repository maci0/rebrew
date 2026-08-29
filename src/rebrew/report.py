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
import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.analysis import StringEntry, Xref, iter_strings, string_refs
from rebrew.annotation import Annotation, min_valid_va_for
from rebrew.binary_loader import load_binary
from rebrew.cli import (
    DISPLAY_STATUSES,
    TargetOption,
    iter_annotations,
    json_print,
    require_config,
)
from rebrew.config import ProjectConfig
from rebrew.depgraph import NodeInfo, build_graph, render_mermaid
from rebrew.imports import find_import_stubs, parse_imports
from rebrew.sources import (
    iter_sources,
    target_marker,
)
from rebrew.status import StatusReport, collect_status
from rebrew.utils import (
    atomic_write_text,
    rel_display_path,
)

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
        # The site has no JS and no external assets; the CSP keeps any
        # escaping of binary-derived content (strings, symbol names) inert —
        # nothing may execute or load off-site.
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">\n"
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
    from ``rebrew-functions.toml`` metadata.
    """
    from rebrew.metadata import get_entry

    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return []
    reversed_path = Path(reversed_dir)
    if not reversed_path.exists():
        return []
    functions: list[dict[str, Any]] = []
    metadata_dir = getattr(cfg, "metadata_dir", None)
    sources = iter_sources(reversed_path, cfg)
    for src, annos in iter_annotations(
        sources,
        target=target_marker(cfg),
        metadata_dir=metadata_dir,
    ):
        for ann in annos:
            if ann.marker_type in ("GLOBAL", "DATA"):
                continue
            if ann.va < min_valid_va_for(cfg):
                continue
            md = {}
            if isinstance(metadata_dir, Path):
                try:
                    md = get_entry(metadata_dir, ann.va, ann.module)
                except (OSError, ValueError, KeyError):
                    md = {}
            functions.append(
                {
                    "name": _display_name(ann, src),
                    "va": ann.va,
                    "status": ann.status or "UNKNOWN",
                    "size": ann.size,
                    "cflags": ann.cflags,
                    "module": ann.module,
                    "file": rel_display_path(src, reversed_path),
                    "blocker": str(md.get("blocker", "")),
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


def _ne_summary(cfg: ProjectConfig) -> dict[str, Any] | None:
    """16-bit NE summary for the report index (None for non-NE targets)."""
    bin_path = getattr(cfg, "target_binary", None)
    if not bin_path:
        return None
    bin_p = Path(bin_path)
    if not bin_p.exists() or not bin_p.is_file():
        return None
    try:
        from rebrew.binary_loader import load_binary, section_dict
        from rebrew.data import find_dispatch_tables
        from rebrew.ne_loader import enumerate_ne_functions

        info = load_binary(bin_path)
        if info.format != "ne":
            return None
        funcs = enumerate_ne_functions(info)
        vmt = find_dispatch_tables(info.data, section_dict(info), {}, min_entries=3, info=info)
        ne_segs = info.ne_segments  # type: ignore[attr-defined]
        return {
            "segments": len(ne_segs),
            "code_segments": sum(1 for s in ne_segs if s.is_code),
            "functions": len(funcs),
            "vmt_tables": len(vmt),
        }
    except Exception:  # best-effort summary
        return None


def _render_index(
    target: str,
    report: StatusReport,
    functions: list[dict[str, Any]],
    ne: dict[str, Any] | None = None,
) -> str:
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
    standard = set(DISPLAY_STATUSES)
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

    # 16-bit NE targets get their own card set (segments, VMTs).
    ne_html = ""
    if ne:
        ne_cards = "".join(
            "<div class='card'>"
            f"<div class='value'>{html.escape(str(v))}</div>"
            f"<div class='label'>{html.escape(k)}</div>"
            "</div>"
            for k, v in (
                ("Format", "16-bit NE"),
                (
                    "Segments",
                    f"{ne['code_segments']} code / {ne['segments'] - ne['code_segments']} data",
                ),
                ("Functions", str(ne["functions"])),
                ("VMTs", str(ne["vmt_tables"])),
            )
        )
        ne_html = f"<h2>16-bit NE target</h2><div class='cards'>{ne_cards}</div>"

    body = f"<h2>Function index</h2><div class='cards'>{card_html}</div>{ne_html}{table}"
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
    try:
        imports: list[dict[str, Any]] = parse_imports(binary)
    except (OSError, ValueError):
        return _page(
            "Imports",
            target,
            "imports.html",
            "<p class='note'>Failed to parse imports from the target binary.</p>",
        )
    try:
        stubs = find_import_stubs(binary)
    except (OSError, ValueError):
        stubs = {}
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
                    from rebrew.depgraph import binary_call_edges
                    from rebrew.ne_loader import enumerate_ne_functions

                    info = load_binary(bin_path)
                    if info.format == "ne":
                        ranges = [
                            (f.va, f.va + f.size, f"fcn_{f.va:08x}")
                            for f in enumerate_ne_functions(info)
                        ]
                        edges.extend(binary_call_edges(info, ranges))
                except Exception:  # best-effort augmentation
                    pass
        mermaid = render_mermaid(nodes, edges, dispatch_edges)
    except Exception:  # best-effort graph; the report must not crash
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
    # Build callee sets once instead of scanning the full edge list per node.
    callees_by_src: dict[str, list[str]] = {}
    for a, b in edges:
        callees_by_src.setdefault(a, []).append(b)
    for v in callees_by_src.values():
        v.sort()
    dispatch_by_src: dict[str, list[str]] = {}
    for a, b in dispatch_edges:
        dispatch_by_src.setdefault(a, []).append(b)
    for v in dispatch_by_src.values():
        v.sort()
    for name in sorted(nodes):
        info = nodes[name]
        status = info.get("status", "")
        va = info.get("va", 0)
        va_str = f"0x{va:08x}" if va else "-"
        callees = callees_by_src.get(name, [])
        dispatch = dispatch_by_src.get(name, [])
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
        ("index.html", _render_index(target, report, functions, ne=_ne_summary(cfg))),
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


def generate_decomp_dev_report(cfg: ProjectConfig, out_path: Path) -> dict[str, Any]:
    """Write an objdiff-format ``report.json`` for decomp.dev ingestion.

    decomp.dev (the decomp-scene progress hub) polls a GitHub Actions
    artifact named ``<version>_report`` containing a ``report.json`` in the
    objdiff report format (``objdiff-core/protos/report.proto``, version 2,
    JSON-serialized).  This emits that file from rebrew's existing status
    data:

    - ``EXACT``/``RELOC``/``PROVEN`` functions count as fully matched
      (``fuzzy_match_percent`` 100) — a byte-matched function is placed
      correctly by construction when the binary is relinked;
    - ``NEAR_MATCHING`` functions carry their cached ``match_percent`` when
      the verify cache has one, else 0;
    - everything else (STUB, unannotated registry functions) is 0.

    ``total_functions``/``total_code`` come from the function registry and
    the binary's ``.text`` size (the catalog's denominators), so progress is
    measured against the whole binary, not just the annotated subset.

    Returns the machine-readable summary dict.
    """
    from rebrew.catalog.loaders import parse_function_list
    from rebrew.catalog.registry import build_function_registry
    from rebrew.catalog.sections import get_text_section_size
    from rebrew.cli import iter_annotations
    from rebrew.config import FUNCTION_STRUCTURE_JSON
    from rebrew.metadata import MATCHED_STATUSES
    from rebrew.sources import iter_sources, target_marker

    sources = list(iter_sources(cfg.reversed_dir, cfg))
    marker = target_marker(cfg)
    annos_by_file: list[tuple[str, list[Any]]] = []
    for path, annos in iter_annotations(sources, target=marker, metadata_dir=cfg.metadata_dir):
        annos_by_file.append((rel_display_path(path), annos))

    # Registry = the whole-binary function set (denominator); the ghidra
    # export / function list may be missing — degrade to annotated VAs then.
    funcs: list[dict[str, Any]] = []
    ghidra_json = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON
    try:
        if cfg.function_list and Path(cfg.function_list).exists():
            funcs = list(parse_function_list(Path(cfg.function_list)))
        registry = build_function_registry(funcs, cfg, ghidra_json, cfg.target_binary)
    except (OSError, KeyError, ValueError, TypeError):
        registry = {}

    # Cached match_percent for NEAR_MATCHING (the fuzzy measure).
    cached_pct: dict[int, float] = {}
    try:
        from rebrew.verify import _load_verify_cache

        cache = _load_verify_cache(cfg.root / ".rebrew" / "verify_cache.json", cfg)
        if cache is not None:
            for key, entry in cache.entries.items():
                mp = entry.result.match_percent
                if mp is not None and isinstance(key, int):
                    cached_pct[key] = float(mp)
    except (OSError, ValueError, TypeError):
        pass

    def fuzzy_for(status: str, va: int) -> float:
        if status in MATCHED_STATUSES:
            return 100.0
        if status == "NEAR_MATCHING":
            return cached_pct.get(va, 0.0)
        return 0.0

    matched_statuses = set(MATCHED_STATUSES)
    units: list[dict[str, Any]] = []
    total_code = 0
    matched_code = 0
    fuzzy_code = 0.0
    total_functions = 0
    matched_functions = 0
    for file_rel, annos in annos_by_file:
        items: list[dict[str, Any]] = []
        unit_code = 0
        unit_matched = 0
        unit_fuzzy = 0.0
        unit_fns = 0
        for a in annos:
            if a.marker_type in ("GLOBAL", "DATA"):
                continue
            size = int(a.size or 0)
            if size <= 0:
                continue
            va = int(a.va)
            fuzzy = fuzzy_for(a.status, va)
            items.append(
                {
                    "name": a.name or a.symbol or f"func_{va:08x}",
                    "size": size,
                    "fuzzy_match_percent": round(fuzzy, 2),
                    "address": va,
                }
            )
            unit_code += size
            unit_fuzzy += size * fuzzy / 100.0
            unit_fns += 1
            if a.status in matched_statuses:
                unit_matched += size
                matched_functions += 1
        if not items:
            continue
        units.append(
            {
                "name": file_rel,
                "measures": {
                    "total_code": unit_code,
                    "matched_code": unit_matched,
                    "fuzzy_match_percent": round(unit_fuzzy / unit_code * 100.0, 2)
                    if unit_code
                    else 0.0,
                    "total_functions": unit_fns,
                    "matched_functions": sum(1 for i in items if i["fuzzy_match_percent"] >= 100.0),
                },
                "functions": items,
            }
        )
        total_code += unit_code
        matched_code += unit_matched
        fuzzy_code += unit_fuzzy
        total_functions += unit_fns

    registry_total = len(registry) if registry else total_functions
    if registry_total < total_functions:
        registry_total = total_functions
    text_size = get_text_section_size(cfg.target_binary) or total_code

    # Data measures: rebrew places data rather than "matching" it, so report
    # the totals honestly and leave matched/complete data at 0.
    data_size = 0
    try:
        from rebrew.binary_loader import load_binary

        info = load_binary(cfg.target_binary)
        for name in (".data", ".rdata", ".bss"):
            sec = info.sections.get(name)
            if sec is not None:
                data_size += int(getattr(sec, "virtual_size", 0) or 0)
    except (ImportError, OSError, KeyError, ValueError, RuntimeError):
        pass

    measures = {
        "fuzzy_match_percent": round(fuzzy_code / text_size * 100.0, 2) if text_size else 0.0,
        "total_code": text_size,
        "matched_code": matched_code,
        "matched_code_percent": round(matched_code / text_size * 100.0, 2) if text_size else 0.0,
        "total_data": data_size,
        "matched_data": 0,
        "matched_data_percent": 0.0,
        "total_functions": registry_total,
        "matched_functions": matched_functions,
        "matched_functions_percent": round(matched_functions / registry_total * 100.0, 2)
        if registry_total
        else 0.0,
        # A byte-matched rebrew function is byte-identical, hence "linked"
        # by construction when the rebuilt binary is relinked — map
        # complete_* onto matched_* for the decomp.dev "fully linked" bar.
        "complete_code": matched_code,
        "complete_code_percent": round(matched_code / text_size * 100.0, 2) if text_size else 0.0,
        "complete_data": 0,
        "complete_data_percent": 0.0,
        "total_units": len(units),
        "complete_units": sum(
            1
            for u in units
            if u["measures"]["matched_functions"] == u["measures"]["total_functions"]
        ),
    }

    report_doc = {"version": 2, "measures": measures, "units": units}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(out_path, json.dumps(report_doc, indent=2), encoding="utf-8")

    return {
        "out": str(out_path),
        "total_functions": registry_total,
        "matched_functions": matched_functions,
        "total_code": text_size,
        "matched_code": matched_code,
        "fuzzy_match_percent": measures["fuzzy_match_percent"],
        "units": len(units),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew report · · · · · · · · · · · · · · Write site to <output_dir>/report\n\n"
    "  rebrew report --out site · · · · · · · · · Write site to ./site\n\n"
    "  rebrew report --decomp-dev report.json · · Write an objdiff-format\n"
    "                                            report.json for decomp.dev\n\n"
    "  rebrew report --json · · · · · · · · · · · Machine-readable summary\n\n"
    "[dim]Generates a self-contained static HTML site (function index, strings, "
    "imports, call graph) with all styling inlined — no external assets.  "
    "`--decomp-dev` instead emits the objdiff report v2 JSON the decomp.dev "
    "progress hub ingests from a GitHub Actions artifact.[/dim]"
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
    decomp_dev: Path | None = typer.Option(
        None,
        "--decomp-dev",
        help="Write an objdiff-format report.json for decomp.dev (path to report.json).",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate a static HTML documentation site for a decomp project."""
    cfg = require_config(target=target, json_mode=json_output)

    if decomp_dev is not None:
        result = generate_decomp_dev_report(cfg, decomp_dev)
        if json_output:
            json_print(result)
            return
        console.print(f"[bold green]decomp.dev report written to:[/bold green] {result['out']}")
        console.print(
            f"  [dim]{result['matched_functions']}/{result['total_functions']} functions "
            f"matched ({result['fuzzy_match_percent']:.1f}% fuzzy of "
            f"{result['total_code']} code bytes)[/dim]"
        )
        console.print(
            "[dim]Upload it as a GitHub Actions artifact named `<version>_report` "
            "containing `report.json`, then register the repo at decomp.dev/manage/new.[/dim]"
        )
        return

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
