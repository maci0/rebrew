"""report.py - Static HTML documentation site for a decomp project.

Generates a self-contained (no external JS/CSS/CDN) static site into an
output directory with four pages:

- ``index.html``   — summary cards + function table (name, VA, file, status,
  size, cflags, blocker), sorted by VA.  A closed "Status reference"
  disclosure under the cards gives one line per status the page names.
  Large tables split across
  ``index-pN.html`` so the first paint stays within a few hundred rows.
- ``strings.html`` — printable strings extracted from the binary's data
  sections (via :mod:`rebrew.analysis`) with per-string reference counts;
  likewise paginated when the list is long. A multi-page function or
  strings pager names the address span of its rows.
- ``imports.html`` — PE import table (dll, API, IAT slot) and detected
  ``jmp [IAT]`` import stubs.  Both tables paginate (``imports-pN.html``,
  ``import-stubs.html``) once they pass the same row budget as the index.
- ``graph.html``   — the function call graph as embedded Mermaid source
  (from :mod:`rebrew.depgraph`).  The plain-text adjacency list ships as a
  sibling ``adjacency.txt``.  A Mermaid source over 32 KB ships as
  ``callgraph.mmd`` and the HTML page keeps the opening lines, so the
  document can paint before the rest of the graph is read.

Each file states what it carries that a reader may be refused
(:data:`SiteDataKind`) where it is generated; the summary's ``kinds`` maps every
written file, sidecars included, to its kinds, and a file without one fails
the build.

Every HTML/text page also writes max-effort ``.gz`` and ``.zst`` sidecars
(when smaller) so static servers with precompressed-asset support can skip
per-request compression.  Gzip sidecars use ``mtime=0``.  A rebuild deletes
pages and sidecars this run did not write, so a server cannot keep serving
the previous body under the same name.  Every page degrades gracefully: missing binaries,
missing data sections, or call-graph failures produce a note inside the page
instead of aborting the whole report.

Usage:
    rebrew coverage report                       # Write site to <output_dir>/report
    rebrew coverage report --output site         # Write site to ./site
    rebrew coverage report --json                # Machine-readable summary
"""

import re
from typing import Literal, get_args  # module statement: definition-time use
lazy import json
lazy import logging
lazy import math
lazy from pathlib import Path
lazy from typing import Any

import typer
from jinja2 import Environment, PackageLoader, select_autoescape
lazy from markupsafe import Markup

from rebrew.cli import (
    TargetOption,
    console,
    json_print,
    require_config,
)
from rebrew.status_style import (
    DISPLAY_STATUSES,
    STATUS_HEX,
    STATUS_SUMMARIES,
    status_legend_rows,
    status_text_css,
)
from rebrew.theme import FAVICON_SVG, inline
lazy from rebrew.analysis import StringEntry, Xref, iter_strings, string_refs
lazy from rebrew.compression import precompress
lazy from rebrew.config import ProjectConfig, target_module
lazy from rebrew.depgraph import NodeInfo, build_graph, render_mermaid
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.formats.import_table import find_import_stubs, parse_imports
lazy from rebrew.metadata.bindings import (
    SourceBinding,
    iter_source_bindings,
    library_bindings_for_file,
    min_valid_va_for,
)
lazy from rebrew.sources import iter_library_headers, iter_sources, scan_files
lazy from rebrew.status import StatusReport, collect_status
lazy from rebrew.utils import (
    atomic_write_bytes,
    atomic_write_text,
    floor_pct,
    parse_int_literal,
    rel_display_path,
    truncate_text,
)

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

# Rows per HTML page for index/strings/imports tables.  Keeps the entry
# document's HTML parse budget small on large projects (thousands of
# functions, strings, or imports); extra pages are linked via a no-JS pager.
_TABLE_PAGE_SIZE = 250


def _total_pages(total: int) -> int:
    """Ceiling page count for *total* rows at ``_TABLE_PAGE_SIZE`` rows/page.

    The one computation the index, strings and paged-table renderers share so
    they cannot drift on the ceil/floor edge (a single-page table still counts
    as one page).
    """
    return max(1, -(-total // _TABLE_PAGE_SIZE))


# Strings-table cells longer than these collapse into a <details> disclosure.
_STRING_CELL_CHARS = 80
_REFS_CELL_COUNT = 5
# Mermaid past this stays out of graph.html.  A few thousand functions is
# hundreds of KB of source; the page keeps the opening lines and links the file.
_MERMAID_INLINE_MAX = 32 * 1024
# Files this command owns inside the output directory (plus .gz / .zst sidecars).
# Anything else in --output is left alone.
_OWNED_REPORT_FILE = re.compile(
    r"^(?:index|strings|imports|import-stubs)(?:-p[1-9][0-9]*)?\.html$"
    r"|^graph\.html$"
    r"|^favicon\.svg$"
    r"|^adjacency\.txt$"
    r"|^callgraph\.mmd$"
)


#: Status token -> the mark classes the stylesheet colours.  A status the
#: vocabulary does not know (a stale status token, a hand-edited TOML) gets the
#: bare ``st`` class rather than a class name built from the token, which
#: would otherwise add selectors of its own.  DISPATCH is a graph fill and
#: never body text.
_STATUS_CLASSES: dict[str, str] = {
    status: f"st status-{status}" for status in STATUS_HEX if status != "DISPATCH"
}


def _status_forced_selectors() -> str:
    """Forced-colors selector for the status text rules.

    Every status mark carries the shared ``st`` class, so one selector
    covers the whole vocabulary — a per-status list would have to be
    re-spelled whenever the mark table grows.
    """
    return "  .st"


# Chrome is the shared token set (rebrew.theme, resolved below) and the status
# marks are status_style.STATUS_HEX, the same ones the coverage dashboard renders.
_TEMPLATE_ENV = Environment(
    loader=PackageLoader("rebrew", "templates/report"),
    autoescape=select_autoescape(["html", "html.j2", "xml"]),
    keep_trailing_newline=True,
)


def _render_template(name: str, **context: Any) -> str:
    """Render one Jinja2 template from ``rebrew/templates/report/``."""
    return _TEMPLATE_ENV.get_template(name).render(**context)


_CSS = inline(
    _render_template(
        "report.css.j2",
        status_text_css=status_text_css(),
        status_forced=_status_forced_selectors(),
    )
)


def _paged_href(stem: str, page: int) -> str:
    """Filename for page *page* (1-based) of a paginated report table."""
    return f"{stem}.html" if page <= 1 else f"{stem}-p{page}.html"


def _count_phrase(count: int, singular: str, plural: str) -> str:
    """``"1 function"`` / ``"12 functions"`` for a one-line table intro."""
    return f"{count} {singular if count == 1 else plural}"


def _page_va_span(vas: list[int]) -> str:
    """``0xlo`` or ``0xlo–0xhi`` for the addresses on one report page."""
    if not vas:
        return ""
    lo = min(vas)
    hi = max(vas)
    start = f"0x{lo:08x}"
    if lo == hi:
        return start
    return start + "\u2013" + f"0x{hi:08x}"


def _pager_nav(
    stem: str,
    page: int,
    total_pages: int,
    total_rows: int,
    noun: str,
    label: str = "Table pages",
    span: str = "",
    *,
    bottom: bool = False,
) -> str:
    """No-JS first/prev/next/last pager for multi-page report tables.

    *span* is the address range of this page (``0x10001000–0x10003f70``),
    so a reader can open the page that contains an address.  Numbered links
    jump straight to a nearby page; First and Last cover the ends a long
    report would otherwise take a click per page to reach.

    *bottom* marks the copy that repeats under the table, which a table of up
    to ``_TABLE_PAGE_SIZE`` rows otherwise pushes off the screen.
    """
    if total_pages <= 1:
        return ""
    start = (page - 1) * _TABLE_PAGE_SIZE + 1
    end = min(page * _TABLE_PAGE_SIZE, total_rows)
    items: list[dict[str, Any]] = []
    if page > 2:
        items.append(
            {
                "current": False,
                "href": _paged_href(stem, 1),
                "aria_label": f"First page of {noun}",
                "text": "First",
            }
        )
    if page > 1:
        items.append(
            {
                "current": False,
                "href": _paged_href(stem, page - 1),
                "aria_label": f"Previous page of {noun}",
                "text": "Previous",
            }
        )
    # Two pages either side.  A wider window turns a long report's pager into
    # a second nav row; First/Last already reach the ends, so those two
    # numbers are not linked a second time.
    window = range(max(1, page - 2), min(total_pages, page + 2) + 1)
    for number in window:
        if (number == 1 and page > 2) or (number == total_pages and page < total_pages - 1):
            continue
        if number == page:
            items.append({"current": True, "text": f"Page {number} of {total_pages}"})
            continue
        items.append(
            {
                "current": False,
                "href": _paged_href(stem, number),
                "aria_label": f"Page {number} of {total_pages} of {noun}",
                "text": str(number),
            }
        )
    if page < total_pages:
        items.append(
            {
                "current": False,
                "href": _paged_href(stem, page + 1),
                "aria_label": f"Next page of {noun}",
                "text": "Next",
            }
        )
    if page < total_pages - 1:
        items.append(
            {
                "current": False,
                "href": _paged_href(stem, total_pages),
                "aria_label": f"Last page of {noun}",
                "text": "Last",
            }
        )
    return _render_template(
        "pager.html.j2",
        bottom=bottom,
        label=label,
        start=start,
        end=end,
        total_rows=total_rows,
        noun=noun,
        span=span,
        items=items,
    )


#: What a report file carries that a reader may be refused, from this closed set.
#: Each file the site writes states its kinds where it is generated
#: (:func:`generate_report`); its sidecars carry the same.  ``none`` stands alone:
#: the file carries none of the others.
SiteDataKind = Literal[
    "call_graph",
    "cross_references",
    "decompilation",
    "ai_derived",
    "member_identities",
    "none",
]

#: Every :data:`SiteDataKind`, for a consumer that validates a manifest.
SITE_DATA_KINDS: tuple[SiteDataKind, ...] = get_args(SiteDataKind)

#: A file that carries none of the withheld kinds.
_NO_WITHHELD: tuple[SiteDataKind, ...] = ("none",)


def _write_sidecar(path: Path, blob: bytes | None) -> None:
    """Write *blob* or remove a sidecar that would no longer match *path*."""
    if blob is not None:
        atomic_write_bytes(path, blob)
        return
    try:
        path.unlink()
    except FileNotFoundError:
        return


def _write_static(
    path: Path,
    content: str | bytes,
    kinds: tuple[SiteDataKind, ...],
    declared: dict[str, tuple[SiteDataKind, ...]],
) -> None:
    """Write *content* and max-effort ``.gz`` / ``.zst`` sidecars when smaller.

    *kinds* is what the file carries; it is recorded in *declared* under the
    file's name and under each sidecar written.

    Sidecars that do not shrink the body are removed.  A static server that
    prefers ``name.gz`` over ``name`` would otherwise keep serving the previous
    page after this one stopped compressing.  :func:`rebrew.compression.precompress`
    pins gzip ``mtime=0``, so an unchanged page keeps a byte-identical sidecar
    across rebuilds.
    """
    if isinstance(content, str):
        atomic_write_text(path, content, encoding="utf-8")
        raw = content.encode("utf-8")
    else:
        atomic_write_bytes(path, content)
        raw = content
    if not kinds or ("none" in kinds and len(kinds) > 1):
        raise ValueError(f"{path.name}: kinds must be 'none' alone or withheld kinds")
    declared[path.name] = kinds
    for suffix, blob in ((".gz", precompress(raw, "gzip")), (".zst", precompress(raw, "zstd"))):
        _write_sidecar(Path(str(path) + suffix), blob)
        if blob is not None:
            declared[path.name + suffix] = kinds


def _owned_report_name(name: str) -> str | None:
    """Return the page name for an owned file or its sidecar, else ``None``."""
    base = name.removesuffix(".gz").removesuffix(".zst")
    if _OWNED_REPORT_FILE.fullmatch(base):
        return base
    return None


def _prune_stale_report_files(out: Path, written: set[str]) -> None:
    """Delete owned pages and sidecars this run did not write.

    Leaves every other file in *out* alone (``--output`` may not be empty).
    """
    for child in list(out.iterdir()):
        if not child.is_file():
            continue
        base = _owned_report_name(child.name)
        if base is None or base in written:
            continue
        try:
            child.unlink()
        except FileNotFoundError:
            continue


def _cards(pairs: list[tuple[str, str]]) -> str:
    """Render (label, value) summary cards as a description list."""
    return _render_template("cards.html.j2", pairs=pairs)


def _data_table(caption: str, headers: list[str], rows_html: str) -> str:
    """Build a captioned data table with column scopes and a scroll region."""
    return _render_template(
        "data_table.html.j2",
        caption=caption,
        headers=headers,
        rows_html=rows_html,
    )


def _no_functions_note(reversed_dir: Path | None) -> Markup:
    """Why the index and the call graph are empty, naming the directory read.

    "The project's reversed directory" names a config key, not a place: a
    reader who has to go looking for it cannot tell an empty directory from the
    wrong one.  The path the loader actually read is the one thing on the page
    that settles that.
    """
    if reversed_dir is None:
        return Markup(
            "No reversed functions found. Set <code>reversed_dir</code> in "
            "rebrew-project.toml, then regenerate this report."
        )
    return Markup(
        "No reversed functions found. Add annotated sources under "
        "<code>{}</code>, then regenerate this report."
    ).format(str(reversed_dir))


def _status_legend(statuses: set[str]) -> str:
    """A disclosure naming every status the page shows, one line each.

    The cards and the table both print bare tokens, and a static page cannot
    link a reader to ``docs/MATCH_TYPES.md`` on the machine that generated it.
    Closed by default: the names are reference, not the first thing to read,
    and an open block would push a long table off the screen.
    """
    rows = status_legend_rows(statuses)
    if not rows:
        return ""
    # A table row saved without a STATUS prints the UNKNOWN the classifier
    # gives it, so that token needs its own line beside the stored ones.
    if "UNKNOWN" in statuses and all(status != "UNKNOWN" for status, _ in rows):
        rows = [*rows, ("UNKNOWN", STATUS_SUMMARIES["UNKNOWN"])]
    styled_rows = [(status, _STATUS_CLASSES.get(status, "st"), meaning) for status, meaning in rows]
    return _render_template("status_legend.html.j2", rows=styled_rows)


def _page(title: str, target: str, active: str, body: str) -> str:
    """Wrap *body* in the shared page skeleton (inline CSS, no external assets)."""
    return _render_template(
        "base.html.j2",
        title=title,
        target=target,
        active=active,
        pages=_PAGES,
        css=_CSS,
        body=body,
    )


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


def _target_name(cfg: ProjectConfig) -> str:
    """Best-effort human-readable target name for page titles."""
    return getattr(cfg, "target_name", "") or getattr(cfg, "module", "") or "rebrew"


def _display_name(ann: SourceBinding, src: Path) -> str:
    """Best display name for an annotation: C name, symbol, or file stem.

    A missing C name uses the symbol. ``hook@@12`` is ``hook``,
    ``@keeps@4`` is ``keeps``, and ``__foo`` is ``_foo``.
    """
    if ann.name:
        return ann.name
    if ann.symbol:
        from rebrew.rename_ops import c_name_from_symbol

        return c_name_from_symbol(ann.symbol)
    return src.stem


def _collect_functions(cfg: ProjectConfig, *, trusted: Any = None) -> list[dict[str, Any]]:
    """Return per-function rows (name, va, file, status, size, cflags, blocker) sorted by VA.

    Mirrors the aggregation done by :func:`rebrew.status.collect_status` so
    the table stays consistent with the summary cards: same annotation source,
    same GLOBAL/DATA skip, same ``MIN_VALID_VA`` floor.  The blocker text
    (written by ``rebrew diagnose near --fix-blocker`` / ``diff --fix-blocker``) comes
    from ``rebrew-functions.toml`` metadata.
    """
    from rebrew.metadata.functions import load_metadata

    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return []
    reversed_path = Path(reversed_dir)
    if not reversed_path.exists():
        return []
    functions: list[dict[str, Any]] = []
    sizes: dict[int, int] = {}
    if trusted is not None:
        from rebrew.catalog.loaders import scan_reversed_dir, trusted_function_list

        inventory = trusted_function_list(cfg)
        trusted.bind(cfg, scan_reversed_dir(cfg.reversed_dir, cfg=cfg), inventory)
        sizes = {int(item["va"]): int(item["size"]) for item in inventory}
    metadata_dir = getattr(cfg, "metadata_dir", None)
    entries: dict[tuple[str, int], dict[str, Any]] = {}
    if isinstance(metadata_dir, Path):
        try:
            entries = load_metadata(metadata_dir, deepcopy=False)
        except (OSError, ValueError, KeyError) as exc:
            # A migrated project keeps STATUS and BLOCKER only in this store, so
            # a failed load renders every function as UNKNOWN with no blocker,
            # and the finished HTML report reads as complete.  Say which store
            # failed, matching the sibling loaders.
            logging.getLogger(__name__).warning(
                "metadata load failed for %s: %s; report shows no statuses or blockers",
                metadata_dir,
                exc,
            )
            entries = {}
    # One traversal feeds both halves below: the source scan and the library
    # header scan used to walk the same tree separately.
    tree = scan_files(reversed_path)
    sources = iter_sources(reversed_path, cfg, scanned=tree)
    for src, annos in iter_source_bindings(
        sources,
        target=target_module(cfg),
        metadata_dir=metadata_dir,
        project_root=getattr(cfg, "root", None),
    ):
        for ann in annos:
            if ann.is_data:
                continue
            if ann.va < min_valid_va_for(cfg):
                continue
            if trusted is not None and ann.va not in sizes:
                continue
            md = entries.get((ann.module, ann.va), {})
            verdict = trusted.verdict(cfg.root, src, ann.va) if trusted is not None else None
            functions.append(
                {
                    "name": _display_name(ann, src),
                    "va": ann.va,
                    "status": (verdict.status if verdict else "UNKNOWN")
                    if trusted is not None
                    else ann.status or "UNKNOWN",
                    "size": sizes[ann.va] if trusted is not None else ann.size,
                    "cflags": ann.cflags,
                    "module": ann.module,
                    "file": rel_display_path(src, reversed_path),
                    "blocker": str(md.get("blocker", "")),
                }
            )
    # library_*.h entries (identify-library / crt-match --fix-source) are counted
    # by the summary cards (collect_status scans them via naming.load_data) but
    # were missing from this table: iter_sources does not glob library_*.h, and
    # their rows need library_bindings_for_file.
    for header in iter_library_headers(reversed_path, cfg, scanned=tree):
        for ann in library_bindings_for_file(header, metadata_dir=metadata_dir):
            if ann.va < min_valid_va_for(cfg):
                continue
            if trusted is not None and ann.va not in sizes:
                continue
            verdict = trusted.verdict(cfg.root, header, ann.va) if trusted is not None else None
            functions.append(
                {
                    "name": ann.symbol or ann.name or f"func_{ann.va:08x}",
                    "va": ann.va,
                    "status": (verdict.status if verdict else "UNKNOWN")
                    if trusted is not None
                    else ann.status or "UNKNOWN",
                    "size": sizes[ann.va] if trusted is not None else ann.size,
                    "cflags": ann.cflags,
                    "module": ann.module,
                    "file": rel_display_path(header, reversed_path),
                    # rebrew-functions.toml is the authoritative blocker store;
                    # the binding carries the copy this pass already loaded.
                    "blocker": str(
                        entries.get((ann.module, ann.va), {}).get("blocker") or ann.blocker or ""
                    ),
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
    return path if path.is_file() else None


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
        from rebrew.data_scan import find_dispatch_tables
        from rebrew.formats.binary_loader import load_binary, section_dict
        from rebrew.formats.ne_loader import enumerate_ne_functions

        info = load_binary(bin_path)
        if info.format != "ne":
            return None
        funcs = enumerate_ne_functions(info)
        vmt = find_dispatch_tables(info.data, section_dict(info), {}, min_entries=3, info=info)
        ne_segs = info.ne_segments
        return {
            "segments": len(ne_segs),
            "code_segments": sum(1 for s in ne_segs if s.is_code),
            "functions": len(funcs),
            "vmt_tables": len(vmt),
        }
    except Exception as exc:  # best-effort summary
        logging.getLogger(__name__).debug("NE summary failed: %s", exc)
        return None


def _function_rows_html(functions: list[dict[str, Any]]) -> str:
    """Render ``<tr>…</tr>`` rows for a slice of the function index table."""
    rows = [
        {
            "name": fn["name"],
            "va_hex": f"0x{fn['va']:08x}",
            "file": fn["file"],
            "status_class": _STATUS_CLASSES.get(fn["status"], "st"),
            "status": fn["status"],
            "size": fn["size"],
            "cflags": fn["cflags"],
            "blocker": fn["blocker"],
        }
        for fn in functions
    ]
    return _render_template("function_rows.html.j2", functions=rows)


def _render_index(
    target: str,
    report: StatusReport,
    functions: list[dict[str, Any]],
    ne: dict[str, Any] | None = None,
    reversed_dir: Path | None = None,
) -> list[tuple[str, str]]:
    """Render index.html (+ ``index-pN.html`` when the table exceeds one page)."""
    sc = report.status_counts
    # One percentage. With a known .text size the code-account card is that
    # share and Byte-matched is a count. Without a size, Byte-matched carries
    # the function share and the code-account card says the size was not measured.
    over_text: dict[str, Any] | None = None
    if report.total_text_bytes > 0:
        matched_card = f"{report.matched_functions}/{report.total_functions}"
        # The percentage's numerator is the accounted bytes (matched plus
        # alignment fill), so that is what has to fit the measured .text.  A
        # span outside .text leaves its bytes in both sums and the ratio reads
        # as e.g. 102.4%, which reads as a broken number.  "100%+" states the
        # figure is at least a full section without inventing one; the note
        # gives the byte counts.
        if report.accounted_text_bytes > report.total_text_bytes:
            counted = f"{report.matched_bytes} bytes of matched functions and identified libraries"
            if report.padding_bytes:
                counted += f" plus {report.padding_bytes} bytes of alignment fill"
            text_card = "100%+"
            over_text = {"counted": counted, "total_text_bytes": report.total_text_bytes}
        else:
            text_card = f"{report.byte_coverage_pct}%"
    else:
        matched_card = (
            f"{report.matched_functions}/{report.total_functions}"
            f" ({report.matched_pct}% of functions)"
        )
        text_card = "n/a"
    cards: list[tuple[str, str]] = [
        ("Total functions", str(report.total_functions)),
        ("With source", f"{report.covered_functions}/{report.total_functions}"),
        ("Byte-matched", matched_card),
        ("PROVEN", str(sc.get("PROVEN", 0))),
        ("NEAR_MATCHING", str(sc.get("NEAR_MATCHING", 0))),
        ("STUB", str(sc.get("STUB", 0))),
        ("Code account", text_card),
    ]
    # Any non-standard statuses (MISMATCH, COMPILE_ERROR, ...) get their own card.
    standard = set(DISPLAY_STATUSES)
    cards.extend(
        (status, str(count)) for status, count in sorted(sc.items()) if status not in standard
    )

    card_html = _cards(cards)
    # The cards print the tokens the legend explains, so the two travel
    # together: DISPLAY_STATUSES has a card whether or not the count is zero.
    shown = set(sc) | set(DISPLAY_STATUSES)
    # A table row saved without a STATUS prints the UNKNOWN the classifier
    # gives it, so that token needs its own line beside the stored ones.
    if any(fn["status"] == "UNKNOWN" for fn in functions):
        shown.add("UNKNOWN")
    legend_html = _status_legend(shown)

    # 16-bit NE targets get their own card set (segments, VMTs).
    ne_cards_html: str | None = None
    if ne:
        ne_cards_html = _cards(
            [
                ("Format", "16-bit NE"),
                (
                    "Segments",
                    f"{ne['code_segments']} code / {ne['segments'] - ne['code_segments']} data",
                ),
                ("Functions", str(ne["functions"])),
                ("VMTs", str(ne["vmt_tables"])),
            ]
        )

    if not functions:
        body = _render_template(
            "index_body.html.j2",
            heading="Function index",
            page_num=1,
            card_html=card_html,
            legend_html=legend_html,
            over_text=over_text,
            ne_cards_html=ne_cards_html,
            empty_note=_no_functions_note(reversed_dir),
            intro="",
            pager="",
            table="",
            pager_end="",
        )
        return [("index.html", _page("Function index", target, "index.html", body))]

    total = len(functions)
    total_pages = _total_pages(total)
    # The strings and imports pages open with a count; the index carried none,
    # so a single-page table gave a reader no idea how much of the target it
    # was showing.  A multi-page table reads the total off its pager.
    intro = _count_phrase(total, "reversed function", "reversed functions")
    pages: list[tuple[str, str]] = []
    for page_num in range(1, total_pages + 1):
        start = (page_num - 1) * _TABLE_PAGE_SIZE
        chunk = functions[start : start + _TABLE_PAGE_SIZE]
        table = _data_table(
            "Reversed functions",
            ["Name", "VA", "File", "Status", "Size", "CFLAGS", "Blocker"],
            _function_rows_html(chunk),
        )
        span = _page_va_span([int(fn["va"]) for fn in chunk])
        pager = _pager_nav("index", page_num, total_pages, total, "functions", span=span)
        pager_end = _pager_nav(
            "index",
            page_num,
            total_pages,
            total,
            "functions",
            label="Table pages, bottom",
            span=span,
            bottom=True,
        )
        if page_num == 1:
            heading = "Function index"
            title = "Function index"
        else:
            # Every page of the table prints the same coloured Status column,
            # so every page carries the key that explains it.  A reader who
            # opens index-pN.html from a link or the pager landed without one.
            heading = "Function index (continued)"
            title = f"Function index ({page_num}/{total_pages})"
        body = _render_template(
            "index_body.html.j2",
            heading=heading,
            page_num=page_num,
            card_html=card_html,
            legend_html=legend_html,
            over_text=over_text,
            ne_cards_html=ne_cards_html,
            empty_note=None,
            intro=intro,
            pager=pager,
            table=table,
            pager_end=pager_end,
        )
        pages.append((_paged_href("index", page_num), _page(title, target, "index.html", body)))
    return pages


def _note_page(
    title: str,
    target: str,
    active: str,
    heading: str,
    note: str | Markup,
    extra: str = "",
) -> str:
    """Render a full page whose body is a heading plus a single explanatory note."""
    body = _render_template(
        "note_body.html.j2",
        heading=heading,
        note=note,
        extra=extra,
    )
    return _page(title, target, active, body)


def _render_strings(cfg: ProjectConfig) -> list[tuple[str, str]]:
    """Render strings.html (+ ``strings-pN.html`` when the table exceeds one page)."""
    target = _target_name(cfg)
    binary = _target_binary(cfg)
    if binary is None:
        return [
            (
                "strings.html",
                _note_page(
                    "Strings",
                    target,
                    "strings.html",
                    "Strings",
                    "Target binary not found. Check the binary path in "
                    "rebrew-project.toml, then regenerate this report.",
                ),
            )
        ]
    try:
        info = load_binary(binary)
        strings = iter_strings(info, min_len=4)
    except OSError, ValueError, RuntimeError:
        return [
            (
                "strings.html",
                _note_page(
                    "Strings",
                    target,
                    "strings.html",
                    "Strings",
                    "Failed to parse the target binary. Confirm the file is a "
                    "supported PE/ELF/NE binary, then regenerate this report.",
                ),
            )
        ]
    if not strings:
        data_sections = [n for n in (".rdata", ".data", ".rodata") if n in info.sections]
        if not data_sections:
            note = (
                "The target binary has no data sections (.rdata/.data/.rodata); nothing to report."
            )
        else:
            note = f"No printable strings (min length 4) found in {', '.join(data_sections)}."
        return [("strings.html", _note_page("Strings", target, "strings.html", "Strings", note))]

    refs: dict[int, list[Xref]] | None
    try:
        refs = string_refs(info, strings)
    except OSError, ValueError, RuntimeError:
        refs = None

    total = len(strings)
    total_pages = _total_pages(total)
    pages: list[tuple[str, str]] = []
    # The count travels with the table the way the index and imports pages
    # carry theirs: a single-page table renders no pager, so without it the
    # reader has no idea how many strings the page is holding.
    intro = (
        f"{_count_phrase(total, 'string', 'strings')} extracted from the binary's "
        "data sections (min length 4)."
    )
    # The Refs and Referenced-from columns read n/a on every page of the
    # table, so the note that says why travels with the table, not with the
    # first page of it: a reader who opens strings-pN.html from a link or the
    # pager would otherwise meet the n/a with no explanation on the page.
    for page_num in range(1, total_pages + 1):
        start = (page_num - 1) * _TABLE_PAGE_SIZE
        chunk = strings[start : start + _TABLE_PAGE_SIZE]
        rows = "".join(
            _string_row(s, None if refs is None else refs.get(s.va) or []) for s in chunk
        )
        table = _data_table(
            "Strings from data sections",
            ["VA", "Section", "Kind", "Text", "Refs", "Referenced from"],
            rows,
        )
        span = _page_va_span([s.va for s in chunk])
        pager = _pager_nav("strings", page_num, total_pages, total, "strings", span=span)
        pager_end = _pager_nav(
            "strings",
            page_num,
            total_pages,
            total,
            "strings",
            label="Table pages, bottom",
            span=span,
            bottom=True,
        )
        heading = "Strings" if page_num == 1 else "Strings (continued)"
        title = "Strings" if page_num == 1 else f"Strings ({page_num}/{total_pages})"
        body = _render_template(
            "strings_body.html.j2",
            heading=heading,
            intro=intro,
            refs_failed=refs is None,
            pager=pager,
            table=table,
            pager_end=pager_end,
        )
        pages.append((_paged_href("strings", page_num), _page(title, target, "strings.html", body)))
    return pages


def _string_row(s: StringEntry, xrefs: list[Xref] | None) -> str:
    """Render one string table row with ref count and first referencing VAs.

    *xrefs* is None when the reference scan failed: both cells read ``n/a``
    rather than a count of 0.
    """
    text_short: str | None = None
    if len(s.text) > _STRING_CELL_CHARS:
        text_short = truncate_text(s.text, _STRING_CELL_CHARS) + "\u2026"
    refs_short: str | None = None
    if xrefs is None:
        count = refs_full = "n/a"
    elif len(xrefs) > _REFS_CELL_COUNT:
        count = str(len(xrefs))
        refs_full = ", ".join(f"0x{x.from_va:08x}" for x in xrefs)
        first = ", ".join(f"0x{x.from_va:08x}" for x in xrefs[:_REFS_CELL_COUNT])
        refs_short = f"{first} (+{len(xrefs) - _REFS_CELL_COUNT} more)"
    else:
        count = str(len(xrefs))
        # Spelled out rather than a dash: the Refs column already reads 0,
        # and an em dash beside it reads like the n/a the failed scan emits.
        refs_full = ", ".join(f"0x{x.from_va:08x}" for x in xrefs) or "none"
    return _render_template(
        "string_row.html.j2",
        va_hex=f"0x{s.va:08x}",
        section=s.section,
        kind=s.kind,
        text_short=text_short,
        text_full=s.text,
        count=count,
        refs_short=refs_short,
        refs_full=refs_full,
    )


def _paginate_rows(
    *,
    stem: str,
    noun: str,
    target: str,
    active: str,
    title: str,
    rows_html: list[str],
    caption: str,
    headers: list[str],
    first_heading: str,
    first_intro: str | Markup,
    continued_heading: str,
    extra_first: str = "",
    extra_all: str = "",
    row_vas: list[int] | None = None,
) -> list[tuple[str, str]]:
    """One HTML page per ``_TABLE_PAGE_SIZE`` chunk of *rows_html*.

    *extra_first* is appended on page 1 only.  *extra_all* is appended on
    every page (a link to a table that did not fit here).  *row_vas* is the
    address of each row in the same order as *rows_html*; when given, each
    pager names the address range it covers.
    """
    total = len(rows_html)
    if total == 0:
        return []
    total_pages = _total_pages(total)
    pages: list[tuple[str, str]] = []
    for page_num in range(1, total_pages + 1):
        start = (page_num - 1) * _TABLE_PAGE_SIZE
        chunk = "".join(rows_html[start : start + _TABLE_PAGE_SIZE])
        table = _data_table(caption, headers, chunk)
        span = _page_va_span(row_vas[start : start + _TABLE_PAGE_SIZE]) if row_vas else ""
        pager = _pager_nav(stem, page_num, total_pages, total, noun, span=span)
        pager_end = _pager_nav(
            stem,
            page_num,
            total_pages,
            total,
            noun,
            label="Table pages, bottom",
            span=span,
            bottom=True,
        )
        heading = first_heading if page_num == 1 else continued_heading
        page_title = title if page_num == 1 else f"{title} ({page_num}/{total_pages})"
        body = _render_template(
            "paginated_body.html.j2",
            heading=heading,
            intro=first_intro,
            pager=pager,
            table=table,
            pager_end=pager_end,
            extra_first=extra_first if page_num == 1 else "",
            extra_all=extra_all,
        )
        pages.append((_paged_href(stem, page_num), _page(page_title, target, active, body)))
    return pages


def _import_rows_html(imports: list[dict[str, Any]]) -> list[str]:
    """One ``<tr>`` per import, IAT order."""
    tmpl = _TEMPLATE_ENV.get_template("import_row.html.j2")
    return [
        tmpl.render(
            dll=str(rec["dll"]),
            name=str(rec["name"]),
            iat_hex=f"0x{int(rec['iat_va']):08x}",
        )
        for rec in sorted(imports, key=lambda r: int(r["iat_va"]))
    ]


def _stub_rows_html(stubs: dict[int, str]) -> list[str]:
    """One ``<tr>`` per jmp [IAT] stub, VA order."""
    tmpl = _TEMPLATE_ENV.get_template("stub_row.html.j2")
    return [tmpl.render(va_hex=f"0x{va:08x}", name=name) for va, name in sorted(stubs.items())]


def _imports_note(target: str, message: str) -> list[tuple[str, str]]:
    """Single imports.html explaining why the table is missing."""
    return [("imports.html", _note_page("Imports", target, "imports.html", "Imports", message))]


def _render_imports(cfg: ProjectConfig) -> list[tuple[str, str]]:
    """Render imports.html and overflow pages for the PE import table and stubs.

    Both tables use the index row budget.  Stubs stay on the first imports
    page when each table fits in that budget; a longer stub list moves to
    ``import-stubs.html`` so the entry page is one table, not two full dumps.
    """
    target = _target_name(cfg)
    binary = _target_binary(cfg)
    if binary is None:
        return _imports_note(
            target,
            "Target binary not found. Check the binary path in "
            "rebrew-project.toml, then regenerate this report.",
        )
    try:
        imports: list[dict[str, Any]] = parse_imports(binary)
    except OSError, ValueError:
        return _imports_note(
            target,
            "Failed to parse imports from the target binary. Confirm "
            "the file is a supported PE binary, then regenerate this report.",
        )
    stubs: dict[int, str]
    try:
        stubs = find_import_stubs(binary)
    except OSError, ValueError:
        stubs = {}
    if not imports and not stubs:
        return _imports_note(
            target,
            "No import table found in the target binary; nothing to report.",
        )

    import_rows = _import_rows_html(imports)
    stub_rows = _stub_rows_html(stubs)
    # Same order the two row builders use, so a pager's VA span lines up with
    # its rows.
    import_vas = [int(rec["iat_va"]) for rec in sorted(imports, key=lambda r: int(r["iat_va"]))]
    stub_vas = sorted(stubs)
    stubs_inline = (
        bool(stub_rows)
        and len(import_rows) <= _TABLE_PAGE_SIZE
        and len(stub_rows) <= _TABLE_PAGE_SIZE
    )
    extra_first = ""
    extra_all = ""
    stub_pages: list[tuple[str, str]] = []
    if stubs_inline:
        extra_first = "<h2>Import stubs (jmp [IAT])</h2>" + _data_table(
            "Import stubs (jmp [IAT])", ["VA", "API"], "".join(stub_rows)
        )
    elif stub_rows:
        extra_all = str(
            Markup(
                "<p><a href='import-stubs.html'>Import stubs (jmp [IAT])</a> are listed on their "
                "own pages ({}).</p>"
            ).format(_count_phrase(len(stub_rows), "stub", "stubs"))
        )
        stub_pages = _paginate_rows(
            stem="import-stubs",
            noun="import stubs",
            target=target,
            active="imports.html",
            title="Import stubs",
            rows_html=stub_rows,
            caption="Import stubs (jmp [IAT])",
            headers=["VA", "API"],
            first_heading="Import stubs (jmp [IAT])",
            first_intro=Markup("{}. <a href='imports.html'>Back to imported APIs</a>.").format(
                _count_phrase(len(stub_rows), "jmp [IAT] stub", "jmp [IAT] stubs")
            ),
            continued_heading="Import stubs (continued)",
            extra_all="<p><a href='imports.html'>Back to imported APIs</a>.</p>",
            row_vas=stub_vas,
        )

    if not import_rows:
        # ``extra_first`` carries the stub table the paginated path inlines
        # under a full imports table.  ``parse_imports`` and
        # ``find_import_stubs`` read the table with different parsers, so
        # ``stub_rows`` can be non-empty exactly when ``import_rows`` is not;
        # dropping it there loses the only list of imports the page had.
        page = _note_page(
            "Imports",
            target,
            "imports.html",
            "Imports",
            "No import table found in the target binary.",
            extra=extra_first + extra_all,
        )
        return [("imports.html", page), *stub_pages]

    pages = _paginate_rows(
        stem="imports",
        noun="imported APIs",
        target=target,
        active="imports.html",
        title="Imports",
        rows_html=import_rows,
        caption="Imported APIs",
        headers=["DLL", "Function", "IAT slot"],
        first_heading="Imports",
        first_intro=f"{_count_phrase(len(import_rows), 'imported API', 'imported APIs')}.",
        continued_heading="Imports (continued)",
        extra_first=extra_first,
        extra_all=extra_all,
        row_vas=import_vas,
    )
    return pages + stub_pages


def _mermaid_preview(mermaid: str, *, max_lines: int = 40, max_chars: int = 4000) -> str:
    """Opening lines of *mermaid*, capped so the preview cannot itself be the page."""
    kept: list[str] = []
    size = 0
    for line in mermaid.splitlines()[:max_lines]:
        if kept and size + len(line) + 1 > max_chars:
            break
        kept.append(line)
        size += len(line) + 1
    preview = "\n".join(kept)
    if preview != mermaid:
        preview += "\n\u2026"
    return preview


def _graph_body(mermaid: str, *, spilled: bool, nodes: int, edges: int, dispatch: int) -> str:
    """graph.html body.  Small sources stay inline; large ones link the file.

    ``<div role='region'>`` (not ``<pre>``) so the heading/description
    association and the scroll region are explicit: a screen reader maps
    ``<pre>`` to a generic text block, which swallows the label.
    """
    counts = ", ".join(
        (
            _count_phrase(nodes, "node", "nodes"),
            _count_phrase(edges, "direct edge", "direct edges"),
            _count_phrase(dispatch, "dispatch edge", "dispatch edges"),
        )
    )
    return _render_template(
        "graph_body.html.j2",
        spilled=spilled,
        counts=counts,
        nbytes=len(mermaid.encode("utf-8")),
        mermaid_text=_mermaid_preview(mermaid) if spilled else mermaid,
    )


def _render_graph(cfg: ProjectConfig, *, trusted: Any = None) -> tuple[str, str | None, str | None]:
    """Render graph.html, optional adjacency.txt, and optional spilled Mermaid.

    Returns ``(html_page, adjacency_text_or_none, mermaid_or_none)``.  The
    third value is the full Mermaid source when it is larger than
    ``_MERMAID_INLINE_MAX`` and was left out of the HTML.  Call-graph
    generation is best-effort: any failure (malformed source bindings,
    unreadable sources, rendering errors) degrades to a note inside the page
    rather than aborting the whole report.
    """
    target = _target_name(cfg)
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return (
            _note_page(
                "Call graph",
                target,
                "graph.html",
                "Call graph",
                "No reversed source directory configured. "
                "Set reversed_dir in rebrew-project.toml, then regenerate this report.",
            ),
            None,
            None,
        )
    try:
        nodes, edges, dispatch_edges = build_graph(Path(reversed_dir), cfg=cfg)
        if trusted is not None:
            from rebrew.catalog.loaders import scan_reversed_dir, trusted_function_list

            inventory = trusted_function_list(cfg)
            entries = trusted.bind(cfg, scan_reversed_dir(cfg.reversed_dir, cfg=cfg), inventory)
            sizes = {int(item["va"]): int(item["size"]) for item in inventory}
            allowed = {
                (entry.va, (cfg.reversed_dir / entry.filepath).resolve())
                for entry in entries
                if not entry.is_data
            }
            nodes = {
                key: node
                for key, node in nodes.items()
                if (node["va"], (cfg.reversed_dir / node["file"]).resolve()) in allowed
            }
            for node in nodes.values():
                va = node["va"]
                verdict = trusted.verdict(cfg.root, cfg.reversed_dir / node["file"], va)
                node["status"] = verdict.status if verdict else "UNKNOWN"
                node["size"] = sizes.get(va, 0) if va is not None else 0
        if not nodes:
            return (
                _note_page(
                    "Call graph",
                    target,
                    "graph.html",
                    "Call graph",
                    _no_functions_note(Path(reversed_dir)),
                ),
                None,
                None,
            )
        # Stub-only projects (e.g. an intake'd NE target) have no source
        # edges — augment with the binary call graph when the target binary
        # is available so graph.html shows the real call structure.
        if not edges:
            bin_path = getattr(cfg, "target_binary", None)
            if bin_path and Path(bin_path).exists():
                try:
                    from rebrew.depgraph import binary_call_edges
                    from rebrew.formats.binary_loader import load_binary

                    info = load_binary(bin_path)
                    if info.format == "ne":
                        ranges = _ne_ranges(info)
                        edges.extend(binary_call_edges(info, ranges))
                except Exception as exc:  # best-effort augmentation
                    logging.getLogger(__name__).debug("NE edge augmentation failed: %s", exc)
        if trusted is not None:
            edges = [(a, b) for a, b in edges if a in nodes and b in nodes]
            dispatch_edges = [(a, b) for a, b in dispatch_edges if a in nodes and b in nodes]
        mermaid = render_mermaid(nodes, edges, dispatch_edges)
        adjacency = _adjacency_list(nodes, edges, dispatch_edges)
    except Exception as exc:  # best-effort graph; the report must not crash
        if trusted is not None:
            raise
        logging.getLogger(__name__).warning(
            "Call graph generation failed for %s", target, exc_info=True
        )
        console.print(
            f"[yellow]report:[/yellow] call graph generation failed ({exc.__class__.__name__}: "
            f"{exc}) - writing a placeholder graph.html"
        )
        return (
            _note_page(
                "Call graph",
                target,
                "graph.html",
                "Call graph",
                "Call graph generation failed. The other pages of this report are complete.",
            ),
            None,
            None,
        )

    spilled = len(mermaid.encode("utf-8")) > _MERMAID_INLINE_MAX
    body = _graph_body(
        mermaid,
        spilled=spilled,
        nodes=len(nodes),
        edges=len(edges),
        dispatch=len(dispatch_edges),
    )
    return (
        _page("Call graph", target, "graph.html", body),
        adjacency,
        mermaid if spilled else None,
    )


def _ne_ranges(info: Any) -> list[tuple[int, int, str]]:
    """``(lo, hi, node-key)`` ranges for an NE target's functions.

    The key uses depgraph's node-key scheme (``va:0x…``) so the augmented edges
    link to the nodes ``build_graph`` produced; a bare ``fcn_…`` label rendered
    phantom nodes disconnected from the real ones.
    """
    from rebrew.formats.ne_loader import enumerate_ne_functions

    return [(f.va, f.va + f.size, f"va:0x{f.va:08x}") for f in enumerate_ne_functions(info)]


def _callees_by_source(edges: list[tuple[str, str]]) -> dict[str, list[str]]:
    """Map each source node to its sorted callee names."""
    by_source: dict[str, list[str]] = {}
    for source, callee in edges:
        by_source.setdefault(source, []).append(callee)
    for names in by_source.values():
        names.sort()
    return by_source


def _adjacency_list(
    nodes: dict[str, NodeInfo],
    edges: list[tuple[str, str]],
    dispatch_edges: list[tuple[str, str]],
) -> str:
    """Plain-text adjacency list over *nodes*: ``name [status] va -> callees``."""
    lines = [f"{len(nodes)} nodes, {len(edges)} direct edges, {len(dispatch_edges)} dispatch edges"]
    # The display label is the symbol, not the internal node key
    # (`va:0x…`/`sym:…`); render_mermaid/render_dot already do this.
    labels = {name: (info.get("symbol", "") or name) for name, info in nodes.items()}
    # Build callee sets once instead of scanning the full edge list per node.
    callees_by_src = _callees_by_source(edges)
    dispatch_by_src = _callees_by_source(dispatch_edges)
    for name in sorted(nodes):
        info = nodes[name]
        status = info.get("status", "")
        va = info.get("va")
        va_str = f"0x{va:08x}" if va is not None else "-"
        label = labels[name]
        callees = [labels.get(c, c) for c in callees_by_src.get(name, [])]
        dispatch = [labels.get(c, c) for c in dispatch_by_src.get(name, [])]
        if not callees and not dispatch:
            lines.append(f"{label} [{status}] {va_str}")
            continue
        parts = [f"{label} [{status}] {va_str} ->", ", ".join(callees)]
        if dispatch:
            parts.append(f"(dispatch: {', '.join(dispatch)})")
        lines.append(" ".join(parts))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(cfg: ProjectConfig, out: Path, *, trusted: Any = None) -> dict[str, Any]:
    """Generate the static HTML report site into *out*.

    Returns the machine-readable summary dict::

        {"out": str, "pages": [...], "summary": {totals...}}

    Every page is written even when its data source is missing or broken —
    such pages degrade to an explanatory note instead.  Oversized index,
    strings, and import tables spill into companion pages; a Mermaid source
    over ``_MERMAID_INLINE_MAX`` spills into ``callgraph.mmd``.  Each text
    asset also gets ``.gz`` / ``.zst`` sidecars when compression shrinks it.
    Owned files this run did not write are removed.
    """
    out.mkdir(parents=True, exist_ok=True)
    report = collect_status(cfg, trusted=trusted)
    functions = _collect_functions(cfg, trusted=trusted)
    target = _target_name(cfg)
    reversed_dir = getattr(cfg, "reversed_dir", None)

    graph_html, adjacency, spilled_mermaid = _render_graph(cfg, trusted=trusted)
    # Each page states what it carries that a reader may be refused (SiteDataKind),
    # read from its renderer: the function index lists names, addresses, files,
    # statuses, flags and blocker notes; the strings pages list each string's
    # referencing addresses; the import pages list the binary's import table; the
    # graph page, the adjacency list and the spilled Mermaid are the call graph.
    page_files: list[tuple[str, str, tuple[SiteDataKind, ...]]] = []
    page_files.extend(
        (name, content, _NO_WITHHELD)
        for name, content in _render_index(
            target,
            report,
            functions,
            ne=_ne_summary(cfg),
            reversed_dir=reversed_dir,
        )
    )
    page_files.extend(
        (name, content, ("cross_references",)) for name, content in _render_strings(cfg)
    )
    page_files.extend((name, content, _NO_WITHHELD) for name, content in _render_imports(cfg))
    page_files.append(("graph.html", graph_html, ("call_graph",)))
    declared: dict[str, tuple[SiteDataKind, ...]] = {}
    # The mark every page links, written once per site rather than inlined
    # into each document.  It is text, so the sidecars apply like any other
    # owned asset.
    written: list[tuple[str, str | bytes, tuple[SiteDataKind, ...]]] = [
        ("favicon.svg", FAVICON_SVG, _NO_WITHHELD),
        *page_files,
    ]
    if adjacency is not None:
        written.append(("adjacency.txt", adjacency, ("call_graph",)))
    if spilled_mermaid is not None:
        written.append(("callgraph.mmd", spilled_mermaid, ("call_graph",)))
    for name, content, kinds in written:
        _write_static(out / name, content, kinds, declared)
    _prune_stale_report_files(out, {name for name, _content, _kinds in written})
    undeclared = sorted(
        child.name
        for child in out.iterdir()
        if child.is_file()
        and _owned_report_name(child.name) is not None
        and child.name not in declared
    )
    if undeclared:
        raise RuntimeError(f"report files without declared kinds: {', '.join(undeclared)}")

    summary = {
        "total_functions": report.total_functions,
        "covered_functions": report.covered_functions,
        "coverage_pct": report.coverage_pct,
        "matched_pct": report.matched_pct,
        "byte_coverage_pct": report.byte_coverage_pct,
        "status_counts": report.status_counts,
    }
    # Primary nav pages stay first and stable for --json consumers; extras
    # (index-p2.html, …) follow in write order.
    primary_names = ["index.html", "strings.html", "imports.html", "graph.html"]
    extra = [n for n, _content, _kinds in page_files if n not in primary_names]
    return {
        "out": str(out),
        "pages": primary_names + extra,
        "summary": summary,
        "kinds": {name: list(kinds) for name, kinds in sorted(declared.items())},
    }


def generate_decomp_dev_report(
    cfg: ProjectConfig, out_path: Path, *, trusted: Any = None
) -> dict[str, Any]:
    """Write the objdiff-format ``report.json`` of :func:`decomp_dev_report` to *out_path*.

    Returns its summary with ``out``, the path written.
    """
    report_doc, summary = decomp_dev_report(cfg, trusted=trusted)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(out_path, json.dumps(report_doc, indent=2), encoding="utf-8")
    return {"out": str(out_path), **summary}


def decomp_dev_report(
    cfg: ProjectConfig, *, trusted: Any = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The objdiff-format report document for decomp.dev ingestion, and its summary.

    decomp.dev (the decomp-scene progress hub) polls a GitHub Actions
    artifact named ``<version>_report`` containing a ``report.json`` in the
    objdiff report format (``objdiff-core/protos/report.proto``, version 2,
    JSON-serialized).  This emits that file from rebrew's existing status
    data:

    - ``EXACT``/``RELOC`` functions count as fully matched
      (``fuzzy_match_percent`` 100) from the stored status and evidence;
    - ``NEAR_MATCHING`` and ``PROVEN`` functions (bytes differ) carry their
      cached ``match_percent`` when the verify cache has one, else 0;
    - everything else (STUB, unannotated registry functions) is 0.

    Use ``rebrew verify --text --raw-link`` to check linked placement.

    ``total_functions``/``total_code`` come from the SHARED progress model
    (``rebrew.status.collect_status`` — ghidra-functions ∪ annotated set and
    the binary's ``.text`` size), so progress is measured against the whole
    binary and matches what ``rebrew status`` reports.

    Returns the document and the machine-readable summary dict.
    """
    from rebrew.sections import get_text_section_size
    from rebrew.workspace.status import FUZZY_STATUSES, MATCHED_STATUSES

    sizes: dict[int, int] = {}
    # One walk of the reversed tree and one trusted bind serve the units below
    # and the shared progress model (collect_status).
    tree = scan_files(cfg.reversed_dir)
    inventory: list[dict[str, Any]] | None = None
    sources = list(iter_sources(cfg.reversed_dir, cfg, scanned=tree))
    target_module_name = target_module(cfg)
    if trusted is not None:
        from rebrew.catalog.loaders import (
            scan_reversed_dir,
            scan_source_bindings,
            trusted_function_list,
        )
        from rebrew.metadata.functions import load_metadata

        inventory = trusted_function_list(cfg)
        # The scan's per-source reads serve the units too: each source is read once.
        metadata_root = cfg.metadata_dir
        per_source = scan_source_bindings(
            cfg.reversed_dir,
            cfg,
            sources,
            metadata_root,
            load_metadata(metadata_root, deepcopy=False),
        )
        trusted.bind(
            cfg,
            scan_reversed_dir(cfg.reversed_dir, cfg=cfg, scanned=tree, source_bindings=per_source),
            inventory,
        )
        sizes = {int(item["va"]): int(item["size"]) for item in inventory}
        bound = [(path, annos) for path, annos in per_source if annos]
    else:
        bound = iter_source_bindings(
            sources,
            target=target_module_name,
            metadata_dir=cfg.metadata_dir,
            project_root=getattr(cfg, "root", None),
        )
    annos_by_file: list[tuple[str, list[Any]]] = []
    for path, annos in bound:
        # Relative to reversed_dir, like every other source-path computation in
        # this module: a bare basename made two `pool.c` under different
        # directories indistinguishable in report.json.
        if trusted is not None:
            from dataclasses import replace

            annos = [
                replace(a, status=(record.status if record else "UNKNOWN"), size=sizes[a.va])
                for a in annos
                if a.va in sizes
                for record in (trusted.verdict(cfg.root, path, a.va),)
            ]
        annos_by_file.append((rel_display_path(path, cfg.reversed_dir), annos))

    # Cached match_percent for NEAR_MATCHING (the fuzzy measure).  Verify-cache
    # keys are strings (JSON object keys); VAs here are ints, so normalize
    # both sides through int() instead of testing key types.
    cached_pct: dict[int, float] = {}
    try:
        from rebrew.verify_cache import cache_path_for, load_verify_cache

        cache = load_verify_cache(cache_path_for(cfg), cfg) if trusted is None else None
        if cache is not None:
            for key, entry in cache.entries.items():
                mp = entry.match_percent
                if mp is None:
                    continue
                try:
                    va_key = parse_int_literal(str(key))
                    pct = float(mp)
                except TypeError, ValueError:
                    continue
                # Corrupt cache entries once stored NaN; NaN * size poisons
                # the unit/project fuzzy totals (and sorts break on NaN).  A
                # percent above 100 is clamped too: it is a fraction of the
                # function's bytes, so it would report more matched code than
                # the unit has.
                if not math.isfinite(pct):
                    continue
                cached_pct[va_key] = max(0.0, min(100.0, pct))
    except (OSError, ValueError, TypeError) as exc:
        logging.getLogger(__name__).warning(
            "verify cache unavailable for fuzzy match percents: %s", exc
        )

    trusted_by_va = {r.va: r for r in trusted.records} if trusted is not None else {}

    def fuzzy_for(status: str, va: int) -> float:
        if status in MATCHED_STATUSES:
            return 100.0
        if trusted is not None and status == "NEAR_MATCHING":
            record = trusted_by_va.get(va)
            return 100.0 * record.match_count / record.size if record else 0.0
        if status in FUZZY_STATUSES:
            return cached_pct.get(va, 0.0)
        return 0.0

    matched_statuses = set(MATCHED_STATUSES)
    units: list[dict[str, Any]] = []
    fuzzy_code = 0.0
    for file_rel, annos in annos_by_file:
        items: list[dict[str, Any]] = []
        unit_code = 0
        unit_matched = 0
        unit_fuzzy = 0.0
        unit_fns = 0
        unit_matched_fns = 0
        for a in annos:
            if a.is_data:
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
                    "fuzzy_match_percent": floor_pct(fuzzy, 100, 2),
                    "address": va,
                }
            )
            unit_code += size
            unit_fuzzy += size * fuzzy / 100.0
            unit_fns += 1
            if a.status in matched_statuses:
                unit_matched += size
                unit_matched_fns += 1
        if not items:
            continue
        units.append(
            {
                "name": file_rel,
                "measures": {
                    "total_code": unit_code,
                    "matched_code": unit_matched,
                    "fuzzy_match_percent": floor_pct(unit_fuzzy, unit_code, 2)
                    if unit_code
                    else 0.0,
                    "total_functions": unit_fns,
                    # By status, like matched_code: a NEAR_MATCHING percent
                    # cached at one decimal rounds 99.96 up to 100.0.
                    "matched_functions": unit_matched_fns,
                },
                "functions": items,
            }
        )
        fuzzy_code += unit_fuzzy

    # Top-level measures come from the SHARED progress model
    # (rebrew.status.collect_status) so the decomp.dev report, `rebrew
    # status`, and the HTML report all agree on the same numbers — the
    # status counts are verify-overlaid (a verify cache that demoted a
    # metadata EXACT is reflected here) and the denominator is the
    # ghidra-functions ∪ annotated set.
    status = collect_status(cfg, tree=tree, trusted=trusted, bound_inventory=inventory)
    registry_total = status.total_functions or 0
    matched_functions = status.matched_functions
    # Trusted coverage keeps library code apart: matched_code is the original
    # code's matched bytes, beside the library account (trusted_library).
    matched_code = status.matched_bytes - status.library_verified_bytes
    text_size = status.total_text_bytes or get_text_section_size(cfg.target_binary) or 0
    trusted_library = (
        {
            "original_code": matched_code + status.unmatched_bytes,
            "library_functions": status.library_identified,
            "library_code": status.library_bytes,
            "library_verified_functions": status.library_verified,
            "library_verified_code": status.library_verified_bytes,
        }
        if trusted is not None
        else {}
    )

    # The fuzzy numerator sums each annotation's declared SIZE; a size running
    # past .text, or two annotations over one function, adds up past the whole
    # binary and the consumer renders a progress bar above 100%. The HTML
    # report already special-cases that overflow; cap it so both agree.
    if text_size:
        fuzzy_code = min(fuzzy_code, float(text_size))

    # Data measures: rebrew places data rather than "matching" it, so report
    # the totals honestly and leave matched/complete data at 0.
    data_size = 0
    try:
        from rebrew.formats.binary_loader import load_binary

        info = load_binary(cfg.target_binary)
        for name in (".data", ".rdata", ".bss"):
            sec = info.sections.get(name)
            if sec is not None:
                data_size += int(getattr(sec, "size", 0) or 0)
    except (ImportError, OSError, KeyError, ValueError, RuntimeError) as exc:
        logging.getLogger(__name__).debug("data section size unavailable: %s", exc)

    measures = {
        "fuzzy_match_percent": floor_pct(fuzzy_code, text_size, 2),
        "total_code": text_size,
        "matched_code": matched_code,
        "matched_code_percent": floor_pct(matched_code, text_size, 2),
        "total_data": data_size,
        "matched_data": 0,
        "matched_data_percent": 0.0,
        "total_functions": registry_total,
        "matched_functions": matched_functions,
        "matched_functions_percent": floor_pct(matched_functions, registry_total, 2),
        # complete_* is the code account `rebrew status` prints: matched
        # functions, identified libraries, and alignment padding.
        # matched_code is that account without the padding.
        "complete_code": status.accounted_text_bytes,
        "complete_code_percent": status.byte_coverage_pct if text_size else 0.0,
        "complete_data": 0,
        "complete_data_percent": 0.0,
        "total_units": len(units),
        "complete_units": sum(
            1
            for u in units
            if u["measures"]["matched_functions"] == u["measures"]["total_functions"]
        ),
        **trusted_library,
    }

    report_doc = {"version": 2, "measures": measures, "units": units}
    return report_doc, {
        "total_functions": registry_total,
        "matched_functions": matched_functions,
        "total_code": text_size,
        "matched_code": matched_code,
        "fuzzy_match_percent": measures["fuzzy_match_percent"],
        "units": len(units),
        **trusted_library,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew coverage report  # Write site to <output_dir>/report\n\n"
    "  rebrew coverage report --output site  # Write site to ./site\n\n"
    "  rebrew coverage report --decomp-dev report.json  # Write an objdiff-format\n"
    "                                            report.json for decomp.dev\n\n"
    "  rebrew coverage report --json  # Machine-readable summary\n\n"
    "[dim]Generates a self-contained static HTML site (function index, strings, "
    "imports, call graph) with all styling inlined, no external assets.  "
    "Long tables paginate; a call graph over 32 KB of Mermaid moves to "
    "callgraph.mmd.  `--decomp-dev` instead emits the objdiff report v2 JSON "
    "the decomp.dev progress hub ingests from a GitHub Actions artifact.[/dim]"
)

app = typer.Typer(
    help="Generate a static HTML documentation site for a decomp project.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output directory (default: <output_dir>/report)"
    ),
    decomp_dev: Path | None = typer.Option(
        None,
        "--decomp-dev",
        help="Write an objdiff-format report.json for decomp.dev (path to report.json)",
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

    if output is None:
        output_dir = getattr(cfg, "output_dir", None) or Path("output")
        output = Path(output_dir) / "report"

    result = generate_report(cfg, output)

    if json_output:
        json_print(result)
        return

    console.print(f"[bold green]Report written to:[/bold green] {output}")
    console.print("  [dim]Open index.html to start.[/dim]")
    for page in result["pages"]:
        console.print(f"  [dim]{page}[/dim]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
