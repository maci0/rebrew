"""data.py – Global data scanner for rebrew.

Scans reversed .c files for ``// GLOBAL: MODULE 0xVA`` and ``// DATA: MODULE 0xVA``
annotations (reccmp standard) and ``extern`` data declarations, cross-references
them with the binary's ``.data``/``.rdata``/``.bss`` sections, detects type conflicts
across files, and outputs a catalog of known globals.

Also provides:
- Dispatch table / vtable detection via ``--dispatch``
- BSS layout verification via ``--bss``
- Header generation via ``--gen-header`` (writes ``rebrew_globals.h``)

"""

import logging
import re
import struct
import tomllib
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.config import ProjectConfig
from rebrew.utils import atomic_write_text, read_source_text

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# reccmp-compatible GLOBAL annotation:  // GLOBAL: SERVER 0x10031ae8
_GLOBAL_RE = re.compile(r"(?://|/\*)\s*GLOBAL:\s*(?P<module>[A-Z0-9_]+)\s+(?P<va>0x[0-9a-fA-F]+)")

# extern data declarations are parsed by c_parser.find_extern_variables()
# via tree-sitter AST walking — see scan_globals().

_ARRAY_SIZE_RE = re.compile(r"\[(\d+)\]")
_ARRAY_STRIP_RE = re.compile(r"\[.*\]")
_DECL_IDENT_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[.*\])?\s*;")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class GlobalEntry:
    """A single discovered global variable."""

    name: str
    va: int = 0  # 0 = no annotation
    type_str: str = ""
    section: str = ""  # .data, .rdata, .bss, or ""
    declared_in: list[str] = field(default_factory=list)
    annotated: bool = False  # True if has a // GLOBAL: annotation

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        d: dict[str, Any] = {"name": self.name, "type": self.type_str}
        if self.va:
            d["va"] = f"0x{self.va:08x}"
        if self.section:
            d["section"] = self.section
        d["declared_in"] = self.declared_in
        d["annotated"] = self.annotated
        return d


@dataclass
class ScanResult:
    """Aggregated global scan results."""

    globals: dict[str, GlobalEntry] = field(default_factory=dict)
    data_annotations: list[dict[str, Any]] = field(default_factory=list)  # // DATA: entries
    type_conflicts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize scan results to a plain dict for JSON output."""
        return {
            "globals": {k: v.to_dict() for k, v in sorted(self.globals.items())},
            "data_annotations": self.data_annotations,
            "type_conflicts": self.type_conflicts,
            "summary": {
                "total": len(self.globals),
                "annotated": sum(1 for g in self.globals.values() if g.annotated),
                "unannotated": sum(1 for g in self.globals.values() if not g.annotated),
                "data_entries": len(self.data_annotations),
                "conflicts": len(self.type_conflicts),
            },
        }


@dataclass
class DispatchEntry:
    """A single entry in a dispatch table."""

    target_va: int
    name: str = ""  # resolved function name, or ""
    status: str = ""  # EXACT / RELOC / NEAR_MATCHING / STUB / UNKNOWN / ""


@dataclass
class DispatchTable:
    """A dispatch table (contiguous function pointer array) in a data section."""

    va: int
    section: str
    entries: list[DispatchEntry] = field(default_factory=list)

    @property
    def num_entries(self) -> int:
        """Total number of entries in this dispatch table."""
        return len(self.entries)

    @property
    def resolved(self) -> int:
        """Number of entries with a resolved function name."""
        return sum(1 for e in self.entries if e.name)

    @property
    def coverage(self) -> float:
        """Fraction of entries that have been resolved (0.0–1.0)."""
        return self.resolved / self.num_entries if self.num_entries else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "va": f"0x{self.va:08x}",
            "section": self.section,
            "num_entries": self.num_entries,
            "resolved": self.resolved,
            "coverage": f"{self.coverage:.0%}",
            "entries": [
                {
                    "target_va": f"0x{e.target_va:08x}",
                    "name": e.name,
                    "status": e.status,
                }
                for e in self.entries
            ],
        }


# ---------------------------------------------------------------------------
# Section classification
# ---------------------------------------------------------------------------


def classify_section(va: int, sections: dict[str, dict[str, Any]]) -> str:
    """Determine which binary section a VA belongs to."""
    for sec_name, sec in sections.items():
        sec_va = sec.get("va", 0)
        sec_size = sec.get("size", 0)
        if sec_va <= va < sec_va + sec_size:
            return sec_name
    return ""


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_globals(src_dir: Path, cfg: ProjectConfig | None = None) -> ScanResult:
    """Scan reversed source files for global declarations.

    Collects:
    1. ``// GLOBAL: MODULE 0xVA`` reccmp annotations (+ next line for declaration)
    2. ``extern <type> <name>;`` data globals (via tree-sitter, filtering functions)

    Returns a ScanResult with all discovered globals and type conflicts.
    Mutates ``entry.type_str`` by appending ``" ⚠ CONFLICT"`` when conflicting
    type declarations are found across files.
    """
    from rebrew.c_parser import find_extern_variables
    from rebrew.cli import iter_sources, rel_display_path

    result = ScanResult()
    # Track all type declarations per name for conflict detection
    type_by_name: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    if not src_dir.exists():
        return result

    for cfile in iter_sources(src_dir, cfg):
        try:
            # Tolerant read: a legacy-encoded source must not have its
            # non-ASCII bytes silently deleted (errors="ignore" used to drop
            # string literals/comments, corrupting GLOBAL:/DATA: scans).
            text, _ = read_source_text(cfile)
        except OSError:
            continue

        lines = text.splitlines()
        fname = rel_display_path(cfile, src_dir)

        # Pre-compute extern variables from tree-sitter (used for unannotated scan)
        extern_vars = {v.name: v for v in find_extern_variables(text)}

        # Track which extern names are already handled via GLOBAL annotation
        annotated_names: set[str] = set()

        for i, line in enumerate(lines):
            # 1. Check for // GLOBAL: annotation
            gm = _GLOBAL_RE.search(line)
            if gm:
                va = int(gm.group("va"), 16)
                # Next line should be the declaration
                decl = lines[i + 1].strip() if i + 1 < len(lines) else ""
                if not decl:
                    warnings.warn(
                        f"{fname}:{i + 1}: // GLOBAL: annotation at 0x{va:08x} "
                        f"has no declaration on the following line",
                        stacklevel=2,
                    )
                name = "unknown"
                type_str = ""

                # Try to parse declaration via tree-sitter (single line)
                decl_vars = find_extern_variables(decl)
                if decl_vars:
                    ev = decl_vars[0]
                    name = ev.name
                    type_str = ev.type_str
                else:
                    # Fallback: try to grab the last identifier before ;
                    # (handles non-extern declarations after GLOBAL annotations)
                    id_match = _DECL_IDENT_RE.search(decl)
                    if id_match:
                        name = id_match.group(1)

                annotated_names.add(name)

                entry = result.globals.get(name)
                if entry is None:
                    entry = GlobalEntry(name=name, va=va, type_str=type_str, annotated=True)
                    result.globals[name] = entry
                else:
                    # Update VA if not set
                    if not entry.va:
                        entry.va = va
                    entry.annotated = True

                if fname not in entry.declared_in:
                    entry.declared_in.append(fname)

                if type_str:
                    type_by_name[name][type_str].append(fname)

                continue

        # 2. Add unannotated extern variables from tree-sitter
        for ev_name, ev in extern_vars.items():
            if ev_name in annotated_names:
                continue  # Already handled via GLOBAL annotation

            entry = result.globals.get(ev_name)
            if entry is None:
                entry = GlobalEntry(name=ev_name, type_str=ev.type_str)
                result.globals[ev_name] = entry

            if fname not in entry.declared_in:
                entry.declared_in.append(fname)

            if ev.type_str:
                type_by_name[ev_name][ev.type_str].append(fname)

    # Detect type conflicts: same name, different type strings
    for name, types in type_by_name.items():
        if len(types) > 1:
            conflict = {
                "name": name,
                "types": dict(types),
            }
            result.type_conflicts.append(conflict)
            if name in result.globals:
                result.globals[name].type_str += " ⚠ CONFLICT"

    return result


def scan_data_annotations(src_dir: Path, cfg: ProjectConfig | None = None) -> list[dict[str, Any]]:
    """Scan for ``// DATA: MODULE 0xVA`` annotations in source files.

    These mark standalone global data objects for tracking in the catalog.
    SIZE/SECTION/NOTE are overlaid from ``rebrew-data.toml`` metadata if present.
    Returns a list of dicts with: va, name, size, section, note, filepath.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.cli import iter_sources, rel_display_path, target_marker
    from rebrew.data_metadata import merge_into_data_annotation

    entries: list[dict[str, Any]] = []
    if not src_dir.exists():
        return entries

    for cfile in iter_sources(src_dir, cfg):
        rel_name = rel_display_path(cfile, src_dir)
        for ann in parse_c_file_multi(
            cfile, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir if cfg else None
        ):
            if ann.marker_type == "DATA":
                # Metadata root is cfg.metadata_dir — passing cfile.parent
                # silently no-ops the overlay when the metadata dir differs
                # from the source dir (the sibling call at line ~1000 uses
                # cfg.metadata_dir correctly).
                merge_into_data_annotation(ann, cfg.metadata_dir if cfg else cfile.parent)
                entries.append(
                    {
                        "va": f"0x{ann.va:08x}",
                        "name": ann.name or cfile.stem,
                        "size": ann.size,
                        "section": ann.section,
                        "note": ann.note,
                        "filepath": ann.filepath or rel_name,
                    }
                )
    return entries


def enrich_with_sections(scan: ScanResult, sections: dict[str, dict[str, Any]]) -> None:
    """Classify each annotated global into its binary section."""
    for entry in scan.globals.values():
        if entry.va:
            entry.section = classify_section(entry.va, sections)


# ---------------------------------------------------------------------------
# Dispatch table detection
# ---------------------------------------------------------------------------


def _build_dispatch_known_functions(cfg: ProjectConfig, src_dir: Path) -> dict[int, dict[str, str]]:
    """Map VA -> {"name", "status"} for dispatch-table naming.

    Source-file annotations take precedence; the function list / Ghidra
    structure registry then fills in targets no source file covers (e.g.
    FLIRT-identified CRT functions).  A "0% resolved" table is misleading
    when the catalog already knows the names.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.cli import iter_sources, rel_display_path, target_marker

    known_functions: dict[int, dict[str, str]] = {}
    for cfile in iter_sources(src_dir, cfg):
        for entry in parse_c_file_multi(
            cfile, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
        ):
            if entry.va:
                known_functions[entry.va] = {
                    "name": entry.name or rel_display_path(cfile, src_dir),
                    "status": entry.status,
                }

    try:
        from rebrew.catalog.loaders import parse_function_list
        from rebrew.catalog.registry import build_function_registry
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        funcs = parse_function_list(cfg.function_list)
        registry = build_function_registry(
            funcs, cfg, src_dir / FUNCTION_STRUCTURE_JSON, cfg.target_binary
        )
        for va, reg_entry in registry.items():
            name = reg_entry.get("list_name") or reg_entry.get("ghidra_name")
            if name and va not in known_functions:
                known_functions[va] = {"name": name, "status": ""}
    except (OSError, ValueError, KeyError, AttributeError) as exc:
        # Registry is best-effort enrichment (function names from the catalog
        # list); a failure must be visible so a name-less data scan is not
        # mistaken for a complete one.
        logging.warning("Function registry unavailable — names/dispatch context omitted: %s", exc)
    return known_functions


def find_dispatch_tables(
    binary_data: bytes,
    sections: dict[str, dict[str, Any]],
    known_functions: dict[int, dict[str, str]],
    ptr_size: int = 4,
    min_entries: int = 3,
    max_stride: int | None = None,
    info: Any = None,
) -> list[DispatchTable]:
    """Detect dispatch tables / vtables in data sections.

    Scans data sections for contiguous pointer-sized entries that all point
    into code sections.  Groups consecutive entries into tables.

    For 16-bit NE binaries (*info* provided, ``format == "ne"``), the code
    sections are the code segments (probe-classified) and the data sections
    the rest; a far pointer ``seg:off`` stored little-endian as 4 bytes
    decodes to the synthetic flat VA ``(seg << 16) | off`` — exactly the
    format the NE loader assigns, so the pointer-into-code check works
    unchanged.  This finds Borland Delphi VMTs (arrays of far pointers to
    methods).

    Args:
        binary_data: Raw binary file bytes.
        sections: Section dict from binary_loader ({name: {va, size, file_offset, raw_size}}).
        known_functions: Map of VA -> {"name": str, "status": str} for reversed funcs.
        ptr_size: Pointer size in bytes (4 for 32-bit PE and 16-bit far pointers).
        min_entries: Minimum entries to qualify as a dispatch table.
        max_stride: Maximum byte distance between consecutive pointer-sized slots to still
            be considered part of the same table.  Defaults to ``ptr_size`` (contiguous).
        info: Optional BinaryInfo; enables NE-aware section selection.

    """
    stride = max_stride if max_stride is not None else ptr_size

    if info is not None and info.format == "ne":
        ne_segs = info.ne_segments
        code_names = [f"SEG{s.index}" for s in ne_segs if s.is_code]
        data_names = [f"SEG{s.index}" for s in ne_segs if not s.is_code]
        code_ranges = [
            (sections[n]["va"], sections[n]["va"] + sections[n]["size"])
            for n in code_names
            if n in sections
        ]
        data_sections = [(n, sections[n]) for n in data_names if n in sections]
    else:
        text_sec = sections.get(".text")
        if not text_sec:
            return []
        code_ranges = [(text_sec["va"], text_sec["va"] + text_sec["size"])]
        data_sections = [
            (name, sec) for name, sec in sections.items() if name in (".data", ".rdata")
        ]

    fmt = "<I" if ptr_size == 4 else "<Q"
    tables: list[DispatchTable] = []

    for sec_name, sec in data_sections:
        sec_offset = sec.get("file_offset", 0)
        sec_raw_size = sec.get("raw_size", sec.get("size", 0))
        sec_va = sec["va"]

        # Borland NE data segments carry the 2-byte [index\x00] marker
        # before their content — the VMT far pointers start after it.  MSVC
        # 16-bit NE segments (e.g. the 1991 SkiFree) have no marker, so the
        # skip is applied only when the marker is actually present.
        if info is not None and info.format == "ne":
            from rebrew.ne_loader import has_borland_marker

            seg_index = int(sec_name[3:]) if sec_name.startswith("SEG") else 0
            if has_borland_marker(binary_data, sec_offset, seg_index):
                sec_offset += 2
                sec_raw_size = max(0, sec_raw_size - 2)
                sec_va += 2

        if sec_offset + sec_raw_size > len(binary_data):
            continue

        sec_bytes = binary_data[sec_offset : sec_offset + sec_raw_size]

        # Walk every pointer-sized slot.  *stride* bounds the maximum allowed
        # gap between consecutive entries of one table — it must not be the
        # scan step: advancing by `stride` on a miss skipped past valid
        # pointers (0/8/16 with garbage at 4/12 were never visited).
        current_entries: list[DispatchEntry] = []
        current_start_va = 0
        last_ptr_i: int | None = None

        def _flush_run(sec_name: str = sec_name) -> None:
            nonlocal current_entries, current_start_va, last_ptr_i
            if len(current_entries) >= min_entries:
                tables.append(
                    DispatchTable(
                        va=current_start_va,
                        section=sec_name,
                        entries=list(current_entries),
                    )
                )
            current_entries = []
            last_ptr_i = None
            current_start_va = 0

        i = 0
        while i + ptr_size <= len(sec_bytes):
            val = struct.unpack_from(fmt, sec_bytes, i)[0]
            entry_va = sec_va + i

            if any(lo <= val < hi for lo, hi in code_ranges):
                # This looks like a function pointer into a code section
                gap = (i - last_ptr_i) if last_ptr_i is not None else 0
                if current_entries and gap > stride:
                    # Gap exceeds the stride — the table ended; start a new run.
                    _flush_run()
                if not current_entries:
                    current_start_va = entry_va

                func_info = known_functions.get(val, {})
                current_entries.append(
                    DispatchEntry(
                        target_va=val,
                        name=func_info.get("name", ""),
                        status=func_info.get("status", ""),
                    )
                )
                last_ptr_i = i
            # else: not a text pointer — do NOT flush.  Non-pointer slots
            # within stride of the last pointer are tolerated (sparse tables);
            # the next pointer's gap check decides whether the run continues.
            i += ptr_size  # always advance by ptr_size; stride only bounds gaps

        # Flush trailing run
        _flush_run()

    tables.sort(key=lambda t: t.va)
    return tables


# ---------------------------------------------------------------------------
# BSS layout verification
# ---------------------------------------------------------------------------


@dataclass
class BssEntry:
    """A known global in the .bss section."""

    name: str
    va: int
    size_hint: int = 0  # from type heuristic
    source_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "name": self.name,
            "va": f"0x{self.va:08x}",
            "size_hint": self.size_hint,
            "source_file": self.source_file,
        }


@dataclass
class BssGap:
    """A gap between known BSS globals — likely an undeclared variable."""

    offset: int
    size: int
    before: str  # name of global before the gap
    after: str  # name of global after the gap

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "offset": f"0x{self.offset:08x}",
            "size": self.size,
            "between": [self.before, self.after],
        }


@dataclass
class BssReport:
    """BSS layout verification report."""

    bss_va: int = 0
    bss_size: int = 0
    known_entries: list[BssEntry] = field(default_factory=list)
    gaps: list[BssGap] = field(default_factory=list)
    coverage_bytes: int = 0

    @property
    def coverage_pct(self) -> float:
        """BSS coverage as a percentage."""
        return self.coverage_bytes / self.bss_size * 100 if self.bss_size else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "bss_va": f"0x{self.bss_va:08x}",
            "bss_size": self.bss_size,
            "known_entries": [e.to_dict() for e in self.known_entries],
            "gaps": [g.to_dict() for g in self.gaps],
            "coverage_bytes": self.coverage_bytes,
            "coverage_pct": f"{self.coverage_pct:.1f}%",
            "summary": {
                "total_globals": len(self.known_entries),
                "gaps": len(self.gaps),
                "total_gap_bytes": sum(g.size for g in self.gaps),
            },
        }


# Common C type sizes for size estimation
_TYPE_SIZES: dict[str, int] = {
    "char": 1,
    "unsigned char": 1,
    "signed char": 1,
    "BYTE": 1,
    "BOOL": 1,
    "short": 2,
    "unsigned short": 2,
    "signed short": 2,
    "WORD": 2,
    "int": 4,
    "unsigned int": 4,
    "signed int": 4,
    "long": 4,
    "unsigned long": 4,
    "DWORD": 4,
    "LONG": 4,
    "ULONG": 4,
    "float": 4,
    "FLOAT": 4,
    "double": 8,
    "DOUBLE": 8,
    "__int64": 8,
    "LONGLONG": 8,
}


def _estimate_type_size(type_str: str) -> int:
    """Estimate the size of a C type from its name."""
    base = type_str.rstrip("*").strip()
    # Strip array suffix
    arr_match = _ARRAY_SIZE_RE.search(base)
    elem_count = int(arr_match.group(1)) if arr_match else 1
    base = _ARRAY_STRIP_RE.sub("", base).strip()

    if "*" in type_str:
        return 4 * elem_count  # 32-bit pointer

    size = _TYPE_SIZES.get(base, 4)  # default to 4 (int)
    return size * elem_count


def verify_bss_layout(
    scan: ScanResult,
    sections: dict[str, dict[str, Any]],
) -> BssReport:
    """Verify BSS layout by checking globals placement and detecting gaps.

    Collects all globals annotated with a .bss VA, sorts them by address,
    and identifies gaps between consecutive entries that may indicate
    missing extern declarations.
    """
    bss = sections.get(".bss", {})
    bss_va = bss.get("va", 0)
    bss_size = bss.get("size", 0)

    report = BssReport(bss_va=bss_va, bss_size=bss_size)
    if not bss_va or not bss_size:
        return report

    bss_end = bss_va + bss_size

    # Collect BSS globals (those with VAs in the .bss range)
    bss_entries: list[BssEntry] = []
    for entry in scan.globals.values():
        if entry.va and bss_va <= entry.va < bss_end:
            size_hint = _estimate_type_size(entry.type_str) if entry.type_str else 4
            bss_entries.append(
                BssEntry(
                    name=entry.name,
                    va=entry.va,
                    size_hint=size_hint,
                    source_file=entry.declared_in[0] if entry.declared_in else "",
                )
            )

    bss_entries.sort(key=lambda e: e.va)
    report.known_entries = bss_entries

    if not bss_entries:
        return report

    # Detect gaps between consecutive entries
    # First gap: from bss_va to first entry
    if bss_entries[0].va > bss_va:
        gap_size = bss_entries[0].va - bss_va
        if gap_size >= 4:  # ignore alignment padding < 4
            report.gaps.append(
                BssGap(
                    offset=bss_va,
                    size=gap_size,
                    before="<bss_start>",
                    after=bss_entries[0].name,
                )
            )

    for i in range(len(bss_entries) - 1):
        curr = bss_entries[i]
        nxt = bss_entries[i + 1]
        expected_end = curr.va + curr.size_hint
        if nxt.va > expected_end:
            gap_size = nxt.va - expected_end
            if gap_size >= 4:
                report.gaps.append(
                    BssGap(
                        offset=expected_end,
                        size=gap_size,
                        before=curr.name,
                        after=nxt.name,
                    )
                )

    # Calculate coverage
    report.coverage_bytes = min(sum(e.size_hint for e in bss_entries), bss_size)

    return report


def _render_dispatch(console: Console, tables: list[DispatchTable]) -> None:
    """Print a Rich table of detected dispatch tables."""
    if not tables:
        console.print("  [dim]No dispatch tables detected.[/]")
        return

    total_entries = sum(t.num_entries for t in tables)
    total_resolved = sum(t.resolved for t in tables)
    coverage_str = f"({total_resolved / total_entries:.0%})" if total_entries else ""
    summary_body = (
        f"[bold]{len(tables)}[/] dispatch tables, "
        f"[bold]{total_entries}[/] total entries, "
        f"[bold]{total_resolved}[/] resolved {coverage_str}"
    )
    console.print(Panel(summary_body, title="Dispatch Tables"))

    for tbl in tables:
        t = Table(
            title=f"0x{tbl.va:08x} ({tbl.section}) — {tbl.num_entries} entries, {tbl.coverage:.0%} resolved",
            show_lines=False,
        )
        t.add_column("#", style="dim", width=4)
        t.add_column("Target VA", width=12)
        t.add_column("Name", min_width=30)
        t.add_column("Status", width=10)

        for idx, entry in enumerate(tbl.entries):
            status_color = {
                "EXACT": "green",
                "RELOC": "blue",
                "NEAR_MATCHING": "yellow",
                "STUB": "red",
            }.get(entry.status, "dim")

            name_str = entry.name or "[dim]???[/]"
            status_str = (
                f"[{status_color}]{entry.status}[/{status_color}]" if entry.status else "[dim]—[/]"
            )

            t.add_row(
                str(idx),
                f"0x{entry.target_va:08x}",
                name_str,
                status_str,
            )
        console.print(t)
        console.print()


def _generate_bss_fix(
    report: BssReport,
    src_dir: Path,
    origin: str,
    *,
    metadata_dir: Path | None = None,
    dry_run: bool = False,
) -> None:
    """Generate a bss_padding.c file with dummy arrays for all detected BSS gaps.

    SIZE, SECTION, and NOTE are written to ``rebrew-data.toml`` metadata, not inline.
    With *dry_run*, prints what would be written without touching the disk.

    *src_dir* is where ``bss_padding.c`` is written (``cfg.reversed_dir``);
    *metadata_dir* is the ``rebrew-data.toml`` root (``cfg.metadata_dir`` —
    the reversed_dir's *parent*).  These differ, and routing the metadata
    writes to src_dir orphans them (reads use metadata_dir everywhere).

    Idempotent on re-run: the generated file's OWN ``// DATA:`` annotations
    close the gaps they fill, so a second run's gap scan reports fewer gaps —
    regenerating from scratch would DELETE the arrays written by the first
    run while the data metadata still claims coverage (idempotency-review
    F4).  The existing auto-generated declarations are merged with the new
    gaps instead, and the file is written BEFORE its metadata so a crash
    between the two can never leave metadata claiming coverage the source
    does not declare.
    """
    from rebrew.data_metadata import set_data_field

    meta_dir = metadata_dir if metadata_dir is not None else src_dir
    out_file = src_dir / "bss_padding.c"

    # Existing auto-generated declarations (offset -> size), preserved across
    # re-runs — see docstring.  Only the auto-generated file is merged; a
    # user-created bss_padding.c (different header) is left alone.
    existing_decls: dict[int, int] = {}
    if out_file.exists():
        text = out_file.read_text(encoding="utf-8")
        if text.startswith("/* Auto-generated by rebrew data --fix-bss */"):
            for line in text.splitlines():
                m = re.match(r"// DATA: \S+ 0x([0-9a-fA-F]{8})", line)
                if m:
                    existing_decls[int(m.group(1), 16)] = 0
            # char gap_XXXXXXXX[N]; — recover the declared size
            for m in re.finditer(r"char gap_([0-9a-fA-F]{8})\[(\d+)\];", text):
                existing_decls[int(m.group(1), 16)] = int(m.group(2))

    if not report.gaps and not existing_decls:
        if report.known_entries:
            console.print("No BSS gaps detected. Layout is perfect!")
        else:
            console.print(
                "[yellow]No annotated BSS globals — nothing to verify. "
                "Add // GLOBAL: annotations (or extern declarations) for "
                ".bss globals to check the layout.[/yellow]"
            )
        return

    # New gaps = detected gaps not already declared by the auto-generated
    # file.  Already-declared offsets keep their existing arrays untouched.
    new_gaps = [g for g in report.gaps if g.offset not in existing_decls]

    lines = [
        "/* Auto-generated by rebrew data --fix-bss */",
        "/* SIZE/SECTION/NOTE metadata is in rebrew-data.toml */\n",
    ]
    # Preserve existing declarations first (stable ordering by offset).
    for offset in sorted(existing_decls):
        size = existing_decls[offset]
        lines.append(f"// DATA: {origin} 0x{offset:08x}")
        lines.append(f"char gap_{offset:08x}[{size}];\n")
    # Then the newly detected gaps.
    for gap in sorted(new_gaps, key=lambda g: g.offset):
        lines.append(f"// DATA: {origin} 0x{gap.offset:08x}")
        lines.append(f"char gap_{gap.offset:08x}[{gap.size}];\n")

    if dry_run:
        console.print(
            f"[dim]Dry run:[/dim] would write {out_file.name} with "
            f"{len(existing_decls)} existing + {len(new_gaps)} new padding array(s):"
        )
        for line in lines:
            if line.startswith("// DATA"):
                console.print(f"  [dim]{line}[/]")
        return

    # File FIRST, then metadata: a crash in between must not leave
    # rebrew-data.toml claiming coverage the .c does not declare.
    atomic_write_text(out_file, "\n".join(lines), encoding="utf-8")
    for gap in new_gaps:
        # Write metadata to data metadata (the metadata root, not src_dir).
        set_data_field(meta_dir, gap.offset, "size", gap.size, origin)
        set_data_field(meta_dir, gap.offset, "section", ".bss", origin)
        set_data_field(
            meta_dir, gap.offset, "note", f"gap between {gap.before} and {gap.after}", origin
        )
    if new_gaps:
        console.print(
            f"Updated {out_file.name}: {len(existing_decls)} existing + "
            f"{len(new_gaps)} new padding array(s)."
        )
        console.print(
            "Metadata written to rebrew-data.toml. Compile this file to fix .bss alignment."
        )
    else:
        console.print(
            f"{out_file.name} is up to date ({len(existing_decls)} padding array(s) already declared)."
        )


def _render_bss(console: Console, report: BssReport) -> None:
    """Print BSS layout verification report."""
    if not report.bss_size:
        console.print("  [dim]No .bss section found in binary.[/]")
        return

    console.print(
        Panel(
            f"BSS at [bold]0x{report.bss_va:08x}[/], size [bold]{report.bss_size:,}[/] bytes\n"
            f"Known globals: [bold]{len(report.known_entries)}[/], "
            f"coverage: [bold]{report.coverage_pct:.1f}%[/] ({report.coverage_bytes:,}B of {report.bss_size:,}B)\n"
            f"Gaps detected: [bold]{('[red]' + str(len(report.gaps)) + '[/red]') if report.gaps else '[green]0[/green]'}[/]",
            title="[bold]BSS Layout Verification[/]",
            border_style="blue",
        )
    )

    if report.known_entries:
        tbl = Table(show_header=True, header_style="bold", border_style="dim")
        tbl.add_column("VA", style="cyan", no_wrap=True)
        tbl.add_column("Name")
        tbl.add_column("Size", justify="right")
        tbl.add_column("Source", style="dim")

        for entry in report.known_entries:
            tbl.add_row(
                f"0x{entry.va:08x}",
                entry.name,
                f"{entry.size_hint}B",
                entry.source_file,
            )
        console.print(tbl)
        console.print()

    if report.gaps:
        gap_tbl = Table(
            title="[bold red]BSS Gaps (potential missing globals)[/]",
            show_header=True,
            header_style="bold",
            border_style="red",
        )
        gap_tbl.add_column("Offset", style="cyan", no_wrap=True)
        gap_tbl.add_column("Size", justify="right")
        gap_tbl.add_column("Between")

        for gap in report.gaps:
            gap_tbl.add_row(
                f"0x{gap.offset:08x}",
                f"{gap.size}B",
                f"{gap.before} → {gap.after}",
            )
        console.print(gap_tbl)
    else:
        console.print("  [green]✓ No gaps detected in BSS layout[/]")


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------


def _render_globals(console: Console, scan: ScanResult, conflicts_only: bool = False) -> None:
    """Print a Rich table of globals."""
    entries = list(scan.globals.values())
    if conflicts_only:
        conflict_names = {c["name"] for c in scan.type_conflicts}
        entries = [e for e in entries if e.name in conflict_names]

    if not entries:
        console.print("[dim]No globals found.[/]")
        return

    tbl = Table(show_header=True, header_style="bold", border_style="dim")
    tbl.add_column("VA", style="cyan", no_wrap=True)
    tbl.add_column("Name")
    tbl.add_column("Type")
    tbl.add_column("Section", style="dim")
    tbl.add_column("Files", style="dim")

    for entry in sorted(entries, key=lambda e: (e.va or 0xFFFFFFFF, e.name)):
        va_str = f"0x{entry.va:08x}" if entry.va else "—"
        files_str = ", ".join(entry.declared_in[:3])
        if len(entry.declared_in) > 3:
            files_str += f" (+{len(entry.declared_in) - 3})"
        style = "red" if "CONFLICT" in entry.type_str else ""
        tbl.add_row(
            va_str, entry.name, entry.type_str, entry.section or "—", files_str, style=style
        )

    title = "[bold]Type Conflicts[/]" if conflicts_only else "[bold]Global Data Inventory[/]"
    console.print(Panel(tbl, title=title, border_style="blue"))


def _section_summary(scan: ScanResult, sections: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-section progress: globals, annotated bytes, and % byte coverage.

    Annotated bytes are estimated from each annotated global's declared type
    (via the same type-size heuristic as BSS coverage).  A section with no
    annotatable contribution reports coverage 0.0%.
    """
    per_section: dict[str, dict[str, Any]] = {}
    for entry in scan.globals.values():
        sec_name = entry.section or "unknown"
        s = per_section.setdefault(
            sec_name, {"name": sec_name, "globals": 0, "annotated": 0, "annotated_bytes": 0}
        )
        s["globals"] += 1
        if entry.annotated:
            s["annotated"] += 1
            s["annotated_bytes"] += _estimate_type_size(entry.type_str) if entry.type_str else 4

    out: list[dict[str, Any]] = []
    for sec_name in [".data", ".rdata", ".bss", "unknown"]:
        sec_data = per_section.get(sec_name)
        if sec_data is None:
            continue
        sec = sections.get(sec_name)
        size = int(sec.get("size", 0)) if sec else 0
        coverage = (sec_data["annotated_bytes"] / size * 100.0) if size else 0.0
        out.append(
            {
                "name": sec_name,
                "globals": sec_data["globals"],
                "annotated": sec_data["annotated"],
                "annotated_bytes": sec_data["annotated_bytes"],
                "section_size": size,
                "coverage_pct": round(coverage, 1),
            }
        )
    return out


def _render_summary(
    console: Console, scan: ScanResult, sections: dict[str, dict[str, Any]]
) -> None:
    """Print section-level summary."""
    rows = _section_summary(scan, sections)

    tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tbl.add_column("Section")
    tbl.add_column("Globals", justify="right")
    tbl.add_column("Annotated", justify="right")
    tbl.add_column("Bytes", justify="right")
    tbl.add_column("% Coverage", justify="right")

    for row in rows:
        sec_name = row["name"]
        size_str = f"{row['section_size']:,}B" if row["section_size"] else "—"
        coverage_str = f"{row['coverage_pct']}%" if row["section_size"] else "—"
        tbl.add_row(
            sec_name,
            str(row["globals"]),
            str(row["annotated"]),
            f"{row['annotated_bytes']:,}B / {size_str}",
            coverage_str,
        )

    annotated = sum(1 for g in scan.globals.values() if g.annotated)
    total = len(scan.globals)
    conflicts = len(scan.type_conflicts)

    subtitle = f"{total} globals ({annotated} annotated, {total - annotated} extern-only)"
    if conflicts:
        subtitle += f" — [red]{conflicts} type conflicts[/]"

    console.print(
        Panel(tbl, title="[bold]Data Section Summary[/]", subtitle=subtitle, border_style="green")
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def annotate_globals(
    src_dir: Path, metadata: Path, marker: str, dry_run: bool = False
) -> dict[str, int]:
    """Insert ``// GLOBAL: <marker> 0x<VA>`` markers from the data metadata.

    For every symbol in ``rebrew-data.toml``, insert the marker immediately
    above the first declaration/definition of that name in each source file
    that mentions it (extern or definition).  Declarations already carrying a
    ``GLOBAL:`` or ``DATA:`` marker are skipped.  Returns ``{file: markers}``.
    """
    with open(metadata, "rb") as fh:
        db = tomllib.load(fh)
    symbols: dict[str, tuple[str, int]] = {}
    for key, val in db.items():
        if not val.get("name"):
            continue
        try:
            mod, _, addr = key.partition(".")
            symbols[str(val["name"])] = (mod, int(addr, 16))
        except ValueError:
            continue

    marker_re = re.compile(r"^\s*//\s*GLOBAL:\s*\S+\s+0x([0-9a-fA-F]+)")
    decl_cache: dict[str, re.Pattern[str]] = {}
    total = 0
    per_file: dict[str, int] = {}
    for f in sorted(src_dir.rglob("*.c")):
        text = f.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        existing = {int(m.group(1), 16) for m in (marker_re.match(ln) for ln in lines) if m}
        insertions: list[tuple[int, str]] = []
        used: set[int] = set()
        for name, (_mod, sym_addr) in sorted(symbols.items(), key=lambda kv: kv[1][1]):
            if sym_addr in existing:
                continue
            pat = decl_cache.get(name)
            if pat is None:
                pat = re.compile(
                    r"^\s*(?:extern\s+)?[\w\s\*]+\s+"
                    + re.escape(name)
                    + r"(\[\d*\])?\s*(?:=\s*[^;]*|\s*;)"
                )
                decl_cache[name] = pat
            hit = next(
                (i for i, ln in enumerate(lines) if i not in used and pat.match(ln)),
                None,
            )
            if hit is None:
                continue
            if hit > 0 and re.match(r"^\s*//\s*DATA:", lines[hit - 1]):
                continue
            used.add(hit)
            insertions.append((hit, f"// GLOBAL: {marker} 0x{sym_addr:08x}"))
        if not insertions:
            continue
        for shift, (hit, marker_line) in enumerate(insertions):
            lines.insert(hit + shift, marker_line)
        total += len(insertions)
        per_file[str(f.relative_to(src_dir))] = len(insertions)
        if not dry_run:
            f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return per_file


app = typer.Typer(
    help="Global data scanner — inventory .data/.rdata/.bss globals.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Modes:[/bold]\n\n"
        "  [dim](default)[/dim] · · · · Scan reversed sources for GLOBAL:/extern declarations\n\n"
        "  --conflicts · · · · Show only globals with type conflicts across files\n\n"
        "  --summary · · · · · Show section-level summary (counts per .data/.rdata/.bss)\n\n"
        "  --dispatch · · · · · Detect dispatch tables / vtables in .data/.rdata sections\n\n"
        "  --bss · · · · · · · Verify .bss layout and detect gaps between globals\n\n"
        "  --fix-bss · · · · · Auto-generate bss_padding.c with dummy arrays for gaps\n\n"
        "  --gen-header · · · · Generate rebrew_globals.h from annotations (no Ghidra)\n\n"
        "[bold]Examples:[/bold]\n\n"
        "  rebrew data · · · · · · · · · · · · · Scan all globals (default mode)\n\n"
        "  rebrew data --conflicts · · · · · · · · Show type conflicts across files\n\n"
        "  rebrew data --summary · · · · · · · · · Section-level overview\n\n"
        "  rebrew data --dispatch · · · · · · · · · Detect vtables in data sections\n\n"
        "  rebrew data --dispatch --min-table-len 5 · Require at least 5 entries per table\n\n"
        "  rebrew data --dispatch --max-pointer-stride 8 · Allow 8-byte strides between slots\n\n"
        "  rebrew data --bss · · · · · · · · · · · Verify .bss layout and gaps\n\n"
        "  rebrew data --fix-bss · · · · · · · · · Generate bss_padding.c for gaps\n\n"
        "  rebrew data --gen-header · · · · · · · · Generate rebrew_globals.h\n\n"
        "  rebrew data --json · · · · · · · · · · · Output as JSON\n\n"
        "[dim]Scans reversed .c files for GLOBAL:/DATA: annotations and extern "
        "declarations, cross-references with binary data sections, and detects "
        "type conflicts across files.[/dim]"
    ),
)


def _emit_extern_decl(row: dict[str, Any]) -> str:
    """Format an `extern` declaration honoring an explicit `type` when given.

    Uses `unsigned char <name>[]` as the fallback when no type is specified.
    Otherwise emits `extern <type> <name>;` — the type string itself carries
    any pointer/array-ness, so no separate array handling is needed.
    """
    type_str = (row.get("type") or "").strip()
    name = row["name"]
    if not type_str:
        return f"extern unsigned char {name}[];"
    # Both the pointer and array spellings emit identically — MSVC accepts
    # `extern T name;` for either (the type carries the pointer/array-ness).
    return f"extern {type_str} {name};"


def _gen_globals_header(
    cfg: ProjectConfig,
    src_dir: Path,
    out_path: Path | None = None,
    force: bool = False,
    *,
    dry_run: bool = False,
    json_output: bool = False,
) -> None:
    """Generate rebrew_globals.h from GLOBAL:/DATA: annotations + data metadata.

    Writes ``{out_path}`` (default: ``{src_dir}/rebrew_globals.h``) with
    ``extern`` declarations for every known global, grouped by section
    (``.data``, ``.rdata``, ``.bss``).  Does not require Ghidra — uses local
    annotation data only.

    Args:
        cfg: Project configuration.
        src_dir: Reversed sources directory (used for annotation scanning).
        out_path: Output file path.  Defaults to ``src_dir/rebrew_globals.h``.
        force: When False (default), refuses to overwrite an existing file and
            exits with an error message.  Pass True to allow overwriting.
        dry_run: When True, report what would be written without touching disk.
        json_output: When True, errors are emitted as JSON.
    """
    import time

    from rebrew.annotation import parse_c_file_multi
    from rebrew.cli import error_exit, iter_sources
    from rebrew.data_metadata import load_data_metadata

    marker = getattr(cfg, "marker", getattr(cfg, "target_name", "GAME").upper())
    metadata = load_data_metadata(cfg.metadata_dir)

    rows: list[dict[str, Any]] = []
    seen_va: set[int] = set()

    for src in sorted(iter_sources(src_dir, cfg)):
        try:
            annotations = parse_c_file_multi(src, target_name=marker, metadata_dir=cfg.metadata_dir)
        except Exception:  # noqa: BLE001 — non-fatal; skip unparseable files
            logging.debug("Skipping %s: annotation parse failed", src, exc_info=True)
            continue
        for ann in annotations:
            if ann.marker_type not in ("GLOBAL", "DATA"):
                continue
            va = ann.va
            if not va or va in seen_va:
                continue
            seen_va.add(va)

            # Merge from metadata: section, size, note, name, type
            sk = (ann.module, va)
            se = metadata.get(sk, {})

            # Prefer annotation name; fall back to metadata name; then to address-based
            raw_name = ann.name or ann.symbol or str(se.get("name", "")) or ""
            if raw_name.startswith("_"):
                raw_name = raw_name[1:]
            name = raw_name or f"g_{va:08x}"

            section = ann.section or str(se.get("section", ""))
            size = ann.size or int(se.get("size", 0) or 0)
            note = str(se.get("note", ""))
            type_str = str(se.get("type", ""))

            rows.append(
                {
                    "va": va,
                    "name": name,
                    "section": section,
                    "size": size,
                    "note": note,
                    "type": type_str,
                }
            )

    rows.sort(key=lambda x: int(x["va"]))

    # Group by section
    by_section: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_section.setdefault(row["section"] or "", []).append(row)

    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    header_lines = [
        "/* Auto-generated by rebrew data --gen-header. DO NOT EDIT.",
        " * Source: GLOBAL:/DATA: annotations + rebrew-data.toml",
        f" * Generated: {generated}",
        " */",
        "",
        "#ifndef REBREW_GLOBALS_H",
        "#define REBREW_GLOBALS_H",
        "",
    ]

    section_order = [".data", ".rdata", ".bss", ""]
    emitted: set[str] = set()
    for sec in section_order:
        items = by_section.get(sec)
        if not items:
            continue
        label = sec if sec else "(unknown section)"
        header_lines.append(f"/* {label} */")
        for row in items:
            note_parts = [f"0x{row['va']:08X}"]
            if row["size"]:
                note_parts.append(f"{row['size']} bytes")
            if row["note"]:
                note_parts.append(row["note"])
            decl = _emit_extern_decl(row)
            header_lines.append(f"{decl} /* {', '.join(note_parts)} */")
        header_lines.append("")
        emitted.add(sec)

    for sec in sorted(by_section):
        if sec in emitted:
            continue
        items = by_section[sec]
        header_lines.append(f"/* {sec or '(unknown)'} */")
        for row in items:
            note_parts = [f"0x{row['va']:08X}"]
            if row["size"]:
                note_parts.append(f"{row['size']} bytes")
            if row["note"]:
                note_parts.append(row["note"])
            decl = _emit_extern_decl(row)
            header_lines.append(f"{decl} /* {', '.join(note_parts)} */")
        header_lines.append("")

    header_lines += ["#endif /* REBREW_GLOBALS_H */", ""]

    out = out_path if out_path is not None else src_dir / "rebrew_globals.h"
    if out.exists() and not force:
        error_exit(
            f"{out} already exists. Use --force to overwrite.",
            json_mode=json_output,
        )

    if dry_run:
        console.print(f"[cyan]dry-run:[/cyan] would write {out} with {len(rows)} globals")
        return

    content = "\n".join(header_lines)
    if out.exists():
        existing = out.read_text(encoding="utf-8")

        # Idempotency: regeneration only bumps the "Generated:" timestamp —
        # skip the write when the body is otherwise identical to avoid
        # needless git churn on every run.
        def _strip_timestamp(text: str) -> str:
            return "\n".join(line for line in text.splitlines() if "Generated:" not in line)

        if _strip_timestamp(existing) == _strip_timestamp(content):
            console.print(f"[dim]{out.name} unchanged[/dim] ({len(rows)} globals)")
            return

    atomic_write_text(out, content, encoding="utf-8")

    console.print(f"[green]Wrote {out.name}[/green] with {len(rows)} globals")
    for sec in section_order:
        items = by_section.get(sec or "")
        if items:
            console.print(f"  {sec or '(unknown)'}: {len(items)}")


@app.callback(invoke_without_command=True)
def main(
    conflicts: bool = typer.Option(
        False, "--conflicts", help="Show only globals with type conflicts"
    ),
    summary: bool = typer.Option(False, "--summary", help="Show section-level summary only"),
    dispatch: bool = typer.Option(
        False, "--dispatch", help="Detect dispatch tables / vtables in data sections"
    ),
    min_table_len: int = typer.Option(
        3,
        "--min-table-len",
        help="Minimum number of entries to qualify as a dispatch table (--dispatch)",
    ),
    max_pointer_stride: int = typer.Option(
        4,
        "--max-pointer-stride",
        help="Maximum byte stride between pointer slots when scanning for tables (--dispatch)",
    ),
    bss: bool = typer.Option(
        False, "--bss", help="Verify .bss layout and detect gaps between globals"
    ),
    fix_bss: bool = typer.Option(
        False, "--fix-bss", help="Auto-generate bss_padding.c with dummy arrays for detected gaps"
    ),
    gen_header: bool = typer.Option(
        False,
        "--gen-header",
        help="Generate rebrew_globals.h from GLOBAL:/DATA: annotations (no Ghidra needed)",
    ),
    annotate: bool = typer.Option(
        False,
        "--annotate",
        help="Insert // GLOBAL: markers from the data metadata into the sources",
    ),
    gen_header_out: Path | None = typer.Option(
        None,
        "--gen-header-out",
        help="Output path for --gen-header (default: {reversed_dir}/rebrew_globals.h)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing output file when using --gen-header",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    layout_audit: bool = typer.Option(
        False,
        "--layout-audit",
        help="Per-TU .data/.bss span/order feasibility audit (what blocks placement convergence)",
    ),
    fill_data: bool = typer.Option(
        False,
        "--fill-data",
        help="Emit _dpad_<addr>[N] pads for the uncovered .data byte runs (byte-exact "
        "from the reference in the raw region, zero-init for BSS)",
    ),
    bss_only: bool = typer.Option(
        False, "--bss-only", help="With --fill-data: only BSS pads, skip initialized-region pads"
    ),
    own: bool = typer.Option(
        False,
        "--own",
        help="Materialize stub-file globals as real definitions in their owner TUs "
        "(original bytes from the reference)",
    ),
    stub_file: Path | None = typer.Option(
        None,
        "--stub-file",
        help="With --own: the stub TU whose placeholders to own (default src/link_stubs.c)",
    ),
    fix_ownership: bool = typer.Option(
        False,
        "--fix-ownership",
        help="Re-partition global definitions across TUs to fix layout-audit SPAN/ORDER violations",
    ),
    converge: bool = typer.Option(
        False,
        "--converge",
        help="Fixed-point .data placement: insert/adjust _dlead_<tu>[N] pads and re-measure "
        "(rebuild between rounds)",
    ),
    rounds: int = typer.Option(
        1, "--rounds", help="With --converge: iteration count (rebuild per round)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Scan reversed source files for global data declarations."""
    cfg = require_config(target=target, json_mode=json_output)

    src_dir = cfg.reversed_dir
    bin_path = cfg.target_binary

    # --gen-header: generate rebrew_globals.h from annotations (no Ghidra)
    if gen_header:
        _gen_globals_header(
            cfg,
            src_dir,
            out_path=gen_header_out,
            force=force,
            dry_run=dry_run,
            json_output=json_output,
        )
        return

    # --layout-audit / --fill-data / --own / --fix-ownership / --converge:
    # .data placement machinery
    if layout_audit or fill_data or own or fix_ownership or converge:
        from rebrew.data_layout import audit_layout, own_data_globals
        from rebrew.data_layout import converge_layout as converge_data_layout
        from rebrew.data_layout import fill_data as fill_data_layout
        from rebrew.data_layout import fix_ownership as fix_data_ownership

        metadata = cfg.metadata_dir / "rebrew-data.toml"
        if not metadata.exists():
            error_exit(f"data metadata not found: {metadata}", json_mode=json_output)
        if layout_audit:
            report = audit_layout(cfg.root, metadata)
            if json_output:
                json_print(report)
            else:
                console.print(
                    f"{'TU':58} {'#sym':>4} {'min addr':>10} {'max addr':>10} "
                    f"{'data':>7} {'bss':>7}"
                )
                console.print("-" * 104)
                for r in report["rows"]:
                    flag = f"  <== {'/'.join(r['flags'])} VIOLATION" if r["flags"] else ""
                    sym_count = len(set(r["dsyms"]) | set(r["bsyms"]))
                    console.print(
                        f"{r['obj']:58} {sym_count:4} "
                        f"{r['min_addr']:#10x} {r['max_addr']:#10x} "
                        f"{r['dsize']:#7x} {r['bsize']:#7x}{flag}"
                    )
                console.print("-" * 104)
                console.print(f"violations: {report['violations']}")
                for r in report["rows"]:
                    if r.get("error"):
                        console.print(f"[red]objdump error on {r['obj']}: {r['error']}[/red]")
                if report["unowned"]:
                    console.print(
                        f"unowned toml symbols ({len(report['unowned'])}): "
                        + ", ".join(s for s, _ in report["unowned"][:10])
                    )
                if report["duplicate_owned"]:
                    console.print(
                        f"duplicate-owned ({len(report['duplicate_owned'])}): "
                        + ", ".join(s for s, _, _ in report["duplicate_owned"][:10])
                    )
            return
        if fill_data:
            result = fill_data_layout(
                cfg.root, metadata, bin_path, src_dir, dry_run=dry_run, bss_only=bss_only
            )
            if json_output:
                json_print(result)
            else:
                console.print(
                    f"[green]data fill-data:[/green] {result['init_pads']} init pads, "
                    f"{result['bss_pads']} bss pads{' (dry run)' if dry_run else ''}"
                )
            return
        if own:
            stub = stub_file if stub_file is not None else cfg.root / "src" / "link_stubs.c"
            if not stub.exists():
                error_exit(f"stub file not found: {stub} (--stub-file)", json_mode=json_output)
            own_result = own_data_globals(
                cfg.root, metadata, bin_path, src_dir, stub, dry_run=dry_run
            )
            if json_output:
                json_print(own_result)
            else:
                console.print(
                    f"[green]data own:[/green] {own_result['owned']} globals materialized"
                    f"{' (dry run)' if dry_run else ''}"
                )
                if own_result["skipped"]:
                    console.print(
                        f"  skipped ({len(own_result['skipped'])}): "
                        + ", ".join(own_result["skipped"][:10])
                    )
            return
        if fix_ownership:
            fix_result = fix_data_ownership(cfg.root, metadata, bin_path, src_dir, dry_run=dry_run)
            if json_output:
                json_print(fix_result)
            else:
                console.print(
                    f"[green]data fix-ownership:[/green] {fix_result['edits']} edits "
                    f"({fix_result['moved']} definitions moved){' (dry run)' if dry_run else ''}"
                )
            return
        conv_result = converge_data_layout(
            cfg.root, metadata, bin_path, src_dir, rounds=rounds, dry_run=dry_run
        )
        if json_output:
            json_print(conv_result)
        else:
            console.print(
                f"[green]data converge:[/green] {len(conv_result['adjustments'])} pad adjustments "
                f"over {conv_result['rounds']} round(s){' (dry run)' if dry_run else ''}"
            )
        return

    # --annotate: insert // GLOBAL: markers from the data metadata
    if annotate:
        metadata = cfg.metadata_dir / "rebrew-data.toml"
        if not metadata.exists():
            error_exit(f"data metadata not found: {metadata}", json_mode=json_output)
        marker = cfg.marker or cfg.target_name.upper()
        per_file = annotate_globals(src_dir, metadata, marker, dry_run=dry_run)
        total = sum(per_file.values())
        if json_output:
            json_print({"markers": total, "files": per_file})
        else:
            console.print(f"[green]data annotate:[/green] {total} markers")
            for f, n in sorted(per_file.items()):
                console.print(f"  {f}: {n}")
        return

    # Scan source files
    scan = scan_globals(src_dir, cfg=cfg)

    # Enrich with binary section info
    sections: dict[str, dict[str, Any]] = {}
    bin_info: Any = None  # single lazy binary parse, shared with --dispatch
    if bin_path and bin_path.exists():
        try:
            from rebrew.binary_loader import load_binary, section_dict
            from rebrew.catalog.sections import sections_from_info

            bin_info = load_binary(bin_path)
            sections = sections_from_info(bin_info)
        except (ImportError, OSError, KeyError, ValueError):
            bin_info = None
            sections = {}
        enrich_with_sections(scan, sections)

        # R4 (np-rebrew TOOLCHAIN_BUGS): cross-check annotated global VAs
        # against the real PE section ranges.  A typo'd or stale VA silently
        # no-ops in the grid/catalog and shows up as an unexplained coverage
        # gap — surface it instead.
        section_ranges = [
            (s["va"], s["va"] + s["size"])
            for s in sections.values()
            if s.get("va") and s.get("size")
        ]
        out_of_range = [
            (name, g.va)
            for name, g in scan.globals.items()
            if g.va and not any(lo <= g.va < hi for lo, hi in section_ranges)
        ]
        if out_of_range:
            console.print(
                f"[yellow]warning:[/yellow] {len(out_of_range)} annotated global(s) "
                "fall outside every PE section range: "
                + ", ".join(f"{n}@0x{va:x}" for n, va in out_of_range[:8])
            )

    # Collect // DATA: annotations
    data_anns = scan_data_annotations(src_dir, cfg=cfg)
    scan.data_annotations = data_anns

    # BSS layout mode
    if bss or fix_bss:
        bss_report = verify_bss_layout(scan, sections)
        if fix_bss:
            _generate_bss_fix(
                bss_report,
                src_dir,
                getattr(cfg, "marker", ""),
                metadata_dir=cfg.metadata_dir,
                dry_run=dry_run,
            )
            return

        if json_output:
            json_print(bss_report.to_dict())
        else:
            console.print()
            _render_bss(console, bss_report)
        return

    # Dispatch table mode
    if dispatch:
        if not bin_path or not bin_path.exists():
            error_exit("target binary not found (needed for --dispatch)", json_mode=json_output)

        if bin_info is None:
            error_exit(
                "target binary could not be parsed (needed for --dispatch)",
                json_mode=json_output,
            )
        binary_data = bin_info.data
        sec_dict = section_dict(bin_info)

        # Build known functions map from reversed source files, then merge in
        # function-list / Ghidra-structure names for targets without sources.
        known_functions = _build_dispatch_known_functions(cfg, src_dir)

        tables = find_dispatch_tables(
            binary_data,
            sec_dict,
            known_functions,
            min_entries=min_table_len,
            max_stride=max_pointer_stride,
            info=bin_info,
        )

        if json_output:
            json_print([t.to_dict() for t in tables])
        else:
            console.print()
            _render_dispatch(console, tables)
        return

    # JSON output
    if json_output:
        data = scan.to_dict()
        data["sections"] = {
            name: {"va": f"0x{s['va']:08x}", "size": s["size"]} for name, s in sections.items()
        }
        if summary:
            # --summary composes with --json: emit a structured section progress view.
            data["summary"] = {
                "sections": _section_summary(scan, sections),
                "conflicts": len(scan.type_conflicts),
            }
        json_print(data)
        return

    # Rich output
    console.print()

    if summary:
        _render_summary(console, scan, sections)
    elif conflicts:
        _render_globals(console, scan, conflicts_only=True)
        if scan.type_conflicts:
            console.print()
            for c in scan.type_conflicts:
                console.print(f"  [bold red]⚠ {c['name']}[/]:")
                for t, files in c["types"].items():
                    console.print(f"    {t:30s} ← {', '.join(files)}")
    else:
        _render_globals(console, scan)
        if scan.type_conflicts:
            console.print(
                f"\n  [yellow]⚠ {len(scan.type_conflicts)} type conflict(s) detected — run with --conflicts for details[/]"
            )

    console.print()


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
