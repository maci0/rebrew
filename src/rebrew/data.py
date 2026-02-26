"""data.py – Global data scanner for rebrew.

Scans reversed .c files for ``// GLOBAL: MODULE 0xVA`` and ``// DATA: MODULE 0xVA``
annotations (reccmp standard) and ``extern`` data declarations, cross-references
them with the binary's ``.data``/``.rdata``/``.bss`` sections, detects type conflicts
across files, and outputs a catalog of known globals.

Also provides:
- Dispatch table / vtable detection via ``--dispatch``
- BSS layout verification via ``--bss``
"""

import json
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rebrew.cli import TargetOption, get_config

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# reccmp-compatible GLOBAL annotation:  // GLOBAL: SERVER 0x10031ae8
_GLOBAL_RE = re.compile(r"(?://|/\*)\s*GLOBAL:\s*(?P<module>[A-Z0-9_]+)\s+(?P<va>0x[0-9a-fA-F]+)")

# DATA annotation:  // DATA: SERVER 0x10025000
_DATA_RE = re.compile(r"(?://|/\*)\s*DATA:\s*(?P<module>[A-Z0-9_]+)\s+(?P<va>0x[0-9a-fA-F]+)")

# extern data declarations — we want:
#   extern int g_foo;
#   extern unsigned short DAT_100358a0;
#   extern char s_message_1002d70c[];
# but NOT function forward-declarations like:
#   extern int __cdecl func_name(int, int);
_EXTERN_RE = re.compile(
    r"^\s*extern\s+"
    r"(?P<type>.+?)\s*"  # type (non-greedy, allow trailing whitespace)
    r"(?P<ptr>\*\s*)?"  # optional pointer asterisk(s)
    r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)"  # identifier
    r"(?P<array>\[.*\])?"  # optional array suffix
    r"\s*;"
)


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
    status: str = ""  # EXACT / RELOC / MATCHING / STUB / UNKNOWN / ""


@dataclass
class DispatchTable:
    """A dispatch table (contiguous function pointer array) in a data section."""

    va: int
    section: str
    entries: list[DispatchEntry] = field(default_factory=list)

    @property
    def num_entries(self) -> int:
        return len(self.entries)

    @property
    def resolved(self) -> int:
        return sum(1 for e in self.entries if e.name)

    @property
    def coverage(self) -> float:
        return self.resolved / self.num_entries if self.num_entries else 0.0

    def to_dict(self) -> dict[str, Any]:
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


def _is_function_decl(type_str: str, rest_of_line: str) -> bool:
    """Heuristic: return True if a line looks like a function decl, not a data global."""
    # Function forward declarations always have parentheses
    if "(" in rest_of_line:
        return True
    # Calling convention keywords imply a function
    return any(cc in type_str for cc in ("__cdecl", "__stdcall", "__fastcall", "__thiscall"))


def scan_globals(src_dir: Path, cfg: Any = None) -> ScanResult:
    """Scan reversed source files for global declarations.

    Collects:
    1. ``// GLOBAL: MODULE 0xVA`` reccmp annotations (+ next line for declaration)
    2. ``extern <type> <name>;`` data globals (filtering out function decls)

    Returns a ScanResult with all discovered globals and type conflicts.
    """
    from rebrew.cli import source_glob

    result = ScanResult()
    # Track all type declarations per name for conflict detection
    type_by_name: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    if not src_dir.exists():
        return result

    for cfile in sorted(src_dir.glob(source_glob(cfg))):
        try:
            lines = cfile.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        fname = cfile.name

        for i, line in enumerate(lines):
            # 1. Check for // GLOBAL: annotation
            gm = _GLOBAL_RE.search(line)
            if gm:
                va = int(gm.group("va"), 16)
                # Next line should be the declaration
                decl = lines[i + 1].strip() if i + 1 < len(lines) else ""
                if not decl:
                    print(
                        f"Warning: {fname}:{i + 1}: // GLOBAL: annotation at 0x{va:08x} "
                        f"has no declaration on the following line",
                        file=sys.stderr,
                    )
                name = "unknown"
                type_str = ""

                # Try to parse: extern <type> <name>[<array>];
                em = _EXTERN_RE.match(decl)
                if em:
                    name = em.group("name")
                    arr = em.group("array") or ""
                    ptr = em.group("ptr").strip() if em.group("ptr") else ""
                    type_str = em.group("type").strip()
                    if ptr:
                        type_str += " *"
                    if arr:
                        type_str += arr
                else:
                    # Fallback: try to grab the last identifier before ;
                    nm = re.search(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[.*\])?\s*;", decl)
                    if nm:
                        name = nm.group(1)

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

            # 2. Check for extern data declarations (not function decls)
            em = _EXTERN_RE.match(line)
            if em:
                full_line = line.strip()
                type_str_raw = em.group("type").strip()

                # Skip function forward-declarations
                if _is_function_decl(type_str_raw, full_line):
                    continue

                name = em.group("name")
                arr = em.group("array") or ""
                ptr = em.group("ptr").strip() if em.group("ptr") else ""
                type_str = type_str_raw
                if ptr:
                    type_str += " *"
                if arr:
                    type_str += arr

                # Skip dllimport functions
                if "__declspec(dllimport)" in full_line:
                    continue

                entry = result.globals.get(name)
                if entry is None:
                    entry = GlobalEntry(name=name, type_str=type_str)
                    result.globals[name] = entry

                if fname not in entry.declared_in:
                    entry.declared_in.append(fname)

                if type_str:
                    type_by_name[name][type_str].append(fname)

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


def scan_data_annotations(src_dir: Path, cfg: Any = None) -> list[dict[str, Any]]:
    """Scan for ``// DATA: MODULE 0xVA`` annotations in source files.

    These mark standalone global data objects for tracking in the catalog.
    Returns a list of dicts with: va, name, size, section, origin, note, filepath.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.cli import source_glob

    entries: list[dict[str, Any]] = []
    if not src_dir.exists():
        return entries

    for cfile in sorted(src_dir.glob(source_glob(cfg))):
        for ann in parse_c_file_multi(cfile):
            if ann.marker_type == "DATA":
                entries.append(
                    {
                        "va": f"0x{ann.va:08x}",
                        "name": ann.name or cfile.stem,
                        "size": ann.size,
                        "section": ann.section,
                        "origin": ann.origin,
                        "note": ann.note,
                        "filepath": ann.filepath or cfile.name,
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


def find_dispatch_tables(
    binary_data: bytes,
    image_base: int,
    sections: dict[str, dict[str, Any]],
    known_functions: dict[int, dict[str, str]],
    ptr_size: int = 4,
    min_entries: int = 3,
) -> list[DispatchTable]:
    """Detect dispatch tables / vtables in data sections.

    Scans ``.data`` and ``.rdata`` sections for contiguous pointer-sized entries
    that all point into ``.text``.  Groups consecutive entries into tables.

    Args:
        binary_data: Raw binary file bytes.
        image_base: Image base VA of the binary (reserved for future use).
        sections: Section dict from binary_loader ({name: {va, size, file_offset, raw_size}}).
        known_functions: Map of VA -> {"name": str, "status": str} for reversed funcs.
        ptr_size: Pointer size in bytes (4 for 32-bit PE).
        min_entries: Minimum entries to qualify as a dispatch table.
    """
    text_sec = sections.get(".text")
    if not text_sec:
        return []

    text_va = text_sec["va"]
    text_end = text_va + text_sec["size"]

    data_sections = [(name, sec) for name, sec in sections.items() if name in (".data", ".rdata")]

    fmt = "<I" if ptr_size == 4 else "<Q"
    tables: list[DispatchTable] = []

    for sec_name, sec in data_sections:
        sec_offset = sec.get("file_offset", 0)
        sec_raw_size = sec.get("raw_size", sec.get("size", 0))
        sec_va = sec["va"]

        if sec_offset + sec_raw_size > len(binary_data):
            continue

        sec_bytes = binary_data[sec_offset : sec_offset + sec_raw_size]

        # Walk through aligned pointers
        current_entries: list[DispatchEntry] = []
        current_start_va = 0

        i = 0
        while i + ptr_size <= len(sec_bytes):
            val = struct.unpack_from(fmt, sec_bytes, i)[0]
            entry_va = sec_va + i

            if text_va <= val < text_end:
                # This looks like a function pointer into .text
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
                i += ptr_size
            else:
                # Not a text pointer — flush current run if long enough
                if len(current_entries) >= min_entries:
                    tables.append(
                        DispatchTable(
                            va=current_start_va,
                            section=sec_name,
                            entries=list(current_entries),
                        )
                    )
                current_entries = []
                i += ptr_size

        # Flush trailing run
        if len(current_entries) >= min_entries:
            tables.append(
                DispatchTable(
                    va=current_start_va,
                    section=sec_name,
                    entries=list(current_entries),
                )
            )

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
        return self.coverage_bytes / self.bss_size * 100 if self.bss_size else 0.0

    def to_dict(self) -> dict[str, Any]:
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
    arr_match = re.search(r"\[(\d+)\]", base)
    elem_count = int(arr_match.group(1)) if arr_match else 1
    base = re.sub(r"\[.*\]", "", base).strip()

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
    report.coverage_bytes = sum(e.size_hint for e in bss_entries)

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
                "MATCHING": "yellow",
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


def _render_summary(
    console: Console, scan: ScanResult, sections: dict[str, dict[str, Any]]
) -> None:
    """Print section-level summary."""
    section_counts: Counter[str] = Counter()
    for entry in scan.globals.values():
        section_counts[entry.section or "unknown"] += 1

    tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tbl.add_column("Section")
    tbl.add_column("Globals", justify="right")
    tbl.add_column("Section Size", justify="right")

    for sec_name in [".data", ".rdata", ".bss", "unknown"]:
        count = section_counts.get(sec_name, 0)
        sec = sections.get(sec_name)
        if count == 0 and sec_name != "unknown" and not sec:
            continue
        size_str = f"{sec.get('size', 0):,}B" if sec else "—"
        tbl.add_row(sec_name, str(count), size_str)

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

app = typer.Typer(
    help="Global data scanner — inventory .data/.rdata/.bss globals.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]
  rebrew-data                                Scan all data sections
  rebrew-data --section .rdata               Scan only .rdata section
  rebrew-data --section .data                Scan only .data section
  rebrew-data --section .bss                 Scan only .bss section
  rebrew-data --json                         Output as JSON
  rebrew-data --annotate                     Generate .c annotation stubs for globals
  rebrew-data 0x10008000                     Show details for specific address

[dim]Analyzes PE data sections to find global variables, string tables,
vtables, and other data structures. Cross-references with existing
annotations to track data-section coverage.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    target: str | None = TargetOption,
    conflicts: bool = typer.Option(
        False, "--conflicts", help="Show only globals with type conflicts"
    ),
    summary: bool = typer.Option(False, "--summary", help="Show section-level summary only"),
    dispatch: bool = typer.Option(
        False, "--dispatch", help="Detect dispatch tables / vtables in data sections"
    ),
    bss: bool = typer.Option(
        False, "--bss", help="Verify .bss layout and detect gaps between globals"
    ),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
) -> None:
    """Scan reversed source files for global data declarations."""
    try:
        cfg = get_config(target=target)
    except (FileNotFoundError, KeyError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    src_dir = cfg.reversed_dir
    bin_path = cfg.target_binary

    # Scan source files
    scan = scan_globals(src_dir, cfg=cfg)

    # Enrich with binary section info
    sections: dict[str, dict[str, Any]] = {}
    if bin_path and bin_path.exists():
        try:
            from rebrew.catalog import get_sections

            sections = get_sections(bin_path)
        except (ImportError, OSError, KeyError, ValueError):
            pass
        enrich_with_sections(scan, sections)

    # Collect // DATA: annotations
    data_anns = scan_data_annotations(src_dir, cfg=cfg)
    scan.data_annotations = data_anns

    # BSS layout mode
    if bss:
        bss_report = verify_bss_layout(scan, sections)
        if output_json:
            typer.echo(json.dumps(bss_report.to_dict(), indent=2))
        else:
            console = Console(stderr=True)
            console.print()
            _render_bss(console, bss_report)
        return

    # Dispatch table mode
    if dispatch:
        if not bin_path or not bin_path.exists():
            typer.echo("Error: target binary not found (needed for --dispatch)", err=True)
            raise typer.Exit(code=1)

        from rebrew.annotation import parse_c_file_multi
        from rebrew.binary_loader import load_binary

        info = load_binary(bin_path)
        binary_data = info.data
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
        from rebrew.cli import source_glob

        known_functions: dict[int, dict[str, str]] = {}
        for cfile in sorted(src_dir.glob(source_glob(cfg))):
            for entry in parse_c_file_multi(cfile):
                if entry.va:
                    known_functions[entry.va] = {
                        "name": entry.name or cfile.stem,
                        "status": entry.status,
                    }

        tables = find_dispatch_tables(binary_data, info.image_base, sec_dict, known_functions)

        if output_json:
            typer.echo(json.dumps([t.to_dict() for t in tables], indent=2))
        else:
            console = Console(stderr=True)
            console.print()
            _render_dispatch(console, tables)
        return

    # JSON output
    if output_json:
        data = scan.to_dict()
        data["sections"] = {
            name: {"va": f"0x{s['va']:08x}", "size": s["size"]} for name, s in sections.items()
        }
        typer.echo(json.dumps(data, indent=2))
        return

    # Rich output
    console = Console(stderr=True)
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
    app()


if __name__ == "__main__":
    main_entry()
