"""data_scan.py – Global data scanning library behind ``rebrew data``.

Scans reversed .c files for ``// GLOBAL: MODULE 0xVA`` and ``// DATA: MODULE 0xVA``
annotations (reccmp standard) and ``extern`` data declarations, detects dispatch
tables / vtables in data sections, and verifies ``.bss`` layout.  Holds no CLI
code, so compile-time callers (``coff_reloc``) and analysis commands import it
without pulling in the ``rebrew data`` Typer app (``rebrew.data``).
"""

import logging
import re
import struct
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rebrew.config import ProjectConfig, inventory_path_for
from rebrew.data_metadata import module_visible_to_target
from rebrew.utils import read_source_text

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# reccmp-compatible GLOBAL annotation:  // GLOBAL: SERVER 0x10031ae8
#
# `DATA:` is the same marker for this scan's purpose -- annotation.DATA_MARKERS
# holds {"GLOBAL", "DATA"} and `Annotation.is_data` treats them identically.
_GLOBAL_RE = re.compile(
    r"(?://|/\*)\s*(?:GLOBAL|DATA):\s*(?P<module>[A-Z0-9_]+)\s+(?P<va>0x[0-9a-fA-F]+)"
)
# Any annotation marker, so a file that only carries another target's
# FUNCTION/STUB lines is that target's source even when its externs have
# no GLOBAL line of their own.
_ANY_MARKER_RE = re.compile(
    r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL|VTABLE|STRING):\s*"
    r"(?P<module>[A-Z0-9_]+)\s+0x[0-9a-fA-F]+"
)

# extern data declarations are parsed by c_parser.find_extern_variables()
# via tree-sitter AST walking — see scan_globals().

# The identifier of a declaration the tree-sitter pass did not return.  It must
# accept a *definition with an initialiser* and not just a `;`-terminated
# declaration: `char s_msg[] = "...";` and `char g_blob[568] = {` are how a
# reversed source spells a global it actually defines.  Array extents may
# repeat (`char g_t[4][8]`), and the initialiser may open a brace on the same
# line or run to a `;`.
_DECL_IDENT_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[[^\]]*\]\s*)*\s*(?:=|;)")


def _data_meta(cfg: ProjectConfig | None, module: str, va: int) -> dict[str, Any]:
    """`rebrew-data.toml` fields for *(module, va)*, or `{}`.

    Tolerant by design: the scan must still report the annotation when there is
    no metadata root, no entry, or an unreadable file.
    """
    if cfg is None or not module:
        return {}
    from rebrew.data_metadata import get_data_entry

    try:
        return get_data_entry(cfg.metadata_dir, va, module=module)
    except (OSError, ValueError, KeyError):
        return {}


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
    conflict: bool = False  # True if files declare this name with different types

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        d: dict[str, Any] = {"name": self.name, "type": self.type_str}
        if self.va:
            d["va"] = f"0x{self.va:08x}"
        if self.section:
            d["section"] = self.section
        d["declared_in"] = self.declared_in
        d["annotated"] = self.annotated
        if self.conflict:
            d["conflict"] = True
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


def _source_visible_to_target(lines: list[str], cfg: ProjectConfig | None) -> bool:
    """Whether *lines* may contribute unannotated externs to the active target.

    No marker means a shared file. A marker for this target, or for a
    library module, means the file is in scope. A file whose markers are
    all another target's is that binary's source (guild-rebrew
    ``GOLD.fcn_*.c`` externs were listed on the server).
    """
    if cfg is None:
        return True
    saw_marker = False
    for line in lines:
        match = _ANY_MARKER_RE.search(line)
        if match is None:
            continue
        saw_marker = True
        if module_visible_to_target(match.group("module"), cfg):
            return True
    return not saw_marker


def scan_globals(src_dir: Path, cfg: ProjectConfig | None = None) -> ScanResult:
    """Scan reversed source files for global declarations.

    Collects:
    1. ``// GLOBAL: MODULE 0xVA`` reccmp annotations (+ next line for declaration)
    2. ``extern <type> <name>;`` data globals (via tree-sitter, filtering functions)

    Returns a ScanResult with all discovered globals and type conflicts;
    every entry of a conflicting name has ``conflict`` set.

    With *cfg*, another target's ``// GLOBAL:`` / ``// DATA:`` marker is
    omitted, and the declaration under it is not re-listed as an extern.
    A file whose markers are all another target's contributes nothing.
    Library-module markers stay: they are not targets.
    """
    from rebrew.c_parser import find_extern_variables
    from rebrew.sources import iter_sources
    from rebrew.utils import rel_display_path

    result = ScanResult()
    # Track all type declarations per name for conflict detection
    type_by_name: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    # Globals key by (name, va): the same name annotated at two VAs in two
    # files is two globals (a TU-local collision), not one entry whose
    # second annotation is skipped.
    by_key: dict[tuple[str, int], GlobalEntry] = {}
    # Name → one entry with that name (same as former linear scan over values).
    by_name: dict[str, GlobalEntry] = {}
    # Name → every entry (for conflict marking without rescanning by_key).
    entries_by_name: dict[str, list[GlobalEntry]] = defaultdict(list)

    if not src_dir.exists():
        return result

    def _remember(entry: GlobalEntry, key: tuple[str, int]) -> None:
        by_key[key] = entry
        by_name[entry.name] = entry
        bucket = entries_by_name[entry.name]
        if not any(e is entry for e in bucket):
            bucket.append(entry)

    for cfile in iter_sources(src_dir, cfg):
        try:
            # Tolerant read: a legacy-encoded source must not have its
            # non-ASCII bytes silently deleted, which would corrupt string
            # literals, comments, and GLOBAL:/DATA: scans.
            text, _ = read_source_text(cfile)
        except OSError:
            continue

        lines = text.splitlines()
        fname = rel_display_path(cfile, src_dir)
        if not _source_visible_to_target(lines, cfg):
            continue

        # A shared file annotates one global per target, each marker followed
        # by its own declaration. Skipping the marker is not enough: the
        # declaration is still an extern, and the last target's name was
        # listed on every target (guild-rebrew `g_6624a0` under GOLD and
        # GOLDTL showed up on the server with no VA). Blank those lines for
        # the extern pass only; the marker walk below still sees them.
        foreign_decl_lines: set[int] = set()
        if cfg is not None:
            for i, line in enumerate(lines):
                gm = _GLOBAL_RE.search(line)
                if (
                    gm
                    and not module_visible_to_target(gm.group("module"), cfg)
                    and i + 1 < len(lines)
                ):
                    foreign_decl_lines.add(i + 1)
        extern_text = text
        if foreign_decl_lines:
            extern_text = "\n".join(
                "" if i in foreign_decl_lines else line for i, line in enumerate(lines)
            )

        # Pre-compute extern variables from tree-sitter (used for unannotated
        # scan).  Definitions are included: a global's real type lives on its
        # definition, and conflict detection that only sees `extern` lines
        # cannot report the mismatch that matters most -- `int g[4] = {...}`
        # in one file against `extern short g;` in another.
        extern_vars = {
            v.name: v for v in find_extern_variables(extern_text, include_definitions=True)
        }

        # Track which names are already handled via GLOBAL annotation
        annotated_names: set[str] = set()

        for i, line in enumerate(lines):
            # 1. Check for // GLOBAL: annotation
            gm = _GLOBAL_RE.search(line)
            if gm:
                # Marker-scope the scan when the module is another TARGET's
                # marker: the same global name sits at a different VA in each
                # binary, and an unscoped scan let the last marker win the
                # name in every target's VA map (guild-rebrew round 1292:
                # GOLDTL's log tables resolved to the SERVER VAs, failing
                # DIR32 validation on bytes that are correct for the client).
                # Library-module markers (MSVCRT, ZLIB, ...) are kept: they
                # are not targets and carry no competing VA.
                if cfg is not None and not module_visible_to_target(gm.group("module"), cfg):
                    continue
                va = int(gm.group("va"), 16)
                # Next line should be the declaration
                decl = lines[i + 1].strip() if i + 1 < len(lines) else ""
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

                # Last resort: the metadata.  A marker may legitimately have no
                # declaration under it -- it annotates a global defined in
                # another TU, or one the source only reaches through a pointer
                # -- and rebrew-data.toml is where that global's name/type/
                # section already live.  Without this the entry lands as
                # "unknown" with no section, which is what made 53 of
                # guild-rebrew's 118 markers unattributable.
                meta = _data_meta(cfg, gm.group("module"), va)
                if meta:
                    if name == "unknown" and meta.get("name"):
                        name = str(meta["name"])
                    if not type_str and meta.get("type"):
                        type_str = str(meta["type"])

                # Warn only when nothing could name it -- neither the source
                # nor the metadata.  Warning on "no declaration on the next
                # line" alone cried wolf on every marker that the metadata
                # resolves perfectly well.
                if name == "unknown":
                    warnings.warn(
                        f"{fname}:{i + 1}: data annotation at 0x{va:08x} has no "
                        f"declaration on the following line and no name in the "
                        f"data metadata",
                        stacklevel=2,
                    )

                key = (name, va)
                annotated_names.add(name)

                entry = by_key.get(key)
                if entry is None:
                    # An extern-only (name, 0) entry from an earlier file is
                    # the same global awaiting its VA — adopt it rather than
                    # forking a duplicate.
                    entry = by_key.pop((name, 0), None)
                    if entry is not None:
                        entry.va = va
                        entry.annotated = True
                        _remember(entry, key)
                    else:
                        entry = GlobalEntry(name=name, va=va, type_str=type_str, annotated=True)
                        _remember(entry, key)
                else:
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

            key = (ev_name, 0)
            entry = by_key.get(key)
            if entry is None:
                # An earlier file may already hold this name as an annotated
                # entry whose VA is known.  Reuse it: creating a duplicate
                # ``(name, 0)`` key would make the final pass overwrite the
                # annotated entry with the valueless one (order-dependent —
                # an extern-only file sorted after the annotated one lost it).
                entry = by_name.get(ev_name)
            if entry is None:
                entry = GlobalEntry(name=ev_name, type_str=ev.type_str)
                _remember(entry, key)

            if fname not in entry.declared_in:
                entry.declared_in.append(fname)

            if ev.type_str:
                type_by_name[ev_name][ev.type_str].append(fname)

    for (name, va), entry in by_key.items():
        if va and name in result.globals and result.globals[name] is not entry:
            result.globals[f"{name}@0x{va:x}"] = entry
        else:
            result.globals[name] = entry

    # Detect type conflicts: same name, different type strings.
    #
    # Compare on a whitespace-normalised key, so `char *` and `char*` are one
    # type rather than a reported conflict.  Spelling a pointer either way is a
    # style difference that no compiler can see, and mixing real conflicts with
    # cosmetic ones is what makes a report like this get ignored.  The original
    # spellings are still what the conflict carries, since the point is to show
    # where each came from.
    for name, types in type_by_name.items():
        if len({" ".join(t.split()).replace(" *", "*") for t in types}) > 1:
            conflict = {
                "name": name,
                "types": dict(types),
            }
            result.type_conflicts.append(conflict)
            for entry in entries_by_name.get(name, ()):
                entry.conflict = True

    return result


def scan_data_annotations(src_dir: Path, cfg: ProjectConfig | None = None) -> list[dict[str, Any]]:
    """Scan for ``// DATA: MODULE 0xVA`` annotations in source files.

    These mark standalone global data objects for tracking in the catalog.
    SIZE/SECTION/NOTE are overlaid from ``rebrew-data.toml`` metadata if present.
    Returns a list of dicts with: va, name, size, section, note, filepath.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.data_metadata import merge_into_data_annotation
    from rebrew.sources import iter_sources, target_marker
    from rebrew.utils import rel_display_path

    entries: list[dict[str, Any]] = []
    if not src_dir.exists():
        return entries

    for cfile in iter_sources(src_dir, cfg):
        rel_name = rel_display_path(cfile, src_dir)
        for ann in parse_c_file_multi(
            cfile, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir if cfg else None
        ):
            if ann.is_data:
                # Metadata root is cfg.metadata_dir; cfile.parent would
                # silently no-op the overlay when the two dirs differ.
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


def build_dispatch_known_functions(cfg: ProjectConfig, src_dir: Path) -> dict[int, dict[str, str]]:
    """Map VA -> {"name", "status"} for dispatch-table naming.

    Source-file annotations take precedence; the function list / Ghidra
    structure registry then fills in targets no source file covers (e.g.
    FLIRT-identified CRT functions).  A "0% resolved" table is misleading
    when the catalog already knows the names.

    Shared by ``rebrew data --dispatch`` and ``rebrew analyze``'s dossier, so
    both report the same resolution count.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import iter_sources, target_marker
    from rebrew.utils import rel_display_path

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
        from rebrew.catalog import build_function_registry, cached_function_list

        funcs = cached_function_list(cfg)
        registry = build_function_registry(
            funcs, cfg, inventory_path_for(cfg.reversed_dir, cfg), cfg.target_binary
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
        info: Optional BinaryInfo; enables NE-aware section selection and
            decodes pointers in its byte order (``endian == "big"``).

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

    byte_order = ">" if getattr(info, "endian", "") == "big" else "<"
    fmt = byte_order + ("I" if ptr_size == 4 else "Q")
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


# Smaller BSS gaps are alignment padding, not an undeclared global.
_BSS_GAP_BYTES_MIN = 4


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

    # Shared type-size model (data_layout) — the same table that sizes
    # materialized definitions, so coverage estimates cannot drift.
    from rebrew.data_layout import estimate_type_size

    # Collect BSS globals (those with VAs in the .bss range)
    bss_entries: list[BssEntry] = []
    for entry in scan.globals.values():
        if entry.va and bss_va <= entry.va < bss_end:
            size_hint = estimate_type_size(entry.type_str) if entry.type_str else 4
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
        if gap_size >= _BSS_GAP_BYTES_MIN:
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
            if gap_size >= _BSS_GAP_BYTES_MIN:
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
