#!/usr/bin/env python3
"""validate.py - Core traceability pipeline for rebrew RE project.

Parses annotations from server_dll/*.c files, reads r2_functions.txt for the
full function list, optionally verifies against original/Server/server.dll, and generates
CATALOG.md + recoverage/data.json.

Supports both OLD format:
    /* func_name @ 0x10001000 (302B) - /O2 - EXACT MATCH [GAME] */
and NEW reccmp-style format:
    // FUNCTION: SERVER 0x10001000
    // STATUS: EXACT
    // ORIGIN: GAME
    // SIZE: 302
    // CFLAGS: /O2 /Gd
    // SYMBOL: _func_name
"""

import typer
from typing import Optional
import hashlib
import json
import math
import os
import re
import struct
import pefile
import subprocess
import sys
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
IMAGE_BASE = 0x10000000
TEXT_VA = 0x10001000
TEXT_RAW_OFFSET = 0x1000

VALID_STATUSES = {"EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB"}
VALID_ORIGINS = {"GAME", "MSVCRT", "ZLIB"}
VALID_MARKERS = {"FUNCTION", "LIBRARY", "STUB"}

# ---------------------------------------------------------------------------
# Data classes (plain dicts for stdlib-only)
# ---------------------------------------------------------------------------


def make_func_entry(
    va: int,
    size: int,
    name: str,
    symbol: str,
    status: str,
    origin: str,
    cflags: str,
    marker_type: str,
    filepath: str,
    source: str = "",
    blocker: str = "",
    note: str = "",
    globals_list: Optional[List[str]] = None,
) -> dict:
    return {
        "va": va,
        "size": size,
        "name": name,
        "symbol": symbol,
        "status": status,
        "origin": origin,
        "cflags": cflags,
        "marker_type": marker_type,
        "filepath": filepath,
        "source": source,
        "blocker": blocker,
        "note": note,
        "globals": globals_list or [],
    }


def make_r2_func(va: int, size: int, r2_name: str) -> dict:
    return {"va": va, "size": size, "r2_name": r2_name}


def make_ghidra_func(va: int, size: int, name: str) -> dict:
    return {"va": va, "size": size, "ghidra_name": name}


# ---------------------------------------------------------------------------
# Cross-tool function registry
# ---------------------------------------------------------------------------

# IAT thunk addresses (6B jmp [addr] stubs -- not reversible C code)
IAT_THUNKS = {
    0x1001A160,
    0x1001A166,
    0x1001A16C,
    0x1001A172,
    0x1001A178,
    0x1001A17E,
    0x1001A184,
    0x10023840,
}

# DLL exports (from DUMPBIN /EXPORTS)
DLL_EXPORTS = {
    0x10009320: "Init",
    0x10009350: "Exit",
}

# r2 entries with known bogus sizes (analysis artifacts)
R2_BOGUS_SIZES = {0x1000AD40, 0x10018200}


def build_function_registry(
    r2_funcs: List[dict],
    ghidra_path: Optional[Path] = None,
) -> Dict[int, dict]:
    """Build a unified function registry merging r2 + ghidra + exports.

    Returns dict keyed by VA with:
        detected_by: list of tool names
        size_by_tool: {tool: size}
        r2_name / ghidra_name: tool-specific names
        is_thunk: bool
        is_export: bool
        canonical_size: best-known size
    """
    registry: Dict[int, dict] = {}

    # --- r2 functions ---
    for func in r2_funcs:
        va = func["va"]
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "r2_name": "",
                "ghidra_name": "",
                "is_thunk": va in IAT_THUNKS,
                "is_export": va in DLL_EXPORTS,
                "canonical_size": 0,
            },
        )
        entry["detected_by"].append("r2")
        r2_size = func["size"]
        if va not in R2_BOGUS_SIZES:
            entry["size_by_tool"]["r2"] = r2_size
        entry["r2_name"] = func["r2_name"]

    # --- Ghidra functions (from cached JSON) ---
    ghidra_funcs = []
    if ghidra_path and ghidra_path.exists():
        try:
            ghidra_funcs = json.loads(ghidra_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    for func in ghidra_funcs:
        va = func["va"]
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "r2_name": "",
                "ghidra_name": "",
                "is_thunk": va in IAT_THUNKS,
                "is_export": va in DLL_EXPORTS,
                "canonical_size": 0,
            },
        )
        if "ghidra" not in entry["detected_by"]:
            entry["detected_by"].append("ghidra")
        entry["size_by_tool"]["ghidra"] = func["size"]
        entry["ghidra_name"] = func["ghidra_name"]

    # --- Exports ---
    for va, name in DLL_EXPORTS.items():
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "r2_name": "",
                "ghidra_name": "",
                "is_thunk": False,
                "is_export": True,
                "canonical_size": 0,
            },
        )
        if "exports" not in entry["detected_by"]:
            entry["detected_by"].append("exports")

    # --- Resolve canonical size: prefer ghidra > r2 ---
    for va, entry in registry.items():
        sizes = entry["size_by_tool"]
        if "ghidra" in sizes:
            entry["canonical_size"] = sizes["ghidra"]
        elif "r2" in sizes:
            entry["canonical_size"] = sizes["r2"]

    return registry


def load_ghidra_functions(path: Path) -> List[dict]:
    """Load cached ghidra_functions.json."""
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


# ---------------------------------------------------------------------------
# Annotation parsers
# ---------------------------------------------------------------------------

# OLD format: /* name @ 0xVA (NB) - /flags - STATUS [ORIGIN] */
_OLD_RE = re.compile(
    r"/\*\s*"
    r"(?P<name>\S+)"
    r"\s+@\s+"
    r"(?P<va>0x[0-9a-fA-F]+)"
    r"\s+\((?P<size>\d+)B\)"
    r"\s*-\s*"
    r"(?P<cflags>[^-]+?)"
    r"\s*-\s*"
    r"(?P<status>[^[]+?)"
    r"\s*\[(?P<origin>[A-Z]+)\]"
    r"\s*\*/"
)

# NEW format markers
_NEW_FUNC_RE = re.compile(
    r"//\s*(?P<type>FUNCTION|LIBRARY|STUB):\s*(?P<target>[A-Z0-9_]+)\s+(?P<va>0x[0-9a-fA-F]+)"
)
_NEW_KV_RE = re.compile(r"//\s*(?P<key>[A-Z]+):\s*(?P<value>.+)")


def _normalize_status(raw: str) -> str:
    """Map old-format status strings to canonical values."""
    s = raw.strip().upper()
    if "EXACT" in s:
        return "EXACT"
    if "RELOC" in s:
        return "RELOC"
    if "STUB" in s:
        return "STUB"
    return s


def _normalize_cflags(raw: str) -> str:
    """Clean up cflags string."""
    return raw.strip().rstrip(",").strip()


def parse_old_format(line: str) -> Optional[dict]:
    """Try to parse old-format header comment. Returns dict or None."""
    m = _OLD_RE.match(line.strip())
    if not m:
        return None
    status = _normalize_status(m.group("status"))
    origin = m.group("origin").strip().upper()
    cflags = _normalize_cflags(m.group("cflags"))
    name = m.group("name")

    # Derive marker type from origin
    if status == "STUB":
        marker_type = "STUB"
    elif origin in ("ZLIB", "MSVCRT"):
        marker_type = "LIBRARY"
    else:
        marker_type = "FUNCTION"

    return make_func_entry(
        va=int(m.group("va"), 16),
        size=int(m.group("size")),
        name=name,
        symbol="_" + name,
        status=status,
        origin=origin,
        cflags=cflags,
        marker_type=marker_type,
        filepath="",
    )


def parse_new_format(lines: List[str]) -> Optional[dict]:
    """Try to parse new reccmp-style annotations from first lines.
    Returns dict or None."""
    # Find the marker line
    marker_type = None
    va = None
    kv = {}

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Check for marker
        m = _NEW_FUNC_RE.match(stripped)
        if m:
            marker_type = m.group("type")
            va = int(m.group("va"), 16)
            continue
        # Check for key-value
        m2 = _NEW_KV_RE.match(stripped)
        if m2:
            kv[m2.group("key").upper()] = m2.group("value").strip()
            continue
        # Non-annotation line => stop
        break

    if marker_type is None or va is None:
        return None

    status = kv.get("STATUS", "RELOC")
    origin = kv.get("ORIGIN", "GAME")
    size_str = kv.get("SIZE", "0")
    cflags = kv.get("CFLAGS", "")
    symbol = kv.get("SYMBOL", "")
    name = symbol.lstrip("_") if symbol else ""

    try:
        size = int(size_str)
    except ValueError:
        size = 0

    source = kv.get("SOURCE", "")
    blocker = kv.get("BLOCKER", "")
    note = kv.get("NOTE", "")

    globals_list = []
    raw_globals = kv.get("GLOBALS", "")
    if raw_globals:
        globals_list = [g.strip() for g in raw_globals.split(",") if g.strip()]

    return make_func_entry(
        va=va,
        size=size,
        name=name,
        symbol=symbol,
        status=status,
        origin=origin,
        cflags=cflags,
        marker_type=marker_type,
        filepath="",
        source=source,
        blocker=blocker,
        note=note,
        globals_list=globals_list,
    )


def parse_c_file(filepath: Path) -> Optional[dict]:
    """Parse a decomp .c file for annotations (tries new then old format)."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    lines = text.splitlines()
    if not lines:
        return None

    # Try new format first (multi-line)
    entry = parse_new_format(lines[:20])
    if entry is not None:
        entry["filepath"] = filepath.name
        return entry

    # Try old format (first line)
    entry = parse_old_format(lines[0])
    if entry is not None:
        entry["filepath"] = filepath.name
        return entry

    return None


# ---------------------------------------------------------------------------
# r2_functions.txt parser
# ---------------------------------------------------------------------------

_R2_LINE_RE = re.compile(r"\s*(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)")


def parse_r2_functions(path: Path) -> List[dict]:
    """Parse r2_functions.txt into list of {va, size, r2_name}."""
    funcs = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        print(f"WARNING: Cannot read {path}", file=sys.stderr)
        return funcs

    for line in text.splitlines():
        m = _R2_LINE_RE.match(line)
        if m:
            funcs.append(
                make_r2_func(
                    va=int(m.group(1), 16),
                    size=int(m.group(2)),
                    r2_name=m.group(3),
                )
            )
    return funcs


# ---------------------------------------------------------------------------
# DLL byte extraction
# ---------------------------------------------------------------------------


def extract_dll_bytes(dll_path: Path, file_offset: int, size: int) -> Optional[bytes]:
    """Extract raw bytes from DLL at given file offset."""
    try:
        with open(dll_path, "rb") as f:
            f.seek(file_offset)
            data = f.read(size)
        # Trim trailing CC/90 padding
        while data and data[-1] in (0xCC, 0x90):
            data = data[:-1]
        return data
    except (OSError, ValueError):
        return None


# COFF .obj parsing: imported from canonical source
from rebrew.matcher.parsers import parse_coff_symbol_bytes


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_reversed_dir(reversed_dir: Path) -> List[dict]:
    """Scan target dir *.c files and parse annotations from each."""
    entries = []
    for cfile in sorted(reversed_dir.glob("*.c")):
        if cfile.name in ("test_func.py",):
            continue
        entry = parse_c_file(cfile)
        if entry is not None:
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# CATALOG.md generation
# ---------------------------------------------------------------------------


def generate_catalog(
    entries: List[dict],
    r2_funcs: List[dict],
    text_size: int,
) -> str:
    """Generate CATALOG.md content."""
    # Deduplicate by VA (keep first occurrence per VA)
    by_va: Dict[int, List[dict]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    unique_vas = set(by_va.keys())
    exact_count = sum(
        1 for vas in by_va.values() if any(e["status"] == "EXACT" for e in vas)
    )
    reloc_count = sum(
        1 for vas in by_va.values() if all(e["status"] == "RELOC" for e in vas)
    )
    stub_count = sum(
        1 for vas in by_va.values() if all(e["status"] == "STUB" for e in vas)
    )

    # Coverage bytes
    r2_by_va = {f["va"]: f for f in r2_funcs}
    covered_bytes = 0
    for va in unique_vas:
        if va in r2_by_va:
            covered_bytes += r2_by_va[va]["size"]
        elif by_va[va]:
            covered_bytes += by_va[va][0]["size"]

    total_funcs = len(r2_funcs)
    matched_count = len(unique_vas)
    coverage_pct = (covered_bytes / text_size * 100.0) if text_size else 0.0

    lines = []
    lines.append("# Reversed Functions Catalog\n")
    lines.append(
        f"Total: {matched_count}/{total_funcs} functions matched "
        f"({exact_count} exact, {reloc_count} reloc-normalized, {stub_count} stubs)  "
    )
    lines.append(
        f"Coverage: {coverage_pct:.1f}% of .text section "
        f"({covered_bytes}/{text_size} bytes)\n"
    )

    # Group by origin
    by_origin: Dict[str, List[dict]] = {"GAME": [], "ZLIB": [], "MSVCRT": []}
    for e in entries:
        origin = e["origin"]
        if origin not in by_origin:
            by_origin[origin] = []
        by_origin[origin].append(e)

    for origin in ("GAME", "ZLIB", "MSVCRT"):
        group = sorted(by_origin.get(origin, []), key=lambda x: x["va"])
        lines.append(f"\n## {origin} ({len(group)} functions)\n")
        lines.append("| VA | Size | Name | Symbol | Flags | Match | File |")
        lines.append("|-----|------|------|--------|-------|-------|------|")
        for e in group:
            va_str = f"0x{e['va']:08X}"
            match_str = f"{e['marker_type']}/{e['status']}"
            lines.append(
                f"| {va_str} | {e['size']}B | {e['name']} | "
                f"{e['symbol']} | {e['cflags']} | {match_str} | {e['filepath']} |"
            )

    # Unmatched functions
    unmatched = [f for f in r2_funcs if f["va"] not in unique_vas]
    unmatched.sort(key=lambda x: x["va"])
    lines.append(f"\n## Unmatched Functions ({len(unmatched)} remaining)\n")
    lines.append("| VA | Size | r2 Name |")
    lines.append("|-----|------|---------|")
    for f in unmatched:
        lines.append(f"| 0x{f['va']:08X} | {f['size']}B | {f['r2_name']} |")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# data.json generation (for coverage dashboard)
# ---------------------------------------------------------------------------


def merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not ranges:
        return []
    ranges = sorted(ranges)
    out = [list(ranges[0])]
    for s, e in ranges[1:]:
        last = out[-1]
        if s <= last[1]:
            last[1] = max(last[1], e)
        else:
            out.append([s, e])
    return [(a, b) for a, b in out]


def generate_data_json(
    entries: List[dict],
    r2_funcs: List[dict],
    text_size: int,
    dll_path: Optional[Path] = None,
    registry: Optional[Dict[int, dict]] = None,
    src_dir: Optional[Path] = None,
    root_dir: Optional[Path] = None,
) -> dict:
    """Generate recoverage/data.json structure."""
    by_va: Dict[int, List[dict]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    unique_vas = set(by_va.keys())
    r2_by_va = {f["va"]: f for f in r2_funcs}

    exact_count = sum(
        1 for vas in by_va.values() if any(e["status"] == "EXACT" for e in vas)
    )
    reloc_count = sum(
        1 for vas in by_va.values() if all(e["status"] == "RELOC" for e in vas)
    )
    matching_count = sum(
        1 for vas in by_va.values() if any(e["status"] == "MATCHING" for e in vas)
    )
    stub_count = sum(
        1 for vas in by_va.values() if any(e["status"] == "STUB" for e in vas)
    )

    covered_bytes = 0
    for va in unique_vas:
        if registry and va in registry:
            covered_bytes += registry[va]["canonical_size"]
        elif va in r2_by_va:
            covered_bytes += r2_by_va[va]["size"]
        elif by_va[va]:
            covered_bytes += by_va[va][0]["size"]

    coverage_pct = (covered_bytes / text_size * 100.0) if text_size else 0.0

    sections = get_sections(dll_path) if dll_path else {}
    globals_dict = get_globals(src_dir) if src_dir else {}

    # Fallback if pefile fails
    if ".text" not in sections:
        sections[".text"] = {
            "va": IMAGE_BASE + TEXT_RAW_OFFSET,
            "size": text_size,
            "fileOffset": TEXT_RAW_OFFSET,
        }

    functions = {}
    for va in sorted(unique_vas):
        elist = by_va[va]
        e = elist[0]

        # Find which section this VA belongs to
        sec_name = ".text"
        file_off = 0
        text_off = 0
        for sname, sdata in sections.items():
            if sdata["va"] <= va < sdata["va"] + sdata["size"]:
                sec_name = sname
                file_off = sdata["fileOffset"] + (va - sdata["va"])
                text_off = va - sdata["va"]
                break

        # Fallback if not found in any section
        if file_off == 0:
            file_off = va - IMAGE_BASE
            text_off = file_off - TEXT_RAW_OFFSET

        reg = registry.get(va, {}) if registry else {}
        canonical_size = reg.get("canonical_size", 0)
        if not canonical_size:
            canonical_size = r2_by_va[va]["size"] if va in r2_by_va else e["size"]

        fn_hash = ""
        if dll_path and dll_path.exists():
            raw = extract_dll_bytes(dll_path, file_off, canonical_size)
            if raw:
                fn_hash = hashlib.sha256(raw).hexdigest()

        functions[e["name"]] = {
            "name": e["name"],
            "vaStart": f"0x{va:08x}",
            "size": canonical_size,
            "status": e["status"],
            "origin": e["origin"],
            "markerType": e["marker_type"],
            "cflags": e["cflags"],
            "symbol": e["symbol"],
            "fileOffset": file_off,
            "textOffset": text_off,
            "sha256": fn_hash,
            "files": [x["filepath"] for x in elist],
            "detected_by": reg.get("detected_by", []),
            "size_by_tool": reg.get("size_by_tool", {}),
            "ghidra_name": reg.get("ghidra_name", ""),
            "r2_name": reg.get("r2_name", ""),
            "is_thunk": reg.get("is_thunk", False),
            "is_export": reg.get("is_export", False),
        }

    # Generate cells for each section
    for sec_name, sec_data in sections.items():
        if sec_name not in [".text", ".rdata", ".data", ".bss"]:
            continue

        sec_va = sec_data["va"]
        sec_size = sec_data["size"]
        if sec_name == ".text":
            unit_bytes = 64
        elif sec_name == ".bss":
            unit_bytes = 4096
        else:
            unit_bytes = 16
        columns = 64

        items_by_off = {}
        if sec_name == ".text":
            for fname, fdata in functions.items():
                off = int(fdata["vaStart"], 16) - sec_va
                if 0 <= off < sec_size:
                    items_by_off[off] = {
                        "size": fdata["size"],
                        "status": fdata["status"],
                        "name": fname,
                    }
        else:
            for va, gdata in globals_dict.items():
                off = va - sec_va
                if 0 <= off < sec_size:
                    items_by_off[off] = {
                        "size": 4,
                        "status": "EXACT",
                        "name": gdata["name"],
                    }  # Default size 4 for globals

        item_starts = sorted(items_by_off.keys())
        segments = []
        off = 0
        idx = 0

        while off < sec_size:
            while idx < len(item_starts) and item_starts[idx] < off:
                idx += 1

            if idx < len(item_starts) and item_starts[idx] == off:
                item = items_by_off[off]
                s = off
                e = min(sec_size, off + item["size"])
                state = item["status"].lower()
                segments.append((s, e, state, [item["name"]]))
                off = e
                continue

            next_off = item_starts[idx] if idx < len(item_starts) else sec_size
            gap_end = min(sec_size, off + unit_bytes, next_off)
            segments.append((off, gap_end, "none", []))
            off = gap_end

        cells = []
        col = 0
        for seg_start, seg_end, state, seg_fns in segments:
            remaining = seg_end - seg_start
            seg_cols = max(1, int(math.ceil(remaining / unit_bytes)))
            cur = seg_start
            cols_left = seg_cols

            while cols_left > 0:
                take_cols = min(cols_left, columns - col)
                if take_cols <= 0:
                    take_cols = columns
                    col = 0
                take_bytes = min(seg_end - cur, take_cols * unit_bytes)
                span = max(1, int(math.ceil(take_bytes / unit_bytes)))
                cell_end = cur + take_bytes
                cells.append(
                    {
                        "start": cur,
                        "end": cell_end,
                        "span": span,
                        "state": state,
                        "functions": seg_fns,
                    }
                )
                col = (col + span) % columns
                cols_left -= span
                cur = cell_end

        sec_data["cells"] = cells
        sec_data["unitBytes"] = unit_bytes
        sec_data["columns"] = columns

    return {
        "sections": sections,
        "globals": globals_dict,
        "paths": {
            "originalDll": f"/{dll_path.relative_to(root_dir)}"
            if dll_path and root_dir
            else "",
        },
        "summary": {
            "totalFunctions": len(r2_funcs),
            "matchedFunctions": len(unique_vas),
            "exactMatches": exact_count,
            "relocMatches": reloc_count,
            "matchingMatches": matching_count,
            "stubCount": stub_count,
            "coveredBytes": covered_bytes,
            "coveragePercent": round(coverage_pct, 2),
            "textSize": text_size,
        },
        "functions": functions,
    }

    # Build defrag cells
    unit_bytes = 64
    columns = 64

    # Map text offsets for matched functions
    fn_by_text_off: Dict[int, dict] = {}
    for fname, fdata in functions.items():
        fn_by_text_off[fdata["textOffset"]] = fdata

    fn_starts = sorted(fn_by_text_off.keys())

    segments: List[Tuple[int, int, str, List[str]]] = []
    off = 0
    idx = 0
    while off < text_size:
        while idx < len(fn_starts) and fn_starts[idx] < off:
            idx += 1

        if idx < len(fn_starts) and fn_starts[idx] == off:
            fn = fn_by_text_off[off]
            s = off
            e = min(text_size, off + fn["size"])
            state = fn["status"].lower()
            segments.append((s, e, state, [fn["name"]]))
            off = e
            continue

        next_fn_off = fn_starts[idx] if idx < len(fn_starts) else text_size
        gap_end = min(text_size, off + unit_bytes, next_fn_off)
        segments.append((off, gap_end, "none", []))
        off = gap_end

    cells = []
    col = 0
    for seg_start, seg_end, state, seg_fns in segments:
        remaining = seg_end - seg_start
        seg_cols = max(1, int(math.ceil(remaining / unit_bytes)))
        cur = seg_start
        cols_left = seg_cols

        while cols_left > 0:
            take_cols = min(cols_left, columns - col)
            if take_cols <= 0:
                take_cols = columns
                col = 0
            take_bytes = min(seg_end - cur, take_cols * unit_bytes)
            span = max(1, int(math.ceil(take_bytes / unit_bytes)))
            cell_end = cur + take_bytes
            cells.append(
                {
                    "start": cur,
                    "end": cell_end,
                    "span": span,
                    "state": state,
                    "functions": seg_fns,
                }
            )
            col = (col + span) % columns
            cols_left -= span
            cur = cell_end

    return {
        "textSize": text_size,
        "unitBytes": unit_bytes,
        "columns": columns,
        "paths": {
            "originalDll": f"/{dll_path.relative_to(root_dir)}"
            if dll_path and root_dir
            else "",
        },
        "summary": {
            "totalFunctions": len(r2_funcs),
            "matchedFunctions": len(unique_vas),
            "exactMatches": exact_count,
            "relocMatches": reloc_count,
            "matchingMatches": matching_count,
            "stubCount": stub_count,
            "coveredBytes": covered_bytes,
            "coveragePercent": round(coverage_pct, 2),
        },
        "functions": functions,
        "cells": cells,
    }


# ---------------------------------------------------------------------------
# reccmp-compatible CSV generation
# ---------------------------------------------------------------------------


def _reccmp_type(entry: dict) -> str:
    """Map our marker_type + origin to reccmp entity type."""
    if entry["marker_type"] == "STUB":
        return "stub"
    if entry["origin"] in ("ZLIB", "MSVCRT"):
        return "library"
    return "function"


def generate_reccmp_csv(
    entries: List[dict],
    r2_funcs: List[dict],
    registry: Optional[Dict[int, dict]] = None,
    target_name: str = "SERVER",
) -> str:
    """Generate reccmp-compatible pipe-delimited CSV.

    Format per https://github.com/isledecomp/reccmp/blob/master/docs/csv.md:
      address|name|symbol|type|size

    Includes ALL known functions (matched + unmatched), so the CSV serves as
    a complete function catalog for the binary.  Comments and blank lines are
    allowed by the reccmp spec.
    """
    by_va: Dict[int, dict] = {}
    for e in entries:
        if e["va"] not in by_va:
            by_va[e["va"]] = e

    r2_by_va = {f["va"]: f for f in r2_funcs}

    lines: List[str] = []
    lines.append(f"# reccmp-compatible function catalog for {target_name}")
    lines.append("# Generated by validate.py — do not edit manually")
    lines.append("#")
    lines.append("# Columns: address (hex) | name | symbol | type | size (decimal)")
    lines.append("")
    lines.append("address|name|symbol|type|size")

    # Collect all known VAs from registry + annotations
    all_vas: set = set()
    if registry:
        all_vas.update(registry.keys())
    all_vas.update(by_va.keys())
    all_vas.update(r2_by_va.keys())

    for va in sorted(all_vas):
        va_hex = f"0x{va:08x}"

        if va in by_va:
            e = by_va[va]
            name = e["name"]
            symbol = e["symbol"]
            etype = _reccmp_type(e)
            # Use canonical size from registry if available
            size = e["size"]
            if registry and va in registry:
                cs = registry[va].get("canonical_size", 0)
                if cs > 0:
                    size = cs
            lines.append(f"{va_hex}|{name}|{symbol}|{etype}|{size}")
        else:
            # Unmatched function — pull name from Ghidra/r2
            reg = registry.get(va, {}) if registry else {}
            name = ""
            if reg.get("ghidra_name", ""):
                gn = reg["ghidra_name"]
                if not gn.startswith("FUN_"):
                    name = gn
            if not name and va in r2_by_va:
                rn = r2_by_va[va]["r2_name"]
                if not rn.startswith("fcn.") and not rn.startswith("sym."):
                    name = rn

            # Determine type
            is_thunk = reg.get("is_thunk", va in IAT_THUNKS)
            etype = "function"
            if is_thunk:
                etype = "stub"

            # Size
            size = reg.get("canonical_size", 0) if reg else 0
            if not size and va in r2_by_va:
                size = r2_by_va[va]["size"]

            symbol = f"_{name}" if name else ""
            size_str = str(size) if size > 0 else ""
            lines.append(f"{va_hex}|{name}|{symbol}|{etype}|{size_str}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Text section size
# ---------------------------------------------------------------------------


def get_sections(dll_path: Path) -> dict:
    try:
        pe = pefile.PE(str(dll_path))
        sections = {}
        for section in pe.sections:
            name = section.Name.decode("utf-8").rstrip("\x00")
            if pe.OPTIONAL_HEADER is not None and hasattr(
                pe.OPTIONAL_HEADER, "ImageBase"
            ):
                va = getattr(pe.OPTIONAL_HEADER, "ImageBase") + section.VirtualAddress
            else:
                va = section.VirtualAddress
            vsize = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData

            if name == ".data" and vsize > raw_size:
                sections[".data"] = {
                    "va": va,
                    "size": raw_size,
                    "fileOffset": section.PointerToRawData,
                }
                sections[".bss"] = {
                    "va": va + raw_size,
                    "size": vsize - raw_size,
                    "fileOffset": 0,
                }
            else:
                sections[name] = {
                    "va": va,
                    "size": vsize,
                    "fileOffset": section.PointerToRawData,
                }
        return sections
    except Exception as e:
        print(f"Warning: Failed to parse PE sections: {e}", file=sys.stderr)
        return {}


def get_globals(src_dir: Path) -> dict:
    globals_dict = {}
    pattern = re.compile(
        r"(?://|/\*)\s*GLOBAL:\s*(?P<target>[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)"
    )
    for p in src_dir.rglob("*.c"):
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            for i, line in enumerate(lines):
                m = pattern.search(line)
                if m:
                    va = int(m.group(2), 16)
                    decl = ""
                    if i + 1 < len(lines):
                        decl = lines[i + 1].strip()

                    name = "unknown"
                    name_m = re.search(
                        r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[.*\])?\s*;", decl
                    )
                    if name_m:
                        name = name_m.group(1)

                    if va not in globals_dict:
                        globals_dict[va] = {
                            "va": va,
                            "name": name,
                            "decl": decl,
                            "files": [p.name],
                        }
                    elif p.name not in globals_dict[va]["files"]:
                        globals_dict[va]["files"].append(p.name)
        except Exception:
            pass
    return globals_dict


def get_text_section_size(dll_path: Path) -> int:
    """Get .text section virtual size from PE headers."""
    try:
        with open(dll_path, "rb") as f:
            # DOS header -> PE offset
            f.seek(0x3C)
            pe_off = struct.unpack("<I", f.read(4))[0]
            # PE signature + COFF header
            f.seek(pe_off + 4)  # skip "PE\0\0"
            (num_sections,) = struct.unpack("<H", f.read(2))
            f.seek(pe_off + 4 + 20)  # skip COFF header (20 bytes)
            # Optional header size
            f.seek(pe_off + 4 + 16)
            (opt_hdr_size,) = struct.unpack("<H", f.read(2))
            # Section headers start after optional header
            sec_start = pe_off + 4 + 20 + opt_hdr_size
            for i in range(num_sections):
                f.seek(sec_start + i * 40)
                sec_name = f.read(8).rstrip(b"\x00").decode("ascii", errors="replace")
                if sec_name == ".text":
                    f.seek(sec_start + i * 40 + 8)  # VirtualSize
                    (vsize,) = struct.unpack("<I", f.read(4))
                    return vsize
    except (OSError, struct.error):
        pass
    # Fallback: estimate from r2_functions.txt last function
    return 0x24000  # rough estimate


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


app = typer.Typer(help="Rebrew validation pipeline: parse annotations, generate catalog and coverage data.")


@app.command()
def main(
    gen_json: bool = typer.Option(False, "--json", help="Generate recoverage/data.json"),
    catalog: bool = typer.Option(False, "--catalog", help="Generate server_dll/CATALOG.md"),
    summary: bool = typer.Option(False, "--summary", help="Print summary to stdout"),
    csv: bool = typer.Option(False, "--csv", help="Generate reccmp-compatible CSV"),
    export_ghidra: bool = typer.Option(False, "--export-ghidra", help="Cache Ghidra function list"),
    root: Path = typer.Option(
        Path(__file__).resolve().parent.parent,
        help="Project root directory",
    ),
    target: str = typer.Option("server_dll", "--target", "-t", help="Target name from rebrew.toml"),
):
    """Rebrew validation pipeline: parse annotations, generate catalog and coverage data."""
    try:
        from rebrew.config import load_config
        _c = load_config(root, target=target)
        dll_path = _c.target_binary
        reversed_dir = _c.reversed_dir
    except Exception:
        dll_path = root / "original" / "Server" / "server.dll"
        reversed_dir = root / "src" / "server_dll"

    r2_path = reversed_dir / "r2_functions.txt"
    ghidra_json_path = reversed_dir / "ghidra_functions.json"

    if not any(
        [
            catalog,
            gen_json,
            csv,
            summary,
            export_ghidra,
        ]
    ):
        catalog = True
        gen_json = True
        csv = True
        summary = True

    if export_ghidra:
        print(
            "To export Ghidra functions, run this in the MCP console:\n"
            f"  get-functions programPath=/{dll_path.name} filterDefaultNames=false\n"
            f"Then save the output as {reversed_dir.name}/ghidra_functions.json with format:\n"
            '  [{"va": 0x10001000, "size": 302, "ghidra_name": "FUN_10001000"}, ...]',
            file=sys.stderr,
        )
        return 0

    print(f"Scanning {reversed_dir}...", file=sys.stderr)
    entries = scan_reversed_dir(reversed_dir)
    r2_funcs = parse_r2_functions(r2_path)

    text_size = get_text_section_size(dll_path) if dll_path.exists() else 0x24000

    registry = build_function_registry(r2_funcs, ghidra_json_path)

    unique_vas = set(e["va"] for e in entries)
    ghidra_count = sum(1 for r in registry.values() if "ghidra" in r["detected_by"])
    r2_count = sum(1 for r in registry.values() if "r2" in r["detected_by"])
    both_count = sum(
        1
        for r in registry.values()
        if "ghidra" in r["detected_by"] and "r2" in r["detected_by"]
    )
    thunk_count = sum(1 for r in registry.values() if r["is_thunk"])
    print(
        f"Found {len(entries)} annotations ({len(unique_vas)} unique VAs) "
        f"from {len(registry)} total functions "
        f"(r2: {r2_count}, ghidra: {ghidra_count}, both: {both_count}, "
        f"thunks: {thunk_count})",
        file=sys.stderr,
    )

    if summary:
        by_origin = {}
        for e in entries:
            by_origin.setdefault(e["origin"], []).append(e)

        exact = sum(1 for e in entries if e["status"] == "EXACT")
        reloc = sum(1 for e in entries if e["status"] == "RELOC")
        print(f"\n=== Rebrew Status ===")
        print(f"Matched: {len(unique_vas)}/{len(registry)} functions")
        print(f"  EXACT: {exact}")
        print(f"  RELOC: {reloc}")
        for origin in ("GAME", "ZLIB", "MSVCRT"):
            count = len(by_origin.get(origin, []))
            print(f"  {origin}: {count}")

        covered = 0
        for va in unique_vas:
            if va in registry:
                covered += registry[va]["canonical_size"]
        pct = (covered / text_size * 100.0) if text_size else 0.0
        print(f"Coverage: {pct:.1f}% ({covered}/{text_size} bytes)")

        print(f"\n=== Tool Detection ===")
        print(
            f"  radare2 only: {sum(1 for r in registry.values() if r['detected_by'] == ['r2'])}"
        )
        print(
            f"  Ghidra only:  {sum(1 for r in registry.values() if r['detected_by'] == ['ghidra'])}"
        )
        print(f"  Both tools:   {both_count}")
        print(f"  IAT thunks:   {thunk_count}")
        size_mismatches = sum(
            1
            for r in registry.values()
            if "ghidra" in r["size_by_tool"]
            and "r2" in r["size_by_tool"]
            and r["size_by_tool"]["ghidra"] != r["size_by_tool"]["r2"]
        )
        print(f"  Size disagree: {size_mismatches}")

    if catalog:
        catalog = generate_catalog(entries, r2_funcs, text_size)
        catalog_path = reversed_dir / "CATALOG.md"
        catalog_path.write_text(catalog, encoding="utf-8")
        print(f"Wrote {catalog_path}", file=sys.stderr)

    if gen_json:
        data = generate_data_json(
            entries, r2_funcs, text_size, dll_path, registry, reversed_dir, root
        )
        coverage_dir = root / "recoverage"
        coverage_dir.mkdir(parents=True, exist_ok=True)
        json_path = coverage_dir / f"data_{target}.json"
        json_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {json_path}", file=sys.stderr)

    if csv:
        csv_text = generate_reccmp_csv(entries, r2_funcs, registry, target)
        csv_path = root / "recoverage" / f"{target.lower()}_functions.csv"
        csv_path.write_text(csv_text, encoding="utf-8")
        print(
            f"Wrote {csv_path} ({len(csv_text.splitlines()) - 6} functions)",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    app()
