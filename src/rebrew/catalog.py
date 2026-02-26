#!/usr/bin/env python3
"""catalog.py - Unified function catalog and reporting.

Merges r2 function lists, Ghidra export JSON, and local reversed .c files
into a single source of truth for progress tracking and batch operations.

Supports both OLD format:
    /* func_name @ 0x10001000 (302B) - /O2 - EXACT MATCH [GAME] */
and NEW reccmp-style format:
    // FUNCTION: [TARGET] 0x10001000
    // STATUS: EXACT
    // ORIGIN: GAME
    // SIZE: 302
    // CFLAGS: /O2 /Gd
    // SYMBOL: _func_name
"""

import contextlib
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import Annotation, parse_c_file_multi
from rebrew.binary_loader import load_binary

# make_func_entry and make_r2_func/make_ghidra_func are now imported from annotation.py
# and defined locally for backward compat


def make_r2_func(va: int, size: int, r2_name: str) -> dict[str, int | str]:
    return {"va": va, "size": size, "r2_name": r2_name}


def make_ghidra_func(va: int, size: int, name: str) -> dict[str, int | str]:
    return {"va": va, "size": size, "ghidra_name": name}


# Default r2 entries with known bogus sizes (analysis artifacts).
# Projects should define their own via r2_bogus_vas in rebrew.toml.
_DEFAULT_R2_BOGUS_SIZES: set[int] = set()


def _resolve_canonical_size(
    sizes: dict[str, int],
    va: int,
    text_data: bytes | None,
    text_va: int,
    text_size: int,
) -> tuple[int, str]:
    """When r2_size > ghidra_size, check if extra bytes are jump table / padding.

    Returns (canonical_size, reason_string).
    """
    ghidra_size = sizes.get("ghidra", 0)
    r2_size = sizes.get("r2", 0)

    if not ghidra_size and not r2_size:
        return 0, "none"

    if not ghidra_size:
        return r2_size, "r2 (only source)"
    if not r2_size:
        return ghidra_size, "ghidra (only source)"

    if ghidra_size >= r2_size:
        return ghidra_size, "ghidra (larger or equal)"

    # r2_size > ghidra_size — check if extra bytes are jump table / padding
    if text_data is None:
        return ghidra_size, "ghidra (no binary data to verify)"

    ghidra_end = va - text_va + ghidra_size
    r2_end = va - text_va + r2_size

    if ghidra_end < 0 or r2_end > len(text_data):
        return ghidra_size, "ghidra (extra bytes out of range)"

    extra = text_data[ghidra_end:r2_end]
    if not extra:
        return ghidra_size, "ghidra (no extra bytes)"

    # Check if extra bytes are NOP/INT3 padding
    if all(b in (0x90, 0xCC) for b in extra):
        return r2_size, "r2 (includes tail padding)"

    # Check if extra bytes are a jump table (array of .text pointers)
    if _is_jump_table(extra, text_va, text_size):
        return r2_size, "r2 (includes jump table)"

    # Check if extra bytes contain jumps back into the function body
    # (out-of-line code pattern: jmp/jcc targeting func_start..ghidra_end)
    func_start_off = va - text_va
    has_back_jump = False
    i = 0
    while i < len(extra):
        b = extra[i]
        # Near relative jmp (E9) or jcc (0F 8x)
        if b == 0xE9 and i + 5 <= len(extra):
            rel = struct.unpack_from("<i", extra, i + 1)[0]
            target = ghidra_end + i + 5 + rel
            if func_start_off <= target < ghidra_end:
                has_back_jump = True
                break
            i += 5
            continue
        if b == 0x0F and i + 6 <= len(extra) and 0x80 <= extra[i + 1] <= 0x8F:
            rel = struct.unpack_from("<i", extra, i + 2)[0]
            target = ghidra_end + i + 6 + rel
            if func_start_off <= target < ghidra_end:
                has_back_jump = True
                break
            i += 6
            continue
        # Short jmp (EB) or short jcc (7x)
        if b == 0xEB and i + 2 <= len(extra):
            rel = struct.unpack_from("<b", extra, i + 1)[0]
            target = ghidra_end + i + 2 + rel
            if func_start_off <= target < ghidra_end:
                has_back_jump = True
                break
            i += 2
            continue
        if 0x70 <= b <= 0x7F and i + 2 <= len(extra):
            rel = struct.unpack_from("<b", extra, i + 1)[0]
            target = ghidra_end + i + 2 + rel
            if func_start_off <= target < ghidra_end:
                has_back_jump = True
                break
            i += 2
            continue
        i += 1

    if has_back_jump:
        return r2_size, "r2 (includes out-of-line code)"

    # Default: trust Ghidra when we can't identify the extra bytes
    return ghidra_size, "ghidra (unrecognized extra bytes)"


def build_function_registry(
    r2_funcs: list[dict[str, Any]],
    cfg: Any,
    ghidra_path: Path | None = None,
    bin_path: Path | None = None,
) -> dict[int, dict[str, Any]]:
    """Build a unified function registry merging r2 + ghidra + exports.

    Returns dict keyed by VA with:
        detected_by: list of tool names
        size_by_tool: {tool: size}
        r2_name / ghidra_name: tool-specific names
        is_thunk: bool
        is_export: bool
        canonical_size: best-known size
    """
    registry: dict[int, dict[str, Any]] = {}

    # --- r2 functions ---
    r2_bogus = (
        set(cfg.r2_bogus_vas) if cfg and hasattr(cfg, "r2_bogus_vas") else _DEFAULT_R2_BOGUS_SIZES
    )
    for func in r2_funcs:
        va = func["va"]
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "r2_name": "",
                "ghidra_name": "",
                "is_thunk": va in getattr(cfg, "iat_thunks", []) if cfg else False,
                "is_export": va in getattr(cfg, "dll_exports", {}) if cfg else False,
                "canonical_size": 0,
            },
        )
        if "r2" not in entry["detected_by"]:
            entry["detected_by"].append("r2")
        r2_size = func["size"]
        if va not in r2_bogus:
            entry["size_by_tool"]["r2"] = r2_size
        entry["r2_name"] = func["r2_name"]

    # --- Ghidra functions (from cached JSON) ---
    ghidra_funcs = []
    if ghidra_path and ghidra_path.exists():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            ghidra_funcs = json.loads(ghidra_path.read_text(encoding="utf-8"))

    for func in ghidra_funcs:
        va = func["va"]
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "r2_name": "",
                "ghidra_name": "",
                "is_thunk": va in getattr(cfg, "iat_thunks", []) if cfg else False,
                "is_export": va in getattr(cfg, "dll_exports", {}) if cfg else False,
                "canonical_size": 0,
            },
        )
        if "ghidra" not in entry["detected_by"]:
            entry["detected_by"].append("ghidra")
        entry["size_by_tool"]["ghidra"] = func["size"]
        entry["ghidra_name"] = func["ghidra_name"]

    # --- Exports ---
    exports: dict[int, str] = getattr(cfg, "dll_exports", {}) if cfg else {}
    for va, _name in exports.items():
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

    # --- Load .text section data for smart size resolution ---
    text_data: bytes | None = None
    text_va = 0
    text_size_val = 0
    if bin_path and bin_path.exists():
        try:
            info = load_binary(bin_path)
            if ".text" in info.sections:
                sec = info.sections[".text"]
                text_va = sec.va
                text_size_val = sec.size
                text_data = info.data[sec.file_offset : sec.file_offset + sec.size]
        except (OSError, KeyError, ValueError):
            pass

    # --- Resolve canonical size: smart resolution ---
    for va, entry in registry.items():
        sizes = entry["size_by_tool"]
        canonical, reason = _resolve_canonical_size(sizes, va, text_data, text_va, text_size_val)
        entry["canonical_size"] = canonical
        entry["size_reason"] = reason

    return registry


def load_ghidra_functions(path: Path) -> list[dict[str, Any]]:
    """Load cached ghidra_functions.json."""
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _classify_ghidra_label(label: str) -> str:
    """Classify a Ghidra data label name into a cell state.

    Known patterns:
        thunk_*  → "thunk"
        default  → "data"  (switch tables are absorbed into parent functions)
    """
    low = label.lower()
    if low.startswith("thunk_"):
        return "thunk"
    return "data"


def load_ghidra_data_labels(src_dir: Path | None) -> dict[int, dict[str, Any]]:
    """Load Ghidra data labels → {va: {"size": int, "label": str, "state": str}}.

    Tries ghidra_data_labels.json first, falls back to ghidra_switchdata.json
    for backward compatibility.

    ghidra_data_labels.json format:
        [{"va": int, "size": int, "label": "switchdataD_10002e9c"}, ...]

    ghidra_switchdata.json format (legacy):
        [{"va": int, "size": int}, ...]
    """
    if src_dir is None:
        return {}

    # Try new format first
    path = src_dir / "ghidra_data_labels.json"
    if not path.exists():
        # Fall back to legacy format
        path = src_dir / "ghidra_switchdata.json"
    if not path.exists():
        return {}

    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}

    result: dict[int, dict[str, Any]] = {}
    for entry in entries:
        va = entry.get("va", 0)
        size = entry.get("size", 0)
        if va and size:
            label = entry.get("label", "")
            state = _classify_ghidra_label(label) if label else "data"
            result[va] = {"size": size, "label": label, "state": state}
    return result


# ---------------------------------------------------------------------------
# r2_functions.txt parser
# ---------------------------------------------------------------------------

_R2_LINE_RE = re.compile(r"\s*(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)")


def parse_r2_functions(path: Path) -> list[dict[str, Any]]:
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


def extract_dll_bytes(bin_path: Path, file_offset: int, size: int) -> bytes | None:
    """Extract raw bytes from DLL at given file offset."""
    try:
        with open(bin_path, "rb") as f:
            f.seek(file_offset)
            data = f.read(size)
        # Trim trailing CC/90 padding (index-based to avoid O(n^2) copies)
        end = len(data)
        while end > 0 and data[end - 1] in (0xCC, 0x90):
            end -= 1
        return data[:end]
    except (OSError, ValueError):
        return None


# COFF .obj parsing: imported from canonical source


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_reversed_dir(reversed_dir: Path, cfg: Any = None) -> list[Annotation]:
    """Scan target dir source files and parse annotations from each.

    Supports multi-function files: a single source file may contain multiple
    ``// FUNCTION:`` blocks, each generating a separate entry.
    """
    from rebrew.cli import source_glob

    entries: list[Annotation] = []
    for cfile in sorted(reversed_dir.glob(source_glob(cfg))):
        parsed = parse_c_file_multi(cfile)
        entries.extend(parsed)
    return entries


# ---------------------------------------------------------------------------
# CATALOG.md generation
# ---------------------------------------------------------------------------


def generate_catalog(
    entries: list[dict[str, Any]],
    r2_funcs: list[dict[str, Any]],
    text_size: int,
) -> str:
    """Generate CATALOG.md content."""
    # Deduplicate by VA (keep first occurrence per VA)
    by_va: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        if e.get("marker_type") in ("GLOBAL", "DATA"):
            continue
        by_va.setdefault(e["va"], []).append(e)

    unique_vas = set(by_va.keys())
    exact_count = sum(1 for vas in by_va.values() if any(e["status"] == "EXACT" for e in vas))
    reloc_count = sum(
        1
        for vas in by_va.values()
        if any(e["status"] in ("RELOC", "MATCHING_RELOC") for e in vas)
        and not any(e["status"] == "EXACT" for e in vas)
    )
    stub_count = sum(
        1
        for vas in by_va.values()
        if any(e["status"] == "STUB" for e in vas)
        and not any(e["status"] in ("EXACT", "RELOC", "MATCHING_RELOC", "MATCHING") for e in vas)
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
        f"Coverage: {coverage_pct:.1f}% of .text section ({covered_bytes}/{text_size} bytes)\n"
    )

    # Group by origin (discovered dynamically from data, excluding GLOBAL/DATA)
    by_origin: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        if e.get("marker_type") in ("GLOBAL", "DATA"):
            continue
        origin = e["origin"]
        by_origin.setdefault(origin, []).append(e)

    for origin in sorted(by_origin):
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


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    ranges = sorted(ranges)
    result: list[tuple[int, int]] = [ranges[0]]
    for s, e in ranges[1:]:
        last_s, last_e = result[-1]
        if s <= last_e:
            result[-1] = (last_s, max(last_e, e))
        else:
            result.append((s, e))
    return result


def _find_ghidra_data_label(
    va: int, data_labels: dict[int, dict[str, Any]]
) -> tuple[int, dict[str, Any]] | None:
    """Return (label_va, label_dict) if *va* falls inside a known Ghidra data label region."""
    for dl_va, dl_info in data_labels.items():
        if dl_va <= va < dl_va + dl_info["size"]:
            return dl_va, dl_info
    return None


def _is_jump_table(data: bytes, section_va: int, section_size: int) -> bool:
    """Check if *data* looks like a jump/switch table (array of .text pointers).

    Skips leading alignment bytes (NOP 0x90, INT3 0xCC, ``mov edi,edi`` 0x8BFF)
    before checking for a run of at least 2 consecutive .text pointers.
    """
    if len(data) < 8:
        return False
    # Skip alignment prefix
    off = 0
    while off < len(data) and data[off] in (0x90, 0xCC):
        off += 1
    # Also skip ``mov edi, edi`` (8B FF) used as 2-byte NOP
    if off + 1 < len(data) and data[off] == 0x8B and data[off + 1] == 0xFF:
        off += 2
    remaining = data[off:]
    if len(remaining) < 8:
        return False
    n_ptrs = len(remaining) // 4
    count = 0
    for i in range(n_ptrs):
        val = struct.unpack_from("<I", remaining, i * 4)[0]
        if section_va <= val < section_va + section_size:
            count += 1
        else:
            break
    return count >= 2


def generate_data_json(
    entries: list[dict[str, Any]],
    r2_funcs: list[dict[str, Any]],
    text_size: int,
    bin_path: Path | None = None,
    registry: dict[int, dict[str, Any]] | None = None,
    src_dir: Path | None = None,
    root_dir: Path | None = None,
) -> dict[str, Any]:
    """Generate db/data.json structure."""
    by_va: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    unique_vas = set(by_va.keys())
    r2_by_va: dict[int, dict[str, Any]] = {f["va"]: f for f in r2_funcs}

    fn_vas = [
        vas
        for vas in by_va.values()
        if any(e.get("marker_type") not in ("GLOBAL", "DATA") for e in vas)
    ]

    exact_count = sum(1 for vas in fn_vas if any(e["status"] == "EXACT" for e in vas))
    reloc_count = sum(
        1
        for vas in fn_vas
        if any(e["status"] in ("RELOC", "MATCHING_RELOC") for e in vas)
        and not any(e["status"] == "EXACT" for e in vas)
    )
    matching_count = sum(
        1
        for vas in fn_vas
        if any(e["status"] in ("MATCHING", "MATCHING_RELOC") for e in vas)
        and not any(e["status"] in ("EXACT", "RELOC") for e in vas)
    )
    stub_count = sum(
        1
        for vas in fn_vas
        if any(e["status"] == "STUB" for e in vas)
        and not any(e["status"] in ("EXACT", "RELOC", "MATCHING_RELOC", "MATCHING") for e in vas)
    )

    covered_bytes = 0
    for va in unique_vas:
        vas = by_va[va]
        if any(e.get("marker_type") not in ("GLOBAL", "DATA") for e in vas):
            if registry and va in registry:
                covered_bytes += registry[va]["canonical_size"]
            elif va in r2_by_va:
                covered_bytes += r2_by_va[va]["size"]
            elif vas:
                covered_bytes += vas[0]["size"]

    sections = get_sections(bin_path) if bin_path else {}
    globals_dict = get_globals(src_dir) if src_dir else {}
    ghidra_data_labels = load_ghidra_data_labels(src_dir)

    # Build thunk offset set from registry
    thunk_offsets: dict[int, str] = {}
    if registry:
        for va, reg_entry in registry.items():
            if reg_entry.get("is_thunk"):
                name = reg_entry.get("ghidra_name") or reg_entry.get("r2_name") or ""
                thunk_offsets[va] = name

    # Detect binary layout for fallback section computation
    image_base = 0
    text_raw_offset = 0
    text_data: bytes | None = None
    if bin_path and bin_path.exists():
        from rebrew.binary_loader import load_binary

        try:
            info = load_binary(bin_path)
            image_base = info.image_base
            text_raw_offset = info.text_raw_offset
            # Capture raw .text section bytes for padding detection
            if ".text" in info.sections:
                sec = info.sections[".text"]
                text_data = info.data[sec.file_offset : sec.file_offset + sec.size]
        except (OSError, KeyError, ValueError):
            pass

    # Fallback if LIEF fails to populate .text section
    if ".text" not in sections:
        sections[".text"] = {
            "va": image_base + text_raw_offset,
            "size": text_size,
            "fileOffset": text_raw_offset,
        }

    functions = {}
    for va in sorted(unique_vas):
        elist = by_va[va]
        e = elist[0]

        # Find which section this VA belongs to
        sec_name = ".text"
        file_off = 0
        text_off = 0
        found_in_section = False
        for sname, sdata in sections.items():
            if sdata["va"] <= va < sdata["va"] + sdata["size"]:
                sec_name = sname
                file_off = sdata["fileOffset"] + (va - sdata["va"])
                text_off = va - sdata["va"]
                found_in_section = True
                break

        # Fallback if not found in any section
        if not found_in_section and image_base:
            file_off = va - image_base
            text_off = file_off - text_raw_offset

        reg = registry.get(va, {}) if registry else {}
        canonical_size = reg.get("canonical_size", 0)
        if not canonical_size:
            canonical_size = r2_by_va[va]["size"] if va in r2_by_va else e["size"]

        fn_hash = ""
        if bin_path and bin_path.exists():
            raw = extract_dll_bytes(bin_path, file_off, canonical_size)
            if raw:
                fn_hash = hashlib.sha256(raw).hexdigest()

        functions[f"0x{va:08x}"] = {
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

        # Build func_end_to_name mapping for parent function detection
        func_end_to_name: dict[int, str] = {}
        if sec_name == ".text":
            for item_off, item_data in items_by_off.items():
                end_off = item_off + item_data["size"]
                func_end_to_name[end_off] = item_data["name"]

        # --- Pre-pass: absorb jump table / out-of-line gaps into parent functions ---
        if sec_name == ".text" and text_data is not None:
            absorbed_any = True
            while absorbed_any:
                absorbed_any = False
                # Rebuild func_end_to_name after each round (sizes may have changed)
                func_end_to_name.clear()
                for item_off, item_data in items_by_off.items():
                    end_off = item_off + item_data["size"]
                    func_end_to_name[end_off] = item_data["name"]

                for func_end_off in sorted(func_end_to_name.keys()):
                    if func_end_off >= sec_size:
                        continue
                    # Find next function start after this end
                    next_func_off = sec_size
                    for s in item_starts:
                        if s > func_end_off:
                            next_func_off = s
                            break

                    # Check what's in the gap
                    gap_bytes = text_data[func_end_off:next_func_off]
                    if not gap_bytes:
                        continue

                    absorb_size = 0

                    # Check Ghidra data labels at gap start
                    dl_result = _find_ghidra_data_label(sec_va + func_end_off, ghidra_data_labels)
                    is_switch_data = False
                    if dl_result is not None:
                        label_va, dl_info = dl_result
                        if dl_info["state"] == "data":
                            label_end_off = (label_va + dl_info["size"]) - sec_va
                            absorb_size = min(label_end_off, next_func_off) - func_end_off
                            is_switch_data = True
                    elif _is_jump_table(gap_bytes, sec_va, sec_size):
                        is_switch_data = True

                    if is_switch_data:
                        # Absorb entire gap up to next function, trimming
                        # only trailing NOP/INT3 padding (switch tables include
                        # both pointer arrays and index/lookup tables)
                        absorb_size = len(gap_bytes)
                        while absorb_size > 0 and gap_bytes[absorb_size - 1] in (0x90, 0xCC):
                            absorb_size -= 1

                    # Check for out-of-line code (jumps back into function body)
                    if absorb_size == 0 and not all(b in (0x90, 0xCC) for b in gap_bytes):
                        func_start_off = None
                        for ioff, idata in items_by_off.items():
                            if (
                                idata["name"] == func_end_to_name[func_end_off]
                                and ioff + idata["size"] == func_end_off
                            ):
                                func_start_off = ioff
                                break
                        if func_start_off is not None:
                            has_back_jump = False
                            i = 0
                            while i < len(gap_bytes):
                                b = gap_bytes[i]
                                if b == 0xE9 and i + 5 <= len(gap_bytes):
                                    rel = struct.unpack_from("<i", gap_bytes, i + 1)[0]
                                    target = func_end_off + i + 5 + rel
                                    if func_start_off <= target < func_end_off:
                                        has_back_jump = True
                                        break
                                    i += 5
                                    continue
                                if (
                                    b == 0x0F
                                    and i + 6 <= len(gap_bytes)
                                    and 0x80 <= gap_bytes[i + 1] <= 0x8F
                                ):
                                    rel = struct.unpack_from("<i", gap_bytes, i + 2)[0]
                                    target = func_end_off + i + 6 + rel
                                    if func_start_off <= target < func_end_off:
                                        has_back_jump = True
                                        break
                                    i += 6
                                    continue
                                if b == 0xEB and i + 2 <= len(gap_bytes):
                                    rel = struct.unpack_from("<b", gap_bytes, i + 1)[0]
                                    target = func_end_off + i + 2 + rel
                                    if func_start_off <= target < func_end_off:
                                        has_back_jump = True
                                        break
                                    i += 2
                                    continue
                                if 0x70 <= b <= 0x7F and i + 2 <= len(gap_bytes):
                                    rel = struct.unpack_from("<b", gap_bytes, i + 1)[0]
                                    target = func_end_off + i + 2 + rel
                                    if func_start_off <= target < func_end_off:
                                        has_back_jump = True
                                        break
                                    i += 2
                                    continue
                                i += 1
                            if has_back_jump:
                                absorb_size = len(gap_bytes)
                                while absorb_size > 0 and gap_bytes[absorb_size - 1] in (
                                    0x90,
                                    0xCC,
                                ):
                                    absorb_size -= 1

                    # Catch-all: small non-padding gaps (≤ 64B) that follow a
                    # function and weren't detected as separate functions by any
                    # tool.  These are typically out-of-line epilogues, IAT thunk
                    # tails, small helper snippets, or switch index tables.
                    _MAX_TAIL_ABSORB = 64
                    if (
                        absorb_size == 0
                        and len(gap_bytes) <= _MAX_TAIL_ABSORB
                        and not all(b in (0x90, 0xCC) for b in gap_bytes)
                    ):
                        absorb_size = len(gap_bytes)
                        while absorb_size > 0 and gap_bytes[absorb_size - 1] in (0x90, 0xCC):
                            absorb_size -= 1

                    if absorb_size > 0:
                        parent_name = func_end_to_name[func_end_off]
                        # Find the parent in items_by_off
                        for ioff, idata in items_by_off.items():
                            if (
                                idata["name"] == parent_name
                                and ioff + idata["size"] == func_end_off
                            ):
                                idata["size"] += absorb_size
                                # Also update the functions dict if present
                                fn_key = parent_name
                                if fn_key in functions:
                                    functions[fn_key]["size"] += absorb_size
                                absorbed_any = True
                                break

                if absorbed_any:
                    item_starts = sorted(items_by_off.keys())

        # Rebuild func_end_to_name after absorption
        func_end_to_name.clear()
        if sec_name == ".text":
            for item_off, item_data in items_by_off.items():
                end_off = item_off + item_data["size"]
                func_end_to_name[end_off] = item_data["name"]

        while off < sec_size:
            while idx < len(item_starts) and item_starts[idx] < off:
                idx += 1

            if idx < len(item_starts) and item_starts[idx] == off:
                item = items_by_off[off]
                s = off
                e = min(sec_size, off + item["size"])
                state = item["status"].lower()
                segments.append((s, e, state, [item["name"]], None, None))
                off = e
                continue

            next_off = item_starts[idx] if idx < len(item_starts) else sec_size
            gap_end = min(sec_size, off + unit_bytes, next_off)
            # Classify gap: padding > ghidra label > thunk > data > none
            gap_state = "none"
            gap_label: str | None = None
            gap_parent: str | None = None
            if sec_name == ".text" and text_data is not None:
                gap_bytes = text_data[off:gap_end]
                if gap_bytes and all(b in (0x90, 0xCC) for b in gap_bytes):
                    gap_state = "padding"
                else:
                    dl_result = _find_ghidra_data_label(sec_va + off, ghidra_data_labels)
                    if dl_result is not None:
                        label_va, dl_info = dl_result
                        gap_state = dl_info["state"]
                        gap_label = dl_info["label"] or None
                        # Extend gap to cover full label region (merge into one segment)
                        label_end_off = (label_va + dl_info["size"]) - sec_va
                        gap_end = min(sec_size, label_end_off, next_off)
                    elif (sec_va + off) in thunk_offsets:
                        gap_state = "thunk"
                        gap_label = thunk_offsets[sec_va + off] or None
                        # Extend to thunk's canonical size from registry
                        if registry and (sec_va + off) in registry:
                            thunk_size = registry[sec_va + off].get("canonical_size", 0)
                            if thunk_size > 0:
                                gap_end = min(sec_size, off + thunk_size, next_off)
                    elif _is_jump_table(gap_bytes, sec_va, sec_size):
                        gap_state = "data"

                # Auto-detect parent function (gap starts where a function ends)
                if gap_state in ("data", "thunk") and off in func_end_to_name:
                    gap_parent = func_end_to_name[off]

            # Merge consecutive same-state heuristic gaps
            if (
                segments
                and segments[-1][2] == gap_state
                and gap_state != "none"
                and not segments[-1][3]  # prev has no functions
                and segments[-1][4] == gap_label  # same label (both None for heuristic)
            ):
                prev = segments[-1]
                segments[-1] = (prev[0], gap_end, gap_state, [], gap_label, gap_parent or prev[5])
            # Absorb unrecognized gaps into preceding data segment with parent
            # (switch tables contain both pointer arrays and lookup/index tables,
            #  but trim trailing NOP/INT3 padding from the absorbed region)
            elif (
                gap_state in ("none", "data")
                and segments
                and segments[-1][2] == "data"
                and not segments[-1][3]  # prev has no functions
                and segments[-1][5]  # prev has a parent function
            ):
                # Trim trailing padding bytes (0x90/0xCC) from the absorbed region
                absorb_end = gap_end
                if gap_state == "none" and text_data is not None:
                    while absorb_end > off and text_data[absorb_end - 1] in (0x90, 0xCC):
                        absorb_end -= 1
                if absorb_end > off:
                    prev = segments[-1]
                    segments[-1] = (prev[0], absorb_end, "data", [], prev[4], prev[5])
                    # If we trimmed padding, emit remaining as a separate gap
                    if absorb_end < gap_end:
                        segments.append((absorb_end, gap_end, "padding", [], None, None))
                else:
                    # Entire gap is padding — don't absorb
                    segments.append((off, gap_end, gap_state, [], gap_label, gap_parent))
            else:
                segments.append((off, gap_end, gap_state, [], gap_label, gap_parent))
            off = gap_end

        cells = []
        col = 0
        for seg_start, seg_end, state, seg_fns, seg_label, seg_parent in segments:
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
                cell_dict: dict[str, Any] = {
                    "start": cur,
                    "end": cell_end,
                    "span": span,
                    "state": state,
                    "functions": seg_fns,
                }
                if seg_label:
                    cell_dict["label"] = seg_label
                if seg_parent:
                    cell_dict["parent_function"] = seg_parent
                cells.append(cell_dict)
                col = (col + span) % columns
                cols_left -= span
                cur = cell_end

        sec_data["cells"] = cells
        sec_data["unitBytes"] = unit_bytes
        sec_data["columns"] = columns

    # Count padding and thunk bytes from .text section cells
    padding_bytes = 0
    thunk_bytes = 0
    data_bytes = 0
    func_cell_bytes = 0
    text_sec = sections.get(".text", {})
    for cell in text_sec.get("cells", []):
        cell_state = cell.get("state")
        cell_size = cell["end"] - cell["start"]
        if cell_state == "padding":
            padding_bytes += cell_size
        elif cell_state == "data":
            data_bytes += cell_size
        elif cell_state == "thunk":
            thunk_bytes += cell_size
        elif cell_state != "none":
            func_cell_bytes += cell_size

    # Coverage = all accounted-for bytes (functions + padding + data + thunks)
    adjusted_covered = func_cell_bytes + padding_bytes + data_bytes + thunk_bytes
    adjusted_pct = (adjusted_covered / text_size * 100.0) if text_size else 0.0

    return {
        "sections": sections,
        "globals": globals_dict,
        "paths": {
            "originalDll": f"/{bin_path.relative_to(root_dir)}" if bin_path and root_dir else "",
        },
        "summary": {
            "totalFunctions": len(fn_vas),
            "matchedFunctions": len(fn_vas) - stub_count,
            "exactMatches": exact_count,
            "relocMatches": reloc_count,
            "matchingMatches": matching_count,
            "stubCount": stub_count,
            "coveredBytes": adjusted_covered,
            "paddingBytes": padding_bytes,
            "dataBytes": data_bytes,
            "thunkBytes": thunk_bytes,
            "coveragePercent": round(adjusted_pct, 2),
            "textSize": text_size,
        },
        "functions": functions,
    }


# ---------------------------------------------------------------------------
# reccmp-compatible CSV generation
# ---------------------------------------------------------------------------


def _reccmp_type(entry: dict[str, Any]) -> str:
    """Map our marker_type + origin to reccmp entity type."""
    if entry["marker_type"] == "STUB":
        return "stub"
    if entry["origin"] in ("ZLIB", "MSVCRT"):
        return "library"
    return "function"


def generate_reccmp_csv(
    entries: list[dict[str, Any]],
    r2_funcs: list[dict[str, Any]],
    registry: dict[int, dict[str, Any]] | None = None,
    target_name: str = "TARGET",
    cfg: Any = None,
) -> str:
    """Generate reccmp-compatible pipe-delimited CSV.

    Format per https://github.com/isledecomp/reccmp/blob/master/docs/csv.md:
      address|name|symbol|type|size

    Includes ALL known functions (matched + unmatched), so the CSV serves as
    a complete function catalog for the binary.  Comments and blank lines are
    allowed by the reccmp spec.
    """
    by_va: dict[int, dict[str, Any]] = {}
    for e in entries:
        if e["va"] not in by_va:
            by_va[e["va"]] = e

    r2_by_va = {f["va"]: f for f in r2_funcs}

    lines: list[str] = []
    lines.append(f"# reccmp-compatible function catalog for {target_name}")
    lines.append("# Generated by validate.py — do not edit manually")
    lines.append("#")
    lines.append("# Columns: address (hex) | name | symbol | type | size (decimal)")
    lines.append("")
    lines.append("address|name|symbol|type|size")

    # Collect all known VAs from registry + annotations
    all_vas: set[int] = set()
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
            is_thunk = reg.get("is_thunk", False)
            if not is_thunk and cfg:
                is_thunk = va in getattr(cfg, "iat_thunks", [])
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


def get_sections(bin_path: Path) -> dict[str, dict[str, int]]:
    try:
        info = load_binary(bin_path)
        sections = {}
        for name, sec in info.sections.items():
            if name == ".data" and sec.size > sec.raw_size:
                sections[".data"] = {
                    "va": sec.va,
                    "size": sec.raw_size,
                    "fileOffset": sec.file_offset,
                }
                sections[".bss"] = {
                    "va": sec.va + sec.raw_size,
                    "size": sec.size - sec.raw_size,
                    "fileOffset": 0,
                }
            else:
                sections[name] = {
                    "va": sec.va,
                    "size": sec.size,
                    "fileOffset": sec.file_offset,
                }
        return sections
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Warning: Failed to parse binary sections: {e}", file=sys.stderr)
        return {}


def get_globals(src_dir: Path, cfg: Any = None) -> dict[int, dict[str, Any]]:
    globals_dict: dict[int, dict[str, Any]] = {}
    from rebrew.cli import source_glob

    pattern = re.compile(r"(?://|/\*)\s*GLOBAL:\s*(?P<target>[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)")
    for p in src_dir.rglob(source_glob(cfg)):
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
                    name_m = re.search(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[.*\])?\s*;", decl)
                    if name_m:
                        name = name_m.group(1)

                    origin = m.group("target")  # MODULE from // GLOBAL: MODULE 0xVA

                    # Estimate size from declaration type
                    size = 4  # default pointer-sized
                    if decl:
                        if "char" in decl and "[" in decl:
                            # char array — try to extract size from [N]
                            arr_m = re.search(r"\[(\d+)\]", decl)
                            if arr_m:
                                size = int(arr_m.group(1))
                        elif "short" in decl:
                            size = 2
                        elif "char" in decl:
                            size = 1
                        elif "double" in decl:
                            size = 8

                    if va not in globals_dict:
                        globals_dict[va] = {
                            "va": va,
                            "name": name,
                            "decl": decl,
                            "files": [p.name],
                            "origin": origin,
                            "size": size,
                        }
                    elif p.name not in globals_dict[va]["files"]:
                        globals_dict[va]["files"].append(p.name)
        except (OSError, KeyError, ValueError):
            pass
    return globals_dict


def get_text_section_size(bin_path: Path) -> int:
    """Get .text section virtual size from binary headers."""
    try:
        info = load_binary(bin_path)
        return info.text_size
    except (OSError, KeyError, ValueError):
        pass
    # Fallback: estimate from r2_functions.txt last function
    return 0x24000  # rough estimate


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


app = typer.Typer(
    help="Rebrew validation pipeline: parse annotations, generate catalog and coverage data.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]
  rebrew-catalog                              Validate annotations (default)
  rebrew-catalog --json                       Generate db/data_<target>.json
  rebrew-catalog --catalog                    Generate CATALOG.md in reversed_dir
  rebrew-catalog --json --catalog             Generate both JSON and CATALOG.md
  rebrew-catalog -t server.dll                Catalog a specific target

[bold]What it does:[/bold]
  1. Scans reversed_dir for .c files with reccmp-style annotations
  2. Cross-references with ghidra_functions.json and r2_functions.txt
  3. Builds function registry merging all detection sources
  4. Generates cell-level coverage data for the .text section
  5. Outputs structured JSON and/or CATALOG.md

[dim]The JSON output feeds into 'rebrew-build-db' to create the SQLite database
used by the recoverage dashboard.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    gen_json: bool = typer.Option(False, "--json", help="Generate db/data.json"),
    catalog: bool = typer.Option(
        False, "--catalog", help="Generate CATALOG.md in reversed directory"
    ),
    summary: bool = typer.Option(False, "--summary", help="Print summary to stdout"),
    csv: bool = typer.Option(False, "--csv", help="Generate reccmp-compatible CSV"),
    export_ghidra: bool = typer.Option(False, "--export-ghidra", help="Cache Ghidra function list"),
    export_ghidra_labels: bool = typer.Option(
        False,
        "--export-ghidra-labels",
        help="Generate ghidra_data_labels.json from detected tables",
    ),
    fix_sizes: bool = typer.Option(
        False,
        "--fix-sizes",
        help="Update // SIZE: annotations in .c files to match canonical sizes",
    ),
    root: Path | None = typer.Option(
        None,
        help="Project root directory (auto-detected from rebrew.toml if omitted)",
    ),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name from rebrew.toml"),
) -> None:
    """Rebrew validation pipeline: parse annotations, generate catalog and coverage data."""
    cfg = None
    try:
        from rebrew.config import load_config

        cfg = load_config(root, target=target)
        bin_path = cfg.target_binary
        reversed_dir = cfg.reversed_dir
        root = cfg.root
        target = cfg.target_name
    except (AttributeError, KeyError, FileNotFoundError):
        if root is None:
            root = Path.cwd().resolve()
        bin_path = root / "binary.dll"
        reversed_dir = root / "src"
        target = target or "default"

    r2_path = reversed_dir / "r2_functions.txt"
    ghidra_json_path = reversed_dir / "ghidra_functions.json"

    if not any(
        [
            catalog,
            gen_json,
            csv,
            summary,
            export_ghidra,
            export_ghidra_labels,
            fix_sizes,
        ]
    ):
        catalog = True
        gen_json = True
        csv = True
        summary = True

    if export_ghidra:
        print(
            "To export Ghidra functions, run this in the MCP console:\n"
            f"  get-functions programPath=/{bin_path.name} filterDefaultNames=false\n"
            f"Then save the output as {reversed_dir.name}/ghidra_functions.json with format:\n"
            '  [{"va": 0x10001000, "size": 302, "ghidra_name": "FUN_10001000"}, ...]\n'
            "\n"
            "To also export data labels (switch tables, etc.), search for non-function\n"
            f"labels in Ghidra and save as {reversed_dir.name}/ghidra_data_labels.json:\n"
            '  [{"va": 0x10002E9C, "size": 20, "label": "switchdataD_10002e9c"}, ...]\n'
            f"(Legacy ghidra_switchdata.json format is still supported for compat.)",
            file=sys.stderr,
        )
        return

    print(f"Scanning {reversed_dir}...", file=sys.stderr)
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    r2_funcs = parse_r2_functions(r2_path)

    text_size = get_text_section_size(bin_path) if bin_path and bin_path.exists() else 0x24000

    registry = build_function_registry(r2_funcs, cfg, ghidra_json_path, bin_path)

    unique_vas = set(e["va"] for e in entries)
    ghidra_count = sum(1 for r in registry.values() if "ghidra" in r["detected_by"])
    r2_count = sum(1 for r in registry.values() if "r2" in r["detected_by"])
    both_count = sum(
        1 for r in registry.values() if "ghidra" in r["detected_by"] and "r2" in r["detected_by"]
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
        print("\n=== Rebrew Status ===")
        print(f"Matched: {len(unique_vas)}/{len(registry)} functions")
        print(f"  EXACT: {exact}")
        print(f"  RELOC: {reloc}")
        for origin in sorted(by_origin):
            count = len(by_origin.get(origin, []))
            print(f"  {origin}: {count}")

        covered = 0
        for va in unique_vas:
            if va in registry:
                covered += registry[va]["canonical_size"]
        pct = (covered / text_size * 100.0) if text_size else 0.0
        print(f"Coverage: {pct:.1f}% ({covered}/{text_size} bytes)")

        print("\n=== Tool Detection ===")
        print(f"  radare2 only: {sum(1 for r in registry.values() if r['detected_by'] == ['r2'])}")
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
        catalog_text = generate_catalog(entries, r2_funcs, text_size)
        catalog_path = reversed_dir / "CATALOG.md"
        catalog_path.parent.mkdir(parents=True, exist_ok=True)
        catalog_path.write_text(catalog_text, encoding="utf-8")
        print(f"Wrote {catalog_path}", file=sys.stderr)

    if gen_json or export_ghidra_labels:
        data = generate_data_json(
            entries, r2_funcs, text_size, bin_path, registry, reversed_dir, root
        )
        if gen_json:
            coverage_dir = root / "db"
            coverage_dir.mkdir(parents=True, exist_ok=True)
            json_path = coverage_dir / f"data_{target}.json"
            json_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote {json_path}", file=sys.stderr)

        if export_ghidra_labels:
            text_sec = data.get("sections", {}).get(".text", {})
            sec_va = text_sec.get("va", 0)
            labels = []
            for cell in text_sec.get("cells", []):
                if cell["state"] in ("data", "thunk"):
                    cell_va = sec_va + cell["start"]
                    labels.append(
                        {
                            "va": cell_va,
                            "size": cell["end"] - cell["start"],
                            "label": cell.get("label", f"switchdata_{cell_va:08x}"),
                        }
                    )
            labels_path = reversed_dir / "ghidra_data_labels.json"
            labels_path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote {labels_path} ({len(labels)} labels)", file=sys.stderr)

    if csv:
        csv_text = generate_reccmp_csv(entries, r2_funcs, registry, target, cfg)
        csv_path = root / "db" / f"{target.lower()}_functions.csv"
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.write_text(csv_text, encoding="utf-8")
        print(
            f"Wrote {csv_path} ({len(csv_text.splitlines()) - 6} functions)",
            file=sys.stderr,
        )

    if fix_sizes:
        from rebrew.annotation import update_size_annotation
        from rebrew.cli import source_glob

        updated = 0
        skipped = 0
        for cfile in sorted(reversed_dir.glob(source_glob(cfg))):
            parsed = parse_c_file_multi(cfile)
            for ann in parsed:
                va = ann.va
                if va not in registry:
                    continue
                canonical = registry[va]["canonical_size"]
                if canonical <= 0 or canonical <= ann.size:
                    continue
                reason = registry[va].get("size_reason", "")
                if update_size_annotation(cfile, canonical):
                    diff = canonical - ann.size
                    print(f"  {cfile.name}: SIZE {ann.size} → {canonical} (+{diff}B, {reason})")
                    updated += 1
                else:
                    skipped += 1
        print(f"Updated {updated} SIZE annotations ({skipped} skipped)", file=sys.stderr)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
