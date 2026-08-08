"""catalog/grid.py - Coverage grid and data.json generation.

Builds cell-level coverage maps for binary sections, handling jump table
detection, gap absorption, padding classification, and thunk identification.
"""

import bisect
import hashlib
import logging
import math
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.binary_loader import BinaryInfo
    from rebrew.catalog.models import GhidraDataLabel

from rebrew.annotation import Annotation
from rebrew.catalog.loaders import load_ghidra_data_labels
from rebrew.catalog.registry import RegistryEntry, is_jump_table
from rebrew.catalog.sections import (
    get_globals,
    has_back_jumps,
    sections_from_info,
    trim_trailing_padding,
)

log = logging.getLogger(__name__)

# Maximum trailing gap (in bytes) that can be absorbed into the preceding function
_MAX_TAIL_ABSORB = 64

# Grid cell sizes per section type (bytes per cell unit)
_TEXT_CELL_BYTES = 64
_BSS_CELL_BYTES = 4096
_DEFAULT_CELL_BYTES = 16
_GRID_COLUMNS = 64


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping half-open ranges into sorted non-overlapping ranges."""
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


def _build_section_index(
    sections: dict[str, Any],
) -> tuple[list[int], list[tuple[str, int, int, int]]]:
    """Build sorted section boundaries for O(log n) VA → section lookup.

    Returns (sorted_starts, section_info) where section_info[i] is
    (name, va_start, va_end, file_offset) for the section whose start is
    sorted_starts[i].
    """
    starts: list[int] = []
    info: list[tuple[str, int, int, int]] = []
    for sname, sdata in sections.items():
        s = sdata["va"]
        starts.append(s)
        info.append((sname, s, s + sdata["size"], sdata["fileOffset"]))
    # Sort by VA start
    paired = sorted(zip(starts, info, strict=True))
    return [p[0] for p in paired], [p[1] for p in paired]


def _lookup_section(
    va: int,
    sorted_starts: list[int],
    section_info: list[tuple[str, int, int, int]],
) -> tuple[str, int, int] | None:
    """O(log n) section lookup via bisect.

    Returns (section_name, file_offset, text_offset) or None.
    """
    idx = bisect.bisect_right(sorted_starts, va) - 1
    if idx < 0:
        return None
    sname, s_va, s_end, s_file_off = section_info[idx]
    if va < s_end:
        return sname, s_file_off + (va - s_va), va - s_va
    return None


def _build_label_index(
    data_labels: dict[int, "GhidraDataLabel"],
) -> tuple[list[int], list[tuple[int, "GhidraDataLabel"]]]:
    """Build sorted label boundaries for O(log n) lookup."""
    items = sorted(data_labels.items())
    starts = [va for va, _ in items]
    info = [(va, dl) for va, dl in items]
    return starts, info


def _find_ghidra_data_label(
    va: int,
    _label_index: tuple[list[int], list[tuple[int, "GhidraDataLabel"]]] | None,
) -> tuple[int, "GhidraDataLabel"] | None:
    """Return (label_va, label_dict) if *va* falls inside a known Ghidra data label region.

    Uses O(log n) bisect lookup against a pre-built sorted index
    (see :func:`_build_label_index`).  Pass ``None`` when no labels exist.
    """
    if _label_index is None:
        return None
    starts, info = _label_index
    idx = bisect.bisect_right(starts, va) - 1
    if idx >= 0:
        dl_va, dl_info = info[idx]
        if dl_va <= va < dl_va + dl_info.size:
            return dl_va, dl_info
    return None


def generate_data_json(
    entries: list[Annotation],
    funcs: list[dict[str, Any]],
    text_size: int,
    bin_path: Path | None = None,
    registry: dict[int, RegistryEntry] | None = None,
    src_dir: Path | None = None,
    root_dir: Path | None = None,
) -> dict[str, Any]:
    """Generate the coverage database structure (db/data.json).

    Builds function coverage maps, cell-level grids per section, and gap
    classification from annotations and the target binary.  Includes
    absorption of jump tables and out-of-line code into parent functions.
    """
    by_va: dict[int, list[Annotation]] = {}
    for e in entries:
        by_va.setdefault(e.va, []).append(e)

    unique_vas = set(by_va)
    funcs_by_va: dict[int, dict[str, Any]] = {f["va"]: f for f in funcs}

    fn_vas = [
        vas
        for vas in by_va.values()
        if any(e.get("marker_type") not in ("GLOBAL", "DATA") for e in vas)
    ]

    # Count functions by highest-priority status present
    _STATUS_PRIORITY = (("EXACT",), ("RELOC",), ("NEAR_MATCHING", "NEAR_MATCH"), ("STUB",))
    exact_count = reloc_count = near_match_count = stub_count = 0
    _counters = {"EXACT": 0, "RELOC": 0, "NEAR_MATCHING": 0, "STUB": 0}
    for vas in fn_vas:
        statuses = {e["status"] for e in vas}
        for status_group in _STATUS_PRIORITY:
            if any(status in statuses for status in status_group):
                _counters[status_group[0]] += 1
                break
    exact_count, reloc_count, near_match_count, stub_count = (
        _counters["EXACT"],
        _counters["RELOC"],
        _counters["NEAR_MATCHING"],
        _counters["STUB"],
    )

    covered_bytes = 0
    for va in unique_vas:
        vas = by_va[va]
        if any(e.get("marker_type") not in ("GLOBAL", "DATA") for e in vas):
            if registry and va in registry:
                covered_bytes += registry[va]["canonical_size"]
            elif va in funcs_by_va:
                covered_bytes += funcs_by_va[va]["size"]
            elif vas:
                covered_bytes += vas[0]["size"]

    sections: dict[str, Any] = {}
    _bin_info: BinaryInfo | None = None
    if bin_path and bin_path.exists():
        from rebrew.binary_loader import load_binary

        # Single lazy parse: sections, layout, and raw bytes all come from
        # one BinaryInfo (previously get_sections + load_binary parsed twice).
        try:
            _bin_info = load_binary(bin_path)
        except (OSError, KeyError, ValueError):
            _bin_info = None
        if _bin_info is not None:
            sections.update(sections_from_info(_bin_info))
    globals_dict = get_globals(src_dir) if src_dir else {}
    ghidra_data_labels = load_ghidra_data_labels(src_dir)
    label_index = _build_label_index(ghidra_data_labels) if ghidra_data_labels else None

    # Build thunk offset set from registry
    thunk_offsets: dict[int, str] = {}
    if registry:
        for va, reg_entry in registry.items():
            if reg_entry.get("is_thunk"):
                name = reg_entry.get("ghidra_name") or reg_entry.get("list_name") or ""
                thunk_offsets[va] = name

    # Detect binary layout for fallback section computation (same parse above)
    image_base = 0
    text_raw_offset = 0
    text_data: bytes | None = None
    _bin_data: bytes | None = None  # Full binary bytes for batch function extraction
    if _bin_info is not None:
        image_base = _bin_info.image_base
        text_raw_offset = _bin_info.text_raw_offset
        _bin_data = _bin_info.data  # Cache full binary for O(1) function byte extraction
        # Capture raw .text section bytes for padding detection
        if ".text" in _bin_info.sections:
            sec = _bin_info.sections[".text"]
            text_data = _bin_data[sec.file_offset : sec.file_offset + sec.size]

    # Fallback if LIEF fails to populate .text section
    if ".text" not in sections:
        sections[".text"] = {
            "va": image_base + text_raw_offset,
            "size": text_size,
            "fileOffset": text_raw_offset,
        }

    # Pre-build section index for O(log n) VA lookups
    sec_sorted_starts, sec_info = _build_section_index(sections)

    functions = {}
    for va in sorted(unique_vas):
        elist = by_va[va]
        e = elist[0]

        # Find which section this VA belongs to (O(log n) via bisect)
        sec_name = ".text"
        file_off = 0
        text_off = 0
        sec_result = _lookup_section(va, sec_sorted_starts, sec_info)
        found_in_section = sec_result is not None
        if sec_result is not None:
            sec_name, file_off, text_off = sec_result

        # Fallback if not found in any section.  A VA outside every section has
        # no meaningful file offsets: emitting negative values would violate
        # build_db's CHECK constraints (aborting the whole rebuild) and slicing
        # the binary from a negative index reads from the file END.  Skip it.
        if not found_in_section:
            if not image_base:
                continue
            file_off = va - image_base
            text_off = file_off - text_raw_offset
            if file_off < 0 or text_off < 0:
                continue

        reg = registry.get(va, {}) if registry else {}
        canonical_size = reg.get("canonical_size", 0)
        if not canonical_size:
            canonical_size = funcs_by_va[va]["size"] if va in funcs_by_va else e["size"]

        # Skip entries with no resolvable size (e.g. library header markers
        # not present in the function list or registry)
        if canonical_size <= 0:
            continue

        fn_hash = ""
        if _bin_data is not None:
            raw = _bin_data[file_off : file_off + canonical_size]
            # Trim trailing CC/90 padding (same as extract_dll_bytes)
            raw = raw[: trim_trailing_padding(raw)] if raw else b""
            if raw:
                fn_hash = hashlib.sha256(raw).hexdigest()

        functions[f"0x{va:08x}"] = {
            "name": e["name"],
            "vaStart": f"0x{va:08x}",
            "size": canonical_size,
            "status": e["status"],
            "module": e["module"],
            "markerType": e["marker_type"],
            "cflags": e["cflags"],
            "symbol": e["symbol"],
            "fileOffset": file_off,
            "textOffset": text_off,
            "sha256": fn_hash,
            "files": [x.filepath for x in elist],
            "detected_by": reg.get("detected_by", []),
            "size_by_tool": reg.get("size_by_tool", {}),
            "ghidra_name": reg.get("ghidra_name", ""),
            "list_name": reg.get("list_name", ""),
            "is_thunk": reg.get("is_thunk", False),
            "is_export": reg.get("is_export", False),
            "blocker": e.get("blocker", ""),
            "blockerDelta": e.get("blocker_delta"),
            "size_reason": reg.get("size_reason", ""),
        }

    # Generate cells for each section
    for sec_name, sec_data in sections.items():
        sec_va = sec_data["va"]
        sec_size = sec_data["size"]
        if sec_name == ".text":
            unit_bytes = _TEXT_CELL_BYTES
        elif sec_name == ".bss":
            unit_bytes = _BSS_CELL_BYTES
        else:
            unit_bytes = _DEFAULT_CELL_BYTES
        columns = _GRID_COLUMNS

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

        item_starts = sorted(items_by_off)
        segments: list[tuple[int, int, str, list[str], str | None, str | None]] = []
        off = 0
        idx = 0

        # Reverse lookup: function end offset → name (for absorption detection)
        func_end_to_name: dict[int, str] = {}
        if sec_name == ".text":
            for item_off, item_data in items_by_off.items():
                end_off = item_off + item_data["size"]
                func_end_to_name[end_off] = item_data["name"]

        # All function starts in this section: the annotated items above plus
        # unannotated registry functions (from the disassembler's function
        # list / ghidra).  Absorption must stop at a real function's start
        # even when it has no .c annotation yet — otherwise the predecessor's
        # span silently swallows un-reversed functions and the coverage DB
        # hides them (reported: `time` 220B inflated to 282B, two list
        # functions invisible).
        boundary_starts = list(item_starts)
        if sec_name == ".text" and registry:
            for va in registry:
                reg_off = va - sec_va
                # Include every known function start, even when the canonical
                # size is unresolved (0) — a start the disassembler/ghidra
                # detected is a real boundary regardless of its size.
                if 0 <= reg_off < sec_size:
                    boundary_starts.append(reg_off)
        boundary_starts = sorted(set(boundary_starts))

        # Iteratively absorb jump tables and out-of-line code into parent functions
        if sec_name == ".text" and text_data is not None:
            _MAX_ABSORB_ROUNDS = 50  # safety guard against runaway absorption
            absorbed_any = True
            _absorb_round = 0
            while absorbed_any:
                # Unreachable for static inputs: each round only absorbs bytes
                # strictly between a function end and the next start, so ends
                # never move past starts; the loop terminates in ≤2 rounds.
                if _absorb_round >= _MAX_ABSORB_ROUNDS:  # pragma: no cover
                    log.warning(
                        "Absorption loop hit %d iterations for section %s — breaking",
                        _MAX_ABSORB_ROUNDS,
                        sec_name,
                    )
                    break
                _absorb_round += 1
                absorbed_any = False
                # Rebuild func_end_to_name and reverse lookup after each round
                func_end_to_name.clear()
                name_end_to_start: dict[tuple[str, int], int] = {}
                for item_off, item_data in items_by_off.items():
                    end_off = item_off + item_data["size"]
                    func_end_to_name[end_off] = item_data["name"]
                    name_end_to_start[(item_data["name"], end_off)] = item_off

                for func_end_off in sorted(func_end_to_name):
                    if func_end_off >= sec_size:
                        continue
                    # Find next function start after this end (O(log n) via
                    # bisect).  Uses ALL known starts (incl. unannotated
                    # registry functions) so absorption never crosses one.
                    # bisect_left so an end exactly touching the next function's
                    # start yields an empty gap instead of skipping past it (which
                    # would re-absorb the next function's body on later rounds).
                    bis_idx = bisect.bisect_left(boundary_starts, func_end_off)
                    next_func_off = (
                        boundary_starts[bis_idx] if bis_idx < len(boundary_starts) else sec_size
                    )

                    # Check what's in the gap
                    gap_bytes = text_data[func_end_off:next_func_off]
                    if not gap_bytes:
                        continue

                    absorb_size = 0

                    # Check Ghidra data labels at gap start
                    dl_result = _find_ghidra_data_label(sec_va + func_end_off, label_index)
                    is_switch_data = False
                    if dl_result is not None:
                        label_va, dl_info = dl_result
                        if dl_info.state == "data":
                            label_end_off = (label_va + dl_info.size) - sec_va
                            absorb_size = min(label_end_off, next_func_off) - func_end_off
                            is_switch_data = True
                    elif is_jump_table(gap_bytes, sec_va, sec_size):
                        is_switch_data = True

                    if is_switch_data:
                        # Absorb entire gap up to next function, trimming
                        # only trailing NOP/INT3 padding (switch tables include
                        # both pointer arrays and index/lookup tables)
                        absorb_size = trim_trailing_padding(gap_bytes)

                    # Check for out-of-line code (jumps back into function body)
                    if absorb_size == 0 and trim_trailing_padding(gap_bytes) > 0:
                        func_start_off = name_end_to_start.get(
                            (func_end_to_name[func_end_off], func_end_off)
                        )
                        if func_start_off is not None and has_back_jumps(
                            gap_bytes, func_start_off, func_end_off, base_offset=func_end_off
                        ):
                            absorb_size = trim_trailing_padding(gap_bytes)

                    # Catch-all: small non-padding gaps that follow a function
                    # and weren't detected as separate functions by any tool.
                    # These are typically out-of-line epilogues, IAT thunk tails,
                    # small helper snippets, or switch index tables.
                    if (
                        absorb_size == 0
                        and len(gap_bytes) <= _MAX_TAIL_ABSORB
                        and trim_trailing_padding(gap_bytes) > 0
                    ):
                        absorb_size = trim_trailing_padding(gap_bytes)

                    if absorb_size > 0:
                        parent_name = func_end_to_name[func_end_off]
                        # Find the parent via pre-built reverse lookup (O(1))
                        parent_off = name_end_to_start.get((parent_name, func_end_off))
                        if parent_off is not None and parent_off in items_by_off:
                            items_by_off[parent_off]["size"] += absorb_size
                            # Also update the functions dict if present
                            if parent_name in functions:
                                functions[parent_name]["size"] += absorb_size
                            absorbed_any = True

                if absorbed_any:
                    item_starts = sorted(items_by_off)

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
            # Classify gap: padding, ghidra label, thunk, jump table, or unclassified
            gap_state = "none"
            gap_label: str | None = None
            gap_parent: str | None = None
            if sec_name == ".text" and text_data is not None:
                gap_bytes = text_data[off:gap_end]
                if gap_bytes and trim_trailing_padding(gap_bytes) == 0:
                    gap_state = "padding"
                else:
                    dl_result = _find_ghidra_data_label(sec_va + off, label_index)
                    if dl_result is not None:
                        label_va, dl_info = dl_result
                        gap_state = dl_info.state
                        gap_label = dl_info.label or None
                        # Extend gap to cover full label region (merge into one segment)
                        label_end_off = (label_va + dl_info.size) - sec_va
                        gap_end = min(sec_size, label_end_off, next_off)
                    elif (sec_va + off) in thunk_offsets:
                        gap_state = "thunk"
                        gap_label = thunk_offsets[sec_va + off] or None
                        # Extend to thunk's canonical size from registry
                        if registry and (sec_va + off) in registry:
                            thunk_size = registry[sec_va + off].get("canonical_size", 0)
                            if thunk_size > 0:
                                gap_end = min(sec_size, off + thunk_size, next_off)
                    elif is_jump_table(gap_bytes, sec_va, sec_size):
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

    original_dll_path = ""
    if bin_path and root_dir:
        try:
            original_dll_path = f"/{bin_path.relative_to(root_dir)}"
        except ValueError:
            original_dll_path = f"/{bin_path.name}"

    # Project-relative reversed-source root; recoverage uses it to resolve .c
    # file paths for the detail panels.  Falls back to "/src/<target>" only
    # when root_dir is unavailable (path-less invocation).
    source_root = ""
    if src_dir and root_dir:
        try:
            source_root = f"/{src_dir.relative_to(root_dir)}"
        except ValueError:
            source_root = "/" + src_dir.name

    return {
        "sections": sections,
        "globals": globals_dict,
        "paths": {
            "originalDll": original_dll_path,
            "sourceRoot": source_root,
        },
        "summary": {
            "totalFunctions": len(fn_vas),
            "matchedFunctions": len(fn_vas) - stub_count,
            "exactMatches": exact_count,
            "relocMatches": reloc_count,
            "nearMatchCount": near_match_count,
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
