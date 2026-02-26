"""catalog/grid.py - Coverage grid and data.json generation.

Builds cell-level coverage maps for binary sections, handling jump table
detection, gap absorption, padding classification, and thunk identification.
"""

import hashlib
import math
import struct
from pathlib import Path
from typing import Any

from rebrew.catalog.loaders import extract_dll_bytes, load_ghidra_data_labels
from rebrew.catalog.registry import _is_jump_table
from rebrew.catalog.sections import get_globals, get_sections


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


def generate_data_json(
    entries: list[Any],
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

    sections: dict[str, Any] = {}
    if bin_path:
        for k, v in get_sections(bin_path).items():
            sections[k] = dict(v)
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
        segments: list[tuple[int, int, str, list[str], str | None, str | None]] = []
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
