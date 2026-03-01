"""catalog/registry.py - Function registry building and size resolution.

Merges function list and Ghidra function lists into a unified registry with
smart size resolution (jump table detection, padding absorption, etc.).
"""

import contextlib
import json
import struct
from pathlib import Path
from typing import Any, cast

from rebrew.binary_loader import load_binary
from rebrew.config import ProjectConfig

# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def make_func_entry(va: int, size: int, name: str) -> dict[str, int | str]:
    """Create a normalized function-list record."""
    return {"va": va, "size": size, "name": name}


def make_ghidra_func(va: int, size: int, name: str) -> dict[str, int | str]:
    """Create a normalized Ghidra function record."""
    return {"va": va, "size": size, "ghidra_name": name}


# Default r2 entries with known bogus sizes (analysis artifacts).
# Projects should define their own via r2_bogus_vas in rebrew-project.toml.
_DEFAULT_R2_BOGUS_SIZES: set[int] = set()


# ---------------------------------------------------------------------------
# Jump table detection (shared by registry + grid)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Canonical size resolution
# ---------------------------------------------------------------------------


def _resolve_canonical_size(
    sizes: dict[str, int],
    va: int,
    text_data: bytes | None,
    text_va: int,
    text_size: int,
) -> tuple[int, str]:
    """When list_size > ghidra_size, check if extra bytes are jump table / padding.

    Returns (canonical_size, reason_string).
    """
    ghidra_size = sizes.get("ghidra", 0)
    list_size = sizes.get("list", 0)

    if not ghidra_size and not list_size:
        return 0, "none"

    if not ghidra_size:
        return list_size, "list (only source)"
    if not list_size:
        return ghidra_size, "ghidra (only source)"

    if ghidra_size >= list_size:
        return ghidra_size, "ghidra (larger or equal)"

    # list_size > ghidra_size — check if extra bytes are jump table / padding
    if text_data is None:
        return ghidra_size, "ghidra (no binary data to verify)"

    ghidra_end = va - text_va + ghidra_size
    list_end = va - text_va + list_size

    if ghidra_end < 0 or list_end > len(text_data):
        return ghidra_size, "ghidra (extra bytes out of range)"

    extra = text_data[ghidra_end:list_end]
    if not extra:
        return ghidra_size, "ghidra (no extra bytes)"

    # Check if extra bytes are NOP/INT3 padding
    if all(b in (0x90, 0xCC) for b in extra):
        return list_size, "list (includes tail padding)"

    # Check if extra bytes are a jump table (array of .text pointers)
    if _is_jump_table(extra, text_va, text_size):
        return list_size, "list (includes jump table)"

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
        return list_size, "list (includes out-of-line code)"

    # Default: trust Ghidra when we can't identify the extra bytes
    return ghidra_size, "ghidra (unrecognized extra bytes)"


# ---------------------------------------------------------------------------
# Registry builder
# ---------------------------------------------------------------------------


def build_function_registry(
    funcs: list[dict[str, Any]],
    cfg: ProjectConfig | None,
    ghidra_path: Path | None = None,
    bin_path: Path | None = None,
) -> dict[int, dict[str, Any]]:
    """Build a unified function registry merging function list + ghidra + exports.

    Returns dict keyed by VA with:
        detected_by: list of tool names
        size_by_tool: {tool: size}
        list_name / ghidra_name: tool-specific names
        is_thunk: bool
        is_export: bool
        canonical_size: best-known size
    """
    registry: dict[int, dict[str, Any]] = {}

    # --- Function list ---
    r2_bogus = (
        set(cfg.r2_bogus_vas) if cfg and hasattr(cfg, "r2_bogus_vas") else _DEFAULT_R2_BOGUS_SIZES
    )
    for func in funcs:
        va = int(func["va"])
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "list_name": "",
                "ghidra_name": "",
                "is_thunk": va in cfg.iat_thunks if cfg else False,
                "is_export": va in cfg.dll_exports if cfg else False,
                "canonical_size": 0,
            },
        )
        detected_by = cast(list[str], entry["detected_by"])
        if "list" not in detected_by:
            detected_by.append("list")
        size_by_tool = cast(dict[str, int], entry["size_by_tool"])
        list_size = int(func["size"])
        if va not in r2_bogus:
            size_by_tool["list"] = list_size
        entry["list_name"] = str(func["name"])

    # --- Ghidra functions (from cached JSON) ---
    ghidra_funcs: list[dict[str, Any]] = []
    if ghidra_path and ghidra_path.exists():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            ghidra_funcs = cast(
                list[dict[str, Any]],
                json.loads(ghidra_path.read_text(encoding="utf-8")),
            )

    for func in ghidra_funcs:
        va = int(func["va"])
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "list_name": "",
                "ghidra_name": "",
                "is_thunk": va in cfg.iat_thunks if cfg else False,
                "is_export": va in cfg.dll_exports if cfg else False,
                "canonical_size": 0,
            },
        )
        detected_by = cast(list[str], entry["detected_by"])
        if "ghidra" not in detected_by:
            detected_by.append("ghidra")
        size_by_tool = cast(dict[str, int], entry["size_by_tool"])
        size_by_tool["ghidra"] = int(func["size"])
        entry["ghidra_name"] = str(func["ghidra_name"])

    # --- Exports ---
    exports: dict[int, str] = cfg.dll_exports if cfg else {}
    for va, _name in exports.items():
        entry = registry.setdefault(
            va,
            {
                "detected_by": [],
                "size_by_tool": {},
                "list_name": "",
                "ghidra_name": "",
                "is_thunk": False,
                "is_export": True,
                "canonical_size": 0,
            },
        )
        detected_by = cast(list[str], entry["detected_by"])
        if "exports" not in detected_by:
            detected_by.append("exports")

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
        sizes = cast(dict[str, int], entry["size_by_tool"])
        canonical, reason = _resolve_canonical_size(sizes, va, text_data, text_va, text_size_val)
        entry["canonical_size"] = canonical
        entry["size_reason"] = reason

    return registry
