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

import argparse
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants (from config, with hardcoded fallbacks for standalone use)
# ---------------------------------------------------------------------------
try:
    from rebrew.config import cfg as _cfg
    IMAGE_BASE = _cfg.image_base
    TEXT_VA = _cfg.text_va
    TEXT_RAW_OFFSET = _cfg.text_raw_offset
except Exception:
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
    r"//\s*(?P<type>FUNCTION|LIBRARY|STUB):\s*SERVER\s+(?P<va>0x[0-9a-fA-F]+)"
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


def va_to_file_offset(va: int) -> int:
    return va - TEXT_VA + TEXT_RAW_OFFSET


def extract_dll_bytes(dll_path: Path, va: int, size: int) -> Optional[bytes]:
    """Extract raw bytes from DLL at given VA."""
    try:
        with open(dll_path, "rb") as f:
            f.seek(va_to_file_offset(va))
            data = f.read(size)
        # Trim trailing CC/90 padding
        while data and data[-1] in (0xCC, 0x90):
            data = data[:-1]
        return data
    except (OSError, ValueError):
        return None


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
# Verification (--verify)
# ---------------------------------------------------------------------------


def verify_entry(entry: dict, dll_path: Path, root: Path) -> Tuple[bool, str]:
    """Compile a .c file and compare output bytes against DLL."""
    cfile = root / "src" / "server_dll" / entry["filepath"]
    if not cfile.exists():
        return False, f"File not found: {cfile}"

    cl_exe = str(root / "tools" / "MSVC600" / "VC98" / "Bin" / "CL.EXE")
    inc_path = str(root / "tools" / "MSVC600" / "VC98" / "Include")

    cflags_str = entry["cflags"]
    cflags = cflags_str.split() if cflags_str else ["/O2"]
    symbol = entry["symbol"] if entry["symbol"] else "_" + entry["name"]

    target_bytes = extract_dll_bytes(dll_path, entry["va"], entry["size"])
    if target_bytes is None:
        return False, "Cannot extract DLL bytes"

    workdir = tempfile.mkdtemp(prefix="validate_")
    try:
        src_name = cfile.name
        local_src = os.path.join(workdir, src_name)
        shutil.copy2(str(cfile), local_src)

        obj_name = os.path.splitext(src_name)[0] + ".obj"
        cmd = (
            ["wine", cl_exe, "/nologo", "/c", "/MT", "/Gd"]
            + cflags
            + [f"/I{inc_path}", f"/Fo{obj_name}", src_name]
        )
        env = cfg.msvc_env()
        r = subprocess.run(cmd, capture_output=True, cwd=workdir, env=env, timeout=30)
        obj_path = os.path.join(workdir, obj_name)

        if r.returncode != 0 or not os.path.exists(obj_path):
            return False, f"Compile error: {r.stderr.decode()[:200]}"

        obj_bytes, reloc_offsets = parse_coff_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            return False, f"Symbol '{symbol}' not found in .obj"

        if len(obj_bytes) != len(target_bytes):
            return (
                False,
                f"Size mismatch: got {len(obj_bytes)}B, want {len(target_bytes)}B",
            )

        # Compare with reloc masking
        reloc_set = set()
        if reloc_offsets:
            for ro in reloc_offsets:
                for j in range(4):
                    if ro + j < len(obj_bytes):
                        reloc_set.add(ro + j)

        mismatches = []
        for i in range(len(obj_bytes)):
            if i in reloc_set:
                continue
            if obj_bytes[i] != target_bytes[i]:
                mismatches.append(i)

        if not mismatches:
            if reloc_offsets:
                return True, f"RELOC-NORM MATCH ({len(reloc_offsets)} relocs)"
            else:
                return True, "EXACT MATCH"
        else:
            return False, f"MISMATCH: {len(mismatches)} byte diffs at {mismatches[:5]}"

    except subprocess.TimeoutExpired:
        return False, "Compile timed out"
    except Exception as exc:
        return False, f"Error: {exc}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Text section size
# ---------------------------------------------------------------------------


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


def main():
    parser = argparse.ArgumentParser(
        description="Rebrew verification pipeline: compile each .c and verify bytes match."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Project root directory",
    )
    args = parser.parse_args()

    root = args.root
    try:
        from rebrew.config import load_config
        _c = load_config(root)
        dll_path = _c.target_binary
        reversed_dir = _c.reversed_dir
    except Exception:
        dll_path = root / "original" / "Server" / "server.dll"
        reversed_dir = root / "src" / "server_dll"
    r2_path = reversed_dir / "r2_functions.txt"
    ghidra_json_path = reversed_dir / "ghidra_functions.json"

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

    # Verify

    if not dll_path.exists():
        print(f"ERROR: {dll_path} not found", file=sys.stderr)
        return 1

    passed = 0
    failed = 0
    # Deduplicate: only verify once per VA
    seen_vas = set()
    for entry in sorted(entries, key=lambda x: x["va"]):
        if entry["va"] in seen_vas:
            continue
        seen_vas.add(entry["va"])

        ok, msg = verify_entry(entry, dll_path, root)
        status_char = "OK" if ok else "FAIL"
        print(f"  [{status_char}] 0x{entry['va']:08X} {entry['name']}: {msg}")
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\nVerification: {passed} passed, {failed} failed")
    if failed > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
