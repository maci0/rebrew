"""catalog/sections.py - Binary section and globals helpers.

Provides section parsing from binary headers and global variable
scanning from annotated source files.
"""

import re
import sys
from pathlib import Path
from typing import Any

from rebrew.binary_loader import load_binary
from rebrew.config import ProjectConfig

_GLOBAL_COMMENT_RE = re.compile(r"(?://|/\*)\s*GLOBAL:\s*(?P<target>[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)")
_DECL_NAME_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[.*\])?\s*;")
_ARRAY_SIZE_RE = re.compile(r"\[(\d+)\]")


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


def get_globals(src_dir: Path, cfg: ProjectConfig | None = None) -> dict[int, dict[str, Any]]:
    globals_dict: dict[int, dict[str, Any]] = {}
    from rebrew.cli import iter_sources

    for p in iter_sources(src_dir, cfg):
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            for i, line in enumerate(lines):
                m = _GLOBAL_COMMENT_RE.search(line)
                if m:
                    va = int(m.group(2), 16)
                    decl = ""
                    if i + 1 < len(lines):
                        decl = lines[i + 1].strip()

                    name = "unknown"
                    name_m = _DECL_NAME_RE.search(decl)
                    if name_m:
                        name = name_m.group(1)

                    origin = m.group("target")  # MODULE from // GLOBAL: MODULE 0xVA

                    # Estimate size from declaration type
                    size = 4  # default pointer-sized
                    if decl:
                        if "char" in decl and "[" in decl:
                            arr_m = _ARRAY_SIZE_RE.search(decl)
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
