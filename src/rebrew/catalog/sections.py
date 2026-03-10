"""catalog/sections.py - Binary section and globals helpers.

Provides section parsing from binary headers, global variable
scanning from annotated source files, and shared x86 code-analysis
utilities (back-jump detection, padding trimming).
"""

import re
import struct
import warnings
from pathlib import Path
from typing import Any

from rebrew.binary_loader import load_binary
from rebrew.config import ProjectConfig

# Padding opcodes that can be trimmed from function tails (INT3 and NOP).
PADDING_BYTES: tuple[int, ...] = (0xCC, 0x90)


def trim_trailing_padding(data: bytes, padding: tuple[int, ...] = PADDING_BYTES) -> int:
    """Return the length of *data* after stripping trailing padding bytes.

    >>> trim_trailing_padding(b'\\x55\\x89\\xe5\\xcc\\xcc')
    3
    >>> trim_trailing_padding(b'\\xcc\\xcc\\xcc')
    0
    """
    end = len(data)
    while end > 0 and data[end - 1] in padding:
        end -= 1
    return end


def has_back_jumps(
    data: bytes,
    func_start_off: int,
    func_end_off: int,
    base_offset: int,
) -> bool:
    """Check if *data* (starting at *base_offset*) contains jumps targeting
    the range [*func_start_off*, *func_end_off*).

    Detects x86 near jmp (E9), near jcc (0F 8x), short jmp (EB), and
    short jcc (70-7F).  Used to identify out-of-line code that belongs
    to the preceding function.
    """
    i = 0
    while i < len(data):
        b = data[i]
        # Near relative jmp (E9)
        if b == 0xE9 and i + 5 <= len(data):
            rel = struct.unpack_from("<i", data, i + 1)[0]
            target = base_offset + i + 5 + rel
            if func_start_off <= target < func_end_off:
                return True
            i += 5
            continue
        # Near jcc (0F 80-8F)
        if b == 0x0F and i + 6 <= len(data) and 0x80 <= data[i + 1] <= 0x8F:
            rel = struct.unpack_from("<i", data, i + 2)[0]
            target = base_offset + i + 6 + rel
            if func_start_off <= target < func_end_off:
                return True
            i += 6
            continue
        # Short jmp (EB)
        if b == 0xEB and i + 2 <= len(data):
            rel = struct.unpack_from("<b", data, i + 1)[0]
            target = base_offset + i + 2 + rel
            if func_start_off <= target < func_end_off:
                return True
            i += 2
            continue
        # Short jcc (70-7F)
        if 0x70 <= b <= 0x7F and i + 2 <= len(data):
            rel = struct.unpack_from("<b", data, i + 1)[0]
            target = base_offset + i + 2 + rel
            if func_start_off <= target < func_end_off:
                return True
            i += 2
            continue
        i += 1
    return False


_GLOBAL_COMMENT_RE = re.compile(r"(?://|/\*)\s*GLOBAL:\s*(?P<target>[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)")
_DECL_NAME_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[.*\])?\s*;")
_ARRAY_SIZE_RE = re.compile(r"\[(\d+)\]")


def get_sections(bin_path: Path) -> dict[str, dict[str, int]]:
    """Return section metadata keyed by section name."""
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
        warnings.warn(f"Failed to parse binary sections: {e}", stacklevel=2)
        return {}


def get_globals(src_dir: Path, cfg: ProjectConfig | None = None) -> dict[int, dict[str, Any]]:
    """Scan annotated sources and return globals keyed by VA."""
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
                            "module": origin,
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
    except (ImportError, OSError, KeyError, ValueError, RuntimeError):
        return 0
