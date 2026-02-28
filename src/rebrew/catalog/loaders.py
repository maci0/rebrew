"""catalog/loaders.py - File loaders and parsers for function/data sources.

Loads Ghidra function JSON, function lists, Ghidra data labels,
and scans reversed directories for annotated source files.
"""

import json
import re
import sys
from pathlib import Path

from rebrew.annotation import Annotation, parse_c_file_multi
from rebrew.catalog.registry import make_func_entry
from rebrew.config import ProjectConfig

# ---------------------------------------------------------------------------
# Ghidra function loader
# ---------------------------------------------------------------------------


def load_ghidra_functions(path: Path) -> list[dict[str, object]]:
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


def load_ghidra_data_labels(src_dir: Path | None) -> dict[int, dict[str, object]]:
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

    result: dict[int, dict[str, object]] = {}
    for entry in entries:
        va = entry.get("va", 0)
        size = entry.get("size", 0)
        if va and size:
            label = entry.get("label", "")
            state = _classify_ghidra_label(label) if label else "data"
            result[va] = {"size": size, "label": label, "state": state}
    return result


# ---------------------------------------------------------------------------
# Function list parser
# ---------------------------------------------------------------------------

_FUNC_LINE_RE = re.compile(r"\s*(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)")


def parse_function_list(path: Path) -> list[dict[str, object]]:
    """Parse function list into list of {va, size, name}."""
    funcs = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        print(f"WARNING: Cannot read {path}", file=sys.stderr)
        return funcs

    for line in text.splitlines():
        m = _FUNC_LINE_RE.match(line)
        if m:
            funcs.append(
                make_func_entry(
                    va=int(m.group(1), 16),
                    size=int(m.group(2)),
                    name=m.group(3),
                )
            )
    return funcs


# ---------------------------------------------------------------------------
# DLL byte extraction
# ---------------------------------------------------------------------------


def extract_dll_bytes(bin_path: Path, file_offset: int, size: int) -> bytes | None:
    """Extract raw bytes from DLL at given file offset."""
    try:
        with bin_path.open("rb") as f:
            f.seek(file_offset)
            data = f.read(size)
        # Trim trailing CC/90 padding (index-based to avoid O(n^2) copies)
        end = len(data)
        while end > 0 and data[end - 1] in (0xCC, 0x90):
            end -= 1
        return data[:end]
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_reversed_dir(reversed_dir: Path, cfg: ProjectConfig | None = None) -> list[Annotation]:
    """Scan target dir source files and parse annotations from each.

    Supports multi-function files: a single source file may contain multiple
    ``// FUNCTION:`` blocks, each generating a separate entry.
    """
    from rebrew.cli import iter_sources

    entries: list[Annotation] = []
    for cfile in iter_sources(reversed_dir, cfg):
        parsed = parse_c_file_multi(cfile, target_name=cfg.marker if cfg else None)
        entries.extend(parsed)
    return entries
