"""catalog/loaders.py - File loaders and parsers for function/data sources.

Loads Ghidra function JSON, function lists, Ghidra data labels,
and scans reversed directories for annotated source files.
"""

import json
import re
import warnings
from pathlib import Path
from typing import Any

from rebrew.annotation import Annotation, parse_c_file_multi, parse_library_header
from rebrew.catalog.models import FunctionEntry, GhidraDataLabel
from rebrew.catalog.registry import make_func_entry
from rebrew.catalog.sections import trim_trailing_padding
from rebrew.config import ProjectConfig

# ---------------------------------------------------------------------------
# Ghidra function loader
# ---------------------------------------------------------------------------


def load_function_structure(path: Path) -> list[FunctionEntry]:
    """Load the function structure cache (``function_structure.json``).

    Returns an empty list if the file does not exist.
    Raises ``ValueError`` if the file is corrupt, ``OSError`` on I/O failure.
    """
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(
                f"Corrupt structure JSON at {path.name}: Expected a JSON array, got {type(data).__name__}"
            )
        return [FunctionEntry.from_dict(d) for d in data if isinstance(d, dict)]
    except json.JSONDecodeError as e:
        raise ValueError(f"Corrupt structure JSON at {path.name}: {e}") from e


def _classify_ghidra_label(label: str) -> str:
    """Classify a Ghidra data label name into a grid cell state string.

    Returns ``"thunk"`` for ``thunk_*`` prefixed labels, ``"data"`` otherwise
    (switch tables are absorbed into parent functions during grid generation).
    """
    low = label.lower()
    if low.startswith("thunk_"):
        return "thunk"
    return "data"


def load_ghidra_data_labels(src_dir: Path | None) -> dict[int, GhidraDataLabel]:
    """Load Ghidra data labels → {va: GhidraDataLabel}.

    Tries ghidra_data_labels.json first, falls back to ghidra_switchdata.json
    (older format).

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
        if not isinstance(entries, list):
            return {}
    except (json.JSONDecodeError, OSError):
        return {}

    result: dict[int, GhidraDataLabel] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        gdl = GhidraDataLabel.from_dict(entry)
        if gdl.label:
            gdl.state = _classify_ghidra_label(gdl.label)
        if gdl.va and gdl.size:
            result[gdl.va] = gdl
    return result


# ---------------------------------------------------------------------------
# Function list parser
# ---------------------------------------------------------------------------

_FUNC_LINE_RE_SIZE_FIRST = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+(\d+)\s+(\S+)")
_FUNC_LINE_RE_NAME_FIRST = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+(\S+)\s+(\d+)\s*$")


def parse_function_list(path: Path) -> list[dict[str, Any]]:
    """Parse function list into list of {va, size, name}."""
    funcs: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        warnings.warn(f"Cannot read {path}", stacklevel=2)
        return funcs

    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue

        m1 = _FUNC_LINE_RE_SIZE_FIRST.match(line)
        if m1:
            funcs.append(
                make_func_entry(
                    va=int(m1.group(1), 16),
                    size=int(m1.group(2)),
                    name=m1.group(3),
                )
            )
            continue

        m2 = _FUNC_LINE_RE_NAME_FIRST.match(line)
        if m2:
            funcs.append(
                make_func_entry(
                    va=int(m2.group(1), 16),
                    size=int(m2.group(3)),
                    name=m2.group(2),
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
        # Trim trailing CC/90 padding
        return data[: trim_trailing_padding(data)]
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_reversed_dir(reversed_dir: Path, cfg: ProjectConfig | None = None) -> list[Annotation]:
    """Scan source files and ``library_*.h`` headers under *reversed_dir*.

    Supports multi-function files: a single source file may contain multiple
    ``// FUNCTION:`` blocks, each generating a separate entry.

    When *cfg* is provided, merges each directory's ``rebrew-function.toml``
    metadata so that volatile fields (STATUS, CFLAGS, SIZE, BLOCKER, etc.)
    are visible to catalog tools.  When *cfg* is None, volatile metadata is
    not loaded.
    """
    from rebrew.cli import iter_library_headers, iter_sources, target_marker

    entries: list[Annotation] = []
    for cfile in iter_sources(reversed_dir, cfg):
        parsed = parse_c_file_multi(
            cfile,
            target_name=target_marker(cfg),
            base_dir=reversed_dir,
            metadata_dir=cfg.metadata_dir if cfg else None,
        )
        entries.extend(parsed)

    # Scan library_*.h files for LIBRARY markers (CRT/zlib identifications)
    for hfile in iter_library_headers(reversed_dir):
        parsed = parse_library_header(hfile, target_name=target_marker(cfg))
        entries.extend(parsed)

    return entries
