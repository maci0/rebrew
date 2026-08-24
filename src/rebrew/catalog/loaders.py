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
from rebrew.config import ProjectConfig
from rebrew.sources import iter_library_headers, iter_sources, target_marker
from rebrew.utils import read_source_text


def make_func_entry(va: int, size: int, name: str) -> dict[str, int | str]:
    """Create a normalized function-list record."""
    return {"va": va, "size": size, "name": name}


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
            warnings.warn(
                f"Ignoring corrupt Ghidra data labels at {path}: expected JSON array, got {type(entries).__name__}",
                stacklevel=2,
            )
            return {}
    except json.JSONDecodeError as exc:
        warnings.warn(f"Ignoring corrupt Ghidra data labels at {path}: {exc}", stacklevel=2)
        return {}
    except OSError as exc:
        warnings.warn(f"Cannot read Ghidra data labels at {path}: {exc}", stacklevel=2)
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

# Path-keyed cache of parsed function lists (multiple projects per process).
_function_list_cache: dict[str, list[dict[str, Any]]] = {}


def cached_function_list(cfg: ProjectConfig) -> list[dict[str, Any]]:
    """Parse ``cfg.function_list`` once per path, caching the raw entries.

    Shared by crt-match and round-trip, which both need the list as a
    ``{va: …}`` map and previously duplicated the cache/parse/fallback
    scaffold.  Returns ``[]`` when the list is unset, missing, or corrupt.
    """
    path = str(getattr(cfg, "function_list", ""))
    funcs = _function_list_cache.get(path)
    if funcs is None:
        try:
            p = Path(path)
            funcs = parse_function_list(p) if p.is_file() else []
        except (OSError, ValueError, KeyError):
            funcs = []
        _function_list_cache[path] = funcs
    return funcs


def parse_function_list(path: Path) -> list[dict[str, Any]]:
    """Parse function list into list of {va, size, name}."""
    funcs: list[dict[str, Any]] = []
    try:
        text, _ = read_source_text(path)
    except OSError as exc:
        warnings.warn(f"Cannot read {path}: {exc}", stacklevel=2)
        return funcs

    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue

        m1 = _FUNC_LINE_RE_SIZE_FIRST.match(line)
        if m1:
            if m1.group(3).startswith("sym.imp."):
                # rizin names IAT slots `sym.imp.<DLL>.<func>` — the import
                # address table lives INSIDE .text on MSVC PEs, so discovery
                # walks it as code and emits a fake "function" per slot.
                # They are data, not functions; skip (see build_function_registry
                # for the VA-based guard that catches non-`sym.imp.` names too).
                continue
            if m1.group(3) == "->":
                # rizin afl alias marker ("0x1000 5 -> 0x2000"): the target
                # is its own entry, so nothing to record here.  Treating the
                # trailing number as a size fed garbage extents (e.g. an
                # 8512-byte "size" for a 6-byte thunk) into the registry and
                # verify --fix-sizes.  Mirrors parse_rizin_afl's handling.
                continue
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
            if m2.group(2).startswith("sym.imp."):
                continue
            if m2.group(2) == "->":
                # rizin afl alias marker ("0x1000 -> 0x2000") — see above.
                continue
            funcs.append(
                make_func_entry(
                    va=int(m2.group(1), 16),
                    size=int(m2.group(3)),
                    name=m2.group(2),
                )
            )

    return funcs


def parse_rizin_afl(text: str) -> list[tuple[int, int, str]]:
    """Parse rizin ``afl`` output into ``(va, size, name)`` tuples.

    Shared by discover and intake, which previously each hand-rolled a
    parser with subtly different column handling.  Handles both afl column
    layouts (``va size name`` / ``va offset size name``) and rizin versions
    that print sizes as 0x-prefixed hex; ``->``/``loc``/``sub.*`` names are
    normalized to ``fcn.<va>``.
    """
    funcs: list[tuple[int, int, str]] = []
    for line in text.splitlines():
        p = line.split()
        if not p or not p[0].startswith("0x"):
            continue
        try:
            va = int(p[0], 16)
        except ValueError:
            continue
        if len(p) >= 4 and p[2].isdigit():
            size, name = int(p[2]), p[3]
        elif len(p) >= 3:
            try:
                # Rizin versions differ on size radix (decimal vs 0x-prefixed
                # hex); int(x, 0) tolerates both without misreading plain
                # decimal as hex.
                size = int(p[1], 0)
            except ValueError:
                continue
            name = p[2]
        else:
            continue
        if name in ("->", "loc") or name.startswith("sub."):
            name = f"fcn.{va:08x}"
        funcs.append((va, size, name))
    return funcs


# ---------------------------------------------------------------------------
# DLL byte extraction
# ---------------------------------------------------------------------------

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

    # Shared sources: the project-level shared root serves every target, so
    # its library_*.h LIBRARY markers participate in each target's scan too.
    if cfg is not None:
        shared = getattr(cfg, "shared_dir", None)
        if shared is not None and shared.is_dir():
            for hfile in iter_library_headers(shared):
                parsed = parse_library_header(hfile, target_name=target_marker(cfg))
                entries.extend(parsed)

    return entries
