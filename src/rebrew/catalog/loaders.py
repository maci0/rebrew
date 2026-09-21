"""catalog/loaders.py - File loaders and parsers for function/data sources.

Loads Ghidra function JSON, function lists, Ghidra data labels,
and scans reversed directories for annotated source files.
"""

import json
import threading
import warnings
from pathlib import Path
from typing import Any

from rebrew.annotation import Annotation, parse_c_file_multi, parse_library_header
from rebrew.catalog.models import FunctionEntry, GhidraDataLabel
from rebrew.config import ProjectConfig
from rebrew.sources import iter_library_headers, iter_sources, target_marker

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
        # Entries stamped `_generated_by: "rebrew catalog"` are the catalog's
        # OWN compatibility export — consuming them as Ghidra evidence on the
        # next run would inflate detection stats with our own output.
        return [
            FunctionEntry.from_dict(d)
            for d in data
            if isinstance(d, dict) and d.get("_generated_by") != "rebrew catalog"
        ]
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
        # VA 0 is reserved/null — skip duplicates
        if gdl.va and gdl.size and gdl.va != 0 and gdl.va not in result:
            result[gdl.va] = gdl
    return result


# ---------------------------------------------------------------------------
# Discovery inventory (function_structure.json)
# ---------------------------------------------------------------------------

# Path-keyed cache of discovery inventories (multiple projects per process).
# Value is ``(mtime_size_fp, funcs)`` so a rewrite replaces the same slot
# instead of orphaning a new ``path:mtime`` key on every edit (unbounded growth).
# Fingerprint includes size: same-ns rewrites (``cp -p``, coarse filesystems)
# must not keep serving the previous inventory.
# Guarded: eviction is a multi-step next(iter)+del on a shared dict; concurrent
# catalog/verify callers must not race the check-then-act.
_function_list_cache: dict[str, tuple[str, list[dict[str, Any]]]] = {}
_FUNCTION_LIST_CACHE_MAX = 32
_function_list_cache_lock = threading.Lock()
# VA frozenset derived from the same inventory — avoids rebuilding
# ``{f["va"] for f in funcs}`` on every EXTRACT_ERROR in verify.
_function_vas_cache: dict[str, tuple[str, frozenset[int]]] = {}


def _inventory_fingerprint(path: str) -> str:
    """``mtime_ns:size`` for *path*, or ``""`` when unreadable / unset."""
    if not path:
        return ""
    try:
        st = Path(path).stat()
    except OSError:
        return ""
    return f"{st.st_mtime_ns}:{st.st_size}"


def cached_function_list(cfg: ProjectConfig) -> list[dict[str, Any]]:
    """Discovery inventory as ``[{va, size, name}]``, once per path.

    Reads ``function_structure.json`` next to the target (written by
    ``rebrew intake``/``discover`` or a Ghidra export) — the former
    ``functions.txt`` list is gone.  Returns ``[]`` when unset, missing,
    or corrupt.  Corruption is logged at WARNING — callers that must not
    treat a corrupt inventory as empty (e.g. orphan pruning) should call
    :func:`load_function_structure` and fail closed instead.
    """
    import logging

    from rebrew.config import FUNCTION_STRUCTURE_JSON

    reversed_dir = getattr(cfg, "reversed_dir", "")
    path = str(Path(reversed_dir) / FUNCTION_STRUCTURE_JSON) if reversed_dir else ""
    fp = _inventory_fingerprint(path)
    cache_key = path if path else ""
    with _function_list_cache_lock:
        cached = _function_list_cache.get(cache_key)
        if cached is not None and cached[0] == fp:
            return list(cached[1])
    try:
        funcs = [
            {"va": e.va, "size": e.size, "name": e.name or e.tool_name}
            for e in load_function_structure(Path(path))
            if path and Path(path).is_file()
        ]
    except (OSError, ValueError, KeyError) as exc:
        logging.getLogger(__name__).warning(
            "Failed to load function inventory %s (%s); treating as empty",
            path or "<unset>",
            exc,
        )
        funcs = []
    with _function_list_cache_lock:
        if (
            len(_function_list_cache) >= _FUNCTION_LIST_CACHE_MAX
            and cache_key not in _function_list_cache
        ):
            oldest = next(iter(_function_list_cache))
            _function_list_cache.pop(oldest, None)
            _function_vas_cache.pop(oldest, None)
        _function_list_cache[cache_key] = (fp, funcs)
        _function_vas_cache[cache_key] = (
            fp,
            frozenset(va for f in funcs if isinstance((va := f.get("va")), int)),
        )
    return list(funcs)


def cached_function_vas(cfg: ProjectConfig) -> frozenset[int]:
    """VA set for the discovery inventory, once per path.

    Shares invalidation with :func:`cached_function_list`.  Prefer this over
    rebuilding a set comprehension from the list on hot membership checks.
    """
    from rebrew.config import FUNCTION_STRUCTURE_JSON

    reversed_dir = getattr(cfg, "reversed_dir", "")
    path = str(Path(reversed_dir) / FUNCTION_STRUCTURE_JSON) if reversed_dir else ""
    fp = _inventory_fingerprint(path)
    cache_key = path if path else ""
    with _function_list_cache_lock:
        cached = _function_vas_cache.get(cache_key)
        if cached is not None and cached[0] == fp:
            return cached[1]
        list_cached = _function_list_cache.get(cache_key)
        if list_cached is not None and list_cached[0] == fp:
            vas = frozenset(va for f in list_cached[1] if isinstance((va := f.get("va")), int))
            _function_vas_cache[cache_key] = (fp, vas)
            return vas
    # Populate both caches via the list loader, then re-read the VA set.
    cached_function_list(cfg)
    with _function_list_cache_lock:
        cached = _function_vas_cache.get(cache_key)
        if cached is not None and cached[0] == fp:
            return cached[1]
    return frozenset()


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

    When *cfg* is provided, merges each directory's ``rebrew-functions.toml``
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

    # Scan library_*.h files for LIBRARY markers (CRT/zlib identifications).
    # `cfg` makes the scan include the project's shared root, which
    # scan_reversed_dir already covered for the catalog.
    for hfile in iter_library_headers(reversed_dir, cfg):
        parsed = parse_library_header(
            hfile,
            target_name=target_marker(cfg),
            metadata_dir=cfg.metadata_dir if cfg else None,
        )
        entries.extend(parsed)

    return entries
