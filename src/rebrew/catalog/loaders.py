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
from rebrew.config import ProjectConfig, inventory_path_for, module_marker
from rebrew.sources import iter_library_headers, iter_sources, scan_files, target_marker
from rebrew.utils import preset_module_key, read_json_text

# ---------------------------------------------------------------------------
# Ghidra function loader
# ---------------------------------------------------------------------------


# Decoded structure-JSON payloads, keyed by path.  The file is multi-MB on a
# real target and several commands (cross-import, binsync overlay, similarity)
# build a registry more than once per run, so the read + ``json.loads`` is
# repeated for identical bytes.  Value is ``(mtime_size_fp, cost, data)``; a
# rewrite replaces the same slot instead of orphaning a key per edit.  Callers
# get fresh ``FunctionEntry`` objects, so nothing here is mutable-shared.
#
# The bound is on retained source CHARACTERS, not entries: one decoded
# inventory is a multi-MB list of dicts costing several times its text as
# Python objects, so an entry cap made the real limit the heap — a
# multi-target session retaining 32 of them.  Same discipline as
# ``verify_hash._SOURCE_MEMO`` and ``data_layout._OBJDUMP_CACHE``.  One
# inventory larger than the budget still stays (its replacement is what the
# caller is about to parse anyway); it is evicted by the next store.
_structure_json_cache: dict[str, tuple[str, int, list[Any]]] = {}
_STRUCTURE_JSON_CACHE_MAX_CHARS = 32 * 1024 * 1024
_structure_json_chars = 0
_structure_json_cache_lock = threading.Lock()


def _structure_json(path: Path) -> list[Any]:
    """Decoded ``function_structure.json`` payload for *path*, once per revision.

    Raises ``ValueError`` if the file is corrupt, ``OSError`` on I/O failure.
    """
    global _structure_json_chars
    key = str(path)
    fp = _inventory_fingerprint(key)
    with _structure_json_cache_lock:
        cached = _structure_json_cache.get(key)
    if cached is not None and cached[0] == fp:
        return cached[2]
    text = read_json_text(path)
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError(
            f"Corrupt structure JSON at {path.name}: Expected a JSON array, got {type(data).__name__}"
        )
    cost = len(text)
    with _structure_json_cache_lock:
        stale = _structure_json_cache.pop(key, None)
        if stale is not None:
            _structure_json_chars -= stale[1]
        _structure_json_cache[key] = (fp, cost, data)
        _structure_json_chars += cost
        while (
            _structure_json_chars > _STRUCTURE_JSON_CACHE_MAX_CHARS
            and len(_structure_json_cache) > 1
        ):
            oldest = next(iter(_structure_json_cache))
            _structure_json_chars -= _structure_json_cache.pop(oldest)[1]
    return data


def load_function_structure(path: Path) -> list[FunctionEntry]:
    """Load the function structure cache (``function_structure.json``).

    Returns an empty list if the file does not exist.
    Raises ``ValueError`` if the file is corrupt, ``OSError`` on I/O failure.
    """
    if not path.exists():
        return []

    try:
        data = _structure_json(path)
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
        entries = json.loads(read_json_text(path))
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
        # VA 0 is reserved/null, and a negative size (or VA) is corrupt
        # export JSON: grid.py derives a gap's end from label_va + size, so a
        # negative one would shrink the gap backwards. Skip duplicates too.
        if gdl.va > 0 and gdl.size > 0 and gdl.va not in result:
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
# Same derivation, ordered: callers that bisect for the next function VA
# (skeleton generation, gap tracing) run once per function over a batch.
_sorted_vas_cache: dict[str, tuple[str, tuple[int, ...]]] = {}


def _inventory_fingerprint(path: str) -> str:
    """``mtime_ns:size:ino`` for *path*, or ``""`` when unreadable / unset."""
    if not path:
        return ""
    try:
        st = Path(path).stat()
    except OSError:
        return ""
    return f"{st.st_mtime_ns}:{st.st_size}:{st.st_ino}"


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

    reversed_dir = getattr(cfg, "reversed_dir", "")
    path = str(inventory_path_for(reversed_dir, cfg)) if reversed_dir else ""
    fp = _inventory_fingerprint(path)
    with _function_list_cache_lock:
        cached = _function_list_cache.get(path)
        if cached is not None and cached[0] == fp:
            return [dict(f) for f in cached[1]]
    funcs: list[dict[str, Any]] = []
    if path and Path(path).is_file():
        try:
            funcs = [
                {"va": e.va, "size": e.size, "name": e.name or e.tool_name}
                for e in load_function_structure(Path(path))
            ]
        except (OSError, ValueError, KeyError) as exc:
            logging.getLogger(__name__).warning(
                "Failed to load function inventory %s (%s); treating as empty",
                path,
                exc,
            )
            # Not memoized: a transient read error under an unchanged
            # mtime/size would otherwise pin [] until the file is rewritten.
            return []
    with _function_list_cache_lock:
        if (
            len(_function_list_cache) >= _FUNCTION_LIST_CACHE_MAX
            and path not in _function_list_cache
        ):
            oldest = next(iter(_function_list_cache))
            _function_list_cache.pop(oldest, None)
            _function_vas_cache.pop(oldest, None)
            _sorted_vas_cache.pop(oldest, None)
        _function_list_cache[path] = (fp, funcs)
        _function_vas_cache[path] = (
            fp,
            frozenset(va for f in funcs if isinstance((va := f.get("va")), int)),
        )
        _sorted_vas_cache[path] = (
            fp,
            tuple(sorted(va for f in funcs if isinstance((va := f.get("va")), int))),
        )
    return [dict(f) for f in funcs]


def cached_function_vas(cfg: ProjectConfig) -> frozenset[int]:
    """VA set for the discovery inventory, once per path.

    Shares invalidation with :func:`cached_function_list`.  Prefer this over
    rebuilding a set comprehension from the list on hot membership checks.
    """
    reversed_dir = getattr(cfg, "reversed_dir", "")
    path = str(inventory_path_for(reversed_dir, cfg)) if reversed_dir else ""
    fp = _inventory_fingerprint(path)
    with _function_list_cache_lock:
        cached = _function_vas_cache.get(path)
        if cached is not None and cached[0] == fp:
            return cached[1]
        list_cached = _function_list_cache.get(path)
        if list_cached is not None and list_cached[0] == fp:
            vas = frozenset(va for f in list_cached[1] if isinstance((va := f.get("va")), int))
            _function_vas_cache[path] = (fp, vas)
            return vas
    # Derive from the list the loader returns, not a re-read of the cache: a
    # concurrent rewrite between the stat above and the reload changes the
    # fingerprint, and a re-read keyed on the stale one returned an empty set.
    funcs = cached_function_list(cfg)
    return frozenset(va for f in funcs if isinstance((va := f.get("va")), int))


def cached_sorted_function_vas(cfg: ProjectConfig) -> tuple[int, ...]:
    """Function VAs from the discovery inventory, ascending, once per path.

    Shares invalidation with :func:`cached_function_list`.  Callers that ask
    "which function starts after this VA" read this instead of re-sorting
    :func:`cached_function_list`, which copies every entry per call.
    """
    reversed_dir = getattr(cfg, "reversed_dir", "")
    path = str(inventory_path_for(reversed_dir, cfg)) if reversed_dir else ""
    fp = _inventory_fingerprint(path)
    with _function_list_cache_lock:
        cached = _sorted_vas_cache.get(path)
        if cached is not None and cached[0] == fp:
            return cached[1]
    funcs = cached_function_list(cfg)
    return tuple(sorted(va for f in funcs if isinstance((va := f.get("va")), int)))


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
        # The 4-column layout is ``va offset size name``, so p[2] is the size
        # and p[3] the name.  Test for a parseable number rather than a decimal
        # one so a 0x-prefixed size still selects this branch; falling through
        # would read the offset as the size and the size as the name.
        four_col_size: int | None = None
        if len(p) >= 4:
            try:
                four_col_size = int(p[2], 0)
            except ValueError:
                four_col_size = None
        if four_col_size is not None:
            size, name = four_col_size, p[3]
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
    # Hoisted: `metadata_dir` re-derives its answer with a filesystem probe
    # per ancestor, and this loop runs once per source file.
    metadata_root = cfg.metadata_dir if cfg else None
    tree = scan_files(reversed_dir)
    for cfile in iter_sources(reversed_dir, cfg, scanned=tree):
        parsed = parse_c_file_multi(
            cfile,
            target_name=target_marker(cfg),
            base_dir=reversed_dir,
            metadata_dir=metadata_root,
        )
        entries.extend(parsed)

    # Scan library_*.h files for LIBRARY markers (CRT/zlib identifications).
    # `cfg` makes the scan include the project's shared root, which
    # scan_reversed_dir already covered for the catalog.
    # Headers carry no target affinity in their path, so keep only rows of
    # this target's module (sources are scoped by parse_c_file_multi above).
    marker = preset_module_key(module_marker(cfg)) if cfg else ""
    for hfile in iter_library_headers(reversed_dir, cfg, scanned=tree):
        parsed = parse_library_header(hfile, metadata_dir=metadata_root)
        entries.extend(
            e for e in parsed if not marker or preset_module_key(e.module or "") in ("", marker)
        )

    return entries
