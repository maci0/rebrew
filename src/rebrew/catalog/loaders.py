"""catalog/loaders.py - File loaders and parsers for function/data sources.

Loads Ghidra function JSON, function lists, Ghidra data labels,
and scans reversed directories for annotated source files.
"""

import threading
from typing import Any
lazy import warnings
lazy from collections.abc import Sequence
lazy from pathlib import Path

lazy import msgspec

lazy from rebrew.catalog.models import FunctionEntry, GhidraDataLabel
lazy from rebrew.config import ProjectConfig, inventory_path_for, target_module
lazy from rebrew.metadata.bindings import (
    SourceBinding,
    iter_source_bindings,
    library_bindings_for_file,
    library_inventory_bindings,
    read_source_bindings,
)
lazy from rebrew.source.discovery import iter_library_headers, iter_sources, scan_files
lazy from rebrew.utils import parse_int_literal, preset_module_key, read_json_text

# ---------------------------------------------------------------------------
# Ghidra function loader
# ---------------------------------------------------------------------------


# Decoded structure-JSON payloads, keyed by path.  The file is multi-MB on a
# real target and several commands (source import-related, binsync overlay,
# similarity) build a registry more than once per run, so the read + ``json.loads``
# is repeated for identical bytes.  Value is ``(mtime_size_fp, cost, data)``; a
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
    data = msgspec.json.decode(text)
    if not isinstance(data, list):
        raise ValueError(
            f"Corrupt structure JSON at {path}: Expected a JSON array, got {type(data).__name__}"
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
        # Entries stamped `_generated_by: "rebrew coverage catalog"` are the catalog's
        # OWN compatibility export — consuming them as Ghidra evidence on the
        # next run would inflate detection stats with our own output.
        return [
            FunctionEntry.from_dict(d)
            for d in data
            if isinstance(d, dict) and d.get("_generated_by") != "rebrew coverage catalog"
        ]
    except msgspec.DecodeError as e:
        raise ValueError(f"Corrupt structure JSON at {path}: {e}") from e


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

    path = src_dir / "ghidra_data_labels.json"
    if not path.exists():
        path = src_dir / "ghidra_switchdata.json"
    if not path.exists():
        return {}

    try:
        entries = msgspec.json.decode(read_json_text(path))
        if not isinstance(entries, list):
            warnings.warn(
                f"Ignoring corrupt Ghidra data labels at {path}: expected JSON array, got {type(entries).__name__}",
                stacklevel=2,
            )
            return {}
    except ValueError as exc:
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
_function_list_cache: dict[str, tuple[str, tuple[dict[str, Any], ...]]] = {}
_FUNCTION_LIST_CACHE_MAX = 32
_function_list_cache_lock = threading.Lock()
# VA frozenset derived from the same inventory — avoids rebuilding
# ``{f["va"] for f in funcs}`` on every EXTRACT_ERROR in verify.
_function_vas_cache: dict[str, tuple[str, frozenset[int]]] = {}
# Same derivation, ordered: callers that bisect for the next function VA
# (skeleton generation, gap tracing) run once per function over a batch.
_sorted_vas_cache: dict[str, tuple[str, tuple[int, ...]]] = {}
# VA → entry, same fingerprint. A size or name lookup runs once per function
# (verify, asm, binsync import); scanning the inventory each time is the
# whole list again.
_function_by_va_cache: dict[str, tuple[str, dict[int, dict[str, Any]]]] = {}


def _inventory_fingerprint(path: str) -> str:
    """``mtime_ns:ctime_ns:size:ino`` for *path*, or ``""`` when unreadable / unset."""
    if not path:
        return ""
    try:
        st = Path(path).stat()
    except OSError:
        return ""
    return f"{st.st_mtime_ns}:{st.st_ctime_ns}:{st.st_size}:{st.st_ino}"


def cached_function_list(cfg: ProjectConfig) -> tuple[dict[str, Any], ...]:
    """Discovery inventory as ``({va, size, name}, ...)``, once per path.

    Reads ``function_structure.json`` next to the target (written by
    ``rebrew intake``/``discover`` or a Ghidra export) — the former
    ``functions.txt`` list is gone.  Returns ``()`` when unset, missing,
    or corrupt.  Corruption is logged at WARNING — callers that must not
    treat a corrupt inventory as empty (e.g. orphan pruning) should call
    :func:`load_function_structure` and fail closed instead.

    The tuple and its dicts are the cached objects. A hit returns them
    without copying: verify, asm, and the other per-function lookups call
    this once per function, and copying every entry each time dominated
    the lookup. Mutate a copy (``dict(entry)``), not the entry itself.
    """
    import logging

    reversed_dir = getattr(cfg, "reversed_dir", "")
    path = str(inventory_path_for(reversed_dir, cfg)) if reversed_dir else ""
    fp = _inventory_fingerprint(path)
    with _function_list_cache_lock:
        cached = _function_list_cache.get(path)
        if cached is not None and cached[0] == fp:
            return cached[1]
    loaded: list[dict[str, Any]] = []
    if path and Path(path).is_file():
        try:
            loaded = [
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
            # mtime/size would otherwise pin () until the file is rewritten.
            return ()
    funcs = tuple(loaded)
    with _function_list_cache_lock:
        if (
            len(_function_list_cache) >= _FUNCTION_LIST_CACHE_MAX
            and path not in _function_list_cache
        ):
            oldest = next(iter(_function_list_cache))
            _function_list_cache.pop(oldest, None)
            _function_vas_cache.pop(oldest, None)
            _sorted_vas_cache.pop(oldest, None)
            _function_by_va_cache.pop(oldest, None)
        _function_list_cache[path] = (fp, funcs)
        _function_vas_cache[path] = (
            fp,
            frozenset(va for f in funcs if isinstance((va := f.get("va")), int)),
        )
        _sorted_vas_cache[path] = (
            fp,
            tuple(sorted(va for f in funcs if isinstance((va := f.get("va")), int))),
        )
    return funcs


def trusted_function_list(cfg: ProjectConfig) -> list[dict[str, Any]]:
    """Read the retained inventory without the live cache's degraded fallback."""
    path = inventory_path_for(cfg.reversed_dir, cfg)
    if not path.is_file():
        raise ValueError("trusted coverage inventory is missing")
    functions = load_function_structure(path)
    result: list[dict[str, Any]] = [
        {"va": e.va, "size": e.size, "name": e.name or e.tool_name} for e in functions
    ]
    if len({item["va"] for item in result}) != len(result) or any(
        item["va"] < 0 or item["size"] < 0 for item in result
    ):
        raise ValueError("trusted coverage inventory has ambiguous extents")
    return result


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


def cached_function_by_va(cfg: ProjectConfig) -> dict[int, dict[str, Any]]:
    """Discovery inventory keyed by VA, once per path.

    Shares invalidation with :func:`cached_function_list`. The values are
    that cache's own entries, so a lookup reads size and name without
    scanning the inventory. A duplicate VA keeps the first entry.
    """
    reversed_dir = getattr(cfg, "reversed_dir", "")
    path = str(inventory_path_for(reversed_dir, cfg)) if reversed_dir else ""
    fp = _inventory_fingerprint(path)
    with _function_list_cache_lock:
        cached = _function_by_va_cache.get(path)
        if cached is not None and cached[0] == fp:
            return cached[1]
        listed = _function_list_cache.get(path)
    funcs = listed[1] if listed is not None and listed[0] == fp else cached_function_list(cfg)
    by_va: dict[int, dict[str, Any]] = {}
    for entry in funcs:
        va = entry.get("va")
        if isinstance(va, int):
            by_va.setdefault(va, entry)
    with _function_list_cache_lock:
        current = _function_list_cache.get(path)
        if current is not None and current[0] == fp:
            _function_by_va_cache[path] = (fp, by_va)
    return by_va


def cached_sorted_function_vas(cfg: ProjectConfig) -> tuple[int, ...]:
    """Function VAs from the discovery inventory, ascending, once per path.

    Shares invalidation with :func:`cached_function_list`.  Callers that ask
    "which function starts after this VA" read this instead of re-sorting
    the inventory on every lookup.
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

    Shared by discover and intake.  Handles both afl column
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
                four_col_size = parse_int_literal(p[2])
            except ValueError:
                four_col_size = None
        if four_col_size is not None:
            size, name = four_col_size, p[3]
        elif len(p) >= 3:
            try:
                # Rizin versions differ on size radix (decimal vs 0x-prefixed
                # hex); parse_int_literal tolerates both without misreading plain
                # decimal as hex.
                size = parse_int_literal(p[1])
            except ValueError:
                continue
            name = p[2]
        else:
            continue
        if size < 0:
            continue
        if name in ("->", "loc") or name.startswith("sub."):
            name = f"fcn.{va:08x}"
        funcs.append((va, size, name))
    return funcs


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_source_bindings(
    reversed_dir: Path,
    cfg: ProjectConfig | None,
    sources: Sequence[Path],
    metadata_root: Path,
    function_entries: dict[tuple[str, int], dict[str, Any]],
) -> list[tuple[Path, list[SourceBinding]]]:
    """Each source's bindings, as :func:`scan_reversed_dir` reads them, in *sources* order.

    A source that fails to parse raises, as in the scan.  *metadata_root* is the
    scan's store root (``cfg.metadata_dir``, else *reversed_dir*) and
    *function_entries* its function store (``load_metadata(..., deepcopy=False)``).
    """
    from rebrew.metadata.data import data_file_index, data_rows_for_path, load_data_metadata

    if not sources:
        # A scan with no sources does not read the data store.
        return []
    data_entries = load_data_metadata(metadata_root, deepcopy=False)
    data_index = data_file_index(metadata_root)
    return [
        (
            cfile,
            read_source_bindings(
                cfile,
                target_name=target_module(cfg),
                base_dir=reversed_dir,
                metadata_dir=metadata_root,
                project_root=cfg.root if cfg else None,
                # One snapshot of both stores for every source, instead of
                # re-reading and re-fingerprinting them per file.
                function_entries=function_entries,
                preloaded_data_rows=data_rows_for_path(metadata_root, cfile, index=data_index),
                data_entries=data_entries,
            ),
        )
        for cfile in sources
    ]


def scan_reversed_dir(
    reversed_dir: Path,
    cfg: ProjectConfig | None = None,
    *,
    inventory_only: bool = False,
    scanned: Sequence[Path] | None = None,
    source_bindings: list[tuple[Path, list[SourceBinding]]] | None = None,
    similarity: bool = True,
) -> list[SourceBinding]:
    """Scan source files and ``library_*.h`` headers under *reversed_dir*.

    Supports multi-function files through stored identities or address anchors.
    With *inventory_only*, metadata-backed files need no source parsing;
    declaration consumers retain prototype and anchor validation by default.

    Loads the dedicated function store once: ``cfg.metadata_dir`` when *cfg*
    is provided, otherwise *reversed_dir* itself.  Its volatile fields (STATUS,
    CFLAGS, SIZE, BLOCKER, etc.) are then visible to catalog tools.

    *scanned* is a :func:`rebrew.source.discovery.scan_files` result for
    *reversed_dir*, so a caller that already walked the tree does not walk it
    again for sources and headers.  *source_bindings* is a
    :func:`scan_source_bindings` result for the same sources, so a caller that
    also needs them per file reads each source once.  Without *similarity* the
    bindings carry no ``similarity``; checking that each stored score is still
    current hashes every function's compile inputs.
    """
    entries: list[SourceBinding] = []
    # Hoisted: `metadata_dir` re-derives its answer with a filesystem probe
    # per ancestor, and this loop runs once per source file.
    metadata_root = cfg.metadata_dir if cfg else reversed_dir
    from rebrew.metadata.functions import load_metadata

    metadata = load_metadata(metadata_root, deepcopy=False)
    tree = list(scanned) if scanned is not None else scan_files(reversed_dir)
    sources = iter_sources(reversed_dir, cfg, scanned=tree)
    if inventory_only:
        for _cfile, parsed in iter_source_bindings(
            sources,
            target=target_module(cfg),
            base_dir=reversed_dir,
            metadata_dir=metadata_root,
            project_root=cfg.root if cfg else None,
            inventory_only=True,
            function_entries=metadata,
        ):
            entries.extend(parsed)
    else:
        if source_bindings is None:
            source_bindings = scan_source_bindings(
                reversed_dir, cfg, sources, metadata_root, metadata
            )
        for _cfile, parsed in source_bindings:
            entries.extend(parsed)

    # Scan library_*.h files for LIBRARY bindings (CRT/zlib identifications).
    # `cfg` makes the scan include the project's shared root, which
    # scan_reversed_dir already covered for the catalog.
    # Headers carry no target affinity in their path, so keep only rows of
    # this target's module (sources are scoped by read_source_bindings above).
    target_module_name = preset_module_key(target_module(cfg)) if cfg else ""
    from rebrew.function_providers import bind_compiled_source, compiled_source_annotations

    for hfile in iter_library_headers(reversed_dir, cfg, scanned=tree):
        parsed = library_bindings_for_file(
            hfile,
            metadata_dir=metadata_root,
            function_entries=metadata,
            inventory_only=inventory_only,
        )
        if cfg:
            parsed = [
                bind_compiled_source(cfg, entry, metadata.get((entry.module, entry.va), {}))
                for entry in parsed
                if not target_module_name
                or preset_module_key(entry.module or "") in ("", target_module_name)
            ]
        entries.extend(
            e
            for e in parsed
            if not target_module_name
            or preset_module_key(e.module or "") in ("", target_module_name)
        )

    seen = {(entry.module, entry.va) for entry in entries}
    if cfg and metadata_root is not None:
        for entry in library_inventory_bindings(
            metadata_root, reversed_dir, function_entries=metadata
        ):
            if (
                not target_module_name
                or preset_module_key(entry.module or "") in ("", target_module_name)
            ) and (
                entry.module,
                entry.va,
            ) not in seen:
                entries.append(
                    bind_compiled_source(cfg, entry, metadata.get((entry.module, entry.va), {}))
                )
                seen.add((entry.module, entry.va))
        for entry in compiled_source_annotations(cfg, metadata=metadata):
            if (entry.module, entry.va) not in seen:
                entries.append(entry)
                seen.add((entry.module, entry.va))

    if cfg is not None and similarity:
        from rebrew.verify.hash import current_similarity

        for entry in entries:
            entry.similarity = current_similarity(cfg, metadata.get((entry.module, entry.va), {}))

    return entries
