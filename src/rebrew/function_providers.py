"""Separate library ancestry from compiled sources and prebuilt link providers."""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path, PureWindowsPath
from typing import Any

from rebrew.config import ProjectConfig, target_module
from rebrew.metadata.bindings import DATA_KINDS, SourceBinding
from rebrew.metadata.functions import (
    identity_file,
    load_metadata,
    stored_file_matches,
    validate_identity_file,
)
from rebrew.sources import contained_path, source_roots
from rebrew.utils import preset_module_key, rel_display_path


def select_source_bindings(
    cfg: ProjectConfig, entries: Sequence[SourceBinding]
) -> tuple[list[SourceBinding], list[tuple[int, str, str]]]:
    """Select one function provider per VA, retaining data and duplicate diagnostics.

    Managed file, kind and symbol bindings win over conflicting candidates.
    Without a managed provider, preserve the first source before headers.
    Both compile selection and operand catalogs must use this same decision.
    """
    metadata_dir = getattr(cfg, "metadata_dir", None)
    managed = {
        (preset_module_key(module), va): row
        for (module, va), row in (
            load_metadata(metadata_dir, deepcopy=False) if metadata_dir else {}
        ).items()
    }
    counts = Counter(entry.va for entry in entries if entry.kind not in DATA_KINDS)

    def rank(entry: SourceBinding) -> tuple[int, bool, bool, bool, bool]:
        """Resolve source paths only when a duplicate needs disambiguation."""
        filepath = getattr(entry, "filepath", "")
        if entry.kind in DATA_KINDS or counts[entry.va] < 2:
            return entry.va, False, False, False, filepath.endswith(".h")
        row = managed.get((preset_module_key(entry.module or target_module(cfg)), entry.va), {})
        path = contained_path(source_roots(cfg), filepath)
        bound = bool(
            metadata_dir
            and path
            and stored_file_matches(str(row.get("file", "")), identity_file(path, metadata_dir))
        )
        return (
            entry.va,
            not bound,
            bound and entry.kind != row.get("kind", entry.kind),
            bound and bool(row.get("symbol")) and entry.symbol != row["symbol"],
            filepath.endswith(".h"),
        )

    selected: list[SourceBinding] = []
    kept: dict[int, SourceBinding] = {}
    duplicates: list[tuple[int, str, str]] = []
    for entry in sorted(entries, key=rank):
        if entry.kind in DATA_KINDS:
            selected.append(entry)
        elif entry.va in kept:
            duplicates.append((entry.va, kept[entry.va].filepath, entry.filepath))
        else:
            kept[entry.va] = entry
            selected.append(entry)
    return selected, duplicates


def bind_compiled_source(
    cfg: ProjectConfig, entry: SourceBinding, metadata: dict[str, Any]
) -> SourceBinding:
    """Resolve an explicit source identity, retaining its function classification.

    Header annotations name reference functions; a managed ``file``/``symbol``
    identity names the translation unit and native symbol we compile. Missing
    files remain candidates so verification fails instead of silently skipping.
    """
    stored = str(metadata.get("file", ""))
    if not stored or Path(stored).suffix.casefold() not in {".c", ".cpp", ".cc", ".cxx"}:
        return entry
    validate_identity_file(stored)
    root = Path(getattr(cfg, "root", cfg.metadata_dir)).resolve()
    base = root if metadata.get("kind", entry.kind) == "LIBRARY" else Path(cfg.metadata_dir)
    source = (base / stored.replace("\\", "/")).resolve()
    if not source.is_relative_to(root):
        raise ValueError(f"function source {stored!r} escapes the project")
    return replace(
        entry,
        filepath=rel_display_path(source, cfg.reversed_dir),
        symbol=str(metadata.get("symbol") or entry.symbol),
        status=str(metadata.get("status") or "STUB"),
    )


_COMPILED_SUFFIXES = {".c", ".cpp", ".cc", ".cxx"}


def _compiled_suffix(stored: str) -> bool:
    dot = stored.rfind(".")
    return dot >= 0 and stored[dot:].lower() in _COMPILED_SUFFIXES


def _parent_is_real(parent: Path, cache: dict[Path, bool]) -> bool:
    """True when *parent* and its ancestors contain no symlink."""
    found = cache.get(parent)
    if found is None:
        found = parent.resolve() == parent
        cache[parent] = found
    return found


def _base_binding_facts(root: Path, base: Path, reversed_dir: Path) -> tuple[bool, str | None]:
    """Containment and display prefix for rows whose stored path starts at *base*.

    ``validate_identity_file`` rejects absolute and ``..`` identities, so a base
    that is lexically inside *root* keeps every row inside it. The prefix is the
    stored-path spelling of ``reversed_dir`` relative to the same base, which
    turns the common in-directory row into a slice instead of a path walk.
    """
    if not base.is_absolute():
        return False, None
    inside = base.is_relative_to(root)
    if not reversed_dir.is_absolute():
        return inside, None
    prefix = os.path.relpath(reversed_dir, base).replace(os.sep, "/")
    if prefix == ".":
        return inside, ""
    if prefix == ".." or prefix.startswith("../"):
        return inside, None
    return inside, prefix + "/"


def _plain_relative(norm: str) -> bool:
    """True when *norm* needs no path normalization before slicing its prefix."""
    return "/./" not in norm and "//" not in norm and not norm.startswith("./")


def _bind_compiled_row(
    cfg: ProjectConfig,
    entry: SourceBinding,
    metadata: dict[str, Any],
    *,
    root: Path,
    metadata_base: Path,
    reversed_dir: Path,
    real_parents: dict[Path, bool],
    base_facts: dict[Path, tuple[bool, str | None]],
) -> SourceBinding:
    """Same result as :func:`bind_compiled_source` without resolving a plain path.

    A stored relative path under a real directory matches the resolved display
    path. A symlink, or a path that is not lexically inside the project, still
    goes through the resolving binder. Containment and the display prefix are
    facts of the base, computed once per call instead of a path walk per row.
    """
    stored = str(metadata.get("file", ""))
    if not stored or not _compiled_suffix(stored):
        return entry
    validate_identity_file(stored)
    norm = stored if "\\" not in stored else stored.replace("\\", "/")
    base = root if metadata.get("kind", entry.kind) == "LIBRARY" else metadata_base
    inside, prefix = base_facts[base]
    source = base / norm
    if source.is_symlink() or not _parent_is_real(source.parent, real_parents) or not inside:
        return bind_compiled_source(cfg, entry, metadata)
    if prefix is not None and norm.startswith(prefix) and _plain_relative(norm):
        entry.filepath = norm[len(prefix) :]
    else:
        entry.filepath = rel_display_path(source, reversed_dir)
    entry.symbol = str(metadata.get("symbol") or entry.symbol)
    entry.status = str(metadata.get("status") or "STUB")
    return entry


def compiled_source_annotations(
    cfg: ProjectConfig,
    *,
    metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> list[SourceBinding]:
    """Read target-scoped compiled identities independently of source-tree discovery.

    Binding replaces a migrated header's file identity with its compiled source.
    The source can sit outside reversed_dir; missing sources remain candidates.
    """
    from rebrew.config import target_module
    from rebrew.metadata.functions import apply_metadata_entry, load_metadata
    from rebrew.utils import preset_module_key

    if metadata is None:
        metadata_dir = getattr(cfg, "metadata_dir", None)
        if metadata_dir is None:
            return []
        metadata = load_metadata(metadata_dir, deepcopy=False)
    target_module_name = preset_module_key(target_module(cfg))
    root = Path(getattr(cfg, "root", cfg.metadata_dir)).resolve()
    metadata_base = Path(cfg.metadata_dir)
    reversed_dir = Path(cfg.reversed_dir)
    real_parents: dict[Path, bool] = {}
    base_facts = {
        metadata_base: _base_binding_facts(root, metadata_base, reversed_dir),
        root: _base_binding_facts(root, root, reversed_dir),
    }
    results: list[SourceBinding] = []
    for (module, va), entry in metadata.items():
        if preset_module_key(module) != target_module_name:
            continue
        kind = entry.get("kind")
        if kind not in {"FUNCTION", "LIBRARY"}:
            continue
        stored = entry.get("file") or ""
        if not isinstance(stored, str):
            stored = str(stored)
        if not _compiled_suffix(stored):
            continue
        annotation = SourceBinding(
            module=module,
            va=va,
            name=str(entry.get("name") or ""),
            symbol=str(entry.get("symbol") or ""),
            kind=str(kind),
        )
        apply_metadata_entry(annotation, entry)
        results.append(
            _bind_compiled_row(
                cfg,
                annotation,
                entry,
                root=root,
                metadata_base=metadata_base,
                reversed_dir=reversed_dir,
                real_parents=real_parents,
                base_facts=base_facts,
            )
        )
    return results


def resolve_library_providers(
    cfg: ProjectConfig,
    entries: list[SourceBinding],
    headers: dict[int, dict[str, str]],
    library_vas: frozenset[int],
) -> list[dict[str, Any]]:
    """Describe actual providers independently of library-origin markers.

    A source identity establishes compiled ownership. Only a unique native
    symbol in a configured external archive's raw link map establishes a
    prebuilt provider; an archive name alone does not mean it was prebuilt.
    An unmatched declaration stays unresolved; its name or VA is not evidence.
    """
    from rebrew.data_ownership import parse_link_map

    rows: dict[int, dict[str, Any]] = {
        va: {"va": f"0x{va:08x}", "name": row.get("name", ""), "provider": "unresolved"}
        for va, row in headers.items()
    }
    for entry in entries:
        if entry.va in library_vas:
            rows[entry.va] = {
                "va": f"0x{entry.va:08x}",
                "name": entry.name,
                "provider": "compiled",
                "file": entry.filepath,
                "symbol": entry.symbol,
            }
    raw = getattr(cfg, "raw_link", None)
    link_map = Path(raw).with_suffix(".map") if raw else None
    symbols: dict[str, set[tuple[str, str, str]]] = {}
    prebuilt_archives = {
        PureWindowsPath(spec).stem.casefold()
        for spec in (getattr(cfg, "external_libs", None) or {}).values()
        if spec
    }
    if link_map is not None and link_map.is_file():
        for symbol in parse_link_map(
            link_map.read_text(encoding="utf-8", errors="surrogateescape")
        ):
            if symbol.is_function:
                symbols.setdefault(symbol.name, set()).add(
                    (symbol.library, symbol.member, symbol.object)
                )
    for va, row in rows.items():
        if row["provider"] == "compiled":
            continue
        name = headers[va].get("symbol", "")
        matches = symbols.get(name, set()) | symbols.get("_" + name, set()) if name else set()
        if len(matches) == 1:
            library, member, _ = next(iter(matches))
            if PureWindowsPath(library).stem.casefold() in prebuilt_archives:
                row.update(provider="prebuilt", library=library, member=member, map=str(link_map))
    return [rows[va] for va in sorted(rows)]
