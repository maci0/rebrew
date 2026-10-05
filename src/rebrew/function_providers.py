"""Separate library ancestry from compiled sources and prebuilt link providers."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path, PureWindowsPath
from typing import Any

from rebrew.annotation import Annotation
from rebrew.config import ProjectConfig
from rebrew.metadata import validate_identity_file
from rebrew.utils import rel_display_path


def bind_library_source(
    cfg: ProjectConfig, entry: Annotation, metadata: dict[str, Any]
) -> Annotation:
    """Resolve an explicit library source identity, retaining its library origin.

    Header annotations name reference functions; a managed ``file``/``symbol``
    identity names the translation unit and native symbol we compile. Missing
    files remain candidates so verification fails instead of silently skipping.
    """
    stored = str(metadata.get("file", ""))
    if not stored or Path(stored).suffix.casefold() not in {".c", ".cpp", ".cc", ".cxx"}:
        return entry
    validate_identity_file(stored)
    root = Path(cfg.root).resolve()
    source = (root / stored.replace("\\", "/")).resolve()
    if not source.is_relative_to(root):
        raise ValueError(f"library source {stored!r} escapes the project")
    return replace(
        entry,
        filepath=rel_display_path(source, cfg.reversed_dir),
        symbol=str(metadata.get("symbol") or entry.symbol),
        status=str(metadata.get("status") or "STUB"),
    )


def compiled_library_annotations(
    cfg: ProjectConfig,
    *,
    metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> list[Annotation]:
    """Read target-scoped compiled library identities independently of headers.

    Binding replaces a migrated header's file identity with its compiled source.
    The source can sit outside reversed_dir; missing sources remain candidates.
    """
    from rebrew.config import module_marker
    from rebrew.metadata import apply_metadata_entry, load_metadata
    from rebrew.utils import preset_module_key

    if metadata is None:
        metadata_dir = getattr(cfg, "metadata_dir", None)
        if metadata_dir is None:
            return []
        metadata = load_metadata(metadata_dir, deepcopy=False)
    marker = preset_module_key(module_marker(cfg))
    results: list[Annotation] = []
    for (module, va), entry in metadata.items():
        stored = str(entry.get("file", ""))
        if (
            preset_module_key(module) != marker
            or entry.get("marker_type") != "LIBRARY"
            or Path(stored).suffix.casefold() not in {".c", ".cpp", ".cc", ".cxx"}
        ):
            continue
        annotation = Annotation(
            module=module,
            va=va,
            name=str(entry.get("name") or ""),
            symbol=str(entry.get("symbol") or ""),
            marker_type="LIBRARY",
        )
        apply_metadata_entry(annotation, entry)
        results.append(bind_library_source(cfg, annotation, entry))
    return results


def resolve_library_providers(
    cfg: ProjectConfig,
    entries: list[Annotation],
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
