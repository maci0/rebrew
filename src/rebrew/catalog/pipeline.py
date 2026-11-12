"""catalog/pipeline.py — Build catalog scan/registry/coverage data.

Domain orchestration shared by ``rebrew coverage catalog`` and
``rebrew coverage export --output snapshots/``.  Lives outside ``cli.py`` so
library callers do not import the Typer entry module.
"""

from __future__ import annotations

lazy from typing import Any

lazy from rebrew.catalog.grid import build_coverage_data
lazy from rebrew.catalog.loaders import (
    cached_function_list,
    scan_reversed_dir,
    trusted_function_list,
)
lazy from rebrew.catalog.registry import build_function_registry, count_detection_sources
lazy from rebrew.config import inventory_path_for
lazy from rebrew.sections import get_text_section_size
lazy from rebrew.utils import console
lazy from rebrew.workspace.status import TrustedCoverage


def build_catalog_data(
    cfg: Any,
    *,
    with_data: bool = True,
    progress: bool = True,
    trusted: TrustedCoverage | None = None,
) -> dict[str, Any]:
    """Build scan, registry, and coverage-grid data without changing canonical metadata.

    Reads may refresh the metadata-doc and data-scan-roles disk caches.
    Shared by ``run_catalog`` (which then writes the requested artifacts)
    and ``rebrew coverage export --output snapshots/`` (which renders the dict into
    ``snapshots/coverage-<target>.toml``).  With *with_data* False the (expensive)
    grid generation is skipped and the ``data`` value is None.
    """
    bin_path = cfg.target_binary
    reversed_dir = cfg.reversed_dir
    ghidra_json_path = inventory_path_for(reversed_dir, cfg)

    if progress:
        console.print(f"Scanning {reversed_dir}...", style="dim")
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)

    funcs = cached_function_list(cfg) if trusted is None else trusted_function_list(cfg)
    if trusted is not None:
        entries = trusted.bind(cfg, entries, funcs)

    # The .text size drives the coverage percentage.  With no binary there
    # is no real denominator, so report 0 (coverage_pct -> 0.0) and say so.
    binary_missing = bin_path is None or not bin_path.is_file()
    if binary_missing:
        if progress:
            console.print(
                f"[yellow]warning:[/yellow] target binary missing ({bin_path}) — "
                "text_size=0, identified bytes reported as 0%",
                style="dim",
            )
        text_size = 0
    else:
        text_size = get_text_section_size(bin_path)

    try:
        registry = build_function_registry(funcs, cfg, ghidra_json_path, bin_path)
    except ValueError as exc:
        # A corrupt function_structure.json must fail with a clean message,
        # not a raw traceback (skeleton.py guards the identical load).
        raise ValueError(f"Corrupt {ghidra_json_path}: {exc}") from exc

    unique_vas = {e["va"] for e in entries}
    ghidra_count, list_count, both_count, thunk_count = count_detection_sources(registry)
    if progress:
        console.print(
            f"Found {len(entries)} annotations ({len(unique_vas)} unique VAs); "
            f"inventory: {len(registry)} functions "
            f"(list: {list_count}, ghidra: {ghidra_count}, both: {both_count}, "
            f"thunks: {thunk_count})",
            style="dim",
        )
    data = (
        build_coverage_data(
            entries,
            funcs,
            text_size,
            bin_path,
            registry,
            reversed_dir,
            cfg.root,
            metadata_dir=cfg.metadata_dir,
            cfg=cfg,
            trusted=trusted is not None,
        )
        if with_data
        else None
    )
    if data is not None and trusted is None:
        for entry in entries:
            function = data["functions"].get(f"0x{entry.va:08x}")
            if function is not None and entry.similarity is not None:
                function["similarity"] = entry.similarity / 100.0
    return {
        "target": cfg.target_name,
        "entries": entries,
        "funcs": funcs,
        "registry": registry,
        "text_size": text_size,
        "binary_missing": binary_missing,
        "counts": {
            "ghidra": ghidra_count,
            "list": list_count,
            "both": both_count,
            "thunks": thunk_count,
        },
        "data": data,
    }
