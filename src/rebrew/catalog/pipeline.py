"""catalog/pipeline.py — Build catalog scan/registry/coverage data.

Domain orchestration shared by ``rebrew catalog`` and ``rebrew build-db
--regen``.  Lives outside ``cli.py`` so library callers do not import the
Typer entry module.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from rich.console import Console

from rebrew.catalog.grid import generate_data_json
from rebrew.catalog.loaders import cached_function_list, scan_reversed_dir
from rebrew.catalog.registry import build_function_registry, count_detection_sources
from rebrew.config import inventory_path_for
from rebrew.sections import get_text_section_size

console = Console(stderr=True)


def build_catalog_data(cfg: Any, *, with_data: bool = True) -> dict[str, Any]:
    """Scan, registry, and coverage-grid dict for one target (no disk writes).

    Shared by ``run_catalog`` (which then writes the requested artifacts)
    and ``rebrew build-db --regen`` (which imports the dict straight into
    SQLite) — the ``db/data_<target>.json`` file is just the serialized
    form of this dict, not a separate pipeline stage.  With
    *with_data* False the (expensive) grid generation is skipped — the
    ``data`` value is None.
    """
    bin_path = cfg.target_binary
    reversed_dir = cfg.reversed_dir
    ghidra_json_path = inventory_path_for(reversed_dir, cfg)

    console.print(f"Scanning {reversed_dir}...", style="dim")
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)

    # Load the discovery inventory
    jobs = getattr(cfg, "default_jobs", 4) or 4

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        future_funcs = pool.submit(cached_function_list, cfg)
        funcs = future_funcs.result()

    # The .text size drives the coverage percentage.  A missing binary used
    # to fall back to a fabricated 0x24000 (92160B) section — coverage was
    # then reported against a made-up denominator, indistinguishable from a
    # real measurement and ingested as truth by build-db/dashboards.
    # Use 0 instead (coverage_pct → 0.0) and say so.
    text_size = 0
    binary_missing = bin_path is None or not bin_path.exists()
    if not binary_missing:
        text_size = get_text_section_size(bin_path)
    if binary_missing:
        console.print(
            f"[yellow]warning:[/yellow] target binary missing ({bin_path}) — "
            "text_size=0, coverage reported as 0%",
            style="dim",
        )

    try:
        registry = build_function_registry(funcs, cfg, ghidra_json_path, bin_path)
    except ValueError as exc:
        # A corrupt function_structure.json must fail with a clean message,
        # not a raw traceback (skeleton.py guards the identical load).
        raise ValueError(f"Corrupt {ghidra_json_path}: {exc}") from exc

    unique_vas = {e["va"] for e in entries}
    ghidra_count, list_count, both_count, thunk_count = count_detection_sources(registry)
    console.print(
        f"Found {len(entries)} annotations ({len(unique_vas)} unique VAs) "
        f"from {len(registry)} total functions "
        f"(list: {list_count}, ghidra: {ghidra_count}, both: {both_count}, "
        f"thunks: {thunk_count})",
        style="dim",
    )
    data = (
        generate_data_json(
            entries,
            funcs,
            text_size,
            bin_path,
            registry,
            reversed_dir,
            cfg.root,
            metadata_dir=cfg.metadata_dir,
            cfg=cfg,
        )
        if with_data
        else None
    )
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
