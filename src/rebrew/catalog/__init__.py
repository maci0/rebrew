"""catalog - Unified function catalog and reporting package.

Re-exports the library API so that ``from rebrew.catalog import X`` works
without loading the Typer command in ``rebrew.catalog.cli``.
"""

lazy from rebrew.catalog.grid import (
    build_coverage_data as build_coverage_data,
)
lazy from rebrew.catalog.loaders import (
    cached_function_list as cached_function_list,
)
lazy from rebrew.catalog.loaders import (
    cached_function_vas as cached_function_vas,
)
lazy from rebrew.catalog.loaders import (
    cached_sorted_function_vas as cached_sorted_function_vas,
)
lazy from rebrew.catalog.loaders import (
    load_function_structure as load_function_structure,
)
lazy from rebrew.catalog.loaders import (
    load_ghidra_data_labels as load_ghidra_data_labels,
)
lazy from rebrew.catalog.loaders import (
    parse_rizin_afl as parse_rizin_afl,
)
lazy from rebrew.catalog.loaders import (
    scan_reversed_dir as scan_reversed_dir,
)
lazy from rebrew.catalog.models import (
    FunctionEntry as FunctionEntry,
)
lazy from rebrew.catalog.models import (
    GhidraDataLabel as GhidraDataLabel,
)
lazy from rebrew.catalog.pipeline import (
    build_catalog_data as build_catalog_data,
)
lazy from rebrew.catalog.registry import (
    RegistryEntry as RegistryEntry,
)
lazy from rebrew.catalog.registry import (
    build_function_registry as build_function_registry,
)
lazy from rebrew.catalog.registry import (
    count_detection_sources as count_detection_sources,
)
lazy from rebrew.catalog.registry import (
    is_jump_table as is_jump_table,
)

__all__ = [
    "FunctionEntry",
    "GhidraDataLabel",
    "RegistryEntry",
    "build_catalog_data",
    "build_function_registry",
    "cached_function_list",
    "cached_function_vas",
    "cached_sorted_function_vas",
    "count_detection_sources",
    "build_coverage_data",
    "is_jump_table",
    "load_function_structure",
    "load_ghidra_data_labels",
    "parse_rizin_afl",
    "scan_reversed_dir",
]
