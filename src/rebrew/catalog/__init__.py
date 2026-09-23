"""catalog - Unified function catalog and reporting package.

Re-exports the library API so that ``from rebrew.catalog import X`` works
without loading the Typer command in ``rebrew.catalog.cli``.
"""

from rebrew.catalog.export import (
    generate_reccmp_csv as generate_reccmp_csv,
)
from rebrew.catalog.grid import (
    generate_data_json as generate_data_json,
)
from rebrew.catalog.loaders import (
    cached_function_list as cached_function_list,
)
from rebrew.catalog.loaders import (
    cached_function_vas as cached_function_vas,
)
from rebrew.catalog.loaders import (
    load_function_structure as load_function_structure,
)
from rebrew.catalog.loaders import (
    load_ghidra_data_labels as load_ghidra_data_labels,
)
from rebrew.catalog.loaders import (
    parse_rizin_afl as parse_rizin_afl,
)
from rebrew.catalog.loaders import (
    scan_reversed_dir as scan_reversed_dir,
)
from rebrew.catalog.models import (
    FunctionEntry as FunctionEntry,
)
from rebrew.catalog.models import (
    GhidraDataLabel as GhidraDataLabel,
)
from rebrew.catalog.pipeline import (
    build_catalog_data as build_catalog_data,
)
from rebrew.catalog.registry import (
    RegistryEntry as RegistryEntry,
)
from rebrew.catalog.registry import (
    build_function_registry as build_function_registry,
)
from rebrew.catalog.registry import (
    count_detection_sources as count_detection_sources,
)
from rebrew.catalog.registry import (
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
    "count_detection_sources",
    "generate_data_json",
    "generate_reccmp_csv",
    "is_jump_table",
    "load_function_structure",
    "load_ghidra_data_labels",
    "parse_rizin_afl",
    "scan_reversed_dir",
]
