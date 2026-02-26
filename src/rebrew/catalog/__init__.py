"""catalog - Unified function catalog and reporting package.

Re-exports all public names for backward compatibility so that
``from rebrew.catalog import X`` continues to work unchanged.
"""

from rebrew.catalog.cli import app as app
from rebrew.catalog.cli import main_entry as main_entry
from rebrew.catalog.export import generate_catalog as generate_catalog
from rebrew.catalog.export import generate_reccmp_csv as generate_reccmp_csv
from rebrew.catalog.grid import generate_data_json as generate_data_json
from rebrew.catalog.grid import merge_ranges as merge_ranges
from rebrew.catalog.loaders import extract_dll_bytes as extract_dll_bytes
from rebrew.catalog.loaders import load_ghidra_data_labels as load_ghidra_data_labels
from rebrew.catalog.loaders import load_ghidra_functions as load_ghidra_functions
from rebrew.catalog.loaders import parse_r2_functions as parse_r2_functions
from rebrew.catalog.loaders import scan_reversed_dir as scan_reversed_dir
from rebrew.catalog.registry import _DEFAULT_R2_BOGUS_SIZES as _DEFAULT_R2_BOGUS_SIZES
from rebrew.catalog.registry import _is_jump_table as _is_jump_table
from rebrew.catalog.registry import build_function_registry as build_function_registry
from rebrew.catalog.registry import make_ghidra_func as make_ghidra_func
from rebrew.catalog.registry import make_r2_func as make_r2_func
from rebrew.catalog.sections import get_globals as get_globals
from rebrew.catalog.sections import get_sections as get_sections
from rebrew.catalog.sections import get_text_section_size as get_text_section_size
