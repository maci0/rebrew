"""matcher – Core GA engine for binary matching.

Re-exports the public API from all matcher submodules.
"""

from .ast_engine import (
    parse_c_ast as parse_c_ast,
)
from .compiler import (
    build_candidate as build_candidate,
)
from .compiler import (
    build_candidate_obj_only as build_candidate_obj_only,
)
from .compiler import (
    flag_sweep as flag_sweep,
)
from .compiler import (
    generate_flag_combinations as generate_flag_combinations,
)
from .core import (
    BuildCache as BuildCache,
)
from .core import (
    BuildResult as BuildResult,
)
from .core import (
    GACheckpoint as GACheckpoint,
)
from .core import (
    Score as Score,
)
from .core import (
    StructuralSimilarity as StructuralSimilarity,
)
from .flag_data import (
    COMMON_MSVC_FLAGS as COMMON_MSVC_FLAGS,
)
from .flag_data import (
    MSVC6_FLAGS as MSVC6_FLAGS,
)
from .flag_data import (
    MSVC_SWEEP_TIERS as MSVC_SWEEP_TIERS,
)
from .flags import Checkbox as Checkbox
from .flags import Flags as Flags
from .flags import FlagSet as FlagSet
from .mutator import *  # noqa: F403 — mutator.py defines __all__
from .mutator import (
    set_target_range as set_target_range,
)
from .parsers import (
    extract_function_from_binary as extract_function_from_binary,
)
from .parsers import (
    list_obj_symbols as list_obj_symbols,
)
from .parsers import (
    parse_obj_relocs_full as parse_obj_relocs_full,
)
from .parsers import (
    parse_obj_symbol_and_relocs as parse_obj_symbol_and_relocs,
)
from .parsers import (
    parse_obj_symbol_bytes as parse_obj_symbol_bytes,
)
from .scoring import (
    code_similarity as code_similarity,
)
from .scoring import (
    diff_functions as diff_functions,
)
from .scoring import (
    precompute_target as precompute_target,
)
from .scoring import (
    score_candidate as score_candidate,
)
from .scoring import (
    structural_similarity as structural_similarity,
)
from .solutions import (
    SolutionEntry as SolutionEntry,
)
from .solutions import (
    find_similar as find_similar,
)
from .solutions import (
    load_ga_runs as load_ga_runs,
)
from .solutions import (
    load_solutions as load_solutions,
)
from .solutions import (
    load_solutions_file as load_solutions_file,
)
from .solutions import (
    record_ga_run as record_ga_run,
)
from .solutions import (
    save_solution as save_solution,
)
from .solutions import (
    save_solutions as save_solutions,
)

__all__ = [
    "BuildCache",
    "GACheckpoint",
    "BuildResult",
    "Checkbox",
    "COMMON_MSVC_FLAGS",
    "FlagSet",
    "Flags",
    "MSVC6_FLAGS",
    "MSVC_SWEEP_TIERS",
    "Score",
    "SolutionEntry",
    "StructuralSimilarity",
    "build_candidate",
    "build_candidate_obj_only",
    "diff_functions",
    "extract_function_from_binary",
    "find_similar",
    "flag_sweep",
    "generate_flag_combinations",
    "list_obj_symbols",
    "load_ga_runs",
    "load_solutions",
    "load_solutions_file",
    "parse_c_ast",
    "parse_obj_relocs_full",
    "parse_obj_symbol_and_relocs",
    "parse_obj_symbol_bytes",
    "precompute_target",
    "record_ga_run",
    "save_solution",
    "save_solutions",
    "score_candidate",
    "code_similarity",
    "set_target_range",
    "structural_similarity",
]
