"""matcher – Core GA engine for binary matching.

Re-exports the public API from all matcher submodules.
"""

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
from .parsers import (
    extract_function_from_binary as extract_function_from_binary,
)
from .parsers import (
    list_obj_symbols as list_obj_symbols,
)
from .parsers import (
    parse_obj_symbol_bytes as parse_obj_symbol_bytes,
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
    record_ga_run as record_ga_run,
)
from .solutions import (
    save_solution as save_solution,
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
    "parse_obj_symbol_bytes",
    "precompute_target",
    "record_ga_run",
    "save_solution",
    "score_candidate",
    "structural_similarity",
]
