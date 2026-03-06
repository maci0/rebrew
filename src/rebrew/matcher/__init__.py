"""matcher – Core GA engine for binary matching.

Re-exports the public API: compilation backend, scoring, mutation operators,
flag sweep, build cache, checkpointing, and COFF/PE parsers.
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
from .core import (
    compute_args_hash as compute_args_hash,
)
from .core import (
    load_checkpoint as load_checkpoint,
)
from .core import (
    save_checkpoint as save_checkpoint,
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
from .scoring import diff_functions as diff_functions
from .scoring import score_candidate as score_candidate
from .scoring import structural_similarity as structural_similarity
