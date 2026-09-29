"""matcher – Core GA engine for binary matching.

Public names resolve lazily via :func:`__getattr__` so importing
``rebrew.matcher.parsers`` (compile / verify infrastructure) does not load the
GA mutator or compiler stack.  Flag tables stay at package root
(``rebrew.flag_data``) for the same reason.
"""

from __future__ import annotations

import threading
from importlib import import_module
from typing import TYPE_CHECKING, Any

from rebrew.flag_data import (
    COMMON_MSVC_FLAGS as COMMON_MSVC_FLAGS,
)
from rebrew.flag_data import (
    MSVC6_FLAGS as MSVC6_FLAGS,
)
from rebrew.flag_data import (
    MSVC_SWEEP_TIERS as MSVC_SWEEP_TIERS,
)
from rebrew.flags import Checkbox as Checkbox
from rebrew.flags import Flags as Flags
from rebrew.flags import FlagSet as FlagSet

if TYPE_CHECKING:
    # Mirrors _LAZY_EXPORTS so a consumer type-checking
    # ``from rebrew.matcher import build_candidate`` sees the real signature
    # instead of ``Any`` from __getattr__.  tests/test_sdk_surface.py fails
    # when the two lists drift.  Nothing here runs at import time.
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
    from .mutations.runtime import (
        MUTATION_ATTEMPTS as MUTATION_ATTEMPTS,
    )
    from .mutations.runtime import (
        get_target_range as get_target_range,
    )
    from .mutations.runtime import (
        set_target_range as set_target_range,
    )
    from .mutator import (
        ALL_MUTATIONS as ALL_MUTATIONS,
    )
    from .mutator import (
        MutationLog as MutationLog,
    )
    from .mutator import (
        compute_population_diversity as compute_population_diversity,
    )
    from .mutator import (
        crossover as crossover,
    )
    from .mutator import (
        mutate_chain as mutate_chain,
    )
    from .mutator import (
        mutate_code as mutate_code,
    )
    from .mutator import (
        quick_validate as quick_validate,
    )
    from .mutator import (
        refresh_mutations as refresh_mutations,
    )
    from .mutator import (
        split_preamble_body as split_preamble_body,
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
        iter_ga_runs as iter_ga_runs,
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

# (submodule, attribute) — resolved on first attribute access.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "parse_c_ast": (".ast_engine", "parse_c_ast"),
    "build_candidate": (".compiler", "build_candidate"),
    "build_candidate_obj_only": (".compiler", "build_candidate_obj_only"),
    "flag_sweep": (".compiler", "flag_sweep"),
    "generate_flag_combinations": (".compiler", "generate_flag_combinations"),
    "BuildResult": (".core", "BuildResult"),
    "GACheckpoint": (".core", "GACheckpoint"),
    "Score": (".core", "Score"),
    "StructuralSimilarity": (".core", "StructuralSimilarity"),
    "set_target_range": (".mutations.runtime", "set_target_range"),
    "get_target_range": (".mutations.runtime", "get_target_range"),
    "MUTATION_ATTEMPTS": (".mutations.runtime", "MUTATION_ATTEMPTS"),
    "extract_function_from_binary": (".parsers", "extract_function_from_binary"),
    "list_obj_symbols": (".parsers", "list_obj_symbols"),
    "parse_obj_relocs_full": (".parsers", "parse_obj_relocs_full"),
    "parse_obj_symbol_and_relocs": (".parsers", "parse_obj_symbol_and_relocs"),
    "parse_obj_symbol_bytes": (".parsers", "parse_obj_symbol_bytes"),
    "code_similarity": (".scoring", "code_similarity"),
    "diff_functions": (".scoring", "diff_functions"),
    "precompute_target": (".scoring", "precompute_target"),
    "score_candidate": (".scoring", "score_candidate"),
    "structural_similarity": (".scoring", "structural_similarity"),
    "SolutionEntry": (".solutions", "SolutionEntry"),
    "find_similar": (".solutions", "find_similar"),
    "iter_ga_runs": (".solutions", "iter_ga_runs"),
    "load_ga_runs": (".solutions", "load_ga_runs"),
    "load_solutions": (".solutions", "load_solutions"),
    "load_solutions_file": (".solutions", "load_solutions_file"),
    "record_ga_run": (".solutions", "record_ga_run"),
    "save_solution": (".solutions", "save_solution"),
    "save_solutions": (".solutions", "save_solutions"),
    "utc_now_iso": (".solutions", "utc_now_iso"),
    # mutator core surface (ops arrive via _load_mutator_exports)
    "mutate_code": (".mutator", "mutate_code"),
    "ALL_MUTATIONS": (".mutator", "ALL_MUTATIONS"),
    "MutationLog": (".mutator", "MutationLog"),
    "compute_population_diversity": (".mutator", "compute_population_diversity"),
    "crossover": (".mutator", "crossover"),
    "mutate_chain": (".mutator", "mutate_chain"),
    "quick_validate": (".mutator", "quick_validate"),
    "refresh_mutations": (".mutator", "refresh_mutations"),
    "split_preamble_body": (".mutator", "split_preamble_body"),
}

__all__ = [
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
    "ALL_MUTATIONS",
    "MutationLog",
    "build_candidate",
    "build_candidate_obj_only",
    "compute_population_diversity",
    "crossover",
    "diff_functions",
    "extract_function_from_binary",
    "find_similar",
    "flag_sweep",
    "generate_flag_combinations",
    "list_obj_symbols",
    "iter_ga_runs",
    "load_ga_runs",
    "load_solutions",
    "load_solutions_file",
    "mutate_chain",
    "mutate_code",
    "parse_c_ast",
    "parse_obj_relocs_full",
    "parse_obj_symbol_and_relocs",
    "parse_obj_symbol_bytes",
    "precompute_target",
    "quick_validate",
    "record_ga_run",
    "refresh_mutations",
    "save_solution",
    "save_solutions",
    "score_candidate",
    "code_similarity",
    "get_target_range",
    "MUTATION_ATTEMPTS",
    "set_target_range",
    "split_preamble_body",
    "structural_similarity",
    "utc_now_iso",
]

_mutator_loaded = False

#: Serializes :func:`_load_mutator_exports` and :func:`__getattr__`'s cache
#: stores.  The fill publishes a batch of ``globals()`` entries before flipping
#: ``_mutator_loaded``, and the GA pool plus ``match --all-targets`` reach this
#: from several threads at once, so the flag and the batch it guards have to
#: become visible together.
_LAZY_EXPORT_LOCK = threading.Lock()


def _load_mutator_exports() -> None:
    """Bind packaged ``mut_*`` ops into this package and fold them into ``__all__``."""
    global _mutator_loaded, __all__
    if _mutator_loaded:
        return
    with _LAZY_EXPORT_LOCK:
        if _mutator_loaded:
            return
        mutator = import_module(".mutator", __name__)
        mut_all: list[str] = list(mutator.__all__)
        for name in mut_all:
            globals()[name] = getattr(mutator, name)
        __all__ = list(dict.fromkeys([*__all__, *mut_all]))
        _mutator_loaded = True


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        mod_name, attr = _LAZY_EXPORTS[name]
        mod = import_module(mod_name, __name__)
        value = getattr(mod, attr)
        with _LAZY_EXPORT_LOCK:
            globals()[name] = value
        if mod_name == ".mutator":
            _load_mutator_exports()
        return value
    # Packaged mut_* ops — do not load mutator for submodule names
    # (``from rebrew.matcher import compiler`` must raise so importlib can
    # bind the submodule).
    if name.startswith("mut_"):
        _load_mutator_exports()
        if name in globals():
            return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(__all__) | {n for n in globals() if not n.startswith("_")})
