"""matcher – Core GA engine for binary matching.

Public names resolve lazily via :func:`__getattr__` so importing
``rebrew.matcher.parsers`` (compile / verify infrastructure) does not load the
GA mutator or compiler stack.  Flag tables stay at package root
(``rebrew.flag_data``) for the same reason.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

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

# (submodule, attribute) — resolved on first attribute access.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "parse_c_ast": (".ast_engine", "parse_c_ast"),
    "build_candidate": (".compiler", "build_candidate"),
    "build_candidate_obj_only": (".compiler", "build_candidate_obj_only"),
    "flag_sweep": (".compiler", "flag_sweep"),
    "generate_flag_combinations": (".compiler", "generate_flag_combinations"),
    "BuildCache": (".core", "BuildCache"),
    "BuildResult": (".core", "BuildResult"),
    "GACheckpoint": (".core", "GACheckpoint"),
    "Score": (".core", "Score"),
    "StructuralSimilarity": (".core", "StructuralSimilarity"),
    "set_target_range": (".mutations.runtime", "set_target_range"),
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
    "load_ga_runs": (".solutions", "load_ga_runs"),
    "load_solutions": (".solutions", "load_solutions"),
    "load_solutions_file": (".solutions", "load_solutions_file"),
    "record_ga_run": (".solutions", "record_ga_run"),
    "save_solution": (".solutions", "save_solution"),
    "save_solutions": (".solutions", "save_solutions"),
    # mutator core surface (ops arrive via _load_mutator_exports)
    "mutate_code": (".mutator", "mutate_code"),
    "ALL_MUTATIONS": (".mutator", "ALL_MUTATIONS"),
    "MutationLog": (".mutator", "MutationLog"),
    "compute_population_diversity": (".mutator", "compute_population_diversity"),
    "crossover": (".mutator", "crossover"),
    "mutate_chain": (".mutator", "mutate_chain"),
    "quick_validate": (".mutator", "quick_validate"),
    "refresh_mutations": (".mutator", "refresh_mutations"),
}

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
    "set_target_range",
    "structural_similarity",
]

_mutator_loaded = False


def _load_mutator_exports() -> None:
    """Bind packaged ``mut_*`` ops into this package and fold them into ``__all__``."""
    global _mutator_loaded, __all__
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
