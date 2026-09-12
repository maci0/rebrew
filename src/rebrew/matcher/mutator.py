"""mutator.py – Unified C source mutation engine for GA-based binary matching.

Provides mutation functions that transform C89 source code to explore
the MSVC6 code generation space.  Uses tree-sitter AST for most mutations,
with regex fallback for complex multi-statement patterns.

Public API: ``mutate_code(source, rng, track_mutation=False)`` applies a random
mutation.  When ``track_mutation=True``, returns ``(mutated_source, mutation_name)``
instead of just str.  Returns original source unchanged if all attempts fail.
"""

import logging
import random
from collections.abc import Callable
from functools import lru_cache
from typing import Literal, overload

from rebrew.matcher.mutations.advanced import (
    mut_add_loop_break,
    mut_commute_float_operands,
    mut_extract_condition_to_var,
    mut_hoist_common_tail,
    mut_if_else_call_to_ternary_arg,
    mut_loop_condition_extraction,
    mut_loop_to_memcpy,
    mut_memcpy_to_loop,
    mut_merge_nested_ifs,
    mut_register_param,
    mut_remove_loop_break,
    mut_sink_common_tail,
    mut_split_and_condition,
    mut_split_or_condition,
    mut_ternary_arg_to_if_else_call,
    mut_toggle_dllimport,
    mut_unregister_param,
    mut_widen_local_type,
)
from rebrew.matcher.mutations.basic import (
    _split_preamble_body,
    compute_population_diversity,
    crossover,
    mut_accum_to_early_return,
    mut_add_cast,
    mut_add_redundant_parens,
    mut_add_register_keyword,
    mut_bitand_to_if_false,
    mut_change_array_index_order,
    mut_change_param_order,
    mut_change_return_type,
    mut_combine_ptr_arith,
    mut_comparison_boundary,
    mut_compound_assign_toggle,
    mut_demorgan,
    mut_dowhile_to_while,
    mut_duplicate_loop_body,
    mut_early_return_to_accum,
    mut_extract_else_body,
    mut_flip_eq_zero,
    mut_flip_lt_ge,
    mut_fold_constant_add,
    mut_for_to_while,
    mut_goto_to_return,
    mut_guard_clause,
    mut_hoist_return,
    mut_if_false_to_bitand,
    mut_if_to_ternary,
    mut_insert_noop_block,
    mut_int_to_pointer_param,
    mut_introduce_local_alias,
    mut_introduce_temp_for_call,
    mut_invert_loop_direction,
    mut_materialize_constant,
    mut_merge_declaration_init,
    mut_negate_condition,
    mut_pointer_to_int_param,
    mut_postpre_increment,
    mut_reassociate_add,
    mut_remove_cast,
    mut_remove_register_keyword,
    mut_remove_temp_var,
    mut_reorder_declarations,
    mut_reorder_elseif,
    mut_return_to_goto,
    mut_sink_return,
    mut_split_declaration_init,
    mut_split_ptr_arith,
    mut_struct_vs_ptr_access,
    mut_swap_adjacent_declarations,
    mut_swap_adjacent_stmts,
    mut_swap_and_operands,
    mut_swap_eq_operands,
    mut_swap_if_else,
    mut_swap_ne_operands,
    mut_swap_or_operands,
    mut_ternary_to_if,
    mut_toggle_bool_not,
    mut_toggle_calling_convention,
    mut_toggle_char_signedness,
    mut_toggle_signedness,
    mut_toggle_volatile,
    mut_tweak_integer_literal,
    mut_unfold_constant_add,
    mut_volatile_access,
    mut_while_to_dowhile,
    mut_while_to_for,
    mut_xor_zero_toggle,
    quick_validate,
)
from rebrew.matcher.mutations.enhancements import (
    mut_commute_add_general,
    mut_commute_bit_and,
    mut_commute_bit_or,
    mut_commute_bit_xor,
    mut_commute_mul_general,
    mut_dummy_stack_vars,
    mut_extract_complex_args,
    mut_hoist_repeated_deref,
    mut_inject_block_register,
    mut_inject_dummy_registers,
    mut_invert_if_else,
    mut_retype_local_equiv,
    mut_zero_to_bitand,
)
from rebrew.matcher.mutations.pragmas import (
    mut_add_auto_inline_pragma,
    mut_add_intrinsic_pragma,
    mut_add_optimize_pragma,
    mut_remove_auto_inline_pragma,
    mut_remove_intrinsic_pragma,
    mut_remove_optimize_pragma,
    mut_toggle_check_stack_pragma,
)
from rebrew.matcher.mutations.runtime import (
    _MUTATION_ATTEMPTS,
    _target_range,
    set_target_range,
)
from rebrew.matcher.mutations.structural import (
    mut_add_volatile_intermediate,
    mut_array_to_ptr_arith,
    mut_cast_to_bitmask,
    mut_decouple_index_math,
    mut_if_chain_to_switch,
    mut_inject_dummy_array,
    mut_inject_dummy_var,
    mut_move_switch_default,
    mut_preinit_byte_load,
    mut_ptr_arith_to_array,
    mut_reorder_register_vars,
    mut_reorder_switch_cases,
    mut_scope_variable,
    mut_split_switch,
    mut_swap_register_keywords,
    mut_switch_add_explicit_default,
    mut_switch_break_to_return,
    mut_switch_to_if_chain,
    mut_while_to_goto_loop,
    mut_wrap_in_else,
)

logger = logging.getLogger(__name__)


_BUILTIN_MUTATIONS = [
    mut_hoist_repeated_deref,
    mut_tweak_integer_literal,
    mut_flip_eq_zero,
    mut_flip_lt_ge,
    mut_add_redundant_parens,
    mut_swap_eq_operands,
    mut_swap_ne_operands,
    mut_reassociate_add,
    mut_swap_or_operands,
    mut_swap_and_operands,
    mut_toggle_bool_not,
    mut_return_to_goto,
    mut_goto_to_return,
    mut_swap_if_else,
    mut_add_cast,
    mut_remove_cast,
    mut_toggle_volatile,
    # --- Per-access qualifier and constant materialization (MSVC6 codegen
    #     levers a declaration-level qualifier cannot reach) ---
    mut_volatile_access,
    mut_materialize_constant,
    mut_add_register_keyword,
    mut_remove_register_keyword,
    mut_if_false_to_bitand,
    mut_reorder_elseif,
    mut_bitand_to_if_false,
    mut_introduce_temp_for_call,
    mut_remove_temp_var,
    mut_toggle_signedness,
    mut_swap_adjacent_declarations,
    mut_split_declaration_init,
    mut_merge_declaration_init,
    mut_while_to_dowhile,
    mut_dowhile_to_while,
    mut_early_return_to_accum,
    mut_accum_to_early_return,
    mut_pointer_to_int_param,
    mut_int_to_pointer_param,
    mut_duplicate_loop_body,
    mut_fold_constant_add,
    mut_unfold_constant_add,
    mut_change_array_index_order,
    mut_struct_vs_ptr_access,
    mut_change_return_type,
    mut_combine_ptr_arith,
    mut_split_ptr_arith,
    mut_change_param_order,
    mut_toggle_calling_convention,
    mut_toggle_char_signedness,
    mut_comparison_boundary,
    mut_insert_noop_block,
    mut_introduce_local_alias,
    mut_reorder_declarations,
    mut_extract_else_body,
    mut_for_to_while,
    mut_while_to_for,
    mut_if_to_ternary,
    mut_ternary_to_if,
    mut_hoist_return,
    mut_sink_return,
    mut_swap_adjacent_stmts,
    mut_guard_clause,
    mut_invert_loop_direction,
    mut_compound_assign_toggle,
    mut_demorgan,
    mut_postpre_increment,
    mut_xor_zero_toggle,
    mut_negate_condition,
    # --- MSVC6-targeted structural mutations (2026-03 batch) ---
    mut_while_to_goto_loop,
    mut_inject_dummy_var,
    mut_inject_dummy_array,
    mut_scope_variable,
    mut_array_to_ptr_arith,
    mut_ptr_arith_to_array,
    mut_decouple_index_math,
    mut_preinit_byte_load,
    mut_cast_to_bitmask,
    mut_swap_register_keywords,
    mut_add_volatile_intermediate,
    mut_reorder_register_vars,
    # --- Switch statement mutations (MSVC6 comparison chain codegen) ---
    mut_reorder_switch_cases,
    mut_switch_to_if_chain,
    mut_split_switch,
    mut_move_switch_default,
    # --- Advanced Control Flow & Switch Edge Cases (MSVC6 blocks) ---
    mut_if_chain_to_switch,
    mut_switch_add_explicit_default,
    mut_wrap_in_else,
    mut_switch_break_to_return,
    # --- Phase 3: Advanced Logical & Evaluation Mutations ---
    mut_split_and_condition,
    mut_merge_nested_ifs,
    mut_split_or_condition,
    mut_extract_condition_to_var,
    mut_loop_condition_extraction,
    # --- MSVC6 type width & codegen mutations (2026-03 GA improvements) ---
    mut_widen_local_type,
    mut_toggle_dllimport,
    mut_memcpy_to_loop,
    mut_loop_to_memcpy,
    mut_commute_float_operands,
    # --- Phase 4: Manual decomp insight mutations ---
    mut_register_param,
    mut_unregister_param,
    mut_remove_loop_break,
    mut_add_loop_break,
    mut_if_else_call_to_ternary_arg,
    mut_ternary_arg_to_if_else_call,
    mut_hoist_common_tail,
    mut_sink_common_tail,
    # --- Phase 5: MSVC6 codegen insights (commutative, block registers, type retyping, bitand) ---
    mut_commute_bit_or,
    mut_commute_bit_and,
    mut_commute_bit_xor,
    mut_commute_add_general,
    mut_commute_mul_general,
    mut_inject_block_register,
    mut_retype_local_equiv,
    mut_zero_to_bitand,
    # --- Phase 6: MSVC6 codegen quirks (branch layout, stack padding, inversion) ---
    mut_invert_if_else,
    mut_dummy_stack_vars,
    mut_inject_dummy_registers,
    mut_extract_complex_args,
    # --- Pragma levers: #pragma optimize / intrinsic / check_stack /
    #     auto_inline (codegen switches that flags cannot reach) ---
    mut_add_optimize_pragma,
    mut_remove_optimize_pragma,
    mut_add_intrinsic_pragma,
    mut_remove_intrinsic_pragma,
    mut_toggle_check_stack_pragma,
    mut_add_auto_inline_pragma,
    mut_remove_auto_inline_pragma,
]

# ---------------------------------------------------------------------------
# Registry assembly — packaged mutations + entry-point mutations
# ---------------------------------------------------------------------------

#: setuptools entry-point group whose members register extra GA mutations.
#: A member is ``module:attr`` naming a callable with the mutator signature
#: ``(source: str, rng: random.Random) -> str | None`` (see the ``mut_*``
#: operators).  Discovered mutations join ``ALL_MUTATIONS`` alongside the
#: packaged ones; a duplicate name is a :class:`RegistryError` (single-source
#: discipline — the GA must never pick between two operators of one name).
MUTATION_ENTRY_POINT_GROUP = "rebrew.mutations"


def _merge_entry_point_mutations() -> list[Callable[..., str | None]]:
    """The full mutation list: packaged operators + ``rebrew.mutations``.

    An optional registry: a broken or conflicting plugin mutation is
    skipped with a warning (the GA keeps the packaged operators) instead of
    bricking ``rebrew match``."""
    from rebrew.registry import (
        RegistryError,
        entry_point_registrations,
        load_registration_optional,
        merge_into,
    )

    merged: dict[str, Callable[..., str | None]] = {m.__name__: m for m in _BUILTIN_MUTATIONS}
    for reg in entry_point_registrations(MUTATION_ENTRY_POINT_GROUP):
        if not reg.attr:
            logger.warning(
                "skipping %s registration %r: expected 'module:attr' naming a mutation function",
                reg.group,
                reg.name,
            )
            continue
        mut_fn = load_registration_optional(reg, logger)
        if mut_fn is None:
            continue
        if not callable(mut_fn):
            logger.warning(
                "skipping %s registration %r: expected a callable mutation, got %s",
                reg.group,
                reg.name,
                type(mut_fn).__name__,
            )
            continue
        try:
            merge_into(merged, reg.name, mut_fn, reg.origin, group=reg.group)
        except RegistryError as exc:
            logger.warning("skipping %s registration %r: %s", reg.group, reg.name, exc)
    return list(merged.values())


ALL_MUTATIONS = _merge_entry_point_mutations()


def refresh_mutations() -> list[Callable[..., str | None]]:
    """Re-run discovery and refresh the :data:`ALL_MUTATIONS` snapshot.

    Long-lived GA runs can pick up mutation plugins installed after startup
    without a restart."""
    global ALL_MUTATIONS

    ALL_MUTATIONS = _merge_entry_point_mutations()
    return ALL_MUTATIONS


__all__ = [
    "ALL_MUTATIONS",
    "MutationLog",
    "compute_population_diversity",
    "crossover",
    "mutate_chain",
    "mutate_code",
    "quick_validate",
    # Only the PACKAGED operators are re-exported: their names are module
    # attributes of mutator.py, so `from .mutator import *` can bind them.
    # A plugin mutation (via rebrew.mutations) lives in the plugin's module,
    # not here — it joins ALL_MUTATIONS but must not leak into __all__.
    *[m.__name__ for m in _BUILTIN_MUTATIONS],
]


@lru_cache(maxsize=64)
def _mutation_weight_list(
    weights_items: tuple[tuple[str, float], ...],
) -> tuple[float, ...] | None:
    """Flatten a mutation-weight mapping into the per-mutation weight list.

    Cached: the GA passes the same ``mutation_weights`` dict for every
    ``mutate_code`` call (perf-review: rebuilding the 114-entry list with a
    dict lookup per mutation function on every call was pure overhead in
    the per-generation mutation loop).  Returns ``None`` when no weight is
    positive (caller then falls back to uniform ``rng.choice``).
    """
    mapping = dict(weights_items)
    weights = [mapping.get(m.__name__, 1.0) for m in ALL_MUTATIONS]
    if not any(w > 0 for w in weights):
        return None
    return tuple(weights)


@overload
def mutate_code(
    source: str,
    rng: random.Random,
    track_mutation: Literal[False] = False,
    mutation_weights: dict[str, float] | None = None,
) -> str: ...


@overload
def mutate_code(
    source: str,
    rng: random.Random,
    track_mutation: Literal[True],
    mutation_weights: dict[str, float] | None = None,
) -> tuple[str, str]: ...


def mutate_code(
    source: str,
    rng: random.Random,
    track_mutation: bool = False,
    mutation_weights: dict[str, float] | None = None,
) -> str | tuple[str, str]:
    """Apply a random mutation to the source code.

    Attempts up to ``_MUTATION_ATTEMPTS`` mutations to find a syntactically
    valid change.  Returns original source unchanged if all attempts fail.

    When *mutation_weights* is provided, it maps mutation function names
    (e.g. ``"mut_swap_if_else"``) to relative weights.  Mutations not
    listed default to weight 1.0.
    """
    preamble, body = _split_preamble_body(source)

    # The GA's target range is full-source byte offsets, but mutations query
    # the preamble-stripped body: convert once here so every mutation's
    # _cursor sees body coordinates (converting inside _cursor is impossible —
    # it never sees the source text).  Saved and restored around the loop;
    # leaving a narrowed range set would silently scope later mutations of
    # other sources (e.g. crossover, which never passes through here).
    body_offset = len(preamble) + 1 if preamble else 0
    saved_range = getattr(_target_range, "range", None)
    if saved_range is not None:
        set_target_range(
            max(0, saved_range[0] - body_offset),
            max(0, saved_range[1] - body_offset),
        )

    try:
        weights: tuple[float, ...] | None = None
        if mutation_weights:
            weights = _mutation_weight_list(tuple(sorted(mutation_weights.items())))

        for _ in range(_MUTATION_ATTEMPTS):
            if weights:
                mut_func = rng.choices(ALL_MUTATIONS, weights=weights, k=1)[0]
            else:
                mut_func = rng.choice(ALL_MUTATIONS)
            new_body = mut_func(body, rng)
            if new_body and new_body != body:
                new_source = preamble + "\n" + new_body
                if quick_validate(new_source):
                    if track_mutation:
                        return new_source, mut_func.__name__
                    return new_source
    finally:
        _target_range.range = saved_range

    if track_mutation:
        return source, "none"
    return source


class MutationLog:
    """Tracks applied mutations as revertible effects (paper §3.1).

    Each :meth:`apply` records the pre-mutation source — the inverse,
    captured at the point of application (the witness of Definition 8: the
    inverse reverts the effect where it was applied).  Inverses accumulate
    in reverse order (the paper's twisted composition), so :meth:`undo_all`
    restores the original source byte-identically, LIFO.  An inverse fires
    at most once — :meth:`undo` pops it off the stack, so a second undo can
    never re-apply it (the ``armed`` flag of the paper's Algorithm 1).
    """

    def __init__(self) -> None:
        self._stack: list[tuple[str, Callable[[], str]]] = []

    @property
    def depth(self) -> int:
        """Number of applied (not yet undone) mutations."""
        return len(self._stack)

    def apply(
        self,
        source: str,
        rng: random.Random,
        mutation_weights: dict[str, float] | None = None,
    ) -> tuple[str, str]:
        """Mutate *source*, record the inverse, return ``(mutated, name)``.

        A mutation that left the source unchanged (``"none"``) records no
        inverse — its inverse would be the identity, which changes nothing.
        """
        mutated, name = mutate_code(
            source, rng, track_mutation=True, mutation_weights=mutation_weights
        )
        if mutated != source:
            self._stack.append((source, lambda: source))
        return mutated, name

    def undo(self) -> str | None:
        """Revert the most recent mutation; returns the restored source.

        Returns ``None`` when the log is empty (nothing to revert — the
        inverse is never fired twice, it is consumed by this call).
        """
        if not self._stack:
            return None
        _original, inverse = self._stack.pop()
        return inverse()

    def undo_all(self) -> str | None:
        """Revert every mutation in LIFO order; returns the original source.

        Returns ``None`` when the log is empty.
        """
        if not self._stack:
            return None
        result: str | None = None
        while self._stack:
            result = self.undo()
        return result


def mutate_chain(
    source: str,
    rng: random.Random,
    max_steps: int = 4,
    mutation_weights: dict[str, float] | None = None,
    *,
    guard: Callable[[str], bool] | None = None,
) -> tuple[str, MutationLog]:
    """Apply up to *max_steps* mutations to *source*, recording inverses.

    Each step mutates the current source; a *guard* (checked before each
    step) can stop the chain at a step boundary — the step-boundary
    interruption of the paper's Section 4.3.2: once the guard trips,
    iteration stops and only the inverses accumulated so far remain.

    Returns ``(final_source, log)``; ``log.undo_all()`` restores *source*
    byte-identically (LIFO).  ``max_steps`` caps the chain, not the log.
    """
    log = MutationLog()
    current = source
    for _ in range(max_steps):
        if guard is not None and not guard(current):
            break
        current, _name = log.apply(current, rng, mutation_weights=mutation_weights)
    return current, log
