# AGENTS.md — matcher/

GA engine for binary-matching decompilation. Compiles C with MSVC6 under Wine, scores byte similarity against targets, mutates source to converge on exact matches.

## Module Map

| Module | Role | Key Exports |
|--------|------|-------------|
| `core.py` | Types (pure, no logic) | `Score`, `BuildResult`, `BuildCache`, `GACheckpoint`, `StructuralSimilarity` |
| `compiler.py` | Compilation backend | `build_candidate()`, `build_candidate_obj_only(cache=)`, `flag_sweep(cache=)`, `generate_flag_combinations()` |
| `scoring.py` | Binary comparison (pure) | `score_candidate()`, `diff_functions()`, `structural_similarity()` |
| `mutator.py` | C mutations (pure) | `mutate_code()`, `crossover()`, `compute_population_diversity()`, 120 `mut_*` operators |
| `parsers.py` | Object parsing (read-only) | `parse_obj_symbol_bytes()`, `list_obj_symbols()`, `extract_function_from_binary()` |
| `flags.py` | Flag primitives | `FlagSet`, `Checkbox` (frozen), `Flags` alias |
| `flag_data.py` | MSVC flag defs | `MSVC6_FLAGS`, `COMMON_MSVC_FLAGS`, `MSVC_SWEEP_TIERS` |

## Dependency Graph

```
compiler.py
├── core.BuildResult
├── flag_data.MSVC6_FLAGS, COMMON_MSVC_FLAGS, MSVC_SWEEP_TIERS
├── flags.Checkbox, FlagSet
├── parsers.extract_function_from_binary, parse_obj_symbol_bytes
├── compile.filter_wine_stderr (external, from rebrew.compile)
└── compile_cache.CompileCache (external, optional — via cache=)

scoring.py
├── core.Score, StructuralSimilarity
├── capstone (external)
└── numpy (external)

mutator.py → ast_engine (internal: _C_LANGUAGE, ASTMutator, parse_c_ast)
core.py    → diskcache (external), no internal imports
parsers.py → lief (external), no internal imports
flags.py   → no imports (pure dataclasses)
flag_data.py → flags.Checkbox, FlagSet
```

Minimal coupling — each module largely independent. `compiler.py` orchestrates; rest is pure/read-only.

## Data Flow

```
Source (.c) ──→ compiler.build_candidate()
                  ├─ Check cache (if cache=, SHA-256 keyed)
                  ├─ Write temp dir (on miss)
                  ├─ Run CL.EXE via Wine/wibo (60s timeout)
                  ├─ parsers.parse_obj_symbol_bytes() → bytes + relocs
                  ├─ Cache result (on miss)
                  └─ Return BuildResult {ok, obj_bytes, reloc_offsets, error_msg}
                        │
                        ▼
              scoring.score_candidate(candidate_bytes, target_bytes, relocs)
                  ├─ Zero reloc slots
                  ├─ Mask register-only diffs
                  ├─ Byte compare (numpy)
                  ├─ Mnemonic compare (capstone)
                  └─ Return Score {byte_score, reloc_score, mnemonic_score, ...}
                        │
                        ▼
              mutator.mutate_code(source, rng)
                  ├─ Pick random mutation from ALL_MUTATIONS (120 ops)
                  ├─ Apply, validate syntax
                  └─ Return (mutated_source, mutation_name)
                        │
                        ▼
              [GA loop in match.py: compile → score → mutate]
```

## Key Types

### Score
Multi-metric fitness: `byte_score` (0.0 = perfect), `reloc_score`, `mnemonic_score`, `prologue_bonus`, `total` (weighted). Lower is better.

### BuildResult
Compilation outcome: `ok` + `obj_bytes` + `reloc_offsets` + `error_msg`. Never raises — failures return `BuildResult(ok=False)`.

### StructuralSimilarity
Classifies diffs as `exact`, `reloc_only` (fixable via relocs), `register_only`, or `structural`. `flag_sensitive` indicates flags alone could fix it.

### BuildCache
Disk-backed memoization (diskcache/SQLite): source hash → `BuildResult`. Per-run instance (not global), thread-safe.

### GACheckpoint
Serializable GA state for resume: `generation`, `best_score`, `best_source`, `population`, `rng_state`. JSON, validated by `args_hash` to reject stale checkpoints.

## Mutation Operators

121 operators in `mutator.py` (`mut_*`):

- **Commutative/logic**: `mut_commute_add_general`, `mut_commute_mul_general`, `mut_swap_eq_operands`, `mut_swap_ne_operands`, `mut_swap_or_operands`, `mut_swap_and_operands`, `mut_reassociate_add`, `mut_demorgan`
- **Comparison/boolean**: `mut_flip_eq_zero`, `mut_flip_lt_ge`, `mut_comparison_boundary`, `mut_toggle_bool_not`, `mut_negate_condition`
- **Control flow**: `mut_swap_if_else`, `mut_reorder_elseif`, `mut_extract_else_body`, `mut_guard_clause`, `mut_hoist_return`, `mut_sink_return`, `mut_return_to_goto`, `mut_goto_to_return`, `mut_while_to_goto_loop`
- **Loop**: `mut_for_to_while`, `mut_while_to_for`, `mut_while_to_dowhile`, `mut_dowhile_to_while`, `mut_duplicate_loop_body`, `mut_invert_loop_direction`, `mut_remove_loop_break`, `mut_add_loop_break`
- **Ternary/branch**: `mut_if_to_ternary`, `mut_ternary_to_if`, `mut_if_false_to_bitand`, `mut_bitand_to_if_false`, `mut_if_else_call_to_ternary_arg`, `mut_ternary_arg_to_if_else_call`
- **Cast/type**: `mut_add_cast`, `mut_remove_cast`, `mut_toggle_signedness`, `mut_toggle_char_signedness`, `mut_change_return_type`
- **Variable layout**: `mut_swap_adjacent_declarations`, `mut_reorder_declarations`, `mut_split_declaration_init`, `mut_merge_declaration_init`, `mut_swap_adjacent_stmts`
- **Expression**: `mut_compound_assign_toggle`, `mut_postpre_increment`, `mut_xor_zero_toggle`, `mut_add_redundant_parens`, `mut_fold_constant_add`, `mut_unfold_constant_add`, `mut_combine_ptr_arith`, `mut_split_ptr_arith`
- **Pointer/array**: `mut_change_array_index_order`, `mut_struct_vs_ptr_access`, `mut_array_to_ptr_arith`, `mut_ptr_arith_to_array`, `mut_decouple_index_math`
- **Calling/params**: `mut_toggle_calling_convention`, `mut_change_param_order`, `mut_pointer_to_int_param`, `mut_int_to_pointer_param`, `mut_register_param`, `mut_unregister_param`
- **Stack frame (MSVC6)**: `mut_inject_dummy_var`, `mut_inject_dummy_array`, `mut_scope_variable`
- **Register pressure (MSVC6)**: `mut_toggle_volatile`, `mut_add_register_keyword`, `mut_remove_register_keyword`, `mut_swap_register_keywords`, `mut_add_volatile_intermediate`, `mut_reorder_register_vars`
- **Zero-extension (MSVC6)**: `mut_preinit_byte_load`, `mut_cast_to_bitmask`
- **Branch merging (MSVC6)**: `mut_hoist_common_tail`, `mut_sink_common_tail`
- **MSVC6 quirks (Phase 6)**: `mut_invert_if_else`, `mut_dummy_stack_vars`, `mut_inject_dummy_registers`, `mut_extract_complex_args`
- **Misc**: `mut_introduce_temp_for_call`, `mut_remove_temp_var`, `mut_introduce_local_alias`, `mut_insert_noop_block`, `mut_early_return_to_accum`, `mut_accum_to_early_return`

Selected uniformly by default; `mutate_code()` accepts optional `mutation_weights` for bias.

## Consumers

- **`match.py`** — Single-function GA CLI; imports `BuildCache`, `build_candidate`, `score_candidate`, `mutate_code`, `crossover`, `diff_functions`, `structural_similarity` + `flag_sweep` from `compiler.py` for batch (`--all`).

## Gotchas

- **Hardcoded profile**: `_COMPILER_PROFILE = "msvc6"` in `compiler.py` — flag sweep always uses MSVC6.
- **Heuristic reloc/register detection**: `scoring.py` zeros reloc slots / masks register diffs via pattern matching, not COFF metadata.
- **60s timeout**: `build_candidate()` kills hung compilers → `BuildResult(ok=False)`, never raises.
- **Wine stderr**: `compiler.py` calls `rebrew.compile.filter_wine_stderr()` via lazy import (avoids cycle).
- **No global state**: each GA run owns its `BuildCache`, `Random`, and temp dirs — safe for concurrent invocations.
