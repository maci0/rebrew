# AGENTS.md — matcher/

Core GA (Genetic Algorithm) engine for binary-matching decompilation.
Compiles C source with MSVC6 under Wine, scores byte-level similarity against
target binaries, and mutates source code to converge on exact matches.

## Module Map

| Module | Role | Key Exports |
|--------|------|-------------|
| `core.py` | Data types (pure, no logic) | `Score`, `BuildResult`, `BuildCache`, `GACheckpoint`, `StructuralSimilarity` |
| `compiler.py` | Compilation backend | `build_candidate()`, `build_candidate_obj_only(cache=)`, `flag_sweep(cache=)`, `generate_flag_combinations()` |
| `scoring.py` | Binary comparison (pure, no I/O) | `score_candidate()`, `diff_functions()`, `structural_similarity()` |
| `mutator.py` | C source mutations (pure, no I/O) | `mutate_code()`, `crossover()`, `compute_population_diversity()`, 120 `mut_*` operators |
| `parsers.py` | Object file parsing (read-only) | `parse_obj_symbol_bytes()`, `list_obj_symbols()`, `extract_function_from_binary()` |
| `flags.py` | Flag primitives | `FlagSet`, `Checkbox` (frozen dataclasses), `Flags` (type alias) |
| `flag_data.py` | MSVC flag definitions | `MSVC6_FLAGS`, `COMMON_MSVC_FLAGS`, `MSVC_SWEEP_TIERS` |

## Dependency Graph

```
compiler.py
├── core.BuildResult
├── flag_data.MSVC6_FLAGS, COMMON_MSVC_FLAGS, MSVC_SWEEP_TIERS
├── flags.Checkbox, FlagSet
├── parsers.extract_function_from_binary, parse_obj_symbol_bytes
├── compile.filter_wine_stderr (external, from rebrew.compile)
└── compile_cache.CompileCache (external, optional — passed via cache= param)

scoring.py
├── core.Score, StructuralSimilarity
├── capstone (external)
└── numpy (external)

mutator.py → ast_engine (internal: _C_LANGUAGE, ASTMutator, parse_c_ast)
core.py    → diskcache (external), NO internal imports
parsers.py → lief (external), NO internal imports
flags.py   → NO imports (pure dataclasses)
flag_data.py → flags.Checkbox, FlagSet
```

**Design principle**: Minimal coupling. Each module is largely independent.
`compiler.py` orchestrates the pipeline; everything else is pure or read-only.

## Data Flow

```
Source (.c) ──→ compiler.build_candidate()
                  ├─ Check compile cache (if cache= provided, SHA-256 keyed)
                  ├─ Write to temp dir (on cache miss)
                  ├─ Run CL.EXE via Wine/wibo (60s timeout)
                  ├─ parsers.parse_obj_symbol_bytes() → bytes + relocs
                  ├─ Store result in cache (on cache miss)
                  └─ Return BuildResult {ok, obj_bytes, reloc_offsets, error_msg}
                        │
                        ▼
              scoring.score_candidate(candidate_bytes, target_bytes, relocs)
                  ├─ Normalize relocations (zero out reloc slots)
                  ├─ Normalize registers (mask register-only diffs)
                  ├─ Byte-level comparison (numpy vectorized)
                  ├─ Mnemonic comparison (capstone disassembly)
                  └─ Return Score {byte_score, reloc_score, mnemonic_score, ...}
                        │
                        ▼
              mutator.mutate_code(source, rng)
                  ├─ Pick random mutation from ALL_MUTATIONS (120 operators)
                  ├─ Apply mutation, validate syntax
                  └─ Return (mutated_source, mutation_name)
                        │
                        ▼
              [GA loop in match.py repeats: compile → score → mutate]
```

## Key Types

### Score
Multi-metric fitness: `byte_score` (0.0 = perfect), `reloc_score`, `mnemonic_score`,
`prologue_bonus`, `total` (weighted composite). Lower is better.

### BuildResult
Compilation outcome: `ok` bool + `obj_bytes` + `reloc_offsets` + `error_msg`.
Never raises exceptions — failed compiles return `BuildResult(ok=False)`.

### StructuralSimilarity
Classifies instruction-level diffs into: `exact`, `reloc_only` (fixable by
relocations), `register_only` (register allocation), `structural` (real diffs).
`flag_sensitive` bool indicates if compiler flags alone could fix the mismatch.

### BuildCache
Disk-backed memoization (diskcache/SQLite). Maps source hash → `BuildResult`.
Instance-based (not global singleton), thread-safe. Created per GA run.

### GACheckpoint
Serializable GA state for resuming: `generation`, `best_score`, `best_source`,
`population`, `rng_state`. JSON-based. Validated by `args_hash` to reject stale
checkpoints when GA parameters change.

## Mutation Operators

121 operators in `mutator.py`, all named `mut_*`. Categories:

- **Commutative / logic**: `mut_commute_simple_add`, `mut_commute_simple_mul`, `mut_swap_eq_operands`, `mut_swap_ne_operands`, `mut_swap_or_operands`, `mut_swap_and_operands`, `mut_reassociate_add`, `mut_demorgan`
- **Comparison / boolean**: `mut_flip_eq_zero`, `mut_flip_lt_ge`, `mut_comparison_boundary`, `mut_toggle_bool_not`, `mut_negate_condition`
- **Control flow**: `mut_swap_if_else`, `mut_reorder_elseif`, `mut_flatten_nested_if`, `mut_extract_else_body`, `mut_guard_clause`, `mut_split_cmp_chain`, `mut_merge_cmp_chain`, `mut_hoist_return`, `mut_sink_return`, `mut_return_to_goto`, `mut_goto_to_return`, `mut_while_to_goto_loop`
- **Loop transforms**: `mut_for_to_while`, `mut_while_to_for`, `mut_while_to_dowhile`, `mut_dowhile_to_while`, `mut_duplicate_loop_body`, `mut_invert_loop_direction`, `mut_remove_loop_break`, `mut_add_loop_break`
- **Ternary / branch**: `mut_if_to_ternary`, `mut_ternary_to_if`, `mut_if_false_to_bitand`, `mut_bitand_to_if_false`, `mut_if_else_call_to_ternary_arg`, `mut_ternary_arg_to_if_else_call`
- **Cast / type**: `mut_add_cast`, `mut_remove_cast`, `mut_toggle_signedness`, `mut_toggle_char_signedness`, `mut_change_return_type`
- **Variable layout**: `mut_swap_adjacent_declarations`, `mut_reorder_declarations`, `mut_split_declaration_init`, `mut_merge_declaration_init`, `mut_swap_adjacent_stmts`
- **Expression rewrite**: `mut_compound_assign_toggle`, `mut_postpre_increment`, `mut_xor_zero_toggle`, `mut_add_redundant_parens`, `mut_fold_constant_add`, `mut_unfold_constant_add`, `mut_combine_ptr_arith`, `mut_split_ptr_arith`
- **Pointer / array**: `mut_change_array_index_order`, `mut_struct_vs_ptr_access`, `mut_array_to_ptr_arith`, `mut_ptr_arith_to_array`, `mut_decouple_index_math`
- **Calling / params**: `mut_toggle_calling_convention`, `mut_change_param_order`, `mut_pointer_to_int_param`, `mut_int_to_pointer_param`, `mut_register_param`, `mut_unregister_param`
- **Stack frame (MSVC6)**: `mut_inject_dummy_var`, `mut_inject_dummy_array`, `mut_scope_variable`
- **Register pressure (MSVC6)**: `mut_toggle_volatile`, `mut_add_register_keyword`, `mut_remove_register_keyword`, `mut_swap_register_keywords`, `mut_add_volatile_intermediate`, `mut_reorder_register_vars`
- **Zero-extension (MSVC6)**: `mut_preinit_byte_load`, `mut_cast_to_bitmask`
- **Branch merging (MSVC6)**: `mut_hoist_common_tail`, `mut_sink_common_tail`
- **MSVC6 codegen quirks (Phase 6)**: `mut_pragma_optimize`, `mut_pragma_optimize_remove`, `mut_invert_if_else`, `mut_dummy_stack_vars`, `mut_loop_convert`, `mut_extract_complex_args`
- **Misc**: `mut_introduce_temp_for_call`, `mut_remove_temp_var`, `mut_introduce_local_alias`, `mut_insert_noop_block`, `mut_early_return_to_accum`, `mut_accum_to_early_return`

Selected uniformly at random by default. `mutate_code()` accepts optional
`mutation_weights` dict for biased selection.

## Consumers

- **`match.py`** — Single-function GA CLI. Imports `BuildCache`, `build_candidate`,
  `score_candidate`, `mutate_code`, `crossover`, `diff_functions`, `structural_similarity`.
- **`match.py`** — Single-function and batch (`--all`) GA engine. Imports `flag_sweep` from `compiler.py`.

## Gotchas

- **Hardcoded compiler profile**: `_COMPILER_PROFILE = "msvc6"` in `compiler.py`.
  No runtime override — flag sweep always uses MSVC6 flags.
- **Heuristic relocation/register detection**: `scoring.py` zeros out relocation
  slots and masks register diffs via pattern matching, not COFF metadata.
- **60s subprocess timeout**: `build_candidate()` kills hung compilers and returns
  `BuildResult(ok=False)` — does not propagate the timeout as an exception.
- **Wine stderr filtering**: `compiler.py` calls `rebrew.compile.filter_wine_stderr()`
  via lazy import to avoid circular dependency.
- **No global mutable state**: Each GA run creates its own `BuildCache`, `Random`
  instance, and temp directories. Safe for concurrent CLI invocations.
