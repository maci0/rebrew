# AGENTS.md — matcher/

Core GA (Genetic Algorithm) engine for binary-matching decompilation.
Compiles C source with MSVC6 under Wine, scores byte-level similarity against
target binaries, and mutates source code to converge on exact matches.

## Module Map

| Module | Role | Key Exports |
|--------|------|-------------|
| `core.py` | Data types (pure, no logic) | `Score`, `BuildResult`, `BuildCache`, `GACheckpoint`, `StructuralSimilarity` |
| `compiler.py` | Compilation backend | `build_candidate()`, `build_candidate_obj_only()`, `flag_sweep()`, `generate_flag_combinations()` |
| `scoring.py` | Binary comparison (pure, no I/O) | `score_candidate()`, `diff_functions()`, `structural_similarity()` |
| `mutator.py` | C source mutations (pure, no I/O) | `mutate_code()`, `crossover()`, `compute_population_diversity()`, 51 `mut_*` operators |
| `parsers.py` | Object file parsing (read-only) | `parse_obj_symbol_bytes()`, `list_obj_symbols()`, `extract_function_from_binary()` |
| `flags.py` | Flag primitives | `FlagSet`, `Checkbox` (frozen dataclasses) |
| `flag_data.py` | MSVC flag definitions | `MSVC6_FLAGS`, `COMMON_MSVC_FLAGS`, `MSVC_SWEEP_TIERS` |

## Dependency Graph

```
compiler.py
├── core.BuildResult
├── flag_data.MSVC6_FLAGS, COMMON_MSVC_FLAGS, MSVC_SWEEP_TIERS
├── flags.Checkbox, FlagSet
├── parsers.extract_function_from_binary, parse_obj_symbol_bytes
└── compile.filter_wine_stderr (external, from rebrew.compile)

scoring.py
├── core.Score, StructuralSimilarity
├── capstone (external)
└── numpy (external)

mutator.py → NO internal imports (self-contained)
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
                  ├─ Write to temp dir
                  ├─ Run CL.EXE via Wine/wibo (60s timeout)
                  ├─ parsers.parse_obj_symbol_bytes() → bytes + relocs
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
                  ├─ Pick random mutation from ALL_MUTATIONS (51 operators)
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

51 operators in `mutator.py`, all named `mut_*`. Categories:

- **Cast/type**: `mut_add_cast`, `mut_remove_cast`, `mut_change_int_type`
- **Control flow**: `mut_swap_if_else`, `mut_invert_condition`, `mut_for_to_while`
- **Expression**: `mut_commute_operands`, `mut_strength_reduce`, `mut_add_parens`
- **Variable**: `mut_rename_local`, `mut_split_declaration`
- **Calling convention**: `mut_add_cdecl`, `mut_add_stdcall`, `mut_add_fastcall`
- **Pointer/array**: `mut_arrow_to_deref`, `mut_array_to_pointer`
- **Pragma/compiler**: `mut_add_pragma_pack`, `mut_add_volatile`, `mut_add_register`

Selected uniformly at random by default. `mutate_code()` accepts optional
`mutation_weights` dict for biased selection.

## Consumers

- **`match.py`** — Single-function GA CLI. Imports `BuildCache`, `build_candidate`,
  `score_candidate`, `mutate_code`, `crossover`, `diff_functions`, `structural_similarity`.
- **`ga.py`** — Batch GA runner. Imports `flag_sweep` from `compiler.py`.

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
