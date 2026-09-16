# AGENTS.md — matcher/

GA engine for binary-matching decompilation. Compiles C through the docker-backed toolchain abstraction (wine lives inside the image; no host wine/wibo fallback), scores byte similarity against targets, mutates source to converge on exact matches.

## Module Map

| Module | Role | Key Exports |
|--------|------|-------------|
| `core.py` | Types (pure, no logic) | `Score`, `BuildResult`, `BuildCache`, `GACheckpoint`, `StructuralSimilarity` |
| `compiler.py` | Compilation backend | `build_candidate()`, `build_candidate_obj_only(cache=)`, `flag_sweep(cache=)`, `generate_flag_combinations()` |
| `scoring.py` | Binary comparison (pure) | `score_candidate()`, `diff_functions()`, `structural_similarity()` |
| `mutator.py` | Mutation registry + GA helpers | `mutate_code()`, `mutate_chain()`, `MutationLog`, `crossover()`, `compute_population_diversity()`, `ALL_MUTATIONS` (128 packaged ops) |
| `mutations/queries.py` | Shared tree-sitter query library for the mutation operators | `_LazyQuery`, the `_QUERY_*` batch, `_RE_C_ZERO_LITERAL` |
| `mutations/runtime.py` | Operator plumbing | `_capture`, `_first_caps`, `_cursor`, `_apply_query_once`, `set_target_range`, `brace_block`, `_RE_FUNC_PRAGMA` |
| `mutations/pragmas.py` | MSVC6 `#pragma` operators | 7 `mut_*_pragma` operators |
| `mutations/structural.py` | MSVC6 structural operators (control flow, stack frame, folding, zero-extension, register pressure) | 25 `mut_*` operators |
| `mutations/advanced.py` | Phase 3/4 logical + manual-decomp operators, loop-break, ternary, hoist/sink | 18 `mut_*` operators |
| `mutations/enhancements.py` | Phase 5/6 codegen insights + Category 7 register pressure | 13 `mut_*` operators |
| `mutations/basic.py` | Core Phase 1/2 operator set + `quick_validate`/`crossover`/diversity | 65 `mut_*` operators |
| `parsers.py` | Object parsing (read-only) | `parse_obj_symbol_bytes()`, `list_obj_symbols()`, `extract_function_from_binary()` |
| `flags.py` | Flag primitives | `FlagSet`, `Checkbox` (frozen), `Flags` alias |
| `flag_data.py` | Compiler flag axes per dialect | `MSVC6_FLAGS`, `COMMON_MSVC_FLAGS`, `GCC_FLAGS`, `BORLAND_FLAGS`, `WATCOM_FLAGS`, `MSVC152_FLAGS`, `*_SWEEP_TIERS` |
| `solutions.py` | Solution transfer DB | `SolutionEntry`, `load_solutions()`, `save_solution()`, `find_similar()` (seeds GA runs from solved lookalikes) |

## Dependency Graph

```
compiler.py
├── core.BuildResult
├── flag_data.MSVC6_FLAGS, COMMON_MSVC_FLAGS, GCC_FLAGS, BORLAND_FLAGS,
│   WATCOM_FLAGS, MSVC152_FLAGS, *_SWEEP_TIERS
├── flags.Checkbox, FlagSet
├── parsers.extract_function_from_binary, parse_obj_symbol_bytes
├── config.profile_flags_style (external, for the per-style sweep fallback)
├── binary_loader.capstone_mode_for_arch (external, lazy — sweep scoring mode)
├── toolchain_spec.FlagsStyle (external, value type)
├── compile.filter_wine_stderr (external, from rebrew.compile)
└── compile_cache.CompileCache (external, optional — via cache=)

scoring.py
├── core.Score, StructuralSimilarity
├── capstone (external)
└── numpy (external)

mutator.py → ast_engine (internal: _C_LANGUAGE, ASTMutator, parse_c_ast)
core.py    → diskcache (external), no internal imports
parsers.py → lief (external), coff_reloc.CoffRelocRecord
flags.py   → no imports (pure dataclasses)
flag_data.py → flags.Checkbox, FlagSet
```

Minimal coupling — each module largely independent. `compiler.py` orchestrates; rest is pure/read-only.

## Data Flow

```
Source (.c) ──→ compiler.build_candidate()
                  ├─ Check cache (if cache=, SHA-256 keyed)
                  ├─ Write temp dir (on miss)
                  ├─ Run compiler inside the docker image (60s timeout)
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
                  ├─ Pick random mutation from ALL_MUTATIONS (128 ops)
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

128 packaged `mut_*` operators live under `mutations/` (assembled into `ALL_MUTATIONS` by `mutator.py`). Category inventory and rationale: `docs/GA_MUTATIONS.md`. Selected uniformly by default; `mutate_code()` accepts optional `mutation_weights`.

Third-party packages can register mutations without editing host source: a `module:attr` entry point in the `rebrew.mutations` group (see `src/rebrew/registry.py`) joins `ALL_MUTATIONS` at import; a duplicate name raises `RegistryError`.

## Consumers

- **`match.py`** — Single-function GA CLI; imports `BuildCache`, `build_candidate`, `score_candidate`, `mutate_code`, `crossover`, `diff_functions`, `structural_similarity` + `flag_sweep` from `compiler.py` for batch (`--all`).

## Gotchas

- **Profile-parametrized sweep**: `generate_flag_combinations(tier=, profile=)` picks the flag set per profile (packaged: `msvc-6.0`, `watcom-2.0-win32`/`watcom-2.0-win16`, `msvc-1.52`, `borland-3.1`/`borland-5.5`/`borland-2.0`, gcc/clang/mingw; a profile with none falls back to axes matching its registry `flags_style` — posix gets the GCC axes, not MSVC's) and `build_candidate()` resolves the docker image via the toolchain abstraction — no host wine.
- **Heuristic reloc/register detection**: `scoring.py` zeros reloc slots / masks register diffs via pattern matching, not COFF metadata.
- **60s timeout**: `build_candidate()` kills hung compilers → `BuildResult(ok=False)`, never raises.
- **Wine stderr**: `compiler.py` calls `rebrew.compile.filter_wine_stderr()` via lazy import (avoids cycle).
- **No global state**: each GA run owns its `BuildCache`, `Random`, and temp dirs — safe for concurrent invocations.
