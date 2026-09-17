# AGENTS.md — matcher/

GA engine for binary-matching decompilation. Compiles C through the docker-backed toolchain abstraction (wine lives inside the image; no host wine/wibo fallback), scores byte similarity against targets, mutates source to converge on exact matches.

## Modules

| Module | Role |
|--------|------|
| `core.py` | Types: `Score`, `BuildResult`, `BuildCache`, `GACheckpoint`, `StructuralSimilarity` |
| `compiler.py` | `build_candidate_obj_only` (default timeout 60s), `build_candidate` (120s), `flag_sweep`, `generate_flag_combinations` |
| `scoring.py` | `score_candidate`, `diff_functions`, `structural_similarity` (pure) |
| `mutator.py` | `mutate_code` / `ALL_MUTATIONS` (128 packaged ops) + GA helpers |
| `mutations/` | Operators by file (`basic` 65, `structural` 25, `advanced` 18, `enhancements` 13, `pragmas` 7) + `queries` / `runtime` |
| `parsers.py` | Object/binary symbol extraction (LIEF) |
| `flags.py` / `flag_data.py` | Flag axes per dialect + sweep tiers |
| `solutions.py` | Solution-transfer DB (seed GA from solved lookalikes) |
| `ast_engine.py` | tree-sitter C AST for mutations |

## Data flow (GA path)

`build_candidate_obj_only` → cache miss → docker compile (60s default) → `parse_obj_symbol_bytes` → `score_candidate` (reloc zero + register mask + numpy/capstone) → `mutate_code` → loop in `match_ga.py`.

## Non-obvious types

- **Score**: lower is better; `byte_score` 0.0 = perfect; `total` is weighted.
- **BuildResult**: never raises — failures are `ok=False`.
- **StructuralSimilarity**: `exact` / `reloc_only` / `register_only` / `structural`; `flag_sensitive` means flags alone may fix it.
- **BuildCache**: per-run diskcache instance (not global), thread-safe.
- **GACheckpoint**: JSON resume state; `args_hash` rejects stale checkpoints.

## Mutations

128 packaged `mut_*` ops under `mutations/` → `ALL_MUTATIONS` in `mutator.py`. Inventory: `docs/GA_MUTATIONS.md`. Optional weights via `mutate_code(..., mutation_weights=)`. Entry-point group `rebrew.mutations`; duplicate name skipped with warning.

## Consumers

- `match_ga.py` — primary GA loop (`build_candidate_obj_only`)
- `match_sweep.py` — flag sweep
- `diff.py`, `stack_cmp.py` — compile-for-compare helpers

## Gotchas

- **Profile-parametrized sweep**: `generate_flag_combinations(tier=, profile=)` picks axes per profile (incl. `borland-2.0`); unknown profile falls back to registry `flags_style` (posix → GCC axes, not MSVC).
- **Heuristic reloc/register detection**: pattern matching in `scoring.py`, not COFF metadata.
- **Timeouts**: `build_candidate_obj_only` / `flag_sweep` default 60s; `build_candidate` (compile+link) default 120s — hung compile → `BuildResult(ok=False)`, never raises.
- **Wine stderr**: lazy `rebrew.compile.filter_wine_stderr()` (avoids import cycle).
- **No global state**: each run owns `BuildCache`, `Random`, temp dirs — safe to run concurrently.
