# AGENTS.md: matcher/

GA engine for binary-matching decompilation. Compiles C through the docker-backed toolchain abstraction, scores byte similarity against targets, mutates source to converge on exact matches.

## Modules

| Module | Role |
|--------|------|
| `core.py` | Types: `Score`, `BuildResult`, `GACheckpoint`, `StructuralSimilarity` |
| `compiler.py` | `build_candidate_obj_only`, `build_candidate`, `flag_sweep`, `generate_flag_combinations` |
| `scoring.py` | `score_candidate`, `diff_functions`, `structural_similarity` (pure) |
| `mutator.py` | `mutate_code` / `ALL_MUTATIONS` + GA helpers |
| `mutations/` | Operators by file (`basic`, `structural`, `advanced`, `enhancements`, `pragmas`) + `queries` / `runtime` |
| `parsers.py` | Object/binary symbol extraction (LIEF) |
| `solutions.py` | Solution-transfer DB (seed GA from solved lookalikes) |
| `ast_engine.py` | tree-sitter C AST for mutations |

Flag axes (`rebrew.flags` / `rebrew.flag_data`) live at the package root so compile-cache canonicalization and the GA sweep share one definition without the cache layer importing the matcher package.

## Data flow (GA path)

`build_candidate_obj_only` → miss in same-run memo and shared compile cache → docker compile → `parse_obj_symbol_bytes` → `score_candidate` (reloc zero + register mask + numpy/capstone) → `mutate_code` → loop in `match_ga.py`.

## Non-obvious types

- **Score**: lower is better; `byte_score` 0.0 = perfect; `total` is weighted.
- **BuildResult**: check `ok` before using bytes; reported compiler failures use `ok=False`. Build helpers can still raise during argument parsing, filesystem operations, or backend calls.
- **StructuralSimilarity**: `exact` / `reloc_only` / `register_only` / `structural`; `flag_sensitive` means flags alone may fix it.
- **GACheckpoint**: JSON resume state; `args_hash` rejects stale checkpoints.

## Mutations

Packaged `mut_*` ops under `mutations/` → `ALL_MUTATIONS` in `mutator.py`. New ops: named `mut_*`, tree-sitter only (never regex), tested in `tests/test_mutator_p*.py`; inventory: `docs/GA_MUTATIONS.md`. Numeric constants need explicit ops (`mut_tweak_integer_literal` covers small ±deltas). Optional weights via `mutate_code(..., mutation_weights=)`. Entry-point group `rebrew.mutations`; duplicate name skipped with warning (packaged kept).

## Consumers

- `match_ga.py`: primary GA loop (`build_candidate_obj_only`)
- `match_sweep.py`: flag sweep
- `diff.py`, `stack_cmp.py`: compile-for-compare helpers
- `compile.py` / `test.py` / `prove.py`: import **`rebrew.matcher.parsers`** directly (package `__init__` is lazy so this does not load mutator/compiler)

## Gotchas

- **Lazy package exports**: `rebrew.matcher` resolves public names via `__getattr__`. Importing a submodule (e.g. `parsers`) does not load the GA stack; `from rebrew.matcher import mutate_code` still works.
- **Profile-parametrized sweep**: `generate_flag_combinations(tier=, profile=)` picks axes per profile (incl. `borland-2.0`); unknown profile falls back to registry `flags_style` (posix → GCC axes, not MSVC).
- **Heuristic reloc/register detection**: pattern matching in `scoring.py`, not COFF metadata.
- **Timeouts**: `build_candidate_obj_only` / `flag_sweep` default 60s; `build_candidate` (compile+link) defaults to 120s. Direct subprocess timeouts return `BuildResult(ok=False)`. Image-backed path: `timeout=` seeds a synthetic cfg when none is passed; a real `cfg` uses `cfg.compile_timeout`.
- **Wine stderr**: lazy `rebrew.compile.filter_wine_stderr()` (avoids import cycle).
- **No global state**: each run owns its in-memory memo, `Random`, and temp dirs, safe to run concurrently.
