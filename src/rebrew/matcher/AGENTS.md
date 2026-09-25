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

Packaged `mut_*` ops under `mutations/` → `ALL_MUTATIONS` in `mutator.py`. New ops: named `mut_*`, tree-sitter only (never regex), tested in `tests/test_mutator*.py`; inventory: `docs/GA_MUTATIONS.md`. Numeric constants need explicit ops (`mut_tweak_integer_literal` covers small ±deltas). Optional weights via `mutate_code(..., mutation_weights=)`. Entry-point group `rebrew.mutations`; duplicate name skipped with warning (packaged kept).

- **Keep precedence when splicing.** An operator that moves a captured subexpression into a tighter position (subscript base or index, operand of `+`/`*`, before `.`/`->`/`++`) takes it through `runtime._operand_bytes`, which parenthesizes anything that does not already bind as tightly as a postfix operator; wrap a generated `*(...)` in parentheses when `runtime._under_postfix(expr)`. Raw splicing turned `a[i + 1]` into `i + 1[a]` (= `i + a[1]`) and `*((char*)p + i)` into `(char*)p[i]`: valid C with a different value, so no validator catches it. Test each operator on a compound operand and under a postfix parent.
- **Scope is per source, in bytes.** `BinaryMatchingGA._mutate` locates the target function in each source (`_find_function_range`) and sets the scope around that one `mutate_code` call; `mutate_code` shifts it past the preamble by the preamble's UTF-8 byte length. A range cached from another source, or measured in characters, drifts into sibling functions.
- **Crossover cuts only where the parents align** (`difflib` matching blocks over body lines), so a child never drops or repeats a line; identical parents return the parent.

## Consumers

- `match_ga.py`: primary GA loop (`build_candidate_obj_only`)
- `match_sweep.py`: flag sweep
- `diff.py`, `stack_cmp.py`: compile-for-compare helpers
- `compile.py` / `test.py` / `prove.py`: import **`rebrew.matcher.parsers`** directly (package `__init__` is lazy so this does not load mutator/compiler)

## Gotchas

- **Lazy package exports**: `rebrew.matcher` resolves public names via `__getattr__`. Importing a submodule (e.g. `parsers`) does not load the GA stack; `from rebrew.matcher import mutate_code` still works.
- **Profile-parametrized sweep**: `generate_flag_combinations(tier=, profile=)` picks axes per profile (incl. `borland-2.0`). No flag-set entry: use registry `flags_style` (posix → GCC axes, not MSVC `/Gd`); a name that is not a registered toolchain keeps MSVC axes. `flag_sweep` refuses a posix profile absent from the merged tier map (packaged tiers plus `rebrew.flag_sets`) — do not delete that `ValueError` to match the generator fallback.
- **Reloc and registers**: `score_candidate` masks caller-supplied `reloc_offsets` when present; the x86 pattern normalizer runs only when they are absent. Register masking is capstone ModR/M, not COFF metadata.
- **Timeouts**: `build_candidate_obj_only` / `flag_sweep` default 60s; `build_candidate` (compile+link) defaults to 120s. Direct subprocess timeouts return `BuildResult(ok=False)`. Image-backed path: `timeout=` seeds a synthetic cfg when none is passed; a real `cfg` uses `cfg.compile_timeout`.
- **Wine stderr**: lazy `rebrew.compile.filter_wine_stderr()` (avoids import cycle).
- **No global state**: each run owns its in-memory memo, `Random`, and temp dirs, safe to run concurrently.
