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

Externals (the only packages this one may import): `binary_loader`, `coff_reloc`, `compile`, `compile_cache`, `config`, `errors`, `flag_data`, `flags`, `omf16`, `registry`, `temp_dirs`, `toolchain`, `toolchain_spec`, `utils`. The GA drives the toolchain, so the compile and toolchain entries are the intended inward edge; the reverse is not, which is why the flag axes sit outside. `temp_dirs` is the compile sandbox placement policy (`compiler.py` stages there rather than in the system temp dir). Keep further prose on this line free of backticks: the gate reads every backticked name as allowed.

## Data flow (GA path)

`build_candidate_obj_only` → miss in same-run memo and shared compile cache → docker compile → `parse_obj_symbol_bytes` → `score_candidate` (reloc zero + register mask + numpy/capstone) → `mutate_code` → loop in `match_ga.py`.

## Non-obvious types

- **Score**: lower is better; `byte_score` 0.0 = perfect; `total` is a property (the `WEIGHT_*` weighted sum of the five fields, defined beside it in `core.py`), not a stored field.
- **BuildResult**: check `ok` before using bytes; reported compiler failures use `ok=False`. Build helpers can still raise during argument parsing, filesystem operations, or backend calls.
- **StructuralSimilarity**: `exact` / `reloc_only` / `register_only` / `structural`; `flag_sensitive` means flags alone may fix it.
- **GACheckpoint**: JSON resume state; `args_hash` rejects stale checkpoints.

## Mutations

Packaged `mut_*` ops under `mutations/` → `ALL_MUTATIONS` in `mutator.py`. New ops: named `mut_*`, tree-sitter only (never regex), tested in `tests/test_mutator*.py`; inventory: `docs/GA_MUTATIONS.md`. Numeric constants need explicit ops (`mut_tweak_integer_literal` covers small ±deltas). Optional weights via `mutate_code(..., mutation_weights=)`. Entry-point group `rebrew.mutations`; duplicate name skipped with warning (packaged kept).

- **Keep precedence when splicing.** An operator that moves a captured subexpression into a tighter position (subscript base or index, operand of `+`/`*`, before `.`/`->`/`++`) takes it through `runtime._operand_bytes`, which parenthesizes anything that does not already bind as tightly as a postfix operator; wrap a generated `*(...)` in parentheses when `runtime._under_postfix(expr)`. Raw splicing turned `a[i + 1]` into `i + 1[a]` (= `i + a[1]`) and `*((char*)p + i)` into `(char*)p[i]`: valid C with a different value, so no validator catches it. Test each operator on a compound operand and under a postfix parent.
- **Scope is per source, in bytes.** `BinaryMatchingGA._mutate` locates the target function in each source (`_find_function_range`) and sets the scope around that one `mutate_code` call; `mutate_code` shifts it past the preamble by the preamble's UTF-8 byte length. A range cached from another source, or measured in characters, drifts into sibling functions.
- **Crossover cuts only where the parents align** (`difflib` matching blocks over body lines), so a child never drops or repeats a line; identical parents return the parent.

## Consumers

Package-root modules, not modules of this package:

- `match_ga.py`: primary GA loop (`build_candidate_obj_only`)
- `match_sweep.py`: flag sweep
- `diff.py`, `stack_cmp.py`: compile-for-compare helpers
- `compile.py` / `test.py` / `prove.py`: import **`rebrew.matcher.parsers`** directly (package `__init__` is lazy so this does not load mutator/compiler)

## Gotchas

- **Lazy package exports**: `rebrew.matcher` resolves public names via `__getattr__`. Importing a submodule (e.g. `parsers`) does not load the GA stack; `from rebrew.matcher import mutate_code` still works.
- **Profile-parametrized sweep**: `generate_flag_combinations(tier=, profile=)` picks axes per profile (incl. `borland-2.0`). No flag-set entry: use registry `flags_style` (posix → GCC axes, not MSVC `/Gd`); a name that is not a registered toolchain keeps MSVC axes. `flag_sweep` refuses a posix profile absent from the merged tier map (packaged tiers plus `rebrew.flag_sets`) — do not delete that `ValueError` to match the generator fallback.
- **Reloc and registers**: `score_candidate` masks caller-supplied `reloc_offsets` when present; the x86 pattern normalizer runs only when they are absent. Register masking is capstone ModR/M, not COFF metadata.
- **Timeouts**: `build_candidate_obj_only` / `flag_sweep` default 60s; `build_candidate` (compile+link) defaults to 120s. Direct subprocess timeouts return `BuildResult(ok=False)`. Image-backed path: `timeout=` seeds a synthetic cfg when none is passed; a real `cfg` uses `cfg.compile_timeout`. `flag_sweep(deadline=)`, `BinaryMatchingGA.run(deadline=)`, and `prove._run_simulation` read the budget from an injected `clock=` (default `time.monotonic`), so a replayed seed can be bounded by virtual time and land on the same number of generations or combinations.
- **Wine stderr**: lazy `rebrew.compile.filter_wine_stderr()` (avoids import cycle).
- **No global state**: each run owns its in-memory memo, `Random`, and temp dirs, safe to run concurrently.
- **One seed replays a run**: randomness comes only from the `rng: random.Random` threaded through `mutate_code` and every `mut_*` operator, so no module-level `random.*` and no OS entropy beyond the unseeded run's drawn `rng_seed`. Compiles are the only nondeterministic edge, and every caller (`match_ga`, `match_sweep`, `diff`, `stack_cmp`) reaches them as `compiler.build_candidate_obj_only`; a `from ... import build_candidate_obj_only` anywhere captures the object at import time and escapes that seam, along with the `--mutation-focus auto` classification in `match_ga.live_mutation_weights`. `run(clock=)` never falls back to the wall clock, so a budgeted replay lands on the same generations. Record dedupe, log pruning (`_PRUNE_MIN_BYTES`, `_LOSS_RECORD_RETENTION`), and submission-order collection are contracts of `solutions.py` / `match_ga.py`, not here. Pins: `tests/test_ga.py::TestSingleCompileSeam`, `tests/test_match.py::TestGAReplay`, `tests/test_match.py::TestGAVirtualClockReplay`.
