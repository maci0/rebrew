# PRD 04: Byte-Matching Engine

- **Status**: Shipped
- **Date**: 2026-05 (updated 2026-09)
- **Owner**: rebrew team

**Feature name:** GA Engine, Flag Sweep & Symbolic Prover
**One-line value:** Automatically converge a NEAR_MATCHING C source onto a
byte-exact (or provably equivalent) match by exploring source mutations and
compiler flag combinations.

## Problem It Solves

After a human writes a candidate function, the last 5%–20% of "byte
identical" work is dominated by:

- Trying compiler flag permutations (`/O1` vs `/O2`, `/Gd` vs `/Gz`,
  `/Ob1` vs `/Ob2`, structure alignment, FPO, …): easily 50+ flags with
  combinatorial blow-up.
- Mutating expression style (e.g. `a = a + 1` vs `++a`, `if/else` vs
  ternary, local var orderings, loop forms) until the compiler emits the
  exact instruction sequence.
- Proving semantic equivalence when bytes will never match (e.g.
  vendor-specific register allocation) so the function can be marked
  PROVEN without bit-perfect output.

PRD 04 ships the automation layer: a genetic algorithm over C source, an
exhaustive (or tiered) compiler flag sweep, and an angr-backed symbolic
prover that promotes NEAR_MATCHING → PROVEN.

## Users

- **Solo reverser** finishing the long tail of `NEAR_MATCHING` functions.
- **AI agent** (`rebrew-matching` skill) attacking near-misses
  programmatically.
- **CI** running `rebrew match batch --dry-run --algorithm flags` to surface
  candidates without committing.

## Goals

- Single command, GA mode: `rebrew match run seed.c` mutates the source and
  rebuilds until an EXACT/RELOC match (or budget exhausted).
- Single command, flag sweep mode: `rebrew match flags seed.c
  --tier targeted` tries combinations of MSVC flags.
- Batch GA / flag-sweep across all `STUB` or `NEAR_MATCHING` functions
  (`--all`, `--near-miss`, `--improve`).
- Cross-function solution database: successful flag sets and mutations
  seed future GA runs (`--seed-file`, opt-out via `--no-seeds`).
- Symbolic equivalence prover via angr (`rebrew prove`) for the residue
  where byte equality is impossible.

## Non-Goals

- The GA is not an LLM; mutations are deterministic AST/text transforms
  drawn from the `matcher/mutator.py` library.
- The flag sweep is bounded to flag presets defined in `flag_data.py`;
  it does not invent flags (non-MSVC axes exist: watcom opt/codegen/pack).
- `rebrew prove` runs only on an already-admitted lane: NEAR_MATCHING or
  SIZE_MISMATCH (from the metadata STATUS, or from a cached verify verdict when
  the metadata lags), a blocker-documented STUB, or a `GA_CEILING`-documented
  function under `--ceiling`; it does not rewrite source to make it provable.
- No GUI; CLI only.

## Functional Requirements

### `rebrew match run` (GA)

- Default: GA from the seed source over `--generations` (default 100)
  generations with `--pop-size` (default 64) population.
- `--seed N` makes runs reproducible.
- `--cflags`, `--symbol`, `--va`, `--size`, `--cl`, `--inc`, `--link`,
  `--lib`, `--ldflags`, `--output` override or augment values auto-derived
  from source + config.
- `--compare-obj` / `--no-compare-obj` toggles between fast object
  comparison and full link.
- `--seed-file PATH` injects additional seed sources (mutations from
  already-solved functions); ignored when `--no-seeds` is also passed.
- `--no-seeds` disables cross-function seeding and takes precedence over
  `--seed-file`.
- Writes `output/ga_runs/` (default) with the best candidate (`best.c`) and
  per-symbol resume checkpoints (`checkpoints/<symbol>.json`).
- On a win, appends the cflags solution and the run/score record to
  `<project_root>/.rebrew/ga_runs.jsonl`.
- `--ignore-lint` allows running on files with annotation lint errors.

### `rebrew match flags`

- Skips the GA and runs a tiered MSVC flag sweep (tier reference:
  `docs/FLAG_SWEEP_TIERS.md`).
- `--tier quick|targeted|normal|thorough|full` (default `targeted`).
- Auto-detects symbol/VA/size/CFLAGS like `rebrew test`/`rebrew diff`.
- On success, prints the winning flag combination and (in `--all` mode)
  can write it back to `rebrew-functions.toml`.

### `rebrew match batch` (batch)

- Runs GA on every STUB function by default.
- `--improve` runs on every NEAR_MATCHING function (no delta threshold).
- `--near-miss` runs only on NEAR_MATCHING with delta ≤ `--threshold`
  (default 10 bytes).
- `--flag-sweep` runs the flag sweep instead of GA on NEAR_MATCHING set;
  `--fix-cflags` writes wins back to `rebrew-functions.toml`.
- `--jobs JOBS` parallelism, `--dry-run` previews changes without running.

### `rebrew prove`

- Admits three lanes and rejects everything else: metadata STATUS of
  NEAR_MATCHING or SIZE_MISMATCH; a STUB carrying a `blocker` /
  `blocker_delta` (a blocker-documented STUB); or, under `--ceiling`, a
  `GA_CEILING`-documented function (the register- or encoding-only set the GA
  gave up on). When the metadata STATUS differs, a cached verify verdict of
  NEAR_MATCHING/SIZE_MISMATCH is overlaid, so a lagging STATUS is not refused.
  RELOC/EXACT already match byte-for-byte; promoting those to PROVEN is
  rejected.
- Extracts target bytes from the DLL and compiles the C source.
- Refuses promotion when post-compile bytes already match (that is RELOC).
- Loads both blobs into angr; uses claripy/Z3 to prove EAX equivalence
  (`--check-edx` also compares EDX; auto-enabled for 64-bit return types).
- `--timeout N` (default 60 s) and `--loop-bound N` (default 10) govern
  the search.
- `--start-offset` / `--end-offset` prove a sub-range of the function.
- `--all` proves all NEAR_MATCHING/SIZE_MISMATCH functions; `--ceiling` narrows
  the batch to the `GA_CEILING`-documented set; `--max-delta N` skips only
  candidates that HAVE a recorded byte delta above N, so undelta'd candidates
  stay in the batch.
- `--dry-run` leaves metadata untouched even on success.
- On success, promotes STATUS → PROVEN in `rebrew-functions.toml`
  (per ADR-024, PROVEN records semantic equivalence, is not a byte match,
  is excluded from matched counts/coverage, and is not sticky: subsequent
  `rebrew test`/`verify` runs record their byte verdicts over it).

## User Stories / Workflows

### Story 1: Closing a 4-byte near-miss

1. `rebrew test foo.c` says NEAR_MATCHING delta=4.
2. `rebrew diff foo.c --mismatches-only --register-aware` reports two `**`
   lines, classified as
   "register allocation".
3. `rebrew match flags foo.c --tier targeted` cycles register
   allocation flags and reports `/O1 /Gd` produces EXACT.
4. `rebrew cfg module set-cflags GAME "/O1 /Gd" --target main` (or a per-function CFLAGS
   write) saves the win.

### Story 2: GA on a STUB

1. `rebrew todo --category improve-match` highlights `bar.c` (STUB, body
   approximated from r2dec).
2. `rebrew match run bar.c --generations 200 --pop-size 96 --seed 42` runs for ~20 minutes;
   final candidate hits RELOC.
3. `rebrew test bar.c` promotes STATUS in `rebrew-functions.toml`.

### Story 3: Batch flag sweep

1. `rebrew match batch --fix-cflags --dry-run --algorithm flags` lists 38
   NEAR_MATCHING functions.
2. The user removes the `--dry-run`; the sweep runs in parallel with
   `--jobs 8` and writes per-function CFLAGS into `rebrew-functions.toml`.
3. `rebrew verify` afterwards shows 22 new EXACT/RELOC promotions.

### Story 4: Proving the remainder

1. Some functions persistently fail the byte test due to register
   churn; the user runs `rebrew prove --all --json`.
2. angr proves equivalence on most; STATUS promotes to PROVEN.
3. The remaining failures (timeouts / loop bound exceeded) become the
   next manual targets.

## CLI Surface

Search selection and algorithms have separate operations. See
[the CLI reference](../CLI.md) for complete option tables and
[the migration guide](../CLI_MIGRATION.md) for removed mode flags.

| Operation | Purpose | Main controls |
|---|---|---|
| `rebrew match run SOURCE` | Single-function GA | `--generations`, `--pop-size`, `--seed`, `--mutation-focus` |
| `rebrew match batch` | Select and search project functions | `--algorithm`, `--near-miss`, `--threshold`, `--max-stubs`, `--all-targets` |
| `rebrew match flags SOURCE` | Search one profile's compiler flags | `--tier`, `--jobs` |
| `rebrew match toolchains SOURCE` | Search compiler profiles, optionally their flag grids | `--toolchains`, `--exclude-toolchains`, `--flags`, `--tier` |
| `rebrew match history` | Inspect recorded runs | `--json` |

Single-function searches accept `--symbol`, `--va`, and `--size` to select the
function, and `--cl`, `--inc`, `--cflags`, `--link`, `--lib`, and `--ldflags`
for compilation overrides. `--output/-o` names their artifact directory.
GA seed controls belong to `match run` and `match batch`; `--seed-llm` is
available on `match run` only. Batch `--algorithm` selects `ga`, `flags`, or
`flags-then-ga`. Use `--dry-run` to preview selection and `--json` for
structured results.

```bash
rebrew match run src/main/function.c --generations 200 --pop-size 96 --seed 42
rebrew match flags src/main/function.c --tier targeted
rebrew match toolchains src/main/function.c --toolchains msvc-6.0,msvc-6.0-sp6 --flags
rebrew match batch --algorithm flags --near-miss --threshold 10 --dry-run --json
rebrew match history --json
rebrew prove src/main/function.c --timeout 60 --json
```

`prove` records semantic evidence within its modeled inputs and bounds; a
subsequent byte comparison determines byte-match status independently.

## Success Metrics

- Flag sweep `--tier targeted` resolves >50% of small (≤10 B) deltas on a
  representative MSVC6 project.
- GA `-g 200 -p 96` produces a EXACT/RELOC match on >25% of STUB
  functions with a non-trivial seed in under 30 minutes wall-clock per
  function on a 16-core box.
- `rebrew prove --all` clears the NEAR_MATCHING backlog of any function
  whose only remaining diff is register allocation (within timeout
  budget).
- Cross-function solution seeding (`--seed-file`) reduces median
  generations-to-match for similar functions versus a cold GA run.

## Open Questions / Known Limitations

- The GA explores deterministic mutations; novel "creative" rewrites
  (e.g. changing data structures) require a human edit before re-seeding.
- `rebrew prove` now checks `EAX` by default and `EDX:EAX` when
  `--check-edx` is passed or when the C function signature declares a
  64-bit return type (`long long`, `__int64`, `int64_t`, `uint64_t`,
  `long double`).
  EDX checking is auto-enabled from the prototype (E9 v1, partially addressed).
  Memory side-effect checking is now opt-in per VA via `--watch-va` (compares
  4 bytes at each listed VA across state pairs); general tracking of writes to
  globals or output-pointer arguments is still unimplemented, so functions
  that write there can still be falsely promoted if those writes differ.
- angr is a heavy optional dependency (~500 MB) and must be installed via
  the `prove` extra (`uv pip install -e ".[prove]"`).
- The flag-sweep tier definitions cover MSVC, Watcom, Borland and GCC-style
  (posix) profiles only (`flag_data.py`; tier grid, axes and combinations
  are documented in `docs/FLAG_SWEEP_TIERS.md`); other families need new
  flag presets.
- `--no-compare-obj` (full link) is slow; default object-only comparison
  trades a few false negatives (link-time deduplication) for speed.
- Batch flag sweep with `--fix-cflags` writes CFLAGS per function; this
  can fragment the project's CFLAGS configuration. Periodic
  consolidation (e.g. promoting a common CFLAGS to the module-level
  preset via `rebrew cfg module set-cflags`) is the user's responsibility.
