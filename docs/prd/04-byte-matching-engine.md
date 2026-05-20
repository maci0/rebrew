# PRD 04 — Byte-Matching Engine

**Feature name:** GA Engine, Flag Sweep & Symbolic Prover
**One-line value:** Automatically converge a NEAR_MATCHING C source onto a
byte-exact (or provably equivalent) match by exploring source mutations and
compiler flag combinations.

## Problem It Solves

After a human writes a candidate function, the last 5%–20% of "byte
identical" work is dominated by:

- Trying compiler flag permutations (`/O1` vs `/O2`, `/Gd` vs `/Gz`,
  `/Ob1` vs `/Ob2`, structure alignment, FPO, …) — easily 50+ flags with
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
- **CI** running `rebrew match --all --flag-sweep --dry-run` to surface
  candidates without committing.

## Goals

- Single command, GA mode: `rebrew match seed.c` mutates the source and
  rebuilds until an EXACT/RELOC match (or budget exhausted).
- Single command, flag sweep mode: `rebrew match seed.c --flag-sweep-only
  --tier targeted` tries combinations of MSVC flags.
- Batch GA / flag-sweep across all `STUB` or `NEAR_MATCHING` functions
  (`--all`, `--near-miss`, `--improve`).
- Cross-function solution database: successful flag sets and mutations
  seed future GA runs (`--extra-seed`, opt-out via `--no-seed`).
- Symbolic equivalence prover via angr (`rebrew prove`) for the residue
  where byte equality is impossible.

## Non-Goals

- The GA is not an LLM; mutations are deterministic AST/text transforms
  drawn from the `matcher/mutator.py` library.
- The flag sweep is bounded to flag presets defined in `matcher/flag_data.py`;
  it does not invent flags or experiment with non-MSVC compilers.
- `rebrew prove` runs only when the function is already NEAR_MATCHING or
  RELOC; it does not rewrite source to make it provable.
- No GUI; CLI only.

## Functional Requirements

### `rebrew match` (GA)

- Default: GA from the seed source over `--generations` (default 100)
  generations with `--pop-size` (default 64) population.
- `--seed N` makes runs reproducible.
- `--cflags`, `--symbol`, `--va`, `--size`, `--cl`, `--inc`, `--link`,
  `--lib`, `--ldflags`, `--out-dir` override or augment values auto-derived
  from source + config.
- `--compare-obj` / `--no-compare-obj` toggles between fast object
  comparison and full link.
- `--extra-seed PATH` injects additional seed sources (mutations from
  already-solved functions).
- `--no-seed` disables cross-function seeding.
- Writes `output/ga_run/` (default) with best candidate, score log, and
  cflags solution if a match is achieved.
- `--ignore-lint` allows running on files with annotation lint errors.

### `rebrew match --flag-sweep-only`

- Skips the GA and runs a tiered MSVC flag sweep.
- `--tier quick|targeted|normal|thorough|full` (default `targeted`).
- Auto-detects symbol/VA/size/CFLAGS like `rebrew test`/`rebrew diff`.
- On success, prints the winning flag combination and (in `--all` mode)
  can write it back to `rebrew-function.toml`.

### `rebrew match --all` (batch)

- Runs GA on every STUB function by default.
- `--improve` runs on every NEAR_MATCHING function (no delta threshold).
- `--near-miss` runs only on NEAR_MATCHING with delta ≤ `--threshold`
  (default 10 bytes).
- `--flag-sweep` runs the flag sweep instead of GA on NEAR_MATCHING set;
  `--fix-cflags` writes wins back to `rebrew-function.toml`.
- `-j JOBS` parallelism, `--dry-run` lists targets without running.

### `rebrew prove`

- Validates STATUS is NEAR_MATCHING or RELOC.
- Extracts target bytes from the DLL and compiles the C source.
- Loads both blobs into angr; uses claripy/Z3 to prove EAX equivalence.
- `--timeout N` (default 60 s) and `--loop-bound N` (default 10) govern
  the search.
- `--start-offset` / `--end-offset` prove a sub-range of the function.
- `--all` proves every eligible function.
- `--dry-run` leaves metadata untouched even on success.
- On success, promotes STATUS → PROVEN in `rebrew-function.toml`.

## User Stories / Workflows

### Story 1 — Closing a 4-byte near-miss

1. `rebrew test foo.c` says NEAR_MATCHING delta=4.
2. `rebrew diff foo.c -m -r` reports two `**` lines, classified as
   "register allocation".
3. `rebrew match foo.c --flag-sweep-only --tier targeted` cycles register
   allocation flags and reports `/O1 /Gd` produces EXACT.
4. `rebrew cfg set-cflags main GAME "/O1 /Gd"` (or a per-function CFLAGS
   write) saves the win.

### Story 2 — GA on a STUB

1. `rebrew todo -c improve-match` highlights `bar.c` (STUB, body
   approximated from r2dec).
2. `rebrew match bar.c -g 200 -p 96 --seed 42` runs for ~20 minutes;
   final candidate hits RELOC.
3. `rebrew test bar.c` promotes STATUS in `rebrew-function.toml`.

### Story 3 — Batch flag sweep

1. `rebrew match --all --flag-sweep --fix-cflags --dry-run` lists 38
   NEAR_MATCHING functions.
2. The user removes the `--dry-run`; the sweep runs in parallel with
   `-j 8` and writes per-function CFLAGS into `rebrew-function.toml`.
3. `rebrew verify` afterwards shows 22 new EXACT/RELOC promotions.

### Story 4 — Proving the remainder

1. Some functions persistently fail the byte test due to register
   churn; the user runs `rebrew prove --all --json`.
2. angr proves equivalence on most; STATUS promotes to PROVEN.
3. The remaining failures (timeouts / loop bound exceeded) become the
   next manual targets.

## CLI Surface

```
rebrew match [SEED_C]
  Single-function controls
      --cl TEXT
      --inc TEXT
      --cflags TEXT
      --symbol TEXT
      --va TEXT
      --size N
      --out-dir TEXT (default output/ga_run)
      --compare-obj / --no-compare-obj
      --link TEXT
      --lib TEXT
      --ldflags TEXT
      --flag-sweep-only
      --tier quick|targeted|normal|thorough|full (default targeted)
      --ignore-lint
      --seed N
      --extra-seed PATH
      --no-seed
  GA tuning
  -g, --generations N (default 100)
  -p, --pop-size N (default 64)
  -j, --jobs N
  Batch mode
      --all
      --near-miss
      --improve
      --threshold N (default 10)
      --flag-sweep
      --fix-cflags
      --dry-run
  Output
      --json
  -t, --target TEXT

rebrew prove [SOURCE]
      --all
      --timeout N (default 60)
      --loop-bound N (default 10)
      --start-offset N
      --end-offset N
      --dry-run
      --json
  -t, --target TEXT
```

## Success Metrics

- Flag sweep `--tier targeted` resolves >50% of small (≤10 B) deltas on a
  representative MSVC6 project.
- GA `-g 200 -p 96` produces a EXACT/RELOC match on >25% of STUB
  functions with a non-trivial seed in under 30 minutes wall-clock per
  function on a 16-core box.
- `rebrew prove --all` clears the NEAR_MATCHING backlog of any function
  whose only remaining diff is register allocation (within timeout
  budget).
- Cross-function solution seeding (`--extra-seed`) reduces median
  generations-to-match for similar functions versus a cold GA run.

## Open Questions / Known Limitations

- The GA explores deterministic mutations; novel "creative" rewrites
  (e.g. changing data structures) require a human edit before re-seeding.
- `rebrew prove` only checks `EAX` equivalence today (function return
  register); functions with side effects in memory or other registers
  may need manual verification.
- angr is a heavy optional dependency (~500 MB) and must be installed via
  the `prove` extra (`uv pip install -e ".[prove]"`).
- The flag-sweep tier definitions are MSVC-specific (`matcher/flag_data.py`);
  GCC/Clang sweeps would require new flag presets.
- `--no-compare-obj` (full link) is slow; default object-only comparison
  trades a few false negatives (link-time deduplication) for speed.
- Batch flag sweep with `--fix-cflags` writes CFLAGS per function; this
  can fragment the project's CFLAGS configuration. Periodic
  consolidation (e.g. promoting a common CFLAGS to the module-level
  preset via `rebrew cfg set-cflags`) is the user's responsibility.
