# PRD 03 — Skeleton & Iteration

**Feature name:** Skeleton & Iteration Loop
**One-line value:** Compress the inner loop of "write candidate C, compile,
compare against the original, fix" into one keystroke per step, with
auto-promoted STATUS and ROI-prioritised next actions.

## Problem It Solves

The byte-matching workflow is brittle without tooling:

- A skeleton file with the right `// FUNCTION:` marker, the correct
  prototype, and the right metadata stub is tedious to author.
- Tracking which function has which compile flags, which is "close enough"
  (NEAR_MATCHING), and which is exact requires bookkeeping that drifts.
- When the candidate doesn't match byte-for-byte, the user needs a diff
  viewer that explains *why* (relocation? register choice? loop layout?)
  rather than a raw hex dump.
- Re-running the whole pipeline by hand for every save is slow; the user
  wants a tight test/diff/edit cycle.
- Reorganising files (split a multi-function `.c`, merge several into one,
  rename a function with all cross-references) must be safe and idempotent
  or it will corrupt the in-progress work.

PRD 03 covers the inner loop: skeleton generation, test, diff, lint, file
shape changes (split/merge/rename), and the `todo` action ranker that tells
you what to attack next.

## Users

- **Solo reverser** sitting in front of `rebrew test` and `rebrew diff`
  thousands of times per project.
- **AI agent** (`rebrew-workflow` skill) running `rebrew todo` → skeleton
  → edit → test → repeat.
- **Team lead** running `rebrew lint --summary` for a quick health check.

## Goals

- One-command skeleton creation from a VA, with optional embedded
  decompilation (r2dec/r2ghidra/Ghidra headless) and cross-references.
- A `test` command that:
  - Auto-detects symbol, VA, size, and CFLAGS from source and metadata.
  - Compiles via MSVC6 (or configured compiler).
  - Byte-compares against the target.
  - Auto-promotes STATUS (EXACT / RELOC / NEAR_MATCHING / STUB) in
    `rebrew-function.toml`.
- A `diff` command that classifies mismatches into structural / relocation /
  register / invalid-relocation and can auto-write BLOCKER metadata.
- A `lint` command that enforces marker discipline and migrates legacy
  inline metadata into `rebrew-function.toml`.
- File operations (`split`, `merge`, `rename`) that are dry-run-friendly
  and never lose annotations.
- A `todo` ranker that scores every actionable item by ROI and groups
  results by category (compile-error, fix-delta, improve-match,
  start-function, identify-library, run-prover).

## Non-Goals

- `test` does not run the GA — that's PRD 04.
- `skeleton --decomp` does not promise a clean compile; the embedded
  decompilation is a hint, not a working candidate.
- `lint` does not edit code structure; it only adjusts annotations and
  optionally migrates inline metadata.
- `merge` does not re-resolve forward references between functions; the
  user is responsible for include ordering inside the merged file.

## Functional Requirements

### `rebrew skeleton`

- Single mode: `rebrew skeleton 0x10003da0` writes
  `src/<target>/<name>.c` with a `// FUNCTION: <module> 0x...` marker and a
  placeholder body.
- `--name` overrides the auto-derived function name.
- `--output` overrides the destination path.
- `--batch N` generates the N smallest uncovered skeletons (`--min-size`,
  `--max-size` filter the range; `--skip-fragments` excludes entries whose
  first bytes look like data/fragments).
- `--force` overwrites an existing file.
- `--append PATH` appends the marker block to an existing multi-function
  `.c` file rather than creating a new one.
- `--decomp [--decomp-backend auto|r2ghidra|r2dec|ghidra]` embeds a
  decompilation as a starting point; `--decomp-body` writes the decompiled C
  as the function body (a real GA seed) instead of a comment block.
- `--xrefs --endpoint URL` fetches cross-references from Ghidra and
  injects them as comments.
- All volatile metadata (STATUS=STUB, SIZE, CFLAGS, BLOCKER) is written to
  `rebrew-function.toml`, never inlined into the `.c` file.

### `rebrew test`

- Compiles a single `.c` (or every `.c` with `--all`) with MSVC6 via Wine,
  extracts the named COFF symbol, and byte-compares against the target.
- Auto-detects symbol, VA, size from `// FUNCTION:` markers, and STATUS/
  SIZE/CFLAGS from `rebrew-function.toml`.
- `--va`, `--symbol`, `--size`, `--target-bin`, `--cflags`, `--toolchain`
  override values.
- `--no-promote` disables STATUS auto-update (also auto-skipped for files
  outside the project).
- Batch mode: `--all` (+ optional `--dir`, `--origin`, `-j JOBS`, `--dry-run`).
- Exit codes: 0=EXACT/RELOC, 1=NEAR_MATCHING/STUB, 2=BUILD_ERROR.
- On success the writer clears any auto-generated BLOCKER from metadata.

### `rebrew diff`

- Compiles the source, compares to target, and renders a hex diff with
  marker codes (`==` identical, `~~` relocation diff, `RR` register
  encoding diff with `-r`, `**` structural, `XX` invalid relocation).
- `-m` shows only structural diff (`**`) lines.
- `-r` normalises register encodings.
- `--format csv` emits CSV.
- `--fix-blocker` writes the inferred BLOCKER/BLOCKER_DELTA to
  `rebrew-function.toml`.
- `--ignore-lint` runs even when annotation lint errors exist.
- Exit codes: 0=no structural diff, 1=structural diff, 2=build failure.

### `rebrew lint`

- Validates `// FUNCTION:` / `// LIBRARY:` / `// STUB:` / `// GLOBAL:` /
  `// DATA:` markers.
- Error codes: `E001` (missing marker), `E002` (invalid VA), `E012`
  (module mismatch), `E013` (duplicate VA), `E023` (whole-function
  `__declspec(naked)` + `__asm`/`__emit` block instead of real C).
- Warnings: `W005` (STUB without BLOCKER), `W016` (DATA/GLOBAL missing
  SECTION), `W010` (unknown marker key), `W018` (missing CFLAGS), `W019`
  (inline metadata should be in `rebrew-function.toml`), `W020` (asm-dump
  placeholder instead of real C source), `W021` (duplicate global symbol
  across files), `W022` (zero-initializer forces `.data` not `.bss`),
  `W023` (default function name), `W024` (name violates naming convention),
  `W025` (brace style mismatch), `W026` (indent style mismatch), `W027`
  (line too long).
- `--fix` migrates inline metadata into `rebrew-function.toml` and removes
  it from source.
- `--summary` prints a STATUS/origin breakdown table.
- `--quiet` errors-only, `--json` machine-readable.

### `rebrew split` / `rebrew merge` / `rebrew rename`

- `split SRC` produces one `<name>.c` per function. `--va` extracts a
  single function and leaves the rest. `--out-dir` overrides the output
  directory. `--dry-run`, `--force` available.
- `merge SRCS... -o OUTPUT` (inputs may be files or directories)
  deduplicates preambles (includes, typedefs) and keeps each function's
  `// FUNCTION:` marker. `--delete` removes the source files on success.
- `rename TARGET NEW` accepts a function name, file path, or VA, and
  updates the FUNCTION marker, definition, extern declarations, and
  cross-references. `--file NAME` renames the underlying file.

### `rebrew todo`

- Computes a continuous ROI score and emits a globally interleaved list:
  - `setup` — fresh project steps.
  - `compile-error` — failed verify.
  - `extract-error` — symbol not found in `.obj`
    (marker/symbol/implementation issue).
  - `fix-delta` — known small deltas (≤20 B) ripe for flag sweep / GA.
  - `improve-match` — in-progress without small delta.
  - `start-function` — uncovered, ranked by size + difficulty.
  - `missing-annotation` — in Ghidra but no C body / SIZE annotation.
  - `identify-library` — uncovered LIBRARY-origin functions.
  - `run-prover` — small near-matches eligible for `rebrew prove`.
  - `documented` — IAT thunks / non-reproducible code (audit only, hidden
    from the default list).
- `--count N`, `--category C` filters.
- `--stats` adds coverage stats header.

## User Stories / Workflows

### Story 1 — From VA to first match

1. `rebrew todo --json` returns a top action `start-function 0x10003da0`.
2. `rebrew skeleton 0x10003da0 --decomp` writes
   `src/main/sub_10003da0.c` with embedded pseudocode.
3. User edits the body and saves.
4. `rebrew test src/main/sub_10003da0.c` reports `NEAR_MATCHING (delta 6)`.
5. `rebrew diff src/main/sub_10003da0.c -m` shows three `**` lines all
   tagged "register allocation".
6. User flips `/Os` to `/O1` in CFLAGS via `rebrew cfg set-cflags`, reruns
   `rebrew test` — STATUS promotes to EXACT.

### Story 2 — Cleaning up a multi-function file

1. `rebrew split src/main/crt_env.c` splits all functions into individual
   `.c` files under `src/main/`.
2. `rebrew rename old_helper new_helper --file new_helper.c` renames the
   function across files.
3. `rebrew lint --fix` migrates any leftover inline metadata to
   `rebrew-function.toml`.

### Story 3 — Quick action triage

1. After a long break, the user runs `rebrew todo --stats` and sees
   12 compile errors, 8 fix-delta candidates, 200 start-function items.
2. They fix the compile errors first (`rebrew todo -c compile-error`),
   knock out the fix-delta queue with `rebrew test`/`rebrew diff` cycles,
   and only then attack new functions.

### Story 4 — CI lint gate

1. CI runs `rebrew lint --json --quiet`; non-zero exit fails the build
   and prints `E001`/`E002` errors with file+line info.

## CLI Surface

```
rebrew skeleton [VA]
      --name TEXT
  -o, --output TEXT
      --batch N
      --skip-fragments
      --min-size N (default 10)
      --max-size N (default 9999)
      --force
      --append PATH
      --decomp
      --decomp-body
      --decomp-backend auto|r2ghidra|r2dec|ghidra (default auto)
      --xrefs
      --endpoint URL  (default http://localhost:8080/mcp/message)
      --dry-run
      --json
  -t, --target TEXT

rebrew test [SOURCE]
      --va TEXT
      --symbol TEXT
      --target-bin TEXT
      --size N
      --cflags TEXT
      --toolchain TEXT
      --all
      --dir TEXT
      --origin GAME|MSVCRT|ZLIB|...
      --dry-run
  -j, --jobs N
      --no-promote
      --force-status
      --fix-size
      --watch
      --json
  -t, --target TEXT

rebrew diff SEED_C
  -m, --mismatches-only
  -r, --register-aware
      --fix-blocker
      --dry-run
  -f, --format terminal|csv (default terminal)
      --ignore-lint
      --watch
      --json
  -t, --target TEXT

rebrew lint [FILES...]
      --fix
      --dry-run
  -q, --quiet
      --pedantic
      --summary
      --json
  -t, --target TEXT

rebrew split [SOURCE]
      --va TEXT
      --out-dir TEXT
      --dry-run
      --force
      --json
  -t, --target TEXT

rebrew merge [SOURCES...]
  -o, --output TEXT (required)
      --dry-run
      --force
      --delete
      --json
  -t, --target TEXT

rebrew rename TARGET_IDENT NEW_NAME
      --file TEXT
      --dry-run
      --json
  -t, --target TEXT

rebrew todo
  -n, --count N (default 20)
  -c, --category TEXT
  -s, --stats
      --json
  -t, --target TEXT
```

## Success Metrics

- `rebrew test` round-trip (no cache) under 1 s on a 50-line C file.
- With cache hits, `rebrew test --all` over a 500-function project runs in
  under 5 s.
- STATUS in `rebrew-function.toml` always reflects the latest test result;
  no out-of-band STATUS writes from the source file.
- `rebrew lint --fix --dry-run` is safe to suggest to humans — never
  surfaces a destructive change unless `--fix` is given without `--dry-run`.
- `rebrew todo`'s ROI ranking is stable across small project changes (no
  thrashing).

## Open Questions / Known Limitations

- `rebrew test` only auto-promotes for files inside the project root; tests
  run on external paths skip promotion silently.
- `rebrew diff` only classifies systemic compiler differences (register
  allocation, branch layout, frame choice). It does not classify
  algorithmic or type-level differences.
- `rebrew skeleton --decomp` requires r2 + r2ghidra/r2dec/ghidra to be
  installed on the host; failure modes degrade to a bare skeleton with a
  warning.
- `rebrew rename` does best-effort cross-reference updates by scanning the
  reversed directory; it deliberately does not rewrite macros or string
  literals — `grep` for the old name afterwards if you suspect any.
- `rebrew split` and `rebrew merge` are textual operations driven by
  `// FUNCTION:` markers; arbitrary C constructs between functions (e.g.
  file-scope statics that span declarations) may need manual fix-up.
- `rebrew todo` does not yet have a "blocked" category for items waiting on
  external decisions; users currently encode that in BLOCKER metadata.
