# PRD 02: Function Catalog

- **Status**: Shipped
- **Date**: 2026-05 (updated 2026-09)
- **Owner**: rebrew team

**Feature name:** Function Catalog & Triage
**One-line value:** Build a complete, queryable inventory of every function in
the target binary (covered, uncovered, library, stub) so the user always
knows what's left to reverse and where the easy wins are.

## Problem It Solves

A real reversing project has thousands of functions. Without a single
ground-truth catalog the user:

- Cannot tell what's done, in-progress, or untouched.
- Cannot tell which functions are first-party game code vs. third-party
  library code (CRT, zlib, DirectX) that can be matched from upstream sources.
- Has no machine-readable coverage data to feed dashboards (recovery) or
  CI gates.
- Re-disassembles the same VA multiple times instead of extracting `.bin`
  files once.

The Function Catalog feature unifies these by collecting **all** known
function metadata from Ghidra exports, the discovery inventory, FLIRT
signatures, CRT source mirrors, and the user's own `// FUNCTION:` /
`// LIBRARY:` / `// STUB:` annotations, then reports the merged view in
process: `rebrew build-db` is what writes it, as
`db/coverage-<target>.toml`.
(>2026-09: CATALOG.md generation and `functions.txt` were removed; the same
information lives in `rebrew-functions.toml`, served by `status`/`todo`/dashboard.)

## Users

- **Solo reverser** running `rebrew todo` to pick what to work on next.
- **AI agent** (`rebrew-intake` and `rebrew-workflow` skills) running
  catalog + FLIRT + CRT triage as part of onboarding.
- **Dashboard / CI** consumers reading `db/coverage-<target>.toml`
  for progress reporting.
- **Team lead** producing a high-level progress view to share with stakeholders
  (`rebrew status`, dashboard).

## Goals

- Single command (`rebrew catalog`) that scans annotations and produces:
  - the coverage grid, in process (the rendered result is
    `db/coverage-<target>.toml`, written by `rebrew build-db`; the JSON and CSV
    files this goal originally named are gone)
  - Ghidra function/label exports
- Bulk extraction of raw `.bin` slices of uncovered functions for
  byte-level work (`rebrew extract`).
- FLIRT signature scan that flags library functions in the binary
  (`rebrew flirt`).
- CRT source cross-reference matcher that maps `LIBRARY:` markers to a
  specific MSVC CRT source file (`rebrew crt-match`).
- Clear-text coverage document build (`rebrew build-db`).

## Non-Goals

- The catalog does not modify source files (data JSON/CSV are generated; `.c`
  files are read-only).
- `rebrew extract` produces `.bin` files only, never C skeletons. Skeleton
  generation lives in PRD 03.
- `rebrew flirt` is signature-driven; it does not infer arguments or types.
- CRT matching identifies *which* CRT source likely produced a function; it
  doesn't compile or verify the candidate. That belongs to PRD 03/05.

## Functional Requirements

### `rebrew catalog`

- Scans `reversed_dir` for `.c` files containing reccmp-style markers.
- Loads optional `function_structure.json` (discovery inventory / Ghidra
  export).
- Builds a unified registry merging:
  - Local annotations
  - Ghidra functions
  - Bare discovery entries (size-only, no name)
- Resolves canonical sizes (catalog wins over the annotation). Ghidra's size
  wins by default, but the function list wins when the extra bytes are tail
  padding, a jump table, out-of-line code, or a terminator-less code tail.
  `--summary` reports only the aggregate count of size disagreements
  (`Size disagree: N`), never per-function names.
- Outputs in any combination of modes:
  - Default (no flags): scan + validate, and print the summary table.  No
    artifact is written by `catalog` itself; `rebrew build-db` renders the
    coverage document from the same in-process scan.
  - `--data-json` / `--csv` (removed): the grid JSON and the reccmp-compatible
    CSV have no replacement.  A reader that needs the grid reads
    `db/coverage-<target>.toml` (see [COVERAGE_DOCUMENT.md](../COVERAGE_DOCUMENT.md)).
  - `--summary` prints the summary table to stderr.
  - `--export-ghidra` prints interactive Ghidra MCP export instructions for
    `function_structure.json` / `ghidra_data_labels.json` (writes no cache;
    refuses `--json`).
  - `--export-ghidra-labels` writes `ghidra_data_labels.json` from detected
    jump tables / dispatch tables.
  - `--fix-sizes` rewrites `SIZE` in `rebrew-functions.toml` only when the
    catalog's canonical size is larger than the recorded `SIZE` (it never
    shrinks `SIZE`); `--force` skips its confirmation prompt (and is
    required to combine it with `--json`).
- `--json` produces machine-readable output.

### `rebrew extract`

Three subcommands:

- `extract list`: enumerate un-reversed candidates from the function list.
- `extract show VA [--size N]`: disassemble a single function (hex by
  default); `--size N` overrides the catalog-recorded size, also for VAs
  absent from the candidate list (e.g. already reversed).
- `extract batch [N] [--start M]`: extract + disassemble the N smallest
  un-reversed functions (N defaults to 20), optionally offset into the
  sorted list.

All three accept `--binary`/`--min-size`/`--max-size` filters and `--json`.
Output `.bin` files land in the configured `bin_dir`.

### `rebrew flirt`

- Scans the target PE/ELF with FLIRT signatures (`.sig` or `.pat`).
- Emits matched function VAs + likely library identities.
- `--min-size` filters out tiny matches that are likely noise.
- `--va VA` checks a single function VA (hex) instead of the whole `.text`.
- `--show-ambiguous` reports ambiguous matches (offsets with >3 candidate
  names) as well.
- `--binary PATH` overrides the binary; `--target` selects from
  `rebrew-project.toml`.
- `--json` emits structured matches.

### `rebrew crt-match`

- Indexes the `crt_sources` target table (set via `cfg detect-crt` or manually) by symbol.
- Matches `LIBRARY:` annotations (or a single VA) against the indexed
  symbols and ranks candidates.
- `--all` runs across every LIBRARY marker.
- `--fix-source` records a match's `SOURCE` (`FILE:LINE`, or a bare `FILE` for
  asm-only entries) in the matched function's `rebrew-functions.toml` entry;
  the `.c` file is not edited. Only matches at confidence ≥ 0.85 with a known
  source line are written; lower-confidence and filename-only matches are
  skipped.
- `--dry-run` previews `--fix-source` writes without modifying files.
- `--index` prints the constructed CRT index for inspection.
- `--json` emits structured matches.

### `rebrew lib-match`

- Byte-compares reversed functions against linked static-library archives (`.lib`/`.a`) to flag code the linker supplies (ADR-013).
- `--lib PATH` checks against a specific static library (repeatable).
- `--stock-lib NAME` checks against stock archives from the toolchain docker image (e.g. `LIBCMT.LIB`).
- `--compile-commands PATH` indexes objects built from a source-vendored tree
  (default `build/compile_commands.json` when that file exists).
- With no `--lib` or `--stock-lib`, ingests `targets.<name>.external_libs`
  (path specs as libraries, bare names as stock archives). Errors when the
  resulting archive and object set is empty (ADR-013).
- `--va VA` tests a single hex VA instead of every reversed function. With
  no recorded SIZE, a library body that starts the read window still matches.
- `--allow PATH` ignores known library VAs from a file.
- `--json` emits structured matches.

### `rebrew build-db`

- Scans the project in process and writes
  `db/coverage-<target>.toml` (one document per target), a clear-text document per target holding the
  functions, globals, sections with their cells, verify results and status
  history.  Every aggregate (per-section buckets, byte coverage,
  `function_stats`) is derived by the reader, so nothing can disagree with the
  rows it was computed from.
- `--force` is accepted and has no effect: each document is replaced whole, so
  there is no schema to migrate past.
- `--regen` is accepted and dropped: generating in this process is the only
  mode left, so there is nothing for the flag to select.
- The document carries its own `version`; a file from another version is not
  migrated, and a rebuild replaces it.

## User Stories / Workflows

### Story 1: First intake of a new binary

1. After `rebrew init` + `rebrew doctor`, the user runs
   `rebrew flirt --json` and discovers 412 MSVCRT/MFC/DirectX functions.
2. `rebrew catalog --json` reports the catalog summary (the coverage document
   itself comes from `rebrew build-db`).
3. `rebrew extract batch 20` produces 20 `.bin` files ready for the
   reversing loop.
4. `rebrew build-db` produces `db/coverage-<target>.toml`, consumed by the
   recovery dashboard.

### Story 2: Mapping library functions to upstream source

1. User has dozens of `// LIBRARY: MSVCRT 0x...` annotations with empty
   bodies.
2. User runs `rebrew cfg detect-crt` so the MSVC source mirror is registered.
3. `rebrew crt-match --all --fix-source` records each writable match's
   `SOURCE` (e.g. `vcsrc/.../strcpy.c:1234`) in `rebrew-functions.toml`.
4. The user then runs `rebrew test` on the candidates and many promote to
   EXACT/RELOC because the CRT source already compiles to identical bytes.

### Story 3: Resolving a Ghidra/annotation size disagreement

1. `rebrew catalog --summary` counts `_my_func` in `Size disagree: N`, so the
   user knows some function has annotation size 42 where Ghidra reports 47
   (the summary names no functions; the user isolates the VA from the catalog
   JSON).
2. User runs `rebrew catalog --fix-sizes` to write the canonical 47 to
   `rebrew-functions.toml`.
3. Next `rebrew verify` no longer fails the size check.

### Story 4: Dashboard refresh

1. CI runs `rebrew build-db --json` on every push to main.
2. `db/coverage-<target>.toml` is uploaded as an artifact and consumed by recovery.

## CLI Surface

```
rebrew catalog [OPTIONS]
      --summary
      --export-ghidra
      --export-ghidra-labels
      --fix-sizes
      --force
      --root PATH
      --json
  -t, --target TEXT

rebrew extract list   [--json] [-t TARGET]
rebrew extract show VA [--size N] [--json] [-t TARGET]
rebrew extract batch [N] [--start M] [--dry-run] [--json] [-t TARGET]

rebrew flirt [SIG_DIR]
      --binary PATH
      --min-size N           (default 16)
      --va VA
      --init
      --init-matched
      --show-ambiguous
      --json
  -t, --target TEXT

rebrew crt-match [VA]
      --all
      --fix-source
      --index
      --dry-run
      --json
  -t, --target TEXT

rebrew lib-match [OPTIONS]
      --lib PATH
      --stock-lib TEXT
      --compile-commands PATH
      --va VA
      --allow PATH
      --json
  -t, --target TEXT

rebrew build-db
      --root PATH
      --force
      --regen
      --json
  -t, --target TEXT
```

## Success Metrics

- `rebrew catalog --json` runs in under 10 s on a 5000-function binary.
- After FLIRT + catalog + CRT triage, the share of LIBRARY-attributed
  uncovered functions in `rebrew todo` drops to <5% (the rest become
  `identify-library` follow-up work).
- The `coverage-<target>.toml` document format is stable across patch releases
  (its `version` field is the format's version).
- `rebrew status` output is human-readable; metadata TOMLs round-trip
  cleanly through `git diff` (deterministic ordering).

## Open Questions / Known Limitations

- Rebrew ships no `.sig` files of its own. `rebrew flirt --init` copies the
  sibling `rebrew-flirt-sigs` checkout into the project's `flirt_sigs/`
  (`--init-matched` copies only the sigs matching the target), and
  `gen_flirt_pat.py` can build `.pat` files from `.lib` archives. Converting
  `.pat` → `.sig` still requires the upstream `sigmake` tool.
- CRT matching relies on symbol heuristics; ambiguous names yield multiple
  candidates and require manual disambiguation.
- The function list ingester reads `function_structure.json` (discovery /
  Ghidra export). The former `functions.txt` format is gone.
- `--export-ghidra` writes no cache: it prints interactive Ghidra MCP export
  instructions for `function_structure.json` / `ghidra_data_labels.json` and
  exits (refuses `--json`). `rebrew catalog` writes no inventory file at all:
  only `rebrew build-db` writes a file; no command in rebrew produces a
  stamped `function_structure.json` today, so the ingester's `_generated_by`
  filter only skips one written elsewhere. Fetch live data via
  `rebrew sync`.
- `build-db` writes each `coverage-<target>.toml` deterministically.  It never
  migrates an older format: a document from another `version` contributes no
  history and is replaced whole on the next run, so an upgrade costs a rebuild
  and loses nothing the catalog can regenerate.
- `rebrew extract show` uses capstone for x86; non-x86 targets are out of
  scope until matching adds support.
