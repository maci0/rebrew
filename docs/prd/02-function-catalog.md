# PRD 02 — Function Catalog

**Feature name:** Function Catalog & Triage
**One-line value:** Build a complete, queryable inventory of every function in
the target binary — covered, uncovered, library, stub — so the user always
knows what's left to reverse and where the easy wins are.

## Problem It Solves

A real reversing project has thousands of functions. Without a single
ground-truth catalog the user:

- Cannot tell what's done, in-progress, or untouched.
- Cannot tell which functions are first-party game code vs. third-party
  library code (CRT, zlib, DirectX) that can be matched from upstream sources.
- Has no machine-readable coverage data to feed dashboards (recoverage) or
  CI gates.
- Re-disassembles the same VA multiple times instead of extracting `.bin`
  files once.

The Function Catalog feature unifies these by collecting **all** known
function metadata from Ghidra exports, the function list file, FLIRT
signatures, CRT source mirrors, and the user's own `// FUNCTION:` /
`// LIBRARY:` / `// STUB:` annotations, then publishes the merged view as
CATALOG.md, JSON, CSV, and a SQLite coverage DB.

## Users

- **Solo reverser** running `rebrew todo` to pick what to work on next.
- **AI agent** (`rebrew-intake` and `rebrew-workflow` skills) running
  catalog + FLIRT + CRT triage as part of onboarding.
- **Dashboard / CI** consumers reading `db/coverage.db` or `data_<target>.json`
  for progress reporting.
- **Team lead** producing a high-level CATALOG.md to share with stakeholders.

## Goals

- Single command (`rebrew catalog`) that scans annotations and produces:
  - Markdown CATALOG.md
  - SQLite-ready JSON in `db/data_<target>.json`
  - Optional `reccmp`-compatible CSV for interop with other tooling
  - Ghidra function/label exports
- Bulk extraction of raw `.bin` slices of uncovered functions for
  byte-level work (`rebrew extract`).
- FLIRT signature scan that flags library functions in the binary
  (`rebrew flirt`).
- CRT source cross-reference matcher that maps `LIBRARY:` markers to a
  specific MSVC CRT source file (`rebrew crt-match`).
- SQLite coverage database build (`rebrew build-db`).

## Non-Goals

- The catalog does not modify source files (CATALOG.md is generated; `.c`
  files are read-only).
- `rebrew extract` produces `.bin` files only, never C skeletons. Skeleton
  generation lives in PRD 03.
- `rebrew flirt` is signature-driven; it does not infer arguments or types.
- CRT matching identifies *which* CRT source likely produced a function; it
  doesn't compile or verify the candidate. That belongs to PRD 03/05.

## Functional Requirements

### `rebrew catalog`

- Scans `reversed_dir` for `.c` files containing reccmp-style markers.
- Loads optional `function_structure.json` (Ghidra export) and
  `functions.txt`/`.json` (function list).
- Builds a unified registry merging:
  - Local annotations
  - Ghidra functions
  - Bare function-list entries (size-only, no name)
- Resolves canonical sizes (Ghidra/Catalog wins over annotation; warns on
  conflict).
- Outputs in any combination of modes:
  - Default: scan + validate, print summary.
  - `--data-json` writes `db/data_<target>.json` (cell-level coverage grid).
  - `--catalog` writes CATALOG.md to `reversed_dir`.
  - `--csv` writes a reccmp-compatible CSV next to data JSON.
  - `--summary` prints stdout summary table.
  - `--export-ghidra` caches `ghidra_functions.json` for offline tools.
  - `--export-ghidra-labels` writes `ghidra_data_labels.json` from detected
    jump tables / dispatch tables.
  - `--fix-sizes` rewrites `SIZE` in `rebrew-function.toml` when the catalog's
    canonical size differs.
- `--json` produces machine-readable output.

### `rebrew extract`

Three subcommands:

- `extract list` — enumerate un-reversed candidates from the function list.
- `extract show VA` — disassemble a single function (hex by default).
- `extract batch N [--start M]` — extract + disassemble the N smallest
  un-reversed functions, optionally offset into the sorted list.

Output `.bin` files land in the configured `bin_dir`.

### `rebrew flirt`

- Scans the target PE/ELF with FLIRT signatures (`.sig` or `.pat`).
- Emits matched function VAs + likely library identities.
- `--min-size` filters out tiny matches that are likely noise.
- `--exe PATH` overrides the binary; `--target` selects from
  `rebrew-project.toml`.
- `--json` emits structured matches.

### `rebrew crt-match`

- Indexes `crt_source_dirs` (set via `cfg detect-crt` or manually) by symbol.
- Matches `LIBRARY:` annotations (or a single VA) against the indexed
  symbols and ranks candidates.
- `--all` runs across every LIBRARY marker.
- `--fix-source` writes a `// SOURCE: <path>` annotation back to each
  matched `.c` file.
- `--index` prints the constructed CRT index for inspection.
- `--json` emits structured matches.

### `rebrew build-db`

- Consumes `db/data_<target>.json` (one per target) and produces
  `db/coverage.db` (SQLite) containing function, global, section, and
  cell tables.
- Writes CATALOG.md alongside.
- Schema version is stamped in a `metadata` table.

## User Stories / Workflows

### Story 1 — First intake of a new binary

1. After `rebrew init` + `rebrew doctor`, the user runs
   `rebrew flirt --json` and discovers 412 MSVCRT/MFC/DirectX functions.
2. `rebrew catalog --catalog --data-json --json` builds a snapshot of all
   uncovered functions.
3. `rebrew extract batch 20` produces 20 `.bin` files ready for the
   reversing loop.
4. `rebrew build-db` produces `db/coverage.db` consumed by the recoverage
   dashboard.

### Story 2 — Mapping library functions to upstream source

1. User has dozens of `// LIBRARY: MSVCRT 0x...` annotations with empty
   bodies.
2. User runs `rebrew cfg detect-crt` so the MSVC source mirror is registered.
3. `rebrew crt-match --all --fix-source` annotates every match with a
   `// SOURCE: vcsrc/.../strcpy.c` reference.
4. The user then runs `rebrew test` on the candidates and many promote to
   EXACT/RELOC because the CRT source already compiles to identical bytes.

### Story 3 — Resolving a Ghidra/annotation size disagreement

1. `rebrew catalog --summary` prints a warning that `_my_func` has
   annotation size 42 but Ghidra reports 47.
2. User runs `rebrew catalog --fix-sizes` to write the canonical 47 to
   `rebrew-function.toml`.
3. Next `rebrew verify` no longer fails the size check.

### Story 4 — Dashboard refresh

1. CI runs `rebrew catalog --data-json --json` then `rebrew build-db --json`
   on every push to main.
2. `db/coverage.db` is uploaded as an artifact and consumed by recoverage.

## CLI Surface

```
rebrew catalog [OPTIONS]
      --data-json
      --catalog
      --summary
      --csv
      --export-ghidra
      --export-ghidra-labels
      --fix-sizes
      --root PATH
      --json
  -t, --target TEXT

rebrew extract list   [--json] [-t TARGET]
rebrew extract show VA [--size N] [--json] [-t TARGET]
rebrew extract batch N [--start M] [--json] [-t TARGET]

rebrew flirt [SIG_DIR]
      --exe PATH
      --min-size N           (default 16)
      --json
  -t, --target TEXT

rebrew crt-match [VA]
      --all
      --fix-source
      --index
      --json
  -t, --target TEXT

rebrew build-db
      --root PATH
      --json
  -t, --target TEXT
```

## Success Metrics

- `rebrew catalog --json` runs in under 10 s on a 5000-function binary.
- After FLIRT + catalog + CRT triage, the share of LIBRARY-attributed
  uncovered functions in `rebrew todo` drops to <5% (the rest become
  `identify-library` follow-up work).
- `db/coverage.db` schema is stable across patch releases (versioned).
- CATALOG.md is human-readable and round-trips cleanly through `git diff`
  (deterministic ordering).

## Open Questions / Known Limitations

- FLIRT signatures must be supplied by the user; Rebrew ships none.
  `gen_flirt_pat.py` can build `.pat` files from `.lib` archives, but
  converting `.pat` → `.sig` still requires the upstream `sigmake` tool.
- CRT matching relies on symbol heuristics; ambiguous names yield multiple
  candidates and require manual disambiguation.
- The function list ingester accepts both `functions.txt` (one VA per line
  or `VA size name`) and `function_structure.json` (Ghidra export); other
  formats are not supported.
- `--export-ghidra` caches a Ghidra function list but does not re-fetch
  live data; pair with `rebrew sync --refresh-cache` for that.
- `build-db` writes to `db/coverage.db` deterministically but never migrates
  an older schema; users must delete the file when the schema version
  changes.
- `rebrew extract show` uses capstone for x86; non-x86 targets are out of
  scope until matchings adds support.
