# PRD 05 — Verification & Progress

**Feature name:** Verification, Progress Reporting & Caching
**One-line value:** Give the project a single source of truth for "what
percentage of bytes match today" with caching so it's cheap to ask, and
guard against regressions when changes ship.

## Problem It Solves

Once a project has more than a handful of functions, the user needs:

- A bulk command that confirms every reversed function still compiles and
  still produces the expected bytes.
- An incremental cache so re-running the bulk check after one edit doesn't
  recompile every file.
- A high-level "where are we?" snapshot with counts per STATUS and
  percent coverage.
- A regression detector for CI ("PR turns 3 EXACT → NEAR_MATCHING").
- A dependency graph that shows how reversed functions connect.

PRD 05 collects these into `verify`, `status`, `graph`, and `cache`.

## Users

- **Solo reverser** running `rebrew status` between sessions to remember
  where they were.
- **AI agent** (`rebrew-workflow` skill) running `rebrew verify --json` to
  detect regressions before promoting STATUS.
- **CI bot** running `rebrew verify --compare` against the previous
  `db/verify_results.json` to fail on regressions.
- **Team lead** generating `rebrew graph --format mermaid` for design
  reviews.

## Goals

- Bulk verification (`rebrew verify`) with parallel compile, caching, and
  optional regression comparison.
- Read-only project overview (`rebrew status`) that summarises STATUS
  counts, source/target coverage, and progress against the canonical
  function list.
- Function dependency graph (`rebrew graph`) in Mermaid / Graphviz / text
  formats, optionally focused on a neighbourhood around one function.
- Persistent compile cache (`rebrew cache`) that the user can introspect
  and clear when needed.

## Non-Goals

- `verify` does not promote STATUS unconditionally — it calls
  `update_source_status` only when the new STATUS is a true promotion or
  matches the canonical promotion ladder.
- `graph` does not run dataflow analysis; direct call edges come from
  identifiers found in reversed source files, optionally augmented with
  binary-derived edges (`--include-dispatch`, `--binary`).
- `cache` does not manage other on-disk artifacts (e.g. `db/coverage.db`
  belongs to PRD 02). It only handles `.rebrew/compile_cache/`.
- Coverage in `status` is computed from local annotations and metadata,
  not from a live recompile (use `verify` for that).

## Functional Requirements

### `rebrew verify`

- For each `.c` file in `reversed_dir`, compiles with project-configured
  CFLAGS and compares against the target DLL.
- Reports EXACT, RELOC, NEAR_MATCHING (with delta), STUB, or
  COMPILE_ERROR.
- Writes a JSON report to `db/verify_results.json` by default
  (overridable with `-o`).
- `--compare` diffs against the last saved report and flags regressions
  (STATUS downgrades, new compile errors).
- `--full` ignores cache hits and re-verifies everything (edits to shared
  headers or include dirs otherwise invalidate the affected cache entries
  automatically).
- `--summary` prints a STATUS breakdown table.
- `-j JOBS` parallel compile jobs.
- `--json` machine-readable.
- Exit codes: 0=all passed, 1=failures or regressions.
- Calls `update_source_status` per file to keep `rebrew-functions.toml`
  authoritative.

### `rebrew status`

- Reads `rebrew-functions.toml` (STATUS lives in per-function metadata via
  `rebrew.metadata`), source markers, and function structure; no
  compilation.  Inline `// STATUS:` comments in `.c` files are legacy —
  they are counted as a W019 warning and `rebrew lint` migrates them to
  metadata.
- Prints:
  - Counts per STATUS (PROVEN, EXACT, RELOC, NEAR_MATCHING, STUB,
    LIBRARY, …).
  - Coverage as % bytes / % functions.
  - Counts of unresolved BLOCKERs.
  - Pointer to next action (`rebrew todo`).
- `--json` machine-readable.

### `rebrew graph`

- Scans reversed `.c` files for call targets; uses annotations to label
  origin/status of each node.
- `--format mermaid` (default) | `dot` | `summary`.
- `--focus FN [--depth N]` extracts a neighbourhood.
- `--cu-map` overlays compilation-unit boundary inference.
- `--include-dispatch` adds a virtual `dispatch_0x<VA>` node per dispatch
  table detected in the binary, connected to its function-pointer targets
  (dashed edges in mermaid/dot).
- `--min-table-len N` / `--max-pointer-stride N` tune dispatch-table
  detection (with `--include-dispatch`).
- `--binary` builds call edges from the target binary's xrefs instead of
  the reversed C sources (16-bit NE support included).
- `-o PATH` writes output to a file.
- `--json` emits a structured graph.

### `rebrew cache`

- `cache stats` — show the compile cache's path, entry count, disk usage,
  size limit, and session hit/miss counts with hit rate.
- `cache clear` — delete every cached `.obj` blob (`--force` skips the
  confirmation prompt).
- Cache lives in `<project_root>/.rebrew/compile_cache/`.
- Keyed by SHA-256 of (source + flags + compiler signature).

### `rebrew round-trip`

- Splice every function marked EXACT or RELOC (from `rebrew-functions.toml`
  metadata) back into a copy of the original PE binary.
- Apply COFF relocations per the `.obj` relocation records.
- Skip PROVEN functions (their bytes are semantically equivalent but not
  byte-identical by design).
- Verify the result is byte-identical to the original PE (sha256 hash match).
- Writes reassembled PE to disk next to the target binary (suffix
  `.reasm`), or to a custom path with `--out`.
- `--dry-run` skips writing the `.reasm` file; report still emitted.
- `--filter SUBSTR` restricts to functions whose symbol contains the
  substring.
- `--json` machine-readable report.
- Exit codes: 0=round-trip clean, 1=byte mismatch (spliced region differs
  from original), 2=infrastructure failure.

## User Stories / Workflows

### Story 1 — Pre-merge regression check

1. CI runs `rebrew verify --compare --json` against the committed
   `db/verify_results.json`.
2. If any function regressed (EXACT → NEAR_MATCHING, etc.) the job fails.
3. The author runs the same command locally to inspect the regression and
   pinpoint the offending file.

### Story 2 — Fast incremental check after one edit

1. User edits one `.c` file, runs `rebrew verify`.
2. Cache hits skip the compile invocation entirely for unchanged files;
   only the edited file (and dependents) are recompiled.
3. Total wall-clock drops from minutes to seconds.

### Story 3 — Visualising progress

1. User runs `rebrew graph --format mermaid -o docs/graph.md`.
2. The Mermaid diagram highlights EXACT (green), NEAR_MATCHING (yellow),
   STUB (red) nodes and shows call edges, making the missing pieces
   visually obvious.
3. They focus on a specific subtree: `rebrew graph --focus _Init --depth 2`.

### Story 4 — Cleaning a stale cache

1. After rebuilding a toolchain image (`rebrew toolchain build`), the
   user runs `rebrew verify` and observes spurious COMPILE_ERROR rows.
2. `rebrew cache clear` deletes the cached `.obj` files.
3. `rebrew verify --full` rebuilds everything from scratch.

### Story 5 — End-to-end reassembly check before shipping

1. CI bot runs `rebrew round-trip --json` after `rebrew verify` passes.
2. The round-trip splices every matched function back into the PE binary
   and compares the full binary hash against the original.
3. If any unexpected byte mismatch is found (relocation errors, padding
   issues, etc.), the job fails and the developer inspects the `.reasm`
   output with `radare2` or `diffoscope`.
4. This catches bugs that per-function `verify` cannot expose (e.g.
   relocation application errors across section boundaries).

## CLI Surface

```
rebrew verify [OPTIONS]
      --root PATH
  -j, --jobs N
  -o, --output PATH (default db/verify_results.json)
  -s, --summary
      --compare
      --full
      --fix-sizes
      --dry-run
      --watch
      --nolib
      --json
  -t, --target TEXT

rebrew status [OPTIONS]
      --json
  -t, --target TEXT

rebrew graph [OPTIONS]
  -f, --format mermaid|dot|summary (default mermaid)
      --focus FUNC
      --depth N (default 1)
      --cu-map
      --include-dispatch
      --min-table-len N (default 3)
      --max-pointer-stride N (default 4)
      --binary
  -o, --output PATH
      --json
  -t, --target TEXT

rebrew cache stats [--json] [-t TARGET]
rebrew cache clear [--force] [--json] [-t TARGET]

rebrew round-trip [OPTIONS]
      --out PATH
      --dry-run
      --filter SUBSTR
      --strict-catalog
      --fix-headers
      --allow-naked
      --json
  -t, --target TEXT
```

## Success Metrics

- Cached `rebrew verify` on a 500-function project completes in <10 s on a
  cold filesystem cache and <2 s on a warm cache (entirely cache hits).
- `rebrew verify --compare` correctly flags every STATUS regression in
  the previous report and never falsely reports a promotion as a
  regression.
- `rebrew status` runs in <1 s on a 5000-function project.
- `rebrew graph --format mermaid` output pastes cleanly into any
  GitHub/GitLab Markdown viewer.
- `rebrew cache clear` is safe to run at any time and leaves
  `rebrew-project.toml` and source files untouched.
- `rebrew round-trip` on a warm compile cache completes in <30 s for a
  2000-function project (bottleneck: relocation application + PE write).
- `rebrew round-trip --json` output is valid JSON with all fields present
  (target, binary, sha256 hashes, match status, spliced/skipped counts,
  mismatch list).

## Open Questions / Known Limitations

- `verify` does not detect *header* changes; users must add `--full` after
  editing any shared header. (FIXED: the verify cache key now hashes every
  reachable header via `_headers_hash` + `_external_includes_hash` in
  `verify.py`, so editing a shared header re-verifies exactly the entries
  whose sources reach it; `--full` remains available for a hard reset.)
- `verify --compare` baseline lives in a single file
  (`db/verify_results.json`); branching workflows may need
  per-branch artifacts (left to CI to manage).
- `status` percentages are computed from `function_structure.json` if
  available, else from the function list. With neither, % coverage shows
  N/A.
- `graph` direct call edges rely on identifier matching; macros and inline
  assembly are not resolved. (Partially fixed: function-pointer targets are
  now recoverable via `--include-dispatch` dispatch-table scanning of the
  binary, and `--binary` adds xref-derived edges — both opt-in.)
- `cache stats` does not break down hit rate (only count + size); logging
  hit/miss telemetry across the session was not exposed. (FIXED: `cache
  stats` now reports session hits/misses and hit rate.)
- The compile cache is project-local; sharing it across CI runs requires
  caching the `.rebrew/compile_cache/` directory as a build artifact.
- `round-trip` skips PROVEN functions (semantically equivalent, not
  byte-identical); pass-fail verdict reflects only EXACT + RELOC
  functions.
- `round-trip` does not verify padding regions between functions; alignment
  regressions detectable by per-function `verify` are not re-checked after
  splice. (Full padding validation is a follow-up feature.)
