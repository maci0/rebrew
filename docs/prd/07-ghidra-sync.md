# PRD 07 — Ghidra Sync

**Feature name:** Bidirectional Ghidra ↔ Rebrew Sync (via ReVa MCP)
**One-line value:** Keep Rebrew's local C source the source of truth for
"what we know about this binary" while letting users edit names, types,
comments, and structures in Ghidra and re-converge with one command.

## Problem It Solves

Most reversers split their attention between a decompiler GUI (Ghidra) and
a text editor. Without sync:

- Symbol renames in Ghidra never reach the C source.
- Struct/typedef definitions live in two places and drift.
- Comments written in Ghidra's listing view are lost when revisiting.
- New function boundaries discovered in Ghidra don't show up in
  `rebrew todo`.
- Pushing rebrew's annotations back to Ghidra (so the analyst can browse
  with proper names) requires manual data entry.

PRD 07 ships `rebrew sync`, a single command for push + pull of names,
labels, structs, signatures, comments, and boundary corrections, talking
to a running Ghidra instance via the ReVa MCP server.

## Users

- **Solo reverser** flipping between Ghidra and source edits.
- **AI agent** (`rebrew-ghidra-sync` skill) running pull/push as part of
  the intake or matching workflow.
- **Team** sharing a Ghidra project alongside rebrew source.

## Goals

- Single command (`rebrew sync`) with explicit push, pull, and inspect
  modes.
- Safe defaults:
  - Generic names (`FUN_`, `DAT_`, `func_`, `switchdata`) are never
    overwritten.
  - Conflicts (both sides have meaningful names) are reported, not
    silently resolved.
  - Rebrew-authored plate comments are never pulled back into source as
    NOTE.
- Bulk operations for labels, sizes, new function creation, struct
  pushes, signature pushes, and data-label syncing.
- Offline fallback: if Ghidra is not reachable, rebrew uses cached
  `ghidra_functions.json` / `ghidra_data_labels.json` for read-only
  operations.
- Dry-run for every mode.

## Non-Goals

- Sync does not import Ghidra decompilation output (no auto-paste of
  pseudocode into source — that's `rebrew skeleton --decomp`).
- Sync does not depend on a specific Ghidra version beyond what ReVa
  supports; rebrew talks only via MCP HTTP.
- Sync does not edit Ghidra's `.gpr` directly — all writes go through
  ReVa.
- Sync does not version-control the Ghidra project; users are expected to
  commit `.gpr` (or rely on Ghidra Server) on their own.

## Functional Requirements

### Push (rebrew → Ghidra)

- `--push` exports + applies in one step (equivalent to `--export`
  followed by `--apply`).
- `--export` writes `ghidra_commands.json` only.
- `--apply` applies a pre-written `ghidra_commands.json`.
- `--summary` shows what would be pushed without writing.
- `--create-functions / --no-create-functions` (default on): create
  Ghidra functions for every annotated VA (IAT thunks are skipped).
- `--skip-generic / --no-skip-generic` (default on): never push generic
  `func_XXXXXXXX` labels.
- `--sync-sizes` pushes corrected function sizes (Ghidra expansion).
- `--sync-new-functions` creates functions found by r2 that Ghidra missed.
- `--sync-data / --no-sync-data` (default on): push `// DATA:` and
  `// GLOBAL:` labels + bookmarks.
- `--sync-structs / --no-sync-structs` (default on): push struct
  definitions to the `/rebrew` DTM category.
- `--sync-signatures / --no-sync-signatures` (default on): push function
  prototypes.

### Pull (Ghidra → rebrew)

- `--pull` updates local function names from Ghidra (with cross-ref
  rewrites).
- `--pull-signatures` updates externs from Ghidra prototypes.
- `--pull-structs` writes Ghidra struct definitions into `types.h`.
- `--pull-comments` imports Ghidra analysis comments as NOTE metadata.
- `--pull-data` imports data labels and (re)generates `rebrew_globals.h`.
- Conflict resolution:
  - Default: report and skip.
  - `--accept-ghidra` accepts Ghidra names with cross-ref updates.
  - `--accept-local` keeps the local name but records the Ghidra name in
    metadata (`GHIDRA: …`).
- `--module MSVCRT` restricts pull updates to one origin module.

### Cache & runtime

- `--refresh-cache` re-fetches the full Ghidra function list and writes
  `ghidra_functions.json`.
- `--endpoint URL` overrides the default ReVa MCP endpoint.
- `--dry-run` previews any push or pull mode.
- `--json` machine-readable output.

### BinSync export (`rebrew binsync-export`)

- Tangential to Ghidra sync but lives in the same export family.
- Writes a BinSync-compatible state directory
  (`functions/`, `global_vars.toml`).
- Rebrew-specific metadata (STATUS, CFLAGS) is preserved as comments.
- `--dry-run`, `--json`.

## User Stories / Workflows

### Story 1 — Onboarding push

1. After `rebrew catalog` + initial annotations, the user runs
   `rebrew sync --summary` and reviews the planned push.
2. `rebrew sync --push` creates Ghidra functions for every annotated VA,
   pushes structs and signatures, and labels every `// DATA:` /
   `// GLOBAL:` site.
3. Ghidra immediately shows meaningful names; further analysis is much
   faster.

### Story 2 — Pulling Ghidra renames

1. After a Ghidra analysis pass the user renamed 30 functions.
2. `rebrew sync --pull --dry-run` lists the proposed renames.
3. `rebrew sync --pull --accept-ghidra` rewrites local source files,
   updates cross-refs, and writes `GHIDRA: ...` notes where local names
   were preferred.

### Story 3 — Working offline

1. The user travels with no Ghidra running. `rebrew sync --summary`
   warns Ghidra is unreachable but falls back to the cached
   `ghidra_functions.json`.
2. The cache still seeds `rebrew todo` priorities and shows expected
   sizes.

### Story 4 — BinSync exchange with a teammate

1. A teammate uses BinSync. The lead runs
   `rebrew binsync-export ./binsync_state --dry-run` to preview, then
   without `--dry-run` to write.
2. The teammate consumes the state directory in their own decompiler;
   STATUS / CFLAGS metadata is preserved in comments.

## CLI Surface

```
rebrew sync [OPTIONS]
  Push
      --export
      --apply
      --push
      --summary
      --create-functions / --no-create-functions   (default on)
      --skip-generic / --no-skip-generic           (default on)
      --sync-sizes
      --sync-new-functions
      --sync-data / --no-sync-data                 (default on)
      --sync-structs / --no-sync-structs           (default on)
      --sync-signatures / --no-sync-signatures     (default on)
  Pull
      --pull
      --accept-ghidra
      --accept-local
      --module TEXT
      --pull-signatures
      --pull-structs
      --pull-comments
      --pull-data
  Runtime
      --refresh-cache
      --endpoint URL
      --dry-run
      --json
  -t, --target TEXT

rebrew binsync-export OUTDIR
      --dry-run
      --json
  -t, --target TEXT
```

## Success Metrics

- `rebrew sync --push --dry-run` followed by `--push` produces zero net
  diff on a second `--push` (idempotent).
- Generic names from Ghidra never overwrite meaningful local names.
- Pulled names from Ghidra always update every cross-reference in
  reversed source (no orphan references after `--pull --accept-ghidra`).
- Offline runs (Ghidra not reachable) degrade to read-only operations
  with a clear error rather than corrupting state.
- BinSync export round-trips through `binsync-cli` without losing
  STATUS/CFLAGS information.

## Open Questions / Known Limitations

- Sync requires ReVa MCP on Ghidra. There's no fallback to Ghidra's
  built-in scripting interface.
- The endpoint scheme differs between examples (the skill mentions
  port 8089; the `skeleton --xrefs --endpoint` default is 8080 with
  `/mcp/message`). Operators must pick the right URL for their ReVa
  install. (See gap report.)
- `rebrew sync` does not currently support pulling Ghidra *bookmarks*
  back into source; the push direction is one-way for bookmarks.
- `--pull-structs` writes into a single `types.h` file; multi-module
  separation of struct sources would require additional flags.
- BinSync export is one-directional (export only). Importing BinSync
  state back into rebrew annotations is not yet supported.
- Conflict reporting in `--pull` uses the same JSON schema for "Ghidra
  has X, local has Y" entries; tooling consumers should treat it as
  schema-versioned but it is not explicitly tagged with a version
  number.
