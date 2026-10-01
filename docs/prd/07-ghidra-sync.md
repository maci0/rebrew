# PRD 07: Ghidra Sync

- **Status**: Shipped (BinSync-primary field sync + ReVa MCP structural ops)
- **Date**: 2026-05 (updated 2026-09)
- **Owner**: rebrew team

> **Architecture note (2026-09):** `rebrew sync` is BinSync-primary; field sync
> (names, comments, prototypes, structs, globals) flows through a shared state
> dir (`--push`/`--pull --state-dir`, conflicts via `--accept-binsync` /
> `--accept-local`); ReVa MCP is used for structural ops
> (`--create-functions`, `--bookmarks`, `--pull-data`).

**Feature name:** Bidirectional Ghidra ↔ Rebrew Sync (BinSync state dir + ReVa MCP structural ops)
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
labels, structs, prototypes, comments, and boundary corrections, using a
BinSync state directory for field-level sync and the ReVa MCP server
(or `ghidra-cli` bridge) for structural operations in Ghidra.

## Users

- **Solo reverser** flipping between Ghidra and source edits.
- **AI agent** (`rebrew-ghidra-sync` skill) running pull/push as part of
  the intake or matching workflow.
- **Team** sharing a Ghidra project alongside rebrew source.

## Goals

- Single command (`rebrew sync`) with explicit push, pull, and inspect
  modes.
- Safe defaults:
  - Generic names (`FUN_`, `DAT_`, `func_`, `switchdata`, `thunk_`, `g_<hex>`)
    are never overwritten.
  - Concurrent field edits are reported as conflicts; a shared baseline lets
    remote-only edits apply automatically.
  - Tagged notes/GHIDRA comments map to their owned metadata fields; ordinary
    instruction comments remain distinct.
- Bulk operations for labels, sizes, new function creation, struct
  pushes, signature pushes, and data-label syncing.
- Offline field sync: `--push`/`--pull` read and write only the BinSync state
  dir (`--state-dir`, required), so they work with Ghidra not running; only
  the MCP structural ops need a live connection.
- Dry-run for every mode.

## Non-Goals

- Sync does not import Ghidra decompilation output (no auto-paste of
  pseudocode into source; that's `rebrew skeleton --decomp`).
- Sync does not depend on a specific Ghidra version beyond what ReVa (or the
  optional `ghidra-cli` bridge) supports; rebrew talks via ReVa MCP HTTP by
  default, or the `ghidra-cli` subprocess backend when `ghidra_backend = "cli"`
  is set in `rebrew-project.toml`.
- Sync does not edit Ghidra's `.gpr` directly: all writes go through
  ReVa (or the `ghidra-cli` bridge).
- Sync does not version-control the Ghidra project; users are expected to
  commit `.gpr` (or rely on Ghidra Server) on their own.

## Functional Requirements

### Field sync (BinSync state dir)

- `--push` exports local annotations (names, comments/notes, prototypes,
  structs, globals) to the BinSync state directory (`--state-dir PATH`, or
  configured `binsync_state_dir`).
- `--pull` imports the BinSync state directory into rebrew's C sources and
  metadata.
- `--summary` shows what would be pushed without writing to the state directory.
- `--watch` watches sources/headers, metadata, config, binary, and remote state
  (requires `--push --state-dir`).
- Conflict resolution on pull:
  - Default: report conflict and skip.
  - `--accept-binsync`: accept remote field values on pull conflicts, rewriting local
    sources and updating cross-references.
  - `--accept-local`: keep local field values on pull conflicts; retain alternate
    function names as GHIDRA.
- `--create-missing`: creates STUB files for catalog-known BinSync functions
  without a local annotation.

### Structural operations (ReVa MCP)

- `--create-functions`: creates Ghidra functions for every listed VA Ghidra has
  not already detected (IAT thunks and entries with no canonical size are
  skipped); when chained with `--pull`, creates the imported VAs in Ghidra.
- `--bookmarks`: sets status bookmarks in Ghidra via ReVa MCP.
- `--pull-data`: pulls data labels from Ghidra and generates `rebrew_globals.h`.
- Transport fallback: ReVa MCP HTTP is the default transport; when
  `ghidra_backend = "cli"` is configured in `rebrew-project.toml`, the
  `ghidra-cli` binary backend applies the same push-direction structural
  operations (`--create-functions`, `--bookmarks`) without contacting MCP at
  all. A transport that dies after the MCP probe but before any op landed also
  falls back to `ghidra-cli`; an MCP that is down at the probe is refused up
  front. Only the apply/push direction is bridged: `--pull-data` is
  ReVa MCP-only and has no `ghidra-cli` fallback.

### Runtime and common options

- `--endpoint URL`: overrides the default ReVa MCP endpoint
  (`http://localhost:8080/mcp/message`).
- `--dry-run`: previews any push, pull, or structural operations without
  modifying files or Ghidra.
- `--json`: outputs machine-readable JSON results.
- `-t, --target`: selects target from `rebrew-project.toml`.

### Peer BinSync commands

- `rebrew binsync-export`, `rebrew binsync-import`, `rebrew binsync-diff`,
  `rebrew binsync-init`, `rebrew binsync-overlay` and the `rebrew binsync`
  umbrella command (`push`, `pull`, `summary`, `init`, `diff`, `overlay`)
  share the same underlying state directory format (see PRD 09).

## User Stories / Workflows

### Story 1: Onboarding push

1. After `rebrew catalog` + initial annotations, the user runs
   `rebrew sync --summary --state-dir ./state` and reviews the planned push.
2. `rebrew sync --push --state-dir ./state` exports names/comments/prototypes/
   structs/globals into the BinSync state dir;
   `rebrew sync --create-functions --bookmarks` applies both sets of structural
   ops via ReVa MCP in one run (a `--dry-run` on the same flags previews both
   sets together).
3. Ghidra (via BinSync + MCP) shows meaningful names; further analysis is much
   faster.

### Story 2: Pulling Ghidra renames

1. After a Ghidra analysis pass the user renamed 30 functions (state dir updated).
2. `rebrew sync --pull --state-dir ./state --dry-run` lists the proposed renames.
3. `rebrew sync --pull --state-dir ./state --accept-binsync` rewrites local source files and
   updates cross-refs (conflicts resolve in BinSync's favor); with
   `--accept-local` instead, provenance notes record BinSync names where
   local names were kept.

### Story 3: Working offline

1. The user travels with no Ghidra running. `rebrew sync --pull --state-dir
   ./state` imports names, comments, prototypes, structs and globals from the
   BinSync state dir; no MCP connection is involved.
2. `--create-functions`, `--bookmarks` and `--pull-data` fail with an
   `MCP unreachable at <endpoint>` error when ReVa MCP is down; re-run once
   it is back.

### Story 4: BinSync exchange with a teammate

1. A teammate uses BinSync. The lead runs
   `rebrew binsync-export ./binsync_state --dry-run` to preview, then
   without `--dry-run` to write.
2. The teammate consumes the state directory in their own decompiler;
   STATUS / CFLAGS stay local in `rebrew-functions.toml`.

## CLI Surface

```
rebrew sync [OPTIONS]
  Field sync (BinSync state dir)
      --state-dir PATH
      --push
      --pull
      --summary
      --watch
      --accept-binsync
      --accept-local
      --create-missing
  Structural (ReVa MCP)
      --create-functions
      --bookmarks
      --pull-data
  Runtime
      --endpoint URL   (default http://localhost:8080/mcp/message)
      --dry-run
      --json
  -t, --target TEXT

rebrew binsync-export OUTDIR
      --module TEXT
      --git
      --clean
      --dry-run
      --json
  -t, --target TEXT

rebrew binsync-import STATE_DIR
      --module TEXT
      --accept-binsync
      --accept-local
      --create-missing
      --dry-run
      --json
  -t, --target TEXT

rebrew binsync {init,diff,overlay,push,pull,summary}
```

## Success Metrics

- `rebrew sync --push --state-dir D --dry-run` followed by `--push --state-dir D`
  produces zero net diff on a second `--push` (idempotent).
- Generic names from Ghidra never overwrite meaningful local names.
- Pulled names from the BinSync state always update every cross-reference in
  reversed source (no orphan references after `--pull --state-dir D --accept-binsync`).
- Offline field sync applies local state-directory changes without Ghidra;
  structural operations require their configured live backend.
- BinSync export round-trips without losing the exported BinSync fields.

## Open Questions / Known Limitations

- Field sync (`--push`/`--pull --state-dir`) uses the BinSync state directory
  and works offline without Ghidra running. Structural operations
  (`--create-functions`, `--bookmarks`, `--pull-data`) require a live ReVa MCP
  connection. `--create-functions` and `--bookmarks` additionally run on the
  `ghidra-cli` bridge backend when `ghidra_backend = "cli"` is configured;
  `--pull-data` is ReVa MCP-only.
- The MCP endpoint default is `http://localhost:8080/mcp/message` everywhere
  (code, skills, examples). Override with `--endpoint`.
- `rebrew sync` does not currently support pulling Ghidra *bookmarks*
  back into source; the push direction is one-way for bookmarks.
- Conflict reporting in `--pull` uses the same JSON schema for "Ghidra/BinSync
  has X, local has Y" entries; tooling consumers should treat it as
  schema-versioned.
