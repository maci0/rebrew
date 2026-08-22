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
- Offline fallback: if Ghidra is not reachable, `--pull` name/data-label sync
  falls back to the cached `function_structure.json` / `ghidra_data_labels.json`
  for read-only operations.
- Dry-run for every mode.

## Non-Goals

- Sync does not import Ghidra decompilation output (no auto-paste of
  pseudocode into source — that's `rebrew skeleton --decomp`).
- Sync does not depend on a specific Ghidra version beyond what ReVa (or the
  optional `ghidra-cli` bridge) supports; rebrew talks via ReVa MCP HTTP by
  default, or the `ghidra-cli` subprocess backend when `ghidra_backend = "cli"`
  is set in `rebrew-project.toml`.
- Sync does not edit Ghidra's `.gpr` directly — all writes go through
  ReVa (or the `ghidra-cli` bridge).
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

- `--pull` updates local function names from Ghidra (with cross-ref rewrites),
  plus data-label names and plate/pre comments (as NOTE).
- `--pull-signatures` updates `// PROTOTYPE:` annotations from Ghidra
  prototypes (extern replacement is off — Ghidra types may not be valid
  C89/MSVC6).
- `--pull-structs` writes Ghidra struct definitions into `types.h` (default).
  Use `--types-out PATH` to override the output path (single-file mode).
  Use `--by-module` to split output into per-module files (`types_server.h`,
  `types_client.h`, `types_shared.h` for unattributed structs).
  `--types-out` and `--by-module` are mutually exclusive.
- `--pull-datatypes` writes an enum/typedef inventory manifest into
  `enums_types.h` (names/sizes/categories only — ReVa MCP does not expose enum
  member values; `--types-out` also overrides this output path).
- `--pull-params` pulls Ghidra parameter names into unnamed parameters of local
  `.c` files (merge-safe: existing parameter names are never overwritten).
- `--pull-comments` imports Ghidra eol/pre/post analysis comments as
  `// ANALYSIS:` metadata annotations (reccmp-compatible).
- `--pull-data` imports data labels and (re)generates `rebrew_globals.h`.
- Conflict resolution:
  - Default: report and skip.
  - `--accept-ghidra` accepts Ghidra names with cross-ref updates.
  - `--accept-local` keeps the local name but records the Ghidra name in
    metadata (`GHIDRA: …`).
- `--module MSVCRT` restricts pull updates to one origin module.

### Cache & runtime

- `--refresh-cache` re-fetches the full Ghidra function list **and** the
  data-label list, writing both `function_structure.json` and
  `ghidra_data_labels.json` (data-label refresh now included).
- `--endpoint URL` overrides the default ReVa MCP endpoint
  (`http://localhost:8080/mcp/message`).
- `--force` re-exports already-applied operations (with `--export`/`--push`;
  idempotency state lives in `.rebrew/ghidra_sync_state.json`).
- `--watch` watches sources and re-pushes on every change (requires `--push`).
- `--dry-run` previews any push or pull mode.
- `--json` machine-readable output.

### BinSync exchange (`rebrew binsync-export` / `rebrew binsync-import`)

- Tangential to Ghidra sync but lives in the same export family.
- Writes a BinSync-compatible state directory
  (`functions/`, `global_vars.toml`).
- Rebrew-specific metadata (STATUS, CFLAGS) is preserved as comments.
- Import back into rebrew metadata is supported via
  `rebrew binsync-import STATE_DIR` (reads `functions/*.toml`,
  `global_vars.toml`, `structs/*.toml`; `--accept-binsync` / `--accept-local`
  resolve conflicts, `--create-missing` creates STUB files).
- `--dry-run`, `--json`, `--module`, `--git`, `--clean`.

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
3. `rebrew sync --pull --accept-ghidra` rewrites local source files and
   updates cross-refs (conflicts resolve in Ghidra's favor); with
   `--accept-local` instead, `GHIDRA: ...` notes record Ghidra names where
   local names were kept.

### Story 3 — Working offline

1. The user travels with no Ghidra running. `rebrew sync --pull` warns
   that ReVa MCP is unreachable and falls back to the cached
   `function_structure.json` / `ghidra_data_labels.json` for read-only
   name/data-label sync (comments and the other pull modes need a live
   connection).
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
      --pull-datatypes
      --pull-params
      --types-out PATH
      --by-module
      --pull-comments
      --pull-data
  Runtime
      --refresh-cache
      --endpoint URL   (default http://localhost:8080/mcp/message)
      --force
      --watch
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

- Sync requires ReVa MCP on Ghidra by default; an alternative `ghidra-cli`
  bridge backend (`ghidra_backend = "cli"` in `rebrew-project.toml`) covers
  the push/apply direction via subprocess, but pull beyond the rename path
  still expects ReVa.
- The MCP endpoint default is `http://localhost:8080/mcp/message` everywhere
  (code, skills, examples) — the earlier 8080-vs-8089 disagreement is
  resolved. Override with `--endpoint`.
- Offline fallback is partial: only `--pull` name/data-label sync reads the
  local caches; `--pull-signatures` / `--pull-structs` / `--pull-datatypes` /
  `--pull-params` / `--pull-comments` / `--pull-data` require a live MCP
  connection, and pulled comments are not cached.
- `rebrew sync` does not currently support pulling Ghidra *bookmarks*
  back into source; the push direction is one-way for bookmarks.
- `--pull-structs --by-module` splits structs into per-module files; structs
  with no namespace/category in Ghidra land in `types_shared.h`.
- BinSync import is now supported via `rebrew binsync-import STATE_DIR`
  (export-only limitation lifted); export and import remain separate commands.
- Conflict reporting in `--pull` uses the same JSON schema for "Ghidra
  has X, local has Y" entries; tooling consumers should treat it as
  schema-versioned but it is not explicitly tagged with a version
  number.
