---
name: rebrew-ghidra-sync
description: Synchronizes annotations, labels, structs, and comments between local rebrew C files and Ghidra. Field-level sync (names, comments, prototypes, structs, globals) is BinSync-primary via the shared state dir; ReVa MCP remains only for the structural ops BinSync cannot express (function creation, bookmarks, data pulls). Use this skill when syncing with Ghidra, pushing labels, pulling renames, exporting structs, importing comments, or any interaction between rebrew and Ghidra. Triggers on 'Ghidra', 'sync', 'push', 'pull', 'binsync', 'state-dir', 'ReVa', 'MCP', 'create-functions', 'bookmarks', or 'pull-data'.
license: MIT
---

```mermaid
graph TD
    Doctor{Doctor passes?<br/>rebrew doctor} -->|fail| Fix[Fix health check<br/>per doctor report]
    Fix --> Doctor
    Doctor -->|pass| Push[Push to state dir<br/>rebrew sync --push --state-dir D]
    Push --> Plugin[BinSync Ghidra plugin<br/>relays state -> Ghidra]
    Plugin --> Pull[Pull from state dir<br/>rebrew sync --pull --state-dir D]
    Pull -->|new functions| Chain[Create in Ghidra<br/>--pull --create-functions]
    Pull -->|conflict| Resolve{Resolve conflicts?<br/>--accept-binsync / --accept-local}
    Resolve --> Pull
    Pull -->|structural ops| Mcp[rebrew sync --create-functions<br/>--bookmarks / --pull-data]
```

# Rebrew Ghidra Sync

Synchronize annotations and symbols between rebrew source files and Ghidra.
**Field-level sync is BinSync-primary** (metadata-review R1): rebrew exports
and imports the shared BinSync state dir; the BinSync Ghidra plugin (or a
collaborator's tool) relays the state to and from Ghidra.  ReVa MCP remains
only for the structural ops the state dir cannot express: function creation,
bookmarks, and live data pulls.

## When NOT to use this skill

- Editing C source / running tests / picking functions → use `rebrew-workflow`
- Updating local `// GLOBAL:` / `// DATA:` annotations without Ghidra → use `rebrew-data-analysis`
- Onboarding a brand-new binary → use `rebrew-intake` first (Ghidra sync is the last step)

## 1. Configuration & Health Check

Run `rebrew doctor` first — it includes a "Ghidra sync" check. Fix anything it flags before syncing.

Config lives in `rebrew-project.toml` under `[targets.<name>]`:

- `ghidra_program_path` — must match the program open in Ghidra for the MCP structural ops; a mismatch prints a yellow warning.
- MCP endpoint — default `http://localhost:8080/mcp/message`, override per run with `--endpoint URL`.

The BinSync state dir is a git-versioned directory (`functions/*.toml`,
`global_vars.toml`, `structs/*.toml`) shared with collaborators and the
BinSync Ghidra plugin.  Point `--state-dir` at it; the plugin on the Ghidra
side watches/commits the same dir.

## 2. Sync Commands

### BinSync field sync (names, comments/notes, prototypes, structs, globals)

```bash
rebrew sync --push --state-dir D                 # export annotations -> state dir
rebrew sync --summary --state-dir D              # preview the push (no writes)
rebrew sync --pull --state-dir D --dry-run       # preview the import first
rebrew sync --pull --state-dir D                 # import state -> renames, // PROTOTYPE:, notes, globals, structs
rebrew sync --pull --state-dir D --create-functions   # import, then create the imported VAs in Ghidra (MCP)
rebrew sync --pull --state-dir D --accept-binsync      # accept BinSync names on conflicts
rebrew sync --pull --state-dir D --accept-local        # keep local names (records provenance)
rebrew sync --pull --state-dir D --create-missing      # STUB files for functions not in the catalog
rebrew sync --push --state-dir D --watch               # re-export on every source change
```

Notes:
- `--push`/`--pull` require `--state-dir`; they are mutually exclusive.
- The exported TOMLs are **write-locked (0444)** — rebrew chmods, writes, and
  re-locks; a collaborator's tool chmods writable first.  STATUS is NOT in the
  state (it is verify-earned in `rebrew-functions.toml`).
- **`--pull --create-functions` is the chain**: functions imported from the
  state dir are created in Ghidra via MCP, so "add a function to the state →
  it appears in Ghidra" needs no external plugin.

### MCP structural ops (Ghidra must be up + ReVa reachable)

```bash
rebrew sync --create-functions                   # create functions for list-only entries in Ghidra
rebrew sync --bookmarks                          # status bookmarks (rebrew/exact|reloc|matching|stub)
rebrew sync --pull-data                          # Ghidra data labels -> rebrew_globals.h
```

## 3. Where Results Land

- `functions/*.toml`, `global_vars.toml`, `structs/*.toml` — the BinSync state dir (`--state-dir`)
- `rebrew-functions.toml` — per-function STATUS/NOTE/GHIDRA metadata (`cfg.metadata_dir`; STATUS is verify-earned, 0444-locked)
- `rebrew-data.toml` — DATA/GLOBAL `name`/`note` metadata (`cfg.metadata_dir`)
- `rebrew_globals.h` — pulled data header (`cfg.reversed_dir`, from `--pull-data`)
- `.c` files — renames (pull) and `// PROTOTYPE:` annotations

## 4. What Gets Synced

**Push -> state dir:** BinSync-native fields only — function name, addr, size,
prototype, notes; globals (`global_vars.toml`); structs (`structs/*.toml`).
STATUS/CFLAGS stay in `rebrew-functions.toml` (STATUS is verify-earned).

**Pull <- state dir:** names (renames the `.c` file, rewrites extern
cross-references), prototypes (`// PROTOTYPE:`), notes, global names, structs;
`--create-missing` materializes STUB files.  Conflicts are reported and
skipped until resolved with `--accept-binsync` / `--accept-local`.

**MCP structural:** function creation (`--create-functions`, standalone or
chained after `--pull`), status bookmarks (`--bookmarks`), data labels
(`--pull-data`).

## 5. Safety Guarantees

- **STATUS is never synced** — it is verify-earned via `rebrew verify`, not
  imported from shared state; a hand-claimed PROVEN is demoted with a
  `metadata: warning`.
- **Metadata write-lock** — the state TOMLs and rebrew's metadata are 0444;
  direct edits fail with Permission denied, the CLI chmods/updates/re-locks.
- **No accidental overwrites** — generic names are never pulled; meaningful
  local vs BinSync name conflicts are reported and skipped until resolved.
- **Dry-run support** — `--dry-run` previews push or pull before applying.

### Common failure modes & fixes

- **"No action specified"** — pass at least one of `--push`, `--pull`,
  `--create-functions`, `--bookmarks`, `--pull-data`, `--summary`.
- **"--push/--pull require --state-dir"** — field sync goes through the
  BinSync state dir; pass `--state-dir <dir>`.
- **MCP unreachable for a structural op** — verify Ghidra + ReVa are running
  and the endpoint is right; field sync (state dir) works without MCP.
- **`--pull --create-functions` with Ghidra down** — the import succeeds; the
  create step errors ("MCP unreachable").  Re-run `rebrew sync
  --create-functions` once Ghidra is up.
- **New function in the state not in Ghidra** — either the BinSync Ghidra
  plugin is watching the dir, or run `rebrew sync --pull --state-dir D
  --create-functions`.

## 6. Typical Round-Trip

```bash
rebrew doctor                                   # 0. config/backend sanity
rebrew sync --pull --state-dir D --dry-run      # 1. preview incoming state changes
rebrew sync --pull --state-dir D --json         # 2. apply; inspect updated / conflicts
rebrew sync --pull --state-dir D --create-functions   # 3. create new functions in Ghidra
rebrew sync --summary --state-dir D             # 4. preview outgoing changes
rebrew sync --push --state-dir D                # 5. export annotations to the state dir
# 6. the BinSync Ghidra plugin (or a collaborator) relays the state into Ghidra
```
