---
name: rebrew-ghidra-sync
description: Synchronizes annotations, labels, structs, and comments between local rebrew C files and a running Ghidra instance via ReVa MCP. Covers push (export to Ghidra) and pull (import from Ghidra) operations with safety guarantees. Use this skill when syncing with Ghidra, pushing labels, pulling renames, exporting structs, importing comments, or any interaction between rebrew and Ghidra. Triggers on 'Ghidra', 'sync', 'push', 'pull', 'ReVa', 'MCP', 'labels', 'pull-signatures', 'pull-structs', 'pull-comments', or 'pull-data'.
license: MIT
---

# Rebrew Ghidra Sync

Synchronize annotations and symbols between rebrew source files and a running Ghidra instance via ReVa MCP (default backend) or the ghidra-cli binary backend.

## When NOT to use this skill

- Editing C source / running tests / picking functions → use `rebrew-workflow`
- Updating local `// GLOBAL:` / `// DATA:` annotations without Ghidra → use `rebrew-data-analysis`
- Onboarding a brand-new binary → use `rebrew-intake` first (Ghidra sync is the last step)

## 1. Configuration & Health Check

Run `rebrew doctor` first — it includes a "Ghidra sync" check that reports backend, `ghidra_program_path`, and (for the cli backend) whether a `ghidra-cli` binary exists. Fix anything it flags before syncing.

Config lives in `rebrew-project.toml` under `[targets.<name>]`:

- `ghidra_program_path` — must match the program open in Ghidra. If missing, sync falls back to the derived `/<binary_name>`; a mismatch prints a yellow warning (`Ghidra has 'X' open, but rebrew derived 'Y'`) — copy the shown path into config.
- `ghidra_backend` — `"reva"` (default; ReVa MCP over HTTP) or `"cli"` (ghidra-cli binary found on PATH or at `tools/ghidra-cli`). A typo falls back to `"reva"` with a warning.
- MCP endpoint — default `http://localhost:8080/mcp/message`, override per run with `--endpoint URL`.

Backend coverage:
- **`reva`**: all push and all pull operations.
- **`cli`**: push/apply (labels, comments, bookmarks, structs, prototypes) and the main `--pull` fetch. The specialized `--pull-signatures`, `--pull-structs`, `--pull-datatypes`, `--pull-comments`, `--pull-data` still talk to ReVa MCP.

## 2. Sync Commands

### Preview / inspect

```bash
rebrew doctor                            # health check incl. "Ghidra sync" check
rebrew sync --summary                    # offline; counts what --push would export
rebrew sync --summary --json             # JSON: entries, unique_vas, by_module, operations{...}
rebrew sync --refresh-cache --dry-run    # preview cache refresh (no writes)
rebrew sync --refresh-cache              # re-fetch function_structure.json + ghidra_data_labels.json (needs MCP up)
```

`--summary` is fully offline (scans local sources + metadata only; no MCP probe). In JSON mode it prints `{"entries", "unique_vas", "by_module", "operations": {"create_function", "create_label", "set_comment", "set_bookmark", "parse_c_structure", "set_function_prototype", "total"}}` to stdout — parse `operations.total` to size the push.

### Push (rebrew → Ghidra)

```bash
rebrew sync --push                              # export ghidra_commands.json + apply via backend
rebrew sync --push --dry-run                    # export ops file; skip applying
rebrew sync --export                            # write ghidra_commands.json only (works offline)
rebrew sync --apply                             # apply a previously-written ghidra_commands.json
rebrew sync --push --no-sync-data               # skip pushing // DATA: / // GLOBAL: labels
rebrew sync --push --no-sync-structs            # skip pushing local structs to Ghidra DTM
rebrew sync --push --no-sync-signatures         # skip pushing C function prototypes
rebrew sync --push --sync-sizes                 # also push corrected function sizes (expand boundaries)
rebrew sync --push --sync-new-functions         # create Ghidra functions for local-only entries
rebrew sync --push --no-create-functions        # don't auto-create missing Ghidra functions
rebrew sync --push --no-skip-generic            # also push generic auto-names (rarely wanted)
rebrew sync --push --force                      # re-export ops already recorded as applied
rebrew sync --push --watch                      # watch sources + metadata, re-push on every change
```

Notes:
- `--push` = `--export` + `--apply`. `--push --dry-run` still writes `ghidra_commands.json`; only the apply step is skipped.
- Apply progress goes to stderr (`Applying N operations ... Applied OK/TOTAL operations successfully`). If any operations fail, the command exits non-zero (code 1) — the export file is still valid, so fix the connection and re-run `--apply`.
- `--sync-sizes` / `--sync-new-functions` write `ghidra_size_commands.json`; pair them with `--push` to apply.
- `--watch` re-pushes incrementally on file changes (dedup makes each re-push cheap); requires `--push`.

### Pull (Ghidra → rebrew)

```bash
rebrew sync --pull --dry-run                 # preview without writing (run this first)
rebrew sync --pull                           # function renames + plate/pre comments -> NOTE
rebrew sync --pull --json                    # structured: updated / skipped / conflicts / changes[]
rebrew sync --pull --accept-ghidra           # accept all Ghidra names; renames the .c file + rewrites extern cross-refs
rebrew sync --pull --accept-local            # keep local names, record GHIDRA in metadata
rebrew sync --pull --module MSVCRT           # restrict name updates to one origin module
rebrew sync --pull-signatures                # write // PROTOTYPE: annotations from Ghidra decomp
rebrew sync --pull-structs                   # export Ghidra structs into types.h
rebrew sync --pull-structs --types-out PATH  # single-file output to a custom path (not types.h)
rebrew sync --pull-structs --by-module       # split into types_<module>.h / types_shared.h
rebrew sync --pull-datatypes                 # enum/typedef inventory manifest -> enums_types.h
rebrew sync --pull-comments                  # Ghidra EOL/pre/post comments -> ANALYSIS metadata
rebrew sync --pull-data                      # Ghidra data labels -> rebrew_globals.h
```

Notes:
- `--types-out` and `--by-module` are mutually exclusive (error, exit non-zero).
- `--pull` with `--json` prints `{"updated", "skipped", "conflicts", "changes": [{"va", "field", "local", "ghidra", "file", "action", "reason?"}]}` to stdout. `action: "conflict"` entries need a decision — re-run with `--accept-ghidra` or `--accept-local`, or resolve the function manually.
- `--pull` reports conflicts but continues and does NOT fail the command.
- Metadata-owned results (NOTE/ANALYSIS/GHIDRA in `rebrew-function.toml`, DATA/GLOBAL `name`/`note` in `rebrew-data.toml`) are written under the metadata dir — never inline in `.c` files.

## 3. Where Results Land

- `ghidra_commands.json` — sync ops (project root, `cfg.root`)
- `ghidra_size_commands.json` — size/new-function ops (project root)
- `function_structure.json`, `ghidra_data_labels.json` — MCP caches refreshed by `--refresh-cache` (`cfg.reversed_dir`)
- `types.h` / `types_<module>.h` / `enums_types.h` / `rebrew_globals.h` — pulled headers (`cfg.reversed_dir`)
- `rebrew-function.toml` — per-function STATUS/NOTE/GHIDRA/ANALYSIS metadata (`cfg.metadata_dir`)
- `rebrew-data.toml` — DATA/GLOBAL `name`/`note` metadata (`cfg.metadata_dir`)
- `.rebrew/ghidra_sync_state.json` — push idempotency state (project root)

## 4. What Gets Synced

**Push -> Ghidra:**
- Function labels (skips generic `func_XXXXXXXX` unless `--no-skip-generic`)
- Plate comments with `[rebrew]` metadata (marker type, status, module, size, cflags, symbol, files)
- Pre-comments from NOTE metadata (rebrew-function.toml)
- Bookmarks by status category (`rebrew/exact`, `rebrew/reloc`, `rebrew/matching`, `rebrew/stub`)
- Struct definitions -> Ghidra Data Type Manager under `/rebrew` (typedefs pushed before structs so CParser resolves them)
- Function prototypes (parsed from local C files; `set-function-prototype` runs before labels to avoid duplicate-name errors)
- DATA/GLOBAL labels and bookmarks (`rebrew/data` category)
- `--sync-sizes` boundary expansions, `--sync-new-functions` creations

**Pull <- Ghidra:**
- Function renames (updates the function name, renames the `.c` file; `--accept-ghidra` also rewrites `extern` cross-references across the codebase)
- Data label names -> `rebrew-data.toml` `name` field (not inline)
- Plate + pre comments -> NOTE in `rebrew-function.toml` (not inline)
- Data label comments -> `rebrew-data.toml` `note` field
- `--pull-signatures` -> inline `// PROTOTYPE:` annotations on the function. It does NOT rewrite `extern` declarations — Ghidra types (`uint`, `byte`) are not valid C89/MSVC6, so treat the annotation as a hint and hand-clean it.
- `--pull-structs` -> `types.h` (or per-module files with `--by-module`)
- `--pull-datatypes` -> `enums_types.h` manifest (name/size/category only — ReVa MCP does not expose enum member values; define enums in source and `--push` them into Ghidra)
- `--pull-comments` -> ANALYSIS in `rebrew-function.toml`; only comments falling inside a known function's `[va, va+size)` range are pulled
- `--pull-data` -> `rebrew_globals.h` with typed extern declarations grouped by `.data` / `.rdata` / `.bss`

## 5. Safety Guarantees

- **No accidental overwrites**: Generic auto-names (`FUN_`, `DAT_`, `func_`, `switchdata`, `thunk_`) are never pulled; push skips generic labels by default
- **Conflict detection**: When both local and Ghidra have meaningful (non-generic) names that differ, pull reports a CONFLICT and skips the rename — resolve with `--accept-ghidra` or `--accept-local`
- **`[rebrew]` comments filtered**: Auto-generated plate comments are never pulled back
- **Dry-run support**: Use `--dry-run` to preview push or pull before applying
- **Idempotent behavior**: Applied ops are recorded in `.rebrew/ghidra_sync_state.json` and skipped on the next export; use `--force` to re-push everything. Re-running sync is safe and stable.
- **Offline fallback**: Pull operations fall back to cached `function_structure.json` / `ghidra_data_labels.json` if the MCP endpoint is unreachable. Run `--refresh-cache` while Ghidra is up to refresh.

### Common failure modes & fixes

- **"No action specified"** — sync requires at least one action flag (`--summary`, `--export`, `--apply`, `--push`, `--pull`, `--pull-*`, `--refresh-cache`)
- **Program-path mismatch warning** — set `ghidra_program_path = "<path shown>"` in `[targets.X]`
- **Pull silently used stale cache** (yellow "falling back to local caches") — the endpoint was unreachable; verify Ghidra + ReVa are running, then `rebrew sync --refresh-cache`
- **`--push` with Ghidra down** — `ghidra_commands.json` is still exported but apply fails with exit code 1 ("N operations failed"); fix the connection and `rebrew sync --apply`
- **`--pull-comments` pulled nothing** — comments outside every known `[va, va+size)` range are dropped; pull a fresh `function_structure.json` first
- **`--types-out` + `--by-module` together** — mutually exclusive, exits non-zero
- **`--watch` without `--push`** — exits non-zero; `--watch` requires `--push`

## 6. Typical Round-Trip

```bash
rebrew doctor                                   # 0. config/backend sanity
rebrew sync --refresh-cache                     # 1. (Ghidra up) refresh function_structure.json + data labels
rebrew sync --pull --dry-run                    # 2. preview incoming Ghidra changes
rebrew sync --pull --json                       # 3. apply; inspect updated / conflicts from JSON
rebrew sync --summary                           # 4. preview outgoing changes to Ghidra
rebrew sync --push                              # 5. push annotations to Ghidra
```
