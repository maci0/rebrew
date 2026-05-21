---
name: rebrew-ghidra-sync
description: Synchronizes annotations, labels, structs, and comments between local rebrew C files and a running Ghidra instance via ReVa MCP. Covers push (export to Ghidra) and pull (import from Ghidra) operations with safety guarantees. Use this skill when syncing with Ghidra, pushing labels, pulling renames, exporting structs, importing comments, or any interaction between rebrew and Ghidra. Triggers on 'Ghidra', 'sync', 'push', 'pull', 'ReVa', 'MCP', 'labels', 'pull-signatures', 'pull-structs', 'pull-comments', or 'pull-data'.
license: MIT
---

# Rebrew Ghidra Sync

Synchronize annotations and symbols between rebrew source files and a running Ghidra instance via ReVa MCP.

## When NOT to use this skill

- Editing C source / running tests / picking functions → use `rebrew-workflow`
- Updating local `// GLOBAL:` / `// DATA:` annotations without Ghidra → use `rebrew-data-analysis`
- Onboarding a brand-new binary → use `rebrew-intake` first (Ghidra sync is the last step)

## 1. Program Path Validation

Before sync operations, confirm Ghidra target selection in project config:

- Ensure `ghidra_program_path` is set for the active target in `rebrew-project.toml`
- Ensure the same program is open in Ghidra via ReVa MCP
- Default endpoint: `http://localhost:8080/mcp/message`. Override with `--endpoint URL`.

If `ghidra_program_path` is missing or mismatched, fix config before running pull/push.

## 2. Sync Commands

### Preview / inspect

```bash
rebrew sync --summary --json            # preview what would be synced
rebrew sync --refresh-cache             # re-fetch ghidra_functions.json from MCP (no writes)
```

### Push (rebrew → Ghidra)

```bash
rebrew sync --push                              # combined export + apply
rebrew sync --push --dry-run                    # preview without applying
rebrew sync --export                            # write ghidra_commands.json only
rebrew sync --apply                             # apply a previously-written ghidra_commands.json
rebrew sync --push --no-sync-data               # skip pushing // DATA: labels
rebrew sync --push --no-sync-structs            # skip pushing local structs to Ghidra DTM
rebrew sync --push --no-sync-signatures         # skip pushing C function prototypes
rebrew sync --push --sync-sizes                 # also push corrected function sizes
rebrew sync --push --sync-new-functions         # create new Ghidra functions for local-only entries
rebrew sync --push --no-create-functions        # don't auto-create missing Ghidra functions
rebrew sync --push --no-skip-generic            # also push generic auto-names (rarely wanted)
```

### Pull (Ghidra → rebrew)

```bash
rebrew sync --pull                              # function renames + plate/pre comments
rebrew sync --pull --dry-run                    # preview without writing
rebrew sync --pull --accept-ghidra              # accept all Ghidra names + rewrite cross-refs
rebrew sync --pull --accept-local               # keep local names, record GHIDRA in metadata
rebrew sync --pull --module MSVCRT              # restrict to one origin module
rebrew sync --pull-signatures                   # update extern prototypes from Ghidra decomp
rebrew sync --pull-structs                      # export Ghidra structs into types.h
rebrew sync --pull-structs --types-out PATH     # write to a custom path instead of types.h
rebrew sync --pull-structs --by-module          # split into types_<module>.h / types_shared.h
rebrew sync --pull-comments                     # write Ghidra EOL/post comments as // ANALYSIS:
rebrew sync --pull-data                         # generate rebrew_globals.h from Ghidra data labels
```

## 3. What Gets Synced

**Push -> Ghidra:**
- Function labels (skips generic `func_XXXXXXXX` names)
- Plate comments with `[rebrew]` metadata (status, origin, size, cflags)
- Pre-comments from NOTE metadata (rebrew-function.toml)
- Bookmarks by status category (`rebrew/exact`, `rebrew/reloc`, etc.)
- Struct definitions -> Ghidra Data Type Manager under `/rebrew` category
- Function prototypes (parsed from local C files)
- DATA/GLOBAL labels and bookmarks (`rebrew/data` category)

**Pull <- Ghidra:**
- Function renames (updates function name in C definition and handles `extern` cross-references with `--accept-ghidra`)
- Function prototypes (`--pull-signatures` updates the C function definition and `extern` usage across codebase)
- Structs (`--pull-structs` writes `types.h`; `--by-module` splits into per-module files; `--types-out PATH` overrides the output path)
- Comments (`--pull-comments` writes EOL/post comments as `// ANALYSIS:`)
- **Data label names** → written to `rebrew-data.toml` metadata file as `name` field (not inline in `.c`)
- Plate and pre-comments for functions (updates NOTE in rebrew-function.toml)
- **Data label comments** → written to `rebrew-data.toml` metadata file as `note` field (not inline in `.c`)
- Data labels (`--pull-data` fetches Ghidra data labels via MCP and generates `rebrew_globals.h` with typed extern declarations grouped by PE section)

## 4. Safety Guarantees

- **No accidental overwrites**: Generic auto-names (`FUN_`, `DAT_`, `func_`, `switchdata`) are never pulled
- **Conflict detection**: When both local and Ghidra have meaningful (non-generic) names that differ, pull reports a CONFLICT and skips rename — resolve with `--accept-ghidra` or `--accept-local`
- **`[rebrew]` comments filtered**: Auto-generated plate comments are not pulled back
- **Dry-run support**: Use `--dry-run` to preview changes before applying
- **Idempotent behavior**: Re-running sync is safe and produces stable results
- **Offline fallback**: Pull operations fall back to cached `ghidra_functions.json` / `ghidra_data_labels.json` if the MCP endpoint is unreachable. Run `--refresh-cache` while Ghidra is up to refresh.

## 5. Typical Round-Trip

```bash
rebrew sync --pull --dry-run          # 1. preview incoming Ghidra changes
rebrew sync --pull                    # 2. apply Ghidra renames + comments locally
rebrew sync --summary                 # 3. preview outgoing changes to Ghidra
rebrew sync --push                    # 4. push annotations to Ghidra
```
