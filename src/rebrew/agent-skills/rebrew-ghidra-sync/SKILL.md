---
name: rebrew-ghidra-sync
description: Synchronizes annotations, labels, structs, and comments between local rebrew C files and a running Ghidra instance via ReVa MCP. Covers push (export to Ghidra) and pull (import from Ghidra) operations with safety guarantees. Use this skill when syncing with Ghidra, pushing labels, pulling renames, exporting structs, importing comments, or any interaction between rebrew and Ghidra. Triggers on 'Ghidra', 'sync', 'push', 'pull', 'ReVa', 'MCP', 'labels', 'pull-signatures', 'pull-structs', 'pull-comments', or 'pull-data'.
license: MIT
---

# Rebrew Ghidra Sync

Synchronize annotations and symbols between rebrew source files and a running Ghidra instance via ReVa MCP.

## 1. Program Path Validation

Before sync operations, confirm Ghidra target selection in project config:

- Ensure `ghidra_program_path` is set for the active target in `rebrew-project.toml`
- Ensure the same program is open in Ghidra via ReVa MCP

If `ghidra_program_path` is missing or mismatched, fix config before running pull/push.

## 2. Sync Commands

```bash
rebrew sync --summary --json            # preview what would be synced
rebrew sync --push                      # export + apply labels/comments to Ghidra
rebrew sync --push --dry-run            # preview push without applying
rebrew sync --pull                      # fetch Ghidra renames/comments and update local C files
rebrew sync --pull --accept-ghidra      # fetch renames and automatically update cross-references
rebrew sync --pull-signatures           # fetch Ghidra decompilation to update extern prototypes
rebrew sync --pull-structs              # export Ghidra structs into types.h
rebrew sync --pull-comments             # fetch Ghidra EOL/post analysis comments into source
rebrew sync --pull-data                 # fetch Ghidra data labels into rebrew_globals.h
rebrew sync --pull --dry-run            # preview pull without modifying files
```

## 3. What Gets Synced

**Push -> Ghidra:**
- Function labels (skips generic `func_XXXXXXXX` names)
- Plate comments with `[rebrew]` metadata (status, origin, size, cflags)
- Pre-comments from `// NOTE:` annotations
- Bookmarks by status category (`rebrew/exact`, `rebrew/reloc`, etc.)
- Struct definitions -> Ghidra Data Type Manager under `/rebrew` category
- Function prototypes (parsed from local C files)
- DATA/GLOBAL labels and bookmarks (`rebrew/data` category)

**Pull <- Ghidra:**
- Function renames (updates `// SYMBOL:` locally and handles `extern` cross-references with `--accept-ghidra`)
- Function prototypes (`--pull-signatures` writes `// PROTOTYPE:` and updates `extern` usage across codebase)
- Structs (`--pull-structs` writes `types.h` from Ghidra)
- Comments (`--pull-comments` writes EOL/post comments as `// ANALYSIS:`)
- Data label names
- Plate and pre-comments (updates `// NOTE:` locally)
- Data labels (`--pull-data` fetches Ghidra data labels via MCP and generates `rebrew_globals.h` with typed extern declarations grouped by PE section)

## 4. Safety Guarantees

- **No accidental overwrites**: Generic auto-names (`FUN_`, `DAT_`, `func_`, `switchdata`) are never pulled
- **Conflict detection**: When both local and Ghidra have meaningful (non-generic) names that differ, pull reports a CONFLICT and skips rename
- **`[rebrew]` comments filtered**: Auto-generated plate comments are not pulled back
- **Dry-run support**: Use `--dry-run` to preview changes before applying
- **Idempotent behavior**: Re-running sync is safe and produces stable results
