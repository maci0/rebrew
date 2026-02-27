---
name: rebrew-workflow
description: Guides the end-to-end reverse engineering workflow for matching C source against target binary functions. Covers function selection, skeleton generation, compile-and-compare iteration, promotion, verification, Ghidra sync, and dependency graph analysis. Use when reversing, decompiling, or matching functions.
license: MIT
---

# Rebrew Workflow

All commands run from a directory containing `rebrew.toml`. Use `--json` for structured output.

## 1. Triage and Pick a Function

```bash
rebrew triage --json                    # combined overview: coverage, near-misses, recommendations
rebrew next --json                      # find easiest functions to tackle
rebrew next --stats --json              # matching progress
rebrew next --improving --json          # MATCHING functions sorted by byte delta (closest first)
rebrew flirt --json                     # FLIRT scan: identify known library functions (fast wins)
```

Without `--json`, these produce rich terminal tables for human review.

## 2. Generate Skeleton

```bash
rebrew skeleton 0x<VA>                             # generate annotated .c stub
rebrew skeleton 0x<VA> --decomp --decomp-backend r2dec  # include decompilation
rebrew skeleton 0x<VA> --append existing_file.c    # add to multi-function file
rebrew skeleton --list --origin GAME               # list uncovered functions
rebrew skeleton --batch 10                         # generate 10 skeletons (smallest first)
```

The file extension comes from `source_ext` in `rebrew.toml` (default: `.c`).
Use `--json` for structured output in batch/list modes.

## 3. Review Disassembly

```bash
rebrew asm 0x<VA> --size 128 --json            # dump 128 bytes of disassembly at VA
```

## 4. Implement and Test

Iteratively edit source and compile-compare against the target binary:

```bash
rebrew test src/<target>/<file>.c --json    # compile + byte-compare
```

Adjust code and `// CFLAGS:` annotation until STATUS reaches EXACT or RELOC.
For deeper matching (flag sweep, GA engine), use the `rebrew-matching` skill.

## 5. Global Data

If the function references globals, use the `rebrew-data-analysis` skill for
`// GLOBAL:` / `// DATA:` annotations and the `rebrew data` tool.

## 6. Promote Matched Functions

When EXACT or RELOC is achieved, atomically update STATUS:

```bash
rebrew promote src/<target>/<file>.c --json          # test + update STATUS
rebrew promote src/<target>/<file>.c --dry-run --json # preview only
```

Automatically removes BLOCKER/BLOCKER_DELTA annotations on promotion.

## 7. Verify and Track Progress

```bash
rebrew status --json                    # quick EXACT/RELOC/MATCHING/STUB counts
rebrew verify --summary                 # summary table with match %
rebrew verify --json                    # bulk compile + diff all reversed functions
rebrew verify -j 8 -o report.json      # parallel compile, save report to file
rebrew lint --json                      # check annotation correctness
rebrew lint --fix                       # auto-migrate old annotation formats
rebrew lint --summary                   # status/origin breakdown table
```

## 8. Dependency Graph

```bash
rebrew graph --format summary           # stats, leaf functions, top blockers
rebrew graph --focus <Func> --depth 2   # neighbourhood of a specific function
rebrew graph                            # full mermaid call graph
```

## 9. Ghidra Sync

Push annotations and structs to a running Ghidra instance via ReVa MCP, or pull renames/comments from it:

```bash
rebrew sync --summary --json            # preview what would be synced
rebrew sync --push                      # export + apply labels/comments to Ghidra
rebrew sync --push --dry-run            # preview push without applying
rebrew sync --export                    # generate ghidra_commands.json only
rebrew sync --pull                      # fetch Ghidra renames/comments and update local C files
rebrew sync --pull --dry-run            # preview pull without modifying files
rebrew sync --pull --json               # pull with structured JSON output
```

### What gets synced

**Push → Ghidra:**
- Function labels (skips generic `func_XXXXXXXX` names)
- Plate comments with `[rebrew]` metadata (status, origin, size, cflags)
- Pre-comments from `// NOTE:` annotations
- Bookmarks by status category (`rebrew/exact`, `rebrew/reloc`, etc.)
- Struct definitions → Ghidra Data Type Manager under `/rebrew` category
- Function prototypes (parsed from local C files)
- DATA/GLOBAL labels and bookmarks (`rebrew/data` category)

**Pull ← Ghidra:**
- Function renames from Ghidra (updates `// SYMBOL:` and renames file if it matches)
- Data label names from Ghidra
- Plate and pre-comments from Ghidra (mapped to `// NOTE:` annotation)

### Safety guarantees

- **No accidental overwrites**: Generic auto-names (`FUN_`, `DAT_`, `func_`, `switchdata`) are never pulled
- **Conflict detection**: When both local and Ghidra have meaningful (non-generic) names that differ, the pull reports a CONFLICT and skips the rename — resolve manually
- **`[rebrew]` comments filtered**: Our own auto-generated plate comments are never pulled back
- **Dry-run**: Use `--dry-run` with any operation to preview changes before applying
- **Idempotent**: Re-running sync is safe — same result every time

## 10. Coverage Database

```bash
rebrew catalog --json                   # generate catalog JSON from annotations + binary
rebrew build-db                         # build SQLite coverage database from catalog
```

## 11. Batch GA for Near-Miss Functions

```bash
rebrew ga --dry-run --json              # preview which STUBs would be attempted
rebrew ga --generations 200 --json      # run GA on all STUBs
rebrew ga --near-miss --threshold 5     # target MATCHING functions with <=5B delta
```
