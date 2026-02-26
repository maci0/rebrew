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
rebrew-next --json                      # find easiest functions to tackle
rebrew-next --stats --json              # matching progress
rebrew-next --improving --json          # MATCHING functions sorted by byte delta (closest first)
rebrew-flirt --json                     # FLIRT scan: identify known library functions (fast wins)
```

Without `--json`, these produce rich terminal tables for human review.

## 2. Generate Skeleton

```bash
rebrew-skeleton 0x<VA>                             # generate annotated .c stub
rebrew-skeleton 0x<VA> --decomp --decomp-backend r2dec  # include decompilation
```

The file extension comes from `source_ext` in `rebrew.toml` (default: `.c`).

## 3. Review Disassembly

```bash
rebrew-asm 0x<VA> 128 --json            # dump 128 bytes of disassembly at VA
```

## 4. Implement and Test

Iteratively edit source and compile-compare against the target binary:

```bash
rebrew-test src/<target>/<file>.c --json    # compile + byte-compare
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
rebrew-verify --json                    # bulk compile + diff all reversed functions
rebrew-verify -o report.json            # save report to file
rebrew-lint --json                      # check annotation correctness
rebrew-lint --fix                       # auto-migrate old annotation formats
```

## 8. Dependency Graph

```bash
rebrew graph --format summary           # stats, leaf functions, top blockers
rebrew graph --focus <Func> --depth 2   # neighbourhood of a specific function
rebrew graph                            # full mermaid call graph
```

## 9. Ghidra Sync

Push annotations to a running Ghidra instance via ReVa MCP:

```bash
rebrew-sync --summary --json            # preview what would be synced
rebrew-sync --push                      # export + apply to Ghidra
rebrew-sync --export                    # generate ghidra_commands.json only
```

Re-running sync is idempotent. Generic auto-names are skipped.

## 10. Coverage Database

```bash
rebrew-catalog --json                   # generate catalog JSON from annotations + binary
rebrew-build-db                         # build SQLite coverage database from catalog
```

## 11. Batch GA for Near-Miss Functions

```bash
rebrew-ga --dry-run --json              # preview which STUBs would be attempted
rebrew-ga --generations 200 --json      # run GA on all STUBs
rebrew-ga --near-miss --threshold 5     # target MATCHING functions with <=5B delta
```
