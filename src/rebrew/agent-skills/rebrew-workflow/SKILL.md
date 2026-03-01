---
name: rebrew-workflow
description: Guides the end-to-end reverse engineering workflow for matching C source against target binary functions. Covers function selection, skeleton generation, compile-and-compare iteration, promotion, verification, and dependency analysis. Use this skill for ANY reversing task including picking functions to work on, generating skeletons, testing implementations, promoting matched functions, running verification, linting annotations, or tracking progress. Triggers on 'reverse', 'decompile', 'skeleton', 'test function', 'promote', 'verify', 'lint', 'next function', 'workflow', or any rebrew CLI command not covered by a more specific skill.
license: MIT
---

# Rebrew Workflow

All commands run from a directory containing `rebrew-project.toml`. Use `--json` for structured output.
For annotation syntax details, see `references/annotation-format.md`.

## 1. Triage and Pick a Function

```bash
rebrew triage --json                    # combined overview: coverage, near-misses, recommendations
rebrew next --json                      # find easiest functions to tackle (sorted by similarity, then difficulty)
rebrew next --stats --json              # matching progress
rebrew next --improving --json          # MATCHING functions sorted by byte delta (closest first)
rebrew flirt --json                     # FLIRT scan: identify known library functions (fast wins)
```

Without `--json`, these produce rich terminal tables for human review.

### Similarity-based prioritization

`rebrew next` computes byte-level similarity between each uncovered function and all already-matched (EXACT/RELOC) functions. Functions sharing byte patterns with matched code are ranked higher — creating a snowball effect where each match makes the next one easier to find.

- Sort order: similarity (descending) → difficulty (ascending) → size (ascending)
- Terminal output includes a `Sim` column showing similarity as a percentage (e.g. `87%`)
- JSON output includes a `similarity` field (float 0.0–1.0) on each item
- Only functions >20 bytes are scored; smaller ones get similarity 0.0
- Comparison is filtered to functions within ±20% size for performance

## 2. Generate Skeleton

```bash
rebrew skeleton 0x<VA>                             # generate annotated .c stub
rebrew skeleton 0x<VA> --decomp --decomp-backend ghidra # Ghidra decompilation via MCP
rebrew skeleton 0x<VA> --decomp --decomp-backend r2dec # r2dec decompilation
rebrew skeleton 0x<VA> --xrefs                     # include caller context from Ghidra xrefs
rebrew skeleton 0x<VA> --append existing_file.c    # add to multi-function file
rebrew skeleton --list --origin GAME               # list uncovered functions
rebrew skeleton --batch 10                         # generate 10 skeletons (smallest first)
```

The file extension comes from `source_ext` in `rebrew-project.toml` (default: `.c`).
Use `--json` for structured output in batch/list modes.

## 3. Review Disassembly

```bash
rebrew asm 0x<VA> --size 128 --json            # dump 128 bytes of disassembly at VA
```


### Multiple Target Synchronization
Rebrew natively filters annotations by the currently active `--target`. You can place the identical code block under multiple `// FUNCTION: <MODULE>` blocks in the same C file:
```c
// FUNCTION: LEGO1 0x1009a8c0
// STATUS: EXACT

// FUNCTION: BETA10 0x101832f7
// STATUS: MATCHING
void my_func() {}
```
Testing via `rebrew test src/file.c --target LEGO1` will completely ignore the BETA10 block, and vice versa. Always respect existing multi-target blocks.

## 4. Implement and Test

Iteratively edit source and compile-compare against the target binary:

```bash
rebrew test src/<target>/<file>.c --json    # compile + byte-compare
```

Adjust code and `// CFLAGS:` annotation until STATUS reaches EXACT or RELOC.
For deeper matching (flag sweep, GA engine), use the `rebrew-matching` skill.
Compile cache is automatic during matching/test workflows; use `rebrew cache stats` only for operational inspection.

When MATCHING, auto-classify and write blockers:
```bash
rebrew match --diff-only --fix-blocker src/<target>/<file>.c --json  # auto-write BLOCKER annotations
```

## 5. File Organization

Use `rebrew split` and `rebrew merge` to manage multi-function files:

```bash
rebrew split src/<target>/multi.c                    # split into individual files
rebrew split src/<target>/multi.c --dry-run           # preview without writing
rebrew merge a.c b.c -o merged.c                     # merge into one file
rebrew merge a.c b.c -o merged.c --delete            # merge and remove originals
```

Split when: functions in a multi-function file need different CFLAGS, different
origins, or independent tracking. Merge when: functions share the same translation
unit (static locals, file-scoped globals) and must be compiled together.

## 6. Global Data

If the function references globals, use the `rebrew-data-analysis` skill for
`// GLOBAL:` / `// DATA:` annotations and the `rebrew data` tool.

## 7. Promote Matched Functions

When EXACT or RELOC is achieved, atomically update STATUS:

```bash
rebrew promote src/<target>/<file>.c --json          # test + update STATUS
rebrew promote src/<target>/<file>.c --dry-run --json # preview only
rebrew promote --all --json                          # batch promote all promotable functions
rebrew promote --all --dir src/<target>/subdir --json # batch promote within directory
rebrew promote --all --origin GAME --json            # batch promote by origin
rebrew promote --all --dry-run --json                # preview batch promotion
```

Single-file mode tests and atomically updates STATUS. Batch mode (`--all`) discovers
all promotable functions, verifies each, and updates annotations. Never demotes.
Automatically removes BLOCKER/BLOCKER_DELTA annotations on promotion.

## 8. Verify and Track Progress

```bash
rebrew doctor                           # check toolchain/config health
rebrew doctor --install-wibo            # auto-download wibo (lightweight Wine alternative)
rebrew status --json                    # quick EXACT/RELOC/MATCHING/STUB counts
rebrew verify --summary                 # summary table with match %
rebrew verify --json                    # bulk compile + diff all reversed functions
rebrew verify -j 8 -o report.json      # parallel compile, save report to file
rebrew verify --diff --json             # compare against last saved report, detect regressions
rebrew lint --json                      # check annotation correctness
rebrew lint --fix                       # auto-migrate old annotation formats
rebrew lint --summary                   # status/origin breakdown table
```

### Coverage Database

```bash
rebrew catalog --json                   # generate catalog JSON from annotations + binary
rebrew build-db                         # build SQLite coverage database from catalog
```

### Regression Detection

`rebrew verify --diff` compares the current verify run against the last saved
`db/verify_results.json` report. It classifies each function by VA as a
regression (status worsened), improvement (status improved), or new entry.
Exit code 1 if any regressions are detected — suitable for CI/pre-commit hooks.

```
3 regressions detected:
  func_10003da0  EXACT → MATCHING  (delta: 4B)
  func_10006c00  RELOC → MATCHING  (delta: 12B)
  zlib_adler32   EXACT → COMPILE_ERROR

2 improvements:
  func_10008880  MATCHING → EXACT
  func_1000a200  STUB → MATCHING
```

## 9. Dependency Graph

```bash
rebrew graph --format summary           # stats, leaf functions, top blockers
rebrew graph --focus <Func> --depth 2   # neighbourhood of a specific function
rebrew graph                            # full mermaid call graph
```

For Ghidra integration, see the `rebrew-ghidra-sync` skill.
Use it for push/pull sync, signatures, structs, comments, and data labels.

For GA matching, flag sweeps, and batch processing, see the `rebrew-matching` skill.
Use it for `rebrew match`, `rebrew ga`, and blocker-driven byte-level optimization.
