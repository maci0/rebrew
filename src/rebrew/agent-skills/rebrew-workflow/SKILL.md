---
name: rebrew-workflow
description: Guides the end-to-end reverse engineering workflow for matching C source against target binary functions. Covers function selection, skeleton generation, compile-and-compare iteration, verification, and dependency analysis. Use this skill for ANY reversing task including picking functions to work on, generating skeletons, testing implementations, running verification, linting annotations, or tracking progress. Triggers on 'reverse', 'decompile', 'skeleton', 'test function', 'verify', 'lint', 'next function', 'workflow', or any rebrew CLI command not covered by a more specific skill.
license: MIT
---

# Rebrew Workflow

All commands run from a directory containing `rebrew-project.toml`. Use `--json` for structured output.
For annotation syntax details, see `references/annotation-format.md`.

## 1. Pick a Function

```bash
rebrew todo --json                      # Primary: get highest ROI action items
rebrew todo -c start-function --json    # Only new functions to start
rebrew flirt --json                     # FLIRT scan: identify known library functions (fast wins)
rebrew crt-match --all --json # find matching CRT source files
```

**Always default to `rebrew todo --json`.** It evaluates the whole project and suggests tasks by these tiers:
1. Compile errors and verifier regressions (blocks progress)
2. Near-misses (1-4 byte deltas, fast wins)
3. Stubs that need finishing
4. New function starts (ranked by similarity and size)
5. Automated tasks (prove, data fixups)

## 2. Generate Skeleton

```bash
rebrew skeleton 0x<VA>                             # generate annotated .c stub
rebrew skeleton 0x<VA> --decomp --decomp-backend ghidra # Ghidra decompilation via MCP
rebrew skeleton 0x<VA> --xrefs                     # include caller context from Ghidra xrefs
rebrew skeleton 0x<VA> --append existing_file.c    # add to multi-function file
rebrew skeleton --batch 10                         # generate 10 skeletons (smallest first)
```

## 3. Review Disassembly

```bash
rebrew asm 0x<VA> --size 128               # hex dump + disassembly
rebrew asm 0x<VA> --size 128 --format nasm # NASM-reassembleable source
rebrew asm 0x<VA> --size 128 --json        # structured JSON output
```

### Multiple Target Synchronization
Rebrew filters annotations by the active `--target`. Multiple `// FUNCTION: <MODULE>` marker lines in the same C file are supported — **no other metadata in the .c file**:
```c
// FUNCTION: LEGO1 0x1009a8c0

// FUNCTION: BETA10 0x101832f7
void my_func() {}
```
Each target's `rebrew-function.toml` metadata file holds STATUS, SIZE, CFLAGS for that VA.

## 4. Implement and Test

Iteratively edit source and compile-compare against the target binary:

```bash
rebrew test src/<target>/<file>.c          # compile + byte-compare; auto-updates STATUS
rebrew test src/<target>/<file>.c --json   # JSON output
rebrew test src/<target>/<file>.c --no-promote  # skip STATUS update
rebrew test --all --json                   # batch test all reversed .c files
rebrew test --all --origin GAME --json     # batch mode, filter by origin
rebrew test --all --dir src/<target>/ --json    # batch mode, restrict to subdir
rebrew test --all --dry-run                # preview changes without writing
```

`rebrew test` auto-updates STATUS in the metadata file after each run:
- **EXACT/RELOC** → updates STATUS and clears auto-generated BLOCKERs
- **MATCHING / MATCHING_RELOC** (≥60% byte match) → updates STATUS; preserves user-set BLOCKERs
- **< 75%** → no STATUS change (don't demote unless you're sure)

For a byte diff of the current state:

```bash
rebrew diff src/<target>/<file>.c          # byte diff vs target
rebrew diff src/<target>/<file>.c --mm     # only structural diffs (**)
rebrew diff src/<target>/<file>.c --fix-blocker  # auto-write BLOCKER to metadata file
```

> [!CAUTION]
> **Never manually edit `rebrew-function.toml` or `rebrew-data.toml`.**
> All volatile metadata lives in metadata files managed by CLI tools.

For deeper matching (GA engine), see the `rebrew-matching` skill.

## 5. File Organization

```bash
rebrew split src/<target>/multi.c                    # split into individual files
rebrew split src/<target>/multi.c --dry-run           # preview without writing
rebrew split --va 0x10003DA0 src/<target>/multi.c     # extract one function
rebrew merge a.c b.c -o merged.c                     # merge into one file
rebrew rename old_func new_func                       # rename across entire project
rebrew rename old_func new_func --dry-run             # preview rename without writing
```

Split when functions need different CFLAGS or independent tracking.
Merge when functions share a translation unit (static locals, file-scoped globals).

Use `rebrew graph --cu-map` to identify functions likely from the same compilation unit:

```bash
rebrew graph --cu-map --json                         # infer TU boundaries
```

## 6. Global Data

If the function references globals, use the `rebrew-data-analysis` skill for
`// GLOBAL:` / `// DATA:` annotations and the `rebrew data` tool. Global metadata
lives in the **`rebrew-data.toml`** metadata file, managed automatically by `rebrew data`,
`rebrew data --fix-bss`, and `rebrew sync --pull`.

## 7. Prove Stubborn MATCHING Functions

If a function remains MATCHING after source adjustments (structural blockers like
register allocation), use `rebrew prove` for symbolic equivalence:

```bash
rebrew prove src/<target>/<file>.c --json               # prove MATCHING → PROVEN
rebrew prove src/<target>/<file>.c --dry-run --json      # preview without updating
rebrew prove my_func --timeout 120 --json                # find by symbol, 2 min timeout
```

Requires optional dep: `uv pip install -e ".[prove]"`.
For details, see the `rebrew-matching` skill.

## 8. Verify and Track Progress

```bash
rebrew doctor                           # check toolchain/config health
rebrew verify --summary                 # summary table with match %
rebrew verify --json                    # bulk compile + diff all reversed functions
rebrew verify -j 8 -o report.json      # parallel compile, save report to file
rebrew verify --compare --json          # compare against last saved report, detect regressions
rebrew lint --json                      # check annotation correctness
rebrew lint --fix                       # auto-migrate old annotation formats
rebrew lint --summary                   # status/origin breakdown table
```

### Coverage Database

```bash
rebrew catalog --data-json              # write db/data_<target>.json
rebrew build-db                         # build SQLite coverage database
```

### Regression Detection

`rebrew verify --compare` compares the current run against `db/verify_results.json`.
Exit code 1 if any regressions — suitable for CI/pre-commit hooks.

## 9. Dependency Graph

```bash
rebrew graph --format summary           # stats, leaf functions, top blockers
rebrew graph --focus <Func> --depth 2   # neighbourhood of a specific function
rebrew graph                            # full mermaid call graph
rebrew graph --cu-map --json            # infer compilation unit boundaries
```

For Ghidra integration, see the `rebrew-ghidra-sync` skill.
For GA matching and batch processing, see the `rebrew-matching` skill.
