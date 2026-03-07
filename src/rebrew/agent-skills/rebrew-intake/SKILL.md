---
name: rebrew-intake
description: Onboards a new binary into an existing rebrew project. Runs initial reconnaissance (FLIRT signatures, function catalog, coverage database, triage) and produces an actionable summary of the binary's reversing landscape. Use this skill whenever adding a new target binary, starting a new reversing campaign, performing initial binary analysis, running FLIRT scans, building the function catalog, or triaging a binary for the first time. Also use when the user mentions 'intake', 'onboard', 'new binary', 'new target', 'catalog', 'triage', or 'FLIRT scan'.
license: MIT
---

# Rebrew Intake

Onboard a new binary into a rebrew project and produce an initial assessment.

## Prerequisites

A `rebrew-project.toml` must exist with the new target configured. If starting from scratch:

```bash
rebrew init --target <name> --binary <filename> --compiler msvc6
```

Then place the binary at the path specified in `rebrew-project.toml` (default: `original/<filename>`).


### Multi-Target File Layout
When adding a new target that shares codebase with an existing target (e.g., adding `BETA10` to a `LEGO1`
project), you do not need to duplicate `.c` files. Add a second `// FUNCTION: BETA10 0x...` annotation block
above the same function body.

## Intake Procedure

### 1. Verify Configuration

```bash
rebrew doctor                           # check toolchain and project health
rebrew doctor --install-wibo            # auto-download wibo if Wine is unavailable
rebrew cfg list-targets                 # confirm target is configured
```

On Linux, `--install-wibo` downloads wibo (a lightweight Win32 PE loader) as
a faster alternative to Wine for running MSVC CL.EXE. SHA256-verified from GitHub.

If the target is missing, add it:

```bash
rebrew cfg add-target <name> --binary original/<filename>
```

### 2. FLIRT Library Scan

Identify known library functions (MSVCRT, zlib, DirectX, etc.) to separate
library code from game code:

```bash
rebrew flirt --json                     # scan binary against FLIRT signatures
rebrew crt-match --index --json         # verify CRT source directories are configured
rebrew crt-match --all --fix-source --json # auto-annotate SOURCE references for library functions
```

Library matches are fast wins — they can be skeletonized and matched quickly
since the original source is often available.

### 3. Build Function Catalog

```bash
rebrew catalog --json                   # build catalog + data JSON
rebrew catalog db                       # build SQLite coverage database
```

### 4. Initial Triage

```bash
rebrew todo --json                      # prioritized action items overview
rebrew data --dispatch --json           # detect dispatch tables / vtables
```

### 5. Infer Compilation Units

Identify which functions were likely compiled from the same source file:

```bash
rebrew graph --cu-map --json            # cluster functions into inferred translation units
```

This uses inter-function gap analysis and call-graph signals to group contiguous functions.
High-confidence clusters suggest functions that should be merged into the same `.c` file.

### 6. Assess Scope

From the triage output, evaluate:

- **Total functions** and size distribution
- **Library vs game code ratio** (from FLIRT matches)
- **Quick wins**: small functions, leaf functions, known library matches
- **Blockers**: large functions, functions with many dependencies

### 7. Extract Disassembly (Optional)

```bash
rebrew extract list                     # list un-reversed candidates
rebrew extract batch 20                 # extract first 20 smallest
```

### 8. Generate First Skeletons

Start with the easiest functions identified by triage:

```bash
rebrew todo --json                      # get recommended functions
rebrew skeleton --list --origin GAME    # list all uncovered GAME functions
rebrew skeleton --batch 10              # generate 10 skeletons (smallest first)
rebrew skeleton 0x<VA>                  # generate one skeleton by VA
rebrew skeleton 0x<VA> --decomp         # include decompilation in skeleton
rebrew skeleton 0x<VA> --decomp --decomp-backend ghidra  # Ghidra via MCP
rebrew skeleton 0x<VA> --xrefs          # with caller context from Ghidra
```

For library functions identified by FLIRT, check if reference source is available
(e.g. `tools/MSVC600/VC98/CRT/SRC/` for MSVCRT, `references/zlib-1.1.3/` for zlib).

### 9. Sync to Ghidra (Optional)

If a Ghidra instance is available with ReVa MCP:

```bash
rebrew sync --push                      # push annotations + FLIRT labels to Ghidra
```

## Summary Checklist

```
Intake Progress:
- [ ] Binary placed at configured path
- [ ] rebrew cfg confirms target
- [ ] FLIRT scan complete
- [ ] Catalog and coverage DB built (rebrew catalog + rebrew catalog db)
- [ ] Triage report reviewed (rebrew todo)
- [ ] Compilation units inferred (rebrew graph --cu-map)
- [ ] First skeletons generated
- [ ] Ghidra synced (if available)
```
