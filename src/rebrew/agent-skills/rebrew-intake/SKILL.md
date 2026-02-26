---
name: rebrew-intake
description: Onboards a new binary into an existing rebrew project. Runs initial reconnaissance (FLIRT signatures, function catalog, coverage database, triage) and produces an actionable summary of the binary's reversing landscape. Use when adding a new target binary, starting a new reversing campaign, or performing initial binary analysis.
license: MIT
---

# Rebrew Intake

Onboard a new binary into a rebrew project and produce an initial assessment.

## Prerequisites

A `rebrew.toml` must exist with the new target configured. If starting from scratch:

```bash
rebrew init --target <name> --binary <filename> --compiler msvc6
```

Then place the binary at the path specified in `rebrew.toml` (default: `original/<filename>`).

## Intake Procedure

### 1. Verify Configuration

```bash
rebrew cfg list-targets                 # confirm target is configured
rebrew status --json                    # should show the target with 0 functions
```

If the target is missing, add it:

```bash
rebrew cfg add-target <name> --binary original/<filename>
```

### 2. FLIRT Library Scan

Identify known library functions (MSVCRT, zlib, DirectX, etc.) to separate
library code from game code:

```bash
rebrew flirt --json                     # scan binary against FLIRT signatures
```

Library matches are fast wins — they can be skeletonized and matched quickly
since the original source is often available.

### 3. Build Function Catalog

Generate the function catalog from the binary's symbol table and any existing annotations:

```bash
rebrew catalog --json                   # build catalog + data JSON
rebrew build-db                         # build SQLite coverage database
```

### 4. Initial Triage

Get a comprehensive overview of the reversing landscape:

```bash
rebrew triage --json                    # coverage stats, recommendations, FLIRT counts
rebrew next --stats --json              # detailed progress statistics
rebrew data --dispatch --json           # detect dispatch tables / vtables
```

### 5. Assess Scope

From the triage output, evaluate:

- **Total functions** and size distribution
- **Library vs game code ratio** (from FLIRT matches)
- **Quick wins**: small functions, leaf functions, known library matches
- **Blockers**: large functions, functions with many dependencies

### 6. Generate First Skeletons

Start with the easiest functions identified by triage:

```bash
rebrew next --json                      # get recommended functions
rebrew skeleton 0x<VA>                  # generate skeleton for each
```

For library functions identified by FLIRT, check if reference source is available
(e.g. `tools/MSVC600/VC98/CRT/SRC/` for MSVCRT, `references/zlib-1.1.3/` for zlib).

### 7. Sync to Ghidra (Optional)

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
- [ ] Catalog and coverage DB built
- [ ] Triage report reviewed
- [ ] First skeletons generated
- [ ] Ghidra synced (if available)
```
