---
name: rebrew-data-analysis
description: Analyzes global variables, structs, and arrays situated in data sections (.data, .rdata, .bss) across reversed files.
license: MIT
---

# Rebrew Data Analysis

This skill guides the inspection of global variables and detection of C type conflicts across different translation units.

**Note**: All tools respect the `source_ext` setting in `rebrew.toml` (default: `.c`). If your project uses a different extension, tools will automatically scan for the configured extension — no manual adjustment needed.

## Core Tool: `rebrew data`

The `rebrew data` tool parses `// GLOBAL: <VA>` annotations alongside `extern` declarations to find and map globals into sections.

### 1. General Inventory
To see an inventory of all mapped and unmapped globals, categorized by `.data`, `.rdata`, and `.bss`:
- Run `uv run rebrew data`
It outputs a rich table with sizes and origins.

### 2. Detecting Type Conflicts
If you have global declarations pointing to the same virtual address (VA) but modeled with different types across files:
- Run `uv run rebrew data --conflicts`
This will immediately point out which files disagree on a global's format (e.g. `int` vs `struct Entity*`).

### 3. Machine Reporting
For pipelines or bulk inspection:
- Run `uv run rebrew data --json`

### 4. Dispatch Table / VTable Detection
To find dispatch tables (function pointer arrays) in `.data` and `.rdata` sections:
- Run `uv run rebrew data --dispatch`
This scans for contiguous pointer-sized entries pointing into `.text`, then cross-references each against known reversed functions and shows coverage per table.
- For JSON output: `uv run rebrew data --dispatch --json`

### 5. BSS Layout Verification
When debugging mysterious relocation mismatches where code is correct but absolute addresses differ:
- Run `uv run rebrew data --bss` to verify `.bss` layout
- Detects gaps between known globals that indicate missing `extern` declarations
- Use `--json` for machine-readable output: `uv run rebrew data --bss --json`

### 6. DATA Annotations
Standalone global data objects can be tracked with `// DATA:` annotations:
```c
// DATA: SERVER 0x10025000
// SIZE: 256
// SECTION: .rdata
// ORIGIN: GAME
// NOTE: lookup table for sprite indices
const unsigned char g_sprite_lut[256] = { ... };
```
These are parsed by `rebrew-data` and tracked separately from function annotations.

### Note on Annotating Data
When reversing a function, if you encounter global addresses in disassembly:
1. Prefer to declare them normally in a source file or a centralized header.
2. Annotate the file with `// GLOBAL: MODULE 0x<VA>` so the tools can properly track and size the global against the binary segment map.
3. The `MODULE` in the annotation (e.g. `GAME`, `ZLIB`) becomes the `origin` field, and the type declaration determines the `size` — both are now stored in `coverage.db` (schema v2) and served by the recoverage dashboard.
