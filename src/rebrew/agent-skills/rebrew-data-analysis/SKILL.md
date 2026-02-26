---
name: rebrew-data-analysis
description: Analyzes global variables, structs, and arrays in binary data sections (.data, .rdata, .bss). Detects type conflicts across translation units, finds dispatch tables and vtables, and verifies BSS layout. Use when working with globals, data annotations, or debugging relocation mismatches.
license: MIT
---

# Rebrew Data Analysis

Inspect global variables and detect type conflicts across translation units.

## Commands

```bash
rebrew data --json                      # inventory of all globals by section
rebrew data --conflicts --json          # type conflicts: same VA, different types across files
rebrew data --dispatch --json           # detect dispatch tables / vtables in .data/.rdata
rebrew data --bss --json                # verify .bss layout, detect gaps from missing externs
```

## DATA Annotations

Standalone global data objects use `// DATA:` annotations:

```c
// DATA: SERVER 0x10025000
// SIZE: 256
// SECTION: .rdata
// ORIGIN: GAME
// NOTE: lookup table for sprite indices
const unsigned char g_sprite_lut[256] = { ... };
```

## GLOBAL Annotations

When a function references a global address from disassembly:

1. Declare the global in a source file or centralized header.
2. Annotate with `// GLOBAL: MODULE 0x<VA>` for tracking.
3. The `MODULE` value (e.g. `GAME`, `ZLIB`) sets the `origin` field.

## Debugging Relocation Mismatches

If code matches but absolute addresses differ, the cause is often missing globals
in `.bss`. Run `rebrew data --bss --json` to detect gaps between known globals
that indicate missing `extern` declarations.
