---
name: rebrew-data-analysis
description: Analyzes global variables, structs, and arrays in binary data sections (.data, .rdata, .bss). Detects type conflicts across translation units, finds dispatch tables and vtables, and verifies BSS layout. Use this skill when working with globals, data annotations, debugging relocation mismatches, fixing BSS gaps, finding dispatch tables, or dealing with '// DATA:' and '// GLOBAL:' annotations. Triggers on 'global', 'data section', 'BSS', 'vtable', 'dispatch table', 'relocation', 'extern', or 'type conflict'.
license: MIT
---

# Rebrew Data Analysis

Inspect global variables and detect type conflicts across translation units.

## Commands

```bash
rebrew data --json                      # inventory of all globals by section
rebrew data --summary --json            # section-level summary (sizes, counts)
rebrew data --conflicts --json          # type conflicts: same VA, different types across files
rebrew data --dispatch --json           # detect dispatch tables / vtables in .data/.rdata
rebrew data --bss --json                # verify .bss layout, detect gaps from missing externs
rebrew data --fix-bss                   # auto-generate bss_padding.c + write SIZE/SECTION/NOTE to sidecar
```

## DATA Annotations

DATA metadata lives in a **`rebrew-data.toml` sidecar** found via walk-up from the  file's directory (a single file at the source root serves all subdirectories).
Only the stable marker line stays in the `.c` file:

**`.c` file:**
```c
// DATA: SERVER 0x10025000

const unsigned char g_sprite_lut[256] = { ... };
```

**`rebrew-data.toml`** (auto-managed — never edit manually):
```toml
["SERVER.0x10025000"]
name    = "g_sprite_lut"      # preferred label (BinSync/Ghidra import target)
size    = 256
section = ".rdata"
note    = "lookup table for sprite indices"
```

| Field | Purpose |
|-------|---------|
| `name` | Preferred variable label — overrides C stem; populated by `rebrew sync --pull` from Ghidra |
| `size` | Size in bytes |
| `section` | PE section (`.data`, `.rdata`, `.bss`) |
| `note` | Description; populated by `rebrew sync --pull` from Ghidra comments |

> [!CAUTION]
> **Never manually edit `rebrew-data.toml`.** It is managed automatically by `rebrew data`,
> `rebrew data --fix-bss`, and `rebrew sync --pull`.

## GLOBAL Annotations

When a function references a global address from disassembly:

1. Declare the global in a source file or centralized header.
2. Annotate with `// GLOBAL: MODULE 0x<VA>` for tracking.
3. Metadata (name, size, section, note) goes in `rebrew-data.toml` — same format as DATA.

## Debugging Relocation Mismatches

If code matches but absolute addresses differ, the cause is often missing globals
in `.bss`. Run `rebrew data --bss --json` to detect gaps between known globals
that indicate missing `extern` declarations.

### Common causes of relocation-only diffs (`~~` markers)

| Symptom | Cause | Fix |
|---------|-------|-----|
| `mov eax, [0x1002XXXX]` differs | Global not declared as `extern` | Add `extern int g_var;` and `// GLOBAL:` annotation |
| BSS gap between two globals | Missing `extern` variable in between | Check `--bss` output for gap addresses |
| Multiple `~~` at same VA range | Shared global with different types across files | Run `--conflicts` and unify the type |

### Workflow for fixing relocation mismatches

1. Run `rebrew match --diff-only --json src/<target>/<file>.c` — note `~~` addresses
2. Run `rebrew data --bss --json` — check if the addresses fall in BSS gaps
3. Run `rebrew data --fix-bss` to automatically generate `bss_padding.c` (writes SIZE/SECTION/NOTE to `rebrew-data.toml`)
4. Add missing `extern` declarations with `// GLOBAL:` annotations
5. Re-test with `rebrew test src/<target>/<file>.c --json`

## Dispatch Tables and Vtables

`rebrew data --dispatch` scans `.data` and `.rdata` sections for arrays of
function pointers. Each detected table shows:

- Table VA and size
- Known vs unknown function entries
- Whether the table is likely a vtable (consecutive entries, all code pointers)

Use this to identify virtual method tables that need reverse engineering.
