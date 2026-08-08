---
name: rebrew-data-analysis
description: Analyzes global variables, structs, and arrays in binary data sections (.data, .rdata, .bss). Detects type conflicts across translation units, finds dispatch tables and vtables, and verifies BSS layout. Use this skill when working with globals, data annotations, debugging relocation mismatches, fixing BSS gaps, finding dispatch tables, or dealing with '// DATA:' and '// GLOBAL:' annotations. Triggers on 'global', 'data section', 'BSS', 'vtable', 'dispatch table', 'relocation', 'extern', or 'type conflict'.
license: MIT
---

# Rebrew Data Analysis

Inspect global variables and detect type conflicts across translation units.

## When NOT to use this skill

- Function bodies / disassembly / matching → use `rebrew-workflow` or `rebrew-matching`
- Pulling data labels back from Ghidra → use `rebrew-ghidra-sync` (`rebrew sync --pull-data`)

## Commands

Run from the project root (config discovery walks up to `rebrew-project.toml`). Add
`--target NAME` for non-default targets in multi-target projects.

```bash
rebrew data --json                              # full inventory: globals, data_annotations, type_conflicts, summary, sections
rebrew data --summary --json                    # terminal table is section-level; JSON is still the full inventory
rebrew data --conflicts --json                  # type conflicts: same name, different types across files
rebrew data --dispatch --json                   # detect dispatch tables / vtables in .data/.rdata
rebrew data --dispatch --min-table-len 5 --json # require >= 5 entries per table
rebrew data --dispatch --max-pointer-stride 8   # allow 8-byte stride between slots (sparse tables)
rebrew data --bss --json                        # verify .bss layout, detect gaps from missing externs
rebrew data --fix-bss --dry-run                 # preview bss_padding.c + metadata changes, write nothing
rebrew data --fix-bss                           # generate bss_padding.c + write SIZE/SECTION/NOTE to metadata
rebrew data --gen-header --dry-run              # preview rebrew_globals.h contents
rebrew data --gen-header                        # write rebrew_globals.h from local // GLOBAL: / // DATA: annotations (no Ghidra)
rebrew data --gen-header --gen-header-out /path/to/my_globals.h  # override output path
rebrew data --gen-header --force                # overwrite existing file without prompting
```

Use `--gen-header` when working offline or before any Ghidra sync — it emits typed
`extern` declarations grouped by PE section. `rebrew sync --pull-data` overwrites
this header with Ghidra-sourced labels when available (same default path
`{reversed_dir}/rebrew_globals.h`, but `--pull-data` never prompts).

By default `--gen-header` refuses to overwrite an existing file; pass `--force` to
allow overwriting. Use `--gen-header-out PATH` to write to a custom location instead
of the default `{reversed_dir}/rebrew_globals.h`. Always run `--fix-bss` / `--gen-header`
with `--dry-run` first — `--fix-bss` writes both a source file and metadata.

## What to expect (JSON shapes)

`--json` prints one JSON document on **stdout** (rich tables go to stderr). Parse it
with `jq` or Python; do not parse the terminal output.

- **Default / `--conflicts` / `--summary`** — all three emit the same full inventory;
  `--summary` and `--conflicts` only change the terminal table:
  ```json
  {"globals": {"g_name": {"name": "g_name", "type": "int *", "va": "0x10025000",
                          "section": ".bss", "declared_in": ["server/main.c"], "annotated": true}},
   "data_annotations": [{"va": "0x10025000", "name": "g_sprite_lut", "size": 256,
                         "section": ".rdata", "note": "lookup table", "filepath": "server/main.c"}],
   "type_conflicts": [{"name": "g_count", "types": {"int": ["a.c"], "short": ["b.c"]}}],
   "summary": {"total": 42, "annotated": 10, "unannotated": 32, "data_entries": 5, "conflicts": 1},
   "sections": {".data": {"va": "0x10022000", "size": 4096}}}
  ```
  Check `summary.conflicts > 0` to decide whether `--conflicts` needs attention.
  `globals` with `"annotated": false` are plain `extern` declarations with no VA —
  give them `// GLOBAL: MODULE 0xVA` markers so they resolve to a section.

- **`--bss --json`** → `{"bss_va", "bss_size", "known_entries": [{"name", "va",
  "size_hint", "source_file"}], "gaps": [{"offset", "size", "between": [before, after]}],
  "coverage_pct", "summary": {"total_globals", "gaps", "total_gap_bytes"}}`. Each `gaps`
  entry is a likely undeclared `extern` — that is what `--fix-bss` fills.

- **`--dispatch --json`** → a list of tables:
  `[{"va", "section", "num_entries", "resolved", "coverage", "entries": [{"target_va",
  "name", "status"}]}]`. `status` is `EXACT`/`RELOC`/`NEAR_MATCHING`/`STUB` or `""`
  (unknown). Low `coverage` means the table's targets have no reversed source yet —
  good next-matching candidates.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `rebrew-project.toml not found` / config error | Running outside a project | `cd` into the project root, or pass `--target NAME` |
| `target binary not found (needed for --dispatch)` | Binary missing or unparseable | Fix `target_binary` in `rebrew-project.toml`; only `--dispatch` hard-requires the binary (plain scans degrade gracefully) |
| `already exists. Use --force to overwrite.` | `--gen-header` clobber guard | Pass `--force`, or `--gen-header-out` to a new path |
| `No annotated BSS globals — nothing to verify` | No `// GLOBAL:`/`extern` with a `.bss` VA | Add annotations first, then re-run `--bss` |
| Gap size looks wrong | `size_hint` is estimated from the C type (int=4, char=1, …) | Verify the declared types of the globals on either side of the gap |
| Small gaps not reported | Gaps < 4 bytes are alignment padding and intentionally ignored | Ignore; only ≥ 4-byte gaps are flagged |

## DATA Annotations

DATA metadata lives in a **`rebrew-data.toml` metadata file** at `cfg.metadata_dir` (the parent of `reversed_dir`). There is no walk-up: callers must pass the correct metadata root.
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
| `name` | Preferred variable label — overrides C stem; written by `rebrew sync --pull` from Ghidra |
| `size` | Size in bytes |
| `section` | PE section (`.data`, `.rdata`, `.bss`) |
| `note` | Description; written by `rebrew sync --pull` from Ghidra comments |

> [!CAUTION]
> **Never manually edit `rebrew-data.toml`.** It is managed automatically by `rebrew data`,
> `rebrew data --fix-bss`, and `rebrew sync --pull`. Entries are keyed `"MODULE.0xVA"`
> (qualified, same scheme as `rebrew-function.toml`).

## GLOBAL Annotations

When a function references a global address from disassembly:

1. Declare the global in a source file or centralized header.
2. Annotate with `// GLOBAL: MODULE 0x<VA>` for tracking (declaration must follow on the next line).
3. Metadata (name, size, section, note) goes in `rebrew-data.toml` — same format as DATA.

`--gen-header` picks up both `// GLOBAL:` and `// DATA:` markers, merging in `name`/`size`/
`section`/`note` from `rebrew-data.toml`. `rebrew lint` flags `DATA`/`GLOBAL` markers
missing `SECTION` metadata (W016) and inline volatile keys — run it after adding markers.

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

1. Run `rebrew diff --json src/<target>/<file>.c` — note `~~` addresses
2. Run `rebrew data --bss --json` — check if the addresses fall in BSS gaps
3. Run `rebrew data --fix-bss --dry-run` first (preview), then `rebrew data --fix-bss` to
   generate `bss_padding.c` (writes SIZE/SECTION/NOTE into `{metadata_dir}/rebrew-data.toml`)
4. Add missing `extern` declarations with `// GLOBAL:` annotations
5. Re-run `rebrew data --bss --json` to confirm the gap is gone, then
   `rebrew test src/<target>/<file>.c --json`

## Dispatch Tables and Vtables

`rebrew data --dispatch` scans `.data` and `.rdata` sections for arrays of
function pointers. Each detected table shows:

- Table VA and size
- Known vs unknown function entries (`resolved` / `coverage`)
- Per-entry `status` (EXACT / RELOC / NEAR_MATCHING / STUB / unknown)
- Whether the table is likely a vtable (consecutive entries, all code pointers)

Names come from source annotations first, then the function list / Ghidra structure
registry — so a low-coverage table usually means its targets lack reversed sources
(pick them up in `rebrew-workflow`), not that the detection failed. Tune detection
with `--min-table-len` (default 3) and `--max-pointer-stride` (default 4; raise it
for sparse tables with mixed payload entries). Use this to identify virtual method
tables that need reverse engineering.
