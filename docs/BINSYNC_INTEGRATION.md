# BinSync Integration

`rebrew binsync-export`, `rebrew binsync-import`, and `rebrew binsync-diff`
provide a bidirectional bridge between rebrew and any BinSync-aware decompiler
plugin (IDA Pro, Binary Ninja, Ghidra via BinSync). The export now carries real
global types and struct fields; the import closes the loop for names,
prototypes, and global labels; `binsync-diff` reports divergence read-only.

> For the planned full integration with `libbs` serialization, stack vars, enums,
> and `rebrew binsync` push/pull umbrella, see [prd/09-binsync-full.md](prd/09-binsync-full.md).

---

## Export — `rebrew binsync-export <outdir>`

Writes a [BinSync](https://github.com/binsync/binsync) state directory from the
project's annotations and metadata:

```
<outdir>/
    functions/
        <hex>.toml   -- one per function (reversed + catalog-only with canonical size)
    global_vars.toml -- DATA/GLOBAL annotations (with real C types)
    structs/
        <name>.toml  -- one per struct definition (with fields)
```

Export merges two sources: reversed annotations (`scan_reversed_dir`, the
authoritative names/sizes/prototypes) plus the **project file / catalog**
(`src/<target>/functions.txt` + `function_structure.json` → `build_function_registry`,
canonical sizes) for functions that have not yet been reversed.  This keeps
BinSync in sync with your binary's full function list and offsets, not just the
reversed subset.  Catalog-only functions are exported with no `STATUS`/`CFLAGS`
and no `GHIDRA` comment; import surfaces them as `proposed_missing` until created
with `--create-missing`.

### What Gets Exported

| Rebrew field | BinSync artifact | Location |
|---|---|---|
| `va` + `name`/`symbol` | Function name | `functions/<hex>.toml` `[info].name` |
| `size` | Function size | `functions/<hex>.toml` `[info].size` |
| `prototype` | Function signature | `functions/<hex>.toml` `[header].type` |
| `note` | Analyst note comment | `functions/<hex>.toml` `[comments]` at `va + 1` |
| `ghidra` | Ghidra-synced name comment | `functions/<hex>.toml` `[comments]` at `va + 2` (only when different) |
| DATA/GLOBAL entries | Global variable label + type | `global_vars.toml` (keys are decimal VAs — `functions/<hex>.toml` filenames are hex; matches BinSync's own layout) |
| Struct definitions | Struct type + fields | `structs/<name>.toml` |
| Export manifest | Freshness facts | `manifest.toml` (`exported_at`, `content_hash`, optional `commit`) |

### Rebrew Metadata Comment Format

`STATUS`/`CFLAGS` are verify-earned and never exported.  Notes and the
Ghidra-synced name travel as structured comments at offset addresses (to
avoid colliding with the function address itself):

```
268469377 = "[rebrew:note] Matches original exactly"
268469379 = "[rebrew:ghidra] OtherToolName"
```

(`va + 1` for the note, `va + 2` for a differing Ghidra name.)

### Function TOML Layout

```toml
# functions/10008880.toml
[info]
name = "_BitReverse@4"
addr = 268469376
size = 31

[header]
type = "int __cdecl BitReverse(int x)"

[comments]
268469377 = "[rebrew:note] Matches original exactly"
```

### Global Variables

DATA and GLOBAL annotations are written to `global_vars.toml` with their real
C types (resolved from `extern` declarations + data metadata; `char` fallback):

```toml
[268500000]
name = "g_szNotepad"
addr = 268500000
size = 64
type = "char[64]"
section = ".rdata"

[268500100]
name = "g_counter"
addr = 268500100
size = 4
type = "int"
```

`section` (`.data`/`.rdata`/`.bss`/…) round-trips both ways when present and
is omitted when empty, so foreign BinSync tools keep reading the file.

### Structs

Struct definitions are collected from `*.h` headers and source files via
tree-sitter and emitted with field-level detail:

```toml
# structs/Point.toml
[info]
name = "Point"

definition = "typedef struct {\n    int x;\n    int y;\n    char name[32];\n} Point;"

[fields.x]
type = "int"

[fields.y]
type = "int"

[fields.name]
type = "char[32]"
```

If `STRUCT:` annotations name a struct that isn't defined in any scanned header,
a minimal placeholder is still emitted (no `fields`).

---

## Import — `rebrew binsync-import <state-dir>`

Reads a BinSync state directory (own export or one produced by another tool)
and applies changes back into rebrew metadata/source:

- **Names** — BinSync `functions/<hex>.toml` `[info].name` → rebrew symbols
  (via `rebrew rename` cross-reference rewriting). Generic→meaningful is applied
  directly; meaningful↔meaningful raises a conflict.
- **Prototypes** — BinSync `[header].type` → `// PROTOTYPE:` inline annotations
  in the local `.c` files (PROTOTYPE is a file-only key, not metadata).
  Comparison is whitespace-normalized (formatting-only differences are not
  divergence); a differing local prototype raises a conflict like a name —
  `--accept-binsync` overwrites.
- **Globals** — BinSync `global_vars.toml` → `rebrew-data.toml` names, plus
  differing `type`/`size`/`section` written back.
- **Notes** — BinSync `[comments]` `[rebrew:note]` → rebrew `note` metadata
  (differing notes only; identical notes skipped).
- **Structs** — BinSync `structs/*.toml` definitions unknown locally land in
  `binsync_types.h`; known names are never overwritten. Definitions validate
  through the shared type model — unparseable ones import as comments, never
  as compile-breaking typedefs.

Conflict resolution mirrors `rebrew sync`:

```
CONFLICT 0x10001000: local=_OldName vs binsync=_NewName
```

- `--accept-binsync` — accept BinSync name (rewrites local files).
- `--accept-local` — keep local, record BinSync name as `GHIDRA` provenance.

`--module FILTER` restricts to one module; `--dry-run`/`--json` work as elsewhere.  For BinSync
functions with no local annotation but present in the catalog, import proposes a new STUB
(`proposed_missing`); pass `--create-missing` to materialize it (see `--create-missing` in the flag table).

### Examples

```bash
# Preview what would be imported
rebrew binsync-import ./binsync_state --dry-run

# Accept all BinSync renames
rebrew binsync-import ./binsync_state --accept-binsync

# Accept only one module
rebrew binsync-import ./binsync_state --module SERVER --accept-binsync

# Machine-readable summary
rebrew binsync-import ./binsync_state --dry-run --json | jq .
```

---

## Diff — `rebrew binsync-diff <state-dir>`

Read-only divergence report between the local project (reversed annotations +
catalog) and a BinSync state directory. Never writes; exits `1` when any
divergence exists (CI-friendly). Same filtering semantics as
`binsync-import --dry-run`.

- **Names** — generic-vs-meaningful and meaningful↔meaningful conflicts
- **Prototypes** — BinSync `[header].type` vs local prototype (whitespace-normalized)
- **Globals** — `global_vars.toml` labels missing or renamed locally
- **New in BinSync** — catalog-known functions present in BinSync but not yet
  reversed locally (the same population import surfaces as `proposed_missing`)
- **Freshness** — `manifest.toml` facts surfaced in `--json` (`exported_at`, `content_hash`)

```bash
rebrew binsync-diff ./binsync_state            # divergences (exit 1 if any)
rebrew binsync-diff ./state --json | jq .      # machine-readable report
rebrew binsync-diff ./state --module SERVER    # one module only
```

---

## Common Flags

All three commands support the standard rebrew surface (`binsync-diff` is
read-only: no `--dry-run` or `--accept-*`; it exits `1` on divergence):

| Flag | Effect |
|---|---|
| `--target NAME` | Operate on a specific target |
| `--module NAME` | Only this module (export filters, import/diff skip) |
| `--dry-run` | Preview without writing |
| `--json` | Machine-readable output |
| `--git` (export only) | Stage + `git commit` the state directory after writing |
| `--clean` (export only) | Delete orphan `functions/<hex>.toml` no longer in the catalog/annotations |
| `--create-missing` (import only) | Create STUB files for catalog-known BinSync functions with no local annotation |

### Export Examples

```bash
# Export to a directory
rebrew binsync-export ./binsync_state

# Export one module only
rebrew binsync-export ./binsync_state --module SERVER

# Export + git commit the state
rebrew binsync-export ./binsync_state --git

# Export for a specific target (multi-target project)
rebrew binsync-export ./binsync_state --target server

# Preview without writing (dry-run)
rebrew binsync-export ./binsync_state --dry-run

# Machine-readable summary
rebrew binsync-export ./binsync_state --json
```

---

## Coverage by Status

| Status | Name | Prototype | Metadata comment |
|--------|------|-----------|-----------------|
| EXACT / RELOC / PROVEN | ✅ | ✅ (if annotated) | ✅ |
| NEAR_MATCHING | ✅ | ✅ (if annotated) | ✅ |
| STUB | ✅ | ✅ (if annotated) | ✅ |
| LIBRARY | ✅ | ✅ (if annotated) | ✅ |
| (no STATUS) | ✅ | ✅ (if annotated) | omitted |

The metadata-comment column is notes and differing Ghidra names only —
`STATUS`/`CFLAGS` are verify-earned and never leave the project.

---

## Limitations (remaining)

- **No libbs yet** — BinSync state is written as plain TOML, not via the `libbs` crate. A future `libbs>=2.0` dependency will add libbs validation and stack-var/enum/typedef support.
- **No stack vars / locals** — per-function local variable names are not yet round-tripped.
- **No per-instruction comments** — function-level notes only.

---

## Related

- [`rebrew sync`](GHIDRA_SYNC.md) — bidirectional Ghidra sync via ReVa MCP
- [`rebrew catalog`](CLI.md#rebrew-catalog) — function registry and coverage grid
- [BinSync GitHub](https://github.com/binsync/binsync)
- [libbs](https://github.com/binsync/libbs)
