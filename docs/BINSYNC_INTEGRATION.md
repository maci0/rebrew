# BinSync Export

`rebrew binsync-export <outdir>` writes a [BinSync](https://github.com/binsync/binsync)
state directory from the project's annotations and metadata. The output can be
loaded by any BinSync-aware decompiler plugin (IDA Pro, Binary Ninja, Ghidra).

---

## What Gets Exported

| Rebrew field | BinSync artifact | Location |
|---|---|---|
| `va` + `name`/`symbol` | Function name | `functions/<hex>.toml` `[info].name` |
| `size` | Function size | `functions/<hex>.toml` `[info].size` |
| `prototype` | Function signature | `functions/<hex>.toml` `[header].type` |
| `status`, `cflags` | Rebrew metadata comment | `functions/<hex>.toml` `[comments]` |
| `note` | Analyst note comment | `functions/<hex>.toml` `[comments]` |
| `ghidra` | Ghidra-synced name comment | `functions/<hex>.toml` `[comments]` |
| DATA/GLOBAL entries | Global variable label | `global_vars.toml` |
| Struct definitions | Struct type | `structs/<name>.toml` |

### Rebrew Metadata Comment Format

Rebrew-specific fields have no BinSync equivalent, so they are stored as a
structured comment at the function's address:

```
[rebrew] STATUS=EXACT CFLAGS=/O1 /Gd/Oy
```

If a `// NOTE:` or `// GHIDRA:` annotation is present, a separate comment is
added at `va + 1` (offset, to avoid collision):

```
[rebrew:note] Stubbed via GlobalFree wrapper
```

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
268469376 = "[rebrew] STATUS=EXACT CFLAGS=/O1 /Gd"
268469377 = "[rebrew:note] Matches original exactly"
```

### Global Variables

DATA and GLOBAL annotations are written to `global_vars.toml`:

```toml
[268500000]
name = "g_szNotepad"
addr = 268500000
size = 64
type = "char"
```

### Structs

If `STRUCT:` annotations are present, they're emitted to `structs/<name>.toml`:

```toml
[info]
name = "NPSTATE"

[fields]
# (libbs-compatible struct field entries)
```

---

## Usage

```bash
# Export to a directory
rebrew binsync-export ./binsync_state

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
| MATCHING / MATCHING_RELOC | ✅ | ✅ (if annotated) | ✅ |
| STUB / EXACT_STUB | ✅ | ✅ (if annotated) | ✅ |
| LIBRARY | ✅ | ✅ (if annotated) | ✅ |
| (no STATUS) | ✅ | ✅ (if annotated) | omitted |

---

## Limitations

- **No bidirectional sync** — export only; changes in IDA/BinNinja don't flow back.
- **EAX-only semantics** — rebrew metadata fields (STATUS, CFLAGS) have no native BinSync equivalent; stored as structured comments that other tools cannot parse without custom logic.
- **Struct fields** — emitted as raw TOML placeholders; actual field types require libbs-compatible struct serialization.
- **No auto-push** — the output is a static snapshot; re-run after new annotations or verified matches.

---

## Related

- [`rebrew sync`](GHIDRA_SYNC.md) — bidirectional Ghidra sync via ReVa MCP
- [`rebrew catalog`](CLI.md#rebrew-catalog) — function registry and coverage grid
- [BinSync GitHub](https://github.com/binsync/binsync)
- [libbs](https://github.com/binsync/libbs)
