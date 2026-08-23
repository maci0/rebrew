# Rebrew Metadata Format

> **Scope:** This document covers the **TOML metadata files** (`rebrew-function.toml`,
> `rebrew-data.toml`) that store volatile per-function fields (STATUS, CFLAGS, BLOCKER,
> NOTE, GHIDRA) and data section metadata (NAME, SIZE, SECTION, NOTE).
> For the source-file marker format (`// FUNCTION: MODULE 0xVA`) and `library_*.h`
> headers see [ANNOTATIONS.md](ANNOTATIONS.md).
> For the **full store map** (canonical vs derived vs cache, who owns which
> fact, precedence) see [METADATA.md](METADATA.md).

This document describes the two-layer metadata system used by rebrew to track
function and data metadata.

## Layer 1: Inline reccmp Markers (in `.c` files)

Only **one kind** of marker line remains inside source files — the
reccmp-compatible marker line:

```c
// FUNCTION: SERVER 0x10008880
```

Variants for different marker types:

| Marker      | Meaning                              |
|-------------|--------------------------------------|
| `FUNCTION`  | Game/application function            |
| `LIBRARY`   | Matched CRT / library function       |
| `STUB`      | Stub (unfinished / blocked)          |
| `GLOBAL`    | Global variable                      |
| `DATA`      | Read-only data (.rdata / .data)      |

### What stays inline

- `// FUNCTION: MODULE 0xVA`  (and LIBRARY/STUB/GLOBAL/DATA)

### What does **not** stay inline

The following keys are **metadata-only** and must not appear in source files.
`rebrew lint` fires **W019** for any of these found inline, and
`rebrew lint --fix` migrates them to the correct TOML.

`STATUS`, `CFLAGS`, `TOOLCHAIN`, `SKIP`, `GLOBALS`, `BLOCKER`, `BLOCKER_DELTA`,
`SOURCE`, `NOTE`, `SECTION`, `GHIDRA`, `ANALYSIS`, `ORIGIN`, `SIZE`,
`PROVE_CONSTRAINTS`

## Layer 2: Metadata TOML Files

All mutable metadata lives in per-directory TOML metadata files.

### `rebrew-function.toml`

Keyed by `MODULE.0xVA`:

```toml
["SERVER.0x10008880"]
status = "NEAR_MATCHING"
cflags = "/O2 /Gd"
blocker = "needs vtable"
note = "register allocation differs in inner loop"
```

**Managed exclusively** by `rebrew.metadata`:

| Function                    | Purpose                        |
|-----------------------------|--------------------------------|
| `update_source_status()`    | Set STATUS (with PROVEN guard) |
| `update_statuses_batch(metadata_dir, updates)` | Bulk STATUS updates (`rebrew verify`) with the same promotion rules |
| `update_field(key, value)`  | Set any non-STATUS field       |
| `remove_field(key)`         | Delete a field                 |
| `get_entry(directory, va, module)` | Read an entry                  |

> **Never write `rebrew-function.toml` manually** — always go through the
> `rebrew.metadata` API or the CLI gate `rebrew blocker set/clear`
> (other BLOCKER writers: `rebrew diff --fix-blocker`, `rebrew near-diag
> --fix-blocker`, `rebrew document-unmatched`).

### `rebrew-data.toml`

Keyed by `MODULE.0xVA`, used for GLOBAL/DATA entries:

```toml
["SERVER.0x10050000"]
size = 4
section = ".bss"
note = "player count"
```

Owned fields per entry: `name`, `size`, `section`, `note`.

Managed by `rebrew.data_metadata`.

## Status Lifecycle

STATUS values and their progression:

```
STUB → NEAR_MATCHING → RELOC → EXACT → PROVEN
```

| Status           | Meaning                                         |
|------------------|--------------------------------------------------|
| `STUB`           | Placeholder / blocked                            |
| `NEAR_MATCHING`  | Partially matching (≥60% similarity)             |
| `RELOC`          | Byte-match after relocation masking              |
| `EXACT`          | Byte-identical to target                         |
| `PROVEN`         | Semantically verified via `rebrew prove`         |

`rebrew test`/`rebrew verify` also persist machine verdicts outside this
lifecycle: `SIZE_MISMATCH`, `COMPILE_ERROR`, `EXTRACT_ERROR`, `MISSING_SIZE`,
`MISSING_FILE`, `INVALID_VA`, plus `SKIP` for user-skipped functions (see
`rebrew.metadata.KNOWN_STATUSES`).

### PROVEN Guard

`update_source_status()` **refuses to demote** a PROVEN function unless
called with `force=True`. This prevents accidental regression.

## Migration

To strip all inline metadata keys from source files:

```bash
rebrew lint --fix
```

This will:
1. Remove `// STATUS:`, `// CFLAGS:`, `// BLOCKER:`, etc. from `.c` files.
2. Write the values to the appropriate TOML (`rebrew-function.toml`, or
   `rebrew-data.toml` for DATA/GLOBAL markers).
3. Leave only the reccmp marker line (`// FUNCTION: MODULE 0xVA`) inline.
