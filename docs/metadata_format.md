# Rebrew Metadata Format

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

`STATUS`, `CFLAGS`, `SKIP`, `GLOBALS`, `BLOCKER`, `BLOCKER_DELTA`, `SOURCE`,
`NOTE`, `SECTION`, `GHIDRA`, `ANALYSIS`, `ORIGIN`, `SIZE`

## Layer 2: Metadata TOML Files

All mutable metadata lives in per-directory TOML metadata files.

### `rebrew-function.toml`

Keyed by `MODULE.0xVA`:

```toml
[SERVER."0x10008880"]
status = "MATCHING"
cflags = "/O2 /Gd"
blocker = "needs vtable"
note = "register allocation differs in inner loop"
```

**Managed exclusively** by `rebrew.metadata`:

| Function                    | Purpose                        |
|-----------------------------|--------------------------------|
| `update_source_status()`    | Set STATUS (with PROVEN guard) |
| `update_field(key, value)`  | Set any non-STATUS field       |
| `remove_field(key)`         | Delete a field                 |
| `get_entry(directory, va)`  | Read an entry                  |

> **Never write `rebrew-function.toml` manually** — always go through the
> `rebrew.metadata` API.

### `rebrew-data.toml`

Keyed by `MODULE.0xVA`, used for GLOBAL/DATA entries:

```toml
[SERVER."0x10050000"]
size = 4
section = ".bss"
note = "player count"
```

Managed by `rebrew.data_metadata`.

## Status Lifecycle

STATUS values and their progression:

```
RELOC → STUB → MATCHING → EXACT → PROVEN
```

| Status     | Meaning                                         |
|------------|--------------------------------------------------|
| `RELOC`    | Default — not yet attempted                      |
| `STUB`     | Placeholder / blocked                            |
| `MATCHING` | Byte-match except relocations                    |
| `EXACT`    | Byte-identical to target                         |
| `PROVEN`   | Symbolically verified via `rebrew prove`         |

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
2. Write the values to the appropriate `rebrew-function.toml` metadata.
3. Leave only the reccmp marker line (`// FUNCTION: MODULE 0xVA`) inline.
