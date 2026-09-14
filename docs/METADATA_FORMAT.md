# Rebrew Metadata Format

> **Scope:** This document covers the **TOML metadata files** (`rebrew-functions.toml`,
> `rebrew-data.toml`) that store volatile per-function fields (STATUS, SIZE, CFLAGS,
> TOOLCHAIN, BLOCKER, BLOCKER_DELTA, NOTE, GHIDRA, ANALYSIS, SKIP, GLOBALS, LOCALS,
> COMMENTS, SOURCE, PROVE_CONSTRAINTS) and data section metadata (NAME, TYPE, SIZE,
> SECTION, NOTE, STATUS).
> For the source-file marker format (`// FUNCTION: MODULE 0xVA`) and `library_*.h`
> headers see [ANNOTATIONS.md](ANNOTATIONS.md).
> For the **full store map** (canonical vs derived vs cache, who owns which
> fact, precedence, and why none of these TOMLs are hand-edited) see
> [METADATA.md](METADATA.md) — every write goes through `rebrew.metadata` /
> `rebrew.data_metadata` (locked + atomic), or the CLI gates
> (`rebrew blocker`, `rebrew test`/`verify`/`prove`, `rebrew library`, `rebrew data`).

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
- `// SIZE: N` — the **reccmp-native** compile contract (reccmp reads it
  from the `.c`).  The TOML `SIZE` is an *override*; lint W019 warns only
  when the two disagree.
- `// CFLAGS:` — same co-read contract: an external build reads the `.c`
  directly, so W019 warns only on inline↔metadata disagreement, never
  migrates.
- `// TOOLCHAIN:` / `// SOURCE:` / `// SECTION:` / `// STRUCT:` /
  `// CALLERS:` — structural/file-borne keys still read inline by
  `_kv_to_annotation` (the toolchain override and `// SOURCE: naked`
  must travel with the file; SECTION is owned by `rebrew-data.toml` for
  DATA/GLOBAL entries and never lands in `rebrew-functions.toml`).

### What does **not** stay inline

The following keys are **metadata-only** and must not appear in source files.
`rebrew lint` fires **W019** for any of these found inline.  `rebrew lint --fix`
migrates the storable ones to the correct TOML and also drops
W029-redundant per-function `cflags` that only repeat the inherited ladder.
`ORIGIN` (legacy everywhere) and `SECTION` on FUNCTION/LIBRARY/STUB markers
are never stored — `--fix` strips them instead of migrating.

`STATUS`, `SIZE`, `CFLAGS`, `TOOLCHAIN`, `SKIP`, `GLOBALS`, `BLOCKER`,
`BLOCKER_DELTA`, `SOURCE`, `NOTE`, `SECTION`, `GHIDRA`, `ANALYSIS`,
`PROVE_CONSTRAINTS`, `LOCALS`, `COMMENTS`
(`ORIGIN` also warns but is stripped, never stored)

## Layer 2: Metadata TOML Files

All mutable metadata lives in per-directory TOML metadata files.

### `rebrew-functions.toml`

Keyed by `MODULE.0xVA`:

```toml
["SERVER.0x10008880"]
status = "NEAR_MATCHING"
cflags = "/O2 /Gd"
blocker = "needs vtable"
note = "register allocation differs in inner loop"
```

**Managed exclusively** by `rebrew.metadata` (every write under
`metadata_write_lock` + `atomic_write_text` — never hand-edited):

| Function / CLI | Purpose |
|----------------|---------|
| `update_source_status()` / `update_statuses_batch()` | Set STATUS (PROVEN is sticky except against byte matches) — via `rebrew test` / `rebrew verify` / `rebrew prove` (also `match`, `lint`, `binsync-import`, `intake` tag their writes) |
| `update_field(key, value)` / `remove_field(key)` | Set / delete any non-STATUS field (e.g. BLOCKER) — via `rebrew blocker set` / `clear` |
| `get_entry(directory, va, module)` | Read an entry — via `rebrew blocker show` |
| `rebrew diff --fix-blocker` / `rebrew near-diag --fix-blocker` / `rebrew document-unmatched` | Auto-classified BLOCKER writers (same gated API underneath) |

> **Never write `rebrew-functions.toml` manually** — every BLOCKER, STATUS,
> CFLAGS, and NOTE write must go through the API above or its CLI gate
> (`rebrew blocker set/clear` for BLOCKER, `rebrew test`/`verify`/`prove`
> for STATUS, etc.). Hand-edits bypass the lock and get clobbered.

### `rebrew-data.toml`

Keyed by `MODULE.0xVA`, used for GLOBAL/DATA entries:

```toml
["SERVER.0x10050000"]
size = 4
section = ".bss"
note = "player count"
```

Owned fields per entry: `name`, `type`, `size`, `section`, `note`, `status`
(`VERIFIED`/`DRIFT`/`UNCHECKED` data verdicts, written by `verify --data`).

Managed exclusively by `rebrew.data_metadata` (locked + atomic) — via
`rebrew data` (scan/annotate), `rebrew sync --pull-data`, etc. Never
hand-edit `rebrew-data.toml` either.

## Status Lifecycle

STATUS values and their gate ranks (`verify._STATUS_RANK`):

```
EXACT (0) → RELOC (1) → PROVEN / STUB / NEAR_MATCHING / SIZE_MISMATCH / SKIP (2) → …
```

| Status           | Meaning                                         |
|------------------|--------------------------------------------------|
| `STUB`           | Placeholder / blocked                            |
| `NEAR_MATCHING`  | Partially matching (≥60% similarity)             |
| `RELOC`          | Byte-match after relocation masking              |
| `EXACT`          | Byte-identical to target                         |
| `PROVEN`         | Semantically verified via `rebrew prove` — ranks **below** `RELOC`: a proven function still compiles to differing bytes, so a byte match always overrides it |
| `SKIP`           | User-parked ("don't touch") — neutral gate rank, status-equal with `STUB` (`STUB`↔`SKIP` is silent in the `--compare` gate; see `verify._STATUS_RANK`/`_STATUS_ORDER`) |

`rebrew test`/`rebrew verify` also persist machine verdicts outside this
lifecycle: `SIZE_MISMATCH`, `COMPILE_ERROR`, `EXTRACT_ERROR`, `MISSING_SIZE`,
`MISSING_FILE`, `INVALID_VA` (see `rebrew.metadata.KNOWN_STATUSES`;
`INTERNAL_ERROR` is deliberately never persisted).

### PROVEN Guard

`update_source_status()` **refuses to demote** a PROVEN function unless
called with `force=True` — except for byte matches: `EXACT`/`RELOC` mean the
compiler reproduced the target's bytes, which is strictly stronger than the
semantic equivalence PROVEN records, so they promote without force.  This
prevents accidental regression while still recording a byte-match win.

## Migration

To strip all inline metadata keys from source files:

```bash
rebrew lint --fix
```

This will:
1. Remove `// STATUS:`, `// BLOCKER:`, etc. from `.c` files (leaving co-read
   `// SIZE:`/`// CFLAGS:` and file-borne `// TOOLCHAIN:`/`// SOURCE:`/
   `// SECTION:`/`// STRUCT:`/`// CALLERS:` in place).
2. Write the values to the appropriate TOML (`rebrew-functions.toml`, or
   `rebrew-data.toml` for DATA/GLOBAL markers).
3. Leave only the reccmp marker line (`// FUNCTION: MODULE 0xVA`) inline.
4. Drop W029-redundant per-function `cflags` (and matching
   `compiler.cflags_presets` keys that only repeat project `cflags`).
