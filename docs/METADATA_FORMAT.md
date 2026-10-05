# Rebrew Metadata Format

> **Scope:** This document covers the **TOML metadata files** (`rebrew-functions.toml`,
> `rebrew-data.toml`) that store volatile per-function fields (STATUS, SIZE, CFLAGS,
> TOOLCHAIN, BLOCKER, BLOCKER_DELTA, NOTE, GHIDRA, ANALYSIS, SKIP, GLOBALS, LOCALS,
> COMMENTS, SOURCE, PROVE_CONSTRAINTS, ORIGINS, VERIFICATION, and ordinary edit stamps UPDATED_BY / UPDATED_AT)
> and data section metadata (NAME, TYPE, SIZE,
> SECTION, NOTE, STATUS, ORIGINS, VERIFICATION).
> For the source-file marker format (`// FUNCTION: MODULE 0xVA`) and `library_*.h`
> headers see [ANNOTATIONS.md](ANNOTATIONS.md).
> For the **full store map** (canonical vs derived vs cache, who owns which
> fact, precedence, and why none of these TOMLs are hand-edited) see
> [METADATA.md](METADATA.md); every write goes through `rebrew.metadata` /
> `rebrew.data_metadata` (locked + atomic), or the CLI gates
> (`rebrew blocker`, `rebrew test`/`verify`/`prove`, `rebrew library`, `rebrew data list`).

## Layer 1: Legacy inline markers (in `.c` files)

New writers do not emit these lines. An unmigrated function source may still
carry a reccmp-compatible identity marker, which the parser reads.
`rebrew source migrate-markers` moves function identity into `rebrew-functions.toml`
and data identity (`file`, `marker_type`, plus name, type, size, and section
when the row lacks them) into `rebrew-data.toml`, then leaves pure C. Do not
restore markers in migrated files. An unmigrated function example:

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

- `// FUNCTION: MODULE 0xVA`  (and LIBRARY/STUB/GLOBAL/DATA), until
  `rebrew source migrate-markers` records the row and strips the line.
- `// SIZE: N`: metadata-owned. An equal inline copy (including `32` and
  `0x20`) is stripped by `rebrew lint --fix`. A disagreement warns and the
  store wins.
- `// CFLAGS:`: metadata-owned, same rule. Disagreement ignores flag order
  and `/D` defines. An inline CFLAGS with no metadata value is migrated.
- `// SOURCE: naked`: the file-borne naked-reconstruction marker, exempt
  from W019.  Any other inline `// SOURCE:` value warns.
- `// SECTION:` / `// STRUCT:` / `// CALLERS:`: structural keys read
  inline by `_kv_to_annotation` (SECTION is owned by `rebrew-data.toml` for
  DATA/GLOBAL entries and never lands in `rebrew-functions.toml`).

### What does **not** stay inline

The following keys are **metadata-only** and must not appear in source files.
`rebrew lint` fires **W019** for any of these found inline.  `rebrew lint --fix`
migrates the storable ones to the correct TOML and also drops
W029-redundant per-function `cflags` that only repeat the inherited ladder.
`ORIGIN` (legacy everywhere) and `SECTION` on FUNCTION/LIBRARY/STUB markers
are never stored: `--fix` strips them instead of migrating.

`STATUS`, `TOOLCHAIN`, `SKIP`, `GLOBALS`, `BLOCKER`, `BLOCKER_DELTA`, `NOTE`,
`GHIDRA`, `ANALYSIS`, `SOURCE` (except `naked`), `PROVE_CONSTRAINTS`, `LOCALS`,
`COMMENTS`, `ORIGINS`, `VERIFICATION`
(`ORIGIN`, `UPDATED_BY` and `UPDATED_AT` also warn but are stripped, never
stored; a stamp is written by the tools, so migrating an inline copy would
overwrite the real one; `SECTION` on
FUNCTION/LIBRARY/STUB markers is stripped; DATA/GLOBAL SECTION lives in
`rebrew-data.toml`.  `SIZE` and `CFLAGS` are metadata-owned (an equal inline
copy migrates; a disagreement stays inline because the store wins).
`SOURCE: naked` stays file-borne.  `LOCALS`, `COMMENTS` and
`PROVE_CONSTRAINTS`, `ORIGINS`, and `VERIFICATION` are tables, so `--fix` warns but cannot migrate an inline
scalar.)

## Layer 2: Metadata TOML Files

All mutable function and data metadata lives in single root TOML metadata files (`rebrew-functions.toml`, `rebrew-data.toml`) at `cfg.metadata_dir`.

### `rebrew-functions.toml`

Keyed by `MODULE.0xVA`:

Addresses use ASCII hexadecimal digits without spaces or underscores; `0X`
is also accepted. Module names may contain dots and are normalized to Unicode
NFC so cached and raw readers resolve the same identity.

Multiple key spellings for the same `(module, VA)` are reported by lint W031.
Readers merge their fields, with later values winning, and count the identity
once. Granular writers refuse ambiguous stores before changing them, since
updating or deleting one spelling can leave another overriding that change.

```toml
["SERVER.0x10008880"]
status = "NEAR_MATCHING"
cflags = "/O2 /Gd"
blocker = "needs vtable"
note = "register allocation differs in inner loop"
```

**Managed exclusively** by `rebrew.metadata` (every write under
`metadata_write_lock` + `atomic_write_locked`; never hand-edited):

| Function / CLI | Purpose |
|----------------|---------|
| `update_source_status()` / `update_statuses_batch()` | Set STATUS through the promotion gate (SKIP stays parked): via `rebrew test` / `rebrew verify` / `rebrew prove` (also `match`, `lint`, `binsync-import`, `intake` tag their writes) |
| `update_field(directory, va, key, value, module)` / `remove_field(directory, va, key, module)` | Set / delete any non-STATUS field (e.g. BLOCKER): via `rebrew blocker set` / `clear` |
| `get_entry(directory, va, module)` | Read an entry: via `rebrew blocker show` |
| `rebrew diff --fix-blocker` / `rebrew diagnose near --fix-blocker` / `rebrew source document-unmatched` | Auto-classified BLOCKER writers (same gated API underneath) |

#### Owned fields

`rebrew.metadata.METADATA_FIELDS` is the authoritative set; these are the
shapes that matter for a hand-written script or a review:

| Field | Value | Written by |
|---|---|---|
| `STATUS` | one of the twelve `rebrew.metadata.KNOWN_STATUSES` values: the six ladder values below plus the six machine verdicts | the STATUS writers only, through the promotion gate |
| `SIZE` | non-negative integer | annotation migration, `rebrew verify --fix-sizes`, `rebrew coverage catalog --fix-sizes`; an inline `// SIZE:` is migration debt, not a second contract |
| `CFLAGS`, `TOOLCHAIN` | string | `rebrew cfg module set-cflags` / `set-compiler`, library-override resolution, lint `--fix`; an inline `// CFLAGS:` is migration debt |
| `BLOCKER`, `BLOCKER_DELTA` | string / integer | `rebrew blocker set/clear`, `rebrew diff --fix-blocker`, `rebrew diagnose near --fix-blocker`, `rebrew source document-unmatched`; cleared on a byte match |
| `NOTE`, `GHIDRA`, `ANALYSIS` | string | `update_field` (`rebrew blocker`/lint migrations, BinSync pull) |
| `SKIP` | boolean | a manual park through `update_field`; the promotion gate then keeps the row parked (no status write silently unparks it) |
| `GLOBALS`, `LOCALS`, `COMMENTS`, `PROVE_CONSTRAINTS` | `GLOBALS` a list of strings, the other three tables | `GLOBALS` from `rebrew sync pull`, the rest from analysis and prove writers; an inline scalar for the three table fields warns (W019) but cannot migrate, while an inline `GLOBALS` migrates as a list |
| `SOURCE` | string | stays in the `.c` as `// SOURCE: naked`: file-borne, W019-exempt, and self-clearing when the real C body replaces it; a non-naked value is migration debt that `lint --fix` moves into the TOML |
| `ORIGINS` | table keyed by native integration field | successful BinSync pulls; retains tool/user/snapshot and the accepted value digest |
| `VERIFICATION` | table with status, writer, input_hash and measured_at | comparison writers; retained independently of ordinary edits |
| `UPDATED_BY`, `UPDATED_AT` | string / ISO-8601 UTC | every gated writer, as a pair: STATUS through `update_source_status` / `update_statuses_batch`, every other field through `update_field` / `set_fields` (and `MetadataEntry.apply`) |

Function writers and lint W031 share `validate_metadata_field`; W031 also
reports unknown verdicts, incorrectly typed marker identities, and field
names whose case would make readers ignore them. `MetadataEntry.apply`
validates the complete edit and writes STATUS and associated fields in one
atomic replacement. An invalid value or serialization failure leaves the
previous verdict and blockers intact. STATUS parking rules still apply.
`status` marks the last verification stale when function metadata changes
after it, including compile input edits that leave the source untouched.

Nested locals, comments, and constraint tables are sanitized before TOML
serialization, including strings inside arrays and table keys. Sanitization
that would merge distinct keys is rejected rather than discarding a value.

**Provenance names the last write of any kind.** `UPDATED_BY` is one of
`test`, `verify`, `prove`, `match`, `diff`, `near-diag`, `blocker`, `skeleton`,
`lint`, `cross-import`, `binsync-import`, `fix-sizes`, `intake`, plus `rename`
on data rows, and it names the tool that wrote the row most recently, so a
`BLOCKER` edit through
`update_field` stamps itself instead of leaving a months-old `verify` tag
standing on the row.  A writer that passes no tag keeps the stored stamp.
`rebrew-data.toml` carries the same pair, tagged by whichever data writer ran:
`verify` from `verify --data` on each verdict, `rename` on a renamed global,
`data` from `rebrew data list`, `lint` on a migrated data marker; see
[Write provenance](METADATA.md#write-provenance).

> **Never write `rebrew-functions.toml` manually**: every BLOCKER, STATUS,
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

Owned fields per entry: `file`, `marker_type` (`GLOBAL`, `DATA`, `VTABLE`,
or `STRING`; the identity `rebrew source migrate-markers` writes), `name`,
`type`, `size`, `section`, `note`, `status`
(`VERIFIED`/`DRIFT`/`UNCHECKED` data verdicts, written by `verify --data`), and
the `updated_by` / `updated_at` write stamp every gated writer records.
`record_migrated_data_markers` fills a missing name, type, size, or section
without clearing `status`. `rebrew data set` still clears a verdict when
those definition fields change.

`size` is stored as a non-negative integer; the other data fields are strings.
The writers and lint W031 share this validation. A changed `name`, `type`,
`size`, or `section` clears the old verdict, so reports show `UNCHECKED` until
verification measures the new definition. Notes and unchanged values preserve
the verdict. A batch may record a definition and its new measured verdict in
the same atomic write.

Without an explicit `size`, verification and accounting infer only supported
fixed-size types and complete constant arrays under the x86_32 size model.
Unknown typedefs/structs, unresolved or omitted bounds, complex declarators,
and other architectures require an explicit size. They remain `UNCHECKED`
instead of earning `VERIFIED` from a guessed matching prefix. Standard
spellings such as `short int` retain their correct widths.

Data verification reports and writes verdicts by `(module, VA)`, even when
symbols share names or addresses. Each symbol is checked over its own extent;
equal truncated buffers cannot earn `VERIFIED`. Other targets stay outside
the report's denominator and write-back.

Managed exclusively by `rebrew.data_metadata` (locked + atomic): via
`rebrew data list` (the bare command scans; `--annotate`, `--set-type`,
`--set-section`, `--fix-bss`), `rebrew verify --data`, and `rebrew source rename`.
`rebrew sync pull-data` does not touch it: that writes the derived
`rebrew_globals.h`.  Never hand-edit `rebrew-data.toml` either.

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
| `PROVEN`         | Semantically verified via `rebrew prove`: ranks **below** `RELOC`: a proven function still compiles to differing bytes, so it is not matched and the next test/verify records the byte result over it |
| `SKIP`           | User-parked ("don't touch"): neutral gate rank, status-equal with `STUB` (`STUB`↔`SKIP` is silent in the `--compare` gate; see `verify._STATUS_RANK`/`_STATUS_ORDER`) |

`rebrew test`/`rebrew verify` also persist machine verdicts outside this
lifecycle: `SIZE_MISMATCH`, `COMPILE_ERROR`, `EXTRACT_ERROR`, `MISSING_SIZE`,
`MISSING_FILE`, `INVALID_VA` (see `rebrew.metadata.KNOWN_STATUSES`;
`INTERNAL_ERROR` is deliberately never persisted).

### Promotion Gate

`update_source_status()` refuses, unless called with `force=True`, to
overwrite a parked `SKIP`, to replace a `STUB` with a placeholder
`SIZE_MISMATCH`/`MISSING_SIZE`, or to rewrite an unchanged status.  `PROVEN`
has no protection: a byte verdict replaces it.

## Migration

To strip all inline metadata keys from source files:

```bash
rebrew lint --fix
```

This will:
1. Remove `// STATUS:`, `// SIZE:`, `// CFLAGS:`, `// BLOCKER:`,
   `// TOOLCHAIN:`, and the other metadata-owned keys from `.c` files when
   the copy matches the store or the store has no value. A disagreement is
   left in place. File-borne `// SOURCE: naked` and structural `// STRUCT:` /
   `// CALLERS:` stay. Other `// SOURCE:` values migrate. `// SECTION:` on
   DATA/GLOBAL migrates to `rebrew-data.toml`, and on functions is a legacy
   key that `--fix` strips.
2. Write the values to the appropriate TOML (`rebrew-functions.toml`, or
   `rebrew-data.toml` for DATA/GLOBAL markers).
3. Leave the legacy marker line (`// FUNCTION: MODULE 0xVA`) in place.
   `rebrew source migrate-markers` is the command that strips it.
4. Drop W029-redundant per-function `cflags` (and matching
   `compiler.cflags_presets` keys that only repeat project `cflags`).
