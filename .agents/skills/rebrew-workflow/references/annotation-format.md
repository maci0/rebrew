# Annotation Format Reference

## What goes in the `.c` file

Unmigrated function source carries a stable MODULE/VA marker. Legacy
SIZE/CFLAGS are co-readable; other volatile fields belong in metadata.
`rebrew migrate-markers` moves function identity into the store and leaves
pure C. Do not add markers back to migrated files.

An unmigrated example:

```c
// FUNCTION: SERVER 0x10008880

int __cdecl bit_reverse(int x)
{
    return x;
}
```

For library functions:

```c
// LIBRARY: SERVER 0x10023714

int stub(void) { return 0; }
```

For stubs:
```c
// STUB: SERVER 0x1002dead

int stub(void) { return 0; }
```

> [!CAUTION]
> **Never manually edit `rebrew-functions.toml`.** All volatile metadata (STATUS, SIZE, CFLAGS,
> BLOCKER, NOTE, GHIDRA, …; full key list in the SKILL.md caution) is managed exclusively by Rebrew CLI tools:
> - `rebrew test` / `rebrew verify` → STATUS (EXACT/RELOC auto-promote; `--no-promote` skips the test write). Those clear BLOCKER unless the file still has `__asm`, `_asm`, or `__emit`
> - `rebrew blocker set/clear` → BLOCKER / BLOCKER_DELTA (ad-hoc; for STUBs diff cannot classify)
> - `rebrew diff --fix-blocker` / `rebrew near-diag --fix-blocker` → BLOCKER / BLOCKER_DELTA (auto-classified)
> - `rebrew document-unmatched` → STUB skeletons + BLOCKER for every unmatched function
> - `rebrew sync --pull --state-dir <dir>` → NOTE, GHIDRA

## What goes in `rebrew-functions.toml` metadata file

Illustrative managed output, not a file to edit:

```toml
["SERVER.0x10008880"]
status = "EXACT"
size = 31

["SERVER.0x10023714"]
status = "STUB"
size = 103
cflags = "/O1"
blocker = "missing CRT internals"
source = "ENVIRON.C"
```

The metadata file lives **only** at `cfg.metadata_dir`: the parent of `reversed_dir` (e.g.
`src/` for sources under `src/bench/`) when a store sits there, otherwise the outermost
`rebrew-functions.toml` found walking up to the project root, so one store serves every
target of a multi-target project. The loader does no walk-up of its own: it reads exactly
`directory / rebrew-functions.toml`, so library code must pass `cfg.metadata_dir`, not the
`.c` file's directory. This includes **`rebrew lint`**,
which reads the metadata file before validation so that STATUS, SIZE, CFLAGS etc. are accessible
even when not present inline.

## Status Progression

STUB -> NEAR_MATCHING -> RELOC -> EXACT
           \-> PROVEN (via rebrew prove)

Byte verdicts come from `rebrew test` / `rebrew verify`, including regressions.
PROVEN records bounded semantic evidence, earns no matched bytes, and the next
byte verdict replaces it. Never edit STATUS by hand.

`updated_by` / `updated_at` describe ordinary edits. `origins` holds per-field
external source facts; `verification` holds the comparison inputs and measurement
time independently. Repeating identical evidence preserves its timestamp;
changing source, headers, or compiler inputs requires another comparison.

## Multi-Target

Same function body, multiple marker lines:

```c
// FUNCTION: LEGO1 0x1009a8c0

// FUNCTION: BETA10 0x101832f7
void my_func() {}
```

Each target has its own metadata file entry, keyed by `MODULE.0xVA`:

```toml
# A single rebrew-functions.toml at cfg.metadata_dir (e.g. src/ for src/bench/):
["LEGO1.0x1009a8c0"]
status = "EXACT"
size = 42

["BETA10.0x101832f7"]
status = "NEAR_MATCHING"
size = 42
blocker = "register allocation"
```

Using qualified keys prevents collision if two targets ever happen to share
the same VA (which can occur when multiple DLLs are compiled from the same
base address). The key format directly mirrors the `// FUNCTION: MODULE 0xVA`
marker line.

Shared files live under `src/shared` (one marker per target, per-target
`STATUS`). Shared headers live there too: a shared source finds them by
bare name (the shared root is on the include path). Move a per-target file
there with `rebrew cross-import --from <src> --promote`; import with
`--shared` instead of copying.

## Data Annotations

`// DATA:` and `// GLOBAL:` markers, their `rebrew-data.toml` fields, and the
`rebrew data` commands that write them are the `rebrew-data-analysis` skill's
subject. Load that skill for a data marker or a global you are about to touch.
