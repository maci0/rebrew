# Annotation Format Reference

## What goes in the `.c` file

New writers emit pure C and record a `MODULE.0xVA` row. An unmigrated file
may still carry a MODULE/VA marker. SIZE and CFLAGS are metadata-owned.
`rebrew source migrate-markers` moves function identity into `rebrew-functions.toml`
and data identity into `rebrew-data.toml`, and leaves pure C. Do not add markers
back to migrated files.

Unmigrated input the parser still reads:

```c
// FUNCTION: SERVER 0x10008880

int __cdecl bit_reverse(int x)
{
    return x;
}
```

Unmigrated library input:

```c
// LIBRARY: SERVER 0x10023714

int stub(void) { return 0; }
```

`LIBRARY` is origin. The provider is separate: a project `.c` is built from
source, and a unique member of a configured external archive is statically
linked. A row with neither stays unresolved. When both exist, the source wins.

Unmigrated stub input:
```c
// STUB: SERVER 0x1002dead

int stub(void) { return 0; }
```

> [!CAUTION]
> **Never manually edit `rebrew-functions.toml`.** All volatile metadata (STATUS, SIZE, CFLAGS,
> BLOCKER, NOTE, GHIDRA, …; full key list in the SKILL.md caution) is managed exclusively by Rebrew CLI tools:
> - `rebrew test` / `rebrew verify` → STATUS (EXACT/RELOC auto-promote; `--no-promote` skips the test write). Those clear BLOCKER unless the file still has `__asm`, `_asm`, or `__emit`
> - `rebrew blocker set/clear` → BLOCKER / BLOCKER_DELTA (ad-hoc; for STUBs diff cannot classify)
> - `rebrew diff --fix-blocker` / `rebrew diagnose near --fix-blocker` → BLOCKER / BLOCKER_DELTA (auto-classified)
> - `rebrew source document-unmatched` → STUB skeletons + BLOCKER for every unmatched function
> - `rebrew sync pull --state-dir <dir>` → NOTE, GHIDRA

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
`src/` for sources under `src/test/`) when a store sits there, otherwise the outermost
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

One pure-C body, one `MODULE.0xVA` row per target. Both rows name that file:

```c
void my_func(void) {}
```

```toml
# One rebrew-functions.toml at cfg.metadata_dir (e.g. src/ for src/test/):
["LEGO1.0x1009a8c0"]
file = "shared/my_func.c"
marker_type = "FUNCTION"
status = "EXACT"
size = 42

["BETA10.0x101832f7"]
file = "shared/my_func.c"
marker_type = "FUNCTION"
status = "NEAR_MATCHING"
size = 42
blocker = "register allocation"
```

The qualified key is the address an unmigrated marker line used to spell.
Two images can share a VA. An unmigrated file may still stack one marker
line per target; `rebrew source merge` and `rebrew source split` still
rearrange those lines. `--shared` records the destination row on the one file.

Shared files live under `src/shared` (one `MODULE.0xVA` row per target, per-target
`STATUS`). Shared headers live there too: a shared source finds them by
bare name (the shared root is on the include path). Move a per-target file
there with `rebrew source import-related --from <src> --promote`; import with
`--shared` instead of copying.

## Data Annotations

Data rows live in `rebrew-data.toml` (`file` plus `marker_type`). An unmigrated
`// DATA:` or `// GLOBAL:` line is still read, and `rebrew source migrate-markers`
moves it out of `.c` sources with the function markers. A marker-less header
is read from its row. Load `rebrew-data-analysis` before touching a global.
