# Annotation Format Reference

## What goes in the `.c` file

The `.c` file contains **only the marker line** — stable identity that never changes:

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
// SOURCE: ENVIRON.C

int stub(void) { return 0; }
```

For stubs:
```c
// STUB: SERVER 0x1002dead

int stub(void) { return 0; }
```

> [!CAUTION]
> **Never manually edit `rebrew-functions.toml`.** All volatile metadata (STATUS, SIZE, CFLAGS,
> BLOCKER, NOTE, GHIDRA) is managed exclusively by Rebrew CLI tools:
> - `rebrew promote` → STATUS
> - `rebrew match --fix-blocker` → BLOCKER / BLOCKER_DELTA
> - `rebrew match --flag-sweep-only --fix-cflags` → CFLAGS
> - `rebrew sync --pull` → NOTE, GHIDRA

## What goes in `rebrew-functions.toml` sidecar

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

The sidecar file is found automatically by all rebrew tools via walk-up from the
source file's directory (climbs parent dirs until `rebrew-functions.toml` is found),
so a single file at a project root can serve all subdirectories. Tools including — including **`rebrew lint`**, which reads the
sidecar before running validation so that STATUS, SIZE, CFLAGS etc. are visible
even when not present inline.

## Status Progression

STUB -> MATCHING -> RELOC -> EXACT
           \-> PROVEN (via rebrew prove)

Managed via `rebrew promote`. Never edit STATUS by hand.

## Multi-Target

Same function body, multiple marker lines:

```c
// FUNCTION: LEGO1 0x1009a8c0

// FUNCTION: BETA10 0x101832f7
void my_func() {}
```

Each target has its own sidecar entry, keyed by `MODULE.0xVA`:

```toml
# A single rebrew-functions.toml found via walk-up (e.g. at src/server.dll/):
["LEGO1.0x1009a8c0"]
status = "EXACT"
size = 42

["BETA10.0x101832f7"]
status = "MATCHING"
size = 42
blocker = "register allocation"
```

Using qualified keys prevents collision if two targets ever happen to share
the same VA (which can occur when multiple DLLs are compiled from the same
base address). The key format directly mirrors the `// FUNCTION: MODULE 0xVA`
marker line.

## Data Annotations

DATA/GLOBAL metadata lives in a **`rebrew-data.toml` sidecar** — the data
analogue of `rebrew-functions.toml`. Only the stable marker line stays in
the `.c` file:

**`.c` file:**
```c
// DATA: SERVER 0x10025000

const unsigned char g_sprite_lut[256] = { ... };
```

**`rebrew-data.toml`** (auto-managed, found via walk-up from source dir):
```toml
["SERVER.0x10025000"]
name    = "g_sprite_lut"      # preferred label (BinSync/IDA import target)
size    = 256
section = ".rdata"
note    = "lookup table for sprite indices"
```

> [!NOTE]
> `name` is the primary BinSync/IDA interop field. When `rebrew sync --pull`
> receives a renamed data label from Ghidra it writes the name here (not inline).

> [!CAUTION]
> **Never manually edit `rebrew-data.toml`.** It is managed automatically by
> `rebrew data`, `rebrew data --fix-bss`, and `rebrew sync --pull`.

## Global Annotations

```c
// GLOBAL: SERVER 0x10050000
extern int g_frame_counter;
```

Metadata (size, section, note, name) goes in `rebrew-data.toml` — same format as DATA.
