# Post-Link Layout Normalization (`rebrew postlink`)

`rebrew postlink` converges a *built* binary's layout onto a *reference*
binary, byte-for-byte, after linking.  It exists because linkers — MSVC6's
`LINK.EXE` in particular — are **not source-order-preserving assemblers for
every section**: several parts of the output layout are determined by the
linker's internal hash-driven processing, so a recompilation whose *content*
is correct can still differ from the original build in *placement*.  These
differences are not decompilation errors; they are linker artifacts, and this
tool normalizes them away so a byte diff measures only real code/data
differences.

```
rebrew postlink <built.dll> <reference.dll> [--fix imports|data|pe-metadata|all] [--output out.dll]
rebrew postlink <built.dll> --layout layout/<target> [--fix ...]
```

Fixers run in dependency order (`imports` → `data` → `pe-metadata`); each is
idempotent, refuses to run when its preconditions are not met, and reports
what it changed (`--json` for machine-readable output).

## The reference: text-only layout metadata

The fixers never need the original DLL (or any binary snapshot): they
reconstruct the reference from a **text-only layout package** written by
`rebrew gen-layout` into `layout/<target>/` and committed to git:

- `layout.txt` — structured metadata (image base, sections with raw
  pointers, exports, imports with their reference IAT-slot VAs, export
  directory stamp);
- `header.hex`, `iat.hex`, `prefix.hex`, `bookkeeping.hex`, `data.hex`,
  `reloc.hex` — hex dumps of exactly the linker-stamped regions the fixers
  copy or check (the `prefix` is checked for drift, never copied);
- `operands.txt`, `calls.txt` — sparse `.text` maps (offset → reference
  value) covering every position the operand rewrites can touch.

Everything is plain text — zero binary bytes at rest — so a public checkout
reproduces the byte-identical DLL without the original binary.  A reference
DLL may still be passed directly; it is reduced to the same metadata in
memory.  Regenerate the package whenever the original changes
(`rebrew gen-layout --target <t>`).

---

## The three fixers

### 1. `imports` — import-layer placement

The MSVC6 linker assigns IAT slots and places the import descriptors, OFT
arrays, hint/name records and DLL-name strings in a hash-driven order that
rarely matches the original build's.  For an **identical import set** every
byte of that region is derived from the set — only its order is
linker-determined — so the fixer:

1. verifies the import set matches the reference (DLLs + entries, sorted so
   the comparison is order-insensitive — converging the IAT slot order is
   exactly this fixer's job), refusing otherwise;
2. rewrites `.text` operands that reference moved IAT slots (`call dword ptr
   [__imp_X]` addresses) to the reference's slot addresses;
3. verifies the `.rdata` prefix between the IAT and the import directory
   already matches the reference (a drift here means a *content* problem, not
   placement);
4. copies the IAT arrays and the import bookkeeping region verbatim.

This is the correct way to handle the "IAT order looks random" symptom; do
**not** fight it with `/OPT:REF` (which discards `/include`-only imports) or
by reordering objects.

### 2. `data` — data operands, `.data`, `.reloc`

The linker's `.data` COMDAT order is also hash-driven (not source-orderable),
and the built `.text`'s absolute data operands point at *our* global
addresses while the reference's point at *its* layout.  The fixer:

1. rewrites `.text` absolute data operands to the reference's values,
   scanning **every byte offset** (x86 operands are misaligned — a
   4-byte-aligned scan misses most of them) and covering the **full `.data`
   VirtualSize**, not just the raw size;
2. rewrites `E8`/`E9` relative call/jump targets, but only where the
   surrounding instruction context matches (so real code differences are
   never overwritten);
3. trims the extra `.text` tail the build carries beyond the reference's
   content end (import thunks pulled by `/include`, `link_stubs` placeholders,
   dead-stripped-in-the-original init code) and fixes `.text` VirtualSize;
4. grows `.data` to the reference's raw size and copies it, and replaces
   `.reloc` at the reference's file offset.

The `.data` copy is only valid because the content is genuinely
reconstructible — the same caveat as the project's `_emit`-dump pattern.  For
a strict decomp it should sit behind an explicit verification-build flag.

### 3. `pe-metadata` — toolchain-stamped headers

The MSVC6 link step stamps the DOS stub (Rich header, `e_lfanew`),
`TimeDateStamp`, an empty CheckSum, a too-small `.data` VirtualSize (BSS
placeholders are emitted as `char[1]`), a `.reloc` VA that predates the BSS
growth, and `SizeOfImage`.  Once the section layout has converged (same
names + RVAs), every one of those fields is derivable from the reference, so
the fixer copies the reference's full header block — COFF `Characteristics`,
optional header, and section table — verbatim.  The CheckSum is **copied**,
never recomputed: it covers the whole image, and a built `.text` that still
differs would never produce the reference's value.

---

## Generalized techniques

These insights came out of matching a real MSVC6-built `server.dll` and are
reusable across any decompilation that hits the same wall:

- **Hash-driven placement diagnostic.**  When the layout differs despite
  identical inputs, check for COMDAT/hash ordering (import records, `.data`)
  *before* assuming a source problem.  The signature is a region whose
  content is identical to the reference's but whose order differs.
- **`.data` raw vs VirtualSize.**  BSS globals live beyond the raw size — the
  operand-rewrite ranges must cover the full VirtualSize, or references into
  the BSS tail are silently missed.
- **Every-offset operand scan.**  Scan the `.text` at every byte offset, not
  4-aligned positions; x86 instruction operands are misaligned.
- **Context-matched rel32 rewrite.**  Only rewrite `E8`/`E9` operands when the
  preceding opcode and surrounding bytes match the reference — otherwise real
  code differences would be papered over.
- **The debug-directory trap.**  A `/debug` link emits an extra 0x1c-byte
  debug directory at the start of `.rdata` that shifts *everything* after it.
  Build the byte-identity artifact without debug info (`/Z7` + `/debug` off),
  or nothing below it will ever align.

---

## Integration

`rebrew postlink` is designed to run as a post-link step, e.g. a CMake
`POST_BUILD` command — against the committed text layout package, so the
build needs neither the original DLL nor any binary blob:

```cmake
add_custom_command(TARGET server_dll POST_BUILD
  COMMAND rebrew postlink "$<TARGET_FILE:server_dll>"
          --layout "${PROJECT_SOURCE_DIR}/layout/server.dll"
  VERBATIM)
```

It writes in place by default (use `--output` for a copy).  Each fixer is
idempotent and cheap, so running it on every link is fine.

## See also

- `rebrew postlink --help` — CLI reference
- `docs/TOOLCHAIN.md` — the MSVC6 compile/link backend
- `docs/GAP_ANALYSIS.md` — when to use placement fixes vs. real re-decompilation
