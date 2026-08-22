# ADR-001: Native 16-bit Windows NE parsing

- **Status**: Accepted
- **Date**: 2026-08

## Context

rebrew's target space includes 1990s Windows 3.x games and apps, many of
which are 16-bit NE executables (MZ stub + `NE` header): Borland Delphi 1.0
apps, Turbo Pascal for Windows, and 16-bit MSVC builds.  The PE/ELF/Mach-O
pipeline (LIEF) cannot parse them, rizin cannot analyze NE well enough for
function discovery, and the old behavior was to reject the format outright
("16-bit not supported").

## Decision

`load_binary` parses NE natively via `rebrew.ne_loader`:

- MZ `e_lfanew` locates the NE header (must be **sought to**, not assumed
  within the MZ stub — the MSVC 16-bit linker places it at 0x400, Borland
  at 0x40).
- Segment table, resident-name table (exports), module reference +
  imported names tables (imports), and the entry table are parsed.
- Segments map to `BinaryInfo` sections with synthetic flat VAs
  `(segment << 16 | offset)`, so every downstream tool (`strings`,
  `analyze`, `asm`, `describe`, `data`, `report`, `graph`) works on NE
  without special-casing beyond the `x86_16` arch preset.
- `is_ne(path)` gates the NE path ahead of LIEF; the signature is read at
  `e_lfanew` (a fixed 0x104-byte stub read missed MSVC binaries whose NE
  header sits at 0x400 — see ADR-002 for the symptom).

## Consequences

- A whole class of 1990s targets became onboardable end-to-end
  (holiday.exe: 1783 functions, 3739 strings; ski16.exe: 137).
- The synthetic flat-VA scheme means per-segment addressing is encoded in
  the VA; tools that assume a single linear image (PE relocs, IAT slots)
  degrade gracefully rather than misparse.
- Byte matching for 16-bit targets is **implemented** (not future work):
  the `msvc1.52` profile compiles C89 to 16-bit OMF inside the
  `rebrew/msvc:1.52-win16` image (DOSBox in-image; execution is docker-only
  per ADR-008), the built-in `omf16` parser decodes both OMF dialects
  (objconv crashes on them), and `test`/`verify`/`match --flag-sweep-only`
  run on NE targets (see TOOLCHAIN.md item 6).  Delphi's Borland ABI
  remains unmatchable — those functions are documented as blockers.
