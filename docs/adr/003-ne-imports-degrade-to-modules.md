# ADR-003: NE import parsing degrades to module list, never fabricates

- **Status**: Accepted
- **Date**: 2026-08

## Context

The NE import-table parser assumed the classic layout: per module, a
uint16 count followed by uint16 entries, located right after the entry
table.  In practice:

- MSVC-built NEs (ski16.exe) place the **non-resident name table** where
  the classic import table should be — its first Pascal string length byte
  + name byte read as an absurd count (0x5308), producing 21,256 fake
  ordinal imports.
- Borland binaries differ too (holiday.exe: "WAVEMIX: 18443 imports").
- Many Win16 binaries genuinely carry no classic import table; their
  imports flow through entry-table entries + segment thunks.

The parser never validated counts, so garbage silently propagated into
`analyze`, `imports`, `describe`, and `report` — thousands of fabricated
"ordinals" presented as real data.

## Decision

`parse_imports` sanity-gates the import table:

- A per-module count outside `1..0x1000` (or past the file) aborts the
  table walk — the module list is kept, per-API detail is dropped.
- By-name offsets must resolve to a printable Pascal string inside the
  imported names table; otherwise the block is treated as misplaced.
- `rebrew imports` reports module-level records (dll + empty name) when a
  module has no recoverable detail, so the DLL set stays visible.

Per-API Win16 imports via entry-table analysis is explicitly **future
work**, documented as such — not approximated by guessing.

## Consequences

- ski16.exe: KERNEL/GDI/USER modules, zero fabricated ordinals; holiday:
  13 real module references (duplicate KERNEL entries are genuine — the
  names table contains "KERNEL" at several offsets).
- Analysis output is smaller but honest; a reverser can trust that an
  empty import list means "no recoverable detail", not "no imports".
- The old garbage would have misled library-identification and name
  recovery; that class of silent corruption is now structurally
  impossible (out-of-range counts cannot pass).
