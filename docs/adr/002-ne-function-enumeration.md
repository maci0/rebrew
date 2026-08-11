# ADR-002: NE function enumeration — Borland markers vs MSVC-style segments

- **Status**: Accepted
- **Date**: 2026-08

## Context

`enumerate_ne_functions` linear-sweeps NE code segments for 16-bit
prologs (`push bp` / `enter`) and walks to the next `ret`/`retf`.  The
original implementation hard-coded two Borland assumptions:

1. Every segment starts with a `[index\x00][name-string]` prefix.
2. Every function opens with `push bp` or `enter`.

Both are false for MSVC 16-bit NE binaries (e.g. the original 1991
SkiFree): segments start directly with code, and the entry function opens
`push ds / pop ax / nop / inc bp / push bp / mov bp, sp`.  The result was
a misaligned sweep that chopped the segment entry function and produced
233 garbage functions on ski16.exe.

## Decision

- Detect the Borland marker **conditionally** (`has_borland_marker`):
  only when `data[off] == segment_index and data[off+1] == 0` is the
  2-byte marker + name string skipped.  `probe_is_code` takes the segment
  index to make this check.
- For markerless (MSVC-style) segments, force a candidate at the segment
  start — the first bytes of a code segment are always a real function
  (entry point / LibMain / WinMain-adjacent startup), even without a
  recognizable prolog.
- Borland segments must NOT get the forced-start candidate: their content
  after the name string can be a far-call fixup table, and the real
  function only starts at its own prolog (holiday.exe regresses to a
  bogus 90-byte "function" over the table otherwise).

## Consequences

- ski16.exe: 137 correct functions (entry function recovered at 0x10000)
  vs 233 garbage; holiday.exe: unchanged at 1783 — both conventions
  enumerated correctly from one sweep.
- The sweep remains heuristic (prolog-anchored); non-prolog functions in
  the middle of a segment are still missed, same as before.
- `has_borland_marker` doubles as the toolchain-detection signal
  (ADR-005).
