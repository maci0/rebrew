# ADR-005: Toolchain detection — backend order, NE marker family, linker fallback

- **Status**: Accepted
- **Date**: 2026-08

## Context

`detect_toolchain` picks the compiler family/version that drives the
compiler profile and intake's blocker wording.  Two gaps surfaced from
the corpus:

1. 16-bit NE binaries reported `family="unknown"` — but the NE segment
   marker convention (ADR-002) identifies the family: Borland
   `[index\x00]` markers mean Delphi/Turbo Pascal, markerless segments
   with content mean MSVC 16-bit.
2. PE binaries whose diec record lacks a compiler entry (explorer.exe on
   Win2K SP4: only a Linker + Installer detection) got no version hint,
   even though the Microsoft Linker version pins the MSVC era.

## Decision

- Detection backend order stays best-first: DIE (`diec`) → PDB →
   structural heuristics, with the NE branch inserted after `load_binary`
   succeeds (NE binaries now load natively):
  - String evidence (RTL markers) outranks the marker heuristic — a
    stripped/synthetic NE may lack segment markers but still carry
    "Borland Delphi" strings.
  - Borland segment markers → `delphi` (high confidence); markerless
    segments with content → `msvc` "16-bit MSVC-style" (medium); a
    segment-less synthetic NE stays `unknown` (no evidence).
- `_diec_version_hint` falls back to the Microsoft Linker version when no
  compiler record exists, mapped through `_linker_era_hint`
  (5.x → MSVC 5.0, 6.x → 6.0, 7.0/7.1 → 7.0/7.1, 8.x/9.x → 8.0/9.0),
  labeled with the raw linker version ("MSVC 5.0 (linker 5.12.9049)").

## Consequences

- The full corpus is now family-classified: ski16 → msvc (16-bit),
  holiday → delphi (high conf), ski32/win2k → msvc with era hints;
  explorer.exe gets "MSVC 5.0 (linker 5.12.9049)" instead of a blank hint.
- The NE family feeds `intake` profile selection and blocker wording —
  the "compiler family not identified — defaulting to msvc6" note
  disappears for 16-bit MSVC targets.
- The linker fallback is honest about its source (labels the raw linker
  version), so a mislabeled era is diagnosable.
