# Architecture Decision Records (ADR)

Decision records for rebrew's architecture.  Each ADR captures a
significant design choice: the context that forced it, the decision
itself, and the consequences (including trade-offs accepted).

## Convention

- Records live in `docs/adr/` as `NNN-short-title.md`, numbered in the
  order they were written.
- Every ADR has four sections: **Status**, **Context**, **Decision**,
  **Consequences**.
- Status values: `Accepted` (in force), `Superseded by NNN`, `Proposed`.
- Write a new ADR when a change is architectural: a new format/profile/
  backend, a behavioral contract change, or a deliberate trade-off that
  future readers must not silently undo.  Small fixes and polish do not
  need an ADR — the CHANGELOG covers those.

## Records

| ADR | Title |
| --- | --- |
| 001 | Native 16-bit Windows NE parsing |
| 002 | NE function enumeration: Borland markers vs MSVC-style segments |
| 003 | NE import parsing degrades to module list, never fabricates |
| 004 | Intake re-discovery prunes only exact auto-stubs |
| 005 | Toolchain detection: backend order + NE marker family + linker fallback |
| 006 | Standardized toolchain invocation (docker-first, host fallback) |
| 007 | Complete containerization + unified byte-reproducibility gate |
| 008 | Docker-only toolchain execution (no host wine/dosbox) |
