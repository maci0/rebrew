# ADR-010: Shared multi-version sources (`src/shared` + per-target defines)

- **Status**: Amended by [ADR-030](030-address-only-source.md) (address anchors and metadata-only state replace the `// FUNCTION:` marker)
- **Date**: 2026-08

## Context

A rebrew project can hold several targets (binary versions, or a DLL+EXE
pair), and `rebrew source import-related` (ADR-009, originally `cross-import`) propagates **identical** code
between them by copying the `.c` per target.  But two scenarios need the
*same source file* to serve multiple targets, not a copy:

1. **Same code, different VAs**: one function, one implementation, but the
   address differs per version.  Copying the file per target means the
   implementation can drift apart; the isledecomp/LEGO Island project keeps
   one file and stacks one address anchor per target.
2. **Mostly-same code**: a function differs between versions in a branch
   or a call.  isledecomp expresses the delta as `#ifdef BETA10` blocks
   compiled with a per-target `-D` macro, and excludes the hopelessly
   divergent functions from the secondary target entirely.

rebrew already has most of the primitives: per-target config with
`reversed_dir = src/<TARGET>`, per-target compiler flags, and per-target
metadata keyed by `module.va` in one `rebrew-functions.toml`.  What was
missing was a way for one source file to be discovered and compiled for
every target, plus a per-target compile-time define.  (At acceptance the
source carried a `// FUNCTION: <target> <va>` block; [ADR-030](030-address-only-source.md)
replaced that with an optional address anchor and moved every other field
into the metadata store.)

## Decision

1. **`[project] shared_dir`** (default `src/shared`, empty string disables):
   a project-level source root scanned for **every** target.  A file there
   may carry one optional `/* ADDRESS: <module> <va> */` anchor per target
   (the comment form follows `address_comments`); the anchor binds exactly
   the next C definition, and every other fact (STATUS, SIZE, flags,
   provenance) lives in metadata, not in the comment.  Each target's
   binding read (`read_source_bindings`, filtered by `target_name`) sees
   only its own `MODULE.0xVA` row.  The stored `filepath` is relative to
   the target's `reversed_dir` (`../shared/f.c`), which resolves back to the
   shared file for compile/verify without touching the resolution code.
   Metadata lives in the shared `rebrew-functions.toml` under per-target
   keys, so each target tracks its own status for the same source.
2. **`[targets.<name>] defines = ["V2"]`**: per-target compile-time defines,
   emitted as `/DV2` (MSVC) or `-DV2` (posix) on every compile for that
   target; the switch that makes `#ifdef V2` deltas in shared sources
   work.  Defines join the flag list, so they shape the compile-cache key
   automatically, and the verify cache stores them per entry so a defines
   edit invalidates cached results.
3. Source discovery goes through the existing single choke point
   (`iter_sources`), so verify/status/todo/catalog and the rest pick up
   shared sources with no per-tool changes.

## Consequences

- **Positive**: one implementation serves N versions; VAs stay per-target
  metadata; version deltas are ordinary `#ifdef` blocks driven by per-target
  defines; the isledecomp workflow (stacked address anchors, `#ifdef`
  deltas, per-version status) maps onto rebrew's per-target machinery with
  no schema changes to existing targets.
- **Negative**: a shared file compiles once per target; N targets mean N
  compiles of the same source (the compile cache keeps it cheap).  The
  `#ifdef`-divergent functions must still compile under **all** targets'
  defines (a branch guarded out per target is fine; a function that only
  exists in one version should stay in that target's own `reversed_dir`).
  The `target_name` binding filter requires the stored module to match the
  target exactly: a shared file whose row names the wrong target is
  silently invisible to that target's scan (same contract as per-target
  files).  Functions that diverged beyond `#ifdef`-ability are left out of
  the secondary target (or handled by `source import-related`'s copy flow; see
  [ADR-022](022-shared-single-file-imports.md) for automated `source import-related --shared`
  import and lint support).
- **Contract notes**: `shared_dir` defaults to `src/shared` for NEW
  projects; existing projects that happen to have a `src/shared` directory
  will start scanning it (documented; disable with `shared_dir = ""`).
  Shared files use the same address-anchor and metadata format as
  per-target files; no format changes.
