# ADR-010: Shared multi-version sources (`src/shared` + per-target defines)

## Status

Accepted

## Context

A rebrew project can hold several targets (binary versions, or a DLL+EXE
pair), and `rebrew cross-import` (ADR-009) propagates **identical** code
between them by copying the `.c` per target.  But two scenarios need the
*same source file* to serve multiple targets, not a copy:

1. **Same code, different VAs** — one function, one implementation, but the
   address differs per version.  Copying the file per target means the
   implementation can drift apart; the isledecomp/LEGO Island project keeps
   one file and stacks one annotation marker per target.
2. **Mostly-same code** — a function differs between versions in a branch
   or a call.  isledecomp expresses the delta as `#ifdef BETA10` blocks
   compiled with a per-target `-D` macro, and excludes the hopelessly
   divergent functions from the secondary target entirely.

rebrew already has most of the primitives: per-target config with
`reversed_dir = src/<TARGET>`, per-target compiler flags, the same
`// FUNCTION: <target> <va>` marker syntax, and per-target metadata keyed by
`module.va` in one `src/rebrew-function.toml`.  What was missing was a way
for one source file to be discovered and compiled for every target, plus a
per-target compile-time define.

## Decision

1. **`[project] shared_dir`** (default `src/shared`, empty string disables):
   a project-level source root scanned for **every** target.  A file there
   may carry one `// FUNCTION: <target> <va>` marker per target; each
   target's scan (via `parse_c_file_multi`'s existing `target_name` filter)
   sees only its own marker.  The stored `filepath` is relative to the
   target's `reversed_dir` (`../shared/f.c`), which resolves back to the
   shared file for compile/verify without touching the resolution code.
   Metadata (STATUS/SIZE/…) lives in the shared `rebrew-function.toml`
   under per-target keys, so each target tracks its own status for the same
   source.
2. **`[targets.<name>] defines = ["V2"]`**: per-target compile-time defines,
   emitted as `/DV2` (MSVC) or `-DV2` (posix) on every compile for that
   target — the switch that makes `#ifdef V2` deltas in shared sources
   work.  Defines join the flag list, so they shape the compile-cache key
   automatically, and the verify cache stores them per entry so a defines
   edit invalidates cached results.
3. Source discovery goes through the existing single choke point
   (`iter_sources`), so verify/status/todo/catalog and the rest pick up
   shared sources with no per-tool changes.

## Consequences

- **Positive**: one implementation serves N versions; VAs stay per-target
  metadata; version deltas are ordinary `#ifdef` blocks driven by per-target
  defines; the isledecomp workflow (stacked markers, `#ifdef` deltas,
  per-version status) maps onto rebrew's per-target machinery with no
  schema changes to existing targets.
- **Negative**: a shared file compiles once per target — N targets mean N
  compiles of the same source (the compile cache keeps it cheap).  The
  `#ifdef`-divergent functions must still compile under **all** targets'
  defines (a branch guarded out per target is fine; a function that only
  exists in one version should stay in that target's own `reversed_dir`).
  The `target_name` marker filter requires the marker module to match the
  target exactly — a shared file whose marker names the wrong target is
  silently invisible to that target's scan (same contract as per-target
  files).  Functions that diverged beyond `#ifdef`-ability are left out of
  the secondary target (or handled by `cross-import`'s copy flow).
- **Contract notes**: `shared_dir` defaults to `src/shared` for NEW
  projects; existing projects that happen to have a `src/shared` directory
  will start scanning it (documented; disable with `shared_dir = ""`).
  Shared files use the same marker/metadata format as per-target files —
  no format changes.
