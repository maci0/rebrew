# 022 — Shared single-file imports (`cross-import --shared`)

## Status

Accepted

## Context

ADR-009 imports a matched function by COPYING its source into the
destination's `reversed_dir` (marker rewritten to the destination module +
VA). ADR-010 defines the alternative: one `src/shared` file serving every
target with one `// FUNCTION: <target> <va>` marker per target. The copy
path fights the shared tree — two files with the same body drift apart,
and guild-rebrew (three binaries sharing one game codebase) needs the one
file to be the deliverable, not the copy.

Two blockers kept the shared path from working. `rebrew lint` E012
rejected any marker not naming the linted target's own module, so a
stacked `// FUNCTION: V1` block in a file linted under V2 was an error —
even though each target's scan/verify already filters to its own marker
and the metadata keys `(module, va)` already isolate per-target STATUS.
And `cross-import` had no way to write the stacked form: it only knew the
copy.

## Decision

- `rebrew cross-import --shared` stacks the destination marker block
  (`// FUNCTION: <dst> <va>` + `// SIZE:`) onto the shared source in place
  (idempotent — an existing `<dst> <va>` block is left alone), then
  compiles + verifies against the destination binary through the standard
  `verify_entry` + `apply_status_updates` flow before any STATUS promotion.
  A mismatch reports `imported-unverified`, never a false match. `--dry-run`
  previews as `would-import-shared`. A source still living in the per-target
  tree is moved under `src/shared` first (preserving relative path);
  `--promote` does the move alone without importing. A matched import
  deletes the destination's old stub file so the VA is claimed once (an
  unverified import leaves the stub); the copy path already replaced it by
  overwriting. Shared imports record no absolute source-dir `/I` — the file
  moves with its headers and compile.py adds src_parent itself, so the
  absolute path would only bake one checkout into the metadata (the copy
  path keeps it: its destination tree lacks the source headers).
- E012 accepts a marker naming any known project marker
  (`cfg.all_markers`, computed at load from every `[targets.*]` marker);
  a module naming NO target still fires E012. Stacked blocks for other
  targets are exempt from the linted target's W018 — each block answers to
  its own target's CFLAGS defaults.
- `rebrew doctor` gains a Shared-sources check: skipped on single-target
  projects; warns on multi-target projects when `shared_dir` is disabled or
  the directory is missing (fix points at `mkdir` + `--shared`).
- Compiling a file under the shared root adds the shared root to the
  include path (docker path via `_effective_compile_flags`, raw matcher
  path alongside defines), so a nested shared file finds root-level shared
  headers by bare name. Joins the flags so the compile-cache key tracks it.
- `rebrew cmake-flags` collects shared sources (via `iter_sources`, which
  also honours `source_ext`) — the old `reversed_dir` rglob left every
  shared TU flagless in the CMake build.
- `--dir` (verify / test --all) resolves project-relative first, so
  `src/shared` scopes the shared tree; reversed-relative stays the fallback.
- `rebrew cfg add-target` creates the shared root when the project gains its
  2nd target (unless `shared_dir` is disabled) and prints the `--shared`
  pointer — directory only, never config.
- `rebrew split --va` matches any stacked marker in a block, not just the
  first (the stacked-last marker used to hide the others).
- `rebrew merge --shared` collapses identical twin copies into one stacked
  block (per-block SIZE preserved); same-name divergent bodies are refused
  with names — the bulk migration from per-target copies to `src/shared`.
- DATA side: `fill-data`, `--own`, `--fix-ownership`, and `inline-strings`
  scan the shared tree (data metadata was already `(module, va)` keyed);
  `gen-stubs` already covered it via the whole-tree scan.

## Consequences

- One file serves N targets with per-target STATUS in the shared
  `rebrew-functions.toml` — no drift between copies. Guild-rebrew's
  `doctor` now warns (3 targets, no `src/shared`) instead of staying silent.
- The default copy path is unchanged; `--shared` is opt-in per import, so
  divergent functions (beyond `#ifdef`-ability) keep the copy flow.
- No auto-migration of existing per-target copies; the copies keep working.
