# ADR-022: Shared single-file imports (`cross-import --shared`)

- **Status**: Accepted. Amends [ADR-009](009-cross-target-import.md) (adds the
  stacked-marker import beside the copy path).
- **Date**: 2026-09

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
  Its duplicate-VA guard keys `(module, va)` like E013, so same-VA twins
  across targets stack instead of erroring.
- DATA side: `fill-data`, `--own`, `--fix-ownership`, and `inline-strings`
  scan the shared tree (data metadata was already `(module, va)` keyed);
  `gen-stubs` already covered it via the whole-tree scan.
- Sync side: BinSync pull (`sync --pull`, `binsync-import`, overlay
  renames) writes shared files — the importer's containment guard covers
  the shared tree, not just `reversed_dir`, and type-dedup scans shared
  headers so `src/shared` structs are not re-imported as duplicates.
  Push/export was already shared-aware via cfg scans; Ghidra MCP ops
  create in-Ghidra or write the per-target globals header, unaffected.
- `link-order` sorts a stacked file by the requesting target's own marker
  VA (unknown modules keep the old cross-marker minimum).

## Consequences

- One file serves N targets with per-target STATUS in the shared
  `rebrew-functions.toml` — no drift between copies. Guild-rebrew's
  `doctor` now warns (3 targets, no `src/shared`) instead of staying silent.
- The default copy path is unchanged; `--shared` is opt-in per import, so
  divergent functions (beyond `#ifdef`-ability) keep the copy flow.
- No auto-migration of existing per-target copies; the copies keep working.

## Coverage audit (2026-09-22)

Every other surface checked shared-correct, no change needed:

- Scan side (`iter_sources`/`scan_reversed_dir` with cfg): status, catalog,
  todo, rename, extract, context, binsync export, ghidra watch — shared
  files appear per target with only their own marker.
- Compile/verify/test/diff/prove/match: target-filtered blocks, per-target
  defines, shared root on the include path; compile + verify caches key on
  content+flags+defines+toolchain, so identical shared bodies share hits
  and `#ifdef` variants stay separate.
- Metadata: `rebrew-functions.toml` and `rebrew-data.toml` both key
  `(module, va)` — same-VA twins across targets stay isolated (proven live:
  V1 EXACT / V2 STUB on one `0x401000`).
- Creation tools (skeleton, new-file paths) default per-target — correct:
  sharing is a promotion decision (`--promote`, `merge --shared`), not a
  creation default.
- Remaining raw `*.c`/`*.h` rglobs are intentionally scoped: gen-stubs
  scans the whole tree (covers shared), inline-strings `--source-dir` is
  explicit, round-trip/types/binsync headers are per-target build state.
- Second audit (skeleton, diag tools, watch, graph, refactor): skeleton
  writes per-target by default with cfg-aware uncovered detection (no
  shared duplication); stack-cmp/gap-trace/climb/near-diag/prove resolve
  via `resolve_source_arg` + target filter; verify/test/match watch modes
  poll `iter_sources`; rename operates in place with shared-aware
  candidates; link-order fix above. No changes needed.
- Per-target `inventory_file`: the last blocker for a pure single tree.
  `reversed_dir` doubles as scan root and inventory home, so one shared
  `reversed_dir` collides all targets' `function_structure.json`.
  `[targets.<name>].inventory_file` (project-root-relative) overrides the
  home per target; `cfg.inventory_path` / `inventory_path_for` centralize
  all 27 touch points (mock-safe via getattr).
