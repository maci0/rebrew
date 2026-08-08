# Changelog

All notable user-visible changes to Rebrew are recorded here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Rebrew is pre-1.0: under [SemVer](https://semver.org/spec/v2.0.0.html)'s `0.x`
rule, any release may contain breaking changes.  Breaking entries are marked
**Breaking:** so an upgrade never surprises you.  See `CONTRIBUTING.md` for the
versioning policy.

## [Unreleased]

### Added
- `rebrew diff --dry-run` — preview `--fix-blocker` metadata writes without
  touching `rebrew-function.toml`.
- `rebrew extract batch --dry-run` — preview which `.bin` files would be
  written (JSON: `DRY_RUN` status, plus a `failed` count in the summary).
- `rebrew cfg set` / `add-module` / `set-cflags` gained `--dry-run` with
  future-tense previews (no in-memory mutation).
- `rebrew cfg set-cflags --target` now actually takes effect — per-target
  presets are written under the target's `compiler` sub-table, where the
  loader reads them (previously a silent no-op).
- `recoverage check --json` and `recoverage stats --json` — machine-readable
  verdicts/output.
- Per-module CFLAGS presets (`cflags_presets`) are now consumed as the
  CFLAGS fallback across match/diff/verify/test/prove/near_diag
  (`rebrew.cli.resolve_cflags`).
- `rebrew sync --refresh-cache --json` now actually writes the cache (the
  flag previously made it a silent no-op).
- `rebrew init --install-wibo` writes a working config (wine prefix dropped
  from the command).
- `rebrew data --gen-header` / catalog warn on globals whose VA falls
  outside every PE section.

### Changed
- **Breaking (JSON):** `rebrew imports --json` now emits stub VAs as hex
  strings (`{"va": "0x...", "name": ...}` list) and `iat_va` as hex, matching
  every other rebrew JSON (previously stringified decimal dict keys).
- **Breaking (CLI):** `rebrew verify --compare` no longer advances the
  baseline report on a failing (regressed) run, and a failed gate run no
  longer writes the verify cache — the CI gate can no longer self-heal.
- Verify cache now invalidates on annotation SIZE changes (metadata-only
  `catalog --fix-sizes`), external `-I` header edits, and
  `compiler.runner`-only config edits.
- `rebrew verify` PROVEN overlay no longer masks real regressions
  (COMPILE_ERROR / EXTRACT_ERROR / MISSING_FILE surface as failures).
- Bad-VA arguments to `rebrew diff`/`match`/`asm`/`similar` now produce
  accurate errors instead of misleading symbol errors or silent empty output.
- `rebrew sync --dry-run` no longer writes `ghidra_commands.json`.
- `rebrew build-db` never deletes a locked/valid database; schema-less
  debris files auto-rebuild; infrastructure errors exit 2 (EXIT_ERROR).
- Main-command catch-all exits cleanly (no traceback, JSON envelope when
  `--json`) with EXIT_ERROR.
- `rebrew cfg` write commands surface OSError/tomlkit parse errors as clean
  messages.
- `rebrew extract batch` continues past a per-function disassembly error
  instead of aborting the batch.
- `rebrew asm --size` beyond the image warns and reports `truncated`.
- `rebrew flirt --va` bypasses the scan size gate so short functions are
  actually probed.
- CFLAGS resolution unified across tools (per-function → preset →
  `[compiler].cflags` → `/O2 /Gd`).

### Fixed
- `rebrew diff 0x<VA> --watch` lost VA targeting on re-entry (diffed the
  wrong function in multi-function files).
- `rebrew verify` PROVEN overlay masked regressions in proven functions.
- angr's import-time unicorn ERROR leaked to stderr on every `todo`/`doctor`
  run (and prove's status-guard failures).
- `rebrew sync --push --dry-run` wrote the export artifact.
- Coverage DB: failed builds left an empty DB that wedged later builds;
  full rebuilds left orphan `verify_results` rows and a dead v3 index.
- Coverage DB schema gate now verifies query-critical columns, not just
  object names.
- Default `marker` for dotted target names (e.g. `server.dll`) no longer
  produces a marker that matches no annotation module.
- Source filenames starting with `@`/`-` are prefixed `./` before CL.EXE
  (MSVC response-file/option confusion).
- Recovered `cu_map`'s orphaned standalone CLI surface (reachable only via
  `rebrew graph --cu-map`).

## [0.1.0] - 2026-08-08

First tagged release.  Rebrew is a compiler-in-the-loop decompilation
workbench: it compiles your C source with MSVC6 (under Wine/wibo), byte-compares
against the target binary, and drives the match loop with a GA engine,
symbolic proving, and a coverage database.

### Added

- **Matching**: `rebrew match` GA engine with flag sweeps (`--flag-sweep-only`,
  tiers quick/targeted/normal/thorough/full), solved-cflag seeding
  (`--seed-from-solved`), batch resume (`--skip-recent`, `--ga-history`,
  `--sweep-then-ga`), and `output/ga_runs` result storage.
- **Proving**: `rebrew prove` symbolic equivalence via angr — EDX/64-bit return
  checking (`--check-edx`), memory side-effect comparison (`--watch-va`), slice
  proving (`--start-offset/--end-offset`), and batch `--all` mode.
- **Round-trip**: `rebrew round-trip` splices every EXACT/RELOC function's
  compiled bytes back into a copy of the target PE and SHA-256 verifies the
  result.  Resolves MSVC `$SG<N>`/`??_C@` string constants by content, decodes
  Ghidra VA-encoded auto-names (`_g_1003546c`), maps `$L<N>`/`$cleanup_loop$<N>`
  jump tables from the .obj layout, and binds string literals that are strict
  prefixes of the target's copy.  Wrong fallbacks surface as
  `catalog_resolution_drift`, never silent corruption.
- **Similarity & triage**: `rebrew similar` (structurally similar functions),
  `rebrew near-diag` (structured diff diagnosis), `rebrew imports` (IAT
  introspection), `rebrew todo` (ROI-ranked action list).
- **Dashboard**: `rebrew dashboard` — read-only web dashboard over the
  coverage database (paired with the `recoverage` project).
- **Agent skills**: `rebrew skills` bundles five workflow skills
  (intake, workflow, matching, data-analysis, ghidra-sync) for AI agents.
- **Verification**: `rebrew verify --compare` detects regressions against the
  last saved report; `rebrew verify -o db/verify_results.json` feeds the
  coverage database (`build-db` imports it into the `verify_results` table).
- **Ghidra sync**: ReVa MCP sync plus a new `ghidra_backend = "cli"` backend;
  pull signatures/structs/datatypes/comments/data, size sync, bookmark sync.
- **Data analysis**: `rebrew data --dispatch`, `--bss`, `--fix-bss`,
  `--gen-header`, and configurable dispatch thresholds.
- **Catalog**: `rebrew catalog --data-json`, `--export-ghidra-labels`,
  `--fix-sizes`, `--csv`, CATALOG.md generation; `rebrew build-db` produces a
  versioned SQLite coverage DB (schema v4) with cell-level per-byte states.
- **Watch mode**: `--watch` on test/verify/diff/match/prove re-runs on source
  change.
- `rebrew doctor` extended with optional-tool (angr/claripy), FLIRT-signature,
  and Ghidra-sync health checks; `rebrew doctor --install-wibo` bootstraps the
  lightweight Wine replacement.
- **Metadata**: volatile per-function fields (STATUS, SIZE, CFLAGS, BLOCKER,
  NOTE, GHIDRA, …) live in `rebrew-function.toml`; per-directory data metadata
  in `rebrew-data.toml`; both under `cfg.metadata_dir`.  `rebrew lint --fix`
  migrates inline leftovers.
- **Property/fuzz tests**: hypothesis-based tests across parsers and the COFF
  .obj extraction helpers; the suite runs 3460 tests / 0 skipped with
  `uv sync --all-extras` (angr included).

### Changed

- **Breaking:** `coverage.db` schema is version `"4"` (normalized,
  range-checked cell rows; `cells` → `sections` foreign key with cascade
  delete).  `rebrew build-db` refuses to write into a version `"3"` database;
  rebuild it with `rebrew build-db --force`.  See `docs/DB_FORMAT.md`.
- **Breaking:** volatile annotation fields migrated out of `.c` headers into
  `rebrew-function.toml`; inline `// STATUS:` / `// SIZE:` are deprecated
  (lint W019) and no longer authoritative.
- angr is installed by the documented dev install (`uv sync --all-extras`);
  `rebrew prove` tests run for real instead of skipping.
- Ghidra MCP failure warnings name the failing endpoint and the fix.
- `rebrew catalog --fix-sizes` and `rebrew data --fix-bss` write metadata to
  `cfg.metadata_dir` (previously the source directory — fixes were silently
  lost).
- `rebrew build-db` emits `paths.sourceRoot` and imports the last
  `verify_results.json`; CATALOG.md coverage is computed from the real .text
  size.

### Fixed

- Round-trip oversize check now requires exact compiled size (a longer compile
  is no longer silently truncated); string search bounded by raw section
  extent.
- Negative section offsets (annotated VAs outside the binary) no longer abort
  the whole `build-db` rebuild (CHECK-constraint violation); grid skips them,
  build-db clamps defensively.
- `remove_annotation_key` no longer reports a write when nothing was removed;
  same-value writes are no-ops.
- 30 mypy errors in `rebrew prove` under real angr types; `SimState` typing,
  `self.addr` narrowing.
- Config load warns when the target binary is missing (image_base
  auto-detection skipped) instead of silently zeroing the layout.
- Ghidra auto-names with 9+ trailing hex digits are no longer mis-decoded as
  VAs.
