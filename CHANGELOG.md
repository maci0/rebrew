# Changelog

All notable user-visible changes to Rebrew are recorded here.  The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Rebrew is pre-1.0: under [SemVer](https://semver.org/spec/v2.0.0.html)'s `0.x`
rule, any release may contain breaking changes.  Breaking entries are marked
**Breaking:** so an upgrade never surprises you.  See `CONTRIBUTING.md` for the
versioning policy.

## [Unreleased]

### Added

- `rebrew similar` — find functions structurally similar to a given one.
- `rebrew test --watch` — re-run on source change.
- `rebrew round-trip` resolves MSVC `$SG<N>` string constants automatically and
  falls back to `cfg.cflags` when function metadata carries no explicit CFLAGS.

### Changed

- **Breaking:** `coverage.db` schema is now version `"4"` (normalized,
  range-checked cell rows; `cells` → `sections` foreign key with cascade
  delete).  `rebrew build-db` refuses to write into a version `"3"` database;
  rebuild it with `rebrew build-db --force`.  See `docs/DB_FORMAT.md`.
- Ghidra MCP failure warnings from the decompiler backend now name the failing
  endpoint and the fix.
