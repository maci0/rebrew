# ADR-012: Metadata store tiers (canonical vs derived vs cache)

- **Status**: Amended by [ADR-023](023-markers-toml-single-source.md)
  (superseded by [ADR-030](030-address-only-source.md), itself amended by
  [ADR-033](033-consolidated-source-evidence.md): identity and state live
  in the metadata stores, and a `.c` carries optional ADDRESS anchors
  only), [ADR-031](031-live-coverage-views.md) (live coverage and durable
  history), [ADR-034](034-metadata-storage-backends.md) (amended by
  [ADR-035](035-metadata-replication.md): storage backends behind one
  `MetadataStore`)
- **Date**: 2026-08

## Context

Rebrew accumulated many persistence surfaces over time: `.c` annotation
markers, three TOML stores (`rebrew-functions.toml`, `rebrew-data.toml`,
`rebrew-libraries.toml`), `functions.txt`, a coverage grid JSON, a SQLite
coverage DB, a verify cache, compile caches, and GA solutions/history
files.  New contributors (and the agent docs) repeatedly asked "why are
there so many places, and which one is the truth?"

An audit (2026-08) found the architecture was *mostly* sound (STATUS has a
single gate, function-list parsing is centralized) but the tier structure
was undocumented, and the code carried real drift that made the boundaries
harder to see:

- Three hand-rolled TOML loaders (function/data/library stores) with an
  inconsistent parser choice (`tomllib` vs `tomlkit`) and a missing write
  lock on the data store.
- Dead and duplicate parsing code (`load_all_sources_parallel`, two rizin
  `afl` parsers, a second function-list projection cache, a double
  functions.txt parse per verify run).
- Schema drift: `TOOLCHAIN` was a live metadata field missing from
  `METADATA_FIELDS` (bypassing the routing gate); module-less `0xVA`
  metadata keys could be written but never read back.
- BinSync import still emitted the deprecated inline `// STATUS: STUB`
  form that lint W019 exists to eliminate.
- Docs claimed the grid JSON was keyed by name (it is keyed by VA) and
  reported the wrong `db_version`.

## Decision

Adopt an explicit **four-tier model**. The tier membership and the
per-fact ownership are the table in [METADATA.md](../METADATA.md); this
record keeps the rules, and the citing ADRs in the status line record
what has changed since:

- **Canonical** holds the non-derivable facts: the C sources,
  `rebrew-project.toml`, and the managed metadata stores. At acceptance
  those stores were `rebrew-functions.toml`, `rebrew-data.toml` and
  `rebrew-libraries.toml`, and the `.c` files carried identity as inline
  marker lines. Identity and state have since moved entirely into the
  metadata stores ([ADR-030](030-address-only-source.md)); a `.c` now
  carries optional `/* ADDRESS: MODULE 0xVA */` anchors only, and readers
  reject inline state (lint E024) with no migration of it.
- **Derived, VCS-intended** is generated from the binary and committed so
  a rebuild never needs `original/` around: the discovery inventory
  (`function_structure.json`, replacing the removed `functions.txt` /
  `CATALOG.md`), the layout package, the link scaffolding and the FLIRT
  signatures. Regenerable by the command that writes each one (`rebrew
  build layout`, `rebrew binary functions`, `rebrew build link-stubs`).
- **Derived, gitignored** is rebuildable build output and is never
  hand-edited. At acceptance this tier held a coverage grid JSON, a
  SQLite `coverage.db` and a reccmp CSV, all three since removed
  ([ADR-031](031-live-coverage-views.md) and the amendment below). The
  `--compare` baseline lives in `.rebrew/verify_baseline.toml`; the
  unguarded `db/verify_results.json` snapshots are no longer written
  (`verify_cache.load_baseline`).
- **Cache** is delete-safe: the verify cache, Ghidra sync-state, the
  compile caches, GA run checkpoints (`out_dir/checkpoints`,
  `out_dir/best.c`) and the in-memory mtime caches. There is no per-run
  GA build cache; same-run compiles memoize in memory and cross-run
  persistence is the shared compile cache's job. Except
  `.rebrew/ga_runs.jsonl`, the live GA history and win fingerprints
  (`matcher/solutions.py`; `load_solutions` derives winners from the
  log). The `.rebrew/solutions.json` store is gone.

Single-source rules enforced by code where cheap:

- One parser per file format, in shared modules (`catalog/loaders.py`,
  `rebrew.metadata.document`).
- The managed metadata stores load through one `load_metadata_doc`
  (`metadata/document.py`, mtime-cached) and serialize writes through one
  `metadata_write_lock`, which takes the store transaction.
  `rebrew-libraries.toml` is not qualified-key data, so
  `parse_library_metadata` keeps its own flat-table validation, but it
  reads through the same `MetadataStore` and `rebrew library set` / `rm`
  write under `metadata_write_lock`. [ADR-034](034-metadata-storage-backends.md)
  puts the TOML, SQLite and PostgreSQL backends behind that one store.
- Writes to canonical stores go through the gated APIs only. STATUS goes
  strictly through `update_source_status` / `update_statuses_batch` (one
  promotion gate). `rebrew verify` and `rebrew intake` collect a run and
  apply it with `update_statuses_batch`; `rebrew test` calls
  `update_source_status` once per changed function, and that writer funnels
  through the same batch helper.
- No module-less metadata keys; `TOOLCHAIN` is a declared metadata field.
- BinSync import routes STATUS through the metadata gate.

## Consequences

**Positive**

- The tier map (docs/METADATA.md) answers "which store is the truth?" for
  every fact in one table; new contributors stop guessing.
- Loader/lock unification removes a class of subtle bugs: the data store
  previously could not serialize concurrent writers, and the two TOML
  parsers could disagree on edge-case files.
- Deleted ~250 lines of dead/duplicate parsing; verify parses the
  function list once instead of twice.
- BinSync-created stubs no longer emit inline metadata. (The W019 lint
  that flagged it was removed with the marker parser; inline state is now
  rejected outright as E024, per [ADR-030](030-address-only-source.md).)

**Negative**

- Behavioral strictness: empty-module metadata writes now raise instead of
  silently writing an unreadable key. Import paths stopped producing inline
  `// STATUS:`/`// NOTE:` (and the other volatile keys), and nothing parses
  them back out of a `.c`. At acceptance, `lint --fix` / W019 migrated any
  already present into `rebrew-functions.toml`; that migration is gone, and
  a file still carrying them fails lint E024.
- The docs and ADR must be kept current when the store map changes (the
  ADR convention already requires this); [METADATA.md](../METADATA.md) is
  the living store map.

**Trade-offs accepted**

- We deliberately did **not** merge `rebrew-data.toml` into
  `rebrew-functions.toml` or drop `coverage.db`: distinct key spaces
  (functions vs data symbols) and a real query consumer (dashboard,
  recovery) justify the split.  Simplification came from shared
  mechanics and documented tiers, not fewer files.  The layout package
  (`layout/<target>/`) is a derived-but-VCS-intended tier of its own:
  committed so postlink never needs `original/` around, regenerable from
  the reference binary on change.
- `verify_cache.toml` stays a *measured-result mirror* (not folded into
  metadata) so `rebrew status`/`todo` serve without recompiling and
  demotions aren't masked; its overlay precedence is documented.

*(Amended: the `coverage.db` tier named above is gone.  Tier 3's coverage entry
is one clear-text document per target, `coverage-<target>.toml`, written
wholesale by `rebrew coverage export --output <dir>` for offline use (normal
dashboards read live metadata per [ADR-031](031-live-coverage-views.md)): no schema
migration, no `--force` unlink, and no derived cache table between the catalog
and a reader.  The document still stamps `version`; a previous document carrying
any other value contributes nothing, so the stamp bounds what an older document
may contribute rather than gating the rebuild.  The accepted trade-off above, that
`coverage.db` was kept for its query consumer, is superseded for that reason, and
[COVERAGE_DOCUMENT.md](../COVERAGE_DOCUMENT.md) is the living format.)*
