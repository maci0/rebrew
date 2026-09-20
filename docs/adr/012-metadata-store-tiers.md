# ADR-012: Metadata store tiers (canonical vs derived vs cache)

- **Status**: Accepted
- **Date**: 2026-08

## Context

Rebrew accumulated many persistence surfaces over time: `.c` annotation
markers, three TOML stores (`rebrew-functions.toml`, `rebrew-data.toml`,
`rebrew-libraries.toml`), `functions.txt`, a coverage grid JSON, a SQLite
coverage DB, a verify cache, compile caches, and GA solutions/history
files.  New contributors (and the agent docs) repeatedly asked "why are
there so many places, and which one is the truth?"

An audit (2026-08) found the architecture was *mostly* sound — STATUS has a
single gate, function-list parsing is centralized — but the tier structure
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

Adopt an explicit **four-tier model** and document it as the contract
(current store map: [METADATA.md](../METADATA.md)):

1. **Canonical (user-owned)** — `.c` marker lines (identity), the three
   TOML stores (overrides), `rebrew-project.toml` (config).  The only
   stores that hold non-derivable facts.
2. **Derived, VCS-intended** — `src/<target>/function_structure.json`
   (discovery inventory; replaces the removed `functions.txt` /
   `CATALOG.md`), the layout package (`layout/<target>/`:
   `rebrew-layout.toml` + `*.hex`), `<target>.def`, `crt_region/*.c`,
   `src/link_stubs.c`, `flirt_sigs/*.pat`, toolchain files.  Generated
   from the binary but committed so a rebuild never needs `original/`
   around; regenerable via the generating command (gen-layout, discover,
   catalog, link-stubs).
3. **Derived, gitignored (build output)** — grid JSON, coverage.db, CSV,
   `bin/<target>/*.bin`, `output/report/`.  Rebuildable via one command;
   never hand-edited.  The `--compare` baseline lives in
   `.rebrew/verify_baseline.json` (unguarded `db/verify_results.json`
   snapshots are no longer written — see `verify_cache.load_baseline`).
4. **Cache (delete-safe)** — verify cache, Ghidra sync-state, compile
   caches, GA build caches/checkpoints, in-memory mtime caches.  Except
   `.rebrew/ga_runs.jsonl` (live GA history / win fingerprints; see
   `matcher/solutions.py` — `load_solutions` derives winners from the log;
   the old `.rebrew/solutions.json` store is gone).

Single-source rules enforced by code where cheap:

- One parser per file format, in shared modules (`catalog/loaders.py`,
  `rebrew/utils.py`).
- All TOML stores load through one shared `load_metadata_doc` (tomllib,
  mtime-cached) and serialize writes through one shared
  `metadata_write_lock` (thread + flock).
- Writes to canonical stores go through the gated APIs only; STATUS
  strictly via `update_source_status`.
- No module-less metadata keys; `TOOLCHAIN` is a declared metadata field.
- BinSync import routes STATUS through the metadata gate.
- Volatile metadata (`STATUS`/`BLOCKER`/`NOTE`/…) is not parsed from
  inline `.c` comments (`_kv_to_annotation` defaults STATUS to `STUB`);
  values live in `rebrew-functions.toml`, migrated by `lint --fix` /
  W019.  Still read inline: `SIZE`/`CFLAGS` (reccmp contract; co-read),
  `TOOLCHAIN` and non-naked `SOURCE` (until migrated; metadata wins on
  merge), `// SOURCE: naked` (file-borne), and structural `STRUCT`/
  `CALLERS`.  The `library_*.h` extended KV parser remains the exception.

## Consequences

**Positive**

- The tier map (docs/METADATA.md) answers "which store is the truth?" for
  every fact in one table; new contributors stop guessing.
- Loader/lock unification removes a class of subtle bugs: the data store
  previously could not serialize concurrent writers, and the two TOML
  parsers could disagree on edge-case files.
- Deleted ~250 lines of dead/duplicate parsing; verify parses the
  function list once instead of twice.
- BinSync-created stubs no longer emit W019-flagged inline metadata.

**Negative**

- Behavioral strictness: empty-module metadata writes now raise instead of
  silently writing an unreadable key; inline `// STATUS:`/`// NOTE:` (and
  other volatile keys) are no longer produced by import paths and are no
  longer parsed from existing `.c` files — `lint --fix` / W019 migrate
  them into `rebrew-functions.toml`.
- The docs and ADR must be kept current when the store map changes (the
  ADR convention already requires this); [METADATA.md](../METADATA.md) is
  the living store map.

**Trade-offs accepted**

- We deliberately did **not** merge `rebrew-data.toml` into
  `rebrew-functions.toml` or drop `coverage.db`: distinct key spaces
  (functions vs data symbols) and a real query consumer (dashboard,
  recoverage) justify the split.  Simplification came from shared
  mechanics and documented tiers, not fewer files.  The layout package
  (`layout/<target>/`) is a derived-but-VCS-intended tier of its own —
  committed so postlink never needs `original/` around, regenerable from
  the reference binary on change.
- `verify_cache.json` stays a *measured-result mirror* (not folded into
  metadata) so `rebrew status`/`todo` serve without recompiling and
  demotions aren't masked; its overlay precedence is documented.
