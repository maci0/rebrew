# Metadata & Derived-State Architecture (the "store tiers")

This is the one-page map of **every place rebrew persists or caches data**
and, crucially, which of them is authoritative for which fact.  It exists
so the "why are there so many files?" question has a written answer: most
of the surface is *derived snapshots and caches*, not competing sources of
truth.  Pages 6–7 of [architecture.drawio](architecture.drawio) draw the
same tiers and the data/globals/layout pipeline.

## Storage API and backend selection

The four managed stores below use `rebrew.metadata.storage.metadata_store(path)`.
Its `MetadataStore` protocol owns persistence, discovery, fingerprints, review
snapshots and transactions. Domain APIs still own validation, identities,
provenance and earned verdicts. Call `rebrew.metadata.functions`,
`rebrew.metadata.data`, `rebrew.metadata.source_provenance`, `rebrew.type_metadata`
or the library API when changing records. A storage handle stays bound to its
backend; domain write locks select storage again after acquiring the project
configuration lock.

TOML remains the default. Experimental SQLite is enabled per project:

```bash
rebrew metadata migrate sqlite --dry-run --json
rebrew metadata migrate sqlite --expected-digest <input_digest-from-preview>
rebrew metadata migrate toml --dry-run
rebrew metadata migrate toml
```

Migration validates all four store schemas, discovers nested library settings, verifies
copied documents, and only then writes `[metadata] backend = "sqlite"` (or
`"toml"`) in `rebrew-project.toml`. Project configuration stays in TOML.
Changing that setting manually selects storage without importing existing data;
inactive metadata is never used as a fallback. Previews create no storage files.
The report lists inactive destination documents that will be removed because
they are absent from the active source. Source files remain available after a
transfer. A failed transfer leaves the source selected; retry to replace any
incomplete inactive destination.

SQLite uses the canonical project-root `rebrew-metadata.sqlite3` database,
protected by its `.lock` sidecar and mode 0444 at rest. Back up the database as
durable project data; ignore its `.lock` and transient `-journal`. It stores each
logical document using TOML encoding to preserve existing value types. A
transaction can cover all four stores in that database. This experimental
backend adds no relational query API or performance promise. See
[ADR 034](adr/034-metadata-storage-backends.md).

### PostgreSQL

Install the optional `rebrew[pgsql]` extra and the system `libpq` client library.
Connection settings belong in `rebrew-project.toml`:

```toml
[metadata]
backend = "pgsql"

[metadata.pgsql]
dsn = "service=rebrew"
project = "my-game"
```

`dsn` accepts a libpq connection string or PostgreSQL URI. A libpq service and
password file keep credentials outside the committed project configuration.
`project` is a required stable namespace: checkouts with the same database and
project key share documents; different keys remain separate. The database must
already exist. The database role needs access to `public.rebrew_metadata_documents`
and permission to create it on the first write. Reads and previews create nothing.

For existing TOML or SQLite metadata, add `[metadata.pgsql]` while retaining the
current `backend`, then run `rebrew metadata migrate pgsql --dry-run --json` and
`rebrew metadata migrate pgsql --expected-digest <input_digest-from-preview>`.
Setting `backend = "pgsql"` directly selects it without importing local documents.
Migration back to TOML or SQLite uses the same command. Before replacing an
inactive PostgreSQL destination, migration saves its documents under
`.rebrew/pgsql-before-transfer/`. A later transfer that displaces different
bytes rotates the previous snapshot to a numbered sibling
(`rebrew-functions.toml.1`, `.2`, …) instead of overwriting it, so every
displaced destination survives; an identical snapshot is reused.

This experimental backend preserves TOML types and comments. Transactions span
all documents for a project; PostgreSQL advisory locks serialize participating
writers across checkouts. Cache fingerprints detect remote document edits,
including in the live coverage dashboard. Single-backend connection failures raise
an error without falling back to inactive local files or printing credentials.

Use PostgreSQL's `pg_dump` and `pg_restore`/`psql` for database backups and restores,
and back up sources, project configuration, GA logs and BinSync baselines separately.
`rebrew metadata backup` and `restore` reject the PostgreSQL backend rather than
copying inactive local metadata. Database permissions and backups replace local
file modes as the protection for this backend.

### Multiple read and write backends

Use separate lists to read from a database while also maintaining files:

```toml
[metadata]
read_backends = ["sqlite", "pgsql", "toml"]
write_backends = ["sqlite", "pgsql", "toml"]

[metadata.pgsql]
dsn = "service=rebrew"
project = "my-game"
```

`read_backends` is ordered. A read tries the next configured source only when
one is unavailable. An empty document, missing record, malformed metadata or an
incompatible schema does not cause fallback. The sources are not merged during
ordinary reads. `write_backends` lists every destination to update. The lists
are independent, nonempty, and reject duplicate or unknown names. Omit
`write_backends` to write to all configured readers. Existing single-backend
projects can keep `backend = "toml"` or `"sqlite"`/`"pgsql"`; do not combine
`backend` with `read_backends`.

All domain owners still use `MetadataStore` operations. Routing is below that
interface, including discovery, snapshots, fingerprints, writes and removals.
SQL stores remain document-based; selecting them does not introduce indexed
queries over individual metadata records or guarantee faster workloads.

A successful replicated write first commits its complete operation to
`.rebrew/metadata-journal.toml`, then publishes to the configured writers.
An unavailable or failed writer is reported and remains queued. The journal
survives process exit and keeps reads from returning an older replica value
for an operation already committed locally. Metadata payloads, earned verdicts,
verification receipts and history are copied unchanged. An exception before
the operation commits discards its staged metadata edits.

Each backend stores document timestamps and causal revision clocks in a
separate `.rebrew/metadata-replication.toml` logical document. Its rows are
internal state and are excluded from managed-document discovery. Tombstones
represent removed documents, so an older offline copy cannot resurrect them.
Clocks distinguish a later version from an independently edited copy; a larger
wall-clock timestamp alone cannot safely resolve an offline conflict. Conflicting
independent changes, including differing pre-existing unstamped documents, stop
reconciliation and preserve both copies for review. Reconciliation is per logical
document; it does not merge independently changed rows within a document.

Recovered destinations catch up during the next metadata write, or explicitly:

```bash
rebrew metadata reconcile --dry-run --json
rebrew metadata reconcile --json
```

Preview and ordinary reads do not create storage or perform repair writes.
Reconciliation validates document schemas, catches up reachable writers and
reports unavailable ones as `pending`; it does not change the configured lists.
There is no background retry daemon. Use `metadata migrate` to prepare a single
backend before enabling the lists; use `metadata reconcile` after enabling them.

Back up the local recovery journal and the TOML replication sidecar along with
the chosen durable stores. The TOML and SQLite backup commands include these
local files; PostgreSQL backups additionally need the project files. Independent
backends do not share one atomic commit. A replica may lag after a failure or
crash; recovery depends on retaining the journal and replication state. Their
local files use mode 0444 at rest. See [ADR 035](adr/035-metadata-replication.md).

## Backup and restore

Durable, must-back-up state: the C sources under `src/` (and any other
source tree the project config points at), `rebrew-project.toml`, the four
managed metadata stores (`rebrew-functions.toml`, `rebrew-data.toml`,
`rebrew-types.toml`, `rebrew-libraries.toml`, including their `.d/`
drop-ins) in the TOML backend, or `rebrew-metadata.sqlite3` in the
SQLite backend, plus `.rebrew/ga_runs.jsonl` (GA win fingerprints;
fsynced per record, never pruned for wins), the BinSync
baselines (`.rebrew/sync/*.toml`), the decomp.me upload ledger
(`.rebrew/decompme-uploads.json`, claim tokens), the replication
journal and sidecar (`.rebrew/metadata-journal.toml`,
`.rebrew/metadata-replication.toml`), the verify cache and
`--compare` baseline (`.rebrew/verify_cache.toml` /
`.rebrew/verify_cache.json` (legacy JSON compat sidecar) /
`.rebrew/verify_baseline.toml`, or the same filenames under
`.rebrew/targets/<sha256-of-exact-target-name>/`), and the Ghidra
sync dedup state (`.rebrew/ghidra_sync_state.json`), the root scan
caches (`.rebrew/name-map-cover.json`, `.rebrew/data-scan-roles.json`;
store-fingerprint-guarded parse facts, a stale copy degrades to a
re-parse), the extern-name cache (`.rebrew/extern-names.json`,
`rebrew todo` caller counts) and the name-to-VA cache
(`.rebrew/name_to_va_cache.json`, single-file `rebrew test`; both
fingerprint-guarded, regenerable with a whole-tree re-scan), the
`pgsql-before-transfer` snapshots (`.rebrew/pgsql-before-transfer/**/*.toml`;
the only copy of the destination a `metadata migrate pgsql` replaced),
and the
metadata-doc parsed-document caches (`.rebrew/metadata-doc/*.json`,
hand-reviewed fingerprints), and coverage snapshots
(`snapshots/coverage-*.toml`, carrying the durable `history[]`
status-transition log). The TOML and
SQLite backup commands (`rebrew metadata backup`) carry the whole
`.rebrew/` extras set plus coverage snapshots; the manual copy
procedure below must too.
Everything else is
regenerable: compile caches, `output/`,
`bin/`, and toolchain images (re-pull via `rebrew toolchain pull`).
The target binary named by each `[targets.*].binary` is the
non-regenerable reference the whole project verifies against. TOML and SQLite
backups include existing binaries whose configured paths are project-relative
and contain no `..` component. Absolute paths and parent-relative paths are
skipped. `rebrew doctor`'s Backup readiness check names the reference when present.

Back up source trees separately: the metadata backup command does not walk C or
Pascal source directories. Both TOML and SQLite bundles include
`rebrew-project.toml`; restore parses and installs it before recovering
configured reference binaries and BinSync state. A SQLite bundle without that
file requires a separately saved matching config and manual recovery of those
binary/state files. A complete recovery set combines the metadata bundle with
source backups and any reference binaries or BinSync state excluded by the path
rules above.

RPO is the last successful backup of the files above; RTO is a file
copy restore plus `rebrew verify` for the touched target. No schedule
or off-host copy is provisioned by rebrew itself: the operator owns
the cadence (how often `rebrew metadata backup --dir <off-tree>`
runs) and the off-tree store, which sets the actual RPO. There is no
point-in-time recovery: logical corruption is recovered by restoring
the whole backup set, not by replay.

The GA log (`.rebrew/ga_runs.jsonl`) is the one append-only durable
file with its own fast path: `rebrew match solutions --backup <dir>`
copy-verifies it byte-for-byte off-tree, and `restore_ga_runs`
validates every line and preserves the displaced log as
`.before-restore`, rotating an older sidecar to a numbered sibling
(`.before-restore.1`, …) when a later restore displaces different bytes.
GA records are fsynced before `rebrew match run`
reports a win. Metadata backup bundles also retain source pre-images.
`.rebrew/source-backups/*.orig` that survive a clean run are the only
copy of bytes the live tree no longer holds: a shared import that
stripped a claim, and `rebrew skeleton --force` (`*.pre-skeleton.*.orig`).
`rebrew metadata backup` copies those `*.orig` files and restore puts
them back. An in-flight climb or qualifier copy is removed when that run
finishes, so a bundle taken mid-run may also hold one; it is the same
pre-image, not a second store. `*.before-restore` sidecars plus their
numbered siblings (what each restore displaced, rotated aside rather than
overwritten) and `*.before-transfer` snapshots plus theirs
(`.before-transfer.1`, …, what each backend migrate replaced) stay out of
the bundle. They persist until explicitly removed; keep prior bundles as
off-tree copies. PostgreSQL destination snapshots under
`.rebrew/pgsql-before-transfer/`, including numbered siblings, are included.

The configured BinSync state dir (`targets.<name>.binsync_state_dir`,
or `--state-dir` on sync commands) is durable project state as well:
it is git-versioned (the plugin commits and rebase-pulls it) and is
carried by `rebrew metadata backup` only when its configured path is
project-relative, contains no `..` component and exists as a directory. Then
every file under it, including `.git/`, is copied and restored. Back up an
absolute or parent-relative state directory separately. Pushing or cloning the
state repo remains a valid second copy. `rebrew doctor`'s Backup readiness check
names it when it is configured and present.

Every `rebrew metadata backup` bundle carries a manifest
(`rebrew-backup.manifest.json`, beside the SQLite database or inside
the TOML bundle directory) listing each backed-up file with its size
and sha256. Restore verifies the whole manifest before installing
anything and refuses a bundle with a missing or corrupted file, so a
backup is re-opened and proven before it is trusted. Keep the most
recent backup alongside the current one: the manifest detects a torn
or truncated copy, and the previous backup is the only copy of the
pre-restore state if a restore is pointed at the wrong bundle. A
backup never restored is a hypothesis, not a backup: run the restore
procedure against a scratch copy of the latest bundle (not the live
tree) whenever the backup job, the backend, or the restore command
changes, and after any incident in which the live tree was lost.

Backup procedure: with no `rebrew` process running (the TOML writers
hold `.lock` sidecars and the SQLite writer holds its own transaction),
copy the project tree excluding `.rebrew/compile_cache/`, `output/`,
`bin/`, `__pycache__/`, and any `-journal`/`-wal` sidecar. For the
SQLite backend, prefer the online backup command below. A manual single-file
copy is safe only after all connections have closed cleanly and no recovery
journal or WAL remains. A database copied during a transaction may contain
uncommitted changes; discarding its journal can prevent recovery. Preserve the
original database and sidecars and let SQLite recover them before taking a new
backup. See [SQLite rollback journals](https://www.sqlite.org/lockingv3.html#the_rollback_journal)
and the [online backup API](https://www.sqlite.org/backup.html). Keep the copy outside the
project directory; the project `.gitignore` excludes the SQLite
database, so git is not a backup for it. Commit the TOML stores and
sources to git as usual. Copy the `.rebrew/` extras listed above
out of the project as well: they live under the gitignored
`.rebrew/` directory, so by default they are lost with the host.
Prefer `rebrew metadata backup --dir <off-tree>` to a manual copy:
it gathers the extras and verifies every copied byte, and
`rebrew metadata restore --file <backup>` installs them back.

Restore procedure: stop all `rebrew` processes, unpack the backup,
confirm `rebrew-project.toml` selects the backend matching the
restored stores (`backend = "toml"` with the TOML files, or
`"sqlite"` with `rebrew-metadata.sqlite3`), then run
`rebrew doctor` and `rebrew verify --target <name>` for one target.
If a SQLite copy was taken while a transaction was active, retain that copy
and its original sidecars for recovery; do not delete the journal to make it
open. Restore a verified online backup or take a new backup after SQLite has
recovered the original database. A corrupt or wrong-schema database is refused with
`MetadataStorageError` and never silently replaced; restore it from
the backup copy or migrate back to TOML from a TOML backup.

### PostgreSQL backup and restore

The PostgreSQL backend keeps its documents in the database, so there
is no rebrew-side backup command: `rebrew metadata backup` and
`restore` reject it rather than copying inactive local files. Back up
the database and the project files as separate pieces, in this order:

```bash
# 1. Database (the durable documents). --format=custom keeps it
#    restorable with pg_restore into a fresh cluster.
pg_dump --format=custom --file=rebrew-metadata.backup.dump <dsn>
```

Then make an off-tree copy of the project files using the manual copy procedure
above, including sources, `rebrew-project.toml`, reference binaries, `.rebrew/`
extras and any configured source or BinSync directories outside the project.
`rebrew metadata backup` cannot perform this step while `pgsql` is selected.

Restore in the same order: create the database and role, restore with
`pg_restore --dbname=<dsn> rebrew-metadata.backup.dump`, then install
the project files and run `rebrew doctor` and `rebrew verify` as
above. The dump is the only copy of the PostgreSQL documents: keep it
off-tree like any other backup, and keep the most recent dump
alongside the current one (a restore pointed at a bad dump is itself
recoverable only from the previous one). There is no point-in-time
recovery here either: logical corruption is recovered by restoring
the whole dump, not by replay.

Assembly evidence on definitions without a VA and target-scoped support-file
purposes live under `[source]` in format-3 `rebrew-functions.toml`, including
function drop-ins. They share the function store and its storage transaction;
there is no separate active source store.

## Metadata drop-in directories (TOML backend)

Each managed store may be split between its optional main TOML and TOML files
immediately inside a sibling directory:

| Main file | Drop-ins |
|---|---|
| `rebrew-functions.toml` | `rebrew-functions.d/*.toml` |
| `rebrew-data.toml` | `rebrew-data.d/*.toml` |
| `rebrew-types.toml` | `rebrew-types.d/*.toml` |
| `rebrew-libraries.toml` | `rebrew-libraries.d/*.toml` |

For example, `rebrew-functions.d/game.toml` and
`rebrew-functions.d/runtime.toml` can hold different function records. Each
fragment is a complete document in that store's existing schema, including
its `format` and required tables. Library settings retain their existing
schema without a format marker. Names are arbitrary; only direct files with
the `.toml` suffix are read, in filename order after the main file. Nested
directories and backup files are ignored. No project configuration option is
needed, and `rebrew-project.toml` is unchanged.

These files partition records: duplicate identities are errors, even when
the fields agree or the VA has a different hexadecimal spelling. Source
records are unique by file/symbol/module or file/module; type records by
identity/module; library settings by field. Library walk-up still selects
the nearest directory containing settings.

Use the existing CLI and owner APIs for edits. Updates and removals go back
to the file holding the record; new records go into the main TOML. Writers
retain comments in existing files, use the main store's `.toml.lock` for the
whole collection, and write mode 0444. Review digests and live caches include
all fragments and notice added, removed, renamed and edited files. Multi-file
write failures roll back prior files; each replacement is atomic, but the
collection is not a crash-atomic transaction. Keep all fragments in version
control, with the same ownership and earned-STATUS rules as the main stores.

## The four tiers

The canonical managed filenames below are logical document names. With SQLite
selected, their durable contents live in `rebrew-metadata.sqlite3` instead.
The database uses the default `delete` journal (no WAL): its rollback
journal beside it is part of the file set, and a torn file copy is not a
backup.  `rebrew.metadata.sqlite.backup_metadata_database` copies it
transactionally with the SQLite online backup API and verifies the copy
before reporting it; `restore_metadata_database` installs it back,
preserving the current database as `.before-restore` and rotating an
older sidecar to a numbered sibling when a later restore displaces
different bytes.  A backend transfer
(`rebrew metadata migrate`) snapshots the inactive destination
(`.before-transfer`) before overwriting it, rotating an older snapshot
aside to a numbered sibling when the bytes differ, so the pre-transfer
bytes survive the switch and a later one.

| Tier | Stores | Contract |
|---|---|---|
| **Canonical (durable)** | pure C sources, `rebrew-functions.toml`, `rebrew-data.toml`, `rebrew-types.toml`, `rebrew-libraries.toml`, `rebrew-project.toml` | Source/config are editable; identity and other non-derivable evidence are CLI/API-managed. Optional ADDRESS anchors bind declarations; old inline blocks and earlier schemas are rejected. Derived views are rebuilt from these plus the binary; recorded history is identified separately below. |
| **Derived, VCS-intended** | `src/<target>/function_structure.json` (discovery inventory), `<target>.def`, `crt_region/*.c`, `src/link_stubs.c`, `src/<target>/bss_padding.c`, `src/<target>/rebrew_globals.h`, `layout/<target>/`, `[link]` config blocks, `flirt_sigs/*.pat`, `cmake/toolchain-*.cmake` | Build scaffolding generated from the binary / binary-derived facts (`rebrew build layout`, `rebrew binary functions`, `rebrew coverage catalog`, `rebrew build link-stubs`, `rebrew data fix-bss`, `rebrew data header`, signature tools).  Committed to git so a rebuild never needs `original/` around; regenerable via the generating command.  Never hand-edit. |
| **Derived, gitignored (build output)** | `snapshots/coverage-<target>.toml`, `bin/<target>/*.bin`, `output/report/` | Rebuildable via `rebrew coverage export --output snapshots/` / `rebrew verify` / `rebrew binary extract` / `rebrew coverage report`.  Treat as build output.  `rebrew verify` writes a report file only with an explicit `--output` path; the `--compare` baseline lives beside the selected verify cache (see [`rebrew verify`](CLI.md#rebrew-verify)). The `--compare` baseline is loaded via `verify_cache.load_baseline` and written only on a passing gate. |
| **Cache (delete-safe)** | `.rebrew/verify_cache.toml` (and its legacy JSON sidecar `.rebrew/verify_cache.json`) (or under `.rebrew/targets/<sha256-of-exact-target-name>/` once the project keeps per-target verification state), `.rebrew/compile_cache/`, `output/ga_runs/*/checkpoints/*.json`, `output/ga_runs/*/best.c`, `output/ga_runs/*/<symbol>.best.c`, in-flight `.rebrew/source-backups/*.orig` (removed on clean finish), in-memory mtime caches | Regenerated on demand.  Deleting costs a recompile/re-verify/resync at most.  Durable exceptions: `.rebrew/ga_runs.jsonl` is *history*, not cache; it accumulates GA outcomes (including winning fingerprints) re-running would not reproduce, each record is fsynced before `rebrew match run` reports the run so a host that loses power does not take the win with it, and only the non-winning lines are capped (newest `_LOSS_RECORD_RETENTION`, wins kept forever).  `.rebrew/source-backups/` holds a copy of a `.c` that `rebrew match climb` / `rebrew match qualifiers` is about to rewrite in place: it exists only while that run is in flight, is removed when the run finishes, and is the way back to the pre-run bytes after a kill that runs no cleanup (SIGKILL, OOM, power cut).  Two rewrites keep their copy after a clean run, because the live file no longer holds the old bytes: `rebrew skeleton --force` (`*.pre-skeleton.*.orig`) and a shared import that strips a claim (`*.shared-import.*.orig`).  Those retained pre-images are durable, carried by `rebrew metadata backup` and restored with the bundle.  They accumulate one file per rewrite; prune the directory when the migration or the overwrite is confirmed good.  There is no per-run build diskcache: same-run compiles memoize in memory, cross-run persistence is the shared compile cache's job. |

## Who owns which fact

`rebrew-types.toml` is a canonical managed store for stable type identity and
target layout evidence (see [ADR 029](adr/029-managed-type-identities.md)).
`types.ID.MODULE` binds a C definition file/name to compiler-checked `size` and
`offsets`, separate `native_size` and `extent` (`allocation` or `stride`),
reviewed `evidence`, `cflags`, and input fingerprints. `rebrew types bind` owns
the locked atomic 0444 writes; never hand-edit this store. Keep it in version
control and ignore its `.lock`. `types check`/lint W031 report stale evidence;
`types check --compile` repeats layout assertions. Rebind the same ID after
reviewing a changed definition/context. A type has no instance address and
these records create no game progress or function/data verdict.

The type owner can record a reviewed source-path change inside a coordinated
transaction. It retains each prior full type record in `path_history`, labels
its freshness unassessed, and sets `path_revalidation_required`. Type checks
report that binding stale without compiling it. A successful reviewed rebind
clears the marker and retains the history. `rehome_type_bindings` is a metadata
owner API: it does not move files or establish include and target equivalence.
Older Rebrew versions with strict
format-1 field validation do not understand these optional fields; do not write
them in a project that still relies on such a version.

The format-3 `rebrew-functions.toml` includes addressless source evidence under
`source.definitions."metadata-relative/file.c".C_symbol.MODULE`, with
`source_hash` and `evidence` fields. `source.files.FILE.MODULE` records support
purposes. `rebrew source document-assembly` and `source register --support` use
the same function-store lock and atomic 0444 writer; keep the function store in
version control and ignore its `.lock`. Ordinary function/data comments remain
in their existing fields. The SHA-256 binds the parsed
definition text, including its signature/body/comments, to the selected target.
The review record neither asserts compiled reachability nor creates a byte
STATUS. Renames, moves and definition edits require clearing the old record
and reviewing evidence again; malformed or stale records warn through W031
and cannot exempt W020. See [the CLI contract](CLI.md#rebrew-source-document-assembly).

| Fact | Canonical store | Derived/cached copies |
|---|---|---|
| Function **identity** (which VAs are functions) | merged registry (`catalog/registry.py`: discovery inventory + `function_structure.json` + exports, minus IAT slots) | the coverage document's `functions` array (the grid is built in-process by `catalog/grid.py` and has no file of its own) |
| Function **size** | registry `canonical_size` (`+ size_reason`): the compile contract is stored metadata `SIZE` | the coverage document's `functions[].size` |
| Function **name** | C definition name (or the row's `name` / catalog fallback). The `MODULE.0xVA` key is the address | the coverage document's `functions[].name`, plus `list_name`/`ghidra_name` preserving the other authorities |
| Match **STATUS** | `rebrew-functions.toml`: written **only** via `metadata.update_source_status` / `update_statuses_batch` (promotion gate: SKIP stays parked); triggered by `rebrew test` / `rebrew verify` / `rebrew prove` (also `match`, `lint`, `binsync-import`, `intake`). Every write tags `updated_by` (test/verify/prove/match/lint/binsync-import/intake) + UTC `updated_at` | the coverage document's `functions[].status` + `updated_by`/`updated_at` and its `history[]` change log; the selected verify cache's measured-result overlay at report time |
| **BLOCKER / BLOCKER_DELTA** | `rebrew-functions.toml`: `metadata.update_field` / `remove_field` through `rebrew blocker set/clear`, `rebrew diff --fix-blocker`, `rebrew diagnose near --fix-blocker`, and `rebrew source document-unmatched`. Never hand-edited | the coverage document's `functions[].blocker`/`blockerDelta`; `rebrew status`/`todo` counts; `lint` W005 when `STUB` lacks one |
| **cflags / toolchain** | `rebrew-functions.toml` (per-function) → `rebrew-libraries.toml` (per-library, walk-up) → project defaults, resolved by `resolve_compile_overrides` | the coverage document's `functions[].cflags` |
| **Data symbols (globals)** | `rebrew-data.toml` (`file`/`kind` identity, plus `name`/`type`/`size`/`section`/`note`, verify-written data STATUS `VERIFIED`/`DRIFT`/`UNCHECKED`, and the `updated_by`/`updated_at` write stamp) | the coverage document's `globals[]`; `src/<target>/rebrew_globals.h` (`rebrew data header`; extern declarations for the build); `rebrew status` data counts + `rebrew todo --category data-drift` |
| Coverage presence | the project tree | the coverage document (`rebrew coverage export --output snapshots/` renders it in-process) |
| **Layout / PE normalization** | `layout/<target>/` package: `rebrew-layout.toml` (sections, exports, imports, export_stamp, link_options, image_base), `header.hex` (full PE header block: SizeOfImage/CheckSum/TimeDateStamp/section table), `iat.hex`, `prefix.hex`, `bookkeeping.hex`, `data.hex`, `reloc.hex`, `operands.txt`, `calls.txt` | `[link]` block (`file_align`, `stack_*`, `tsaware`, `timestamp`) consumed by `rebrew build round-trip --fix-headers` |
| **Import order / IAT** | original binary (IAT order), captured into `layout/<target>/` | `crt_region/crt_imports.c` (`#pragma comment(linker, "/include:__imp_...")`), `layout/<target>/rebrew-layout.toml` `imports[]` |
| **`.data` / BSS layout** | `rebrew-data.toml` (symbols) + `layout/<target>/data.hex` (reference bytes) | `src/link_stubs.c` (`g_bss_tail` pad, mutated by `rebrew build calibrate-bss`), `src/<target>/bss_padding.c` (`rebrew data fix-bss`; `gap_<va:08x>[N]` dummy arrays for detected gaps), `_dpad_<addr>[N]` pads inserted into `.c` files by `rebrew data layout fill` (byte-exact from the reference in the raw region, zero-init for BSS), `rebrew-layout.toml` `sections[.data].vs` |
| **Export table** | original binary, captured into `layout/<target>/` (`exports`, `export_stamp`, `exp_rva`) | `<target>.def` (`name @ ordinal` for the linker) |
| **Ghidra provenance** (names/sizes) | `src/<target>/function_structure.json`, `ghidra_data_labels.json` (external exports, provenance-stamped) | registry `list_name`/`ghidra_name`, the coverage document's `functions[].detected_by` / `size_by_tool` / `size_reason` |

## Write provenance

Who last changed a fact, and when, lives in the canonical store itself: both
stores carry an `UPDATED_BY` / `UPDATED_AT` pair, and every gated writer
supplies its own tag.

- **Function store.** `update_source_status` / `update_statuses_batch` stamp on
  a status write; `update_field` and `set_fields` stamp on every other field, so
  a `BLOCKER` / `NOTE` / `CFLAGS` / `GHIDRA` edit names the tool that made it
  instead of leaving the last status writer's tag standing.  `MetadataEntry.apply`
  (the typed facade) forwards the same keyword.  A writer that passes no tag
  leaves the stored stamp alone, so an un-tagged programmatic write is never
  mistaken for a tool's work.
- **The tag vocabulary is closed.**
  `rebrew.metadata.functions.PROVENANCE_TAGS` lists the nineteen writers (`binsync-import`,
  `blocker`, `cross-import`, `data`, `diff`, `document-unmatched`, `fix-sizes`,
  `import-splat`, `inline-strings`, `intake`, `lint`, `match`, `near-diag`,
  `prove`, `rehome`, `rename`, `skeleton`, `test`, `verify`).  A tag outside it is a typo
  or a tool nobody updated the list for; `rebrew lint` reports both (W031)
  rather than letting "who wrote this" be answerable only by grepping the
  writers.
- **Each store carries a format stamp.**  The top-level `format`
  (`rebrew.metadata.document.FUNCTION_FORMAT_VERSION`, currently `3`, for the
  function store; `FORMAT_VERSION`, currently `2`, for data) is mandatory.
  Readers and writers reject missing or foreign versions; they never silently
  upgrade a store. W031 also reports malformed metadata.
- **The pair means "last changed", not "last checked".**  A writer that sets a
  field to the value it already holds returns without a write, so a re-run of
  `verify --data` that finds the same `VERIFIED` / `DRIFT` / `UNCHECKED` verdict
  leaves the stamp where the last *change* left it.  Durable measurement evidence is the row's `verification` table;
  the coverage document's `verify_results[].verified_at` is a derived view; "who changed this, and
  when" is the pair.
- **Deletes leave no tombstone.**  `remove_field` / `remove_fields_batch` and
  the orphan pruning drop a field or a row outright; the coverage document's
  `history[]` records status transitions only.  A store that needs an audit
  trail of removals gets one deliberately (a log the tools append to), not by
  hoping the absence is reconstructable.
- **Identity paths are gated.** `validate_identity_file` checks the `file`
  field before storage, refusing an absolute path or a `..` segment. Source and
  compiled-provider identities use the distinct resolution roots in the
  [current source contract](#current-source-contract). W034 reports rows written
  before that gate.  W035 reports a row whose module matches no target module or
  library module: invisible to `status`/`todo`, which filter by module.
- **The store is found by directory, not by search.**  A reader is handed
  `metadata_dir` (plus `reversed_dir` and `shared_dir`) and reads whatever is
  there; no loader walks up looking for a better copy.  So a second
  `rebrew-data.toml` elsewhere in the tree is not a backup, it is a file that
  answers for its own directory when a tool is pointed at it and is invisible
  everywhere else.  W036 reports one outside those three directories.
- **Data store.** `set_data_field` / `set_data_fields_batch` stamp the same pair
  alongside whichever field they change, tagged by the writer that ran: `verify`
  from `verify --data` on a
  `VERIFIED` / `DRIFT` / `UNCHECKED` verdict, `rename` from `rebrew source rename` on a
  renamed global, `data` from `rebrew data list`, `lint` when it fills a data
  row's missing section.
  The separate `verification` table keeps the measurement's producer, input
  digest and time alive after deleting `db/` and after later label/note edits.
  The coverage document's `verify_results[]` row
  (`verified_at`, `byte_delta`, `diff_lines`, `similarity`, `reg_delta`,
  `effective_match`) is derived and a rebuild only carries it forward.
- **Similarity belongs to the comparison.** Function rows may carry a protected
  `similarity` percentage, copied from accepted test/verify evidence. Numeric
  alignment counts stay in `verification`; ordinary setters cannot supply the
  row field. Live readers omit scores with stale source/header/compiler inputs
  or changed size/compile overrides. This score never changes STATUS or matched
  byte accounting; see [the store format](METADATA_FORMAT.md#functions).
- **Status history is durable.** The function metadata owner appends
  `status_history` (`old_status`, `new_status`, `changed_at`, `updated_by`)
  atomically with each accepted status transition. It validates, deduplicates and
  retains the newest 10,000 events per native identity. Live views and portable
  documents expose that history with each identity's `va`. Generic field setters
  cannot forge history. `rebrew coverage import-history --snapshots <directory>`
  preserves existing exported events without changing verdicts, bindings, edit
  stamps or measurement evidence; `--dry-run` creates no files or locks.
- **No generation stamp.** The document deliberately carries no "written at"
  field: a rebuild of unchanged input must be byte-identical, and a timestamp is
  the one value that would move on every run.  Freshness is read from the inputs:
  live readers fingerprint metadata, inventory, source, binary and link inputs.
  Explicit offline readers key their cache on portable document file identity.
  `version` is the schema stamp, not a build stamp.

### External origin and measurement evidence

`UPDATED_BY/AT` remains the last ordinary row change. `verification` separately
records the comparison `status`, `writer` (`test` or `verify`), `input_hash`
(SHA256), and `measured_at`, plus available source/reference/header/compiler
fingerprints. Function evidence is captured before compilation. A linked EXACT
(`rebrew verify --text --raw-link`) adds `linked_image` and `linked_image_hash`, the
raw link it was measured on; see [linked EXACT](CLI.md#rebrew-verify). Data evidence
includes the definition and compared bytes. Repeating the same evidence preserves
its time and does not replace a note editor's stamp; a changed input digest is
recorded even if the verdict stays the same. `measured_at` is the first observation
of that exact evidence, not a heartbeat recording every check.

`origins.<native_field>` records the last accepted external value's tool, user
when supplied, snapshot content hash, binary/commit identity when available, and
`value_hash`. It is distinct from the importing command's `UPDATED_BY` tag. A
later local edit can make that origin historical; sync health reports such
`stale_origins` instead of attributing the new value to the earlier contributor.
Definition edits still invalidate data STATUS, while retaining earlier evidence
for inspection. Sync health reports stale measurement evidence independently.

## Precedence rules (who wins on conflict)

1. **Dedicated metadata is the only state source.** Identity is the qualified
   `MODULE.0xVA` row with `file`, `symbol`, `name`, and `kind`. SIZE, CFLAGS,
   STATUS, reconstruction `source`, STRUCT/CALLERS and other state are stored
   there. Optional ADDRESS comments bind exactly the next C declaration.
   Inline state and old block formats fail lint E024; `--fix` does not migrate
   them. `rebrew source register` validates current anchors and preserves
   existing stored fields. No compatibility reader is shipped.
2. **STATUS display precedence**: metadata `PROVEN`/`SKIP` (and `STUB` over
   the cache's `SIZE_MISMATCH`/`MISSING_SIZE`/`STUB`) > the selected verify cache's
   measured result (the cache holds byte verdicts only, never PROVEN)
   > grid/DB snapshot.
3. **Per-function > per-library > project** for toolchain/cflags
   (`resolve_compile_overrides`).
4. **SIZE precedence**: compile contract = stored metadata `SIZE`;
   coverage = registry canonical size.
5. **Shared-tree scoping**: one `rebrew-functions.toml` holds qualified rows
   for every target at a metadata root. Shared C definitions may bind one row
   per target, with optional stacked ADDRESS anchors. Library headers carry no
   inventory state: readers use managed LIBRARY rows naming the header, scoped
   to the active target and configured libraries. A compiled-source provider
   binding takes precedence over a header declaration. Independent same-VA
   identities in different modules remain separate.
6. **Library attributions are not progress**: `kind = "LIBRARY"` rows and
   rows whose module is listed in `targets.<name>.external_libs` tally
   into `library_identified`, outside the EXACT/RELOC progress table and
   its denominators; the table answers "how much of this binary's code
   is reversed".

## Sync stores (external)

- **BinSync state dir** (the field-level sync interchange): `functions/*.toml`, `global_vars.toml`, `structs/*.toml` carry
  BinSync-native fields (name, prototype, size, notes, globals, structs);
  rebrew exports via `rebrew sync push --state-dir D` and imports via
  `rebrew sync pull --state-dir D`. Raw local artifacts use
  `rebrew binsync export` / `rebrew binsync import`. The BinSync Ghidra plugin relays
  the state to/from Ghidra.  STATUS/CFLAGS are NOT in the state: they stay
  local in `rebrew-functions.toml`: STATUS is comparison-earned and CFLAGS
  are compiler inputs. See [BINSYNC_INTEGRATION.md](BINSYNC_INTEGRATION.md)
  for shared field ownership and reconciliation.
- **Ghidra** (ReVa MCP): only the structural ops the state dir cannot
  express; `rebrew sync create-functions`, `rebrew sync bookmarks`,
  `rebrew sync pull-data`.
  `src/<target>/function_structure.json` and `ghidra_data_labels.json` are
  Ghidra exports used as **registry inputs** (not sync outputs).
- **recondb checkout** (sibling repo, `REBREW_FLIRT_SIGS_DIR`
  overrides): standard-library `.pat` signature sources, merged with the
  project's own `flirt_sigs/` at load time (project sigs win).  Read-only
  input, like the recompile-toolchains checkout, it is external, not a
  project store.

## Layout package lifecycle

`rebrew build layout` derives `layout/<target>/` (text-only: `rebrew-layout.toml` +
`*.hex` byte files) and the `[link]` config block
from the reference binary.  The package is committed to git;
`rebrew build postlink --layout <dir>` consumes it to normalize a built binary onto the
reference **without the original DLL present**.  Regenerate the package
whenever the reference binary changes: the layout files carry
"do not hand-edit" headers.

## Store formats

A store **rebrew owns** is clear-text TOML, one format for all of them:
`rebrew-project.toml`, `rebrew-functions.toml`, `rebrew-data.toml`,
`rebrew-types.toml`, `rebrew-libraries.toml`,
`snapshots/coverage-<target>.toml`, and the verify cache and
`--compare` baseline (`.rebrew/verify_cache.toml` / `.rebrew/verify_baseline.toml`,
or the same filenames under `.rebrew/targets/<sha256-of-exact-target-name>/` once
the project keeps per-target verification state). Normal dashboards read canonical project
inputs through `load_project_coverage`; no generated coverage store or project
`db_dir` is required. `coverage export --output <directory>` creates portable
TOML snapshots for explicit offline use. Readers use `tomllib`; owning writers
preserve documents with `tomlkit`.

The stores that stay in another tool's format are that tool's contract, not
rebrew's to rename:

| File | Owner of the format |
|---|---|
| `compile_commands.json` | clang's compilation database |
| `objdiff.json` | objdiff's project file |
| `sigs/index.json` (FLIRT pack) | the signature pack that ships it |
| `src/<target>/function_structure.json`, `ghidra_data_labels.json`, `ghidra_switchdata.json` | the Ghidra scripts that export and re-import them |
| `.rebrew/ga_runs.jsonl` (+ `.rebrew/sync/*.toml` BinSync baselines) | rebrew's own append-only GA log: one line per event, so a TOML document would have to be rewritten per event.  Derived in that nothing reads it as authoritative, but *not* regenerable: a win record is the fingerprint (cflags, size, source hash, mutations) of a run that took hours, and re-running does not reproduce it.  Winning lines are kept for good; non-winning ones are capped at the newest `_LOSS_RECORD_RETENTION` so the log stays bounded.  It lives under the gitignored run directory, so copy it out of the project (or commit it) if the solved history is worth keeping.  `rebrew match solutions --backup <dir>` makes the off-tree copy and verifies it byte-for-byte; `--restore <file>` installs it back, preserving the current log as `.before-restore`; `rebrew metadata backup --dir <dir>` also carries the GA log and the BinSync baselines inside its bundle (TOML: in `rebrew-metadata.backup.toml/`; SQLite: beside `rebrew-metadata.backup.sqlite3`) and `rebrew metadata restore --file` installs them back |
| declib BinSync state files | declib |

"One source of truth" is about rebrew-owned state: one store per fact, no cache
that can disagree with it.  A format another program reads stays where it is
until that program changes with it.

## Rules for new stores

1. Ask *which tier* the new store is before writing it.  If it derives
   from existing canonical data, it belongs in Derived or Cache, and
   should be buildable from one command, never hand-edited.
2. One parser per file format.  Shared parsers live in
   `catalog/loaders.py` (discovery inventory, rizin `afl`) and
   `rebrew/metadata/document.py` (`load_metadata_doc`, `parse_metadata_doc`);
   the collection transaction is `metadata.storage.metadata_write_lock`.
   Do not hand-roll another copy.
3. Writes to canonical stores go through the gated APIs:
   `update_source_status` / `update_statuses_batch` (STATUS),
   `update_field` / `remove_field` (function metadata, incl. `rebrew blocker`
   for BLOCKER), `set_data_field` / `set_data_fields_batch` (data metadata;
   keys limited to `DATA_METADATA_FIELDS`, STATUS to the three data
   verdicts, so a function-only field such as BLOCKER raises), `rebrew library set`
   (library overrides).  **Do not hand-edit `rebrew-functions.toml`,
   `rebrew-data.toml`, `rebrew-types.toml`, or `rebrew-libraries.toml`**:
   every write goes through `metadata_write_lock`, and the two function/data
   stores use `atomic_write_locked` on top (see `rebrew/metadata/functions.py`,
   `rebrew/metadata/data.py`, `rebrew/library.py`).
   `rebrew-project.toml` is a store too: every writer (`lint --fix` dropping a
   `cflags_presets` key, a splat import patching `[targets.<name>].arch`, the
   intake arch rewrite, the doctor wibo fixup) takes
   `rebrew.config.project_toml_lock` around the whole read, edit, and write,
   not just the write.  Each edits one key in a document it parsed wholesale,
   so an unlocked writer drops a concurrent writer's key silently.
   No module-less metadata keys: the writers reject an empty module (a bare
   `0xVA` key was once writable but never readable; the guard now raises
   instead).
4. Caches must be invalidation-correct: stat-keyed or content-keyed, and
   written with the shared `atomic_write_text` / `metadata_write_lock`
   machinery (tool-owned TOML uses `atomic_write_locked` so the file stays
   mode 0444). `write_coverage_toml` holds `_coverage_write_lock` across
   validation and replacement of an explicit export. Malformed existing snapshots
   and unimported historical events block overwrite, preserving old evidence.
   Import the events through the metadata owner before re-exporting. Live reads
   never write snapshots or acquire writer locks.
5. Generated scaffolding that must survive without `original/` (layout
   package, `.def`, `crt_region/`, `link_stubs.c`, toolchain files) is
   **VCS-intended**: derive it once, commit it, rebuild only on binary
   change.  Keep the generator idempotent so re-runs are no-ops when the
   binary is unchanged.

## Integration baseline and freshness

`.rebrew/sync/<identity>.toml` is a project-local integration sidecar. Its identity
scopes it to the state directory and target module; its binary hash prevents
using acknowledgements from a different image. It stores the normalized values
last observed equal after successful application. It is not authoritative
metadata: deleting it loses automatic three-way decisions, not names or evidence.

Push, pull and `binsync diff --json` use the same native field rules from
`metadata.SYNC_FIELD_RULES`. STATUS, compiler flags and verification evidence
are not integration fields. Function SIZE is export-only. Names and prototypes
are compared separately; prototype pulls update the actual C definition through
the AST, and type updates require an unambiguous existing definition.

With a baseline, a local-only change is pending push, a remote-only change is
pending pull, equal values are acknowledged without rewriting, and differing
changes on both sides are conflicts. Push preserves incoming/conflicting values.
Pull keeps unresolved fields, with explicit `--accept-binsync` or `--accept-local`
for resolution. Failed applications and previews never acknowledge their changes.
Omitted remote fields or removed functions are reported as `deletion_required`;
absence is not permission to erase local work or resurrect the remote object.
Explicit local clears and `--clean` exports remain deliberate outgoing removals.

`manifest.toml` carries `metadata_schema`, `input_hash` of the canonical native
projection, and `content_hash` over artifact paths and contents, alongside the
existing export time and binary identity. Timestamps and verification stamps
are excluded from the projection. `health` in diff/push/pull JSON explains pending
pushes/pulls, conflicts, missing baselines, removals, changed inputs or artifacts,
stale origins and evidence, and blocking binary/schema mismatches. An unchanged
export preserves artifact, manifest and baseline mtimes. Watch mode refreshes
its input paths so newly added sources and types, data metadata, config, binary,
and remote state changes trigger reconciliation.

Data storage relationships use managed `storage_kind` (`object`, `alias`,
`literal`, `span`, `import`), `backing` (the allocating global), and `link_symbol`
(the exact verified native symbol). Write them through `rebrew data set --storage-kind`,
`--backing`, `--link-symbol`, or `set_data_fields_batch`. These describe
provenance rather than a byte verdict; recording them does not verify storage.

## Current source contract

Functions use format 3; data uses format 2. Qualified `MODULE.0xVA` tables hold function/data
identity and state; `kind` classifies the row. Source accepts only optional
ADDRESS anchors immediately above C declarations. `source = "naked"`, structure
and caller information are function metadata. Assembly evidence and support file
purposes use `[source.definitions]` and `[source.files]` in the function store.
BinSync manifests retain schema 2: synchronized field records did not change
when the local function container gained its addressless source section.

`rebrew source register` records current declaration-bound identities without
importing state from comments. Older schemas and inline blocks are rejected;
ordinary readers have no legacy fallback. To upgrade, preview
`rebrew source consolidate --dry-run --json`, then apply with its
`--expected-digest`. This explicit one-shot migration preserves function rows,
verdicts and source receipts before retiring `rebrew-source.toml`. See [source addresses](ANNOTATIONS.md)
and [ADR 030](adr/030-address-only-source.md).

Source `file` identities use exact paths relative to the resolved metadata root.
Configured source directories must resolve inside that root; see the
[configuration rule](CONFIG.md#what-the-config-loader-provides).
Compiled LIBRARY providers explicitly use the project root. Source readers and
file-index helpers share that distinction; their optional `project_root` keyword
passes known configuration context without another project lookup. Standalone
reads resolve the enclosing project from the metadata directory, never CWD.
Suffix/basename matching is not supported. Contradictory address anchors fail
instead of inheriting the managed provider's verdict.

Non-verdict data edits use `metadata.data.patch_data_fields_batch`: normalize and
validate all fields, merge equal repetitions, reject contradictions and report
`input_digest`. A dry run takes no writer lock and creates no artifacts. Apply
can require that digest; it is checked again under the same metadata write lock.
Identity/definition/placement changes remove current `status` while retaining
`verification`; notes and unchanged fields preserve the verdict.


Reviewed source identity changes use `metadata.binding_history.change_source_binding`.
The managed `binding_history` array retains prior identities and their last measured
status/verification. Generic setters cannot edit it. Retirement removes the current
source claim and verdict, preserving the native row/size and all existing evidence.
Only a reviewed rebind can reactivate it; a delayed comparison cannot promote a
retired row. Ordinary registration and historical ADDRESS comments cannot resurrect
it. A replacement drops its own current verdict; an explicit existing counterpart
is validated and left unchanged. Automatic pruning preserves binding history.

`catalog.inventory.repair_inventory_extents` edits only selected native inventory
sizes. Its complete-input digest and one-publication batch are independent from
function/data metadata, and boundary evidence does not earn a comparison verdict.

### Reviewed native library identity

`native_identity` is managed by `metadata.native_identity.record_native_identity`
after `native_review.review_native_identity` proves the complete compiled function,
typed fixups and compiler-literal values. Generic field writers cannot forge or
remove it. The receipt is binary-bound and records the exact symbol, complete
size, object hash, named dependencies, current source claim, reason and UTC review
time. Resolver reads validate the receipt and current binary/claim/size/dependencies;
stale receipts remain historical evidence but contribute no trusted name. Library
attribution and selected build providers do not establish this identity themselves.

The callee map retains conflicting function names as `coff_reloc.AMBIGUOUS_VA`
(a negative non-address). This is separate from an absent/unidentified symbol.
An ambiguous operand fails both tolerant and strict comparison and reports
`AMBIGUOUS`; it does not fail construction of the entire target catalog. The
symbol resolver never exposes the sentinel as a relocation destination.
