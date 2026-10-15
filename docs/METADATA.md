# Metadata & Derived-State Architecture (the "store tiers")

This is the one-page map of **every place rebrew persists or caches data**
and, crucially, which of them is authoritative for which fact.  It exists
so the "why are there so many files?" question has a written answer: most
of the surface is *derived snapshots and caches*, not competing sources of
truth.  Pages 6–7 of [architecture.drawio](architecture.drawio) draw the
same tiers and the data/globals/layout pipeline.

## The four tiers

| Tier | Stores | Contract |
|---|---|---|
| **Canonical (durable)** | pure C sources, `rebrew-functions.toml`, `rebrew-data.toml`, `rebrew-source.toml`, `rebrew-types.toml`, `rebrew-libraries.toml`, `rebrew-project.toml` | Source/config are editable; identity and other non-derivable evidence are CLI/API-managed. Optional ADDRESS anchors bind declarations; old inline blocks and earlier schemas are rejected. Derived views are rebuilt from these plus the binary; recorded history is identified separately below. |
| **Derived, VCS-intended** | `src/<target>/function_structure.json` (discovery inventory), `<target>.def`, `crt_region/*.c`, `src/link_stubs.c`, `src/<target>/bss_padding.c`, `src/<target>/rebrew_globals.h`, `layout/<target>/`, `[link]` config blocks, `flirt_sigs/*.pat`, `cmake/toolchain-*.cmake` | Build scaffolding generated from the binary / binary-derived facts (`rebrew build layout`, `rebrew binary functions`, `rebrew coverage catalog`, `rebrew build link-stubs`, `rebrew data fix-bss`, `rebrew data header`, signature tools).  Committed to git so a rebuild never needs `original/` around; regenerable via the generating command.  Never hand-edit. |
| **Derived, gitignored (build output)** | `snapshots/coverage-<target>.toml`, `bin/<target>/*.bin`, `output/report/` | Rebuildable via `rebrew coverage export --output snapshots/` / `rebrew verify` / `rebrew binary extract` / `rebrew coverage report`.  Treat as build output.  `rebrew verify` writes a report file only with an explicit `--output` path; the `--compare` baseline lives in `.rebrew/verify_baseline.toml` (the old `db/verify_results.json` snapshot was unguarded and is no longer written; see `verify_cache.load_baseline`). |
| **Cache (delete-safe)** | `.rebrew/verify_cache.toml`, `.rebrew/compile_cache/`, `output/ga_runs/*/checkpoints/*.json`, `output/ga_runs/*/best.c`, `output/ga_runs/*/<symbol>.best.c`, `.rebrew/source-backups/*.orig`, in-memory mtime caches | Regenerated on demand.  Deleting costs a recompile/re-verify/resync at most.  The exception: `.rebrew/ga_runs.jsonl` is *history*, not cache; it accumulates GA outcomes (including winning fingerprints) re-running would not reproduce, each record is fsynced before `rebrew match run` reports the run so a host that loses power does not take the win with it, and only the non-winning lines are capped (newest `_LOSS_RECORD_RETENTION`, wins kept forever).  `.rebrew/source-backups/` holds a copy of a `.c` that `rebrew match climb` / `rebrew match qualifiers` is about to rewrite in place: it exists only while that run is in flight, is removed when the run finishes, and is the way back to the pre-run bytes after a kill that runs no cleanup (SIGKILL, OOM, power cut).  `rebrew skeleton --force` keeps its backup after a clean replacement (`*.pre-skeleton.*.orig`).  They accumulate one file per rewrite; prune the directory when the migration or the overwrite is confirmed good.  There is no per-run build diskcache: same-run compiles memoize in memory, cross-run persistence is the shared compile cache's job. |

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

`rebrew-source.toml` is managed by `rebrew source document-assembly` (API:
`rebrew.metadata.source_provenance.document_assembly`) with the shared locked, atomic
0444 writer. Keep `rebrew-source.toml` in version control and ignore its
`rebrew-source.toml.lock` coordination file, just like the function/data locks.
It records reviewed original-assembly evidence for a definition
without requiring a VA. `format = 2` and
`definitions."metadata-relative/file.c".C_symbol.MODULE` identify each record;
each definition record has `source_hash` and `evidence`; the separate `files` table records target-scoped support purposes. The SHA-256 binds the parsed
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
| Match **STATUS** | `rebrew-functions.toml`: written **only** via `metadata.update_source_status` / `update_statuses_batch` (promotion gate: SKIP stays parked); triggered by `rebrew test` / `rebrew verify` / `rebrew prove` (also `match`, `lint`, `binsync-import`, `intake`). Every write tags `updated_by` (test/verify/prove/match/lint/binsync-import/intake) + UTC `updated_at` | the coverage document's `functions[].status` + `updated_by`/`updated_at` and its `history[]` change log; `.rebrew/verify_cache.toml` measured-result overlay at report time |
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
  (`rebrew.metadata.functions.FORMAT_VERSION`, currently `2`) is mandatory.
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
- **Identity paths are gated.**  The `file` field is joined onto the project
  root by `verify`, `rename` and BinSync, so `validate_identity_file` refuses an
  absolute path or a `..` segment at the write, and W034 reports rows written
  before that gate.  W035 reports a row whose module matches no target marker or
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
  renamed global, `data` from `rebrew data list`, `lint` on a migrated data marker.
  The separate `verification` table keeps the measurement's producer, input
  digest and time alive after deleting `db/` and after later label/note edits.
  The coverage document's `verify_results[]` row
  (`verified_at`, `byte_delta`, `diff_lines`, `similarity`, `reg_delta`,
  `effective_match`) is derived and a rebuild only carries it forward.
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
   the cache's `SIZE_MISMATCH`/`MISSING_SIZE`/`STUB`) > `.rebrew/verify_cache.toml`
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
from the reference binary.  The package is committed to git; `rebrew
postlink --layout <dir>` consumes it to normalize a built binary onto the
reference **without the original DLL present**.  Regenerate the package
whenever the reference binary changes: the layout files carry
"do not hand-edit" headers.

## Store formats

A store **rebrew owns** is clear-text TOML, one format for all of them:
`rebrew-project.toml`, `rebrew-functions.toml`, `rebrew-data.toml`,
`rebrew-libraries.toml`, `snapshots/coverage-<target>.toml`, `.rebrew/verify_cache.toml`
and `.rebrew/verify_baseline.toml`. Normal dashboards read canonical project
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
| `.rebrew/ga_runs.jsonl` | rebrew's own append-only GA log: one line per event, so a TOML document would have to be rewritten per event.  Derived in that nothing reads it as authoritative, but *not* regenerable: a win record is the fingerprint (cflags, size, source hash, mutations) of a run that took hours, and re-running does not reproduce it.  Winning lines are kept for good; non-winning ones are capped at the newest `_LOSS_RECORD_RETENTION` so the log stays bounded.  It lives under the gitignored run directory, so copy it out of the project (or commit it) if the solved history is worth keeping |
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
   `rebrew/metadata/document.py` (`load_metadata_doc`, `parse_metadata_doc`,
   `metadata_write_lock`): do not hand-roll a third copy.
3. Writes to canonical stores go through the gated APIs:
   `update_source_status` / `update_statuses_batch` (STATUS),
   `update_field` / `remove_field` (function metadata, incl. `rebrew blocker`
   for BLOCKER), `set_data_field` / `set_data_fields_batch` (data metadata;
   keys limited to `DATA_METADATA_FIELDS`, STATUS to the three data
   verdicts, so a function-only field such as BLOCKER raises), `rebrew library set`
   (library overrides).  **Do not hand-edit `rebrew-functions.toml`,
   `rebrew-data.toml`, or `rebrew-libraries.toml`**: every write goes
   through `metadata_write_lock`, and the two function/data stores use
   `atomic_write_locked` on top (see `rebrew/metadata/functions.py`,
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
4. Caches must be invalidation-correct: mtime-keyed or content-keyed, and
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

All stores use format 2. Qualified `MODULE.0xVA` tables hold function/data
identity and state; `kind` classifies the row. Source accepts only optional
ADDRESS anchors immediately above C declarations. `source = "naked"`, structure
and caller information are function metadata. Assembly evidence and support file
purposes use the `definitions` and `files` tables in `rebrew-source.toml`.

`rebrew source register` records current declaration-bound identities without
importing state from comments. Older schemas and inline blocks are rejected;
no legacy migration reader is shipped. See [source addresses](ANNOTATIONS.md)
and [ADR 030](adr/030-address-only-source.md).

Source `file` identities use exact paths relative to the resolved metadata root.
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
