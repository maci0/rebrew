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
| **Canonical (user-owned)** | `.c` marker lines, `rebrew-functions.toml`, `rebrew-data.toml`, `rebrew-libraries.toml`, `rebrew-project.toml` | The only stores you hand-edit or that hold non-derivable facts.  Everything below is regenerable from these (plus the binary). |
| **Derived, VCS-intended** | `src/<target>/function_structure.json` (discovery inventory), `<target>.def`, `crt_region/*.c`, `src/link_stubs.c`, `src/<target>/bss_padding.c`, `src/<target>/rebrew_globals.h`, `layout/<target>/`, `[link]` config blocks, `flirt_sigs/*.pat`, `cmake/toolchain-*.cmake` | Build scaffolding generated from the binary / binary-derived facts (gen-layout, discover-functions, catalog, gen-link-stubs, `rebrew data --fix-bss` / `--gen-header`, flirt).  Committed to git so a rebuild never needs `original/` around; regenerable via the generating command.  Never hand-edit. |
| **Derived, gitignored (build output)** | `db/coverage-<target>.toml`, `bin/<target>/*.bin`, `output/report/` | Rebuildable via `rebrew build-db` / `rebrew verify` / `rebrew extract` / `rebrew report`.  Treat as build output.  `rebrew verify` writes a report file only with an explicit `--output` path; the `--compare` baseline lives in `.rebrew/verify_baseline.toml` (the old `db/verify_results.json` snapshot was unguarded and is no longer written — see `verify_cache.load_baseline`). |
| **Cache (delete-safe)** | `.rebrew/verify_cache.toml`, `.rebrew/compile_cache/`, `output/ga_runs/*/checkpoints/*.json`, `output/ga_runs/*/best.c`, `output/ga_runs/*/<symbol>.best.c`, in-memory mtime caches | Regenerated on demand.  Deleting costs a recompile/re-verify/resync at most.  The exception: `.rebrew/ga_runs.jsonl` is *history*, not cache — it accumulates GA outcomes (including winning fingerprints) re-running would not reproduce.  There is no per-run build diskcache — same-run compiles memoize in memory, cross-run persistence is the shared compile cache's job. |

## Who owns which fact

| Fact | Canonical store | Derived/cached copies |
|---|---|---|
| Function **identity** (which VAs are functions) | merged registry (`catalog/registry.py`: discovery inventory + `function_structure.json` + exports, minus IAT slots) | the coverage document's `functions` array (the grid is built in-process by `catalog/grid.py` and has no file of its own) |
| Function **size** | registry `canonical_size` (`+ size_reason`) — the compile contract is annotation/metadata `SIZE` | the coverage document's `functions[].size` |
| Function **name** | annotation name (the `// FUNCTION: MODULE 0xVA` line) | the coverage document's `functions[].name`, plus `list_name`/`ghidra_name` preserving the other authorities |
| Match **STATUS** | `rebrew-functions.toml` — written **only** via `metadata.update_source_status` / `update_statuses_batch` (promotion gate: SKIP stays parked) — triggered by `rebrew test` / `rebrew verify` / `rebrew prove` (also `match`, `lint`, `binsync-import`, `intake`). Every write tags `updated_by` (test/verify/prove/match/lint/binsync-import/intake) + UTC `updated_at` | the coverage document's `functions[].status` + `updated_by`/`updated_at` and its `history[]` change log; `.rebrew/verify_cache.toml` measured-result overlay at report time |
| **BLOCKER / BLOCKER_DELTA** | `rebrew-functions.toml` — written **only** via `metadata.update_field` / `remove_field` through `rebrew blocker set/clear`, `rebrew diff --fix-blocker`, `rebrew near-diag --fix-blocker`, `rebrew document-unmatched` (never hand-edited) | the coverage document's `functions[].blocker`/`blockerDelta`; `rebrew status`/`todo` counts; `lint` W005 when `STUB` lacks one |
| **cflags / toolchain** | `rebrew-functions.toml` (per-function) → `rebrew-libraries.toml` (per-library, walk-up) → project defaults, resolved by `resolve_compile_overrides` | the coverage document's `functions[].cflags` |
| **Data symbols (globals)** | `rebrew-data.toml` (`name`/`type`/`size`/`section`/`note`, verify-written data STATUS `VERIFIED`/`DRIFT`/`UNCHECKED`, and the `updated_by`/`updated_at` write stamp) | the coverage document's `globals[]`; `src/<target>/rebrew_globals.h` (`rebrew data --gen-header` — extern declarations for the build); `rebrew status` data counts + `rebrew todo --category data-drift` |
| Coverage presence | the project tree | the coverage document (`rebrew build-db` renders it in-process) |
| **Layout / PE normalization** | `layout/<target>/` package — `rebrew-layout.toml` (sections, exports, imports, export_stamp, link_options, image_base), `header.hex` (full PE header block: SizeOfImage/CheckSum/TimeDateStamp/section table), `iat.hex`, `prefix.hex`, `bookkeeping.hex`, `data.hex`, `reloc.hex`, `operands.txt`, `calls.txt` | `[link]` block (`file_align`, `stack_*`, `tsaware`, `timestamp`) consumed by `rebrew round-trip --fix-headers` |
| **Import order / IAT** | original binary (IAT order), captured into `layout/<target>/` | `crt_region/crt_imports.c` (`#pragma comment(linker, "/include:__imp_...")`), `layout/<target>/rebrew-layout.toml` `imports[]` |
| **`.data` / BSS layout** | `rebrew-data.toml` (symbols) + `layout/<target>/data.hex` (reference bytes) | `src/link_stubs.c` (`g_bss_tail` pad, mutated by `rebrew calibrate-bss`), `src/<target>/bss_padding.c` (`rebrew data --fix-bss` — `gap_<va:08x>[N]` dummy arrays for detected gaps), `_dpad_<addr>[N]` pads inserted into `.c` files by `rebrew data --fill-data` (byte-exact from the reference in the raw region, zero-init for BSS), `rebrew-layout.toml` `sections[.data].vs` |
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
  `rebrew.metadata.PROVENANCE_TAGS` lists the eighteen writers (`binsync-import`,
  `blocker`, `cross-import`, `crt-match`, `data`, `diff`, `document-unmatched`,
  `fix-sizes`, `identify-library`, `intake`, `lint`, `match`, `near-diag`,
  `prove`, `rename`, `skeleton`, `test`, `verify`).  A tag outside it is a typo
  or a tool nobody updated the list for; `rebrew lint` reports both (W031)
  rather than letting "who wrote this" be answerable only by grepping the
  writers.
- **Each store carries a format stamp.**  The top-level `format`
  (`rebrew.metadata.FORMAT_VERSION`, currently `1`) is added by the first write
  to a file that has none and never rewritten, including when a file carries a
  foreign value: silently upgrading the stamp would hide the mismatch it exists
  to report.  Readers ignore it; W031 reports a missing or foreign one.
- **The pair means "last changed", not "last checked".**  A writer that sets a
  field to the value it already holds returns without a write, so a re-run of
  `verify --data` that finds the same `VERIFIED` / `DRIFT` / `UNCHECKED` verdict
  leaves the stamp where the last *change* left it.  "When was this measured" is
  the coverage document's `verify_results[].verified_at`; "who changed this, and
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
  library module — invisible to `status`/`todo`, which filter by module.
- **Data store.** `set_data_field` / `set_data_fields_batch` stamp the same pair
  alongside whichever field they change, tagged by the writer that ran: `verify`
  from `verify --data` on a
  `VERIFIED` / `DRIFT` / `UNCHECKED` verdict, `rename` from `rebrew rename` on a
  renamed global, `data` from `rebrew data`, `lint` on a migrated data marker.
  The verdict stamp is the one that matters: it keeps the measurement's author
  and time alive after deleting `db/`.
  The coverage document's `verify_results[]` row
  (`verified_at`, `byte_delta`, `diff_lines`, `similarity`, `reg_delta`,
  `effective_match`) is derived and a rebuild only carries it forward.
- **Coverage document.** It mirrors the function store's
  `functions[].updated_by` / `updated_at` and keeps a change log: `history[]`
  (`va`, `old_status`, `new_status`, `changed_at`, `updated_by`), retained
  newest-last across rebuilds and bounded by `HISTORY_RETENTION`.
- **No generation stamp.** The document deliberately carries no "written at"
  field: a rebuild of unchanged input must be byte-identical, and a timestamp is
  the one value that would move on every run.  Freshness is read from the inputs
  — `[metadata] paths` (`originalDll`, `sourceRoot`) — and the dashboards key
  their snapshot cache on the document's own stat.  `version` is the schema
  stamp, not a build stamp.

## Precedence rules (who wins on conflict)

1. **Metadata wins over inline `.c` annotations** for owned fields (STATUS,
   TOOLCHAIN, BLOCKER, NOTE, GHIDRA, …).  Inline forms of
   those keys are deprecated — lint **W019** flags them, `--fix` migrates.
   `SIZE` is co-read, not migrated: `// SIZE:` is the reccmp-native contract
   in the `.c` (an external build reads the file directly) and the TOML value
   is an override, so W019 warns only on inline↔metadata **disagreement**.
   `// CFLAGS:` gets the same disagreement-only check when the metadata has a
   CFLAGS value; without one it is deprecated and migrated like the rest.  `// SOURCE: naked` is likewise
   file-borne and exempt (it must travel with the file; self-clears when the
   C body replaces it).  The `.c` marker line keeps only identity: `// FUNCTION: MODULE 0xVA`.
2. **STATUS display precedence**: metadata `PROVEN`/`SKIP` (and `STUB` over
   the cache's `SIZE_MISMATCH`/`MISSING_SIZE`/`STUB`) > `.rebrew/verify_cache.toml`
   measured result (the cache holds byte verdicts only, never PROVEN)
   > grid/DB snapshot.
3. **Per-function > per-library > project** for toolchain/cflags
   (`resolve_compile_overrides`).
4. **SIZE precedence**: compile contract = annotation/metadata `SIZE`;
   coverage = registry canonical size.
5. **Shared-tree scoping**: one `rebrew-functions.toml` holds every
   target's rows under module-prefixed keys (`SERVER.0x…`, `GOLD.0x…`) —
   one TOML per metadata root, not one per target.  Progress commands
   (`status`, `todo`) count rows whose module matches the active
   target, `LIBRARY` rows whose module is one of that target's
   `external_libs`, and module-less legacy rows.  A `library_*.h`
   marker enters a target's scan only when its module is that target's
   marker or one of its `external_libs`; those rows count as library
   code (`library_identified`), not as matched game code.  Same-VA
   cross-target entries coexist
   as separate rows and never collide.
6. **Library attributions are not progress**: `LIBRARY`-marker rows and
   rows whose module is listed in `targets.<name>.external_libs` tally
   into `library_identified`, outside the EXACT/RELOC progress table and
   its denominators — the table answers "how much of this binary's code
   is reversed".

## Sync stores (external)

- **BinSync state dir** (the field-level sync interchange): `functions/*.toml`, `global_vars.toml`, `structs/*.toml` carry
  BinSync-native fields (name, prototype, size, notes, globals, structs);
  rebrew exports via `rebrew sync --push --state-dir D` (binsync-export) and
  imports via `--pull` (binsync-import).  The BinSync Ghidra plugin relays
  the state to/from Ghidra.  STATUS/CFLAGS are NOT in the state — they stay
  verify-earned in `rebrew-functions.toml` (the old `[rebrew] STATUS=…`
  comment was write-only and removed).
- **Ghidra** (ReVa MCP): only the structural ops the state dir cannot
  express — `rebrew sync --create-functions`, `--bookmarks`, `--pull-data`.
  `src/<target>/function_structure.json` and `ghidra_data_labels.json` are
  Ghidra exports used as **registry inputs** (not sync outputs).
- **rebrew-flirt-sigs checkout** (sibling repo, `REBREW_FLIRT_SIGS_DIR`
  overrides): standard-library `.pat` signature sources, merged with the
  project's own `flirt_sigs/` at load time (project sigs win).  Read-only
  input — like the rebrew-toolchains checkout, it is external, not a
  project store.

## Layout package lifecycle

`rebrew gen-layout` derives `layout/<target>/` (text-only: `rebrew-layout.toml` +
`*.hex` byte files) and the `[link]` config block
from the reference binary.  The package is committed to git; `rebrew
postlink --layout <dir>` consumes it to normalize a built binary onto the
reference **without the original DLL present**.  Regenerate the package
whenever the reference binary changes — the layout files carry
"do not hand-edit" headers.

## Store formats

A store **rebrew owns** is clear-text TOML, one format for all of them:
`rebrew-project.toml`, `rebrew-functions.toml`, `rebrew-data.toml`,
`rebrew-libraries.toml`, `db/coverage-<target>.toml`, `.rebrew/verify_cache.toml`
and `.rebrew/verify_baseline.toml` (the last two replaced JSON files of the same
name, and `rebrew lint` reports a leftover as a stale artifact, W032).  The
verify cache's rows are the report's rows, so `status`, `todo`, `report`,
`build-db` and the dashboards decode one document with `tomllib` and write it
back with `tomlkit`.

The stores that stay in another tool's format are that tool's contract, not
rebrew's to rename:

| File | Owner of the format |
|---|---|
| `compile_commands.json` | clang's compilation database |
| `objdiff.json` | objdiff's project file |
| `sigs/index.json` (FLIRT pack) | the signature pack that ships it |
| `src/<target>/function_structure.json`, `ghidra_data_labels.json`, `ghidra_switchdata.json` | the Ghidra scripts that export and re-import them |
| `.rebrew/ga_runs.jsonl` | rebrew's own append-only GA log: one line per event, so a TOML document would have to be rewritten per event.  It is derived state under the gitignored run directory, not a source of truth |
| declib BinSync state files | declib |

"One source of truth" is about rebrew-owned state: one store per fact, no cache
that can disagree with it.  A format another program reads stays where it is
until that program changes with it.

## Rules for new stores

1. Ask *which tier* the new store is before writing it.  If it derives
   from existing canonical data, it belongs in Derived or Cache — and
   should be buildable from one command, never hand-edited.
2. One parser per file format.  Shared parsers live in
   `catalog/loaders.py` (discovery inventory, rizin `afl`) and
   `rebrew/metadata_doc.py` (`load_metadata_doc`, `parse_metadata_doc`,
   `metadata_write_lock`) — do not hand-roll a third copy.
3. Writes to canonical stores go through the gated APIs:
   `update_source_status` / `update_statuses_batch` (STATUS),
   `update_field` / `remove_field` (function metadata, incl. `rebrew blocker`
   for BLOCKER), `set_data_field` / `set_data_fields_batch` (data metadata;
   keys limited to `DATA_METADATA_FIELDS`, STATUS to the three data
   verdicts, so a function-only field such as BLOCKER raises), `rebrew library set`
   (library overrides).  **Do not hand-edit `rebrew-functions.toml`,
   `rebrew-data.toml`, or `rebrew-libraries.toml`** — every write goes
   through `metadata_write_lock`, and the two function/data stores use
   `atomic_write_locked` on top (see `rebrew/metadata.py`,
   `rebrew/data_metadata.py`, `rebrew/library.py`).
   `rebrew-project.toml` is a store too: every writer (`lint --fix` dropping a
   `cflags_presets` key, a splat import patching `[targets.<name>].arch`, the
   intake arch rewrite, the doctor wibo fixup) takes
   `rebrew.config.project_toml_lock` around the whole read, edit, and write,
   not just the write.  Each edits one key in a document it parsed wholesale,
   so an unlocked writer drops a concurrent writer's key silently.
   No module-less metadata keys: the writers reject an empty module (a bare
   `0xVA` key was once writable but never readable — the guard now raises
   instead).
4. Caches must be invalidation-correct: mtime-keyed or content-keyed, and
   written with the shared `atomic_write_text` / `metadata_write_lock`
   machinery (tool-owned TOML uses `atomic_write_locked` so the file stays
   mode 0444).  The coverage document is derived output but has history to
   carry forward, so `write_coverage_toml` holds `_coverage_write_lock`
   across its read of the previous document and its replace; without it two
   builders for one target each carry their own delta rows and the second
   write drops the first's history.
5. Generated scaffolding that must survive without `original/` (layout
   package, `.def`, `crt_region/`, `link_stubs.c`, toolchain files) is
   **VCS-intended** — derive it once, commit it, rebuild only on binary
   change.  Keep the generator idempotent so re-runs are no-ops when the
   binary is unchanged.
