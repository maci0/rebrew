# Metadata & Derived-State Architecture (the "store tiers")

This is the one-page map of **every place rebrew persists or caches data**
and, crucially, which of them is authoritative for which fact.  It exists
so the "why are there so many files?" question has a written answer: most
of the surface is *derived snapshots and caches*, not competing sources of
truth.

## The four tiers

| Tier | Stores | Contract |
|---|---|---|
| **Canonical (user-owned)** | `.c` marker lines, `rebrew-functions.toml`, `rebrew-data.toml`, `rebrew-libraries.toml`, `rebrew-project.toml` | The only stores you hand-edit or that hold non-derivable facts.  Everything below is regenerable from these (plus the binary). |
| **Derived, VCS-intended** | `functions.txt`, `src/<target>/CATALOG.md`, `<target>.def`, `crt_region/*.c`, `src/link_stubs.c`, `src/<target>/bss_padding.c`, `src/<target>/rebrew_globals.h`, `layout/<target>/`, `[targets.<t>.layout]` + `[link]` config blocks, `flirt_sigs/*.pat`, `cmake/toolchain-*.cmake` | Build scaffolding generated from the binary / binary-derived facts (gen-layout, discover, catalog, link-stubs, `rebrew data --fix-bss` / `--gen-header`, flirt).  Committed to git so a rebuild never needs `original/` around; regenerable via the generating command.  Never hand-edit. |
| **Derived, gitignored (build output)** | `db/data_<target>.json`, `db/coverage.db`, `db/verify_results.json`, `db/<target>_functions.csv`, `bin/<target>/*.bin`, `output/report/` | Rebuildable via `rebrew catalog` / `rebrew build-db` / `rebrew verify` / `rebrew extract` / `rebrew report`.  Treat as build output. |
| **Cache (delete-safe)** | `.rebrew/verify_cache.json`, `.rebrew/ghidra_sync_state.json`, `.rebrew/compile_cache/`, `output/ga_runs/*/build_cache*`, `output/ga_runs/*/checkpoints/*.json`, `output/ga_runs/*/best.c`, in-memory mtime caches | Regenerated on demand.  Deleting costs a recompile/re-verify/resync at most.  The exception: `.rebrew/solutions.json` and `.rebrew/ga_runs.jsonl` are *history*, not caches — they accumulate knowledge re-running GA would not reproduce. |

## Who owns which fact

| Fact | Canonical store | Derived/cached copies |
|---|---|---|
| Function **identity** (which VAs are functions) | merged registry (`catalog/registry.py`: functions.txt + `function_structure.json` + exports, minus IAT slots) | grid JSON, coverage.db `functions` table |
| Function **size** | registry `canonical_size` (`+ size_reason`) — the compile contract is annotation/metadata `SIZE` | grid `size`, DB `functions.size` |
| Function **name** | annotation name (the `// FUNCTION: MODULE 0xVA` line) | grid/DB `name`, plus `list_name`/`ghidra_name` columns preserving the other authorities |
| Match **STATUS** | `rebrew-functions.toml` — written **only** via `metadata.update_source_status` / `update_statuses_batch` (promotion gate, PROVEN sticky) — triggered by `rebrew test` / `rebrew verify` / `rebrew prove` | grid/DB snapshots; `.rebrew/verify_cache.json` measured-result overlay at report time |
| **BLOCKER / BLOCKER_DELTA** | `rebrew-functions.toml` — written **only** via `metadata.update_field` / `remove_field` through `rebrew blocker set/clear`, `rebrew diff --fix-blocker`, `rebrew near-diag --fix-blocker`, `rebrew document-unmatched` (never hand-edited) | `rebrew status`/`todo` counts; `lint` W005 when `STUB` lacks one |
| **cflags / toolchain** | `rebrew-functions.toml` (per-function) → `rebrew-libraries.toml` (per-library, walk-up) → project defaults, resolved by `resolve_compile_overrides` | grid `cflags`, DB column |
| **Data symbols (globals)** | `rebrew-data.toml` | grid `globals`, DB `globals` table, `src/<target>/rebrew_globals.h` (`rebrew data --gen-header` — extern declarations for the build) |
| Coverage presence | grid JSON (`db/data_<target>.json`) | coverage.db (pure function of the JSON) |
| **Layout / PE normalization** | `layout/<target>/` package — `layout.txt` (sections, exports, imports, export_stamp, link_options, image_base), `header.hex` (full PE header block: SizeOfImage/CheckSum/TimeDateStamp/section table), `iat.hex`, `data.hex`, `reloc.hex`, `operands.txt`, `calls.txt` | `[targets.<t>.layout]` config copy (editor/UI + bss calibration), `[link]` block (`file_align`, `stack_*`, `tsaware`, `timestamp`) consumed by `round_trip --fix-headers` |
| **Import order / IAT** | original binary (IAT order), captured into `layout/<target>/` | `crt_region/crt_imports.c` (`#pragma comment(linker, "/include:__imp_...")`), `[targets.<t>.layout].imports[]` |
| **`.data` / BSS layout** | `rebrew-data.toml` (symbols) + `layout/<target>/data.hex` (reference bytes) | `src/link_stubs.c` (`g_bss_tail` pad, mutated by `rebrew calibrate-bss`), `src/<target>/bss_padding.c` (`rebrew data --fix-bss` — `_pad_<va>[N]` dummy arrays for detected gaps), `_dpad_<addr>[N]` pads inserted into `.c` files by `rebrew data --fill-data` (byte-exact from the reference in the raw region, zero-init for BSS), `layout.txt` `sections[.data].vs` |
| **Export table** | original binary, captured into `layout/<target>/` (`exports`, `export_stamp`, `exp_rva`) | `<target>.def` (`name @ ordinal` for the linker) |
| **Ghidra provenance** (names/sizes) | `src/<target>/function_structure.json`, `ghidra_data_labels.json` (external exports, provenance-stamped) | registry `list_name`/`ghidra_name`, grid/DB columns; `.rebrew/ghidra_sync_state.json` (pushed-op hashes) |

## Precedence rules (who wins on conflict)

1. **Metadata wins over inline `.c` annotations** for owned fields (STATUS,
   SIZE, CFLAGS, TOOLCHAIN, BLOCKER, NOTE, GHIDRA, …).  Inline forms of
   those keys are deprecated — lint **W019** flags them, `--fix` migrates.
   The `.c` marker line keeps only identity: `// FUNCTION: MODULE 0xVA`.
2. **STATUS display precedence**: metadata STATUS > `.rebrew/verify_cache.json`
   measured result (PROVEN is never baked into the cache, so a later
   demotion isn't masked) > grid/DB snapshot.
3. **Per-function > per-library > project** for toolchain/cflags
   (`resolve_compile_overrides`).
4. **SIZE precedence**: compile contract = annotation/metadata `SIZE`;
   coverage = registry canonical size.

## Sync stores (external)

- **BinSync state dir** (the field-level sync interchange, metadata-review
  R1): `functions/*.toml`, `global_vars.toml`, `structs/*.toml` carry
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

`rebrew gen-layout` derives `layout/<target>/` (text-only: `layout.txt` +
`*.hex` byte files) and the `[targets.<t>.layout]` / `[link]` config blocks
from the reference binary.  The package is committed to git; `rebrew
postlink --layout <dir>` consumes it to normalize a built binary onto the
reference **without the original DLL present**.  Regenerate the package
whenever the reference binary changes — the layout files carry
"do not hand-edit" headers.

## Rules for new stores

1. Ask *which tier* the new store is before writing it.  If it derives
   from existing canonical data, it belongs in Derived or Cache — and
   should be buildable from one command, never hand-edited.
2. One parser per file format.  Shared parsers live in
   `catalog/loaders.py` (function lists, rizin `afl`) and
   `rebrew/utils.py` (`load_metadata_doc`, `parse_metadata_doc`,
   `metadata_write_lock`) — do not hand-roll a third copy.
3. Writes to canonical stores go through the gated APIs:
   `update_source_status` / `update_statuses_batch` (STATUS),
   `update_field` / `remove_field` (function metadata, incl. `rebrew blocker`
   for BLOCKER), `set_data_field` (data metadata), `rebrew library set`
   (library overrides).  **Do not hand-edit `rebrew-functions.toml` or
   `rebrew-data.toml`** — every write goes through `metadata_write_lock` +
   `atomic_write_text` (see `rebrew/metadata.py`, `rebrew/data_metadata.py`).
   No module-less metadata keys: the writers reject an empty module (a bare
   `0xVA` key was once writable but never readable — the guard now raises
   instead).
4. Caches must be invalidation-correct: mtime-keyed or content-keyed, and
   written with the shared `atomic_write_text` / `metadata_write_lock`
   machinery.
5. Generated scaffolding that must survive without `original/` (layout
   package, `.def`, `crt_region/`, `link_stubs.c`, toolchain files) is
   **VCS-intended** — derive it once, commit it, rebuild only on binary
   change.  Keep the generator idempotent so re-runs are no-ops when the
   binary is unchanged.
