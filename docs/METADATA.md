# Metadata & Derived-State Architecture (the "store tiers")

This is the one-page map of **every place rebrew persists or caches data**
and, crucially, which of them is authoritative for which fact.  It exists
so the "why are there so many files?" question has a written answer: most
of the surface is *derived snapshots and caches*, not competing sources of
truth.

## The three tiers

| Tier | Stores | Contract |
|---|---|---|
| **Canonical (user-owned)** | `.c` marker lines, `rebrew-function.toml`, `rebrew-data.toml`, `rebrew-library.toml`, `rebrew-project.toml` | The only stores you hand-edit or that hold non-derivable facts.  Everything below is regenerable from these (plus the binary). |
| **Derived (regenerable)** | `functions.txt` (written by discover/intake), `db/data_<target>.json`, `db/coverage.db`, `db/verify_results.json`, `CATALOG.md`, reccmp CSV | Rebuildable via `rebrew discover` / `rebrew catalog` / `rebrew verify` / `rebrew build-db`.  Treat as build output; never hand-edit. |
| **Cache (delete-safe)** | `.rebrew/verify_cache.json`, `.rebrew/compile_cache/`, `output/ga_runs/*/build_cache*`, in-memory mtime caches | Regenerated on demand.  Deleting costs a recompile/re-verify at most.  The exception: `.rebrew/solutions.json` and `.rebrew/ga_runs.jsonl` are *history*, not caches — they accumulate knowledge re-running GA would not reproduce. |

## Who owns which fact

| Fact | Canonical store | Derived/cached copies |
|---|---|---|
| Function **identity** (which VAs are functions) | merged registry (`catalog/registry.py`: functions.txt + `function_structure.json` + exports, minus IAT slots) | grid JSON, coverage.db `functions` table |
| Function **size** | registry `canonical_size` (`+ size_reason`) — the compile contract is annotation/metadata `SIZE` | grid `size`, DB `functions.size` |
| Function **name** | annotation name (the `// FUNCTION: MODULE 0xVA` line) | grid/DB `name`, plus `list_name`/`ghidra_name` columns preserving the other authorities |
| Match **STATUS** | `rebrew-function.toml` — written **only** via `metadata.update_source_status` / `update_statuses_batch` (promotion gate, PROVEN sticky) | grid/DB snapshots; `.rebrew/verify_cache.json` measured-result overlay at report time |
| **cflags / toolchain** | `rebrew-function.toml` (per-function) → `rebrew-library.toml` (per-library, walk-up) → project defaults, resolved by `resolve_compile_overrides` | grid `cflags`, DB column |
| Data symbols (globals) | `rebrew-data.toml` | grid `globals`, DB `globals` table |
| Coverage presence | grid JSON (`db/data_<target>.json`) | coverage.db (pure function of the JSON) |

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

- **Ghidra** (ReVa MCP): the Ghidra program is the store; sync edits `.c`
  markers + TOML metadata.  Pulls land as renames, `NOTE:`/`GHIDRA:`
  metadata, `// PROTOTYPE:` markers.
- **BinSync**: export writes rebrew-only fields as `[rebrew]` comment
  strings in the state dir; import applies back through `.c` files and
  `rebrew-data.toml` — STATUS via `update_source_status` (never inline).

## Rules for new stores

1. Ask *which tier* the new store is before writing it.  If it derives
   from existing canonical data, it belongs in Derived or Cache — and
   should be buildable from one command, never hand-edited.
2. One parser per file format.  Shared parsers live in
   `catalog/loaders.py` (function lists, rizin `afl`) and
   `rebrew/utils.py` (`load_metadata_doc`, `parse_metadata_doc`,
   `metadata_write_lock`) — do not hand-roll a third copy.
3. Writes to canonical stores go through the gated APIs:
   `update_source_status` (STATUS), `update_field` (function metadata),
   `set_data_field` (data metadata), `rebrew library set` (library
   overrides).  No module-less metadata keys (a bare `0xVA` key can be
   written but never read back).
4. Caches must be invalidation-correct: mtime-keyed or content-keyed, and
   written with the shared `atomic_write_text` / `metadata_write_lock`
   machinery.
