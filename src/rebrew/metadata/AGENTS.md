# AGENTS.md: metadata/

Source annotations and the locked metadata stores: every read and write of `rebrew-functions.toml` and `rebrew-data.toml` goes through this package. The field ownership contract lives in [METADATA.md](../../../docs/METADATA.md); the root `AGENTS.md` "Never" section and the volatile-metadata and STATUS rules apply here unchanged.

## Modules

| Module | Role |
|--------|------|
| `functions.py` | `rebrew-functions.toml` store: `METADATA_FIELDS`, `update_field`, `update_source_status`, `update_statuses_batch`, library presets |
| `data.py` | `rebrew-data.toml` store for DATA/GLOBAL rows |
| `storage.py` | `MetadataStore` protocol, backend selection, discovery and review-input API |
| `files.py` | Default TOML backend, `.d/*.toml` discovery and ownership-preserving writes |
| `sqlite.py` | Experimental project-wide SQLite backend and cross-store transactions |
| `locking.py` | Reentrant project and physical-storage locks |
| `document.py` | Qualified-key algebra and backend-neutral document cache |
| `model.py` | `MetadataEntry`: typed view and validation of a function entry |
| `anchors.py` | Optional ADDRESS comments bound to the next C declaration through the AST |
| `bindings.py` | `SourceBinding`, joining current addresses with canonical metadata |
| `source_provenance.py` | Original-assembly evidence and target-scoped support file purposes |

Externals (the only packages this one may import): `c_parser`, `compiler.toolchain`, `config`, `errors`, `registry`, `utils`, `workspace`. `compiler.toolchain` is a lazy read of the toolchain table for `TOOLCHAIN` validation. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- **Name the distinct concepts.** Config `module` selects the target namespace;
  metadata `kind` classifies a row; optional `ADDRESS` comments are source anchors.
  Resolved consumers use `rebrew.config.target_module(cfg)`.

- **Drop-ins partition records.** Each main TOML also reads direct TOMLs in its sibling `.d` directory. Reject duplicates, update existing records in their owning file, and put new records in the main TOML. The main filename owns the collection lock.
- **Persist through storage.** All four managed stores use `storage.metadata_store`; keep validation and provenance in the domain owners. Project configuration remains TOML. No consumer reads inactive backend files as a fallback.
- **Writers lock and write 0444.** Domain edits use `storage.metadata_write_lock` around the complete read/modify/write. Acquire the project-config lock before storage locks so migration cannot race a writer. Backends own atomic writes and mode 0444 at rest; SQLite transactions span its logical documents.
- **Identity can share a STATUS write.** `update_statuses_batch` accepts `identity` (the same keys and empty-value rules as `record_function_rows`) in that locked edit. `overwrite_name` defaults off, so a verdict does not replace a stored name unless the caller asks.
- **Commands live outside.** `rebrew source register` (`source_register.py`), `rebrew blocker` and the other commands that edit metadata stay at the package root.
- **`type_metadata.py` stays outside.** The type store compiles probes and hashes headers, so it imports the compile path this package must not.

- **Current format only.** Functions require format 3; data requires format 2. No inline metadata block parser or ordinary legacy reader; `source consolidate` explicitly migrates reviewed format-2 functions/source stores. All state, including reconstruction source, STRUCT/CALLERS and support purposes, belongs in the stores.

- **History is comparison evidence.** Accepted STATUS transitions append
  `status_history` in the same locked write. Generic field setters cannot forge
  history. `import_status_history` imports reviewed portable history without
  changing current verdicts, identities, edit stamps or verification; dry runs
  read through the strict metadata loader and create no files.

- **Reviewed identity is separate from provider attribution.** `native_identity`
  is written only by `record_native_identity` after a strict complete code,
  operand and compiler-literal proof. Generic field writers cannot forge it;
  stale binary/claim/extent/dependency receipts contribute no trusted name.
