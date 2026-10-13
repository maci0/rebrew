# AGENTS.md: metadata/

Source annotations and the locked metadata stores: every read and write of `rebrew-functions.toml` and `rebrew-data.toml` goes through this package. The field ownership contract lives in [METADATA.md](../../../docs/METADATA.md); the root `AGENTS.md` "Never" section and the volatile-metadata and STATUS rules apply here unchanged.

## Modules

| Module | Role |
|--------|------|
| `functions.py` | `rebrew-functions.toml` store: `METADATA_FIELDS`, `update_field`, `update_source_status`, `update_statuses_batch`, library presets |
| `data.py` | `rebrew-data.toml` store for DATA/GLOBAL rows |
| `document.py` | Qualified-key algebra, document cache and write lock shared by both stores |
| `model.py` | `MetadataEntry`: typed view and validation of a function entry |
| `annotation.py` | `Annotation` and the parser that merges source markers with stored fields |
| `marker_migration.py` | Move inline markers into the stores (`rebrew source migrate-markers`) |
| `source_provenance.py` | Target-scoped original-assembly evidence for definitions without a VA |

Externals (the only packages this one may import): `c_parser`, `compiler.toolchain`, `config`, `errors`, `registry`, `utils`, `workspace`. `compiler.toolchain` is a lazy read of the toolchain table for `TOOLCHAIN` validation. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- **Writers lock and write 0444.** Store writes go through `utils.atomic_write_locked` under `document.metadata_write_lock`; a new writer reuses them instead of opening the TOML itself.
- **Commands live outside.** `rebrew source migrate-markers` (`migrate_markers.py`), `rebrew blocker` and the other commands that edit metadata stay at the package root.
- **`type_metadata.py` stays outside.** The type store compiles probes and hashes headers, so it imports the compile path this package must not.
