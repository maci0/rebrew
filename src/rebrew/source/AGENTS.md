# AGENTS.md: source/

C source discovery, selection, layout/preprocessed views, contracts, bindings, address anchors, merging, splitting, rehoming, renaming, and string inlining.

## Modules

| Module | Role |
|--------|------|
| `discovery.py` | `iter_sources`, `iter_library_headers`, `source_glob`, `scan_files` |
| `selection.py` / `paths.py` / `units.py` | Target source selection, path helpers, and native unit inventory |
| `layout.py` / `preprocessed.py` / `contracts.py` / `guard_context.py` | Parser-backed source spans, MSVC `-E` views, and source contract audits |
| `anchors.py` / `binding.py` / `register.py` / `cflags.py` / `consolidate.py` | Source anchor, binding, registration, and consolidation workflows |
| `organization.py` / `organize.py` / `order.py` | Source organization review and native order planning |
| `merge.py` / `merge_sweep.py` / `guarded_merge.py` / `split.py` / `rehome.py` | TU merge, split, and rehome operations |
| `rename.py` / `rename_batch.py` / `rename_ops.py` / `c_rename.py` / `refactor.py` | Coordinated symbol renaming across C sources and metadata |
| `inline_strings.py` | Inline literal globals from reference binaries |

Externals (the only packages this one may import): `binary.analysis`, `binary.gate`, `blocker`, `buildsys.link_order`, `c_syntax.parser`, `c_syntax.type_metadata`, `c_syntax.types`, `catalog`, `catalog.loaders`, `cli`, `compare.coff_reloc`, `compiler.cache`, `compiler.compile`, `compiler.image_headers`, `compiler.overrides`, `compiler.toolchain`, `config`, `cu_map`, `data.layout`, `errors`, `formats.binary_loader`, `formats.binary_model`, `formats.pe_headers`, `function_providers`, `matcher.parsers`, `metadata.anchors`, `metadata.binding_history`, `metadata.bindings`, `metadata.coordinated`, `metadata.data`, `metadata.functions`, `metadata.locking`, `metadata.source_provenance`, `metadata.storage`, `utils`, `workspace`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Source discovery and layout helpers stay library-only; CLI commands do not get imported by library modules.
