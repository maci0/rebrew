# AGENTS.md: verify/

Batch verification (`rebrew verify`), single-function compile-and-compare (`rebrew test`), verification cache and input hashing, export checks, and placement checks.

## Modules

| Module | Role |
|--------|------|
| `cli.py` | `rebrew verify` batch verification engine and CLI |
| `test.py` | `rebrew test` single-function/file verification CLI |
| `cache.py` | Incremental verify cache and `--compare` baseline I/O |
| `hash.py` | Source, compiler-config, and header-closure fingerprinting |
| `exports.py` | Export-table verification |
| `placement.py` | Function placement verification |

Externals (the only packages this one may import): `alignment`, `binary_gate`, `buildsys.check`, `buildsys.linked_exact`, `call_progress`, `catalog`, `catalog.loaders`, `cli`, `coff_reloc`, `compiler.cache`, `compiler.compile`, `compiler.context`, `compiler.overrides`, `compiler.temp_dirs`, `compiler.toolchain`, `compiler.unshare`, `compiler.xtensa`, `config`, `data.layout`, `data.ownership`, `data.placement`, `data.verify`, `errors`, `formats.binary_loader`, `formats.pe_headers`, `function_providers`, `instruction_diff`, `match_semantics`, `matcher`, `matcher.parsers`, `metadata.bindings`, `metadata.data`, `metadata.document`, `metadata.functions`, `metadata.storage`, `naming`, `orphans`, `present`, `source.discovery`, `source.rename_ops`, `status_style`, `text_audit`, `toolchain_detect`, `utils`, `workspace`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Verification cache/hash helpers stay library-only; CLI entry points live in `cli.py` and `test.py`.
