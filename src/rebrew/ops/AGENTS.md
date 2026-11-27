# AGENTS.md: ops/

Worker dispatch protocol (`rebrew ops call` / `rebrew ops serve`), typed request/reply schemas, retained-source snapshots, and HTTP transport.

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | Worker config, op handlers, `dispatch`, HTTP transport, and CLI |
| `requests.py` | Frozen wire request dataclasses decoded via `msgspec` |
| `replies.py` | Closed `TypedDict` reply contracts and JSON schema projection |
| `named_snapshot.py` | Retained-source snapshot assembly and verification |
| `snapshot_mutations.py` | Retained-source mutation operations |

Externals (the only packages this one may import): `analysis`, `analyze`, `asm`, `buildsys.splat_config`, `c_parser`, `call_progress`, `cfg_ged`, `cli`, `compiler`, `compiler.compile`, `compiler.recompile_client`, `compiler.temp_dirs`, `compiler.toolchain`, `config`, `coverage.input_contract`, `coverage.project`, `coverage.report`, `coverage.toml`, `crypto_scan`, `decompiler`, `describe`, `discover`, `errors`, `fingerprints`, `flirt`, `formats.archives`, `formats.binary_loader`, `formats.binary_model`, `formats.import_table`, `formats.relocations`, `gen_flirt_pat`, `ghidra`, `identify_library`, `imports`, `instruction_diff`, `matcher.scoring`, `metadata.anchors`, `metadata.bindings`, `metadata.functions`, `metadata.replication`, `metadata.sqlite`, `metadata.storage`, `metadata_sets`, `metadata_transfer`, `name_decomp`, `naming`, `pe_info`, `project_archive`, `security_scan`, `skeleton`, `source.c_rename`, `source.discovery`, `source.rename_ops`, `strings`, `struct_recover`, `telemetry`, `toolchain_detect`, `utils`, `verify.cache`, `verify.test`, `workspace`, `xrefs`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Wire request and reply schemas stay aligned with `rebrew.schema.json` and `tools/gen_dispatch_schema.py`.
