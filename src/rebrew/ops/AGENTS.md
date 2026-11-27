# AGENTS.md: ops/

Worker dispatch protocol (`rebrew ops call` / `rebrew ops serve`), typed request/reply schemas, retained-source snapshots, and HTTP transport.

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | `Op`/`OPS`/`dispatch`, CLI entry points, and package re-exports |
| `core.py` | Limits, refusal constants/helpers, `OpsError`, cancellation, and `WorkerConfig` |
| `staging.py` | Filestore resolution, pinned URL downloads, workspace confinement, and snapshot staging |
| `handlers_analysis.py` | Disassembly, analysis, reporting, metadata, and child-command ops |
| `handlers_project.py` | Verification, build, candidate, data, and retained-snapshot ops |
| `http.py` | HTTP transport (`OpsServer`, bearer auth, admission caps, metrics, progress streaming) |
| `requests.py` | Frozen wire request dataclasses decoded via `msgspec` |
| `replies.py` | Closed `TypedDict` reply contracts and JSON schema projection |
| `named_snapshot.py` | Retained-source snapshot assembly and verification |
| `snapshot_mutations.py` | Retained-source mutation operations |

Externals (the only packages this one may import): `binary.analysis`, `binary.analyze`, `binary.asm`, `binary.cfg_ged`, `binary.crypto_scan`, `binary.describe`, `binary.discover`, `binary.fingerprints`, `binary.imports`, `binary.pe_info`, `binary.strings`, `binary.xrefs`, `buildsys.splat_config`, `c_syntax.name_decomp`, `c_syntax.parser`, `c_syntax.struct_recover`, `call_progress`, `cli`, `compare.instruction_diff`, `compiler`, `compiler.compile`, `compiler.recompile_client`, `compiler.temp_dirs`, `compiler.toolchain`, `config`, `coverage.input_contract`, `coverage.project`, `coverage.report`, `coverage.toml`, `decompiler`, `errors`, `formats.archives`, `formats.binary_loader`, `formats.binary_model`, `formats.import_table`, `formats.relocations`, `ghidra`, `library.flirt`, `library.gen_flirt_pat`, `library.identify`, `matcher.scoring`, `metadata.anchors`, `metadata.bindings`, `metadata.functions`, `metadata.replication`, `metadata.sqlite`, `metadata.storage`, `metadata_sets`, `metadata_transfer`, `naming`, `project_archive`, `security_scan`, `skeleton`, `source.c_rename`, `source.discovery`, `source.rename_ops`, `telemetry`, `toolchain_detect`, `utils`, `verify.cache`, `verify.test`, `workspace`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Wire request and reply schemas stay aligned with `rebrew.schema.json` and `tools/gen_dispatch_schema.py`.
