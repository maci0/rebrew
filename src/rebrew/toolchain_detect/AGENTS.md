# AGENTS.md: toolchain_detect/

Heuristic compiler-family, era, CRT-linkage, and codegen-signal detection for target binaries.

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | `detect_toolchain`, `profile_matches_detection`, `suggest_profile`, lazy `lief` loader, and compatibility aliases |
| `tables.py` | Compiler version/compatibility tables, `ToolchainInfo`, `CodegenSignals`, `DetectionTables`, and plugin registry refresh |
| `diec.py` | Detect It Easy (`diec`) discovery, execution, and version-hint backend |
| `codegen.py` | Byte/string/MZ/PDB/PE-metadata scanning and codegen fingerprint helpers |

Externals (the only packages this one may import): `compiler.toolchain`, `formats.binary_loader`, `formats.import_table`, `formats.lzexe`, `formats.ne_loader`, `formats.pdb`, `registry`, `utils`.

## Contracts

- **Hints, not verdicts.** Detection signals are heuristic evidence; keep `detect_toolchain` non-raising on unreadable or unrecognized inputs.
- **Snapshot coherence.** Readers consume `detection_tables()` as a single generation; writers republish through `refresh_detection_tables()` under its lock.
- **No CLI surface here.** Commands stay in `toolchain_cli/` and `doctor.py`.
