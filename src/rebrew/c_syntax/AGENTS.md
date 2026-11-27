# AGENTS.md: c_syntax/

C AST parsing, conditionals, cast rewriting, struct recovery, and type metadata.

## Modules

| Module | Role |
|--------|------|
| `cast_rewrite.py` | cast_rewrite.py - Rewrite raw ``(T *) 0xVA`` casts and declare the globals that replace them. |
| `conditionals.py` | Same-coordinate structural views for conditional C brace fragments. |
| `fixup.py` | fixup.py — compilability fixup for raw decompiler output (DecBench-style). |
| `float_const.py` | float_const.py — find floating-point constants referenced from code. |
| `name_decomp.py` | name_decomp.py — apply known struct names to decompiler output. |
| `parser.py` | c_parser.py – Shared tree-sitter C parsing utilities for rebrew. |
| `pseudo_c.py` | Rewrite decompiler pseudo-C into tokens a C89 compiler accepts. |
| `signature_parser.py` | signature_parser.py – Extract function signatures from C source via tree-sitter. |
| `struct_parser.py` | struct_parser.py – Extract struct/typedef definitions from C source via tree-sitter. |
| `struct_recover.py` | struct_recover.py — recover struct definitions from decompiler output. |
| `symbolize.py` | symbolize.py - Rewrite raw data addresses in a C source to the globals the reference relocates. |
| `type_metadata.py` | Stable type identities with target-specific compiler and native layout evidence. |
| `types.py` | types.py - Shared parsed C type model (structs, sizes, alignment). |
| `types_cli.py` | Manage type identities, check struct layouts and apply types to signatures. |
| `vtordisp.py` | vtordisp.py — find multiple-inheritance thunk (vtordisp) functions. |

Externals (the only packages this one may import): `binary.analysis`, `cli`, `compiler.compile`, `compiler.overrides`, `compiler.temp_dirs`, `config`, `data.ownership`, `decompiler`, `errors`, `formats.binary_loader`, `formats.relocations`, `metadata.bindings`, `metadata.coordinated`, `metadata.data`, `metadata.functions`, `metadata.storage`, `source.contracts`, `source.discovery`, `source.rename_ops`, `utils`, `verify.hash`, `workspace.config`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Library modules remain free of CLI `app`/`main_entry` imports (`tools/check_layering.py`).
