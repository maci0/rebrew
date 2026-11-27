# AGENTS.md: library/

Static library identification, FLIRT signatures/patterns, CRT matching, and vendored inspection.

## Modules

| Module | Role |
|--------|------|
| `cli.py` | library.py — per-library toolchain/flags overrides (rebrew-libraries.toml). |
| `crt_match.py` | CRT source cross-reference matcher. |
| `flirt.py` | Run FLIRT signature matching against functions in the target binary. |
| `gen_flirt_pat.py` | Generate FLIRT .pat files from COFF .lib and ELF .a archives. |
| `identify.py` | identify_library.py — combined library-identification pass. |
| `inspect.py` | lib-inspect: list what each member of a COFF archive defines, references, and allocates. |
| `match.py` | lib_match.py — the ``rebrew library match`` command. |
| `presence.py` | lib-presence — find one COFF object's functions in a reference binary. |
| `vendor.py` | Reproduce vendored source trees from pinned pristine files and ordered patches. |

Externals (the only packages this one may import): `binary.analysis`, `c_syntax.parser`, `catalog`, `catalog.loaders`, `cli`, `compiler.toolchain`, `compiler.toolchain_paths`, `config`, `data.layout`, `errors`, `formats.archives`, `formats.binary_loader`, `formats.coff`, `formats.import_table`, `metadata.binding_history`, `metadata.bindings`, `metadata.functions`, `metadata.storage`, `naming`, `native_review`, `source.binding`, `source.discovery`, `source.rename_ops`, `toolchain_detect`, `utils`, `workspace.config`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Library modules remain free of CLI `app`/`main_entry` imports (`tools/check_layering.py`).
