# AGENTS.md: formats/

Executable, object and archive file parsers: the layer every analysis, compile and coverage tool reads a binary through. No commands live here; `rebrew binary pe` and `rebrew binary unpack-lzexe` stay at the package root (`pe_info.py`, `lzexe_cli.py`) and import these modules.

## Modules

| Module | Role |
|--------|------|
| `binary_loader.py` | `load_binary` and the `rebrew.binary_loaders` plugin group; PE/ELF/Mach-O through LIEF |
| `binary_model.py` | `BinaryInfo`, `SectionInfo`: the format-agnostic model the loaders fill |
| `dfm.py` | Bounded Delphi 1 form codec with lossless property order/wire types |
| `ne_analysis.py` | Validated physical segments/fixups and content-window inventories |
| `ne_loader.py` | 16-bit NE images (LIEF cannot parse NE) |
| `pe_headers.py` / `pe_image.py` | Read and patch PE header fields in place; the image walk for MSVC link options |
| `pe_symbols.py` | PE data directories as symbol records |
| `import_table.py` | Import tables and import-stub detection |
| `relocations.py` | Typed relocation spans |
| `omf16.py` | 16-bit OMF objects (MSVC 1.52 dialect LIEF cannot parse) |
| `lzexe.py` | LZEXE 0.90/0.91 unpacker |
| `archives.py` | Static archive members and stock-library cache paths |

Externals (the only packages this one may import): `errors`, `registry`, `utils`. `registry` is the entry-point lookup behind `rebrew.binary_loaders`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- **LIEF first.** The root `AGENTS.md` Code Style section owns which formats LIEF parses and why `pe_headers`, `pe_image`, `ne_loader` and `omf16` exist.
- **Parsers do not reach upward.** Nothing here imports a command, the compile path, or the metadata stores; a helper that needs them belongs to its caller.
