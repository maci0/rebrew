# AGENTS.md: buildsys/

Build-system integration, CMake toolchain/file generation, linker order/sweep/postlink pipelines, layout manifests, stub generation, and splat imports.

## Modules

| Module | Role |
|--------|------|
| `cmake_tc.py` | `rebrew build cmake-toolchain` generator |
| `cmake_cache.py` / `cmake_flags.py` / `cmake_sources.py` | CMake cache, per-file flag, and source-list sync |
| `check.py` | CMake File API (`codemodel-v2`), `compile_commands.json`, Ninja, and Makefile build check |
| `delphi.py` | 16-bit Delphi build integration |
| `objdiff.py` | `objdiff.json` project generator |
| `link_anchors.py` / `link_order.py` / `link_sweep.py` / `linked_exact.py` | Linker order, option sweep, and linked-exact verification |
| `layout_map.py` / `layout_meta.py` / `gen_layout.py` | PE layout metadata, text maps, and layout generator |
| `gen_stubs.py` / `gen_link_stubs.py` | Extern/link stub generators |
| `postlink.py` | Post-link binary patching and verification |
| `residue.py` | Build residue inspection |
| `splat_config.py` | Splat YAML config import |

Externals (the only packages this one may import): `binary_gate`, `c_parser`, `catalog.loaders`, `catalog.registry`, `cli`, `compiler`, `compiler.cache`, `compiler.compile`, `compiler.delphi16`, `compiler.overrides`, `compiler.temp_dirs`, `compiler.toolchain`, `compiler.unshare`, `config`, `cu_map`, `errors`, `formats.binary_loader`, `formats.binary_model`, `formats.pe_headers`, `formats.pe_image`, `identify_library`, `lint_cflags`, `metadata.anchors`, `metadata.bindings`, `metadata.coordinated`, `metadata.data`, `metadata.functions`, `metadata.locking`, `metadata.storage`, `naming`, `skeleton`, `source.c_rename`, `source.discovery`, `source.selection`, `symbol_addrs`, `toolchain_detect`, `utils`, `verify.cache`, `verify.hash`, `workspace`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Build generators and link-order/postlink helpers stay cycle-free and respect `PACKAGE_EXTERNALS`.
