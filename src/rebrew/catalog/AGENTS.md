# AGENTS.md: catalog/

Merges function sources (discovery inventory, Ghidra JSON, binary exports) into a unified registry and builds the cell-level coverage grid the `db/coverage-<target>.toml` document is rendered from.

## Modules

| Module | Role |
|--------|------|
| `models.py` | `FunctionEntry`, `GhidraDataLabel` |
| `loaders.py` | Ghidra/discovery I/O, `scan_reversed_dir`, `parse_rizin_afl` |
| `registry.py` | `build_function_registry` + canonical size resolution |
| `grid.py` | `generate_data_json` (coverage grid) |
| `pipeline.py` | `build_catalog_data` (scan/registry/grid dict; no disk writes) |
| `cli.py` | `run_catalog` + Typer entry |

Externals (the only packages this one may import): `annotation`, `cli`, `config`, `data_metadata`, `present`, `sections`, `sources`, `status`, `utils`, `workspace`, `binary_loader` (lazy, inside functions), and `binary_model` (`BinaryInfo`). PE section helpers live in `rebrew.sections`; `preset_module_key` / `atomic_write_text` in `rebrew.utils`.

## Data flow

Reversed `.c` + `library_*.h` → `scan_reversed_dir` → annotations; discovery/Ghidra JSON → `load_function_structure`; binary → `load_binary`. Then `build_function_registry` (merge by VA, canonical size) → `generate_data_json` → the dict `rebrew build-db` renders into `db/coverage-{target}.toml`.

## Invariants

- **Canonical size**: when the discovery list is longer than Ghidra, `_resolve_canonical_size` keeps the list size for padding (`0x90`/`0xCC`), a jump/switch table, out-of-line code (jumps back), or a tail with no `ret` (`0xC3`/`0xC2`). No binary bytes, or extra bytes that match none of those: Ghidra size.
- **Target byte order**: jump-table probes read pointer slots through `config.arch_byte_order(arch, endian)`, where `endian` is `BinaryInfo.endian`. The image header wins over the arch default (a little-endian MIPS build is little-endian); an empty `endian` falls back to `arch_is_big_endian`. Pass the loaded image's `arch`/`endian` down rather than defaulting to `x86_32`, which also picks the wrong pointer width.
- **Gap absorption**: predecessor absorbs gaps that are jump tables, OOL code, or tail ≤64B; repeats until stable.
- **Cell sizes**: `.text` 64B (64 cols/row); `.data`/`.rdata` 16B; `.bss` 4096B.

## Gotchas

- **Lazy binary parse**: `generate_data_json` parses once (`_bin_info`) per run; other tools call `load_binary()` themselves.
- **Multi-function files**: multiple `// FUNCTION:` blocks per `.c` are all listed.
- **Library headers**: `parse_library_header` returns every `// LIBRARY: <module> <VA>` row (module is the marker text, not the filename) — do not add a filter there. `scan_reversed_dir` then keeps a row only when its module is empty or this target's marker (`preset_module_key(module_marker(cfg))`): a shared header has no path affinity, and another target's rows must not enter this registry. Inline KV is a legacy read; do not add volatile metadata to source files.
- **Ghidra labels**: only `thunk_*` → "thunk"; everything else → "data". `GhidraDataLabel.from_dict` coerces a non-string `label`/`state` to its default, since export JSON is untrusted and `_classify_ghidra_label` calls `.lower()` on the label.
- **Inventory cache**: `loaders.py` has a bounded, path-keyed process cache invalidated by stat fingerprint (mtime/size/inode). Preserve its lock around lookup, eviction, and replacement.
