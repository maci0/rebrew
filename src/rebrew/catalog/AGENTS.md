# AGENTS.md: catalog/

Merges function sources (discovery inventory, Ghidra JSON, binary exports) into a unified registry, builds cell-level coverage grids, and exports reccmp CSV.

## Modules

| Module | Role |
|--------|------|
| `models.py` | `FunctionEntry`, `GhidraDataLabel` |
| `loaders.py` | Ghidra/discovery I/O, `scan_reversed_dir`, `parse_rizin_afl` |
| `registry.py` | `build_function_registry` + canonical size resolution |
| `grid.py` | `generate_data_json` (coverage grid) |
| `export.py` | `generate_reccmp_csv` |
| `pipeline.py` | `build_catalog_data` (scan/registry/grid dict; no disk writes) |
| `cli.py` | `run_catalog` + Typer entry |

PE section helpers live in `rebrew.sections` (outside this package). Externals: `binary_loader`, `config`, `sources`, `annotation`.

## Data flow

Reversed `.c` + `library_*.h` → `scan_reversed_dir` → annotations; discovery/Ghidra JSON → `load_function_structure`; binary → `load_binary`. Then `build_function_registry` (merge by VA, canonical size) → `generate_data_json` → `db/data_{target}.json`; `generate_reccmp_csv` → `db/{target}_functions.csv`.

## Invariants

- **Canonical size**: when the discovery list is longer than Ghidra, `_resolve_canonical_size` keeps the list size for padding (`0x90`/`0xCC`), a jump/switch table, out-of-line code (jumps back), or a tail with no `ret` (`0xC3`/`0xC2`). No binary bytes, or extra bytes that match none of those: Ghidra size.
- **Gap absorption**: predecessor absorbs gaps that are jump tables, OOL code, or tail ≤64B; repeats until stable.
- **Cell sizes**: `.text` 64B (64 cols/row); `.data`/`.rdata` 16B; `.bss` 4096B.

## Gotchas

- **Lazy binary parse**: `generate_data_json` parses once (`_bin_info`) per run; other tools call `load_binary()` themselves.
- **Multi-function files**: multiple `// FUNCTION:` blocks per `.c` are all listed.
- **Library headers**: `parse_library_header` returns every `// LIBRARY: <module> <VA>` row (module is the marker text, not the filename) — do not add a filter there. `scan_reversed_dir` then keeps a row only when its module is empty or this target's marker (`preset_module_key(module_marker(cfg))`): a shared header has no path affinity, and another target's rows must not enter this registry. Inline KV is a legacy read; do not add volatile metadata to source files.
- **Ghidra labels**: only `thunk_*` → "thunk"; everything else → "data".
- **Inventory cache**: `loaders.py` has a bounded, path-keyed process cache invalidated by stat fingerprint (mtime/size/inode). Preserve its lock around lookup, eviction, and replacement.
