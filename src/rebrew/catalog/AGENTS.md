# AGENTS.md — catalog/

Merges function sources (discovery inventory, Ghidra JSON, PE exports) into a unified registry, builds cell-level coverage grids, and exports reccmp CSV.

## Modules

| Module | Role |
|--------|------|
| `models.py` | `FunctionEntry`, `GhidraDataLabel` |
| `loaders.py` | Ghidra/discovery I/O, `scan_reversed_dir`, `parse_rizin_afl` |
| `registry.py` | `build_function_registry` + canonical size resolution |
| `grid.py` | `generate_data_json` (coverage grid) |
| `export.py` | `generate_reccmp_csv` |
| `cli.py` | `run_catalog` / `build_catalog_data` + Typer entry |

PE section helpers live in `rebrew.sections` (outside this package). Externals: `binary_loader`, `config`, `sources`, `annotation`.

## Data flow

Reversed `.c` + `library_*.h` → `scan_reversed_dir` → annotations; discovery/Ghidra JSON → `load_function_structure`; PE → `load_binary`. Then `build_function_registry` (merge by VA, canonical size) → `generate_data_json` → `db/data_{target}.json`; `generate_reccmp_csv` → `db/{target}_functions.csv`.

## Invariants

- **Canonical size**: when discovery and Ghidra disagree, `_resolve_canonical_size` classifies extra bytes as jump/switch table (.text pointers), padding (`0x90`/`0xCC`), or out-of-line code (jumps back). Needs binary bytes; else Ghidra size.
- **Gap absorption**: predecessor absorbs gaps that are jump tables, OOL code, or tail ≤64B; repeats until stable.
- **Cell sizes**: `.text` 64B (64 cols/row); `.data`/`.rdata` 16B; `.bss` 4096B.

## Gotchas

- **Lazy binary parse**: `generate_data_json` parses once (`_bin_info`) per run; other tools call `load_binary()` themselves.
- **Multi-function files**: multiple `// FUNCTION:` blocks per `.c` are all listed.
- **Library headers**: `library_*.h` with `// LIBRARY:` — origin from stem (`library_msvc.h` → MSVCRT). Optional KV after symbol line (STATUS, SIZE, CFLAGS, SOURCE, BLOCKER) for rebrew; reccmp ignores them.
- **Ghidra labels**: only `thunk_*` → "thunk"; everything else → "data".
- **Stateless**: `cli.py` is the sole orchestrator; no global mutable state.
