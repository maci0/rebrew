# AGENTS.md — catalog/

Merges function sources (lists, Ghidra JSON, PE exports) into a unified registry, builds cell-level coverage grids, and exports CATALOG.md / reccmp CSV.

## Module Map

| Module | Role | Key Exports |
|--------|------|-------------|
| `loaders.py` | I/O (Ghidra JSON, function lists, DLL bytes, source + library header scanning) | `load_function_structure()`, `load_ghidra_data_labels()`, `parse_function_list()`, `scan_reversed_dir()` |
| `registry.py` | Merge sources, resolve canonical sizes | `build_function_registry()`, `make_func_entry()` |
| `grid.py` | Coverage grid generation | `generate_data_json()` |
| `export.py` | Output (CATALOG.md, reccmp CSV) | `generate_catalog()`, `generate_reccmp_csv()` |
| `sections.py` | Section parsing, global scanning, x86 utils | `get_globals()`, `get_text_section_size()`, `trim_trailing_padding()`, `has_back_jumps()` |
| `cli.py` | Typer CLI orchestrator | `app`, `main`, `main_entry` |

## Dependency Graph

```
cli.py (orchestrator — calls all others)
├── loaders.py (scan_reversed_dir, parse_function_list)
├── registry.py (build_function_registry)
├── grid.py (generate_data_json)
├── export.py (generate_catalog, generate_reccmp_csv)
├── sections.py (get_text_section_size)
└── annotation.py (external — parse_c_file_multi, update_size_annotation)

loaders.py
├── registry.py (make_func_entry)
├── annotation.py (external — parse_c_file_multi, parse_library_header)
└── cli.py (external — iter_sources, iter_library_headers)

registry.py
├── binary_loader.py (external — load_binary)
└── config.py (external — ProjectConfig)

grid.py
├── loaders.py (load_ghidra_data_labels)
├── registry.py (is_jump_table)
├── sections.py (get_globals)
└── binary_loader.py (external — load_binary)

export.py → config.py (external — ProjectConfig)
sections.py → binary_loader.py, config.py, cli.py (all external)
```

## Data Flow

```
[Inputs]
  ├─ Reversed .c + library_*.h → loaders.scan_reversed_dir() → list[Annotation]
  ├─ functions.txt     → loaders.parse_function_list() → list[dict]
  ├─ ghidra JSON       → loaders.load_function_structure() → list[FunctionEntry]
  └─ PE binary         → binary_loader.load_binary() → BinaryInfo
        │
        ▼
[Registry] registry.build_function_registry()
  ├─ Merge by VA: list + ghidra + exports
  ├─ Canonical size resolution (_resolve_canonical_size)
  │   └─ Classifies extra bytes as: jump table (.text pointers), padding (0x90/0xCC), out-of-line code (jumps back)
  └─ Output: dict[va, {detected_by, size_by_tool, canonical_size}]
        │
        ▼
[Grid] grid.generate_data_json()
  ├─ Extract raw bytes
  ├─ Cell mapping (.text: 64B cells, 64 cols/row; .data: 16B; .bss: 4096B)
  ├─ Gap absorption (jump tables, out-of-line code, tail ≤64B)
  ├─ Ghidra label integration (thunk vs data)
  └─ Stats (EXACT/RELOC/NEAR_MATCHING/STUB counts, coverage %)
        │
        ▼
[Export]
  ├─ export.generate_catalog() → src/<target>/CATALOG.md
  ├─ export.generate_reccmp_csv() → db/{target}_functions.csv (pipe-delimited)
  └─ grid output → db/data_{target}.json (recoverage dashboard)
```

## Key Concepts

### Canonical Size Resolution
When list and Ghidra sizes disagree, `_resolve_canonical_size()` checks if extra bytes are: (1) jump/switch table (.text pointers), (2) padding (NOP 0x90 / INT3 0xCC), or (3) out-of-line code (jumps back into body). Needs binary data — falls back to Ghidra size otherwise.

### Gap Absorption
Loop in `generate_data_json()`: gaps between functions are absorbed into the predecessor if they contain jump tables, out-of-line code, or small tail code (≤64B). Repeats until stable.

### Cell Coverage
Sections split into fixed cells:
- `.text`: 64B, 64 cols/row
- `.data`/`.rdata`: 16B
- `.bss`: 4096B

Each cell tracks function ownership, match status, and gap class.

## Gotchas

- **Lazy binary parsing**: `generate_data_json` parses once (`_bin_info`) and reuses it for registry/grid/sections in that run; other tools call `load_binary()` themselves (no cross-module cache).
- **Multi-function files**: `scan_reversed_dir()` handles multiple `// FUNCTION:` blocks per `.c` file — both listed.
- **Library headers**: `scan_reversed_dir()` also scans `library_*.h` for `// LIBRARY:` markers. Origin from filename stem (e.g. `library_msvc.h` → MSVCRT, `library_zlib.h` → ZLIB). Supports extended format with optional KV fields (STATUS, SIZE, CFLAGS, SOURCE, BLOCKER) after the symbol line — reccmp ignores them, rebrew captures them for library functions compiled from reference source.
- **Ghidra labels**: only `thunk_*` → "thunk"; everything else → "data".
- **No global mutable state**: all modules stateless; data via params. `cli.py` is sole orchestrator.
