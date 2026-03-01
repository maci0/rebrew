# AGENTS.md — catalog/

Function catalog and coverage analysis pipeline. Merges multiple function
sources (function lists, Ghidra JSON, PE exports) into a unified registry,
generates cell-level coverage grids, and exports CATALOG.md / reccmp CSV.

## Module Map

| Module | Role | Key Exports |
|--------|------|-------------|
| `loaders.py` | File I/O (Ghidra JSON, function lists, DLL bytes, source scanning) | `load_ghidra_functions()`, `load_ghidra_data_labels()`, `parse_function_list()`, `scan_reversed_dir()`, `extract_dll_bytes()` |
| `registry.py` | Merges function sources, resolves canonical sizes | `build_function_registry()`, `make_func_entry()`, `make_ghidra_func()` |
| `grid.py` | Cell-level coverage grid generation | `generate_data_json()` |
| `export.py` | Output generation (CATALOG.md, reccmp CSV) | `generate_catalog()`, `generate_reccmp_csv()` |
| `sections.py` | Binary section parsing, global variable scanning | `get_sections()`, `get_globals()`, `get_text_section_size()` |
| `cli.py` | Typer CLI orchestrator | `app`, `main`, `main_entry` |

## Dependency Graph

```
cli.py (orchestrator — calls all other modules)
├── loaders.py (scan_reversed_dir, parse_function_list)
├── registry.py (build_function_registry)
├── grid.py (generate_data_json)
├── export.py (generate_catalog, generate_reccmp_csv)
├── sections.py (get_text_section_size)
└── annotation.py (external — parse_c_file_multi, update_size_annotation)

loaders.py
├── registry.py (make_func_entry)
├── annotation.py (external — parse_c_file_multi)
└── cli.py (external — iter_sources)

registry.py
├── binary_loader.py (external — load_binary)
└── config.py (external — ProjectConfig)

grid.py
├── loaders.py (extract_dll_bytes, load_ghidra_data_labels)
├── registry.py (_is_jump_table)
├── sections.py (get_globals, get_sections)
└── binary_loader.py (external — load_binary)

export.py → config.py (external — ProjectConfig)
sections.py → binary_loader.py, config.py, cli.py (all external)
```

## Data Flow

```
[Input Sources]
  ├─ Reversed .c files → loaders.scan_reversed_dir() → list[Annotation]
  ├─ functions.txt     → loaders.parse_function_list() → list[dict]
  ├─ ghidra JSON       → loaders.load_ghidra_functions() → list[dict]
  └─ PE binary         → binary_loader.load_binary() → BinaryInfo
        │
        ▼
[Registry] registry.build_function_registry()
  ├─ Merge by VA: list + ghidra + exports
  ├─ Smart size resolution (_resolve_canonical_size)
  │   └─ Detects jump tables, padding (0x90/0xCC), out-of-line code
  └─ Output: dict[va, {detected_by, size_by_tool, canonical_size}]
        │
        ▼
[Grid] grid.generate_data_json()
  ├─ Extract raw bytes from binary
  ├─ Cell-level mapping (.text: 64B cells, .data: 16B, .bss: 4096B)
  ├─ Gap absorption (jump tables, out-of-line code, tail code ≤64B)
  ├─ Ghidra data label integration (thunk vs data classification)
  └─ Summary statistics (EXACT/RELOC/MATCHING/STUB counts, coverage %)
        │
        ▼
[Export]
  ├─ export.generate_catalog() → db/CATALOG.md
  ├─ export.generate_reccmp_csv() → db/{target}_functions.csv (pipe-delimited)
  └─ grid output → db/data_{target}.json (consumed by recoverage dashboard)
```

## Key Concepts

### Smart Size Resolution
When function list and Ghidra disagree on size, `_resolve_canonical_size()` checks
if the extra bytes are: (1) a jump/switch table (array of .text pointers),
(2) padding (NOP 0x90 / INT3 0xCC), or (3) out-of-line code (jumps back into
function body). Requires binary data — falls back to Ghidra size if unavailable.

### Gap Absorption
Iterative loop in `generate_data_json()`: gaps between functions are absorbed into
the preceding function if they contain jump tables, out-of-line code, or small
tail code (≤64B). Loops until no more changes.

### Cell-Based Coverage
Binary sections are divided into fixed-size cells for visualization:
- `.text`: 64-byte cells, 64 columns per row
- `.data`/`.rdata`: 16-byte cells
- `.bss`: 4096-byte cells

Each cell tracks: function ownership, match status, gap classification.

## Gotchas

- **Multiple `load_binary()` calls**: registry, grid, and sections each re-read
  the binary file independently. No cross-module caching.
- **Multi-function files**: `scan_reversed_dir()` supports multiple `// FUNCTION:`
  blocks per `.c` file. Both appear in the entries list.
- **Ghidra label classification**: Only `thunk_*` prefix → "thunk"; everything
  else → "data". No other classification logic.
- **No global mutable state**: All modules are stateless; data flows through
  function parameters. `cli.py` is the sole orchestrator.
