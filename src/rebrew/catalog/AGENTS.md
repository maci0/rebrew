# AGENTS.md: catalog/

Merges function sources (discovery inventory, Ghidra JSON, binary exports) into a unified registry and builds the cell-level view shared by live dashboards and explicit portable exports.

## Modules

| Module | Role |
|--------|------|
| `models.py` | `FunctionEntry`, `GhidraDataLabel` |
| `loaders.py` | Ghidra/discovery I/O, `scan_reversed_dir`, `parse_rizin_afl` |
| `registry.py` | `build_function_registry` + canonical size resolution |
| `grid.py` | `build_coverage_data` (coverage grid) |
| `pipeline.py` | `build_catalog_data` (scan/registry/grid dict; no disk writes) |
| `cli.py` | `run_catalog` + Typer entry |

Externals (the only packages this one may import): `cli`, `config`, `function_providers`, `metadata.bindings`, `metadata.document`, `metadata.data`, `metadata.functions`, `present`, `sections`, `sources`, `status`, `utils`, `workspace`, `formats.binary_loader` (lazy, inside functions), and `formats.binary_model` (`BinaryInfo`). PE section helpers live in `rebrew.sections`; `preset_module_key` / `atomic_write_text` in `rebrew.utils`.

## Data flow

Reversed `.c` + `library_*.h` → `scan_reversed_dir` → annotations; discovery/Ghidra JSON → `load_function_structure`; binary → `load_binary`. Then `build_function_registry` (merge by VA, canonical size) → `build_coverage_data` → the dict shared by live project views and `rebrew coverage export --output <directory>`.

## Invariants

- **Canonical size**: when the discovery list is longer than Ghidra, `_resolve_canonical_size` keeps the list size for padding (`0x90`/`0xCC`), a jump/switch table, out-of-line code (jumps back), or a tail with no `ret` (`0xC3`/`0xC2`, probed on x86 targets only, since those are the x86 `ret` encodings). No binary bytes, extra bytes on a non-x86 target, or extra bytes that match none of those: Ghidra size.
- **Target byte order**: jump-table probes read pointer slots through `config.arch_byte_order(arch, endian)`, where `endian` is `BinaryInfo.endian`. The image header wins over the arch default (a little-endian MIPS build is little-endian); an empty `endian` falls back to `arch_is_big_endian`. Pass the loaded image's `arch`/`endian` down rather than defaulting to `x86_32`, which also picks the wrong pointer width.
- **Gap absorption**: predecessor absorbs gaps that are jump tables, OOL code, or tail ≤64B; repeats until stable.
- **Cell sizes**: `.text` 64B (64 cols/row); `.data`/`.rdata` 16B; `.bss` 4096B.

## Gotchas

- **Lazy binary parse**: `build_coverage_data` parses once (`_bin_info`) per run; other tools call `load_binary()` themselves.
- **Multi-function files**: read every function row whose dedicated metadata `file` names the `.c` file. Optional `ADDRESS: MODULE 0xVA` comments bind the next declaration through the AST; classification and state remain in format-2 metadata. There is no legacy block reader.
- **Library headers**: `library_bindings_for_file` reads LIBRARY identities from `rebrew-functions.toml`; headers carry no inventory state. The module is the row's module, not the filename. Do not add a filter there. `scan_reversed_dir` then keeps a row only when its module is empty or this target's module (`preset_module_key(target_module(cfg))`): a shared header has no path affinity, and another target's rows must not enter this registry. Compiled library providers use their managed source-file and symbol identities.
- **Ghidra labels**: only `thunk_*` → "thunk"; everything else → "data". `GhidraDataLabel.from_dict` coerces a non-string `label`/`state` to its default, since export JSON is untrusted and `_classify_ghidra_label` calls `.lower()` on the label.
- **Inventory cache**: `loaders.py` has a bounded, path-keyed process cache invalidated by stat fingerprint (mtime/size/inode). The decoded-JSON cache is bounded by retained characters, not entry count (one inventory is multi-MB); the entry caches keep an entry cap. Preserve its lock around lookup, eviction, and replacement.

- **Coverage views have their own scope.** Grid cells and coverage documents are
  derived presentation data. Do not substitute cell/symbol counts for the byte
  buckets in `status`; use the shared accounting frame for status/todo. Nested
  origins and verification tables remain canonical metadata, not coverage rows.
