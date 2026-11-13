# Cross-Tool Name Normalization

Reverse engineering tools each generate their own default names for auto-discovered functions.
Rebrew joins discoveries by **virtual address (VA)** and retains tool-specific names
for cross-referencing. Name conversion depends on the ingestion or source-generation path.

---

## Tool Naming Conventions

| Tool | Auto-name prefix | Hex casing | Separator | Example |
|------|-----------------|------------|-----------|---------|
| Ghidra | `FUN_` | UPPER | `_` | `FUN_10001000` |
| IDA Pro | `sub_` | lower | `_` | `sub_10001000` |
| Binary Ninja | `sub_` | lower | `_` | `sub_10001000` |
| radare2 / rizin | `fcn.` | lower | `.` | `fcn.10001000` |
| r2 symbols | `sym.` | lower | `.` | `sym.imp.CreateFileA` |
| FLIRT (r2) | `flirt.` | lower | `.` | `flirt.memcpy` |

> [!IMPORTANT]
> User-assigned names (e.g. `CreateGameObject`, `_inflate`) are never auto-generated
> prefixes and must be preserved as-is.

---

## Name conversion

`rebrew.naming.sanitize_name()` creates safe C filenames and identifiers. It
rewrites Ghidra's `FUN_` prefix to `func_` and lowercases that suffix. Other
prefixes retain their spelling, with punctuation replaced by underscores:

| Input | `sanitize_name()` result |
|-------|--------------------------|
| `FUN_10001000` | `func_10001000` |
| `FUN_1000AB20` | `func_1000ab20` |
| `sub_10001000` | `sub_10001000` |
| `fcn.10001000` | `fcn_10001000` |

The sanitizer also removes surrounding and repeated underscores, guards leading
digits, and caps the result at 64 characters. It can change user-assigned names
when making a C identifier; it does not rewrite the tool's provenance column.

`rebrew.catalog.loaders.parse_rizin_afl()` handles discovery separately. It
converts `->`, `loc`, and `sub.*` labels to `fcn.<va>` with at least eight
lowercase hex digits. Other names, including existing `fcn.` names, pass through.
Neither path normalizes every tool's auto-name to one shared string.

---

## Cross-Reference Model

Rebrew stores tool-specific names as **parallel metadata columns**, keyed by VA:

```
VA (integer)  ←  canonical join key
  ├── name          "func_10001000"  (display name from the selected source binding)
  ├── ghidra_name   "FUN_10001000"   (Ghidra's name at export time)
  ├── list_name     "fcn.10001000"   (name from function list file)
  └── detected_by   ["ghidra", "list"] (which sources found this function)
```

This design allows:

- **Lookup in any direction**: given `FUN_10001000` from a Ghidra script, find the matching function-list name via the shared VA.
- **Display name**: the coverage grid uses the selected source binding's name. `ghidra_name` and `list_name` remain separate provenance fields.
- **Size arbitration**: `size_by_tool` records each tool's size and `canonical_size` resolves disagreements. Ghidra wins on ties or when larger. A larger function-list size can win for tail padding, jump tables, out-of-line code, or an x86 tail containing neither `0xC3` nor `0xC2` return bytes. These are size heuristics; `size_reason` records the selected rule in `catalog/registry.py`.

### Where This Lives

| Layer | File | Key fields |
|-------|------|------------|
| Coverage document | `coverage-<target>.toml` (portable export, one file per target) → `functions` array | `ghidra_name`, `list_name`, `detected_by`, `size_by_tool` |
| REST API | `GET /api/functions?target=` (`rebrew coverage serve`) | Compact arrays under `cols`: `va`, `name`, `symbol`, `size`, `status`, `module`, `files`. Provenance columns (`ghidra_name`, `list_name`) stay in the document only: the dashboard omits them from the wire (same reason it omits `markerType`). `GET /api/globals` and `GET /api/history` use the same array+`cols` shape (`va`/`name`/`decl`/`size`/`module` and `va`/`name`/`old_status`/`new_status`/`changed_at`, with `name` joined from `functions` and `''` once the VA has no function row). There is no per-VA `/api/targets/<t>/functions/<va>` route on this server; the sibling `recovery` API is separate. |

---

## Detecting Auto-Generated vs User-Assigned Names

A name is **not meaningful** (auto-generated / placeholder) when
`rebrew.workspace.names.is_placeholder_name` accepts it: the one rule behind
`is_meaningful` in `binsync/importer.py` (shared by `binsync/diff.py` and
`binsync/overlay.py`), lint W023, the default-names recommendation and the
dependency graph's focus lookup, and the `placeholder_name` the
`rebrew.vocabulary` op publishes. `PLACEHOLDER_NAME_PATTERN` in that module
lists the accepted forms: the empty name, bare `fcn`/`fn`/`fun`, Ghidra's
`FUN_`, `DAT_`, `thunk_` and `switchdata` labels, `FUN_`/`func_`/`sub_`/`fcn_`
hex labels with their calling-convention decorations, rebrew's `fcn.<hex>`
catalog labels and synthetic `g_<4 to 8 hex>` globals, and the dependency
graph's `fn_0x<hex>` nodes.

Other names are treated as **user-assigned**.

`rebrew.naming.normalize_name()` is separate from both ingestion and C-name
sanitization: it strips import/calling-convention decorations and folds Unicode
case for cross-source symbol matching (see `crt_match.py`).

### Implications

- **`rebrew sync push`**: exports fields to the local BinSync state directory; a decompiler plugin relays them to Ghidra.
- **`rebrew sync pull`**: skips generic names such as `func_XXXXXXXX` when applying incoming name changes.
- **`sanitize_name()`** in `rebrew.naming`: rewrites Ghidra `FUN_<hex>` names to `func_<hex>` for C filenames and identifiers.

---

## Adding a New Tool

To add support for a new RE tool (e.g. IDA, Binary Ninja, angr):

### 1. Ingestion

Add a parser in `catalog/loaders.py` (or a new module) that reads the tool's function list export.
The parser must produce records with at minimum:

```python
{"va": int, "size": int, "<tool>_name": str}
```

### 2. Function Registry

Update `build_function_registry()` in `catalog/registry.py` to merge the new tool's data:

```python
registry[va]["<tool>_name"] = entry["<tool>_name"]
registry[va]["detected_by"].append("<tool>")
registry[va]["size_by_tool"]["<tool>"] = entry["size"]
```

### 3. Name Normalization

Extend `PLACEHOLDER_NAME_PATTERN` in `rebrew/workspace/names.py` for the new
tool's auto-labels, in syntax Python `re` and RE2 read alike, with cases in
`tests/test_workspace_names.py`. Preserve the calling-convention decorations it
already recognizes.
If source generation needs a prefix rewrite, extend `sanitize_name()` in
`rebrew/naming.py` and its tests while retaining the shared C-identifier guards.

### 4. Coverage document

Add a `<tool>_name` field to each row of the `functions` array
(`coverage_toml.py`'s `_FUNCTION_COLUMNS`, fed by the grid builder in
`catalog/grid.py`).

### 5. reccmp CSV

There is no CSV emitter today. If one returns, it must check the new tool's
name field when looking for user-assigned names on unmatched functions, and
follow the [reccmp CSV format](https://github.com/isledecomp/reccmp/blob/master/docs/csv.md):
hex `address`, `symbol`, `type`, decimal `size`, and a `name` that carries a
human-meaningful symbol only, never a `FUN_`/`sub_`/`fcn.` auto-name. reccmp
reads an address as hex even without the `0x` prefix, and resolves a blank
`name` from the PDB or its own analysis.
