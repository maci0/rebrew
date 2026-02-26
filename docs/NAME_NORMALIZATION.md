# Cross-Tool Name Normalization

Reverse engineering tools each generate their own default names for auto-discovered functions.
Rebrew normalizes these into a single canonical form so that the **virtual address (VA)** remains the
true join key while every tool-specific name is preserved as metadata for cross-referencing.

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

## Canonical Form

All auto-generated tool names normalize to:

```
func_<hex_address_lowercase>
```

For example, all of these resolve to the same canonical name:

| Tool output | Canonical |
|-------------|-----------|
| `FUN_10001000` | `func_10001000` |
| `sub_10001000` | `func_10001000` |
| `fcn.10001000` | `func_10001000` |
| `FUN_1000AB20` | `func_1000ab20` |

The normalization rules are:

1. Strip the tool-specific prefix (`FUN_`, `sub_`, `fcn.`)
2. Lowercase the hex digits
3. Prepend `func_`

User-assigned names pass through unchanged.

---

## Cross-Reference Model

Rebrew stores tool-specific names as **parallel metadata columns**, keyed by VA:

```
VA (integer)  ←  canonical join key
  ├── name          "func_10001000"  (canonical display name)
  ├── ghidra_name   "FUN_10001000"   (Ghidra's name at export time)
  ├── r2_name       "fcn.10001000"   (radare2's name at export time)
  ├── ida_name      "sub_10001000"   (IDA's name — future)
  ├── binja_name    "sub_10001000"   (Binary Ninja's name — future)
  └── detected_by   ["ghidra", "r2"] (which tools found this function)
```

This design allows:

- **Lookup in any direction**: given `FUN_10001000` from a Ghidra script, find the matching r2 or IDA name instantly via the shared VA.
- **Name precedence**: user-assigned names from *any* tool override auto-generated names. The first non-generic name wins.
- **Size arbitration**: when tools disagree on function size, `size_by_tool` records each tool's opinion and `canonical_size` picks the best (currently: Ghidra > r2, but configurable).

### Where This Lives

| Layer | File | Key fields |
|-------|------|------------|
| Intermediate JSON | `db/data_<target>.json` | `ghidra_name`, `r2_name`, `detected_by`, `size_by_tool` |
| SQLite DB | `db/coverage.db` → `functions` table | Same columns, queryable via SQL |
| REST API | `GET /api/targets/<t>/functions/<va>` | Returns all tool names in response JSON |
| reccmp CSV | `db/<target>_functions.csv` | Only emits user-assigned names; auto-names are left blank |

---

## Detecting Auto-Generated vs User-Assigned Names

A name is considered **auto-generated** (generic) if it matches:

```regex
^(FUN_|func_|sub_|fcn\.|sym\.)[0-9a-fA-F]+$
```

Everything else is treated as a **user-assigned** name and is always preserved.

### Implications

- **`rebrew-sync`**: only pushes labels to Ghidra for user-assigned names (skips generic `func_XXXXXXXX`).
- **`rebrew-catalog --csv`**: emits user-assigned names in the reccmp `name` column; leaves it blank for auto-names per the reccmp spec.
- **`sanitize_name()`** in `skeleton.py`: normalizes any tool prefix to `func_<hex>` for C filenames and identifiers.

---

## Adding a New Tool

To add support for a new RE tool (e.g. IDA, Binary Ninja, angr):

### 1. Ingestion

Add a parser in `catalog.py` (or a new module) that reads the tool's function list export.
The parser must produce records with at minimum:

```python
{"va": int, "size": int, "<tool>_name": str}
```

### 2. Function Registry

Update `build_function_registry()` in `catalog.py` to merge the new tool's data:

```python
registry[va]["<tool>_name"] = entry["<tool>_name"]
registry[va]["detected_by"].append("<tool>")
registry[va]["size_by_tool"]["<tool>"] = entry["size"]
```

### 3. Name Normalization

Add the tool's auto-name prefix to the generic-name regex:

```diff
- _GENERIC_NAME_RE = re.compile(r"^(func_|FUN_)[0-9a-fA-F]+$")
+ _GENERIC_NAME_RE = re.compile(r"^(func_|FUN_|sub_|fcn\.)[0-9a-fA-F]+$")
```

And to `sanitize_name()`:

```diff
  if name.startswith("FUN_"):
      return "func_" + name[4:].lower()
+ if name.startswith("sub_"):
+     return "func_" + name[4:].lower()
+ if name.startswith("fcn."):
+     return "func_" + name[4:].lower()
```

### 4. DB Schema

Add a `<tool>_name TEXT` column to the `functions` table in `build_db.py`.

### 5. reccmp CSV

Update `generate_reccmp_csv()` to check the new tool's name column when looking for user-assigned names on unmatched functions.

---

## reccmp Compatibility

The [reccmp CSV format](https://github.com/isledecomp/reccmp/blob/master/docs/csv.md) expects:

| Column | Expected value |
|--------|---------------|
| `address` | Hex VA (required) |
| `name` | Human-meaningful name only — **not** `FUN_`/`sub_`/`fcn.` auto-names |
| `symbol` | Decorated linker symbol (e.g. `_CreateWindowExA@48`) |
| `type` | One of: `function`, `template`, `synthetic`, `library`, `stub`, `global`, `string`, `widechar`, `float`, `vtable` |
| `size` | Decimal byte count |

> [!NOTE]
> reccmp treats addresses as hex even without the `0x` prefix.
> Auto-generated names should be omitted (left blank) — reccmp will use the PDB or its own analysis to resolve them.

Rebrew's `generate_reccmp_csv()` already follows this convention: it skips `FUN_` and `fcn.` prefixes and only emits user-assigned names.
