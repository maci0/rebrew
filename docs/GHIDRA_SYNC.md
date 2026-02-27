# Ghidra ↔ Rebrew Integration: Ideas & Improvements

## Feature Matrix

| Feature | Direction | Status | Command |
|---------|-----------|--------|---------|
| Export labels / comments / bookmarks to JSON | Local → file | ✅ Done | `--export` |
| Apply JSON commands to Ghidra via ReVa MCP | Local → Ghidra | ✅ Done | `--apply` |
| Export + apply in one step | Local → Ghidra | ✅ Done | `--push` |
| Skip generic `func_XXXXXXXX` labels | Local → Ghidra | ✅ Done | `--skip-generic` (default on) |
| Status-based bookmark categories | Local → Ghidra | ✅ Done | automatic (`rebrew/exact`, `/reloc`, etc.) |
| Custom MCP endpoint URL | — | ✅ Done | `--endpoint URL` |
| Summary / dry-run preview | — | ✅ Done | `--summary` |
| Pull function renames from Ghidra | Ghidra → Local | ✅ Done | `--pull` |
| Pull struct/type definitions from Ghidra | Ghidra → Local | ❌ Not yet | — |
| Pull comments from Ghidra | Ghidra → Local | ✅ Done | `--pull` |
| Push struct definitions to Ghidra DTM | Local → Ghidra | ✅ Done | `--sync-structs` |
| Push function signatures to Ghidra | Local → Ghidra | ✅ Done | `--sync-signatures` |
| Push data segments (.bss, .data) to Ghidra | Local → Ghidra | ✅ Done | `--sync-data` |
| Incremental / dirty-only sync | Both | ❌ Not yet | — |
| Bidirectional conflict detection | Both | ❌ Not yet | — |
| Watch mode (live file-change sync) | Local → Ghidra | ❌ Not yet | — |
| XREF context in skeleton generation | Ghidra → Local | ❌ Not yet | — |
| Ghidra decompilation backend for skeleton | Ghidra → Local | ❌ Not yet | — |
| Validate `programPath` against Ghidra project | — | ❌ Not yet | — |
| Deduplication / idempotency tracking | — | ❌ Not yet | — |

---

## Ideas

### 1. `rebrew sync --pull` — Import Ghidra Renames

After manually renaming functions in Ghidra, pull those names back into the local `.c` files:

```bash
rebrew sync --pull
```

This would:
1. Call ReVa's `get-functions` to get the full function list with renamed labels
2. Diff against `ghidra_functions.json` to find changes
3. For functions that Ghidra renamed (from `FUN_XXXXXXXX` → meaningful name):
   - Update the `// SYMBOL:` annotation in the `.c` file
   - Rename the file to match the new name convention
   - Update `extern` declarations in other files that reference this function

---

### 2. Incremental / Dirty-Only Sync

Currently `--export` regenerates all 1464 operations every time. Instead:

- Track a sync state file (e.g. `ghidra_sync_state.json`) with timestamps or hashes
- Only emit operations for files that changed since the last sync
- Add a `--force` flag to override and re-sync everything

This matters because applying 1464 MCP calls takes time — incremental would cut it to just
the changed functions.

---

### 3. Struct Sync via `parse-c-structure`

When a `.c` file defines a struct with offset annotations:

```c
struct ArrayItem {
    int field0;     // 0x00
    int field4;     // 0x04
    void* ptr8;     // 0x08
    int fieldC;     // 0x0C
};
```

`rebrew sync` detects these and generates `parse-c-structure` commands to push them
into Ghidra's Data Type Manager under the `/rebrew` category. This makes Ghidra's decompiler output use our
struct definitions, dramatically improving readability for the *next* function we pull.

**Detection heuristic:** `tree-sitter-c` extracts any `typedef struct`, `struct`, or `enum` definition found anywhere in the `.c` file.

---

### 4. Function Signature Push

When we have a complete, verified function signature:

```c
int __cdecl func_10006c00(void)
```

Push it to Ghidra as a proper function signature override. `rebrew sync --push` uses `tree-sitter-c` to parse the exact function prototype from the local C file and pushes it to Ghidra using the `set-function-prototype` tool via ReVa MCP.

---

### 5. Cross-Reference Context Enrichment

When reversing a function, automatically fetch its cross-references from Ghidra to find
callers and callees. This context is critical for understanding parameter types.

```bash
rebrew skeleton 0x10006c00 --xrefs
```

This would call:
- `find-cross-references` to get all XREFs
- `get-decompilation` on the top 3 callers
- Embed the caller context as comments in the skeleton

---

### 6. Status Color Coding in Bookmarks

Currently all bookmarks use the "Analysis" type. Instead, use bookmark categories that
map to status:

| Status   | Category      | Color in Ghidra |
|----------|--------------|-----------------|
| EXACT    | `rebrew/exact`   | Green        |
| RELOC    | `rebrew/reloc`   | Blue         |
| MATCHING | `rebrew/matching`| Yellow       |
| STUB     | `rebrew/stub`    | Red          |

This would give instant visual feedback in Ghidra's bookmark window about project progress.

---

### 7. Decompilation Caching in Skeleton Generation

`rebrew skeleton --decomp` currently uses radare2 backends. Add a `--decomp-backend ghidra`
option that calls ReVa's `get-decompilation` and caches the result:

```bash
rebrew skeleton 0x10006c00 --decomp --decomp-backend ghidra
```

The cached Ghidra decompilation would be stored alongside the skeleton as a `.ghidra.c`
file for reference, and would be significantly better quality than radare2 output.

---

### 8. Bidirectional Name Conflict Detection

Before pushing labels, check if Ghidra already has a meaningful name at that VA:

```
Local:  func_10006c00  (generic auto-name)
Ghidra: ResetStatCounters  (manually assigned)
→ Skip push, warn user, or prefer Ghidra's name
```

This prevents accidentally overwriting good Ghidra analysis with generic rebrew names.
The `--pull` command could detect these conflicts and offer resolution.

---

### 9. Watch Mode for Live Sync

A `rebrew sync --watch` mode that monitors `.c` file changes and automatically pushes
updates to Ghidra in near-real-time:

```bash
rebrew sync --watch
# Watching src/server.dll/*.c for changes...
# [12:30:01] func_10006c00.c changed → pushed label + comment
# [12:30:45] zlib_adler32.c status MATCHING→RELOC → updated bookmark
```

This would use `watchdog` or `inotify` to detect file saves and push only the changed
annotations.

---

## Bugs & Issues Found

### Bug: `sync.py` doesn't validate programPath against actual Ghidra project

The `program_path` is derived from `cfg.target_binary.name` which gives `/server.dll`.
But Ghidra may have imported the binary under a different path (e.g. `/Server/server.dll`
or just `server.dll` without leading slash). There should be a way to:
1. Query ReVa for `get-current-program` to validate the path
2. Or make the program path configurable in `rebrew.toml`

### Issue: Labels for generic `func_XXXXXXXX` names pollute Ghidra

Pushing `create-label` for `func_10006c00` overwrites whatever Ghidra had (which might be
a better auto-analysis name like `ResetStatCounters`). The sync should skip pushing labels
when the local name is just the default `func_XXXXXXXX` pattern, unless `--force` is set.

### Issue: No deduplication check

If you run `--export` + `--apply` twice, all 1464 operations are re-applied. ReVa probably
handles this idempotently, but it wastes time. The sync should track what's already been
pushed.

---

## Priority Ranking

| # | Idea | Effort | Impact |
|---|------|--------|--------|
| 1 | `--pull` import renames | Medium | High — bidirectional flow |
| 2 | Struct sync | Medium | High — improves decompiler |
| 3 | Incremental sync | Medium | Medium — performance |
| 4 | Function signature push | Medium | Medium — better decompiler |
| 5 | XREF context in skeleton | Low | Medium — better context |
| 6 | Ghidra decompilation backend | Low | Medium — better skeletons |
| 7 | Conflict detection | Medium | Medium — safety |
| 8 | Bookmark color coding | Low | Low — visual progress |
| 9 | Watch mode | High | Low — nice to have |
