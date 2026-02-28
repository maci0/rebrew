# Ghidra ↔ Rebrew Integration

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
| Pull struct/type definitions from Ghidra | Ghidra → Local | ✅ Done | `--pull-structs` |
| Pull function prototypes from Ghidra | Ghidra → Local | ✅ Done | `--pull-signatures` |
| Pull comments from Ghidra | Ghidra → Local | ✅ Done | `--pull-comments` (analysis) and `--pull` (pre/post) |
| Batch rename accept from Ghidra | Ghidra → Local | ✅ Done | `--pull --accept-ghidra` |
| Push struct definitions to Ghidra DTM | Local → Ghidra | ✅ Done | `--sync-structs` |
| Push function signatures to Ghidra | Local → Ghidra | ✅ Done | `--sync-signatures` |
| Push function sizes to Ghidra | Local → Ghidra | ✅ Done | `--sync-sizes` |
| Push data segments (.bss, .data) to Ghidra | Local → Ghidra | ✅ Done | `--sync-data` |
| Bidirectional conflict detection | Both | ✅ Done | Warns on conflict, `--accept-ghidra`/`--accept-local` |
| Incremental / dirty-only sync | Both | ❌ Not yet | — |
| Watch mode (live file-change sync) | Local → Ghidra | ❌ Not yet | — |
| XREF context in skeleton generation | Ghidra → Local | ❌ Not yet | — |
| Ghidra decompilation backend for skeleton | Ghidra → Local | ❌ Not yet | — |
| Validate `programPath` against Ghidra project | — | ❌ Not yet | — |
| Deduplication / idempotency tracking | — | ❌ Not yet | — |

For improvement ideas related to Ghidra sync, see [IDEAS.md](IDEAS.md) (#5–#9, #11).

---

## Known Issues

### `sync.py` doesn't validate programPath against actual Ghidra project

The `program_path` is derived from `cfg.target_binary.name` which gives `/server.dll`.
But Ghidra may have imported the binary under a different path (e.g. `/Server/server.dll`
or just `server.dll` without leading slash). There should be a way to:
1. Query ReVa for `get-current-program` to validate the path
2. Or make the program path configurable in `rebrew-project.toml`

### No deduplication check

If you run `--export` + `--apply` twice, all operations are re-applied. ReVa probably
handles this idempotently, but it wastes time. The sync should track what's already been
pushed.
