# AGENTS.md: workspace/

`rebrew-project.toml` lookup, `coverage.db` path resolution, and the STATUS / VA vocabulary the coverage consumers share.

## Modules

| Module | Role |
|--------|------|
| `config.py` | `find_root`, `read_config`, `targets_table`, `db_path`, `WorkspaceNotFound` |
| `db.py` | Read-only `coverage.db` access (`open_sqlite_ro`, `coverage_db_lock`, section-cell codec) |
| `status.py` | `KNOWN_STATUSES`, `EARNED_STATUSES`, `MATCHED_STATUSES`, `COVERAGE_DB_STATUSES` |
| `va.py` | `VA_MAX`, `parse_va_candidates` |

Externals (the only packages this one may import): `errors`, `utils`. `errors` is the module-scope import (`WorkspaceNotFound` takes `RebrewError`); `utils` is deferred inside `db.coverage_db_lock` so importing a submodule never pulls tomlkit/rich (`tests/test_workspace_public_api.py::test_submodules_import_without_rebrew_stack`).

## Contracts

- **Every reader opens the DB read-only.** `open_sqlite_ro` uses a `mode=ro` URI plus `PRAGMA query_only=ON`; writes go through the tools that own the schema, not here.
- **One resolution implementation.** `find_root` / `db_path` / `targets_table` are the only place a workspace is located. Other tools import them rather than walking for `rebrew-project.toml` themselves.
- **The codec is shared, not duplicated.** `encode_section_cells` / `decode_section_cells` defer their `zstandard` import to the call, so the dependency appears only for consumers that move cell blobs.
