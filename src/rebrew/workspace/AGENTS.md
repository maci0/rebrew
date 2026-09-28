# AGENTS.md: workspace/

`rebrew-project.toml` lookup, coverage-directory resolution, and the STATUS / VA vocabulary the coverage consumers share.

## Modules

| Module | Role |
|--------|------|
| `config.py` | `find_root`, `read_config`, `targets_table`, `db_dir`, `WorkspaceNotFound`, `WorkspaceConfigError` |
| `status.py` | `KNOWN_STATUSES`, `EARNED_STATUSES`, `MATCHED_STATUSES`, `NEAR_MATCH_CANDIDATE_STATUSES`, `FUZZY_STATUSES`, `COVERAGE_DB_STATUSES` |
| `va.py` | `VA_MAX`, `parse_va_candidates` |

Externals (the only package this one may import): `errors`, the leaf module that gives `WorkspaceNotFound` its `RebrewError` base. `utils` used to be reached through the deleted `db.coverage_db_lock`; nothing here imports it now, which is what keeps importing a submodule free of tomlkit and rich (`tests/test_workspace_public_api.py::test_submodules_import_without_rebrew_stack`).

## Contracts

- **This package resolves, it does not store.** It answers where a project is and where its coverage documents live (`db_dir`); reading and writing them is `rebrew.coverage_toml`'s job. The SQLite helpers this package used to export (`open_sqlite_ro`, `coverage_db_lock`, `SQLITE_TIMEOUT_SECONDS`, the section-cell codec) are gone, so no module in rebrew can open a database.
- **One resolution implementation.** `find_root` / `db_dir` / `targets_table` are the only place a workspace is located. Other tools import them rather than walking for `rebrew-project.toml` themselves.
- **An absent config is a default; a broken one is an error.** `read_config` returns `{}` when there is no `rebrew-project.toml` and raises `WorkspaceConfigError` when the file is present but is not readable UTF-8 TOML. The defaults it would otherwise fall back to (`db/`, the first target, `src/<name>`) name a different workspace, so a parse failure has to stop the command rather than read as an empty one.
