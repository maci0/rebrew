# AGENTS.md: coverage/

Live project coverage views, portable `coverage-*.toml` documents, HTML coverage reports, and the read-only coverage dashboard server.

## Modules

| Module | Role |
|--------|------|
| `project.py` | Live `load_project_coverage` view with stat-identity invalidation |
| `toml.py` | Portable `coverage-*.toml` reader/writer and singleflight cache |
| `db.py` | Coverage snapshot normalizers and `write_coverage` |
| `build_db.py` | `rebrew coverage export` CLI command |
| `history.py` | Portable status-history import/export helpers |
| `input_contract.py` | Verified coverage-input contract for remote/retained reports |
| `report.py` | Static HTML report generator backed by Jinja2 templates in `templates/report/` |
| `dashboard.py` | Read-only local HTTP dashboard UI (part of `COMPOSITION_LAYER` in `tools/check_layering.py`) |

Externals (the only packages this one may import): `binary.analysis`, `binary.sections`, `catalog.loaders`, `catalog.pipeline`, `cli`, `compression`, `config`, `data.ownership`, `data.scan`, `depgraph`, `errors`, `formats.binary_loader`, `formats.import_table`, `formats.ne_loader`, `metadata.bindings`, `metadata.data`, `metadata.functions`, `metadata.storage`, `source.discovery`, `source.rename_ops`, `status`, `status_style`, `telemetry`, `theme`, `utils`, `verify.cache`, `verify.hash`, `workspace`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- `dashboard.py` is in `COMPOSITION_LAYER`: no module outside the composition layer may import it at module scope.
- `toml.py`, `db.py`, `project.py`, `history.py`, and `input_contract.py` are library modules and must not import CLI commands.
