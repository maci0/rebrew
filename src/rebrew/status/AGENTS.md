# AGENTS.md: status/

Aggregates reversing progress across annotations, function structure, data metadata, built images, and the verify cache (`rebrew status`), and renders the terminal dashboard.

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | `app`, `main`, `main_entry`, public re-exports, and local `_`-aliases |
| `collect.py` | `VerifyInfo`, `StatusReport`, `collect_status`, text/data accounting, verify-cache readers, and file-similarity helpers |
| `render.py` | `render_terminal` and Rich terminal dashboard formatting helpers |

Externals (the only packages this one may import): `binary.sections`, `catalog.loaders`, `cli`, `compiler.cache`, `config`, `data.layout`, `formats.binary_loader`, `formats.binary_model`, `metadata.data`, `metadata.document`, `metadata.functions`, `naming`, `present`, `source.discovery`, `status_style`, `utils`, `verify.cache`, `workspace.status`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Invariants

- **Library/command separation**: `collect.py` and `render.py` stay non-CLI (no `typer.Typer`, no `main_entry`) and never import `rebrew.status.__init__`.
- **Monkeypatch compatibility**: Helpers in `collect.py` and `render.py` resolve patchable bindings (`console`, `iter_sources`, `postlink_copied_ranges`, `initialized_data_ranges`, `load_verify_info`, `attach_file_similarity`, `target_binary`, `load_cache_raw`, `load_verify_details`, `compute_text_size`) through `sys.modules.get("rebrew.status")` so patches on `rebrew.status` take effect without introducing an import edge back to `__init__.py`.
