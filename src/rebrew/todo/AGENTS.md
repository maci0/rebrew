# AGENTS.md: todo/

Prioritized action dashboard (`rebrew todo`): synthesizes verify cache verdicts, coverage status, and function/data metadata into an impact-ranked work queue.

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | `rebrew todo` Typer CLI entry point, public re-exports, and `collect_all`, which injects the command-module callables (`status`, `matching.prove`, `library.*`) the library collectors may not import |
| `models.py` | Category constants (`CAT_*`), `TodoItem`, ROI scoring, impact ranking, extern-names cache, and verify-cache loader |
| `collectors.py` | Per-lane action collectors (`collect_setup_steps`, `collect_active_functions`, `collect_new_functions`, data/prover/postlink/binding collectors) and `collect_all` |
| `render.py` | Terminal rendering helpers (`CATEGORY_COLORS`, `render_matched_headline`, `render_stats_header`, `render_todo_panel`) |

Externals (the only packages this one may import): `c_syntax.parser`, `catalog`, `cli`, `compiler.compile`, `config`, `data.layout`, `formats.binary_loader`, `library.identify`, `library.match`, `matching.prove`, `metadata.bindings`, `metadata.data`, `metadata.document`, `metadata.functions`, `naming`, `present`, `source.discovery`, `status`, `status_style`, `utils`, `verify.cache`, `workspace.status`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Library submodules (`models.py`, `collectors.py`, `render.py`) remain free of CLI `app`/`main_entry` definitions and never import `__init__.py` or CLI command modules.
