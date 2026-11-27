# AGENTS.md: lint/

Source binding, metadata store, data extent, provenance, type, scaffold, and C convention validation (`rebrew lint`).

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | `rebrew lint` Typer CLI (`app`, `main`, `main_entry()`), `--fix`, and compatibility aliases |
| `metadata_rules.py` | `LintResult`, `MissingSection`, per-binding metadata rules, and batch W031–W038 store/data/provenance/type/scaffold checks |
| `source_rules.py` | Comment/string stripping, function index, assembly/naked/global/style rules, and `lint_file` core logic |

Externals (the only packages this one may import): `c_syntax.parser`, `c_syntax.type_metadata`, `catalog`, `cli`, `config`, `data.layout`, `formats.binary_loader`, `init`, `lint_cflags`, `metadata.anchors`, `metadata.binding_history`, `metadata.bindings`, `metadata.data`, `metadata.document`, `metadata.functions`, `metadata.source_provenance`, `metadata.source_schema`, `metadata.storage`, `source.discovery`, `source.rename_ops`, `utils`, `workspace.config`, `workspace.names`, `workspace.status`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Helper submodules (`metadata_rules.py`, `source_rules.py`) stay library-only: no `app = typer.Typer`, no `main_entry()`, and never import `__init__.py`.
- Cross-module imports never target `_`-prefixed names; `__init__.py` binds local `_`-aliases to public submodule symbols for test compatibility.
