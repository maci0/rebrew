# AGENTS.md: app/

The umbrella `rebrew` CLI composition layer (ADR 014, ADR 026): the only code that knows every command.

## Modules

| Module | Role |
|--------|------|
| `main.py` | Console-script target (`[project.scripts] rebrew = "rebrew.app.main:main"`), global options |
| `builtins.py` | `DOMAIN_COMPONENTS` / `BUILTIN_COMPONENTS`: one `CliComponent` row per packaged command, by domain |
| `plugin.py` | `CliComponent`, `Context`, `activate`: the component runtime and the `rebrew.commands` / `rebrew.multicommands` entry-point groups |

Externals (the only packages this one may import): `cli`, `errors`, `registry`. Command modules are named as strings in `builtins.py` and imported when a command runs, so they are not edges here. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- **This package is a sink.** Nothing outside it imports it at module scope (`COMPOSITION_LAYER` in `tools/check_layering.py`); a command attaches itself to the umbrella inside its `register()`.
- **New commands register here, not as console scripts.** Add a `CliComponent` row to `builtins.py`; `[project.scripts]` holds only `rebrew`. The root `AGENTS.md` CLI Conventions section owns the rest of the command rules.
