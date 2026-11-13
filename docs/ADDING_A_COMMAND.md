# Adding a command

Checklist for adding a `rebrew <name>` command or a domain operation such as
`rebrew build <name>`. Each step names the gate that enforces it, so a red CI
run tells you which step you skipped.

## 1. Module

Create `src/rebrew/<name>.py` following the CLI conventions in
[AGENTS.md](../AGENTS.md#cli-conventions): a module docstring, the shared
`console` from `rebrew.utils`, `app = typer.Typer(..., epilog=...)` with an
`Examples:` section in the epilog, and `main_entry()` with the docstring
`"""Run the Typer CLI application."""` under an `if __name__ == "__main__"`
guard.

- A single command decorates `main()` with
  `@app.callback(invoke_without_command=True)`; `main_entry()` calls
  `run_standalone(main)` from `rebrew.cli`.
- A group (`is_group=True`) calls `run_cli(app)` from `main_entry()`. Its epilog
  is the landing page, so it lists the common invocations.

Conventions (`tests/test_cli_contract.py` and CLI review flag drift):

- `TargetOption` + `require_config()`: never build config manually.
- Param order, selection-flag helpers, exact help strings, help panels, output
  and `error_exit`: [CLI conventions](../AGENTS.md#cli-conventions).
- Group landing pages stay concise: a clear purpose, copyable examples, and
  accurate preview/write behavior. Do not advertise parent flags removed when
  an operation became a subcommand.
- A "how many rows" option (`--count`, `--limit`, `--top`) runs through
  `require_non_negative(value, "--count", json_mode=json_output)`. Without it
  a negative bound reaches the slice and returns a tail under exit 0; 0 stays
  legal because several commands spell it "no cap".
- STATUS writes only through `rebrew.metadata.functions` writers: never write
  `STATUS` in `.c` files, never hand-edit TOML.

## 2. Registration

Append a `CliComponent` (name, module, help, panel, `is_group`, optional
`attr`) in `src/rebrew/app/builtins.py`:

- a specialized operation goes in its family in `DOMAIN_COMPONENTS` (panel
  `""`), mounted as `rebrew <domain> <name>`;
- a root workflow goes in `BUILTIN_COMPONENTS` with a panel from `Panel.ALL`.

This entry is what makes the command exist; no gate adds it for you, and a
built module that is never registered fails `rebrew <name> --help`. Set
`is_group=True` for a Typer group and `attr` for an exported callable or app
other than the module's `main`/`app`. Mounted module help supplies both the
parent listing and the command page, so keep its first sentence concise;
`CliComponent.help` is the fallback when the module has no app help, and a
callable component can supply `epilog`. Default `needs` are `cli` and
`console`; `apply()` mounts only while those services are provided. See the
[Cordis CLI recipe](CORDIS.md#add-a-cli-plugin) for ownership and the
[tutorial](CORDIS_TUTORIAL.md) for a complete lifetime. Do not add a parallel
dispatcher or a compatibility alias.

Leave `pyproject.toml` `[project.scripts]` alone ([CLI conventions](../AGENTS.md#cli-conventions)). `main_entry()` supports
direct module execution for development, not another installed executable.

Third-party commands skip this step: they register through the
`rebrew.commands` (callables) or `rebrew.multicommands` (Typer groups)
entry-point group and are discovered at startup
(`plugin.entry_point_components`). A name colliding with a built-in is
ignored with a warning: built-ins win.

## 3. Docs

- `docs/CLI.md`: a root command gets one table row and one `### rebrew <name>`
  detail section with the full invocation line and an options table. Every
  nested route (`rebrew <domain> <name>`) must appear in the reference.
- Keep the README quick start short; put the command reference in `docs/CLI.md`.
- Agent skill: name the command in a `SKILL.md` or `references/*.md`
  under `src/rebrew/agent-skills/`, or add the carve-out to
  `_SKILL_OUT_OF_SCOPE` in `tests/test_docs_hygiene.py` with a reason.
  Then regenerate the rendered copies
  ([generated surfaces](STYLE.md#maintain-the-generated-surfaces)).
- Moving an existing route: update its CLI reference, canonical skills and
  rendered copies, generated callers, and [migration guidance](CLI_MIGRATION.md)
  together.
- `CHANGELOG.md` Unreleased: one entry (Added for commands, Fixed
  otherwise).

## 4. Tests

- `tests/test_<name>.py`: pure helpers first (no docker, no project
  fixture); one CLI-mount test (`CliRunner().invoke(app, [name, --help])`
  exits 0) so a missing registration fails fast.
- `tests/test_docs_hygiene.py` checks the rest: every `BUILTIN_COMPONENTS`
  entry has a CLI.md section, a skill mention (or carve-out) and a valid
  panel, and every nested route, walked recursively, appears in the
  reference. `tests/test_cli_contract.py` checks composed help, the
  `Examples:` epilogs and the `main_entry` docstring.

## 5. Verify

```bash
uv run --frozen rebrew <name> --help   # mounts, help renders
make test-one T="tests/test_<name>.py tests/test_docs_hygiene.py"
uv run --frozen ruff check src/rebrew/<name>.py tests/test_<name>.py
uv run --frozen mypy src/rebrew/<name>.py
```

Bare `uv run` (no `--frozen`) can rewrite `uv.lock`. `make test-one` is the
edit-test loop (`NO_COLOR` / the pytest ANSI plugin, one or more node ids).
