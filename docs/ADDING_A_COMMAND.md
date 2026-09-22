# Adding a command

Checklist for adding a `rebrew <name>` command. Every item is enforced
somewhere — the gate is named so a red CI run tells you which step you
skipped.

## 1. Module

Create `src/rebrew/<name>.py` following the CLI tool pattern (AGENTS.md):
module docstring, `console = Console(stderr=True)`, `app = typer.Typer(...)`,
`@app.callback(invoke_without_command=True)` on `main()`, `main_entry()`
(body: `run_standalone(main)` from `rebrew.cli`),
`if __name__ == "__main__"` guard.

Conventions (CLI review will flag drift):

- `TargetOption` + `require_config()` — never build config manually.
- Param order: `--json` before `--target`, both last.
- Exact help strings: `--json` → `"Output results as JSON"`,
  `--dry-run` → `"Preview changes without writing"`.
- `console.print()` for humans; raw `print()` only for piped data.
- `error_exit(msg, json_mode=json_output)` for failures.
- STATUS writes only through `rebrew.metadata` writers — never write
  `STATUS` in `.c` files, never hand-edit TOML.

## 2. Registration

Two places, both required:

- `src/rebrew/builtins.py`: append a `CliComponent` (name, module, help,
  panel, group). The `help` string shows in `--help`; keep it one line.
  Default `needs` are `cli` and `console`; `apply()` mounts only while
  those services are provided. Unmount is a tracked inverse (ADR 014).
- `pyproject.toml` `[project.scripts]`: add
  `rebrew-<name> = "rebrew.<module>:main_entry"` for the standalone script.

Third-party commands skip both: they register through the
`rebrew.commands` entry-point group and are discovered at startup
(`plugin.entry_point_components`). A name colliding with a built-in is
ignored with a warning — built-ins win.

## 3. Docs

- `docs/CLI.md`: one table row + one `### rebrew <name>` detail section
  with the full invocation line and an options table.
- `README.md` tool table: one row if user-facing.
- Agent skill: name the command in the relevant
  `src/rebrew/agent-skills/*/SKILL.md`, or add the carve-out to
  `_SKILL_OUT_OF_SCOPE` in `tests/test_docs_hygiene.py` with a reason.
  Then re-render: `rm -rf .agents/skills && cp -r
  src/rebrew/agent-skills .agents/skills` (+ target substitution per
  `tests/test_skills_sync.py` docstring).
- `CHANGELOG.md` Unreleased: one entry (Added for commands, Fixed
  otherwise).

The `residue` command (v2.5.0) is the cautionary tale: full Typer app,
tests, changelog entry — but never registered, so `rebrew residue --help`
failed until the registration was added after release.

## 4. Tests

- `tests/test_<name>.py`: pure helpers first (no docker, no project
  fixture); one CLI-mount test (`CliRunner().invoke(app, [name, --help])`
  exits 0) so a missing registration fails fast.
- `tests/test_docs_hygiene.py` covers the rest automatically: every
  `BUILTIN_COMPONENTS` entry must have a CLI.md section, a skill mention
  (or carve-out), a valid panel, and a callback-decorated `main`.

## 5. Verify

```bash
uv run python -m rebrew.main <name> --help   # mounts, help renders
uv run pytest tests/test_<name>.py tests/test_docs_hygiene.py -q -p no:cacheprovider
uv run ruff check src/rebrew/<name>.py tests/test_<name>.py
uv run python -m mypy src/rebrew/<name>.py
```
