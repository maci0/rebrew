# Adding a command

Checklist for adding a `rebrew <name>` command. Every item is enforced
somewhere: the gate is named so a red CI run tells you which step you
skipped.

## 1. Module

Create `src/rebrew/<name>.py` following the CLI tool pattern (AGENTS.md):
module docstring, shared `console` from `rebrew.utils`, `app = typer.Typer(...)`,
`@app.callback(invoke_without_command=True)` on `main()`, `main_entry()`
(body: `run_standalone(main)` from `rebrew.cli`),
`if __name__ == "__main__"` guard.

Conventions (CLI review will flag drift):

- `TargetOption` + `require_config()`: never build config manually.
- Param order: `--json` before `--target`, both last.
- Exact help strings: `--json` → `"Output results as JSON"`,
  `--dry-run` → `"Preview changes without writing"`.
- `console.print()` for humans; raw `print()` only for piped data.
- `error_exit(msg, json_mode=json_output)` for failures.
- A "how many rows" option (`--count`, `--limit`, `--top`) runs through
  `require_non_negative(value, "--count", json_mode=json_output)`: a
  negative bound reaches the slice and returns a tail under exit 0, and 0
  stays legal because several commands spell it "no cap".
- STATUS writes only through `rebrew.metadata` writers: never write
  `STATUS` in `.c` files, never hand-edit TOML.

## 2. Registration

- `src/rebrew/builtins.py`: append a `CliComponent` to the appropriate `DOMAIN_COMPONENTS` family
  for a specialized operation, or `BUILTIN_COMPONENTS` for a root workflow
  (name, module, help,
  panel, is_group). The `help` string shows in `--help`; keep it one line.
  Default `needs` are `cli` and `console`; `apply()` mounts only while
  those services are provided. See the [Cordis CLI recipe](CORDIS.md#add-a-cli-plugin)
  for ownership and the [tutorial](CORDIS_TUTORIAL.md) for a complete lifetime.
  This is what makes `rebrew <name>` exist; no gate adds it for you.
- Leave `pyproject.toml` `[project.scripts]` alone. People use one executable,
  `rebrew`; CMake/objdiff hooks also run as subcommands
  ([ADR 027](adr/027-build-hooks-under-umbrella.md)). `main_entry()` supports
  direct module execution for development, not another installed executable.

Third-party commands skip both: they register through the
`rebrew.commands` entry-point group and are discovered at startup
(`plugin.entry_point_components`). A name colliding with a built-in is
ignored with a warning: built-ins win.

## 3. Docs

- `docs/CLI.md`: one table row + one `### rebrew <name>` detail section
  with the full invocation line and an options table.
- Keep the README quick start short; put the command reference in `docs/CLI.md`.
- Agent skill: name the command in a `SKILL.md` or `references/*.md`
  under `src/rebrew/agent-skills/`, or add the carve-out to
  `_SKILL_OUT_OF_SCOPE` in `tests/test_docs_hygiene.py` with a reason.
  Then re-render with `make gen-skills` (renders `src/rebrew/agent-skills`
  into `.agents/skills` with target substitution via `tools/render_skills.py`;
  tested by `tests/test_render_skills.py` and `tests/test_skills_sync.py`).
- `CHANGELOG.md` Unreleased: one entry (Added for commands, Fixed
  otherwise).

The `residue` command (v2.5.0) is the cautionary tale: full Typer app,
tests, changelog entry, but never registered, so `rebrew build residue --help`
failed until the registration was added after release.

## 4. Tests

- `tests/test_<name>.py`: pure helpers first (no docker, no project
  fixture); one CLI-mount test (`CliRunner().invoke(app, [name, --help])`
  exits 0) so a missing registration fails fast.
- `tests/test_docs_hygiene.py` covers the rest automatically: every
  `BUILTIN_COMPONENTS` entry must have a CLI.md section, a skill mention
  (or carve-out), and a valid panel. Every nested route must appear in the
  reference; composed help and examples are checked by `test_cli_contract.py`.
  Command modules retain their callback-decorated apps for module execution.

## 5. Verify

```bash
uv run --frozen rebrew <name> --help   # mounts, help renders
make test-one T="tests/test_<name>.py tests/test_docs_hygiene.py"
uv run --frozen ruff check src/rebrew/<name>.py tests/test_<name>.py
uv run --frozen mypy src/rebrew/<name>.py
```

Bare `uv run` (no `--frozen`) can rewrite `uv.lock`.  `make test-one` is the
edit-test loop (`NO_COLOR` / the pytest ANSI plugin, one or more node ids).

## Domain membership

Packaged families are declared in `builtins.DOMAIN_COMPONENTS`; each member
uses the existing `CliComponent` activation and scoped registration. Set
`is_group=True` for a Typer group and `attr` for an exported callable or app.
A callable component can supply `epilog` with concrete examples. Module-form
commands inherit their app help and epilog. Do not add a parallel dispatcher
or a compatibility alias. Third-party root entry points keep the existing
public registration interface and warn/skip collision policy.

Nested routes are validated recursively. Update their CLI reference, canonical
skills and rendered copies, generated callers, and migration guidance together.
