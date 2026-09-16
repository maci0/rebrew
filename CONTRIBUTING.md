# Contributing to Rebrew

Thanks for contributing!  Rebrew is a compiler-in-the-loop decompilation
workbench for binary-matching game reversing (MSVC6 targets compiled in a
pinned docker image).

## Start here

- **`AGENTS.md`** — the authoritative guide to layout, conventions, build &
  test commands, code style, and architectural rules.
- **`docs/DEVELOPMENT.md`** — hard-won practical knowledge: test conventions,
  Typer/CliRunner quirks, metadata/tomlkit gotchas, import patterns, and
  toolchain-dependent test guidance.
- **`docs/ARCHITECTURE.md`** — high-level data flow (diagram) and module map;
  read this first to see how the pieces fit together.
- **`docs/CLI.md`** — the full CLI surface.

## Bootstrap (clean clone)

Needs **uv**, **Python 3.13+** (see `.python-version`), and **nasm** on `PATH`
(CI installs nasm for asm round-trip tests).  `uv sync` also needs the sibling
[`resembl`](https://github.com/maci0/resembl) checkout at `../resembl` — the
path pin in `pyproject.toml` / `uv.lock` (tag `v2.0.0`, same as CI
`RESEMBL_REF`).  Without it, sync fails with a cryptic “Distribution not found”
path error; `make setup` names the clone command instead.

```bash
# from the directory that will hold both checkouts:
git clone https://github.com/maci0/rebrew.git
git clone --depth 1 --branch v2.0.0 https://github.com/maci0/resembl.git
cd rebrew
make setup                    # uv sync --frozen --all-extras --group similarity + pre-commit install
make test-one T=tests/test_annotation.py   # smoke the edit-test loop
```

## Quick commands

```bash
make help                     # list contributor make targets
make setup                    # frozen sync + pre-commit install (checks ../resembl first)
make test-one T=tests/foo.py  # single file / nodeid (fast edit-test loop)
make test                     # full suite (~6700 tests; needs nasm)
make all                      # local mirror of CI lint+test gates (ruff/mypy/audit/pytest/fixtures)
uv run ruff check src/ tests/ tools/
uv run mypy
uv run pre-commit run --all-files
make build                    # reproducible sdist+wheel (SOURCE_DATE_EPOCH, TZ=UTC)
```

## What to work on

- Open issues in the repo, or the prioritized action list: `rebrew todo`.
- `docs/IDEAS.md` and `docs/GAP_ANALYSIS.md` list known gaps and future work.

## Versioning and releases

Rebrew is 2.x.  From `1.0.0` the CLI command names and the config schema are
frozen: removing or renaming a command/flag, or changing a config key's
meaning, takes a major version bump and a `**Breaking:**` changelog entry.
On-disk format bumps (`coverage.db` `db_version`, compile-cache schema) and a
raised minimum Python are also `**Breaking:**` — they may ship in a minor when
the migration is a documented `--force` rebuild or a cold cache (as with
schema `"7"` in 2.4.0 and the Python 3.13 floor in 2.3.0).

- **One version, one place.**  `__version__` in `src/rebrew/__init__.py` is the
  source of truth; `pyproject.toml` reads it via `[tool.setuptools.dynamic]`.
  Never add a second literal.  Between releases `__version__` stays equal to
  the last tag; stage notes under `## [Unreleased]` until the bump.
- **Bump the on-disk format version with the format.**  Changing the
  `coverage.db` schema means bumping `_CURRENT_DB_VERSION` in `build_db.py` and
  adding a row to the history table in `docs/DB_FORMAT.md`; changing what a
  compile result depends on means bumping `CACHE_SCHEMA_VERSION` in
  `compile_cache.py`.  Both are how users get a clear error (or a cold cache)
  instead of silently wrong results after an upgrade.
- **Record user-visible change in `CHANGELOG.md`** under `## [Unreleased]`, in
  the `Added` / `Changed` / `Fixed` / `Removed` group that fits.  Anything that
  breaks an existing project (renamed CLI flag, changed default, format bump,
  raised minimum Python, removed install extra) goes under `Changed` prefixed
  with `**Breaking:**`.
- **Preflight before tagging with `make release-check`**: verifies
  `__version__` is bumped past the last tag, the tree is clean, and the
  changelog has a dated `[<version>]` section — no release can be tagged out
  of sync with the version or the notes.

## Before submitting

1. Run the full suite and all lint/type gates (commands above).
2. Keep changes minimal and scoped; match the surrounding style.
3. Add tests for new behavior — the suite sits at ~92% coverage, and new
   pure logic is expected to keep it there.
4. Note: this project tracks a `docs/GOAL_PROGRESS.md` session log; you do
   not need to update it unless asked.
