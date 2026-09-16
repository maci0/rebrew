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

## Quick commands

```bash
make setup                    # uv sync --frozen --all-extras --group similarity + pre-commit install
# or: uv sync --frozen --all-extras --group similarity
uv run pytest tests/ -q       # full suite (~3000 tests)
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
