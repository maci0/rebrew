# Contributing to Rebrew

Thanks for contributing!  Rebrew is a compiler-in-the-loop decompilation
workbench for binary-matching game reversing (MSVC6 targets under Wine).

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
make setup                    # uv sync --frozen --all-extras + pre-commit install
# or: uv sync --frozen --all-extras
uv run pytest tests/ -q       # full suite (~3000 tests)
uv run ruff check src/ tests/ tools/
uv run mypy src/rebrew/
uv run pre-commit run --all-files
make build                    # reproducible sdist+wheel (SOURCE_DATE_EPOCH, TZ=UTC)
```

## What to work on

- Open issues in the repo, or the prioritized action list: `rebrew todo`.
- `docs/IDEAS.md` and `docs/GAP_ANALYSIS.md` list known gaps and future work.

## Versioning and releases

Rebrew is pre-1.0.  Under SemVer's `0.x` rule any release may break the CLI,
the config schema, or an on-disk format; nothing here is frozen until `1.0.0`.

- **One version, one place.**  `__version__` in `src/rebrew/__init__.py` is the
  source of truth; `pyproject.toml` reads it via `[tool.setuptools.dynamic]`.
  Never add a second literal.
- **Bump the on-disk format version with the format.**  Changing the
  `coverage.db` schema means bumping `_CURRENT_DB_VERSION` in `build_db.py` and
  adding a row to the history table in `docs/DB_FORMAT.md`; changing what a
  compile result depends on means bumping `CACHE_SCHEMA_VERSION` in
  `compile_cache.py`.  Both are how users get a clear error (or a cold cache)
  instead of silently wrong results after an upgrade.
- **Record user-visible change in `CHANGELOG.md`** under `## [Unreleased]`, in
  the `Added` / `Changed` / `Fixed` / `Removed` group that fits.  Anything that
  breaks an existing project (renamed CLI flag, changed default, format bump,
  raised minimum Python) goes under `Changed` prefixed with `**Breaking:**`.

## Before submitting

1. Run the full suite and all lint/type gates (commands above).
2. Keep changes minimal and scoped; match the surrounding style.
3. Add tests for new behavior — the suite sits at ~92% coverage, and new
   pure logic is expected to keep it there.
4. Note: this project tracks a `docs/GOAL_PROGRESS.md` session log; you do
   not need to update it unless asked.
