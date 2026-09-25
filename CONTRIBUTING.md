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

Needs **uv** (CI pins `uv-version` in `.github/actions/uv-env/action.yml`,
currently `0.12.14`), **Python 3.13+** (see `.python-version`), and **nasm** on `PATH`
(CI installs nasm for asm round-trip tests).  `uv sync` also needs the sibling
[`resembl`](https://github.com/maci0/resembl) checkout at `../resembl` — the
path pin in `pyproject.toml` / `uv.lock` (tag `v2.0.0`, same as CI's
`resembl-ref`).  Without it, sync fails with a cryptic “Distribution not found”
path error; `make setup` fails closed if `uv` is missing, if `../resembl`'s
`version` does not match `RESEMBL_REF`, or if that checkout's `HEAD` is not
`RESEMBL_SHA` (the commit CI's `resembl-sha` pin requires — a moved tag keeps
the version string and still fails here).  It warns (still continues) when `uv`
is older than `UV_VERSION`, and when `../resembl` is not a git checkout so the
commit cannot be checked.

```bash
# from the directory that will hold both checkouts:
git clone https://github.com/maci0/rebrew.git
git clone --depth 1 --branch v2.0.0 https://github.com/maci0/resembl.git
cd rebrew
make setup                    # uv sync --frozen --all-extras --group similarity + pre-commit/pre-push hooks
make test-one T=tests/test_annotation.py   # smoke the edit-test loop
```

`make setup` installs the `prove` extra and the `similarity` group. Those
pull the copyleft components named in [`NOTICE`](NOTICE) (`pyvex`/LibVEX and
GPLv3 `resembl`). Rebrew's own source stays under [`LICENSE`](LICENSE).

## Quick commands

```bash
make help                     # list contributor make targets
make setup                    # frozen sync + pre-commit install (checks uv + ../resembl first)
make clean                    # remove build/dist artifacts and caches
make test-one T=tests/test_annotation.py  # single file / nodeid (fast edit-test loop; defaults to test_annotation.py)
make test                     # full suite (a few minutes; needs nasm)
make coverage                 # full suite under slipcover; fails below COV_FLOOR (CI test job, 3.13)
make lint                     # ruff check src/ tests/ tools/
make format                   # ruff format (writes)
make format-check             # ruff format --check
make mypy                     # mypy type check (matches CI lint job)
make audit                    # uv audit --locked (matches CI lint job)
make check                    # pre-commit hook parity (CI pre-commit job)
make build                    # reproducible sdist+wheel + dist/rebrew.buildinfo (CI package job)
make sbom                     # CycloneDX 1.5 JSON from uv.lock (offline)
make cli-contract             # high-value --help greps (CI cli-contract job)
make all                      # local mirror of CI lint+test+cli-contract gates
make pr-check                 # full local CI verification (all + check + build + sbom)
make gen-fixtures             # regenerate tests/fixtures/ after editing tools/gen_fixtures.py
make gen-skills               # regenerate .agents/skills/ after editing src/rebrew/agent-skills/
```

## What to work on

- Open issues in the repo, or the prioritized action list: `rebrew todo`
  (inside a project workspace with `rebrew-project.toml`).
- Longer-horizon backlog: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Versioning and releases

Rebrew is 2.x.  From `1.0.0` the CLI command names and the config schema are
frozen: removing or renaming a command/flag, or changing a config key's
meaning, takes a major version bump and a `**Breaking:**` changelog entry.
On-disk format bumps (`coverage.db` `db_version`, compile-cache schema) and a
raised minimum Python are also `**Breaking:**` — they may ship in a minor when
the migration is a documented `--force` rebuild or a cold cache (as with
schema `"7"` in 2.4.0 and the Python 3.13 floor in 2.3.0).
The Python import surface (module paths, functions, classes, `__all__`) and
the `rebrew dashboard` `/api/*` JSON are not frozen: a removal, move, or
signature change there ships in a minor with a `**Breaking:**` entry naming
the old and new import path or shape (as with the helper removals in 2.1.0
and 2.2.0).  There is no deprecation window; pin the minor version if you
import rebrew as a library.

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

1. `make pr-check` (or `make all && make check && make build`) — mirrors CI
   lint+test+cli-contract gates, the pre-commit job, and the package job's
   `make build` (sdist/wheel + `dist/rebrew.buildinfo`).
2. Keep changes minimal and scoped; match the surrounding style.
3. Add tests for new behavior — the suite sits at ~86% line coverage
   (`make coverage`), and new pure logic is expected to keep it there.
4. Record user-visible change under `## [Unreleased]` in `CHANGELOG.md` when
   the change affects installs, CLI, config, or on-disk formats (see Versioning
   above).  If you edit `tools/gen_fixtures.py`, run `make gen-fixtures` and
   commit the refreshed `tests/fixtures/` bytes; if you edit `src/rebrew/agent-skills/`,
   run `make gen-skills` and commit the refreshed `.agents/skills/` files.
