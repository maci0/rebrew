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
(CI installs nasm for asm round-trip tests).  `make clone-resembl` also needs
**bash**: it runs `tools/ci_clone_resembl.sh`, and the target says so instead of
printing `bash: not found`.  **shellcheck** is optional locally
but not in CI: the pre-commit shell hook exits 0 without the binary, so
`make check` on a host without it can pass where CI's pre-commit job (which
installs shellcheck) fails; `make check` warns when it is missing.  `uv sync` also
needs the sibling
[`resembl`](https://github.com/maci0/resembl) checkout at `../resembl` — the
path pin in `pyproject.toml` / `uv.lock` (tag `v3.0.0`, same as CI's
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
cd rebrew
make clone-resembl            # clones sibling resembl pin (tag v3.0.0) into ../resembl
make setup                    # uv sync --locked --all-extras --group similarity + pre-commit/pre-push hooks
make test-one T=tests/test_annotation.py   # smoke the edit-test loop
```

`make setup` installs the `prove` extra and the `similarity` group. Those
pull the copyleft components named in [`NOTICE`](NOTICE) (`pyvex`/LibVEX and
GPLv3 `resembl`). Rebrew's own source stays under [`LICENSE`](LICENSE).

`make setup` is what puts the `prove` extra in `.venv`, and that is what
`make mypy` type-checks against: a bare `uv sync` never installs optional
extras, and without angr every `angr`/`claripy` reference collapses to `Any`
(unknown `SimProcedure` base, `import-not-found`, unused `type: ignore`).
The `similarity` group (`rapidfuzz`, `resembl`) is the same class of gap:
`matcher/scoring.py` imports both, and both ship type information, so without
them mypy reports `import-not-found` there. `make mypy` checks for both
before running and names the fix instead of printing the cascade; the same
check runs in the pre-commit `mypy` hook. Every target that
shells out to `uv run` likewise fails with `ERROR: uv not on PATH` rather than
a bare `uv: not found`.

## Quick commands

```bash
make help                     # list contributor make targets
make clone-resembl            # clone sibling resembl pin into ../resembl (required for uv sync)
make setup                    # locked sync (extras + similarity) + pre-commit install (checks uv + ../resembl first)
make clean                    # remove build/dist artifacts and caches
make test-one T=tests/test_annotation.py  # single file / nodeid (fast edit-test loop; defaults to test_annotation.py)
make test                     # full suite (a few minutes; needs nasm)
make coverage                 # full suite under slipcover; fails below COV_FLOOR (CI test job, 3.13)
make lint                     # ruff check .
make format                   # ruff format (writes)
make format-check             # ruff format --check
make mypy                     # mypy type check (matches CI lint job)
make audit                    # uv audit --locked (matches CI lint job)
make check                    # pre-commit hook parity (CI pre-commit job)
make build                    # reproducible sdist+wheel + dist/rebrew.buildinfo (CI package job)
make sbom                     # CycloneDX 1.5 JSON from uv.lock (offline)
make cli-contract             # high-value --help greps (CI cli-contract job)
make all                      # local mirror of CI lint+test+cli-contract gates
make pr-check                 # full local CI verification (all + check + build + sdist-check + smoke-wheel + sbom)
make sdist-check              # build a wheel from the sdist, diff it against dist/*.whl
make smoke-wheel              # install dist/*.whl into .venv-pkg and smoke-import it
make gen-fixtures             # regenerate tests/fixtures/ after editing tools/gen_fixtures.py
make gen-fixtures-check       # fixtures still match the generator
make gen-skills               # regenerate .agents/skills/ after editing src/rebrew/agent-skills/
make gen-skills-check         # rendered .agents/skills/ match the packaged source
make cycles-check             # module-level import cycles (also runs in make check)
make idempotency-check        # every --json command run twice (CI test job)
make release-check            # version/changelog/tag preflight before tagging
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
import rebrew as a library.  `tools/public_surface.py` reads that surface out
of the AST (`--diff <tag>` prints the delta) and
`tests/test_public_surface.py::TestSurfaceGate` fails the build when the delta
against the last tag removes or reshapes a public name and `[Unreleased]` has
no `**Breaking:**` entry naming it.

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
- **A dated section is frozen.**  Release notes move from `[Unreleased]`
  into `[<version>]` once, at the release commit; after that the published
  section never gains a line, because a reader of that tag's notes would be
  describing code it does not contain.  Later work goes back under
  `[Unreleased]`, even when the gap in the earlier section is obvious.
  `tests/test_packaging.py::test_notes_added_after_the_tag_stay_unreleased`
  fails the build when a tagged section grows.
- **Cut the release in this order.**  Bump `__version__`, date the
  `[<version>]` section, empty `[Unreleased]`, then `make release-check` and
  commit.  Tag that commit (`git tag v<version>`) and push the tag; the tag is
  the only record of which `__version__` shipped, and the packaging tests read
  it (`test_every_git_tag_has_a_changelog_section`,
  `test_notes_added_after_the_tag_stay_unreleased`).  Nothing publishes
  automatically, so the upload is a manual step from the release commit:
  `make build` then `make sdist-check` then `make sbom` (that order, see
  `pr-check`), and upload `dist/rebrew-*.tar.gz` and `dist/rebrew-*.whl`
  together.  A version already on PyPI is immutable: if a release is wrong,
  cut the next patch rather than re-uploading.
- **Verify the artifact, not just the tree.**  Before uploading, install the
  built wheel into a throwaway environment and run `rebrew --version` plus
  one real command against a project; `make sdist-check` proves the sdist
  reproduces the wheel, but nothing here proves the uploaded file is the one
  that was checked.
- **Preflight before tagging with `make release-check`**: verifies
  `__version__` is bumped past the last tag, the tree is clean, the
  changelog has a dated `[<version>]` section, that section has at least
  one entry, and `[Unreleased]` is empty — a release whose notes are split
  across the two headings ships half of them undocumented, so neither can
  be tagged out of sync with the version or the notes.

## Before submitting

0. Branch off `main` (`feat/`, `fix/`, `refactor/`, `docs/`, `test/`, `build/`,
   `ci/`, `chore/`) and open the pull request against `main`; do not commit
   straight to `main`.  Every CI job runs on the pull request, so a green local
   `make pr-check` plus a green `pre-commit` job is what review expects.
1. `make pr-check` (or `make all && make check && make build && make sdist-check && make smoke-wheel && make sbom`)
   — mirrors CI
   lint+test+cli-contract gates, the pre-commit job, the package job's
   `make build` (sdist/wheel + `dist/rebrew.buildinfo`), its
   sdist-completeness check (a wheel built from the sdist must carry the same
   files as the shipped wheel), and its wheel smoke install
   (`make smoke-wheel`: the built wheel into a throwaway `.venv-pkg`, so
   missing package-data fails here rather than on a user's install).
   `make sbom` goes after `make build`:
   `build` clears `dist/*.cdx.json`, so a BOM generated before it is deleted
   before you can ship it. `make sdist-check` does not clear it (it depends on
   `dist/rebrew.buildinfo`, which builds only when `dist/` is empty or an input is
   newer than it).
2. Keep changes minimal and scoped; match the surrounding style.
3. Add tests for new behavior — the suite sits at ~86% line coverage
   (`make coverage`), and new pure logic is expected to keep it there.
4. Record user-visible change under `## [Unreleased]` in `CHANGELOG.md` when
   the change affects installs, CLI, config, or on-disk formats (see Versioning
   above).  If you edit `tools/gen_fixtures.py`, run `make gen-fixtures` and
   commit the refreshed `tests/fixtures/` bytes; if you edit `src/rebrew/agent-skills/`,
   run `make gen-skills` and commit the refreshed `.agents/skills/` files.
