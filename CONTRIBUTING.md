# Contributing to Rebrew

Thanks for contributing!  Rebrew is a compiler-in-the-loop decompilation
workbench for binary-matching game reversing (MSVC6 targets compiled in a
pinned docker image).

## Start here

- **`AGENTS.md`**: the authoritative guide to layout, conventions, build &
  test commands, code style, and architectural rules.
- **`docs/DEVELOPMENT.md`**: hard-won practical knowledge (test conventions,
  Typer/CliRunner quirks, metadata/tomlkit gotchas, import patterns, and
  toolchain-dependent test guidance).
- **`docs/ARCHITECTURE.md`**: high-level data flow (diagram) and module map;
  read this first to see how the pieces fit together.
- **`docs/CLI.md`**: the full CLI surface.

## Bootstrap (clean clone)

Needs **uv** (CI pins `uv-version` in `.github/actions/uv-env/action.yml`,
currently `0.12.14`), **Python 3.13+** (see `.python-version`), **nasm** on `PATH`
(CI installs nasm for asm round-trip tests), and **bun** on `PATH` (the
`tests/dashboard_*.mjs` interaction tests skip without it, so a host with no
bun sees a green `make test` that never ran the dashboard JS the CI job
does; `make test` fails on a missing bun, `make test-one` only warns).
`make clone-resembl` also needs
**bash**: it runs `tools/ci_clone_resembl.sh`, and the target says so instead of
printing `bash: not found`.  **shellcheck** is optional locally
but not in CI: the pre-commit shell hook exits 0 without the binary, so
`make check` on a host without it can pass where CI's pre-commit job (which
installs shellcheck) fails; `make check` warns when it is missing.  The W3C
validator **vnu** is optional locally for the same reason: `tests/html_validate.py`
skips the dashboard shell and the generated report pages without it, the CI test
job installs it, and `make test` / `make coverage` warn when it is missing.
`make vnu` installs the pinned archive (the same helper and the same sha256 the
CI job uses) into `~/.cache/rebrew/vnu` and prints the `export PATH=` line to
eval.  `uv sync` also
needs the sibling
[`resembl`](https://github.com/maci0/resembl) checkout at `../resembl`: the
path pin in `pyproject.toml` / `uv.lock` (tag `v3.1.1`, same as CI's
`resembl-ref`).  Without it, sync fails with a cryptic “Distribution not found”
path error; `make setup` fails closed if `uv` is missing, if `../resembl`'s
`version` does not match `RESEMBL_REF`, or if that checkout's `HEAD` is not
`RESEMBL_SHA` (the commit CI's `resembl-sha` pin requires; a moved tag keeps
the version string and still fails here).  It warns (still continues) when `uv`
is older than `UV_VERSION`, and when `../resembl` is not a git checkout so the
commit cannot be checked.

```bash
# from the directory that will hold both checkouts:
git clone https://github.com/maci0/rebrew.git
cd rebrew
make doctor                   # report every missing prerequisite, with the fix for each
make clone-resembl            # clones sibling resembl pin (tag v3.1.1) into ../resembl
make setup                    # uv sync --locked --all-extras --group similarity + pre-commit/pre-push hooks
make vnu                      # optional: the W3C HTML gate skips without it, CI runs it
make test-one T=tests/test_annotation.py   # smoke the edit-test loop
```

`make doctor` is read-only and runs every preflight the other targets use (uv
and its version, the sibling `../resembl` checkout, bash, nasm, bun, shellcheck,
yamllint, vnu, and
the `prove` extra / `similarity` group in `.venv`), so a host missing several of
them sees all of them at once instead of one failed target at a time.  It
separates the two that the next two bootstrap steps install (`../resembl` and
the venv extras) from a host tool the bootstrap cannot install, so on a clean
clone it exits 0 and prints `make clone-resembl` / `make setup` as the next
step, and it exits non-zero only for a missing uv, bash, nasm or bun.  Every
line still prints its own fix.  The
checks still guard their own targets: a missing nasm surfaces at `make test`
whether or not `make doctor` was run.

`make setup` installs the `prove` extra and the `similarity` group. Those
pull the attributed components named in [`NOTICE`](NOTICE) (`pyvex`/LibVEX,
`OLDAP-2.8` lmdb, and GPL-3.0-only `resembl`). Rebrew's own source stays under
[`LICENSE`](LICENSE).

`make setup` is what puts the `prove` extra in `.venv`, and that is what
`make mypy` type-checks against: a bare `uv sync` never installs optional
extras, and without angr every `angr`/`claripy` reference collapses to `Any`
(unknown `SimProcedure` base, `import-not-found`, unused `type: ignore`).
The `similarity` group (`rapidfuzz`, `resembl`) is the same class of gap:
`src/rebrew/matcher/scoring.py` imports both, and both ship type
information, so without them mypy reports `import-not-found` there. `make
mypy` checks for both before running and names the fix instead of printing
the cascade; the same check runs in the pre-commit `mypy` hook. `make test`
and `make coverage` run the same preflight for the same reason on the other
gate: those tests skip without the groups, so a venv that never saw `make
setup` would report a green suite that never exercised the code CI's test job
runs. `make test-one`
only warns, like its nasm and bun checks, so an unrelated file stays
runnable. Every target that
shells out to `uv run` likewise fails with `ERROR: uv not on PATH` rather than
a bare `uv: not found`.

## Adding a dependency

`make add-dep ADD_DEP_SPEC=<spec>` wraps `uv add`, which is the only supported
way in: it writes `pyproject.toml` and `uv.lock` together, and `make setup`
and every CI job sync with `--locked`, so a hand-edited manifest that never
reached the lock fails several commands later instead of at the edit.
`--optional dev <pkg>` puts it in a dev extra, `--group similarity` in that
group.

One step is not automatable, and the gate for it runs in `make test`:
`tools/licenses.py` records, per `name==version`, the license string the
pinned artifact declares in its own METADATA (`License-Expression`, else
`License`, else the first `Classifier: License ::`).  Record it verbatim; a
trove classifier such as `OSI Approved :: BSD License` does not say which BSD,
and rewriting one into an SPDX id upstream never wrote puts a license claim
in a released artifact.  A copyleft or attribution-bearing grant also gets a
`NOTICE` section.  `TestCycloneDxSbom::test_license_table_covers_the_lock_exactly`
in `tests/test_packaging.py` fails the suite listing every distribution left
`unrecorded`, and `make sbom` refuses to emit a component without one.

## Quick commands

```bash
make help                     # list contributor make targets
make doctor                   # report every missing prerequisite (uv, ../resembl, bash, nasm, bun, shellcheck, yamllint, vnu, venv extras)
make clone-resembl            # clone sibling resembl pin into ../resembl (required for uv sync)
make vnu                      # install the pinned W3C HTML validator and print the PATH line for it
make setup                    # locked sync (extras + similarity) + pre-commit install (checks uv + ../resembl first)
make add-dep ADD_DEP_SPEC=<spec>  # add a dependency (wraps `uv add`; prints the license-table step)
make clean                    # remove build/dist artifacts and caches
make test-one T=tests/test_annotation.py  # single file / nodeid (fast edit-test loop; defaults to test_annotation.py)
make test-one T=tests/test_annotation.py FLAGS="-k stdcall"  # narrow further with any pytest flag
make test-one T=tests/test_dashboard.py::TestSummaryRequests   # one class
make test                     # full suite (a few minutes; needs nasm + bun + the setup extras, warns without vnu)
make coverage                 # full suite under slipcover; fails below COV_FLOOR (CI test job, 3.13)
make lint                     # ruff check .
make format                   # ruff format (writes)
make format-check             # ruff format --check
make mypy                     # mypy type check (matches CI lint job)
make audit                    # uv audit --locked --ignore-until-fixed GHSA-w8v5-vhqr-4h9v (matches CI lint job)
make check                    # pre-commit hook parity (CI pre-commit job)
make build                    # reproducible sdist+wheel + dist/rebrew.buildinfo (CI package job)
make sbom                     # CycloneDX 1.5 JSON from uv.lock (offline)
make cli-contract             # high-value --help greps (CI cli-contract job)
make all                      # local mirror of CI lint+test+cli-contract gates
make pr-check                 # full local CI verification (all + check + build + sdist-check + smoke-wheel + build-repro + verify-dist + sbom)
make sdist-check              # build a wheel from the sdist, diff it against dist/*.whl
make build-repro              # rebuild HEAD under .scratch/ at another path/mode/TZ/locale, diff the hashes (clean tree)
make smoke-wheel              # install dist/*.whl into .venv-pkg and smoke-import it
make gen-fixtures             # regenerate tests/fixtures/ after editing tools/gen_fixtures.py
make gen-fixtures-check       # fixtures still match the generator
make gen-skills               # regenerate .agents/skills/ after editing src/rebrew/agent-skills/
make gen-skills-check         # rendered .agents/skills/ match the packaged source
make cycles-check             # module-level import cycles (also runs in make check)
make layering-check           # wrong-direction imports (also runs in make check)
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
On-disk format bumps (`coverage-<target>.toml` `version`, compile-cache schema)
and a raised minimum Python are also `**Breaking:**`; they may ship in a minor,
because the migration is a wholesale document rewrite (`build-db` replaces each
file whole) or a cold cache (as with the compile-cache schema `5` -> `6` bump in
2.7.0 and the Python 3.13 floor in 2.3.0).
The Python import surface (module paths, functions, classes, `__all__`) and
the `rebrew dashboard` `/api/*` JSON are not frozen: a removal, move, or
signature change there ships in a minor with a `**Breaking:**` entry naming
the old and new import path or shape (as with the helper removals in 2.1.0
and 2.2.0).  There is no deprecation window; pin the minor version if you
import rebrew as a library.  `tools/public_surface.py` reads that surface out
of the AST (`--diff <tag>` prints the delta) and
`tests/test_public_surface.py::TestSurfaceGate` fails the build when the delta
against the last tag removes or reshapes a public name and `[Unreleased]` has
no `**Breaking:**` entry naming it.  A move that leaves the old path working
is not a break and needs no entry: `rebrew.utils` owning a name that
`rebrew.cli` still imports is scored as the origin's shape, so only the
import path that actually went away is flagged.  A move that took the name
out of the old module counts as a break either way, and the entry has to name
the symbol or the module it moved to: a mention of the origin module alone
says nothing about where the import goes now.
A dropped `/api/*` route is the same break for a client reading the JSON:
`tools/public_surface.py::dashboard_routes` reads `_KNOWN_ROUTES` out of
`src/rebrew/dashboard.py` and
`tests/test_public_surface.py::TestDashboardRoutes` fails the build when the
delta against the last tag drops a path and `[Unreleased]` has no
`**Breaking:**` entry naming it.  A route table spelled as anything but
literals stops the gate instead of reading as a table with no routes.

- **One version, one place.**  `__version__` in `src/rebrew/__init__.py` is the
  source of truth; `pyproject.toml` reads it via `[tool.setuptools.dynamic]`.
  Never add a second literal.  Between releases `__version__` stays equal to
  the last tag; stage notes under `## [Unreleased]` until the bump.
- **Bump the on-disk format version with the format.**  Changing the coverage
  document means bumping `_TOML_VERSION` in `coverage_toml.py` and documenting
  the change in `docs/COVERAGE_DOCUMENT.md`; changing what a compile result depends on
  means bumping `CACHE_SCHEMA_VERSION` in `compile_cache.py`.  Both are how users
  get a clear error (or a cold cache) instead of silently wrong results after an
  upgrade.
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
  automatically, so the upload is a manual step, and it uploads the bytes CI
  verified rather than a fresh local build: download the release commit's
  `rebrew-dist-<sha>` artifact from the green `package` run, unpack it into an
  empty `dist/`, and run `make verify-dist` there (it re-derives the manifest
  digests from the files beside it, so a truncated download fails before the
  upload rather than after it; both `verify-dist` and `smoke-wheel` read `dist/`
  as they find it and never rebuild it, so unpack into an empty `dist/` and run
  them in a checkout of the release commit), then
  `uv publish dist/rebrew-*.tar.gz dist/rebrew-*.whl` from that same `dist/`.
  The artifact is the only build that ran the whole package job: reproducible
  rebuild, sdist-to-wheel member diff, and clean-venv smoke install.
  Name both files: `uv publish` defaults to `dist/*`, which also matches
  `rebrew.buildinfo` and `rebrew.cdx.json`, and the index rejects a path that
  is not a distribution.  The credential is the environment, never the command
  line, because argv is world-readable through the process table:
  `export UV_PUBLISH_TOKEN=...` from the password manager, or configure
  trusted publishing on the project and pass
  `--trusted-publishing always` with no token at all.  The same command uploads
  a PEP 740 attestation beside the files and prints its URL: that attestation
  is the only record that the bytes on the index came from a trusted publisher
  rather than from whoever answered the request.  There is no flag to ask for
  it, and `UV_PUBLISH_NO_ATTESTATIONS` is the only way to turn it off, so
  `make release-check` fails on a uv too old to attest and on a shell carrying
  that variable.  A version already on
  PyPI is immutable: if a release is wrong, cut the next patch rather than
  re-uploading.
- **Verify the artifact, not just the tree.**  Run `make smoke-wheel` against
  the unpacked `rebrew-dist-<sha>` before uploading: it installs that exact
  wheel into a throwaway `.venv-pkg` and smoke-imports it, so the file that
  ships is the one that ran.  A wheel rebuilt locally says nothing about the
  one on the index.
- **A wrong release is yanked, not replaced.**  PyPI rejects a re-upload of an
  existing version, so the recovery step is to yank it on the index: `pip
  install rebrew` then stops resolving that version, while anyone who pinned it
  keeps a resolvable file.  Yank once the fix is on PyPI, not before; a yank
  with no successor published leaves installs broken either way.
- **Preflight before tagging with `make release-check`** (which runs
  `tools/release_check.py`): verifies
  `__version__` is bumped past the last tag, the tree is clean, the
  changelog has exactly one dated `[<version>]` section, that section has at
  least one entry, and `[Unreleased]` is empty; a release whose notes are
  split across the two headings, or across two headings for the same version,
  ships half of them undocumented, so neither can be tagged out of sync with
  the version or the notes.  It also fails a patch release whose section
  carries a `**Breaking:**` entry, the same rule
  `tests/test_packaging.py::test_patch_release_never_ships_a_breaking_entry`
  enforces on the tree.

## Before submitting

0. Branch off `main` (`feat/`, `fix/`, `refactor/`, `docs/`, `test/`, `build/`,
   `ci/`, `chore/`) and open the pull request against `main`; do not commit
   straight to `main`.  Every CI job runs on the pull request, so a green local
   `make pr-check` plus a green `pre-commit` job is what review expects.
1. `make pr-check` (or `make all && make check && make build && make sdist-check && make smoke-wheel && make build-repro && make verify-dist && make sbom`):
   mirrors CI
   lint+test+cli-contract gates, the pre-commit job, the package job's
   `make build` (sdist/wheel + `dist/rebrew.buildinfo`), its
   sdist-completeness check (a wheel built from the sdist must carry the same
   files as the shipped wheel), its wheel smoke install
   (`make smoke-wheel`: the built wheel into a throwaway `.venv-pkg`, so
   missing package-data fails here rather than on a user's install), and its
   byte-reproducibility check (`make build-repro`: rebuild `HEAD` from a
   `git archive` copy under `.scratch/` at another path, file mode, timezone
   and locale, and compare the wheel, the sdist, the SBOM and
   `dist/rebrew.buildinfo` across the two trees (the manifest's `source-commit`
   and `source-dirty` lines excepted, since the copy has no `.git`); commit
   first, it builds `HEAD` and
   refuses a tree with uncommitted changes, whose dist/ and `HEAD` copy would
   differ by construction).
   `make sbom` goes after `make build`:
   `build` clears `dist/*.cdx.json`, so a BOM generated before it is deleted
   before you can ship it. `make sdist-check` does not clear it (it depends on
   `dist/rebrew.buildinfo`, which builds only when `dist/` is empty or a build
   input is newer than it, input list covering the `src/` directories so an
   added or deleted module rebuilds too).
2. Keep changes minimal and scoped; match the surrounding style.
3. Add tests for new behavior: the suite sits at ~86% line coverage
   (`make coverage`), and new pure logic is expected to keep it there.
4. Record user-visible change under `## [Unreleased]` in `CHANGELOG.md` when
   the change affects installs, CLI, config, or on-disk formats (see Versioning
   above).  If you edit `tools/gen_fixtures.py`, run `make gen-fixtures` and
   commit the refreshed `tests/fixtures/` bytes; if you edit `src/rebrew/agent-skills/`,
   run `make gen-skills` and commit the refreshed `.agents/skills/` files.
