# Contributing to Rebrew

Start with the bootstrap below. Use [AGENTS.md](AGENTS.md) for repository
rules, [Development](docs/DEVELOPMENT.md) for coding and test conventions,
and [Architecture](docs/ARCHITECTURE.md) for the module map and data flow.

## Bootstrap (clean clone)

Run `make doctor` to check host tools and get a fix for each missing item.
On a clean clone, it reports `make clone-resembl` and `make setup` as setup
steps. It exits nonzero for missing required host tools. Version drift and
missing optional tools produce `CHECK` lines. Each Make target still checks
its own prerequisites. uv selects Python from `.python-version`.

| Prerequisite | Pin | Needed by | Without it |
|--------------|-----|-----------|------------|
| **uv** | `UV_VERSION` (`0.13.6`, CI's `uv-version` in `.github/actions/uv-env/action.yml`) | every target that runs `uv run` | fails with `ERROR: uv not on PATH`; an older uv warns |
| **Python 3.15+** | `.python-version` | everything | |
| sibling [`resembl`](https://github.com/maci0/resembl) at `../resembl` | `RESEMBL_REF` (tag `v5.3.0`, CI's `resembl-ref`) and `RESEMBL_SHA` | `uv sync` (path pin in `pyproject.toml` / `uv.lock`) | `make setup` fails if its `version` is not `RESEMBL_REF` or its `HEAD` is not `RESEMBL_SHA` (a moved tag keeps the version string and still fails); warns when it is not a git checkout; a bare `uv sync` fails with a "Distribution not found" path error |
| **bash** | | `make clone-resembl` (`tools/ci_clone_resembl.sh`) | fails, naming bash |
| **nasm** | | asm round-trip tests | fails `make test` / `make coverage`; `make test-one` and `make setup` warn |
| **bun** | `BUN_VERSION` (`1.4.4`, CI's `bun-version` in `.github/workflows/ci.yml`) | `tests/dashboard_*.mjs` interaction tests | fails `make test` / `make coverage`; `make test-one` and `make setup` warn; a different version warns |
| **cc**, **pkg-config**, **json-c** development files | | native runner tests (`build-essential pkg-config libjson-c-dev` on Debian/Ubuntu) | fails `make test` / `make coverage`; `make test-one` and `make setup` warn |
| **JDK**, **Apache Ant**, cc/make | | JPype 1.7.1 sdist build for the `binsync` extra (`declib` → `pyghidra` → `jpype1`) | `make setup` fails naming it instead of dying in the build; CI installs `ant default-jdk build-essential` |
| **Rust** (cargo + rustc) | `RUST_VERSION` (`1.99.1`, `rust-toolchain.toml`), maturin `1.15.0` | `python-flirt` sdist build in `make setup` (sdist-only in `uv.lock`) | `make setup` fails naming it; another rustc or maturin version warns |
| **Go** | `GO_VERSION` (matches `services/jobs/go.mod` and CI) | `make jobs-check` | fails `make jobs-check`; `make setup` warns |
| **GNU patch** | | vendor tests, `rebrew library vendor` | fails `make test` / `make coverage`; `make test-one` and `make setup` warn |
| **shellcheck**, **yamllint** | | pre-commit shell and YAML hooks | warns: the hooks exit 0 locally, so `make check` can pass where CI's pre-commit job fails |
| **biome** | `tools/ci_install_biome.sh` | pre-commit dashboard-JS hook | warns, same shape; `make biome` installs the pin |
| **vnu** (W3C validator) | `tools/ci_install_vnu.sh` | `tests/html_validate.py` (dashboard shell, report pages) | warns: the tests skip, CI runs them; `make vnu` installs the pin into `~/.cache/rebrew/vnu` |
| venv `prove` extra and `similarity` group | | `make mypy`, `make test`, `make coverage` | those targets fail naming the fix; `make test-one` warns |

`ensure-unshare-build` also probes `unshare --user --map-root-user true` (the
probe CI runs after relaxing AppArmor's
`kernel.apparmor_restrict_unprivileged_userns`) and warns when namespaces are
denied, instead of letting the native tests skip silently.

```bash
# from the directory that will hold both checkouts:
git clone https://github.com/maci0/rebrew.git
cd rebrew
make doctor                   # report every missing prerequisite, with the fix for each
make clone-resembl            # clones sibling resembl pin (tag v5.3.0) into ../resembl
make setup                    # uv sync --locked --all-extras --group similarity + pre-commit/pre-push hooks
make vnu                      # optional: the W3C HTML gate skips without it, CI runs it
make biome                    # optional: the dashboard-JS hook skips without it, CI runs it
make test-one T=tests/test_annotation_roundtrip.py   # smoke the edit-test loop
```

`make vnu` and `make biome` print an `export PATH=` line to eval.

`make setup` installs the `prove` extra and the `similarity` group. Those
pull the attributed components named in [`NOTICE`](NOTICE) (`pyvex`/LibVEX,
`OLDAP-2.8` lmdb, and GPL-3.0-only `resembl`). Rebrew's own source stays under
[`LICENSE`](LICENSE).

Use the locked contributor environment for type checks and the full test
suite. A bare `uv sync` omits the extras and similarity group the gates need.

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

`make help` lists the contributor targets with a one-line description and the
bootstrap steps; it is the one list to keep current. The edit-test loop:

```bash
make test-one                                              # defaults to tests/test_annotation_roundtrip.py
make test-one T=tests/test_annotation_roundtrip.py FLAGS="-k roundtrip"  # narrow with any pytest flag
make test-one T=tests/test_dashboard.py::TestSummaryRequests              # one class
make test                     # full suite, a few minutes
make all                      # CI lint, test, cli-contract and jobs-service gates; make pr-check adds the rest
```

## Documentation, templates, and skills

Follow [documentation style](docs/STYLE.md): current guides own runtime facts;
ADRs, released notes, and scoped PRDs preserve historical decisions/evidence.
The [documentation index](docs/README.md) links each subject's home.
Edit packaged skills/templates, then regenerate the copies; the style guide
lists the rendering, link, CLI-help, metadata-field, and template checks.
Python SDK examples belong in [PYTHON_API.md](docs/PYTHON_API.md), not the README.

## What to work on

- Open issues in the repo, or the prioritized action list: `rebrew todo`
  (inside a project workspace with `rebrew-project.toml`).
- Longer-horizon backlog: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Versioning and releases

Rebrew is 6.x. The required release bump depends on which contract changes.

| Change | Minimum version bump |
| --- | --- |
| Remove or rename a CLI command or flag, or change a config key's meaning | Major |
| Break a public Python import or change its signature, or break the dashboard HTTP API | Minor |
| Bump the coverage document or compile-cache format, or raise the Python minimum | Minor |

Prefix breaking entries with `**Breaking:**` in the changelog. Name the
affected command, symbol, route, or format and describe the migration. Use
`tools/public_surface.py --diff <tag>` to inspect changes to the Python API.
Library consumers can pin a minor version to avoid breaking updates.

`src/rebrew/__init__.py` owns `__version__`. Keep it at the last release
between releases. For a format change, also bump the relevant format version
(`_TOML_VERSION` in `coverage_toml.py` or `CACHE_SCHEMA_VERSION` in
`compiler/cache.py`) and document the migration.

### Cut a release

1. Bump `__version__`, move the release entries from `[Unreleased]` to a
   single dated version section in `CHANGELOG.md`, and commit. Leave
   `[Unreleased]` empty and keep published sections frozen.
2. Run `make release-check` from the clean checkout. It checks the version,
   changelog, and published Resembl pin. Tag that commit and push the tag.
3. Download the green `package` job's `rebrew-dist-<sha>` artifact. Unpack it
   into an empty `dist/` in a checkout of the release commit. Run
   `make verify-dist` and `make smoke-wheel` against those files.
4. GitHub Releases is the distribution channel. Copy the dated changelog
   section into `release-notes.md` and attach the verified artifacts. Replace
   `X.Y.Z` with the release version:

   ```bash
   version=X.Y.Z
   gh release create "v${version}" dist/rebrew-*.tar.gz dist/rebrew-*.whl \
     dist/rebrew.buildinfo dist/rebrew.cdx.json --verify-tag \
     --title "Rebrew ${version}" --notes-file release-notes.md
   ```

Fix a published mistake with a new patch release and leave the existing tag
and assets available for reference. See [package CI](docs/CI.md#package-ci-this-repo)
for artifact and reproducibility checks.

## Before submitting

1. Branch off `main` and open the pull request against it. Use a prefix
   such as `fix/`, `feat/`, or `docs/`.
2. Run the relevant tests during development. Commit before `make pr-check`
   because its reproducible-build gate compares against `HEAD`. See
   [required checks](docs/CI.md#required-status-checks).
3. Add tests for changed behavior and keep the `COV_FLOOR` line-coverage
   gate in the Makefile. Record user-visible changes to installs, CLI,
   config, or on-disk formats under `[Unreleased]` in `CHANGELOG.md`.
4. Run `make gen-fixtures` after changing the fixture generator and
   `make gen-skills` after changing packaged skills. Include the regenerated
   files with the change.
