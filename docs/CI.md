# CI integration

Suggested gates for reverse-engineering workspaces that use rebrew.

## Package CI (this repo)

GitHub Actions (`.github/workflows/ci.yml`) runs lint, the full unit test suite
across the supported Python versions (3.13–3.14; the 3.13 entry runs it as
`make coverage`, failing below `COV_FLOOR`) — plus, on that same 3.13 entry,
a fixture-freshness
check (`tools/gen_fixtures.py --check`) and an idempotency sweep over the
offline `--json` CLI surface, both version-independent, so the 3.14 entry
skips them — a pre-commit hook-parity job (`make check` with
the ruff and mypy hooks skipped, since the lint job runs them; it installs
shellcheck first through `tools/ci_apt_install.sh`, so the shell hook is
enforced there), a package job
that builds the sdist/wheel via `make build` (SOURCE_DATE_EPOCH, umask 022, C/UTC,
`PYTHONHASHSEED=0`; `tools/normalize_sdist.py` rewrites sdist tar metadata and
wheel entry modes), checks both artifacts hash the same when
`make build` reruns from a `git archive` copy extracted under umask 077 at
another path under another TZ and locale (an EXIT trap removes that copy on
every exit path, so a failed comparison does not leave a second source tree
beside the workspace), emits a CycloneDX 1.5 SBOM
(`dist/rebrew.cdx.json` from `uv.lock` via `tools/generate_sbom.py`, with the
MIT license on the rebrew component, a `pkg:github/maci0/rebrew` purl at the
`v` tag for `__version__`, project URLs as external references, each
locked distribution's own declared license from `tools/licenses.py`, and the
copyleft expressions listed in `NOTICE` — certifi and hypothesis (MPL-2.0,
in every resolve) plus the optional resembl, m2c, pyvex, and tqdm (`MPL-2.0 AND MIT`, pulled in by the binsync extra); the
generator validates the document it emits, so a lock that parsed short, or a
component whose grant nobody recorded, fails the build instead of shipping a
BOM that reads to a scanner as a clean bill of health), writes
`dist/rebrew.buildinfo`
(project name and `__version__`, uv/python/`.python-version`/setuptools parsed
from `pyproject.toml` + epoch knobs, the sha256 of `build-constraints.txt`, and
the source commit and dirty flag), and installs the
wheel into a clean venv for a smoke import through `make smoke-wheel` — the
Makefile owns that recipe, the same way it owns the build, so the CI and
contributor paths cannot drift. Runtime deps come from
`uv sync --frozen --no-dev --no-default-groups --no-install-project`, then the
wheel is overlaid with
`--no-deps` so the smoke cannot drift past `uv.lock`. The smoke assertions
live in `tools/smoke_wheel_install.py`, run with that venv's interpreter so
the import resolves to the wheel's site-packages rather than `src/`: it
reports the installed version and path and exits non-zero naming any of
`agent-skills/`, `AGENTS.md.template`, `PRINCIPLES.md`, `py.typed`, or
`workspace/py.typed` the wheel failed to ship. A `cli-contract`
job that greps the high-value `--help` surfaces. No pipeline step inlines
Python in a `run:` block: each check is a `tools/` script or a Makefile
target, so a failure names a file and a line instead of an anonymous exit
code. The package job also runs
`make sdist-check`: it builds a wheel *from* the shipped sdist through the
same hash-pinned build constraints and diffs the archive member lists
(`tools/check_sdist_wheel.py`). The wheel is smoke-installed, but the sdist is
the artifact a source install compiles, its file list comes from
`MANIFEST.in` rather than package-data, and `tools/normalize_sdist.py` rewrites
its tar metadata after the build, so a prune rule that dropped a runtime file
would otherwise ship a working wheel and a broken source install.
`make sbom` is the last build-touching step of the package job (and the last
target in `make pr-check`), because `make build` clears `dist/*.cdx.json` so a
bumped version cannot leave a stale BOM. An SBOM generated before it is deleted
again, and the upload's `if-no-files-found: error` still passes on the wheel,
sdist and buildinfo patterns, so the artifact would ship with no BOM.
`make sdist-check` no longer contributes to that (it depends on
`dist/rebrew.buildinfo`, which builds only when `dist/` is empty or a build
input is newer than the artifacts, rather than on the phony `build`; the input
list carries the `src/` directories as well as the files, so adding or
deleting a module also rebuilds). The step asserts
`test -s dist/rebrew.cdx.json`; `tests/test_ci_pins.py` pins the order.
The lint job also runs
`make audit` (`uv audit --locked`; diskcache's unfixed pickle advisory is
`--ignore-until-fixed` until upstream ships a fix). Every job installs uv
through the local composite action `.github/actions/uv-env`, which holds the
one `uv-version` / `python-version` / `resembl-ref` pin set both workflows
share (commit-SHA-pinned `setup-uv` / `checkout` Actions; Dependabot scans the
action's directory as well as `.github/workflows/`).
Lint, pre-commit, package, cli-contract, and toolchain-sync pin the exact
Python patch from `.python-version`; the test matrix pins that patch for its
3.13 entry (the coverage gate) and floats on the 3.14 minor for forward-compat
coverage. Jobs run on pinned `ubuntu-24.04` (not
`ubuntu-latest`). Both workflows also take `workflow_dispatch`: the apt and
codeload helpers retry three times, so a mirror that stays down past that
needs a manual re-run, and re-running a failed job alone cannot pick up a
fixed mirror or a new runner image. `setup-uv` runs with `enable-cache` and
`cache-python`, so the pinned managed CPython is cached alongside the uv
cache. Workflow `permissions` are `contents: read` only:
`setup-uv`'s `enable-cache` saves through the runner's cache token, not
`GITHUB_TOKEN`. It does **not**
require a target binary or MSVC toolchain.

Every job that runs `uv sync` first clones the sibling `resembl` repo
(`maci0/resembl`, tag from the action's `resembl-ref` input, currently
`v3.0.0`) into the
directory above the workspace via `tools/ci_clone_resembl.sh` (retries on
network flake; the job passes `secrets.GITHUB_TOKEN` as the action's
`github-token` input, which reaches only the clone step — header auth in a
gitconfig created under umask 077, with the token unset before `git` runs,
and hooks / fsmonitor / LFS smudge disabled before the SHA check — so
lint/test steps never see the token):
`pyproject.toml`'s `[tool.uv.sources]` resolves
the `similarity` group's `resembl` from `../resembl`, so a default
`uv sync --locked` fails to build the installation plan when that checkout is
absent. Keep `resembl-ref` in step with the `resembl` version in `uv.lock`,
and `resembl-sha` with the commit that tag resolves to: the clone fails when
the tag points anywhere else.  `make setup` checks the same commit
(`RESEMBL_SHA` in the Makefile) so a local checkout on another commit fails
before `uv sync`, with the checkout command, instead of diverging from CI.
Both host packages the jobs install come from one helper,
`tools/ci_apt_install.sh` (nasm for the asm round-trip tests, shellcheck for
the pre-commit gate, jq for the nightly drift result gate): apt mirrors flake
under load, so it retries update and
install with a backoff, skips packages already on `PATH`, and fails the step
naming the package after the last attempt.
The package job skips the sibling clone (`clone-resembl: "false"`): its
lockfile sync uses
`--no-dev --no-default-groups --no-install-project` (no path dep needed)
before the
`--no-deps` wheel overlay. After the smoke import it uploads the verified
`dist/` wheel, sdist, `rebrew.buildinfo`, and CycloneDX SBOM as a workflow
artifact (`rebrew-dist-<sha>`, 14-day retention). The test job checks out with `fetch-depth: 0` and `fetch-tags: true`.
`git describe` walks from HEAD to the last release tag, so the commits
between them have to be in the clone. Tag refs alone are not enough.
Dev installs use `uv sync --locked --all-extras --group similarity` (Makefile
`make setup`); the `m2c` git dep is a separate `--group m2c` opt-in.

The workflow runs three distinct sync shapes, so the environment a gate sees
is not the same everywhere:

| Job | Sync | Why |
|-----|------|-----|
| `lint`, `test`, `pre-commit` | `uv sync --locked --all-extras --group similarity` | the contributor env: extras on, so mypy sees the `prove` stubs and the `resembl` path dep resolves; `--locked` fails a `pyproject.toml` edit that never reached `uv.lock` |
| `package` | `UV_PROJECT_ENVIRONMENT=.venv-pkg uv sync --frozen --no-dev --no-default-groups --no-install-project`, then `UV_PROJECT_ENVIRONMENT=.venv-pkg uv pip install --no-deps dist/*.whl` | runtime deps from the lock, then the built wheel layered on top; nothing from `src/`; `--frozen` rather than `--locked` because re-resolving reads `[tool.uv.sources]` and this job has no `../resembl` |
| `cli-contract`, `toolchain-sync` | `uv sync --locked` | default groups only: the CLI surface being grepped and the toolchain drift check need no extra |

The workflow sets `_TYPER_FORCE_DISABLE_TERMINAL`, typer's switch for the
forced-ANSI mode it enables whenever `GITHUB_ACTIONS` is set. Without it the
help text carries escape sequences on a CI runner, which breaks every
assertion on help output (the help-listing tests and the cli-contract grep).
`make test` / `make check` / `make cli-contract` also set `NO_COLOR=1` /
`TERM=dumb` / `_TYPER_FORCE_DISABLE_TERMINAL`, because Rich Consoles
created at import inspect the real stderr TTY and would otherwise color
status text on a local terminal (and typer's CI ANSI mode splits option
names across escape sequences).  The pytest plugin `pytest_ansi_env`
(loaded via `pyproject.toml` `addopts`) applies the same trio for a bare
`uv run --frozen pytest`, so `FORCE_COLOR` / `GITHUB_ACTIONS` in a
developer shell cannot break CliRunner assertions that `make test`
would have passed.  `make all` includes `cli-contract`.

The nightly `toolchain-sync.yml` drift check installs through the same pinned
uv flow (`uv sync --locked`) and the same `.github/actions/uv-env` pins,
so scheduled runs can never silently resolve newer dependency versions than
the audited lockfile. It checks sources once, prints that JSON result, and
fails on drift, failed checks, unpinned sources, or an empty source inventory.
`GH_TOKEN` is mapped onto the resembl-clone and `check-updates` steps only
(authenticated git + GitHub API rate limits). The result gate uses `jq`,
installed up front through the same `tools/ci_apt_install.sh` helper nasm and
shellcheck come from, rather than assumed from the runner image.

## Project / workspace CI

Wire these into the **game/workspace** repo (the one with `rebrew-project.toml`
and binaries), not necessarily this package:

```bash
# Bulk byte-check with regression detection against the local baseline.
# --compare needs no -o; the baseline lives in .rebrew/ (gitignored run
# state) and carries target/compiler/binary identity guards.
rebrew verify --compare --json

# End-to-end splice check. Default: fail only on hard mismatches.
# --strict-catalog also fails when any splice-set entry lands in
# skipped_catalog (unresolved symbol, size mismatch, ...). No separate
# zero-splice rule.
rebrew round-trip --strict-catalog --json
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Mismatch / regression / catalog failure (`--strict-catalog`) |
| 2 | Config / infrastructure error |

### When to use `--strict-catalog`

| Stage | Recommendation |
|-------|----------------|
| Early reverse (many missing data labels) | omit flag; inspect `skipped_catalog` in JSON |
| Mature target / CI on main | always pass `--strict-catalog` |

### JSON contracts

Reports carry a `schema_version` for:

- `rebrew verify --json` → `2`, plus a `provenance` field
- `rebrew round-trip --json` → `1`
- `rebrew prove --json` / `rebrew prove --all --json` → `1`
