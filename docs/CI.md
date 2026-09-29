# CI integration

Suggested gates for reverse-engineering workspaces that use rebrew.

## Package CI (this repo)

GitHub Actions (`.github/workflows/ci.yml`) runs lint, the full unit test suite
across the supported Python versions (3.13–3.14; the 3.13 entry runs it as
`make coverage`, failing below `COV_FLOOR`) — plus, on that same 3.13 entry,
a fixture-freshness
check (`tools/gen_fixtures.py --check`) and an idempotency sweep
(`tools/check_idempotency.py --fixture-dir`, which runs the offline `--json`
CLI surface twice for output determinism and each mutating command twice
against its own scratch project, requiring the first run to actually change
it), both version-independent, so the 3.14 entry
skips them — a pre-commit hook-parity job (`make check` with
the two ruff hooks and the mypy hook skipped, since the lint job runs them; it installs
shellcheck and yamllint first through `tools/ci_apt_install.sh`, so the shell
and YAML hooks are enforced there; the SKILL.md command validator
`tools/validate_skill_commands.py` runs there too, so a flag a skill
documents but the CLI no longer accepts fails the job), a package job
that builds the sdist/wheel via `make build` (SOURCE_DATE_EPOCH, umask 022, C/UTC,
`PYTHONHASHSEED=0`; `tools/normalize_sdist.py` rewrites sdist tar metadata and
wheel entry modes), checks both artifacts hash the same when
`make build-repro` reruns from a `git archive` copy extracted under umask 077 at
another path under another TZ and locale (an EXIT trap removes that copy on
every exit path, so a failed comparison does not leave a second source tree
beside the workspace), emits a CycloneDX 1.5 SBOM
(`dist/rebrew.cdx.json` from `uv.lock` via `tools/generate_sbom.py`, with the
MIT license on the rebrew component, a `pkg:github/maci0/rebrew` purl at the
`v` tag for `__version__`, project URLs as external references, each
locked distribution's own declared license from `tools/licenses.py`, and the
attributed expressions listed in `NOTICE` — certifi and hypothesis (MPL-2.0,
in every resolve) plus the optional resembl, m2c, pyvex, tqdm (`MPL-2.0 AND MIT`, pulled in by the binsync extra), and lmdb (`OLDAP-2.8`, an attribution grant rather than a reciprocal one, pulled in by the prove extra); every
component also carries a CycloneDX `scope`, `required` for the closure of
`[project].dependencies` and `optional` for the distributions only a dev
group or an install extra reaches, so the dev tree the lock resolves into the
same file (mypy, pytest, ruff, angr, declib) does not read to a scanner as
shipped with the wheel; the
generator validates the document it emits, so a lock that parsed short, a
component whose grant nobody recorded, a component with no scope, or an
inventory with nothing in it marked `required` fails the build instead of
shipping a
BOM that reads to a scanner as a clean bill of health), writes
`dist/rebrew.buildinfo`
(project name and `__version__`, uv/python/`.python-version`/setuptools parsed
from `pyproject.toml` + epoch knobs, the sha256 of `build-constraints.txt` and
of `uv.lock` (the input the SBOM inventories and the smoke install resolves),
the sha256 of the two artifacts the manifest ships beside, and
the source commit and dirty flag), re-reads that manifest against the bytes
actually in `dist/` through `make verify-dist` (a stale or hand-edited manifest
keeps every key and still describes the wrong artifact, and the check lives
here so a contributor gets the same verdict from `make pr-check` before
pushing), and installs the
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
`workspace/py.typed` the wheel failed to ship. It then runs every console
script the installed distribution declares, as the installer wrote it, and
exits non-zero naming one that is missing from the bin directory or that fails
to start; the three `rebrew-cmake-*` compiler-driver bridges are excluded
because CMake hands them a compiler command line rather than a CLI one. A
`cli-contract`
job that greps the high-value `--help` surfaces. No pipeline step and no
Makefile recipe inlines Python: each check is a `tools/` script
(`release_check.py` for the release preflight, `require_extras.py` for the
`ensure-extras` mypy guard) or a Makefile target, so a failure names a file and
a line instead of an anonymous exit code. The package job also runs
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
`ubuntu-latest`). Both workflows also take `workflow_dispatch`: the apt
install and resembl clone helpers retry three times, so a network that stays
down past that needs a manual re-run, and re-running a failed job alone
cannot pick up a fixed mirror or a new runner image. `setup-uv` runs with
`enable-cache` and `cache-python`, so the pinned managed CPython is cached
alongside the uv cache. Workflow `permissions` are `contents: read` only:
`setup-uv`'s `enable-cache` saves through the runner's cache token, not
`GITHUB_TOKEN`. It does **not**
require a target binary or MSVC toolchain.

Every job that runs `uv sync` first clones the sibling `resembl` repo
(`maci0/resembl`, tag from the action's `resembl-ref` input, currently
`v3.1.0`) into the
directory above the workspace via `tools/ci_clone_resembl.sh` (retries on
network flake; each attempt clones into a sibling staging directory that
replaces `../resembl` by rename only after the SHA check, so a retargeted tag
or an exhausted retry leaves an existing checkout in place; the job passes
`secrets.GITHUB_TOKEN` as the action's
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
Every host package the jobs install comes from one helper,
`tools/ci_apt_install.sh` (nasm for the asm round-trip tests, shellcheck and
yamllint for the pre-commit gate, jq for the nightly drift result gate): apt
mirrors flake
under load, so it retries update and
install with a backoff, skips packages already on `PATH`, and fails the step
naming the package after the last attempt.
`node` is the one host binary the test job only asserts (`node --version`):
the runner image ships it, `tests/dashboard_*.mjs` need it, and
`test_dashboard.py` skips those scripts when it is missing, so a job that lost
it would go green without ever running the dashboard JS. Asserting beats
apt-installing a version CI never pins.
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
| `package` | `UV_PROJECT_ENVIRONMENT=.venv-pkg uv sync --frozen --no-dev --no-default-groups --no-install-project`, then `uv pip install --python .venv-pkg --no-deps dist/*.whl` | runtime deps from the lock, then the built wheel layered on top; nothing from `src/`; `--frozen` rather than `--locked` because re-resolving reads `[tool.uv.sources]` and this job has no `../resembl` |
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
shellcheck come from, rather than assumed from the runner image. Its allowlist
of passing statuses is the `STATUS_CURRENT` / `STATUS_STATIC_ASSET` /
`STATUS_STATIC_TARBALL` constants in `rebrew.toolchain_cli`, listed once as
`$ok` and used by both the verdict and the diagnostic, so a wording change in
the command fails `tests/test_ci_pins.py` instead of reddening the nightly; a
failing verdict names the sources it is about. One GitHub API blip is not
drift either: `_live_commit_sha` retries a transport failure or a retryable
status on the same backoff the pinned-media download uses, and only a 404-class
answer is reported on the first attempt.

## Required status checks

Branch protection on `main` must require every job in `ci.yml`; a rule that
lists a subset leaves the rest advisory. GitHub names the checks after the job
id, with the `test` matrix expanded per entry, so the required contexts are
`lint`, `test (3.13.15)`, `test (3.14)`, `pre-commit`, `package`, and
`cli-contract`.

| Job | Gate |
|-----|------|
| `lint` | ruff, ruff format, mypy, `uv audit` |
| `test` | the full suite on 3.13 (under the coverage floor) and 3.14, fixture freshness, idempotency sweep |
| `pre-commit` | hook parity, including shellcheck and yamllint |
| `package` | reproducible sdist/wheel, smoke install, sdist member diff, SBOM |
| `cli-contract` | the public `--help` surfaces |

`tests/test_ci_pins.py` compares this table against the job ids `ci.yml`
defines. A job added here stays unprotected until the branch-protection rule
names it, and a job removed or renamed from the workflow leaves a required
context nothing ever reports, which blocks every pull request until the rule
is edited; the test is what keeps the two from drifting apart unnoticed.

`toolchain-sync.yml` is deliberately absent: it is a nightly drift check, not
a merge gate, and requiring it would hold a pull request on an upstream
release-asset lookup.

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
