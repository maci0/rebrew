# CI integration

Suggested gates for reverse-engineering workspaces that use rebrew.

## Package CI (this repo)

GitHub Actions (`.github/workflows/ci.yml`) runs lint, the full unit test suite
across the supported Python versions (3.13–3.14; the 3.13 entry runs it as
`make coverage`, failing below `COV_FLOOR`) — including a fixture-freshness
check (`tools/gen_fixtures.py --check`) and an idempotency sweep over the
offline `--json` CLI surface — a pre-commit hook-parity job (`make check` with
the ruff and mypy hooks skipped, since the lint job runs them), a package job
that builds the sdist/wheel via `make build` (SOURCE_DATE_EPOCH, umask 022, C/UTC,
`PYTHONHASHSEED=0`; `tools/normalize_sdist.py` rewrites sdist tar metadata and
wheel entry modes), checks both artifacts hash the same when
`make build` reruns from a `git archive` copy extracted under umask 077 at
another path under another TZ and locale, emits a CycloneDX 1.5 SBOM
(`dist/rebrew.cdx.json` from `uv.lock` via `tools/generate_sbom.py`, with the
MIT license on the rebrew component, a `pkg:github/maci0/rebrew` purl at the
`v` tag for `__version__`, project URLs as external references, and the
optional copyleft expressions from `NOTICE`), writes `dist/rebrew.buildinfo`
(uv/python/`.python-version`/setuptools parsed from `pyproject.toml` + epoch
knobs, source commit and dirty flag), and installs the
wheel into a clean venv for a smoke import — runtime deps come from
`uv sync --frozen --no-install-project`, then the wheel is overlaid with
`--no-deps` so the smoke cannot drift past `uv.lock` — and a `cli-contract`
job that greps the high-value `--help` surfaces. The lint job also runs
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
`ubuntu-latest`). Workflow `permissions` are `contents: read` only:
`setup-uv`'s `enable-cache` saves through the runner's cache token, not
`GITHUB_TOKEN`. It does **not**
require a target binary or MSVC toolchain.

Every job that runs `uv sync` first clones the sibling `resembl` repo
(`maci0/resembl`, tag from the action's `resembl-ref` input, currently
`v2.0.0`) into the
directory above the workspace via `tools/ci_clone_resembl.sh` (retries on
network flake; the job passes `secrets.GITHUB_TOKEN` as the action's
`github-token` input, which reaches only the clone step — header auth in a
gitconfig created under umask 077, with the token unset before `git` runs,
and hooks / fsmonitor / LFS smudge disabled before the SHA check — so
lint/test steps never see the token):
`pyproject.toml`'s `[tool.uv.sources]` resolves
the `similarity` group's `resembl` from `../resembl`, so a default
`uv sync --frozen` fails to build the installation plan when that checkout is
absent. Keep `resembl-ref` in step with the `resembl` version in `uv.lock`,
and `resembl-sha` with the commit that tag resolves to: the clone fails when
the tag points anywhere else.  `make setup` checks the same commit
(`RESEMBL_SHA` in the Makefile) so a local checkout on another commit fails
before `uv sync`, with the checkout command, instead of diverging from CI.
The package job skips the sibling clone (`clone-resembl: "false"`): its
lockfile sync uses
`--no-default-groups --no-install-project` (no path dep needed) before the
`--no-deps` wheel overlay. After the smoke import it uploads the verified
`dist/` wheel, sdist, `rebrew.buildinfo`, and CycloneDX SBOM as a workflow
artifact (`rebrew-dist-<sha>`, 14-day retention). The test job sets
`fetch-tags: true` so
the packaging CHANGELOG↔tag contract runs under the default shallow checkout.
Dev installs use `uv sync --frozen --all-extras --group similarity` (Makefile
`make setup`); the `m2c` git dep is a separate `--group m2c` opt-in.

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
uv flow (`uv sync --frozen`) and the same `.github/actions/uv-env` pins,
so scheduled runs can never silently resolve newer dependency versions than
the audited lockfile. It checks sources once, prints that JSON result, and
fails on drift, failed checks, unpinned sources, or an empty source inventory.
`GH_TOKEN` is mapped onto the resembl-clone and `check-updates` steps only
(authenticated git + GitHub API rate limits). The result gate uses `jq`,
included in the Ubuntu runner image.

## Project / workspace CI

Wire these into the **game/workspace** repo (the one with `rebrew-project.toml`
and binaries), not necessarily this package:

```bash
# Bulk byte-check with regression detection against the local baseline.
# --compare needs no -o; the baseline lives in .rebrew/ (gitignored run
# state) and carries target/compiler/binary identity guards.
rebrew verify --compare --json

# End-to-end splice check. Default: fail only on hard mismatches.
# --strict-catalog also fails on unresolved symbols / zero successful splices.
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

Reports include `schema_version: 2` (plus a `provenance` field) for:

- `rebrew verify --json`
- `rebrew round-trip --json`
- `rebrew prove --json` / `rebrew prove --all --json`
