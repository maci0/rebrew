# CI integration

Use the package gates when contributing to Rebrew and the workspace gates
when verifying a project that uses it.

## Package CI (this repo)

[CI](../.github/workflows/ci.yml) runs lint, tests, hook parity, package
checks, and CLI contract checks on Ubuntu 24.04. The jobs service has its
own Go gate. Python jobs use the patch pinned in `.python-version`. The
test job fetches full Git history and tags for release-contract tests.

### Dependencies and host tools

The [uv setup action](../.github/actions/uv-env/action.yml) pins uv, Python,
and the sibling Resembl checkout (`v5.4.1` at a checked commit). Update the
action, Makefile, and lock together when advancing that pin. The sibling
clone checks the commit before replacing an existing checkout and retries
transient failures. Both workflows can be dispatched manually after an
outage.

| Job | Dependency install |
| --- | --- |
| Lint and test | `uv sync --locked --all-extras --group similarity`, with a dedicated uv cache for the all-extras build |
| Pre-commit and CLI contract | `uv sync --locked`, with the sibling checkout present for resolution |
| Package | `make smoke-wheel` uses `uv sync --frozen --no-dev --no-default-groups --no-install-project` in `.venv-pkg`, then installs the wheel with `--no-deps`. This job skips the sibling clone. |

[`tools/ci_apt_install.sh`](../tools/ci_apt_install.sh) checks for existing
tools and retries apt failures. Lint and test install `ant default-jdk
build-essential` for the JPype source build. The test job also installs
`nasm patch build-essential pkg-config libjson-c-dev` for assembly, vendor,
and native runner tests. Its disposable runner enables unprivileged user
namespaces and probes them before testing. Rebrew leaves host policy changes
to the operator on local machines.

The test job installs Bun for dashboard interactions and W3C Nu for HTML
validation. `make test` requires Bun. Bare pytest skips dashboard scripts
without Bun and skips HTML validation without Nu. See the
[contributor bootstrap](../CONTRIBUTING.md#bootstrap-clean-clone).
The pre-commit job installs `shellcheck`, `yamllint`, and Biome. It skips
the Ruff and mypy hooks because lint runs those checks directly.

### Test and package gates

- `make coverage` runs the full suite with the `COV_FLOOR` threshold. The
  test job then runs `make gen-fixtures-check` and `make idempotency-check`.
  The idempotency sweep compares two runs, ignoring timestamps and derived
  read caches. Mutating cases must change their scratch project on the
  first run. The sweep rebuilds directories it owns. Choose a fresh
  `--fixture-dir` when the existing directory lacks its ownership marker.
- The lint job runs `make audit` against the lock. See the
  [security policy](../SECURITY.md) for the scope of dependency checks.
- Help and shell-output assertions use consistent terminal settings.
  `make test`, `make check`, and `make cli-contract` disable forced ANSI
  output, and the pytest plugin applies the same settings to
  `uv run --frozen pytest`. The CLI contract job checks help without a
  project binary or an MSVC image.
- The package job runs `make build` and `make verify-dist` to produce and
  check the wheel, sdist, and `rebrew.buildinfo`. `make build-repro` rebuilds
  from a Git archive under a different path, umask, locale, and timezone.
  The comparison excludes the source-commit and source-dirty entries
  because the archive lacks Git metadata.
- `make smoke-wheel` checks the installed version, packaged skills and
  templates, type markers, and console scripts. `make sdist-check`
  rebuilds a wheel from the sdist using the same pinned build constraints
  and compares archive member names and payload hashes. It skips directory
  entries.
- `make sbom` runs after the last build because `make build` clears stale
  SBOMs. The generator validates the CycloneDX 1.5 inventory, component
  licenses, and dependency scope. See [dependency records](../CONTRIBUTING.md#adding-a-dependency).
  CI checks the SBOM is nonempty and uploads it with the wheel, sdist, and
  buildinfo as `rebrew-dist-<sha>` for 14 days. The wheel, sdist, and SBOM
  receive provenance attestations. See [release steps](../CONTRIBUTING.md#cut-a-release).

### Nightly toolchain drift

[Toolchain sync](../.github/workflows/toolchain-sync.yml) uses the same
locked install and Resembl pin. The check prints a JSON report and fails on
drift, failed checks, unpinned sources, or an empty inventory. The workflow
installs `jq` through the apt helper and scopes the GitHub token to the
sibling clone and drift check. It reports drift for manual review.

## Required status checks

Branch protection on `main` must require every job in `ci.yml`; a rule that
lists a subset leaves the rest advisory. GitHub names the checks after the job
id, with the `test` matrix expanded per entry, so the required contexts are
`jobs-service`, `lint`, `test (3.15.2)`, `pre-commit`, `package`, and
`cli-contract`.

| Job | Gate |
|-----|------|
| `jobs-service` | Go formatting, vet, and race tests for the [jobs service](../services/jobs/README.md), using a SHA-256 verified Go release |
| `lint` | ruff, ruff format, mypy, `uv audit` |
| `test` | the full suite on Python 3.15.2 with the coverage floor, fixture freshness, idempotency sweep, and W3C validation |
| `pre-commit` | hook parity, including shellcheck, yamllint and biome |
| `package` | reproducible build, wheel smoke test, sdist member and payload comparison, SBOM, and provenance attestations |
| `cli-contract` | the public `--help` surfaces |

`tests/test_ci_pins.py` compares this table against the job ids `ci.yml`
defines. Update branch protection when a job is added, renamed, or removed.
A job added to `ci.yml` becomes required only when named by the rule. An
old required check that the workflow no longer reports blocks pull requests.

The nightly toolchain drift check runs outside branch protection.

## Project / workspace CI

Wire these into the **game/workspace** repo (the one with `rebrew-project.toml`
and binaries), not necessarily this package:

```bash
# Check bytes and compare against the saved baseline.
rebrew verify --compare --json

# End-to-end splice check. Default: fail only on hard mismatches.
# --strict-catalog also fails when any splice-set entry lands in
# skipped_catalog (unresolved symbol, size mismatch, ...). No separate
# zero-splice rule.
rebrew build round-trip --strict-catalog --json
```

For a regression-only gate, restore a baseline under `.rebrew/` for the same
target, compiler configuration, and binary before running `verify --compare`.
With a missing or incompatible baseline, any failed function fails the run.

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
- `rebrew build round-trip --json` → `1`
- `rebrew prove --json` / `rebrew prove --all --json` → `1`
