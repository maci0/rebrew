# CI integration

Suggested gates for reverse-engineering workspaces that use rebrew.

## Package CI (this repo)

GitHub Actions (`.github/workflows/ci.yml`) runs lint, the full unit test suite
across the supported Python versions (3.13–3.14) — including a fixture-freshness
check (`tools/gen_fixtures.py --check`) and an idempotency sweep over the
offline `--json` CLI surface — a pre-commit hook-parity job, a package job
that builds the sdist/wheel under `SOURCE_DATE_EPOCH`, emits a CycloneDX 1.5
SBOM (`dist/rebrew.cdx.json` from `uv.lock` via `tools/generate_sbom.py`), and
installs the wheel into a clean venv for a smoke import, and a `cli-contract`
job that greps the high-value `--help` surfaces. The lint job also runs
`uv audit --locked` (diskcache's unfixed pickle advisory is
`--ignore-until-fixed` until upstream ships a fix). The uv installer is pinned
via workflow `UV_VERSION` (commit-SHA-pinned `setup-uv` / `checkout` Actions).
Lint, pre-commit, package, cli-contract, and toolchain-sync pin the exact
Python patch from `.python-version`; the test matrix covers the 3.13/3.14
minors for compatibility. Jobs run on pinned `ubuntu-24.04` (not
`ubuntu-latest`). Workflow `permissions` include `actions: write` so
`setup-uv`'s `enable-cache` can persist the uv cache (restore alone works with
`contents: read`, but a cold cache never warms without write). It does **not**
require a target binary or MSVC toolchain.

Every job that runs `uv sync` first clones the sibling `resembl` repo
(`maci0/resembl`, tag from workflow `RESEMBL_REF`, currently `v2.0.0`) into the
directory above the workspace via `tools/ci_clone_resembl.sh` (retries on
network flake; uses `GH_TOKEN` header auth when mapped from
`secrets.GITHUB_TOKEN`): `pyproject.toml`'s `[tool.uv.sources]` resolves
the `similarity` group's `resembl` from `../resembl`, so uv fails to build the
installation plan when that checkout is absent — even for a sync that does not
install the group. Keep `RESEMBL_REF` in step with the `resembl` version in
`uv.lock`. The package job only runs `uv build` / `uv pip install` of the
wheel, so it skips the sibling clone. The test job sets `fetch-tags: true` so
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
names across escape sequences).  `make all` includes `cli-contract`.

The nightly `toolchain-sync.yml` drift check installs through the same pinned
uv flow (`uv sync --frozen`) and the same `RESEMBL_REF` / `UV_VERSION` pins,
so scheduled runs can never silently resolve newer dependency versions than
the audited lockfile. It checks sources once, prints that JSON result, and
fails on drift, failed checks, unpinned sources, or an empty source inventory.
The result gate uses `jq`, included in the Ubuntu runner image.

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
