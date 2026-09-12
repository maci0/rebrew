# CI integration

Suggested gates for reverse-engineering workspaces that use rebrew.

## Package CI (this repo)

GitHub Actions (`.github/workflows/ci.yml`) runs lint, the full unit test suite
across the supported Python versions (3.12–3.14) — including a fixture-freshness
check (`tools/gen_fixtures.py --check`) and an idempotency sweep over the
offline `--json` CLI surface — a pre-commit hook-parity job, and a package job
that builds the sdist/wheel under `SOURCE_DATE_EPOCH` and installs the wheel
into a clean venv for a smoke import. The uv installer is pinned via workflow
`UV_VERSION`; Python default comes from `.python-version`.
It does **not** require a target binary or MSVC toolchain.

Every job that runs a uv command first clones the sibling `resembl` repo
(`maci0/resembl`, tag `v1.0.0`) into the directory above the workspace:
`pyproject.toml`'s `[tool.uv.sources]` resolves the `similarity` extra's
`resembl` from `../resembl`, so uv fails to build the installation plan when
that checkout is absent — even for a sync that does not install the extra.
Keep the cloned tag in step with the `resembl` version in `uv.lock`.

The workflow sets `_TYPER_FORCE_DISABLE_TERMINAL`, typer's switch for the
forced-ANSI mode it enables whenever `GITHUB_ACTIONS` is set. Without it the
help text carries escape sequences on a CI runner, which breaks every
assertion on help output (the help-listing tests and the cli-contract grep).

The nightly `toolchain-sync.yml` drift check installs through the same pinned
uv flow (`uv sync --frozen`), so scheduled runs can never silently resolve
newer dependency versions than the audited lockfile.

## Project / workspace CI

Wire these into the **game/workspace** repo (the one with `rebrew-project.toml`
and binaries), not necessarily this package:

```bash
# Bulk byte-check with regression detection against the previous report.
# PROVEN ranks with RELOC (not FAIL) under --compare.
rebrew verify --compare --json -o db/verify_results.json

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

Reports include `schema_version: 1` for:

- `rebrew verify --json`
- `rebrew round-trip --json`
- `rebrew prove --json` / `rebrew prove --all --json`
