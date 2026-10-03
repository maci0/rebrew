<p align="center">
  <img src="https://raw.githubusercontent.com/maci0/rebrew/main/docs/mascot.png" alt="Rebrew mascot" width="256" />
</p>

# Rebrew

**Compiler-in-the-loop decompilation workbench for binary-matching game reversing.**

Rebrew recompiles your C with the compiler that built the target and compares the bytes against the target, function by function; a function is done when they are identical. One Python CLI carries the compile-compare loop, a genetic-algorithm matcher, the function metadata store, and the verifier.

## What it covers

- Function authoring, byte diffs, compiler flag search, GA matching, and bounded symbolic proofs.
- Library identification, globals/types, data layout, and whole-binary verification.
- Prioritized work and separate file, executable-byte, and stored data-verdict accounting.
- BinSync field reconciliation and provenance, plus live Ghidra structural operations.
- Config-driven toolchains, compile caching, and six packaged agent workflows.

See the [documentation index](https://github.com/maci0/rebrew/blob/main/docs/README.md)
for guides, reference contracts, and integrations. The
[CLI reference](https://github.com/maci0/rebrew/blob/main/docs/CLI.md) owns command flags;
[toolchain documentation](https://github.com/maci0/rebrew/blob/main/docs/TOOLCHAIN.md)
owns compiler/platform support.

## Quick Start

Use Python 3.13+ and Linux x86_64 with Docker for shipped compiler profiles.
Wine, DOSBox, and native compiler runtimes live inside their images; missing
images require `rebrew toolchain pull <profile>` or an authorized build from
[rebrew-toolchains](https://github.com/maci0/rebrew-toolchains).

```bash
uv tool install git+https://github.com/maci0/rebrew.git
mkdir my-decomp && cd my-decomp
rebrew intake /path/to/server.dll        # scaffold, detect compiler, discover, document stubs
rebrew doctor                           # resolve relevant prerequisite failures
rebrew toolchain list                    # inspect the detected profile
rebrew status --json                     # inspect accounting
rebrew todo --json                       # choose a scoped action
```

Use `rebrew <command>` for every routine tool. Separate executable names are
reserved for the four CMake/objdiff build hooks; see the
[CLI reference](https://github.com/maci0/rebrew/blob/main/docs/CLI.md).

Symbolic proving needs the optional extra in the environment running Rebrew:
`uv tool install --reinstall 'rebrew[prove] @ git+https://github.com/maci0/rebrew.git'`.
BinSync needs the `binsync` extra; combine extras as `rebrew[prove,binsync]`
when using both. Contributor checkouts use `make setup`.

`intake` does not run library detection or build coverage documents. Continue
with the [onboarding guide](https://github.com/maci0/rebrew/blob/main/docs/ONBOARDING.md).
Project commands find `rebrew-project.toml` by walking up from the working directory;
standalone binary inspection commands can accept a binary path.

For a manually configured project, use `rebrew init --target server --binary server.dll`,
place the binary in `original/`, then follow `rebrew doctor`. Target names normally
use the binary stem (`server`); binary filenames keep the extension (`server.dll`).

## Working on a function

```bash
rebrew todo --json                       # select an existing stub or uncovered function
rebrew skeleton 0x10003DA0               # only when this inventory VA has no source
rebrew test src/server/func_10003da0.c --json
rebrew diff src/server/func_10003da0.c --json
rebrew verify --compare --json
rebrew lint --json
rebrew build-db                          # refresh the coverage dashboard's documents
```

Check library attribution before implementing a function. `test` and `verify`
earn byte verdicts, including regressions. EXACT and RELOC count as matched;
PROVEN records semantic evidence under the proof's assumptions and earns no
byte-match credit. See [match types](https://github.com/maci0/rebrew/blob/main/docs/MATCH_TYPES.md).

Function/data metadata are CLI/API-managed. Never hand-edit their TOMLs or write
STATUS in C. Function identity may be an inline marker or migrated TOML identity;
do not restore marker blocks after `rebrew migrate-markers`. See
[metadata ownership](https://github.com/maci0/rebrew/blob/main/docs/METADATA.md).

For integration sync, preview a concrete state directory first:

```bash
rebrew sync --pull --state-dir ./binsync-state --dry-run --json
rebrew binsync diff ./binsync-state --json
```

Apply incoming changes within the requested scope. Publishing state with
`--git-push`, uploading source to decomp.me, and starting persistent watch/server
processes require an explicit request. See
[BinSync integration](https://github.com/maci0/rebrew/blob/main/docs/BINSYNC_INTEGRATION.md).

## Agent and library use

`rebrew init` copies AGENTS.md, PRINCIPLES.md, and packaged skills into a project.
`rebrew skills list --json` lists the effective packaged/user-overlaid skills;
load the skill matching the task and only the references needed for it.
`rebrew init --check` detects scaffold drift; `--refresh-agents` regenerates it.

The [Python API guide](https://github.com/maci0/rebrew/blob/main/docs/PYTHON_API.md)
covers library imports, registry views, structured errors, and injectable clients.
The CLI/config compatibility policy and Python/API versioning policy are in
[CONTRIBUTING.md](https://github.com/maci0/rebrew/blob/main/CONTRIBUTING.md#versioning-and-releases).

For component authors, the [Cordis guide](https://github.com/maci0/rebrew/blob/main/docs/CORDIS.md) owns the composition
contracts; its [runnable tutorial](https://github.com/maci0/rebrew/blob/main/docs/CORDIS_TUTORIAL.md) demonstrates provider
replacement and teardown.

## Development

Clean clone needs **uv**, **Python 3.13+** (`.python-version`), **nasm** and
**bun** on `PATH`, a sibling [`resembl`](https://github.com/maci0/resembl) checkout at
`../resembl` (tag `v3.1.1`, matching CI `RESEMBL_REF` / `uv.lock`; `make setup`
also requires `HEAD` to be the `RESEMBL_SHA` commit CI's `resembl-sha` pins), and
**bash** for the `make clone-resembl` step below.  **bun** drives the
`tests/dashboard_*.mjs` interaction tests, which skip without it, so `make test`
fails on a missing bun while `make test-one` only warns.  **shellcheck** is optional
locally but not in CI: the pre-commit shell hook skips itself without it, so
`make check` warns rather than fails, and CI's pre-commit job installs it.  See
[`CONTRIBUTING.md`](https://github.com/maci0/rebrew/blob/main/CONTRIBUTING.md); `make help` lists targets.
Run the following from the directory that will hold both checkouts:

```bash
git clone https://github.com/maci0/rebrew.git
cd rebrew/
make doctor                # report every missing prerequisite (uv, ../resembl, bash, nasm,
                           # bun, shellcheck, yamllint, vnu, venv extras) with the fix for each;
                           # read-only, and exits non-zero only for a host tool the two steps
                           # below cannot install
make clone-resembl         # clone sibling resembl pin (tag v3.1.1) into ../resembl
make setup                 # uv sync --locked --all-extras --group similarity + pre-commit hooks
make add-dep ADD_DEP_SPEC=<spec>  # add a dependency (wraps `uv add`; prints the license-table step)
make test-one T=tests/test_annotation.py   # single-file edit-test loop
make test                  # full suite (needs nasm + bun)
make lint                  # ruff check (same as CI)
make format                # ruff format (writes)
make all                   # local gates: format-check, lint, mypy, audit, coverage, gen-fixtures-check, cycles-check, layering-check, idempotency-check, cli-contract
make check                 # pre-commit hook parity (before a PR)
make build                 # sdist + wheel + dist/rebrew.buildinfo (CI package job)
make clean                 # remove build/dist artifacts and caches
```

Flag-axis refresh from decomp.me (maintainer, needs network):
`make gen-flags` (`FLAGS_REF=<commit-or-tag>` to sync a pinned ref instead of the
default branch, `make gen-flags-check` to report upstream drift). The generated
header's `Synced:` date follows `SOURCE_DATE_EPOCH`, so re-syncing one upstream
commit writes the same file.

## Ecosystem

[ECOSYSTEM.md](https://github.com/maci0/rebrew/blob/main/docs/ECOSYSTEM.md)
maps compiler images, similarity scoring, coverage consumers, remote compilation,
and agent orchestration. Integration details belong in the topical guides linked
from the [documentation index](https://github.com/maci0/rebrew/blob/main/docs/README.md).

## License

MIT. See [LICENSE](https://github.com/maci0/rebrew/blob/main/LICENSE).
Optional dependency grants and required notices are recorded in
[NOTICE](https://github.com/maci0/rebrew/blob/main/NOTICE).
