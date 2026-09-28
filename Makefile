.PHONY: help doctor setup clean test test-one lint format format-check check build sbom all pr-check \
	gen-fixtures gen-fixtures-check gen-skills gen-skills-check cycles-check idempotency-check mypy audit \
	cli-contract release-check coverage ensure-uv ensure-resembl ensure-nasm warn-nasm ensure-node warn-node warn-shellcheck \
	warn-yamllint \
	ensure-bash \
	smoke-wheel \
	ensure-extras \
	sdist-check \
	build-repro \
	verify-dist \
	clone-resembl warn-uv-version

# Force POSIX sh for recipes (ignore a caller-exported SHELL=bash).  Recipes
# below use only POSIX constructs so Alpine/busybox ash and Debian dash work.
# Version compares use ``sort -t. -k…n`` (POSIX), not GNU ``sort -V``.
SHELL := /bin/sh

.DEFAULT_GOAL := help

# Several targets here write the same output dir and some of them delete it.
# `build` opens by removing dist/*.whl, dist/*.tar.gz, dist/*.buildinfo and
# dist/*.cdx.json; `sbom` writes dist/rebrew.cdx.json; `sdist-check` and
# `smoke-wheel` read the wheel `build` produced.  Prerequisites are not
# ordered, so `make -j pr-check` ran `build`, `sdist-check` and `sbom`
# concurrently: one `build` deleted the BOM the other had just written (the
# exact failure the `sbom`-last comment below describes), and the phony
# `build` and the recursive `make build` behind dist/rebrew.buildinfo raced
# over the same dist/ files.  Sequencing the whole file is the one-line fix;
# none of these recipes parallelize internally.
.NOTPARALLEL:

# Prefer lockfile-pinned deps. Override with `make setup UV_SYNC_FLAGS=` if needed.
# --locked, not --frozen: --frozen only skips the lock update, it never checks
# that uv.lock still matches pyproject.toml, so a dependency edited without
# `uv lock` installs the previous set and every gate below then runs against an
# environment the manifest does not describe.  --locked fails that instead.
# --group similarity pulls the sibling resembl path dep (not a PyPI extra);
# --group m2c is opt-in (git-only decompiler) — add it when exercising fetch_m2c.
UV_SYNC_FLAGS ?= --locked --all-extras --group similarity

# Keep in step with the `resembl-ref` / `resembl-sha` / `uv-version` input
# defaults in .github/actions/uv-env/action.yml (CI's single pin site) and the
# resembl version recorded in uv.lock (path dep).  `make setup` prints the
# clone command when ../resembl is missing; it does not clone for you.
# RESEMBL_SHA is the commit that tag must resolve to: tags move, and a
# same-version checkout on another commit passes the version string check
# while CI clones this commit.
RESEMBL_REF ?= v3.1.0
RESEMBL_SHA ?= 2f6ff431e5cb240e6aab1102cffb3dea0b033ebf
RESEMBL_DIR := $(abspath $(CURDIR)/../resembl)
# Match the CI uv pin so local sync/audit behavior tracks CI.
UV_VERSION ?= 0.12.14

# Single-file / nodeid override for the edit-test loop:
#   make test-one T=tests/test_annotation.py
#   make test-one T=tests/test_annotation.py::TestAnnotationDataclass
#   make test-one T=tests/test_annotation.py FLAGS="-k test_stdcall"
T ?= tests/test_annotation.py
FLAGS ?=

# `make coverage` fail-under percentage; keep in step with [tool.slipcover]
# fail_under in pyproject.toml.
COV_FLOOR ?= 85

# Second source tree `make build-repro` builds the same commit in, at a
# different path, file mode, timezone and locale.  Inside the checkout (not a
# sibling of it) so the copy never sits outside the tree, and gitignored like
# every other scratch path; `make clean` does not need a rule for it because
# the recipe removes it on every exit path.
BUILD_REPRO_DIR ?= .scratch/rebuild

# Everything `make build` reads that can change what ships, minus build
# residue.  `dist/rebrew.buildinfo` depends on this list, so editing a source
# file rebuilds dist/ instead of leaving `sdist-check` / `smoke-wheel` to
# verify the artifacts of an earlier tree.  __pycache__ and egg-info are
# excluded: a test run or a bare `uv build` writes them and neither changes a
# byte of the package.  tools/normalize_sdist.py is here because it rewrites
# both archives after the build, and .python-version because it selects the
# interpreter uv builds with: neither lives under src/, and omitting them let
# an edit to either leave dist/ describing the previous tree.  The sdist's
# top-level docs are here for the same reason from the other side:
# README.md / CHANGELOG.md / SECURITY.md / LICENSE / NOTICE are sdist members
# (MANIFEST.in includes the first three, [project] license-files pulls in the
# last two, setuptools auto-ships the README) and the license files also land
# in the wheel's dist-info, so editing one changes what ships while every
# listed prerequisite stayed untouched.
#
# uv.lock is here for the manifest, not for the bytes: the archives come from
# build-constraints.txt, but dist/rebrew.buildinfo records uv-lock-sha256 (and
# `make sbom` inventories that same lock), so a lock edit left a provenance
# record naming the lock the artifacts were not built beside.
#
# .gitattributes is here for the same reason: it sets the line endings and the
# binary marking of every tracked file, so flipping eol=lf or marking a pattern
# binary rewrites the bytes setuptools copies into both archives.
#
# The directories are prerequisites too.  `find src -type f` only sees the files
# that exist when make expands this list, and make rebuilds a target when a
# prerequisite is *newer*, not when one disappears: adding or deleting a source
# file leaves every listed file untouched, so dist/ stayed "up to date" and
# sdist-check / smoke-wheel verified the previous tree's artifacts.  A
# directory's mtime moves exactly when an entry inside it is created, removed,
# or renamed, which is the event being tracked.  The same __pycache__ /
# egg-info exclusions apply: a test run rewrites those directories constantly
# and none of it changes a byte of the package.
BUILD_INPUT_DIRS := $(shell find src -type d \
	-not -path '*/__pycache__*' -not -path '*.egg-info*')
BUILD_INPUTS := Makefile pyproject.toml build-constraints.txt MANIFEST.in uv.lock \
	.python-version tools/normalize_sdist.py \
	.gitattributes \
	README.md CHANGELOG.md SECURITY.md LICENSE NOTICE \
	$(shell find src -type f -not -path '*/__pycache__/*' -not -path '*.egg-info/*')

# Reproducible package builds: honor SOURCE_DATE_EPOCH when set; otherwise use
# the committer timestamp (or 0 for a non-git tree). `make build` rewrites the
# sdist and the wheel with tools/normalize_sdist.py (sorted entries, fixed
# mtimes, fixed modes; sdist owner 0:0). Wheel modes otherwise follow the
# checkout umask: setuptools copies each source file's mode, and git fills
# the non-executable bits from umask.
# `?=` alone would leave SOURCE_DATE_EPOCH a recursively expanded variable, so
# every $(SOURCE_DATE_EPOCH) below re-ran git.  `override :=` collapses the
# result to a simple variable: one git call, and an empty commit date (a
# non-git tree) becomes 0.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null)
override SOURCE_DATE_EPOCH := $(or $(SOURCE_DATE_EPOCH),0)

# The tools/ helpers run on the pinned interpreter, never an ambient one.
# `uv run --no-project` otherwise takes the first interpreter it discovers: an
# activated venv, a parent checkout's .venv, else /usr/bin/python3.  One of
# these helpers rewrites the artifacts (normalize_sdist.py), so a host on
# another patch could produce bytes the python= line in dist/rebrew.buildinfo
# does not describe.  `.python-version` is the pin `uv build` uses for its
# isolated build env, so the environment that builds the wheel and the one
# that normalizes it are the same interpreter; a host without it fails loud
# instead of silently substituting another.  --offline keeps the no-network
# promise the sbom and normalizer recipes already made.
PYTHON_PIN := $(shell cat .python-version)
UV_RUN_TOOLS := uv run --no-project --offline --python $(PYTHON_PIN)

help:
	@printf '%s\n' \
		'  make doctor             # report every missing prerequisite (uv, resembl, nasm, node, shellcheck, yamllint, extras)' \
		'  make setup              # uv sync (locked + extras + similarity) + pre-commit/pre-push hooks' \
		'  make clone-resembl      # clone sibling resembl pin into ../resembl (required for uv sync)' \
		'  make clean              # remove build/dist artifacts and caches' \
		'  make test               # full pytest suite (needs nasm + node on PATH)' \
		'  make test-one T=<node>  # one file/nodeid, e.g. T=tests/test_foo.py::TestBar (nasm/node optional)' \
		'  make coverage           # full suite under slipcover with the COV_FLOOR fail-under gate' \
		'  make lint               # ruff check .' \
		'  make format             # ruff format (writes)' \
		'  make format-check       # ruff format --check' \
		'  make mypy               # mypy (matches CI lint job)' \
		'  make audit              # uv audit --locked --ignore-until-fixed GHSA-w8v5-vhqr-4h9v (CI lint job)' \
		'  make check              # pre-commit run --all-files (CI pre-commit job)' \
		'  make cli-contract       # high-value --help greps (CI cli-contract job)' \
		'  make build              # reproducible sdist+wheel + dist/rebrew.buildinfo' \
		'  make sbom               # CycloneDX 1.5 JSON from uv.lock (offline)' \
		'  make sdist-check        # build a wheel from the sdist and diff it against dist/*.whl' \
		'  make build-repro        # rebuild HEAD under .scratch/ at another path/mode/TZ/locale and diff the hashes (clean tree)' \
		'  make verify-dist        # re-check dist/rebrew.buildinfo against the artifacts actually in dist/' \
		'  make smoke-wheel        # install dist/*.whl into .venv-pkg and smoke-import it (CI package job)' \
		'  make all                # local mirror of CI lint+test(+coverage floor)+cli-contract gates' \
		'  make pr-check           # full local CI verification (all + check + build + sdist-check + smoke-wheel + build-repro + verify-dist + sbom)' \
		'  make gen-fixtures       # regenerate tests/fixtures/ from tools/gen_fixtures.py' \
		'  make gen-fixtures-check # tools/gen_fixtures.py --check' \
		'  make gen-skills         # regenerate .agents/skills/ from src/rebrew/agent-skills/' \
		'  make gen-skills-check   # verify .agents/skills/ matches src/rebrew/agent-skills/' \
		'  make cycles-check       # tools/detect_cycles.py (also in pre-commit / make check)' \
		'  make idempotency-check  # tools/check_idempotency.py' \
		'  make release-check      # version/changelog/tag preflight before tagging' \
		'' \
		'Bootstrap (clean clone):' \
		'  0. make doctor          # reports which of the steps below this host is missing' \
		'  1. Install uv $(UV_VERSION)+ (CI pin), Python 3.13+ (.python-version), nasm + node on PATH' \
		'     (shellcheck + yamllint too: the pre-commit shell and YAML hooks skip' \
		'     themselves without them, CI runs both;' \
		'     bash for step 2: tools/ci_clone_resembl.sh runs under it)' \
		'  2. Clone sibling resembl at $(RESEMBL_REF) into ../resembl' \
		'     git clone --depth 1 --branch $(RESEMBL_REF) https://github.com/maci0/resembl.git ../resembl' \
		'     setup fails unless that checkout HEAD is $(RESEMBL_SHA) (CI resembl-sha)' \
		'  3. make setup && make test-one T=tests/test_annotation.py' \
		'  Before a PR: make all && make check && make build (or make pr-check)'

# Every recipe below shells out to ``uv run``; without this preflight a
# contributor who has not run ``make setup`` yet gets ``uv: not found`` from
# the shell with no pointer at the missing prerequisite.
ensure-uv:
	@set -eu; \
	if ! command -v uv >/dev/null 2>&1; then \
	  echo "ERROR: uv not on PATH (required for setup/test/lint; CI pins UV_VERSION=$(UV_VERSION))."; \
	  echo "Install from https://docs.astral.sh/uv/ then re-run make setup."; \
	  exit 1; \
	fi

# Version drift only matters where uv resolves the environment (setup, build);
# the day-to-day gates run against an already-synced .venv, so they do not
# re-warn.  Split from ensure-uv to keep that one cheap enough for every target.
warn-uv-version: ensure-uv
	@set -eu; \
	uv_out=$$(uv --version); \
	uv_ver=$$(printf '%s\n' "$$uv_out" | awk '{print $$2}'); \
	lowest=$$(printf '%s\n%s\n' "$$uv_ver" "$(UV_VERSION)" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1); \
	if [ "$$lowest" != "$(UV_VERSION)" ]; then \
	  echo "WARNING: uv $$uv_ver is older than CI pin UV_VERSION=$(UV_VERSION)."; \
	  echo "Sync usually still works; upgrade when you can (https://docs.astral.sh/uv/)."; \
	  echo "To silence this check: make setup UV_VERSION=$$uv_ver"; \
	fi

ensure-resembl: ensure-uv
	@set -eu; \
	if [ ! -e "$(RESEMBL_DIR)/pyproject.toml" ]; then \
	  echo "ERROR: sibling resembl checkout missing at $(RESEMBL_DIR)"; \
	  echo "uv sync needs it even when you are not using the similarity group,"; \
	  echo "and uv audit (make audit) resolves the same path dependency."; \
	  echo "(pyproject.toml [tool.uv.sources] pins path = \"../resembl\")."; \
	  echo "Run 'make clone-resembl' or clone manually, then re-run make setup:"; \
	  echo "  git clone --depth 1 --branch $(RESEMBL_REF) https://github.com/maci0/resembl.git $(RESEMBL_DIR)"; \
	  exit 1; \
	fi; \
	resembl_ver=$$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$(RESEMBL_DIR)/pyproject.toml" | head -n 1); \
	want="$(RESEMBL_REF)"; want=$${want#v}; \
	if [ -z "$$resembl_ver" ] || [ "$$resembl_ver" != "$$want" ]; then \
	  echo "ERROR: $(RESEMBL_DIR) version '$$resembl_ver' does not match RESEMBL_REF=$(RESEMBL_REF)"; \
	  echo "Re-clone via 'make clone-resembl' or manually, then re-run make setup:"; \
	  echo "  git clone --depth 1 --branch $(RESEMBL_REF) https://github.com/maci0/resembl.git $(RESEMBL_DIR)"; \
	  exit 1; \
	fi; \
	if command -v git >/dev/null 2>&1 \
	  && git -C "$(RESEMBL_DIR)" rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
	  head_sha=$$(git -C "$(RESEMBL_DIR)" rev-parse HEAD 2>/dev/null || true); \
	  if [ "$$head_sha" != "$(RESEMBL_SHA)" ]; then \
	    echo "ERROR: $(RESEMBL_DIR) HEAD '$$head_sha' does not match RESEMBL_SHA=$(RESEMBL_SHA)"; \
	    echo "CI accepts $(RESEMBL_REF) only when the tag resolves to that commit."; \
	    echo "Check out the pin (or run 'make clone-resembl'), then re-run make setup:"; \
	    echo "  git -C $(RESEMBL_DIR) fetch --depth 1 origin $(RESEMBL_SHA)"; \
	    echo "  git -C $(RESEMBL_DIR) checkout $(RESEMBL_SHA)"; \
	    echo "To use this checkout locally anyway: make setup RESEMBL_SHA=$$head_sha"; \
	    exit 1; \
	  fi; \
	else \
	  echo "WARNING: $(RESEMBL_DIR) is not a git checkout; RESEMBL_SHA=$(RESEMBL_SHA) was not verified."; \
	  echo "CI refuses a $(RESEMBL_REF) tag that does not resolve to that commit."; \
	fi

ensure-nasm:
	@set -eu; \
	if ! command -v nasm >/dev/null 2>&1; then \
	  echo "ERROR: nasm not on PATH (required for asm round-trip tests, same as CI)."; \
	  echo "Install it, then re-run: e.g. apt install nasm / pacman -S nasm / dnf install nasm"; \
	  exit 1; \
	fi

# Soft check for setup / test-one: name the host dep before the first ``make test`` failure.
warn-nasm:
	@set -eu; \
	if ! command -v nasm >/dev/null 2>&1; then \
	  echo "WARNING: nasm not on PATH (required for make test, same as CI; asm round-trip tests skip in make test-one)."; \
	  echo "Install it before running tests: e.g. apt install nasm / pacman -S nasm / dnf install nasm"; \
	fi

# tests/dashboard_*.mjs drive the dashboard's JS through a stub DOM; the
# pytest wrapper skips them when `node` is absent, so a host without it reads
# a green `make test` as full coverage of a file CI does run (the ubuntu-24.04
# runner image ships node).  Same shape as the nasm preflight above: hard for
# the whole suite, soft for a single file.
ensure-node:
	@set -eu; \
	if ! command -v node >/dev/null 2>&1; then \
	  echo "ERROR: node not on PATH (required by the dashboard interaction tests, same as CI)."; \
	  echo "Install it, then re-run: e.g. apt install nodejs / pacman -S node / dnf install nodejs"; \
	  echo "Or iterate without it: make test-one T=tests/test_foo.py (dashboard_*.mjs tests skip)."; \
	  exit 1; \
	fi

warn-node:
	@set -eu; \
	if ! command -v node >/dev/null 2>&1; then \
	  echo "WARNING: node not on PATH (required by the dashboard interaction tests, same as CI; they skip in make test-one)."; \
	  echo "Install it before running the full suite: e.g. apt install nodejs / pacman -S node / dnf install nodejs"; \
	fi

# The shellcheck hook exits 0 when the binary is absent, so a contributor
# without it sees `make check` pass and CI (which installs shellcheck) fail.
warn-shellcheck:
	@set -eu; \
	if ! command -v shellcheck >/dev/null 2>&1; then \
	  echo "WARNING: shellcheck not on PATH; the pre-commit shell hook skips itself locally."; \
	  echo "CI installs it, so a clean 'make check' here can still fail after push:"; \
	  echo "  apt install shellcheck / pacman -S shellcheck / dnf install shellcheck"; \
	fi

# Same skip-if-absent shape, same consequence, for the YAML gate.
warn-yamllint:
	@set -eu; \
	if ! command -v yamllint >/dev/null 2>&1; then \
	  echo "WARNING: yamllint not on PATH; the pre-commit YAML hook skips itself locally."; \
	  echo "CI installs it, so a clean 'make check' here can still fail after push:"; \
	  echo "  apt install yamllint / pacman -S yamllint / dnf install yamllint"; \
	fi

# tools/ci_clone_resembl.sh is bash (it needs ${var:?} and bash-only options).
# A minimal host without it would read "bash: not found" as a clone failure.
ensure-bash:
	@set -eu; \
	if ! command -v bash >/dev/null 2>&1; then \
	  echo "ERROR: bash not on PATH (make clone-resembl runs tools/ci_clone_resembl.sh with it)."; \
	  echo "Install it: e.g. apk add bash / apt install bash / dnf install bash"; \
	  echo "Or clone the sibling resembl pin by hand (command below), then re-run make setup."; \
	  exit 1; \
	fi

# Clone sibling resembl pin matching CI and uv.lock into ../resembl
clone-resembl: ensure-bash
	@set -eu; \
	RESEMBL_REF=$(RESEMBL_REF) RESEMBL_SHA=$(RESEMBL_SHA) bash tools/ci_clone_resembl.sh "$(RESEMBL_DIR)"

# Setup the development environment
setup: ensure-resembl warn-nasm warn-uv-version
	uv sync $(UV_SYNC_FLAGS)
	uv run --frozen pre-commit install

# `uv run` syncs the default groups, never the optional extras, so a venv made
# by a bare `uv sync` has no angr.  mypy then reports a wall of phantom errors
# (unknown SimProcedure, import-not-found, unused-ignore) whose real cause is
# the missing extra.  Name it before the run instead of after.
#
# The `similarity` group is the same class of gap: scoring.py imports
# rapidfuzz and resembl lazily, so mypy reports one import-not-found there
# when the group is absent.  rapidfuzz and resembl ship type information and
# [[tool.mypy.overrides]] deliberately does not silence them, so the fix is
# installing the group, not muting the checker.
ensure-extras: ensure-uv
	uv run --frozen --no-sync python tools/require_extras.py $(RESEMBL_DIR)

# Whole-environment preflight.  Every other target checks one prerequisite and
# names it when it is missing, so a host without nasm, without shellcheck, or
# with a bare `uv sync` venv finds out one failed command at a time: `make
# setup` (uv, ../resembl), `make test` (nasm, node), `make check` (shellcheck),
# `make mypy` (extras).  This runs each of those checks in one pass and prints
# what it said, so the fix text stays written once, next to the check.
#
# Read-only: it runs the preflight targets and nothing else, installs nothing,
# and never edits .venv.  It runs the hard checks (uv, ../resembl, nasm, node,
# the venv extras) and the warn-level ones (the uv version, shellcheck), so a
# non-zero exit names a prerequisite the suite or the lint gate needs, and a
# warning still prints for a host that only costs a CI-only gate.
doctor:
	@set -u; \
	rc=0; \
	for check in ensure-uv warn-uv-version ensure-resembl ensure-bash ensure-nasm ensure-node warn-shellcheck warn-yamllint ensure-extras; do \
	  case $$check in \
	    ensure-uv) label='uv on PATH' ;; \
	    warn-uv-version) label="uv >= $(UV_VERSION) (CI pin)" ;; \
	    ensure-resembl) label="sibling resembl at $(RESEMBL_DIR)" ;; \
	    ensure-bash) label='bash on PATH (make clone-resembl)' ;; \
	    ensure-nasm) label='nasm on PATH (make test; optional for test-one)' ;; \
	    ensure-node) label='node on PATH (dashboard interaction tests; optional for test-one)' ;; \
	    warn-shellcheck) label='shellcheck on PATH (pre-commit shell hook)' ;; \
	    warn-yamllint) label='yamllint on PATH (pre-commit YAML hook)' ;; \
	    ensure-extras) label="venv extras (angr/claripy, rapidfuzz/resembl)" ;; \
	  esac; \
	  out=$$($(MAKE) --no-print-directory $$check 2>&1) || rc=1; \
	  if [ -z "$$out" ]; then \
	    printf 'ok    %s\n' "$$label"; \
	  else \
	    printf 'CHECK %s\n' "$$label"; \
	    printf '%s\n' "$$out" | grep -v '^make\[[0-9]*\]: \*\*\*' | sed 's/^/      /'; \
	  fi; \
	done; \
	if [ $$rc -eq 0 ]; then \
	  echo 'environment ready: run make setup, then make test-one T=tests/test_annotation.py'; \
	else \
	  echo 'environment incomplete: fix the CHECK lines above before make setup' >&2; \
	fi; \
	exit $$rc

# Run tests.  Match CI: a TTY / FORCE_COLOR / GITHUB_ACTIONS makes Rich/typer
# emit ANSI, which splits numbers and option names and breaks assertions on
# help/status text.  The pytest plugin ``pytest_ansi_env`` sets the same
# trio for bare ``uv run pytest``; export here too so the recipe stays
# self-documenting and covers any non-pytest child processes.
test: ensure-nasm ensure-node ensure-uv
	NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen pytest tests/ -v --tb=short

# Fast edit-test loop: one file or pytest node id.  Only warns about nasm and
# node: their tests skip without those binaries, so unrelated files still run.
test-one: warn-nasm warn-node ensure-uv
	NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen pytest $(T) $(FLAGS) -v --tb=short

# Coverage floor (AGENTS.md: ratchet up, never down).  slipcover ignores
# [tool.slipcover] fail_under, so the floor is passed on the command line.
coverage: ensure-nasm ensure-node ensure-uv
	NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen python -m slipcover --fail-under $(COV_FLOOR) -m pytest tests/ -q --tb=short

# Run linting.  The path is `.` (ruff's default, the same scope the
# pre-commit `ruff-check` hook resolves filenames against) rather than an
# explicit src/ tests/ tools/ list: a new top-level Python script would
# otherwise be invisible to the CI gate while the local hook still flagged it.
# Gitignored scratch trees are excluded in [tool.ruff] extend-exclude.
lint: ensure-uv
	uv run --frozen ruff check .

# Run formatting.  Same scope as `lint` (`.`), minus docs/: `ruff format .`
# also reformats the Python snippets inside docs/*.md, which the pre-commit
# ruff-format hook (types: [python]) never sees, so a docs snippet would be
# rewritten locally and only fail the gate here.  Excluding docs/ from the
# path, rather than listing src/ tests/ tools/, keeps the gate over every other
# Python file, so a new top-level script is formatted and checked by the same
# commands the local hook runs.
format: ensure-uv
	uv run --frozen ruff format . --exclude docs

# Verify formatting without mutating the source tree
format-check: ensure-uv
	uv run --frozen ruff format --check . --exclude docs

# Run pre-commit checks on all files.  Match CI workflow env so Rich/typer
# ANSI cannot split option names when GITHUB_ACTIONS/FORCE_COLOR is set.
check: warn-shellcheck warn-yamllint ensure-uv
	NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen pre-commit run --all-files

# High-value CLI --help contract (CI cli-contract job).  Same ANSI guards as
# make test so a local TTY / GITHUB_ACTIONS export cannot break the greps.
cli-contract: ensure-uv
	@set -eu; \
	help=$$(NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen rebrew round-trip --help); \
	printf '%s\n' "$$help" | grep -- '--strict-catalog' >/dev/null; \
	help=$$(NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen rebrew verify --help); \
	printf '%s\n' "$$help" | grep -- '--compare' >/dev/null; \
	help=$$(NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen rebrew prove --help); \
	printf '%s\n' "$$help" | grep 'NEAR_MATCHING' >/dev/null; \
	echo 'cli-contract OK'

# Clean build artifacts, distribution packages, and local tool/test caches.
# .sdist-check is the scratch tree sdist-check builds the comparison wheel in;
# a failed run leaves it behind, so clean it like .venv-pkg.
clean:
	rm -rf dist build rebrew.egg-info src/rebrew.egg-info .sdist-check .coverage htmlcov .coverage.* .pytest_cache .ruff_cache .mypy_cache .scratch/rebrew-idem .venv-pkg .hypothesis
	find src tests tools -type d -name __pycache__ -prune -exec rm -rf {} +

# Build sdist + wheel under a pinned umask/locale/timezone. umask 022 fixes
# modes of files the build creates; setuptools still copies checkout modes
# for package files, so normalize_sdist.py rewrites both archives afterwards.
# Drop prior package artifacts so a bumped version cannot leave multiple
# wheels/sdists in dist/ (CI's package job expects exactly one of each), and
# drop build/ + egg-info first: setuptools packs every file left in build/lib
# into the wheel, so residue from an aborted or bare `uv build` would ship.
# After the build, remove setuptools' in-tree egg-info / build/ residue and
# record a buildinfo manifest (project version, toolchain, SOURCE_DATE_EPOCH,
# the sha256 of build-constraints.txt and of uv.lock, the sha256 of both
# artifacts, the source commit and the dirty flag) next to the artifacts so a
# rebuild can be attempted with the same environment knobs.
# uv.lock is recorded because the rest of the shipped set is derived from it
# (`make sbom` inventories it, `make smoke-wheel` installs from it), and the
# two artifact hashes because the manifest travels beside the files it
# describes: without them nothing binds the provenance to those exact bytes.
# They are computed after normalize_sdist.py, which is what produces them.
# An uncommitted change warns rather than fails: the artifacts are still
# valid, but they do not correspond to source-commit, and `make build-repro`
# compares against HEAD, so the next gate would fail on this tree.
# The recipe below refuses to record a version dist/ does not actually carry:
# a stale build cache would otherwise ship rebrew-<old>-*.whl beside a
# manifest naming the new one, and every dist/ consumer finds files by name.
# Toolchain lines record versions, never host paths (the manifest ships).
# The build backend is hash-verified against build-constraints.txt, whose
# setuptools version must equal the pyproject.toml [build-system] pin.
# setuptools= is parsed from pyproject.toml [build-system] (never hardcoded —
# a stale pin next to requires = ["setuptools==…"] would lie in the manifest).
# Two `uv build` calls, not the default one: bare `uv build` builds the wheel
# *from the sdist it just made*, so the shipped wheel and `make sdist-check`'s
# wheel share an input and a MANIFEST.in prune that dropped a runtime file
# removed it from both, leaving that gate green on a wheel missing the file it
# exists to catch.  Building the wheel from the source tree is what makes the
# two member lists independent, and sdist-check can fail again.
# The manifest is written to a sibling temp file and moved into place.  It is
# the file target sdist-check / smoke-wheel / build-repro depend on, so a
# truncated one left behind by a failed run reads as "up to date" and those
# gates then verify the previous tree's artifacts.  The values that shell out
# (`uv --version`, the managed interpreter) are captured in assignments rather
# than inside an `echo` argument, where a failing command substitution only
# blanks the line and the manifest ships a hole.
build: warn-uv-version
	@mkdir -p dist
	@rm -f dist/*.whl dist/*.tar.gz dist/*.buildinfo dist/*.cdx.json
	@rm -rf build rebrew.egg-info src/rebrew.egg-info
	@set -eu; \
	st=$$(sed -n 's/^requires = \["setuptools==\([0-9.][0-9.]*\)"\]/\1/p' pyproject.toml | head -n 1); \
	if [ -z "$$st" ] || ! grep -q "^setuptools==$$st " build-constraints.txt; then \
	  echo "ERROR: pyproject.toml [build-system] setuptools pin '$$st' missing or not in build-constraints.txt"; \
	  exit 1; \
	fi
	umask 022 && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) TZ=UTC LC_ALL=C PYTHONHASHSEED=0 \
		uv build --sdist --out-dir dist --build-constraints build-constraints.txt --require-hashes
	umask 022 && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) TZ=UTC LC_ALL=C PYTHONHASHSEED=0 \
		uv build --wheel --out-dir dist --build-constraints build-constraints.txt --require-hashes
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(UV_RUN_TOOLS) python tools/normalize_sdist.py dist/*.tar.gz dist/*.whl
	@rm -rf build rebrew.egg-info src/rebrew.egg-info
	@set -eu; \
	st=$$(sed -n 's/^requires = \["setuptools==\([0-9.][0-9.]*\)"\]/\1/p' pyproject.toml | head -n 1); \
	ver=$$(sed -n 's/^__version__ = "\([^"]*\)".*/\1/p' src/rebrew/__init__.py | head -n 1); \
	[ -n "$$ver" ] || { echo "ERROR: no __version__ in src/rebrew/__init__.py"; exit 1; }; \
	set -- dist/rebrew-$$ver-*.whl; \
	[ -f "$$1" ] || { echo "ERROR: no dist/rebrew-$$ver-*.whl in dist/ (found: $$(ls -1 dist))"; exit 1; }; \
	[ -f "dist/rebrew-$$ver.tar.gz" ] || { echo "ERROR: no dist/rebrew-$$ver.tar.gz in dist/ (found: $$(ls -1 dist))"; exit 1; }; \
	if command -v sha256sum >/dev/null 2>&1; then \
	  sha() { sha256sum "$$1" | cut -d' ' -f1; }; \
	elif command -v shasum >/dev/null 2>&1; then \
	  sha() { shasum -a 256 "$$1" | cut -d' ' -f1; }; \
	else \
	  echo "ERROR: no sha256sum or shasum on PATH (cannot record the build provenance)"; exit 1; \
	fi; \
	bsum=$$(sha build-constraints.txt); \
	lksum=$$(sha uv.lock); \
	wheelsum=$$(sha "$$1"); \
	sdistsum=$$(sha "dist/rebrew-$$ver.tar.gz"); \
	dirty=$$(if git rev-parse --git-dir >/dev/null 2>&1; then \
	  if [ -n "$$(git status --porcelain)" ]; then echo yes; else echo no; fi; \
	  else echo n/a; fi); \
	if [ "$$dirty" = yes ]; then \
	  echo "WARNING: uncommitted changes; dist/ does not match source-commit=$$(git rev-parse HEAD) and 'make build-repro' rebuilds from HEAD." >&2; \
	fi; \
	tmpinfo=dist/.rebrew.buildinfo.tmp; \
	trap 'rm -f "$$tmpinfo"' EXIT; \
	uv_ver=$$(uv --version); \
	py_ver=$$("$$(uv python find $(PYTHON_PIN))" --version); \
	{ \
	  echo "name=rebrew"; \
	  echo "version=$$ver"; \
	  echo "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)"; \
	  echo "umask=022"; \
	  echo "TZ=UTC"; \
	  echo "LC_ALL=C"; \
	  echo "PYTHONHASHSEED=0"; \
	  echo "uv=$$uv_ver"; \
	  echo "python=$$py_ver"; \
	  echo "python-version=$(PYTHON_PIN)"; \
	  echo "setuptools=$$st"; \
	  echo "build-constraints-sha256=$$bsum"; \
	  echo "uv-lock-sha256=$$lksum"; \
	  echo "wheel-sha256=$$wheelsum"; \
	  echo "sdist-sha256=$$sdistsum"; \
	  echo "source-commit=$$(git rev-parse HEAD 2>/dev/null || echo n/a)"; \
	  echo "source-dirty=$$dirty"; \
	} > "$$tmpinfo"; \
	mv -f "$$tmpinfo" dist/rebrew.buildinfo

# Prove the wheel and the sdist are byte-reproducible from a second source
# tree: a `git archive HEAD` copy under .scratch/, extracted with umask 077
# (git stores only the executable bit, so every file mode differs) and built
# under a different timezone and locale.  Both the path and the environment
# knobs are what the archives must not encode.
#
# The copy comes from HEAD, so this describes the committed tree, not the
# working one: run it after committing, as CI does on the pushed commit.
# A dirty tree is refused before anything is extracted, because the two sides
# then describe different sources: dist/ carries the edits, the copy carries
# HEAD, and the hash diff reports a reproducibility failure that says nothing
# about the build. `make build` only warns about this; here it is the whole
# question, so it stops.
#
# A build failure or a hash mismatch exits non-zero and ends the recipe, so a
# trailing `rm -rf` never runs and the extracted copy would outlive it; the
# EXIT trap covers the failure, the mismatch, and the happy path alike.
#
# The archive is written to a file and extracted, not piped: `set -e` in a
# POSIX shell only sees the last command of a pipeline, so `git archive | tar`
# reports success when git dies halfway, tar extracts the partial tree, and
# the hash diff then blames the build for a repository problem.  The scratch
# archive is a sibling of the tree, never inside it, so the second build never
# sees a file the first checkout does not have.
#
# A mismatch names the differing members: two hashes say that the artifact
# drifted, not what in it, and the usual causes (a timestamp, an ordering, a
# path) are one diffoscope run from the cause.  diffoscope is optional and
# only consulted on the failure path, so the passing build keeps no new
# dependency.
#
# The CI package job runs this target; do not re-inline the recipe there.
build-repro: dist/rebrew.buildinfo
	@set -eu; \
	repro="$(BUILD_REPRO_DIR)"; \
	if git rev-parse --git-dir >/dev/null 2>&1 && [ -n "$$(git status --porcelain)" ]; then \
	  echo "ERROR: build-repro rebuilds HEAD, so an uncommitted tree cannot be compared." >&2; \
	  echo "dist/ would carry your edits and $(BUILD_REPRO_DIR) the commit: the hash diff" >&2; \
	  echo "then reports a reproducibility failure that says nothing about the build." >&2; \
	  echo "Commit first (CI runs this on the pushed commit), or stash and re-run." >&2; \
	  git status --porcelain >&2; \
	  exit 1; \
	fi; \
	trap 'rm -rf -- "$$repro"; rm -f -- "$$archive"' EXIT; \
	archive="$$repro.tar"; \
	umask 077; \
	rm -rf "$$repro"; \
	rm -f "$$archive"; \
	mkdir -p "$$repro"; \
	git archive --format=tar --output="$$archive" HEAD; \
	tar -x -C "$$repro" -f "$$archive"; \
	rm -f "$$archive"; \
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) TZ=Asia/Tokyo LC_ALL=C.UTF-8 \
		$(MAKE) -C "$$repro" build; \
	sha() { \
		if command -v sha256sum >/dev/null 2>&1; then \
			sha256sum "$$1" | cut -d' ' -f1; \
		else \
			shasum -a 256 "$$1" | cut -d' ' -f1; \
		fi; \
	}; \
	for ext in whl tar.gz; do \
		first=$$(sha dist/*.$$ext); \
		second=$$(sha "$$repro"/dist/*.$$ext); \
		if [ "$$first" != "$$second" ]; then \
			echo "ERROR: .$$ext is not reproducible (dist/=$$first $(BUILD_REPRO_DIR)/dist/=$$second)" >&2; \
			if command -v diffoscope >/dev/null 2>&1; then \
			  for f in dist/*.$$ext; do \
			    diffoscope "$$f" "$(BUILD_REPRO_DIR)/$$f" >&2 || true; \
			  done; \
			else \
			  echo "hint: install diffoscope to name the differing members" >&2; \
			fi; \
			exit 1; \
		fi; \
		echo ".$$ext reproducible: $$first"; \
	done

# Re-derive, from the files on disk, every fact `make build` recorded in
# dist/rebrew.buildinfo.  `build` writes the manifest and the artifacts in one
# recipe, so nothing has read the two back until now: a normalize_sdist.py
# rewrite, a stray `uv build`, or a half-finished run leaves a manifest that
# names bytes the shipped files no longer have, and a consumer that trusts it
# gets a provenance record for the wrong artifact.
#
# The CI package job ran a weaker version of this as inline YAML: it grepped
# that the keys exist and that SOURCE_DATE_EPOCH matches, which a hand-edited
# or truncated manifest passes.  That check also ran nowhere else, so no
# contributor could run it.  Here it lives next to the other gates, compares
# the recorded digests against freshly computed ones, and `pr-check` runs it.
#
# Read-only: it hashes what is in dist/ and the two input files, and writes
# nothing.
verify-dist: dist/rebrew.buildinfo ensure-uv
	@set -eu; \
	for f in dist/*.whl; do set -- "$$@" "$$f"; done; \
	[ $$# -eq 1 ] && [ -f "$$1" ] || { echo "ERROR: expected exactly one wheel in dist/ (run 'make build')"; exit 1; }; \
	wheel=$$1; \
	set --; \
	for f in dist/*.tar.gz; do set -- "$$@" "$$f"; done; \
	[ $$# -eq 1 ] && [ -f "$$1" ] || { echo "ERROR: expected exactly one sdist in dist/ (run 'make build')"; exit 1; }; \
	sdist=$$1; \
	[ -f dist/rebrew.buildinfo ] || { echo "ERROR: dist/rebrew.buildinfo missing (run 'make build')"; exit 1; }; \
	if command -v sha256sum >/dev/null 2>&1; then \
	  sha() { sha256sum "$$1" | cut -d' ' -f1; }; \
	elif command -v shasum >/dev/null 2>&1; then \
	  sha() { shasum -a 256 "$$1" | cut -d' ' -f1; }; \
	else \
	  echo "ERROR: no sha256sum or shasum on PATH (cannot check the build provenance)"; exit 1; \
	fi; \
	recorded() { \
	  v=$$(sed -n "s/^$$1=//p" dist/rebrew.buildinfo | head -n 1); \
	  [ -n "$$v" ] || { echo "ERROR: dist/rebrew.buildinfo has no $$1 line"; exit 1; }; \
	  printf '%s' "$$v"; \
	}; \
	check() { \
	  [ "$$2" = "$$3" ] || { echo "ERROR: $$1: buildinfo records $$2, the file on disk is $$3" >&2; exit 1; }; \
	}; \
	check wheel-sha256 "$$(recorded wheel-sha256)" "$$(sha "$$wheel")"; \
	check sdist-sha256 "$$(recorded sdist-sha256)" "$$(sha "$$sdist")"; \
	check build-constraints-sha256 "$$(recorded build-constraints-sha256)" "$$(sha build-constraints.txt)"; \
	check uv-lock-sha256 "$$(recorded uv-lock-sha256)" "$$(sha uv.lock)"; \
	check SOURCE_DATE_EPOCH "$$(recorded SOURCE_DATE_EPOCH)" "$(SOURCE_DATE_EPOCH)"; \
	recorded setuptools >/dev/null; \
	echo "dist provenance OK: $${wheel##*/} and $${sdist##*/} match dist/rebrew.buildinfo"

# CycloneDX 1.5 SBOM from the committed lock (no network).  Writes
# dist/rebrew.cdx.json so package CI / release consumers share one inventory.
# generate_sbom.py is stdlib-only: --no-project skips the project sync (and
# its ../resembl path dep), --offline keeps the no-network promise.
sbom: warn-uv-version
	@mkdir -p dist
	$(UV_RUN_TOOLS) python tools/generate_sbom.py -o dist/rebrew.cdx.json

# Prove the sdist carries every runtime file the wheel ships.  The wheel is
# smoke-installed; nothing else exercises the sdist, and its file list comes
# from MANIFEST.in plus the post-build rewrite in normalize_sdist.py rather
# than from package-data.  Build a wheel *from* the sdist through the same
# hash-pinned build constraints `make build` uses, then diff the two member
# lists.  The intermediate wheel lands in .sdist-check/.
#
# The prerequisite is the buildinfo *file*, not the phony `build` target:
# `build` opens by deleting dist/*.whl, dist/*.tar.gz, dist/*.buildinfo and
# dist/*.cdx.json, so a `make sdist-check` of its own (the CI package job runs
# it as a separate invocation, and so does anyone following the help text)
# would wipe the SBOM and buildinfo `make build` / `make sbom` had just
# produced.  The file rule below builds only when dist/ is empty or a build
# input (file or directory) is newer, and it carries the ordering under
# `make -j`, where a bare prerequisite list would not.
dist/rebrew.buildinfo: $(BUILD_INPUTS) $(BUILD_INPUT_DIRS)
	@$(MAKE) --no-print-directory build

# ensure-uv first: it is the cheap check, and the buildinfo rule below can
# trigger a full rebuild, so a missing uv should be named before that runs.
# (The buildinfo rule reaches ensure-uv through `build` only when it actually
# rebuilds; on an up-to-date dist/ the recipe below was the only uv caller.)
sdist-check: ensure-uv dist/rebrew.buildinfo
	@set -eu; \
	for f in dist/*.tar.gz; do set -- "$$@" "$$f"; done; \
	[ $$# -eq 1 ] && [ -f "$$1" ] || { echo "ERROR: expected exactly one sdist in dist/ (run 'make build')"; exit 1; }; \
	sdist=$$1; \
	set --; \
	for f in dist/*.whl; do set -- "$$@" "$$f"; done; \
	[ $$# -eq 1 ] && [ -f "$$1" ] || { echo "ERROR: expected exactly one wheel in dist/ (run 'make build')"; exit 1; }; \
	wheel=$$1; \
	rm -rf .sdist-check; mkdir .sdist-check; \
	umask 022 && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) TZ=UTC LC_ALL=C PYTHONHASHSEED=0 \
	  uv build --wheel --out-dir .sdist-check --build-constraints build-constraints.txt \
	  --require-hashes "$$sdist"; \
	$(UV_RUN_TOOLS) python tools/check_sdist_wheel.py "$$wheel" .sdist-check/*.whl; \
	rm -rf .sdist-check

# Install the built wheel into a throwaway venv and smoke-import it (CI
# package job).  This is the only gate that proves the artifact a user
# installs is complete: `import rebrew` and the console script read nothing
# that package-data drops, so a wheel missing agent-skills/ or py.typed runs
# fine here and fails on the user's first `rebrew skills list`.
# Runtime deps come from the lock with --no-default-groups
# --no-install-project (no ../resembl needed); the wheel is then overlaid with
# --no-deps so a live PyPI resolve cannot drift past the audited lock.
# --frozen here, not the --locked the other installs use: re-resolving to prove
# the lock is current reads [tool.uv.sources] and needs the sibling checkout,
# and the point of this target is that it runs without one.
# The CI package job runs this target; do not re-inline the recipe here.
# `make clean` removes .venv-pkg.
smoke-wheel: dist/rebrew.buildinfo ensure-uv
	@set -eu; \
	for f in dist/*.whl; do set -- "$$@" "$$f"; done; \
	[ $$# -eq 1 ] && [ -f "$$1" ] || { echo "ERROR: expected exactly one wheel in dist/ (run 'make build')"; exit 1; }; \
	wheel=$$1; \
	rm -rf .venv-pkg; \
	uv venv .venv-pkg; \
	UV_PROJECT_ENVIRONMENT=.venv-pkg uv sync --frozen --no-dev --no-default-groups --no-install-project; \
	uv pip install --python .venv-pkg --no-deps "$$wheel"; \
	.venv-pkg/bin/python tools/smoke_wheel_install.py; \
	.venv-pkg/bin/rebrew --help >/dev/null

# Run all non-mutating verification gates (mirrors CI lint + test +
# cli-contract jobs: ruff, mypy, uv audit, pytest under the COV_FLOOR gate
# (CI's 3.13 test entry runs `make coverage`, not `make test`), fixture
# freshness, idempotency sweep, CLI help greps, plus the import-cycle hook
# that the CI pre-commit job also runs).  For full hook parity (hygiene +
# skills validate) also run `make check` before a PR.
all: format-check lint mypy audit coverage gen-fixtures-check cycles-check idempotency-check cli-contract

# Full local verification: single runnable step mirroring every CI gate
# (all non-mutating gates + pre-commit hook parity + reproducible build +
# wheel smoke install + SBOM).  ``sbom`` runs last on purpose: ``make build``
# clears dist/*.cdx.json, and ``sdist-check`` depends on ``build``, so an
# earlier sbom leaves dist/ with no BOM for the same reason CI had to move its
# step.  ``smoke-wheel`` runs after ``sdist-check`` so it installs the same
# wheel the sdist comparison already accepted, and ``verify-dist`` runs after
# both because it reads the bytes those two leave in dist/ and the manifest
# ``build`` recorded for them.
pr-check: all check build sdist-check smoke-wheel build-repro verify-dist sbom

# Regenerate checked-in binary fixtures (run after editing tools/gen_fixtures.py).
gen-fixtures: ensure-uv
	uv run --frozen python tools/gen_fixtures.py

# Fixture freshness: checked-in fixtures match the generator (CI test job).
gen-fixtures-check: ensure-uv
	uv run --frozen python tools/gen_fixtures.py --check

# Regenerate rendered agent skills from src/rebrew/agent-skills/ (target bench).
# tools/render_skills.py owns the render so the substitution is deterministic
# and its failure names a file; a `cp -r` + `sed -i` pipeline depended on GNU
# sed, on find's traversal order, and on nothing failing in between.
gen-skills: ensure-uv
	uv run --frozen python tools/render_skills.py

# Verify rendered agent skills match packaged source (same as tests/test_skills_sync.py).
gen-skills-check: ensure-uv
	uv run --frozen python tools/render_skills.py --check
	NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen pytest tests/test_skills_sync.py -v --tb=short

# Module-level import cycles (pre-commit import-cycles hook / CI pre-commit job).
cycles-check: ensure-uv
	uv run --frozen python tools/detect_cycles.py

# Idempotency sweep: every --json command, run twice (CI test job).
idempotency-check: ensure-uv
	uv run --frozen python tools/check_idempotency.py --fixture-dir .scratch/rebrew-idem

# Type check (CI lint job).
mypy: ensure-extras ensure-uv
	uv run --frozen mypy

# Dependency advisory gate (CI lint job).
# ensure-resembl, not just ensure-uv: `uv audit` resolves the project
# workspace, and uv.lock carries resembl as a `../resembl` path
# dependency, so a checkout without the sibling dies inside uv with a raw
# "Distribution not found at: file:///.../resembl" naming neither the cause
# nor the fix.  `uv audit` has no --no-project escape (unlike the sbom
# recipe), so the sibling is a hard requirement of this gate; the preflight
# turns that into the named message and clone line.  CI always has the
# checkout (the uv-env action clones it), so only local runs hit this.
audit: ensure-resembl ensure-uv
	uv audit --locked --ignore-until-fixed GHSA-w8v5-vhqr-4h9v

# Release preflight: verify the version/changelog/tag contract from
# CONTRIBUTING.md without mutating anything.  Passes only when a release is
# actually being prepared: __version__ bumped past the last tag, a dated
# [<version>] section that has at least one entry, an empty [Unreleased] block
# (notes split across the two headings ship half undocumented), and a clean
# tree to tag.
# Manual gate by design (CONTRIBUTING.md): wiring it into CI would fail every
# push except the release commit, since __version__ stays equal to the last
# tag during normal development. Run `make release-check` before tagging.
#
# The checks live in tools/release_check.py: the version comes out of the
# package and the changelog sections are parsed, which a POSIX-sh recipe could
# only reach with an inline interpreter call and a chain of awk/grep.  One
# language per command, and a failure names a file and a line.
release-check: ensure-uv
	uv run --frozen python tools/release_check.py
