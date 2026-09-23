.PHONY: help setup test test-one lint format format-check check build sbom all \
	gen-fixtures gen-fixtures-check cycles-check idempotency-check mypy audit \
	cli-contract release-check ensure-uv ensure-resembl ensure-nasm warn-nasm

# Force POSIX sh for recipes (ignore a caller-exported SHELL=bash).  Recipes
# below use only POSIX constructs so Alpine/busybox ash and Debian dash work.
# Version compares use ``sort -t. -k…n`` (POSIX), not GNU ``sort -V``.
SHELL := /bin/sh

.DEFAULT_GOAL := help

# Prefer lockfile-pinned deps. Override with `make setup UV_SYNC_FLAGS=` if needed.
# --group similarity pulls the sibling resembl path dep (not a PyPI extra);
# --group m2c is opt-in (git-only decompiler) — add it when exercising fetch_m2c.
UV_SYNC_FLAGS ?= --frozen --all-extras --group similarity

# Keep in step with the `resembl-ref` / `uv-version` input defaults in
# .github/actions/uv-env/action.yml (CI's single pin site) and the resembl
# version recorded in uv.lock (path dep).  `make setup` prints the clone
# command when ../resembl is missing; it does not clone for you.
RESEMBL_REF ?= v2.0.0
RESEMBL_DIR := $(abspath $(CURDIR)/../resembl)
# Match the CI uv pin so local sync/audit behavior tracks CI.
UV_VERSION ?= 0.12.14

# Single-file / nodeid override for the edit-test loop:
#   make test-one T=tests/test_annotation.py
#   make test-one T=tests/test_annotation.py::TestAnnotationDataclass
T ?= tests/

# Reproducible package builds: honor SOURCE_DATE_EPOCH when set; otherwise use
# the committer timestamp (or 0 for a non-git tree). Wheel builds with this set
# are byte-identical across runs; `make build` then rewrites the sdist with
# tools/normalize_sdist.py (sorted entries, fixed mtimes, 0:0 owner, fixed
# modes) so it is byte-identical across checkouts too.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

# List contributor-facing targets (default goal).
help:
	@printf '%s\n' \
		'Contributor targets:' \
		'  make setup              # uv sync (frozen + extras + similarity) + pre-commit/pre-push hooks' \
		'  make test               # full pytest suite (needs nasm on PATH)' \
		'  make test-one T=<node>  # one file/nodeid, e.g. T=tests/test_foo.py::TestBar (nasm optional)' \
		'  make lint               # ruff check src/ tests/ tools/' \
		'  make format             # ruff format (writes)' \
		'  make format-check       # ruff format --check' \
		'  make mypy               # mypy (matches CI lint job)' \
		'  make audit              # uv audit --locked (matches CI lint job)' \
		'  make check              # pre-commit run --all-files (CI pre-commit job)' \
		'  make cli-contract       # high-value --help greps (CI cli-contract job)' \
		'  make build              # reproducible sdist+wheel + dist/rebrew.buildinfo' \
		'  make sbom               # CycloneDX 1.5 JSON from uv.lock (offline)' \
		'  make all                # local mirror of CI lint+test+cli-contract gates' \
		'  make gen-fixtures       # regenerate tests/fixtures/ from tools/gen_fixtures.py' \
		'  make gen-fixtures-check # tools/gen_fixtures.py --check' \
		'  make cycles-check       # tools/detect_cycles.py (also in pre-commit / make check)' \
		'  make idempotency-check  # tools/check_idempotency.py' \
		'  make release-check      # version/changelog/tag preflight before tagging' \
		'' \
		'Bootstrap (clean clone):' \
		'  1. Install uv $(UV_VERSION)+ (CI pin), Python 3.13+ (.python-version), nasm on PATH' \
		'  2. Clone sibling resembl at $(RESEMBL_REF) into ../resembl' \
		'     git clone --depth 1 --branch $(RESEMBL_REF) https://github.com/maci0/resembl.git ../resembl' \
		'  3. make setup && make test-one T=tests/test_annotation.py' \
		'  Before a PR: make all && make check && make build'

ensure-uv:
	@set -eu; \
	if ! command -v uv >/dev/null 2>&1; then \
	  echo "ERROR: uv not on PATH (required for setup/test/lint; CI pins UV_VERSION=$(UV_VERSION))."; \
	  echo "Install from https://docs.astral.sh/uv/ then re-run make setup."; \
	  exit 1; \
	fi; \
	uv_out=$$(uv --version); \
	uv_ver=$$(printf '%s\n' "$$uv_out" | awk '{print $$2}'); \
	lowest=$$(printf '%s\n%s\n' "$$uv_ver" "$(UV_VERSION)" | sort -t. -k1,1n -k2,2n -k3,3n | head -1); \
	if [ "$$lowest" != "$(UV_VERSION)" ]; then \
	  echo "WARNING: uv $$uv_ver is older than CI pin UV_VERSION=$(UV_VERSION)."; \
	  echo "Sync usually still works; upgrade when you can (https://docs.astral.sh/uv/)."; \
	  echo "To silence this check: make setup UV_VERSION=$$uv_ver"; \
	fi

ensure-resembl: ensure-uv
	@set -eu; \
	if [ ! -e "$(RESEMBL_DIR)/pyproject.toml" ]; then \
	  echo "ERROR: sibling resembl checkout missing at $(RESEMBL_DIR)"; \
	  echo "uv sync needs it even when you are not using the similarity group"; \
	  echo "(pyproject.toml [tool.uv.sources] pins path = \"../resembl\")."; \
	  echo "Clone the pin matching CI / uv.lock, then re-run make setup:"; \
	  echo "  git clone --depth 1 --branch $(RESEMBL_REF) https://github.com/maci0/resembl.git $(RESEMBL_DIR)"; \
	  exit 1; \
	fi; \
	resembl_ver=$$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$(RESEMBL_DIR)/pyproject.toml" | head -1); \
	want="$(RESEMBL_REF)"; want=$${want#v}; \
	if [ -z "$$resembl_ver" ] || [ "$$resembl_ver" != "$$want" ]; then \
	  echo "ERROR: $(RESEMBL_DIR) version '$$resembl_ver' does not match RESEMBL_REF=$(RESEMBL_REF)"; \
	  echo "Re-clone the pin, then re-run make setup:"; \
	  echo "  git clone --depth 1 --branch $(RESEMBL_REF) https://github.com/maci0/resembl.git $(RESEMBL_DIR)"; \
	  exit 1; \
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

# Setup the development environment
setup: ensure-resembl warn-nasm
	uv sync $(UV_SYNC_FLAGS)
	uv run --frozen pre-commit install

# Run tests.  Match CI: a TTY / FORCE_COLOR / GITHUB_ACTIONS makes Rich/typer
# emit ANSI, which splits numbers and option names and breaks assertions on
# help/status text.  The pytest plugin ``pytest_ansi_env`` sets the same
# trio for bare ``uv run pytest``; export here too so the recipe stays
# self-documenting and covers any non-pytest child processes.
test: ensure-nasm
	NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen pytest tests/ -v --tb=short

# Fast edit-test loop: one file or pytest node id.  Only warns about nasm:
# the nasm round-trip tests skip without it, so unrelated files still run.
test-one: warn-nasm
	NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen pytest $(T) -v --tb=short

# Run linting
lint:
	uv run --frozen ruff check src/ tests/ tools/

# Run formatting
format:
	uv run --frozen ruff format src/ tests/ tools/

# Verify formatting without mutating the source tree
format-check:
	uv run --frozen ruff format --check src/ tests/ tools/

# Run pre-commit checks on all files.  Match CI workflow env so Rich/typer
# ANSI cannot split option names when GITHUB_ACTIONS/FORCE_COLOR is set.
check:
	NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
		uv run --frozen pre-commit run --all-files

# High-value CLI --help contract (CI cli-contract job).  Same ANSI guards as
# make test so a local TTY / GITHUB_ACTIONS export cannot break the greps.
cli-contract:
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

# Build sdist + wheel under a pinned umask/locale/timezone for deterministic
# wheels (setuptools copies the umask-filtered file modes into wheel entries).
# Drop prior package artifacts so a bumped version cannot leave multiple
# wheels/sdists in dist/ (CI's package job expects exactly one of each).
# After the build, remove setuptools' in-tree egg-info / build/ residue and
# record a buildinfo manifest (toolchain + SOURCE_DATE_EPOCH) next to the
# artifacts so a rebuild can be attempted with the same environment knobs.
# Toolchain lines record versions, never host paths (the manifest ships).
# setuptools= is parsed from pyproject.toml [build-system] (never hardcoded —
# a stale pin next to requires = ["setuptools==…"] would lie in the manifest).
build: ensure-uv
	@mkdir -p dist
	@rm -f dist/*.whl dist/*.tar.gz dist/*.buildinfo
	umask 022 && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) TZ=UTC LC_ALL=C PYTHONHASHSEED=0 uv build
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) uv run --frozen --no-project python tools/normalize_sdist.py dist/*.tar.gz
	@rm -rf build rebrew.egg-info
	@set -eu; \
	st=$$(sed -n 's/^requires = \["setuptools==\([0-9.][0-9.]*\)"\]/\1/p' pyproject.toml | head -1); \
	if [ -z "$$st" ]; then \
	  echo "ERROR: could not parse setuptools pin from pyproject.toml [build-system]"; \
	  exit 1; \
	fi; \
	{ \
	  echo "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)"; \
	  echo "umask=022"; \
	  echo "TZ=UTC"; \
	  echo "LC_ALL=C"; \
	  echo "PYTHONHASHSEED=0"; \
	  echo "uv=$$(uv --version)"; \
	  echo "python=$$("$$(uv python find)" --version)"; \
	  echo "python-version=$$(cat .python-version)"; \
	  echo "setuptools=$$st"; \
	} > dist/rebrew.buildinfo

# CycloneDX 1.5 SBOM from the committed lock (no network).  Writes
# dist/rebrew.cdx.json so package CI / release consumers share one inventory.
# generate_sbom.py is stdlib-only: --no-project skips the project sync (and
# its ../resembl path dep), --offline keeps the no-network promise.
sbom:
	@mkdir -p dist
	uv run --frozen --no-project --offline python tools/generate_sbom.py -o dist/rebrew.cdx.json

# Run all non-mutating verification gates (mirrors CI lint + test +
# cli-contract jobs: ruff, mypy, uv audit, pytest, fixture freshness,
# idempotency sweep, CLI help greps, plus the import-cycle hook that the CI
# pre-commit job also runs).  For full hook parity (hygiene + skills validate)
# also run `make check` before a PR.
all: format-check lint mypy audit test gen-fixtures-check cycles-check idempotency-check cli-contract

# Regenerate checked-in binary fixtures (run after editing tools/gen_fixtures.py).
gen-fixtures:
	uv run --frozen python tools/gen_fixtures.py

# Fixture freshness: checked-in fixtures match the generator (CI test job).
gen-fixtures-check:
	uv run --frozen python tools/gen_fixtures.py --check

# Module-level import cycles (pre-commit import-cycles hook / CI pre-commit job).
cycles-check:
	uv run --frozen python tools/detect_cycles.py

# Idempotency sweep: every --json command, run twice (CI test job).
idempotency-check:
	uv run --frozen python tools/check_idempotency.py --fixture-dir .scratch/rebrew-idem

# Type check (CI lint job).
mypy:
	uv run --frozen mypy

# Dependency advisory gate (CI lint job).
audit:
	uv audit --locked --ignore-until-fixed GHSA-w8v5-vhqr-4h9v

# Release preflight (release-review): verify the version/changelog/tag contract
# from CONTRIBUTING.md without mutating anything.  Passes only when a release
# is actually being prepared: __version__ bumped past the last tag, a matching
# [Unreleased]-style section present, and a clean tree to tag.
# Manual gate by design (CONTRIBUTING.md): wiring it into CI would fail every
# push except the release commit, since __version__ stays equal to the last
# tag during normal development. Run `make release-check` before tagging.
release-check:
	@set -eu; \
	V=$$(uv run --frozen python -c "from rebrew import __version__; print(__version__)"); \
	LAST=$$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0); \
	LASTV=$${LAST#v}; \
	HIGH=$$(printf '%s\n%s\n' "$$LASTV" "$$V" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1); \
	if [ "$$V" = "$$LASTV" ] || [ "$$HIGH" != "$$V" ]; then \
	  echo "ERROR: __version__ ($$V) not bumped past last tag ($$LAST)"; exit 1; \
	fi; \
	if [ -n "$$(git status --porcelain)" ]; then \
	  echo "ERROR: working tree not clean (commit first)"; exit 1; \
	fi; \
	if ! grep -Eq "^## \[$$V\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$$" CHANGELOG.md; then \
	  echo "ERROR: CHANGELOG.md has no dated [$$V] - YYYY-MM-DD section (date the [Unreleased] block)"; exit 1; \
	fi; \
	echo "release preflight OK: version $$V (last tag $$LAST)"
