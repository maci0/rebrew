.PHONY: help setup test test-one lint format format-check check build sbom all \
	gen-fixtures-check idempotency-check mypy audit release-check ensure-resembl ensure-nasm

.DEFAULT_GOAL := help

# Prefer lockfile-pinned deps. Override with `make setup UV_SYNC_FLAGS=` if needed.
# --group similarity pulls the sibling resembl path dep (not a PyPI extra);
# --group m2c is opt-in (git-only decompiler) — add it when exercising fetch_m2c.
UV_SYNC_FLAGS ?= --frozen --all-extras --group similarity

# Keep in step with RESEMBL_REF in .github/workflows/ci.yml and the resembl
# version recorded in uv.lock (path dep).  `make setup` clones this tag when
# ../resembl is missing only if you run the printed command yourself.
RESEMBL_REF ?= v2.0.0
RESEMBL_DIR := $(abspath $(CURDIR)/../resembl)

# Single-file / nodeid override for the edit-test loop:
#   make test-one T=tests/test_annotation.py
#   make test-one T=tests/test_annotation.py::TestAnnotationDataclass
T ?= tests/

# Reproducible package builds: honor SOURCE_DATE_EPOCH when set; otherwise use
# the committer timestamp (or 0 for a non-git tree). Wheel builds with this set
# are byte-identical across runs; sdist tar directory mtimes still vary under
# setuptools (known limitation: ship/compare wheels).
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

# List contributor-facing targets (default goal).
help:
	@printf '%s\n' \
		'Contributor targets:' \
		'  make setup              # uv sync (frozen + extras + similarity) + pre-commit install' \
		'  make test               # full pytest suite (needs nasm on PATH)' \
		'  make test-one T=<node>  # one file/nodeid, e.g. T=tests/test_foo.py::TestBar' \
		'  make lint               # ruff check src/ tests/ tools/' \
		'  make format             # ruff format (writes)' \
		'  make format-check       # ruff format --check' \
		'  make mypy               # mypy (matches CI lint job)' \
		'  make audit              # uv audit --locked (matches CI lint job)' \
		'  make check              # pre-commit run --all-files' \
		'  make build              # reproducible sdist+wheel' \
		'  make sbom               # CycloneDX 1.5 JSON from uv.lock (offline)' \
		'  make all                # local mirror of CI lint+test gates' \
		'  make gen-fixtures-check # tools/gen_fixtures.py --check' \
		'  make idempotency-check  # tools/check_idempotency.py' \
		'  make release-check      # version/changelog/tag preflight before tagging' \
		'' \
		'Bootstrap (clean clone):' \
		'  1. Install uv + Python 3.13+ (see .python-version) and nasm on PATH' \
		'  2. Clone sibling resembl at $(RESEMBL_REF) into ../resembl' \
		'     git clone --depth 1 --branch $(RESEMBL_REF) https://github.com/maci0/resembl.git ../resembl' \
		'  3. make setup && make test-one T=tests/test_annotation.py'

ensure-resembl:
	@if [ ! -e "$(RESEMBL_DIR)/pyproject.toml" ]; then \
	  echo "ERROR: sibling resembl checkout missing at $(RESEMBL_DIR)"; \
	  echo "uv sync needs it even when you are not using the similarity group"; \
	  echo "(pyproject.toml [tool.uv.sources] pins path = \"../resembl\")."; \
	  echo "Clone the pin matching CI / uv.lock, then re-run make setup:"; \
	  echo "  git clone --depth 1 --branch $(RESEMBL_REF) https://github.com/maci0/resembl.git $(RESEMBL_DIR)"; \
	  exit 1; \
	fi

ensure-nasm:
	@if ! command -v nasm >/dev/null 2>&1; then \
	  echo "ERROR: nasm not on PATH (required for asm round-trip tests, same as CI)."; \
	  echo "Install it, then re-run: e.g. apt install nasm / pacman -S nasm / brew install nasm"; \
	  exit 1; \
	fi

# Setup the development environment
setup: ensure-resembl
	uv sync $(UV_SYNC_FLAGS)
	uv run pre-commit install

# Run tests
test: ensure-nasm
	uv run pytest tests/ -v

# Fast edit-test loop: one file or pytest node id
test-one: ensure-nasm
	uv run pytest $(T) -v --tb=short

# Run linting
lint:
	uv run ruff check src/ tests/ tools/

# Run formatting
format:
	uv run ruff format src/ tests/ tools/

# Verify formatting without mutating the source tree
format-check:
	uv run ruff format --check src/ tests/ tools/

# Run pre-commit checks on all files
check:
	uv run pre-commit run --all-files

# Build sdist + wheel under a pinned locale/timezone for deterministic wheels
build:
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) TZ=UTC LC_ALL=C PYTHONHASHSEED=0 uv build

# CycloneDX 1.5 SBOM from the committed lock (no network).  Writes
# dist/rebrew.cdx.json so package CI / release consumers share one inventory.
sbom:
	@mkdir -p dist
	uv run python tools/generate_sbom.py -o dist/rebrew.cdx.json

# Run all non-mutating verification gates (mirrors CI lint + test jobs:
# ruff, mypy, uv audit, pytest, fixture freshness, idempotency sweep).
all: format-check lint mypy audit test gen-fixtures-check idempotency-check

# Fixture freshness: checked-in fixtures match the generator (CI test job).
gen-fixtures-check:
	uv run python tools/gen_fixtures.py --check

# Idempotency sweep: every --json command, run twice (CI test job).
idempotency-check:
	uv run python tools/check_idempotency.py --fixture-dir .scratch/rebrew-idem

# Type check (CI lint job runs plain `uv run mypy`).
mypy:
	uv run mypy

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
	@set -euo pipefail; \
	V=$$(uv run python -c "from rebrew import __version__; print(__version__)"); \
	LAST=$$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0); \
	LASTV=$${LAST#v}; \
	if [ "$$V" = "$$LASTV" ]; then \
	  echo "ERROR: __version__ ($$V) not bumped from last tag ($$LAST)"; exit 1; \
	fi; \
	if [ -n "$$(git status --porcelain)" ]; then \
	  echo "ERROR: working tree not clean (commit first)"; exit 1; \
	fi; \
	if ! grep -q "^## \[$$V\]" CHANGELOG.md; then \
	  echo "ERROR: CHANGELOG.md has no [$$V] section (date the [Unreleased] block)"; exit 1; \
	fi; \
	echo "release preflight OK: version $$V (last tag $$LAST)"
