.PHONY: setup test lint format format-check check build all

# Prefer lockfile-pinned deps. Override with `make setup UV_SYNC_FLAGS=` if needed.
UV_SYNC_FLAGS ?= --frozen --all-extras

# Reproducible package builds: honor SOURCE_DATE_EPOCH when set; otherwise use
# the committer timestamp (or 0 for a non-git tree). Wheel builds with this set
# are byte-identical across runs; sdist tar directory mtimes still vary under
# setuptools (known limitation: ship/compare wheels).
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

# Setup the development environment
setup:
	uv sync $(UV_SYNC_FLAGS)
	uv run pre-commit install

# Run tests
test:
	uv run pytest tests/ -v

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
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) TZ=UTC LC_ALL=C uv build

# Run all non-mutating verification gates
all: format-check lint test
