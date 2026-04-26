.PHONY: setup test lint format check all

# Setup the development environment
setup:
	uv sync --all-extras
	uv run pre-commit install

# Run tests
test:
	uv run pytest tests/ -v

# Run linting
lint:
	uv run ruff check src/ tests/

# Run formatting
format:
	uv run ruff format src/ tests/

# Run pre-commit checks on all files
check:
	uv run pre-commit run --all-files

# Run formatting, linting, and tests
all: format lint test
