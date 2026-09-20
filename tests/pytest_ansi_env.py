"""ANSI-safe env for the pytest suite (matches ``make test`` / CI).

Loaded via ``[tool.pytest.ini_options] addopts = -p pytest_ansi_env`` so a
bare ``uv run --frozen pytest`` (documented in AGENTS.md) cannot fail when
``FORCE_COLOR`` / ``GITHUB_ACTIONS`` make typer/Rich split option names and
version digits across escape sequences.  Not a fixture conftest — env only.
"""

from __future__ import annotations

import os

# Applied at plugin import — before CliRunner tests invoke typer/Rich.
os.environ["NO_COLOR"] = "1"
os.environ["TERM"] = "dumb"
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"


def pytest_configure() -> None:
    """Re-assert guards if an earlier plugin cleared them."""
    os.environ["NO_COLOR"] = "1"
    os.environ["TERM"] = "dumb"
    os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"
