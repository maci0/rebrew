"""ANSI-safe env for the pytest suite (matches ``make test`` / CI).

Loaded via ``[tool.pytest.ini_options] addopts = -p pytest_ansi_env`` so a
bare ``uv run --frozen pytest`` (documented in AGENTS.md) cannot fail when
``FORCE_COLOR`` / ``GITHUB_ACTIONS`` make typer/Rich split option names and
version digits across escape sequences.  Not a fixture conftest — env only.

The same plugin turns on pytest-xdist for a full-suite invocation.  ``make
coverage`` stays one process: ``python -m slipcover`` sets
``SLIPCOVER_ENABLED``, and the slipcover pytest plugin is not that signal
(it is loaded on every run).
"""

from __future__ import annotations

import os
from typing import Any

# Applied at plugin import — before CliRunner tests invoke typer/Rich.
os.environ["NO_COLOR"] = "1"
os.environ["TERM"] = "dumb"
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"

_SERIAL_FLAGS = frozenset({"--collect-only", "--pdb", "--trace"})


def pytest_configure() -> None:
    """Re-assert guards if an earlier plugin cleared them."""
    os.environ["NO_COLOR"] = "1"
    os.environ["TERM"] = "dumb"
    os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"


def _explicit_workers(args: list[str]) -> bool:
    """True when the caller already chose a worker count or turned xdist off."""
    for index, arg in enumerate(args):
        if arg in {"-n", "--numprocesses"} or arg.startswith("--numprocesses="):
            return True
        if arg.startswith("-n") and not arg.startswith("--"):
            rest = arg[2:]
            if rest in {"auto", "logical"} or rest.isdigit():
                return True
        plugin = ""
        if arg == "-p" and index + 1 < len(args):
            plugin = args[index + 1]
        elif arg.startswith("-p") and not arg.startswith("--"):
            plugin = arg[2:]
        if plugin in {"no:xdist", "noxdist"}:
            return True
    return False


def _full_suite(early_config: Any) -> bool:
    """True for a bare pytest or an invocation whose only path is ``tests``."""
    paths = list(getattr(early_config.known_args_namespace, "file_or_dir", None) or [])
    for raw in paths:
        norm = str(raw).replace("\\", "/").rstrip("/")
        if norm.startswith("./"):
            norm = norm[2:]
        if norm != "tests":
            return False
    return True


def pytest_load_initial_conftests(early_config: Any, parser: Any, args: list[str]) -> None:
    """Inject ``-n auto`` for the full suite once xdist has registered ``-n``.

    Subsets (a file, a node id, any path other than ``tests``), collection,
    debugging, ``SLIPCOVER_ENABLED``, and an explicit ``-n`` stay one process.
    Workers re-enter this hook; ``PYTEST_XDIST_WORKER`` stops the injection.
    """
    del parser
    if os.environ.get("PYTEST_XDIST_WORKER") or os.environ.get("SLIPCOVER_ENABLED"):
        return
    if _explicit_workers(args):
        return
    if any(flag in args for flag in _SERIAL_FLAGS):
        return
    if not _full_suite(early_config):
        return
    if not early_config.pluginmanager.has_plugin("xdist"):
        return
    args[:0] = ["-n", "auto"]
