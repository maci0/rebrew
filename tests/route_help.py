"""``rebrew <route> --help`` for every route of the composed CLI, rendered once per session.

``tests/test_cli_contract.py`` asserts on these pages and
``tests/test_skill_commands_validate.py`` reads them instead of rendering every
route a second time. The render is the call ``tools/validate_skill_commands.py``
makes in ``_run_help``: click's ``CliRunner`` on ``typer.main.get_command(app)``
with ``COLUMNS=200``.
"""

from __future__ import annotations

from typing import cast
lazy from pathlib import Path

import pytest
from session_cache import build_once

#: ``COLUMNS`` for composed help: wide enough that Rich keeps flag names whole.
COMPOSED_HELP_COLUMNS = "200"


def _render_route_help(_directory: Path) -> dict[str, list[int | str]]:
    """``{route: [exit code, output]}`` of ``rebrew <route> --help`` on one composed tree."""
    import typer
    from click.core import Command
    from click.testing import CliRunner

    from rebrew.app.main import app

    command = cast("Command", typer.main.get_command(app))
    runner = CliRunner()
    pages: dict[str, list[int | str]] = {}
    pending: list[tuple[tuple[str, ...], Command]] = [((), command)]
    while pending:
        path, current = pending.pop()
        result = runner.invoke(command, [*path, "--help"], env={"COLUMNS": COMPOSED_HELP_COLUMNS})
        pages[" ".join(path)] = [result.exit_code, result.output]
        children: dict[str, Command] = getattr(current, "commands", {})
        pending.extend(((*path, name), child) for name, child in children.items())
    return pages


def composed_route_help(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[int, str]]:
    """``(exit code, output)`` per route, keyed by the space-joined route (``""`` is the root)."""
    _, pages = build_once(tmp_path_factory, "composed-route-help", _render_route_help)
    return {route: (int(code), str(output)) for route, (code, output) in pages.items()}
