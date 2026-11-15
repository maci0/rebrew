"""Build each typer app's click command once per test process.

``typer.testing.CliRunner.invoke`` rebuilds the whole click command tree on
every call: 2,999 builds of 214 apps cost 51 s of the suite's 592 s CPU. A
built command is reused while the app registers the same command, group and
callback objects, so a test that adds a command to an app after an earlier
build gets a fresh one. Loaded through ``addopts`` like ``pytest_ansi_env``.
"""

from __future__ import annotations

import weakref
from typing import Any

import typer
import typer.main
import typer.testing
from typer import _click

# typer.testing's private module global is what CliRunner.invoke calls.
_TESTING_GLOBALS = vars(typer.testing)
if _TESTING_GLOBALS.get("_get_command") is not typer.main.get_command:
    raise RuntimeError(
        "typer.testing no longer builds commands through typer.main.get_command;"
        " update tests/typer_command_cache.py"
    )

_BUILT: weakref.WeakKeyDictionary[typer.Typer, tuple[tuple[Any, ...], _click.Command]] = (
    weakref.WeakKeyDictionary()
)


def _registrations(app: typer.Typer) -> tuple[Any, ...]:
    """The objects a build reads, compared by identity (none define ``__eq__``)."""
    return (
        app.info,
        app.registered_callback,
        tuple(app.registered_commands),
        tuple(
            (group, _registrations(group.typer_instance))
            if isinstance(group.typer_instance, typer.Typer)
            else (group, None)
            for group in app.registered_groups
        ),
    )


def _cached_command(app: typer.Typer) -> _click.Command:
    registrations = _registrations(app)
    hit = _BUILT.get(app)
    if hit is not None and hit[0] == registrations:
        return hit[1]
    command = typer.main.get_command(app)
    _BUILT[app] = (registrations, command)
    return command


_TESTING_GLOBALS["_get_command"] = _cached_command
