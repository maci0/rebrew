"""The suite's typer command cache reuses a build until the app registers something new."""

from __future__ import annotations

import typer
from typer.testing import CliRunner
from typer_command_cache import _cached_command


def test_a_build_is_reused_until_a_command_is_added() -> None:
    app = typer.Typer()

    @app.command()
    def first() -> None:
        typer.echo("first ran")

    built = _cached_command(app)
    assert _cached_command(app) is built

    @app.command()
    def second() -> None:
        typer.echo("second ran")

    rebuilt = _cached_command(app)
    assert rebuilt is not built
    assert CliRunner().invoke(app, ["second"]).output == "second ran\n"


def test_a_subcommand_added_to_a_group_rebuilds_the_parent() -> None:
    app = typer.Typer()
    group = typer.Typer()
    app.add_typer(group, name="group")

    @group.command()
    def one() -> None:
        typer.echo("one")

    built = _cached_command(app)

    @group.command()
    def two() -> None:
        typer.echo("two")

    assert _cached_command(app) is not built
    assert CliRunner().invoke(app, ["group", "two"]).output == "two\n"
