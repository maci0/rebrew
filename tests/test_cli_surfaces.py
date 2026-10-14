"""Render every mounted help surface, including nested commands, without project state."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import typer
from rich.cells import cell_len
from typer._click.core import Context
from typer.core import TyperOption
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.cli import add_global_options


def _commands(command: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[Any, tuple[str, ...]]]:
    yield command, path
    if hasattr(command, "list_commands"):
        context = Context(command)
        for name in command.list_commands(context):
            yield from _commands(command.get_command(context, name), (*path, name))


class TestMountedHelp:
    @pytest.mark.parametrize("width", [60, 80, 120])
    def test_every_help_page_renders_without_project_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, width: int
    ) -> None:
        monkeypatch.chdir(tmp_path)
        root = add_global_options(typer.main.get_command(app))
        runner = CliRunner()
        missing_flags = []
        for command, path in _commands(root):
            route = " ".join(("rebrew", *path))
            assert command.help, route
            assert "Example" in (command.epilog or ""), route
            with runner.isolation(
                env={
                    "NO_COLOR": "1",
                    "TERM": "dumb",
                    "_TYPER_FORCE_DISABLE_TERMINAL": "1",
                    "COLUMNS": str(width),
                }
            ) as streams:
                with pytest.raises(SystemExit) as exited:
                    root.main([*path, "--help"], prog_name="rebrew", terminal_width=width)
                assert exited.value.code == 0, route
                rendered = streams[0].getvalue().decode()
                errors = streams[1].getvalue().decode()
            assert not errors, (route, errors)
            assert "Usage: rebrew" in rendered, route
            assert "--help" in rendered and "-h" in rendered, route
            for param in command.params:
                if getattr(param, "hidden", False):
                    continue
                for flag in (*param.opts, *getattr(param, "secondary_opts", [])):
                    if flag.startswith("-") and flag not in rendered:
                        missing_flags.append((route, width, flag))
            assert all(cell_len(line.rstrip()) <= width for line in rendered.splitlines()), route
        assert missing_flags == []
        assert list(tmp_path.iterdir()) == []

    def test_short_help_is_eager_and_preserves_plugin_help_names(self) -> None:
        probe = typer.Typer()

        @probe.command()
        def command(required: str) -> None:
            pytest.fail("help must not run the callback")

        configured = add_global_options(typer.main.get_command(probe))
        assert configured.context_settings["help_option_names"] == ["--help", "-h"]
        with CliRunner().isolation():
            with pytest.raises(SystemExit) as exited:
                configured.main(["-h"], prog_name="probe")
            assert exited.value.code == 0
        configured.context_settings["help_option_names"] = ["--assist"]
        add_global_options(configured)
        assert configured.context_settings["help_option_names"] == ["--assist"]

    def test_option_panels_preserve_command_specific_grouping(self) -> None:
        probe = typer.Typer()

        @probe.command()
        def command(
            output: str = typer.Option("", "--output", rich_help_panel="Artifacts"),
            json_output: bool = typer.Option(False, "--json"),
            target: str = typer.Option("", "--target"),
        ) -> None:
            pass

        configured = add_global_options(typer.main.get_command(probe))
        panels = {
            p.name: p.rich_help_panel for p in configured.params if isinstance(p, TyperOption)
        }
        assert panels["output"] == "Artifacts"
        assert panels["json_output"] == "Output options"
        assert panels["target"] == "Project options"
        assert panels["version"] == panels["verbose"] == panels["quiet"] == "Global options"

    def test_command_quiet_keeps_its_own_meaning(self) -> None:
        from rebrew.lint import app

        command = add_global_options(typer.main.get_command(app))
        quiet = next(param for param in command.params if "--quiet" in param.opts)
        assert isinstance(quiet, TyperOption)
        assert quiet.rich_help_panel != "Global options"

    def test_shared_panel_order_is_consistent(self) -> None:
        from rebrew.app.main import app

        rank = {"Output options": 1, "Project options": 2, "Global options": 3}
        for command, route in _commands(typer.main.get_command(app)):
            ranks = [
                rank[param.rich_help_panel]
                for param in command.params
                if isinstance(param, TyperOption) and param.rich_help_panel in rank
            ]
            assert ranks == sorted(ranks), route
