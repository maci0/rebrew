"""Keep examples copyable and unavailable-command summaries accurate."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import typer
from rich.cells import cell_len
from rich.text import Text

from rebrew.app.builtins import BUILTIN_COMPONENTS, DOMAIN_COMPONENTS
from rebrew.app.main import app
from rebrew.cli import SOURCE_HELP


def _surfaces(command: Any, route: str = "rebrew") -> Iterator[tuple[str, Any]]:
    yield route, command
    for name, child in getattr(command, "commands", {}).items():
        yield from _surfaces(child, f"{route} {name}")


class TestHelpCopy:
    def test_source_resolvers_describe_all_supported_input_forms(self) -> None:
        root = typer.main.get_command(app)
        routes = {
            "test",
            "diff",
            "prove",
            "match run",
            "match flags",
            "match toolchains",
            "match climb",
            "match qualifiers",
            "diagnose drift",
            "diagnose near",
            "diagnose stack",
            "diagnose probe",
            "diagnose gap",
            "export decompme",
            "blocker set",
            "blocker clear",
            "blocker show",
            "orphans drop",
            "types apply",
        }
        for route in routes:
            command = root
            for part in route.split():
                command = command.commands[part]
            argument = next(p for p in command.params if p.param_type_name == "argument")
            assert argument.help.startswith(SOURCE_HELP), route

    def test_example_headings_are_styled_at_every_depth(self) -> None:
        root = typer.main.get_command(app)
        for route, command in _surfaces(root):
            assert "[bold]Examples:[/bold]" in (command.epilog or ""), route
            assert command.rich_markup_mode == "rich", route

    def test_examples_fit_eighty_columns_without_splitting_commands(self) -> None:
        root = typer.main.get_command(app)
        for route, command in _surfaces(root):
            for line in Text.from_markup(command.epilog or "").plain.splitlines():
                if line.lstrip().startswith(("rebrew ", "execute_process(", "# ")):
                    assert cell_len(line.rstrip()) <= 76, (route, line)

    def test_fallback_summaries_match_the_available_command(self) -> None:
        root = typer.main.get_command(app)
        for domain, components in [("", BUILTIN_COMPONENTS), *DOMAIN_COMPONENTS.items()]:
            parent = root.commands[domain] if domain else root
            for component in components:
                command = parent.commands[component.name]
                paragraph = (command.help or "").strip().split("\n\n", 1)[0]
                assert "\n" not in paragraph, (domain, component.name, paragraph)
                assert component.help == paragraph, (domain, component.name)
