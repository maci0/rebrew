"""Finite CLI values reject typos and expose native value completion."""

from typing import Any

import pytest
from typer.main import get_command
from typer.testing import CliRunner


def _command(route: list[str]) -> Any:
    from rebrew.app.main import app

    command: Any = get_command(app)
    for name in route:
        command = command.commands[name]
    return command


class TestFiniteChoices:
    @pytest.mark.parametrize(
        "route, arguments, flag, prefix, expected",
        [
            (["diff"], ["f.c"], "--format", "t", "terminal"),
            (["cfg", "raw"], [], "--format", "j", "json"),
            (["cfg", "target", "add"], ["game", "--binary", "game.exe"], "--format", "p", "pe"),
            (["source", "graph"], [], "--format", "m", "mermaid"),
            (["binary", "asm", "show"], ["0x1000"], "--format", "n", "nasm"),
            (["match", "batch"], [], "--algorithm", "g", "ga"),
            (["match", "flags"], ["f.c"], "--tier", "q", "quick"),
            (["match", "batch"], [], "--tier", "t", "targeted"),
            (["match", "toolchains"], ["f.c"], "--tier", "f", "full"),
            (["match", "run"], ["f.c"], "--mutation-focus", "a", "auto"),
            (["match", "batch"], [], "--mutation-focus", "r", "register"),
            (["recommend"], [], "--category", "h", "hygiene"),
            (["match", "climb"], ["f.c"], "--objective", "a", "aligned"),
        ],
    )
    def test_invalid_values_fail_before_work_and_valid_values_complete(
        self, route: list[str], arguments: list[str], flag: str, prefix: str, expected: str
    ) -> None:
        from rebrew.app.main import app

        result = CliRunner().invoke(app, [*route, *arguments, flag, "not-a-choice"])
        assert result.exit_code == 2, result.output
        assert "Invalid value" in result.output
        assert "not-a-choice" in result.output
        command = _command(route)
        param = next(param for param in command.params if flag in param.opts)
        with command.make_context(command.name, [], resilient_parsing=True) as ctx:
            completed = [item.value for item in param.type.shell_complete(ctx, param, prefix)]
            assert expected in completed
            assert all(value.startswith(prefix) for value in completed)
            value = param.type.convert(expected, param, ctx)
            assert type(value) is str
            assert value == expected

    def test_tier_and_format_choices_match_their_owners(self) -> None:
        from rebrew.config import KNOWN_FORMATS
        from rebrew.flag_data import MSVC_SWEEP_TIERS

        for route, flag, expected in [
            (["cfg", "target", "add"], "--format", KNOWN_FORMATS),
            (["match", "flags"], "--tier", set(MSVC_SWEEP_TIERS)),
        ]:
            command = _command(route)
            param = next(param for param in command.params if flag in param.opts)
            assert set(param.type.choices) == expected


class TestDecompilerCompletion:
    @pytest.mark.parametrize("route", [["decompile"], ["skeleton"], ["types", "recover"]])
    def test_completion_reads_the_current_plugin_registry(
        self, monkeypatch: pytest.MonkeyPatch, route: list[str]
    ) -> None:
        from rebrew import decompiler

        command = _command(route)
        param = next(param for param in command.params if "--decompiler" in param.opts)
        with command.make_context(command.name, [], resilient_parsing=True) as ctx:
            monkeypatch.setattr(decompiler, "_BACKEND_MAP", {"plugin-first": lambda *a: None})
            assert [item.value for item in param.shell_complete(ctx, "plugin-")] == ["plugin-first"]
            monkeypatch.setattr(decompiler, "_BACKEND_MAP", {"plugin-second": lambda *a: None})
            assert [item.value for item in param.shell_complete(ctx, "plugin-")] == [
                "plugin-second"
            ]
