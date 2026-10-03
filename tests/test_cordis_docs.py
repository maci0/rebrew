"""Execute Cordis tutorial transcripts and the guide's runnable recipes."""

import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from rebrew.plugin import (
    CLI_SERVICE,
    CONSOLE_SERVICE,
    CliComponent,
    Context,
    Panel,
    activate,
)
from rebrew.utils import console


def _blocks(path: Path, language: str) -> list[str]:
    """Read the fenced examples of one language from a documentation page."""
    return re.findall(
        rf"^```{language}\n(.*?)^```$",
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE | re.DOTALL,
    )


class TestCordisTutorial:
    def test_example_matches_transcript(self, capsys: pytest.CaptureFixture[str]) -> None:
        path = Path(__file__).resolve().parents[1] / "docs" / "CORDIS_TUTORIAL.md"
        examples = _blocks(path, "python")
        transcripts = _blocks(path, "text")
        assert examples and len(examples) == len(transcripts)
        for example, transcript in zip(examples, transcripts, strict=True):
            exec(compile(example, str(path), "exec"), {"__name__": "__main__"})  # noqa: S102
            captured = capsys.readouterr()
            assert captured.out == transcript
            assert captured.err == ""

    def test_cli_recipe_mounts_and_unmounts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        path = Path(__file__).resolve().parents[1] / "docs" / "CORDIS.md"
        module = ModuleType("rebrew_hello")
        exec(compile(_blocks(path, "python")[0], str(path), "exec"), module.__dict__)  # noqa: S102
        monkeypatch.setitem(sys.modules, module.__name__, module)
        app = typer.Typer()

        @app.callback()
        def _root() -> None:
            pass

        host = Context()
        host.provide(CLI_SERVICE, app)
        host.provide(CONSOLE_SERVICE, console)
        component = CliComponent(
            name="hello", module=module.__name__, attr="main", help="Greet", panel=Panel.PLUGINS
        )
        try:
            scope = activate([component], host)
            result = CliRunner().invoke(app, ["hello", "--name", "Ada"])
            assert result.exit_code == 0
            assert "Hello, Ada!" in result.output
            scope.close()
            assert app.registered_commands == []
        finally:
            host.dispose()

    def test_resource_recipe_withdraws_binding_and_removes_directory(self) -> None:
        path = Path(__file__).resolve().parents[1] / "docs" / "CORDIS.md"
        namespace: dict[str, Any] = {"__name__": "__main__"}
        exec(compile(_blocks(path, "python")[1], str(path), "exec"), namespace)  # noqa: S102
        directory = namespace["path"]
        host = namespace["host"]
        assert isinstance(directory, Path) and not directory.exists()
        assert isinstance(host, Context) and host.disposed and not host.has("report_dir")
