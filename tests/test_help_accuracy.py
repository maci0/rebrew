"""Help strings that must describe what their command actually does."""

from __future__ import annotations

import pytest
import typer
from typer._click.core import Command, Context
from typer.core import TyperGroup

import rebrew.app.main as main_mod


def _command(path: list[str]) -> Command:
    cmd: Command = typer.main.get_command(main_mod.app)
    for name in path:
        assert isinstance(cmd, TyperGroup), path
        sub = cmd.get_command(Context(cmd), name)
        assert sub is not None, path
        cmd = sub
    return cmd


def _option_help(path: list[str], flag: str) -> str:
    for param in _command(path).params:
        if flag in getattr(param, "opts", ()):
            return getattr(param, "help", None) or ""
    raise AssertionError(f"{' '.join(path)} has no {flag}")


class TestHelpAccuracy:
    def test_score_built_claims_no_default(self) -> None:
        """`binary score --built` is required, so its help names no default."""
        cmd = _command(["binary", "score"])
        built = next(p for p in cmd.params if "--built" in getattr(p, "opts", ()))
        assert built.required
        assert "default" not in (built.help or "")

    @pytest.mark.parametrize("path", [["sync", "pull"], ["binsync", "pull"], ["binsync", "import"]])
    def test_create_missing_names_catalog_known_functions(self, path: list[str]) -> None:
        """The importer stubs only VAs the catalog knows and no source binds."""
        text = _option_help(path, "--create-missing")
        assert "catalog-known" in text
        assert "not in the project catalog" not in text

    def test_toolchain_pull_names_the_runtime_knob(self) -> None:
        """`pull` runs `container_runtime()`, which REBREW_CONTAINER_RUNTIME selects."""
        text = _command(["toolchain", "pull"]).help or ""
        assert "REBREW_CONTAINER_RUNTIME" in text
        assert "docker image" not in text
