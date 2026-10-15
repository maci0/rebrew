"""Watch commands reject single-document JSON mode before starting work."""

import importlib
from pathlib import Path

import pytest
from cli_json import cli_payload
from typer.testing import CliRunner


class TestWatchOutputContract:
    @pytest.mark.parametrize(
        "module, route",
        [
            ("test", ["test", "f.c"]),
            ("diff", ["diff", "f.c"]),
            ("prove", ["prove", "f.c"]),
            ("match", ["match", "run", "f.c"]),
            ("verify", ["verify"]),
        ],
    )
    def test_json_watch_fails_before_config_dependencies_or_monitoring(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: str, route: list[str]
    ) -> None:
        from rebrew.app.main import app

        monkeypatch.chdir(tmp_path)
        owner = importlib.import_module(f"rebrew.{module}")

        def _unexpected(*args: object, **kwargs: object) -> None:
            pytest.fail("a rejected JSON watch invocation started work")

        monkeypatch.setattr(owner, "require_config", _unexpected)
        monkeypatch.setattr("rebrew.utils.watch_files", _unexpected)
        if module == "prove":
            monkeypatch.setattr(owner, "_require_angr", _unexpected)
        if module == "test":
            monkeypatch.setattr(owner, "_watch_loop", _unexpected)
        if module == "match":
            monkeypatch.setattr(owner, "run_single_ga", _unexpected)
        result = CliRunner().invoke(app, [*route, "--watch", "--json"])
        assert result.exit_code == 2, result.output
        assert cli_payload(result) == {
            "error": "--watch is terminal-only; omit --json",
            "code": 2,
        }
        assert list(tmp_path.iterdir()) == []
