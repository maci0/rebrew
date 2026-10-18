"""Usage guards for ``test --all``, its batch-only flags, and ``skeleton --batch``."""

from __future__ import annotations

import inspect
import json

import pytest
from typer.models import OptionInfo
from typer.testing import CliRunner

_SINGLE_FUNCTION = (
    (["--all", "--cflags", "/O2"], "--cflags"),
    (["--all", "--toolchain", "msvc-6.0"], "--toolchain"),
    (["--all", "--size", "0"], "--size"),
    (["--all", "--va", "0x1000"], "--va"),
    (["--all", "--symbol", "_foo"], "--symbol"),
    (["--all", "--target-bin", "blob.bin"], "--target-bin"),
)

_REQUIRES_ALL = (
    (["--dir", "src/game"], "--dir"),
    (["--module", "GAME"], "--module"),
    (["--jobs", "4"], "--jobs"),
    (["-j", "4"], "--jobs"),
    (["--jobs", "0"], "--jobs"),
    (["-j", "0"], "--jobs"),
    (["--dir", "src/game", "--module", "GAME", "--jobs", "0", "file.c"], "--dir"),
)

_BATCH_CLASHES = (
    (["--batch", "1", "0x401000"], "a function VA"),
    (["--batch", "1", "--name", "foo"], "--name"),
    (["--batch", "1", "--output", "out.c"], "--output"),
    (["--batch", "1", "-o", "out.c"], "--output"),
    (["--batch", "0", "--append", "existing.c"], "--append"),
    (
        ["--batch", "2", "--name", "foo", "--output", "out.c", "--append", "a.c", "0x401000"],
        "a function VA, --name, --output, --append",
    ),
)


class _ReachedProject(Exception):
    """The command started project work."""


def _refuse_project(**_kwargs: object) -> None:
    raise _ReachedProject


class TestTestAllRejectsSingleFunctionOptions:
    @pytest.mark.parametrize(("argv", "flag"), _SINGLE_FUNCTION)
    def test_rejected_before_project_load(
        self, monkeypatch: pytest.MonkeyPatch, argv: list[str], flag: str
    ) -> None:
        from rebrew.test import app

        monkeypatch.setattr("rebrew.test.require_config", _refuse_project)
        monkeypatch.setattr(
            "rebrew.test.emit_test_batch", lambda *_a, **_k: pytest.fail("batch ran")
        )
        result = CliRunner().invoke(app, argv)
        assert result.exit_code == 2, result.output
        assert f"{flag} cannot be combined with --all" in result.stderr
        assert result.stdout.strip() == ""

    def test_json_error_names_the_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.test import app

        monkeypatch.setattr("rebrew.test.require_config", _refuse_project)
        result = CliRunner().invoke(app, ["--all", "--va", "0x10", "--json"])
        assert result.exit_code == 2, result.output
        error = json.loads(result.stderr.strip().splitlines()[-1])["error"]
        assert error["message"] == "--va cannot be combined with --all"
        assert result.stdout.strip() == ""

    def test_help_says_the_flags_exclude_all(self) -> None:
        from rebrew.test import main

        for name in ("cflags", "toolchain", "size", "va", "symbol", "target_bin"):
            option = inspect.signature(main).parameters[name].default
            assert isinstance(option, OptionInfo)
            assert "Excludes --all." in (option.help or "")

    def test_all_alone_still_loads_the_project(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.test import app

        monkeypatch.setattr("rebrew.test.require_config", _refuse_project)
        with pytest.raises(_ReachedProject):
            CliRunner().invoke(app, ["--all"], catch_exceptions=False)

    def test_all_keeps_batch_filters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.test import app

        monkeypatch.setattr("rebrew.test.require_config", _refuse_project)
        with pytest.raises(_ReachedProject):
            CliRunner().invoke(
                app,
                ["--all", "--dir", "src/game", "--module", "GAME", "--jobs", "0"],
                catch_exceptions=False,
            )


class TestBatchFiltersRequireAll:
    @pytest.mark.parametrize(("argv", "flag"), _REQUIRES_ALL)
    def test_rejected_before_project_load(
        self, monkeypatch: pytest.MonkeyPatch, argv: list[str], flag: str
    ) -> None:
        from rebrew.test import app

        monkeypatch.setattr("rebrew.test.require_config", _refuse_project)
        monkeypatch.setattr(
            "rebrew.test.emit_test_batch", lambda *_a, **_k: pytest.fail("batch ran")
        )
        result = CliRunner().invoke(app, argv)
        assert result.exit_code == 2, result.output
        assert f"{flag} requires --all" in result.stderr
        assert result.stdout.strip() == ""

    def test_help_says_the_flags_require_all(self) -> None:
        from rebrew.test import main

        for name in ("batch_dir", "origin", "jobs"):
            option = inspect.signature(main).parameters[name].default
            assert isinstance(option, OptionInfo)
            assert "Requires --all" in (option.help or "")


class TestSkeletonBatchRejectsSingleFunctionInputs:
    @pytest.mark.parametrize(("argv", "detail"), _BATCH_CLASHES)
    def test_rejected_before_scan(
        self, monkeypatch: pytest.MonkeyPatch, argv: list[str], detail: str
    ) -> None:
        from rebrew.skeleton import app

        monkeypatch.setattr("rebrew.skeleton.require_config", _refuse_project)
        monkeypatch.setattr(
            "rebrew.skeleton.load_function_structure", lambda *_a, **_k: pytest.fail("scan")
        )
        monkeypatch.setattr(
            "rebrew.skeleton.load_existing_vas", lambda *_a, **_k: pytest.fail("scan")
        )
        result = CliRunner().invoke(app, argv)
        assert result.exit_code == 2, result.output
        assert "--batch cannot be combined with " + detail in result.stderr
        assert result.stdout.strip() == ""

    def test_help_says_single_function_inputs_exclude_batch(self) -> None:
        from rebrew.skeleton import main

        params = inspect.signature(main).parameters
        assert "Excludes --batch." in (params["va"].default.help or "")
        for name in ("name", "output", "append"):
            option = params[name].default
            assert isinstance(option, OptionInfo)
            assert "Excludes --batch." in (option.help or "")
        batch = params["batch"].default
        assert isinstance(batch, OptionInfo)
        assert "--name" in (batch.help or "")
        assert "--append" in (batch.help or "")

    def test_batch_alone_still_loads_the_project(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.skeleton import app

        monkeypatch.setattr("rebrew.skeleton.require_config", _refuse_project)
        with pytest.raises(_ReachedProject):
            CliRunner().invoke(app, ["--batch", "1"], catch_exceptions=False)
