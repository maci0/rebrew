"""A wrongly typed ``rebrew-project.toml`` ends every reader with the config error.

``load_config`` refuses a section of the wrong type, but several commands read
the file without it: the ``cfg`` editor, ``build driver``, ``calibrate-bss``,
``init --refresh-agents`` and ``intake``.  ``project = "x"``, ``targets = 5``,
``[targets] game = 5`` or ``compiler = "x"`` escaped them as ``AttributeError``
or ``TypeError``, a traceback with exit 1.  Each now exits 2 with the message
``read_project_toml`` raises, prefixed ``Config error:`` as ``require_config``
does (``intake`` keeps its ``Cannot read`` prefix).
"""

from __future__ import annotations

lazy from pathlib import Path

import pytest
from cli_json import cli_payload
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.cli import EXIT_ERROR

_TARGET = '[targets.game]\nbinary = "game.exe"\nreversed_dir = "src"\n'
_PROJECT = '[project]\ndefault_target = "game"\n'
_COMPILER = '[compiler]\nprofile = "msvc-6.0"\n'

#: ``(id, rebrew-project.toml, message the command reports)``.
_SHAPES = [
    (
        "project-string",
        'project = "x"\n' + _TARGET + _COMPILER,
        "rebrew-project.toml [project] must be a TOML table",
    ),
    ("targets-int", "targets = 5\n" + _PROJECT + _COMPILER, "[targets] must be a TOML table"),
    (
        "target-int",
        _PROJECT + "[targets]\ngame = 5\n" + _COMPILER,
        "[targets.game] must be a TOML table",
    ),
    (
        "compiler-string",
        'compiler = "x"\n' + _PROJECT + _TARGET,
        "[compiler] must be a TOML table",
    ),
]

#: Commands that read the file without ``load_config``.
_JSON_COMMANDS = [
    ["cfg", "target", "list", "--json"],
    ["cfg", "set", "project.shared_dir", "src/shared", "--json"],
    ["cfg", "target", "add", "other", "--binary", "o.exe", "--json"],
    ["build", "calibrate-bss", "--dry-run", "--json"],
    ["init", "--refresh-agents", "--check", "--json"],
]


def _project(root: Path, toml: str) -> None:
    (root / "rebrew-project.toml").write_text(toml, encoding="utf-8")
    (root / "src" / "game").mkdir(parents=True)
    (root / "src" / "link_stubs.c").write_text("char g_bss_tail[0x10];\n", encoding="utf-8")
    (root / "game.exe").write_bytes(b"MZ" + bytes(0x3E))


@pytest.mark.parametrize("argv", _JSON_COMMANDS, ids=lambda argv: "-".join(argv[:2]))
@pytest.mark.parametrize(
    ("toml", "message"), [pytest.param(t, m, id=case) for case, t, m in _SHAPES]
)
def test_wrong_section_type_is_a_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str], toml: str, message: str
) -> None:
    _project(tmp_path, toml)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == EXIT_ERROR, result.exception
    error = cli_payload(result)["error"]
    assert error.startswith("Config error: ")
    assert message in error


@pytest.mark.parametrize(
    ("toml", "message"), [pytest.param(t, m, id=case) for case, t, m in _SHAPES]
)
def test_build_driver_refuses_before_running_a_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str, message: str
) -> None:
    """The driver reads the project's profile and execution backend; a wrong
    section type is reported before any toolchain is resolved or run."""
    _project(tmp_path, toml)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REBREW_TOOLCHAIN", "msvc-6.0")
    result = CliRunner().invoke(app, ["build", "driver", "cl", "--", "/c", "x.c"])
    assert result.exit_code == EXIT_ERROR, result.exception
    assert "Config error: " in result.stderr
    assert message in result.stderr


@pytest.mark.parametrize(
    "argv",
    [
        ["cfg", "set", "project.shared_dir", "src/shared", "--json"],
        ["build", "calibrate-bss", "--dry-run", "--json"],
    ],
    ids=lambda argv: "-".join(argv[:2]),
)
@pytest.mark.parametrize("value", ["5", "[1]"])
def test_default_target_of_the_wrong_type_is_a_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str], value: str
) -> None:
    _project(tmp_path, f"[project]\ndefault_target = {value}\n" + _TARGET + _COMPILER)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == EXIT_ERROR, result.exception
    error = cli_payload(result)["error"]
    assert error.startswith("Config error: rebrew-project.toml [project].default_target must be")


def test_cfg_set_can_still_replace_a_wrongly_typed_default_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default target is checked where it is read, not at load, so the
    editor that repairs it keeps working."""
    _project(tmp_path, "[project]\ndefault_target = 5\n" + _TARGET + _COMPILER)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["cfg", "set", "project.default_target", "game", "--json"])
    assert result.exit_code == 0, result.output
    assert 'default_target = "game"' in (tmp_path / "rebrew-project.toml").read_text()


def test_calibrate_bss_reports_an_unparsable_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A config that does not parse is the config error, not a silent fall
    back to scanning every layout package."""
    _project(tmp_path, "[project\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["build", "calibrate-bss", "--dry-run", "--json"])
    assert result.exit_code == EXIT_ERROR, result.exception
    assert cli_payload(result)["error"].startswith("Config error: ")


def test_refresh_agents_refuses_a_wrongly_typed_target_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _project(tmp_path, _PROJECT + _TARGET + 'compiler = "x"\n' + _COMPILER)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["init", "--refresh-agents", "--check", "--json"])
    assert result.exit_code == EXIT_ERROR, result.exception
    assert cli_payload(result)["error"] == (
        "Config error: rebrew-project.toml [targets.game.compiler] must be a TOML table"
    )


def test_intake_refuses_a_target_that_is_not_a_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``intake`` patches the target's arch and format in place; a target that
    is not a table is refused before any analysis instead of failing that
    patch with ``AttributeError`` (reached for an MZ or NE image)."""
    (tmp_path / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "server"\n[targets]\nserver = "x"\n', encoding="utf-8"
    )
    (tmp_path / "original").mkdir()
    (tmp_path / "original" / "server.exe").write_bytes(b"MZ" + bytes(0x3E))
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["intake", "original/server.exe", "--json"])
    assert result.exit_code == EXIT_ERROR, result.exception
    assert "[targets.server] must be a TOML table" in cli_payload(result)["error"]
