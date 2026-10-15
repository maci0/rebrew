"""clispec 0.3 contract for the rebrew umbrella entry point."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cli_json import cli_payload
from typer.testing import CliRunner

from rebrew.app.main import app

_REQUIRED = ("clispec", "name", "version", "output", "global_args", "commands", "errors")


def _invoke(argv: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    return CliRunner().invoke(app, argv)


def test_schema_is_json_without_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _invoke(["schema"], tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    document = cli_payload(result)
    assert document["clispec"] == "0.3"
    assert document["name"] == "rebrew"
    assert document["version"]
    assert document["output"] == {"tty": "text", "piped": "text"}
    for key in _REQUIRED:
        assert key in document
    assert document["commands"]
    assert document["errors"]
    names = [command["name"] for command in document["commands"]]
    assert names == sorted(names)
    assert "schema" in names
    assert "skills list" in names
    listed = {command["name"] for command in document["commands"]}
    assert "skills" not in listed
    skills = next(command for command in document["commands"] if command["name"] == "skills list")
    assert skills["effects"] == "read_only"
    assert skills["cardinality"] == "bounded"
    assert {field["name"] for field in skills["output_fields"]} == {"name", "description", "origin"}
    flags = {arg["name"]: arg for arg in document["global_args"]}
    assert flags["--output"]["enum"] == ["auto", "text", "json"]
    assert flags["--output"]["default"] == "auto"
    assert "--json" in flags
    kinds = {error["kind"]: error["exit_code"] for error in document["errors"]}
    assert kinds["usage"] == 2
    assert kinds["failure"] == 2
    assert document["outcomes"][0]["code"] == 1


def test_schema_filters_a_command_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _invoke(["schema", "skills", "list"], tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    document = cli_payload(result)
    assert [command["name"] for command in document["commands"]] == ["skills list"]
    assert document["clispec"] == "0.3"


def test_root_help_mentions_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _invoke(["--help"], tmp_path, monkeypatch)
    assert result.exit_code == 0
    assert "schema" in result.stdout


def test_read_collection_json_uses_items_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(["-o", "json", "skills", "list"], tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    document = cli_payload(result)
    assert isinstance(document["items"], list)
    assert document["total"] == len(document["items"])
    assert document["items"]
    assert {"name", "description", "origin"} <= set(document["items"][0])


def test_explicit_text_is_not_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _invoke(["-o", "text", "skills", "list"], tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    with pytest.raises(json.JSONDecodeError):
        cli_payload(result)


def test_json_failure_envelope_is_last_stderr_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(["-o", "json", "skills", "show", "no-such-skill"], tmp_path, monkeypatch)
    assert result.exit_code == 2
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    error = envelope["error"]
    assert error["kind"] == "failure"
    assert "no-such-skill" in error["message"]
    assert "hint" in error
    assert result.stdout.strip() == ""
