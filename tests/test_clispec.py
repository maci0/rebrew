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
    assert "--json" not in flags
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


def _commands(document: dict) -> dict[str, dict]:
    return {command["name"]: command for command in document["commands"]}


def _schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    result = _invoke(["schema"], tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    return cli_payload(result)


_WRITING = ("lint", "diff", "binary extract show", "binary asm show")
_SAME_LEAF_READERS = ("binsync diff", "skills show", "blocker show", "binary extract list")
_NEGATIVES = (
    ("init", "--wizard", "--no-wizard"),
    ("cfg target add", "--copy", "--no-copy"),
    ("binary asm show", "--annotate", "--no-annotate"),
    ("match run", "--compare-obj", "--no-compare-obj"),
    ("match batch", "--seed-solved", "--no-seed-solved"),
)
_HELP_WITHOUT_EM_DASH = (
    ["verify", "--help"],
    ["source", "document-unmatched", "--help"],
    ["source", "import-related", "--help"],
    ["build", "postlink", "--help"],
    ["build", "round-trip", "--help"],
    ["toolchain", "vendor", "--help"],
    ["toolchain", "smoke", "--help"],
    ["toolchain", "check-updates", "--help"],
    ["binsync", "export", "--help"],
    ["diagnose", "stack", "--help"],
    ["coverage", "report", "--help"],
    ["todo", "--help"],
)


def test_writers_are_classified_by_full_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands = _commands(_schema(tmp_path, monkeypatch))
    for path in _WRITING:
        assert commands[path]["effects"] != "read_only", path
    for path in _SAME_LEAF_READERS:
        assert commands[path]["effects"] == "read_only", path
    lint_flags = {arg["name"] for arg in commands["lint"]["args"]}
    diff_flags = {arg["name"] for arg in commands["diff"]["args"]}
    asm_flags = {arg["name"] for arg in commands["binary asm show"]["args"]}
    assert "--fix" in lint_flags
    assert "--fix-blocker" in diff_flags
    assert {"--format", "--inline-c", "--output"} <= asm_flags


def test_negative_spellings_stay_on_the_same_parameter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands = _commands(_schema(tmp_path, monkeypatch))
    for path, positive, negative in _NEGATIVES:
        args = commands[path]["args"]
        owned = [
            arg
            for arg in args
            if arg["name"] in {positive, negative} or arg.get("negative") == negative
        ]
        assert len(owned) == 1, (path, [arg["name"] for arg in args])
        arg = owned[0]
        assert arg["name"] == positive
        assert arg["negative"] == negative
        assert arg["type"] == "boolean"
        assert arg.get("default") is True
        assert not any(item["name"] == negative for item in args)


def test_json_is_a_command_argument(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    document = _schema(tmp_path, monkeypatch)
    assert "--json" not in {arg["name"] for arg in document["global_args"]}
    commands = _commands(document)
    skills = {arg["name"]: arg for arg in commands["skills list"]["args"]}
    assert skills["--json"]["type"] == "boolean"
    assert skills["--json"]["description"] == "Output results as JSON"
    assert "--quiet" not in skills
    assert "--verbose" not in skills
    assert "--version" not in skills
    schema_args = {arg["name"] for arg in commands["schema"].get("args", [])}
    assert "--json" not in schema_args
    asm = {arg["name"]: arg for arg in commands["binary asm show"]["args"]}
    assert "file" in asm["--output"]["description"].lower()
    assert asm["--json"]["type"] == "boolean"

    before = _invoke(["--json", "skills", "list"], tmp_path, monkeypatch)
    assert before.exit_code == 2
    after = _invoke(["skills", "list", "--json"], tmp_path, monkeypatch)
    assert after.exit_code == 0, after.output
    assert isinstance(cli_payload(after)["items"], list)
    rejected = _invoke(["schema", "--json"], tmp_path, monkeypatch)
    assert rejected.exit_code == 2
    selected = _invoke(["-o", "json", "schema", "skills", "list"], tmp_path, monkeypatch)
    assert selected.exit_code == 0, selected.output
    assert list(_commands(cli_payload(selected))) == ["skills list"]


def test_lint_quiet_suppresses_warnings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    document = _schema(tmp_path, monkeypatch)
    global_quiet = next(arg for arg in document["global_args"] if arg["name"] == "--quiet")
    quiet = next(arg for arg in _commands(document)["lint"]["args"] if arg["name"] == "--quiet")
    assert quiet["short"] == "-q"
    assert quiet["type"] == "boolean"
    assert quiet["description"] == "Only show errors, suppress warnings"
    assert quiet["description"] != global_quiet["description"]


@pytest.mark.parametrize("argv", _HELP_WITHOUT_EM_DASH, ids=lambda argv: " ".join(argv[:-1]))
def test_listed_help_has_no_em_dash(
    argv: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _invoke(argv, tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    assert "\u2014" not in result.stdout
    assert "\u2014" not in result.stderr


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
