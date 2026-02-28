"""Tests for the shared CLI helpers in rebrew.cli."""

import json

import pytest
import typer

from rebrew.cli import error_exit, json_print, parse_va

# ---------------------------------------------------------------------------
# error_exit()
# ---------------------------------------------------------------------------


class TestErrorExit:
    def test_plain_stderr_and_exit(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            error_exit("something broke")
        assert exc_info.value.exit_code == 1
        captured = capsys.readouterr()
        assert "something broke" in captured.err
        assert captured.out == ""

    def test_custom_exit_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            error_exit("fatal", code=2)
        assert exc_info.value.exit_code == 2

    def test_json_mode_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit):
            error_exit("bad input", json_mode=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data == {"error": "bad input"}
        assert captured.err == ""

    def test_json_mode_exit_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            error_exit("nope", json_mode=True, code=3)
        assert exc_info.value.exit_code == 3


# ---------------------------------------------------------------------------
# json_print()
# ---------------------------------------------------------------------------


class TestJsonPrint:
    def test_dict_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        json_print({"status": "ok", "count": 42})
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data == {"status": "ok", "count": 42}
        assert captured.err == ""

    def test_list_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        json_print([{"va": "0x1000"}, {"va": "0x2000"}])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2
        assert data[0]["va"] == "0x1000"

    def test_pretty_printed(self, capsys: pytest.CaptureFixture[str]) -> None:
        json_print({"a": 1})
        captured = capsys.readouterr()
        assert "\n" in captured.out

    def test_empty_dict(self, capsys: pytest.CaptureFixture[str]) -> None:
        json_print({})
        captured = capsys.readouterr()
        assert json.loads(captured.out) == {}


# ---------------------------------------------------------------------------
# parse_va()
# ---------------------------------------------------------------------------


class TestParseVa:
    def test_bare_hex(self) -> None:
        assert parse_va("10003da0") == 0x10003DA0

    def test_prefixed_hex(self) -> None:
        assert parse_va("0x10003da0") == 0x10003DA0

    def test_uppercase(self) -> None:
        assert parse_va("0X10003DA0") == 0x10003DA0

    def test_whitespace_stripped(self) -> None:
        assert parse_va("  0x1000  ") == 0x1000

    def test_invalid_exits(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            parse_va("not_hex")
        assert exc_info.value.exit_code == 1
        captured = capsys.readouterr()
        assert "not_hex" in captured.err

    def test_invalid_json_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit):
            parse_va("zzz", json_mode=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data
        assert "zzz" in data["error"]

    def test_empty_string_exits(self) -> None:
        with pytest.raises(typer.Exit):
            parse_va("")

    def test_zero(self) -> None:
        assert parse_va("0") == 0

    def test_small_value(self) -> None:
        assert parse_va("ff") == 255
