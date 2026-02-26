"""Tests for the rebrew promote command."""

import json

from rebrew.promote import _error

# ---------------------------------------------------------------------------
# _error helper
# ---------------------------------------------------------------------------


def test_error_plain_stderr(capsys):
    """Plain text error goes to stderr with ERROR: prefix."""
    _error("compile failed", json_output=False, source="test.c")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ERROR: compile failed" in captured.err


def test_error_json_stdout(capsys):
    """JSON error goes to stdout with source and error keys."""
    _error("compile failed", json_output=True, source="test.c")
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["error"] == "compile failed"
    assert data["source"] == "test.c"
    assert captured.err == ""


def test_error_json_empty_source(capsys):
    """JSON error with no source still includes source key."""
    _error("no file", json_output=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["source"] == ""
    assert data["error"] == "no file"


def test_error_plain_empty_source(capsys):
    """Plain text error with default source still prints."""
    _error("oops", json_output=False)
    captured = capsys.readouterr()
    assert "ERROR: oops" in captured.err
