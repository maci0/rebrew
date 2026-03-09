"""Tests for rebrew.utils."""

import os
from pathlib import Path

import pytest

from rebrew.utils import atomic_write_text


def test_atomic_write_text_success(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    atomic_write_text(f, "hello world")
    assert f.read_text() == "hello world"
    assert not f.with_suffix(".txt.tmp").exists()


def test_atomic_write_text_overwrite(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    f.write_text("old")
    atomic_write_text(f, "new")
    assert f.read_text() == "new"


def test_atomic_write_text_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "test.txt"

    # Mock os.replace to fail to simulate crash during write
    def mock_replace(*args, **kwargs):
        raise OSError("Simulated crash")

    monkeypatch.setattr(os, "replace", mock_replace)

    with pytest.raises(OSError, match="Simulated crash"):
        atomic_write_text(f, "bad")

    # File shouldn't be touched/created
    assert not f.exists()
    # Temp file should be cleaned up by the exception handler
    assert not f.with_suffix(".txt.tmp").exists()


# ---------------------------------------------------------------------------
# _filter_wine_stderr wrapper (moved from test_phase3.py)
# ---------------------------------------------------------------------------


class TestFilterWineStderrWrapper:
    def test_delegates_to_compile(self) -> None:
        from rebrew.compile import filter_wine_stderr
        from rebrew.matcher.compiler import _filter_wine_stderr

        noisy = "0042:err:ntdll:something broken\nreal error: missing ;\n"
        assert _filter_wine_stderr(noisy) == filter_wine_stderr(noisy)

    def test_strips_wine_noise(self) -> None:
        from rebrew.matcher.compiler import _filter_wine_stderr

        result = _filter_wine_stderr("0042:fixme:winediag:test\nactual output")
        assert "fixme" not in result
        assert "actual output" in result

    def test_empty_string(self) -> None:
        from rebrew.matcher.compiler import _filter_wine_stderr

        assert _filter_wine_stderr("") == ""
