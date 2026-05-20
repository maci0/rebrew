"""End-to-end tests for the rebrew round-trip CLI."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.round_trip import app

runner = CliRunner()


class TestRoundTripCli:
    def test_help_lists_required_flags(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for flag in ("--json", "--out", "--no-write", "--filter", "--target"):
            assert flag in result.stdout

    def test_no_config_errors_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["--json"])
        # require_config raises typer.Exit; treat any non-zero as success here.
        assert result.exit_code != 0
