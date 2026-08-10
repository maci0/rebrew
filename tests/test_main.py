"""Tests for main.py — the umbrella rebrew CLI."""

from typer.testing import CliRunner

from rebrew.main import app

runner = CliRunner()


class TestUmbrellaCli:
    def test_version(self) -> None:
        r = runner.invoke(app, ["--version"])
        assert r.exit_code == 0
        assert "rebrew " in r.output

    def test_version_matches_module(self) -> None:
        """--version must agree with the module's __version__ (single source
        of truth — drift means a stale wheel/egg-info in the environment)."""
        from rebrew import __version__

        r = runner.invoke(app, ["--version"])
        assert r.exit_code == 0
        assert __version__ in r.output

    def test_help_lists_command_panels(self) -> None:
        r = runner.invoke(app, ["--help"])
        assert r.exit_code == 0
        for cmd in ("test", "verify", "similar", "near-diag", "catalog", "cfg", "cache", "skills"):
            assert cmd in r.output

    def test_help_groups_panels(self) -> None:
        r = runner.invoke(app, ["--help"])
        assert r.exit_code == 0
        for panel in ("Project Setup", "Development", "Analysis", "Matching", "Export & Sync"):
            assert panel in r.output

    def test_unknown_command_fails(self) -> None:
        r = runner.invoke(app, ["definitely-not-a-command"])
        assert r.exit_code != 0

    def test_no_args_errors_with_missing_command(self) -> None:
        r = runner.invoke(app, [])
        assert r.exit_code == 2  # usage error — a command is required
        assert "Missing command" in r.output
