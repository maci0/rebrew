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
        assert "No such command" in r.output
        assert "definitely-not-a-command" in r.output

    def test_no_args_errors_with_missing_command(self) -> None:
        r = runner.invoke(app, [])
        assert r.exit_code == 2  # usage error — a command is required
        assert "Missing command" in r.output

    def test_compose_prints_discovery_warnings_via_service(self) -> None:
        """Duplicate-plugin warnings resolve CONSOLE_SERVICE through the
        context instead of the module-global console (bypass)."""
        from rebrew.main import app as global_app
        from rebrew.main import compose
        from rebrew.plugin import CLI_SERVICE, CONSOLE_SERVICE

        before = len(global_app.registered_commands)
        ctx, _scope = compose()
        assert ctx.resolve(CLI_SERVICE) is not None
        assert ctx.resolve(CONSOLE_SERVICE) is not None
        added = len(global_app.registered_commands) - before
        assert added > 0
        # Withdrawing the console deactivates every mounted component.
        ctx.unprovide(CONSOLE_SERVICE)
        assert len(global_app.registered_commands) == before

    def test_module_holds_composed_fiber(self) -> None:
        """The import-time composition's fiber is retained, not dropped.

        ``compose()`` hands the caller the scope — the inverse accumulator
        every mount records its disposer on. The module-load call site must
        hold that tuple; discarding it would leave registrations with an
        inverse nobody holds.
        """
        from rebrew import main as main_mod
        from rebrew.plugin import CLI_SERVICE

        ctx, scope = main_mod._COMPOSED
        assert not ctx.disposed
        assert not scope._closed
        assert ctx.resolve(CLI_SERVICE) is main_mod.app


class TestClosedStdout:
    def test_closed_pipe_exits_like_sigpipe(self) -> None:
        """``rebrew ... | head`` must not warn on stderr or exit 120."""
        import os
        import subprocess
        import sys

        read_fd, write_fd = os.pipe()
        os.close(read_fd)  # reader gone before the child writes anything
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "rebrew.main", "skills", "list", "--json"],
                stdout=write_fd,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
        finally:
            os.close(write_fd)
        assert proc.returncode == 141, proc.stderr
        assert proc.stderr == b""
