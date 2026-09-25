"""Tests for main.py — the umbrella rebrew CLI."""

import pytest
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

    def test_quiet_help_describes_log_level(self) -> None:
        """Global --quiet cancels --verbose. It does not hide command output."""
        r = runner.invoke(app, ["--help"])
        assert r.exit_code == 0
        assert "Cancel --verbose" in r.output
        assert "Suppress non-essential output" not in r.output

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
    @pytest.mark.parametrize(
        "argv",
        [
            ["rebrew.main", "skills", "list", "--json"],
            # Output past the pipe buffer: the EPIPE hits inside click (JSON)
            # or Rich (markdown), both of which swallow it into exit 1.
            ["rebrew.main", "skills", "show", "rebrew-workflow", "--json"],
            ["rebrew.main", "skills", "show", "rebrew-workflow"],
            # Standalone console-script entry (``rebrew-skills``).
            ["rebrew.skills", "show", "rebrew-workflow", "--json"],
        ],
    )
    def test_closed_pipe_exits_like_sigpipe(self, argv: list[str]) -> None:
        """``rebrew ... | head`` must not warn on stderr or exit 1/120."""
        import os
        import subprocess
        import sys

        read_fd, write_fd = os.pipe()
        os.close(read_fd)  # reader gone before the child writes anything
        try:
            proc = subprocess.run(
                [sys.executable, "-m", *argv],
                stdout=write_fd,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
        finally:
            os.close(write_fd)
        assert proc.returncode == 141, proc.stderr
        assert proc.stderr == b""


class TestPlainEntryErrorExit:
    def test_error_exit_outside_click_keeps_its_code(self) -> None:
        """A plain console-script entry's ``error_exit`` is a clean exit 2, not a traceback."""
        import subprocess
        import sys

        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "from rebrew.objdiff_project import objdiff_build_entry as e; e()",
            ],
            capture_output=True,
            timeout=120,
            check=False,
        )
        assert proc.returncode == 2, proc.stderr
        assert b"usage: rebrew-objdiff-build" in proc.stderr
        assert b"Traceback" not in proc.stderr
