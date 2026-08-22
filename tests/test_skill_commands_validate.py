"""Tests for tools/validate_skill_commands.py.

Runs the validator script against the real agent-skills directory to confirm
it doesn't crash and that all commands found in SKILL.md files are actually
registered in the CLI.  Does NOT invoke real rebrew commands; it only confirms
``--help`` works (i.e., the subcommand exists and the flag is advertised).

Note: This test spawns subprocesses via ``uv run rebrew <subcommand> --help``,
so it requires the package to be installed (editable install is fine).
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "tools" / "validate_skill_commands.py"


def _script_available() -> bool:
    return _SCRIPT.is_file()


@pytest.mark.skipif(not _script_available(), reason="validate_skill_commands.py not found")
class TestValidateSkillCommands:
    @pytest.fixture(scope="session")
    def _validate_once(self) -> bool:
        """Run the full validation ONCE per session and cache the boolean.

        The validation spawns one ``rebrew <subcommand> --help`` subprocess per
        unique subcommand (~3s) — running it in both tests doubled the suite's
        slowest non-docker cost.  The subprocess test below still exercises the
        CLI entrypoint end-to-end; this fixture only serves the in-process API
        test.
        """
        spec = importlib.util.spec_from_file_location("validate_skill_commands", _SCRIPT)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return bool(mod.validate(quiet=True))

    def test_script_is_importable(self) -> None:
        """The script must be importable (no syntax errors)."""
        spec = importlib.util.spec_from_file_location("validate_skill_commands", _SCRIPT)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        assert hasattr(mod, "validate")

    def test_validate_function_returns_bool(self, _validate_once: bool) -> None:
        """validate() must return a boolean."""
        assert isinstance(_validate_once, bool)

    def test_no_unknown_subcommands(self) -> None:
        """All subcommands referenced in SKILL.md files must exist in the CLI."""
        result = subprocess.run(
            [sys.executable, str(_SCRIPT), "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(_REPO_ROOT),
        )
        # Exit 0 = all OK; exit 1 = failures
        assert result.returncode == 0, (
            "validate_skill_commands.py found drift:\n" + result.stdout + result.stderr
        )
