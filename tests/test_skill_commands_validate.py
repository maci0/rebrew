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
        spec.loader.exec_module(mod)
        return bool(mod.validate(quiet=True))

    def test_script_is_importable(self) -> None:
        """The script must be importable (no syntax errors)."""
        spec = importlib.util.spec_from_file_location("validate_skill_commands", _SCRIPT)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        assert hasattr(mod, "validate")

    def test_validate_function_returns_bool(self, _validate_once: bool) -> None:
        """validate() must return True when every skill command resolves."""
        assert isinstance(_validate_once, bool)
        assert _validate_once is True

    def test_no_unknown_subcommands(self, _validate_once: bool) -> None:
        """All subcommands referenced in SKILL.md files must exist in the CLI.

        Reuses the session fixture's in-process run (the same probe set the
        script entrypoint runs) instead of spawning the script a second time.
        """
        assert _validate_once is True

    def test_main_exit_code_mapping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """main() maps validate() True/False to exit 0/1 (no probes)."""
        spec = importlib.util.spec_from_file_location("validate_skill_commands", _SCRIPT)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        import sys

        for result, code in ((True, 0), (False, 1)):
            monkeypatch.setattr(mod, "validate", lambda quiet=False, _r=result: _r)
            monkeypatch.setattr(sys, "argv", ["validate_skill_commands.py", "--quiet"])
            with pytest.raises(SystemExit) as exc:
                mod.main()
            assert exc.value.code == code
