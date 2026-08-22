"""Tests for the interactive `rebrew init` onboarding wizard."""

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.init import app, init

_FIXTURES = Path(__file__).parent / "fixtures"


def _force_wizard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the wizard gate on regardless of TTY/json state."""
    monkeypatch.setattr("rebrew.init._wizard_active", lambda *args: True)


def _image_present(monkeypatch: pytest.MonkeyPatch, present: bool) -> None:
    """Keep the toolchain-image follow-up hermetic (no docker calls)."""
    monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: present)


def _fail_prompt(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("Prompt.ask must not be called in this run")


def _fail_confirm(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("Confirm.ask must not be called in this run")


def _no_prompts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("rebrew.init.Prompt.ask", _fail_prompt)
    monkeypatch.setattr("rebrew.init.Confirm.ask", _fail_confirm)


def _place_mini_pe(path: Path) -> None:
    """Copy the mini PE fixture to original/mini_pe.exe."""
    (path / "original").mkdir(exist_ok=True)
    shutil.copy(_FIXTURES / "mini_pe.exe", path / "original" / "mini_pe.exe")


# ---------------------------------------------------------------------------
# Gating — the wizard never interferes with unattended runs
# ---------------------------------------------------------------------------


class TestWizardGating:
    """Non-interactive invocations keep the old, prompt-free flow."""

    def test_default_cli_run_never_prompts(self, tmp_path: Path, monkeypatch) -> None:
        """CliRunner provides no TTY, so the wizard gate stays off: no
        input, no monkeypatched gate → completes with zero prompt output."""
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 0, result.output + result.stderr
        assert "onboarding wizard" not in result.stderr
        assert "Select the target binary" not in result.stderr
        assert (tmp_path / "rebrew-project.toml").is_file()

    def test_no_wizard_flag_disables_even_on_tty(self, tmp_path: Path, monkeypatch) -> None:
        """--no-wizard runs the plain flow even when stdin claims a TTY."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.chdir(tmp_path)
        _no_prompts(monkeypatch)
        result = CliRunner().invoke(app, ["--no-wizard"])
        assert result.exit_code == 0, result.output + result.stderr
        assert "onboarding wizard" not in result.stderr
        assert (tmp_path / "rebrew-project.toml").is_file()

    def test_json_with_wizard_enabled_stays_pure_json(self, tmp_path: Path, monkeypatch) -> None:
        """--json wins over --wizard: stdout parses as JSON, no prompts."""
        monkeypatch.chdir(tmp_path)
        _no_prompts(monkeypatch)
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["target"] == "main"
        assert payload["binary"] == "program.exe"
        assert (tmp_path / "rebrew-project.toml").is_file()

    def test_direct_python_call_unaffected(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """ctx=None (the unit-test convention) means every value counts as
        explicit — no prompts even with the gate forced on."""
        _force_wizard(monkeypatch)
        _no_prompts(monkeypatch)
        _image_present(monkeypatch, True)
        monkeypatch.chdir(tmp_path)
        init(
            target_name="demo",
            binary_name="demo.exe",
            compiler_profile="msvc6",
            install_completions=False,
            json_output=True,
            wizard=True,
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["target"] == "demo"
        content = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert 'default_target = "demo"' in content
        assert 'profile = "msvc6"' in content


# ---------------------------------------------------------------------------
# Wizard flow (driven through CliRunner input=)
# ---------------------------------------------------------------------------


class TestWizardFlow:
    """Forced-gate end-to-end runs with the mini_pe fixture in original/."""

    def test_auto_pick_applies_suggested_profile(self, tmp_path: Path, monkeypatch) -> None:
        """Choosing the offered binary + accepting the Enter-defaults writes
        the detected profile (msvc800 for mini_pe) and a stem-based target."""
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, True)
        monkeypatch.chdir(tmp_path)
        # binary: pick 1, profile: <enter> (suggestion), target: <enter>
        # (binary stem), confirm: y, completions: n
        result = CliRunner().invoke(app, [], input="1\n\n\ny\nn\n")
        assert result.exit_code == 0, result.output + result.stderr
        content = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert 'profile = "msvc800"' in content
        assert 'default_target = "mini_pe"' in content
        assert 'binary = "original/mini_pe.exe"' in content
        assert not (tmp_path / "completions").exists()
        assert "msvc800" in result.stderr  # detection summary surfaced

    def test_explicit_compiler_flag_skips_profile_prompt(self, tmp_path: Path, monkeypatch) -> None:
        """--compiler counts as explicit: its prompt is skipped and the
        passed profile is kept despite a differing detection suggestion."""
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, True)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--compiler", "msvc6"], input="1\n\ny\nn\n")
        assert result.exit_code == 0, result.output + result.stderr
        content = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert 'profile = "msvc6"' in content
        assert 'default_target = "mini_pe"' in content

    def test_typed_profile_overrides_suggestion(self, tmp_path: Path, monkeypatch) -> None:
        """Typing a different known profile wins over the detection
        suggestion (and the suggestion/default difference is shown)."""
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, True)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [], input="1\nmsvc600sp6\n\ny\nn\n")
        assert result.exit_code == 0, result.output + result.stderr
        content = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert 'profile = "msvc600sp6"' in content
        assert "suggests" in result.stderr  # suggestion vs default made visible

    def test_unknown_profile_reprompts_then_falls_back(self, tmp_path: Path, monkeypatch) -> None:
        """Garbage profile answers get one reprompt, then the current value."""
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, True)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [], input="1\njunk1\njunk2\n\ny\nn\n")
        assert result.exit_code == 0, result.output + result.stderr
        content = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert 'profile = "msvc6"' in content  # fallback: the current default
        assert "unknown profile 'junk1'" in result.stderr
        assert "unknown 'junk2'" in result.stderr

    def test_manual_binary_entry(self, tmp_path: Path, monkeypatch) -> None:
        """The 'm' choice takes a free-form path/name — missing targets warn
        but keep the entered name verbatim for later staging."""
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, True)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [], input="m\ncustom.exe\n\n\ny\nn\n")
        assert result.exit_code == 0, result.output + result.stderr
        content = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert 'binary = "original/custom.exe"' in content
        assert 'default_target = "custom"' in content
        assert "No such file" in result.stderr


class TestWizardConfirmAbort:
    """Declining the summary aborts cleanly with nothing written."""

    def test_exit_1_and_nothing_written(self, tmp_path: Path, monkeypatch) -> None:
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [], input="1\n\n\nn\n")
        assert result.exit_code == 1
        assert "Aborted" in result.stderr
        assert not (tmp_path / "rebrew-project.toml").exists()
        assert not (tmp_path / "src").exists()
        assert not (tmp_path / "completions").exists()


class TestWizardFullyFlagged:
    """A fully-flagged run with the gate forced on produces zero prompts."""

    def test_zero_prompt_calls(self, tmp_path: Path, monkeypatch) -> None:
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, True)
        monkeypatch.chdir(tmp_path)
        _no_prompts(monkeypatch)
        result = CliRunner().invoke(
            app,
            [
                "--target",
                "mytarget",
                "--binary",
                "mini_pe.exe",
                "--compiler",
                "msvc6",
                "--install-completions",
            ],
        )
        assert result.exit_code == 0, result.output + result.stderr
        content = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert 'default_target = "mytarget"' in content
        assert 'profile = "msvc6"' in content
        # wizard-active extras still fire on the forced-on gate
        assert "toolchain image rebrew/msvc:6.0-win32 present" in result.stderr
        assert "rebrew doctor" in result.stderr
        assert "rebrew intake" in result.stderr


# ---------------------------------------------------------------------------
# Toolchain image status step (wizard-active runs only)
# ---------------------------------------------------------------------------

_FLAGGED = [
    "--target",
    "t",
    "--binary",
    "mini_pe.exe",
    "--compiler",
    "msvc6",
    "--install-completions",
]


class TestToolchainImageStep:
    """Image state reporting + optional in-wizard build, fully mocked."""

    def test_missing_image_declined_prints_hint(self, tmp_path: Path, monkeypatch) -> None:
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, False)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, _FLAGGED, input="n\n")
        assert result.exit_code == 0, result.output + result.stderr
        assert "not present" in result.stderr
        assert "rebrew toolchain build msvc6" in result.stderr

    def test_missing_image_accepted_runs_build(self, tmp_path: Path, monkeypatch) -> None:
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, False)
        monkeypatch.chdir(tmp_path)
        real_which = shutil.which
        monkeypatch.setattr(
            shutil,
            "which",
            lambda name, *a, **k: "/fake/rebrew" if name == "rebrew" else real_which(name, *a, **k),
        )
        real_run = subprocess.run
        calls: list[list[str]] = []

        def _spy_run(cmd: list[str], **kwargs: Any) -> Any:
            # The module attribute IS the global subprocess module — click's
            # completion-script generation also calls .run, so only intercept
            # the toolchain-build call and delegate the rest.
            if cmd[:3] == ["/fake/rebrew", "toolchain", "build"]:
                calls.append(cmd)
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return real_run(cmd, **kwargs)

        monkeypatch.setattr("rebrew.init.subprocess.run", _spy_run)
        result = CliRunner().invoke(app, _FLAGGED, input="y\n")
        assert result.exit_code == 0, result.output + result.stderr
        assert calls == [["/fake/rebrew", "toolchain", "build", "msvc6"]]

    def test_build_failure_warns_but_completes(self, tmp_path: Path, monkeypatch) -> None:
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        _image_present(monkeypatch, False)
        monkeypatch.chdir(tmp_path)
        real_which = shutil.which
        monkeypatch.setattr(
            shutil,
            "which",
            lambda name, *a, **k: "/fake/rebrew" if name == "rebrew" else real_which(name, *a, **k),
        )
        real_run = subprocess.run

        def _spy_run(cmd: list[str], **kwargs: Any) -> Any:
            if cmd[:3] == ["/fake/rebrew", "toolchain", "build"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            return real_run(cmd, **kwargs)

        monkeypatch.setattr("rebrew.init.subprocess.run", _spy_run)
        result = CliRunner().invoke(app, _FLAGGED, input="y\n")
        assert result.exit_code == 0, result.output + result.stderr
        assert "build failed" in result.stderr

    def test_native_profile_reports_nothing_to_build(self, tmp_path: Path, monkeypatch) -> None:
        _place_mini_pe(tmp_path)
        _force_wizard(monkeypatch)
        monkeypatch.chdir(tmp_path)
        _no_prompts(monkeypatch)
        result = CliRunner().invoke(
            app,
            [
                "--target",
                "t",
                "--binary",
                "mini_pe.exe",
                "--compiler",
                "gcc-pe",
                "--install-completions",
            ],
        )
        assert result.exit_code == 0, result.output + result.stderr
        assert "nothing to build" in result.stderr

    def test_non_wizard_run_has_no_followup(self, tmp_path: Path, monkeypatch) -> None:
        """Unchanged non-wizard flow: no image lines, no doctor/intake extras."""
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 0, result.output + result.stderr
        assert "toolchain image" not in result.stderr
        assert "rebrew doctor" not in result.stderr
        assert "rebrew intake" not in result.stderr
