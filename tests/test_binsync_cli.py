"""Tests for the ``rebrew binsync`` umbrella (binsync_cli.py).

Runs real ``git`` (skipped when git is absent).  Reuses the project fixture
style from ``tests/test_binsync_init.py``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.main import app

runner = CliRunner()

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

pytest.importorskip("declib")

_BINARY = b"MZ\x90\x00" + bytes(range(64))
_FOO = "// FUNCTION: A 0x401000\n// STATUS: EXACT\n// SIZE: 11\nint foo(void) { return 1; }\n"


def _git(state: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(state), *args], capture_output=True, text=True)


def _make_project(tmp_path: Path) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(
        "[project]\nname = 'probe'\ndefault_target = 'A'\n"
        "[compiler]\nprofile = 'msvc-6.0'\ncommand = 'CL.EXE'\n"
        "[targets.A]\nbinary = 'a.exe'\nreversed_dir = 'src/a'\n"
        "function_list = 'src/a/functions.txt'\n",
        encoding="utf-8",
    )
    src = tmp_path / "src" / "a"
    src.mkdir(parents=True)
    (tmp_path / "a.exe").write_bytes(_BINARY)
    (src / "foo.c").write_text(_FOO, encoding="utf-8")
    (src / "functions.txt").write_text("0x401000 11 foo\n", encoding="utf-8")
    return tmp_path


def _invoke(tmp_path: Path, monkeypatch: Any, *args: str) -> Any:
    monkeypatch.chdir(tmp_path)
    return runner.invoke(app, ["binsync", *args], catch_exceptions=False)


class TestBinsyncUmbrella:
    def _init(self, state: Path, tmp_path: Path, monkeypatch: Any) -> None:
        result = _invoke(tmp_path, monkeypatch, "init", str(state), "--user", "tester", "--json")
        assert result.exit_code == 0, result.output

    def test_init_then_push_commits(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        self._init(state, tmp_path, monkeypatch)

        result = _invoke(tmp_path, monkeypatch, "push", str(state), "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["functions"] >= 1
        assert (state / "functions").is_dir()
        log = _git(state, "log", "--oneline").stdout.splitlines()
        assert len(log) >= 2  # root commit + push commit

    def test_push_then_pull_round_trips(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        self._init(state, tmp_path, monkeypatch)
        assert _invoke(tmp_path, monkeypatch, "push", str(state), "--json").exit_code == 0

        result = _invoke(tmp_path, monkeypatch, "pull", str(state), "--no-git", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["conflicts"] == 0

    def test_summary_reports_and_writes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        self._init(state, tmp_path, monkeypatch)
        assert _invoke(tmp_path, monkeypatch, "push", str(state), "--json").exit_code == 0

        monkeypatch.chdir(tmp_path)
        before = _git(state, "status", "--porcelain").stdout
        result = runner.invoke(app, ["binsync", "summary", str(state), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert "push" in payload and "pull" in payload
        assert payload["push"]["functions"] >= 1
        after = _git(state, "status", "--porcelain").stdout
        assert before == after

    def test_git_push_lands_branches_on_remote(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        bare = tmp_path / "remote.git"
        subprocess.run(["git", "init", "--bare", str(bare)], capture_output=True, text=True)
        self._init(state, tmp_path, monkeypatch)
        assert _git(state, "remote", "add", "origin", str(bare)).returncode == 0

        result = _invoke(tmp_path, monkeypatch, "push", str(state), "--git-push", "--json")
        assert result.exit_code == 0, result.output
        refs = _git(bare, "for-each-ref", "--format=%(refname)").stdout
        assert "refs/heads/binsync/__root__" in refs
        assert "refs/heads/binsync/tester" in refs

    def test_flat_commands_dispatch_through_umbrella(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        self._init(state, tmp_path, monkeypatch)
        assert _invoke(tmp_path, monkeypatch, "push", str(state), "--json").exit_code == 0

        diff = _invoke(tmp_path, monkeypatch, "diff", str(state), "--json")
        assert diff.exit_code == 0, diff.output

        monkeypatch.chdir(tmp_path)
        overlay_help = runner.invoke(app, ["binsync", "overlay", str(state), "--help"])
        assert overlay_help.exit_code == 0
        assert "Overlay" in overlay_help.output

    def test_push_json_carries_export_counts(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        self._init(state, tmp_path, monkeypatch)

        result = _invoke(tmp_path, monkeypatch, "push", str(state), "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        for key in ("functions", "globals", "structs", "enums", "typedefs", "comments"):
            assert key in payload

    def test_push_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        self._init(state, tmp_path, monkeypatch)

        result = _invoke(tmp_path, monkeypatch, "push", str(state), "--dry-run", "--json")
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["dry_run"] is True
        assert not (state / "functions").exists()

    def test_git_requires_state_repo(self, tmp_path: Path, monkeypatch) -> None:
        """A non-repo state dir must be rejected, never handed to ``git -C``.

        ``git -C`` walks up to the nearest ancestor repo, so an unguarded
        pull/push would act on the surrounding project instead.
        """
        _make_project(tmp_path)
        # The project root IS a git repo; the state dir is not.
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        state = tmp_path / "state"
        state.mkdir()

        for args in (("pull", str(state)), ("push", str(state), "--git-push")):
            result = _invoke(tmp_path, monkeypatch, *args, "--json")
            assert result.exit_code != 0, result.output
            assert "not a git repository" in result.output
        # And the ancestor repo gained no commits or branches from the attempt.
        log = _git(tmp_path, "rev-list", "--all", "--count")
        assert log.stdout.strip() in ("0", "")
