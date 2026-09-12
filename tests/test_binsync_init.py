"""Tests for rebrew.binsync.init: the BinSync git envelope.

Runs real ``git`` (skipped when git is absent).  The command writes the
``binsync/__root__`` root commit and the ``binsync/<user>`` branch upstream
BinSync's Client resolves.
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
from rebrew.utils import md5_file

runner = CliRunner()

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

_BINARY = b"MZ\x90\x00" + bytes(range(64))


def _git(state: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(state), *args], capture_output=True, text=True)


def _make_project(tmp_path: Path, *, write_binary: bool = True) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(
        "[project]\nname = 'probe'\ndefault_target = 'A'\n"
        "[compiler]\nprofile = 'msvc6'\ncommand = 'CL.EXE'\n"
        "[targets.A]\nbinary = 'a.exe'\nreversed_dir = 'src/a'\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "a").mkdir(parents=True)
    if write_binary:
        (tmp_path / "a.exe").write_bytes(_BINARY)
    return tmp_path


def _invoke(state: Path, *extra: str) -> Any:
    return runner.invoke(app, ["binsync-init", str(state), *extra], catch_exceptions=False)


class TestInit:
    def test_creates_root_and_user_branches(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        monkeypatch.chdir(tmp_path)

        result = _invoke(state, "--user", "tester", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        digest = md5_file(tmp_path / "a.exe")
        assert payload == {
            "state_dir": str(state.resolve()),
            "target": "A",
            "user": "tester",
            "binary_hash": digest,
            "root_branch": "binsync/__root__",
            "user_branch": "binsync/tester",
            "dry_run": False,
        }
        assert _git(state, "show", "binsync/__root__:binary_hash").stdout == digest
        assert _git(state, "show", "binsync/__root__:.gitignore").stdout == ".git/*\n"
        branches = _git(state, "branch", "--list", "--format=%(refname:short)").stdout.split()
        assert "binsync/__root__" in branches
        assert "binsync/tester" in branches
        assert _git(state, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "binsync/tester"

    def test_running_twice_errors(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        monkeypatch.chdir(tmp_path)
        first = _invoke(state, "--user", "tester", "--json")
        assert first.exit_code == 0, first.output
        second = _invoke(state, "--user", "tester", "--json")
        assert second.exit_code != 0
        assert "already a BinSync repository" in second.output

    def test_missing_binary_errors(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path, write_binary=False)
        state = tmp_path / "state"
        monkeypatch.chdir(tmp_path)
        result = _invoke(state, "--user", "tester", "--json")
        assert result.exit_code != 0
        assert "target binary not found" in result.output

    def test_dry_run_leaves_no_git(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        state = tmp_path / "state"
        monkeypatch.chdir(tmp_path)
        result = _invoke(state, "--user", "tester", "--dry-run", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["dry_run"] is True
        assert payload["user_branch"] == "binsync/tester"
        assert not (state / ".git").exists()

    def test_preexisting_files_stay_untracked(self, tmp_path: Path, monkeypatch) -> None:
        """The root commit adds only .gitignore and binary_hash, never -A."""
        _make_project(tmp_path)
        state = tmp_path / "state"
        (state / "functions").mkdir(parents=True)
        (state / "functions" / "foo.toml").write_text("x = 1\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        result = _invoke(state, "--user", "tester", "--json")
        assert result.exit_code == 0, result.output
        status = _git(state, "status", "--porcelain", "--untracked-files=all").stdout.splitlines()
        foo = [line for line in status if "functions/foo.toml" in line]
        assert foo and foo[0].startswith("??")
        tree = _git(state, "show", "--pretty=format:", "--name-only", "binsync/__root__").stdout
        assert "functions/foo.toml" not in tree
        assert ".gitignore" in tree
        assert "binary_hash" in tree
