"""Tests for the ``rebrew binsync`` umbrella (binsync_cli.py).

Runs real ``git`` (skipped when git is absent).  Reuses the project fixture
style from ``tests/test_binsync_init.py``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
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
    return subprocess.run(
        ["git", "-C", str(state), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _make_project(tmp_path: Path) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(
        "[project]\nname = 'probe'\ndefault_target = 'A'\n"
        "[compiler]\nprofile = 'msvc-6.0'\ncommand = 'CL.EXE'\n"
        "[targets.A]\nbinary = 'a.exe'\nreversed_dir = 'src/a'\n",
        encoding="utf-8",
    )
    src = tmp_path / "src" / "a"
    src.mkdir(parents=True)
    (tmp_path / "a.exe").write_bytes(_BINARY)
    (src / "foo.c").write_text(_FOO, encoding="utf-8")
    import json as _json

    (src / "function_structure.json").write_text(
        _json.dumps([{"va": 0x401000, "size": 11, "name": "foo"}]), encoding="utf-8"
    )
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
        subprocess.run(
            ["git", "init", "--bare", str(bare)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
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


def _set_function(state: Path, va: int, **fields: str) -> None:
    """Edit one function artifact in the working tree (name and/or prototype)."""
    from rebrew.binsync import serial

    path = state / "functions" / f"{va:08x}.toml"
    func = serial.load_artifact(path, "function")
    if "name" in fields:
        func.name = fields["name"]
        func.header.name = fields["name"]
    if "prototype" in fields:
        func.header.type = fields["prototype"]
    serial.dump_artifact(path, func)


def _commit_as_peer(state: Path, peer: str, edit: Callable[[Path], None]) -> str:
    """Commit rebrew's exported state as BinSync user *peer*, after *edit*.

    Mirrors BinSync's Client: check out ``binsync/<peer>`` (from the root the
    first time), dump the user's whole state there (``metadata.toml`` names
    the peer), and commit, leaving the working tree on that branch.
    """
    from rebrew.binsync import serial

    exported = {
        path.relative_to(state): path.read_bytes()
        for path in state.rglob("*.toml")
        if ".git" not in path.relative_to(state).parts and path.name != "manifest.toml"
    }
    branch = f"binsync/{peer}"
    exists = _git(state, "rev-parse", "--verify", "--quiet", branch).returncode == 0
    args = (branch,) if exists else ("-b", branch, "binsync/__root__")
    assert _git(state, "checkout", "-q", *args).returncode == 0
    if not exists:
        for relative, body in exported.items():
            (state / relative).parent.mkdir(parents=True, exist_ok=True)
            (state / relative).write_bytes(body)
        serial.write_metadata(state, user=peer)
    edit(state)
    assert _git(state, "add", "-A").returncode == 0
    commit = _git(state, "-c", "user.name=g", "-c", "user.email=g@x", "commit", "-qm", "edit")
    assert commit.returncode == 0, commit.stderr
    return _git(state, "rev-parse", branch).stdout.strip()


def _rename_foo(state: Path) -> None:
    _set_function(state, 0x401000, name="_bar")


class TestUserBranches:
    """rebrew writes only binsync/<its user>; other users' branches are read."""

    def _pushed(self, tmp_path: Path, monkeypatch: Any) -> Path:
        _make_project(tmp_path)
        state = tmp_path / "state"
        init_result = _invoke(tmp_path, monkeypatch, "init", str(state), "--user", "tester")
        assert init_result.exit_code == 0, init_result.output
        assert _invoke(tmp_path, monkeypatch, "push", str(state), "--json").exit_code == 0
        return state

    def test_metadata_user_matches_branch(self, tmp_path: Path, monkeypatch) -> None:
        state = self._pushed(tmp_path, monkeypatch)
        assert _git(state, "show", "binsync/tester:metadata.toml").stdout.startswith(
            'user = "tester"'
        )

    def test_push_never_writes_another_users_branch(self, tmp_path: Path, monkeypatch) -> None:
        state = self._pushed(tmp_path, monkeypatch)
        peer_head = _commit_as_peer(state, "ghidra", _rename_foo)
        (tmp_path / "src" / "a" / "foo.c").write_text(_FOO + "// local edit\n", encoding="utf-8")

        result = _invoke(tmp_path, monkeypatch, "push", str(state), "--json")
        assert result.exit_code == 0, result.output
        assert _git(state, "rev-parse", "binsync/ghidra").stdout.strip() == peer_head
        assert _git(state, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "binsync/tester"
        assert 'user = "tester"' in (state / "metadata.toml").read_text(encoding="utf-8")

    def test_push_refuses_dirty_tree_on_another_branch(self, tmp_path: Path, monkeypatch) -> None:
        state = self._pushed(tmp_path, monkeypatch)
        _commit_as_peer(state, "ghidra", _rename_foo)
        (state / "metadata.toml").write_text('user = "ghidra"\nversion = "x"\n', encoding="utf-8")

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["binsync", "push", str(state), "--json"])
        assert result.exit_code != 0
        assert "uncommitted changes on binsync/ghidra" in str(result.exception)

    def test_pull_applies_peer_branch_once(self, tmp_path: Path, monkeypatch) -> None:
        state = self._pushed(tmp_path, monkeypatch)
        peer_head = _commit_as_peer(state, "ghidra", _rename_foo)
        _git(state, "checkout", "-q", "binsync/tester")

        first = _invoke(tmp_path, monkeypatch, "pull", str(state), "--json")
        assert first.exit_code == 0, first.output
        payload = json.loads(first.output)
        assert payload["peers"] == ["ghidra"]
        assert payload["applied_names"] == 1
        assert "int bar(void)" in (tmp_path / "src" / "a" / "bar.c").read_text(encoding="utf-8")

        second = _invoke(tmp_path, monkeypatch, "pull", str(state), "--json")
        assert second.exit_code == 0, second.output
        again = json.loads(second.output)
        applied = {k: v for k, v in again.items() if k.startswith("applied_") and v}
        assert applied == {}
        assert _git(state, "rev-parse", "binsync/ghidra").stdout.strip() == peer_head
        assert _git(state, "status", "--porcelain").stdout == ""


_INIT = "typedef void *LPVOID;\nint __cdecl Init(LPVOID param)\n{\n    return 0;\n}\n"


class TestPrototypePull:
    """A pulled prototype changes the source only when the types differ."""

    def _pushed(self, tmp_path: Path, monkeypatch: Any) -> tuple[Path, Path]:
        _make_project(tmp_path)
        source = tmp_path / "src" / "a" / "foo.c"
        source.write_text("// FUNCTION: A 0x401000\n// SIZE: 11\n" + _INIT, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        migrated = runner.invoke(app, ["source", "migrate-markers"], catch_exceptions=False)
        assert migrated.exit_code == 0, migrated.output
        state = tmp_path / "state"
        assert _invoke(tmp_path, monkeypatch, "init", str(state), "--user", "tester").exit_code == 0
        pushed = _invoke(tmp_path, monkeypatch, "push", str(state), "--json")
        assert pushed.exit_code == 0, pushed.output
        func = (state / "functions" / "00401000.toml").read_text(encoding="utf-8")
        assert 'type = "int __cdecl Init(LPVOID param)"' in func
        return state, source

    def _pull(self, tmp_path: Path, monkeypatch: Any, state: Path) -> dict[str, Any]:
        result = _invoke(tmp_path, monkeypatch, "pull", str(state), "--json")
        assert result.exit_code == 0, result.output
        return dict(json.loads(result.output))

    def test_equivalent_spelling_leaves_source_alone(self, tmp_path: Path, monkeypatch) -> None:
        state, source = self._pushed(tmp_path, monkeypatch)
        before = source.read_text(encoding="utf-8")
        _commit_as_peer(
            state,
            "ghidra",
            lambda s: _set_function(s, 0x401000, prototype="int __cdecl Init(void * ctx)"),
        )
        assert self._pull(tmp_path, monkeypatch, state)["applied_prototypes"] == 0
        assert source.read_text(encoding="utf-8") == before
        again = self._pull(tmp_path, monkeypatch, state)
        assert again["applied_prototypes"] == 0
        assert again["health"]["pending"]["pull"] == 0

    def test_ghidra_placeholder_types_are_not_applied(self, tmp_path: Path, monkeypatch) -> None:
        state, source = self._pushed(tmp_path, monkeypatch)
        before = source.read_text(encoding="utf-8")
        _commit_as_peer(
            state,
            "ghidra",
            lambda s: _set_function(s, 0x401000, prototype="undefined4 Init(undefined4 param_1)"),
        )
        assert self._pull(tmp_path, monkeypatch, state)["applied_prototypes"] == 0
        assert source.read_text(encoding="utf-8") == before

    def test_type_change_keeps_layout(self, tmp_path: Path, monkeypatch) -> None:
        state, source = self._pushed(tmp_path, monkeypatch)
        _commit_as_peer(
            state,
            "ghidra",
            lambda s: _set_function(s, 0x401000, prototype="int __cdecl Init(char * param)"),
        )
        assert self._pull(tmp_path, monkeypatch, state)["applied_prototypes"] == 1
        assert source.read_text(encoding="utf-8") == _INIT.replace("LPVOID param", "char * param")
        again = self._pull(tmp_path, monkeypatch, state)
        assert again["applied_prototypes"] == 0


class TestMissingDeclib:
    """Without the binsync extra every sync command exits 2 before writing."""

    @pytest.mark.parametrize(
        "argv",
        [
            ("binsync", "push"),
            ("binsync", "pull"),
            ("binsync", "summary"),
            ("binsync", "export"),
            ("binsync", "import"),
            ("binsync", "diff"),
            ("sync", "push", "--state-dir"),
            ("sync", "pull", "--state-dir"),
        ],
    )
    def test_exits_2_with_install_hint(
        self, tmp_path: Path, monkeypatch: Any, argv: tuple[str, ...]
    ) -> None:
        import sys

        _make_project(tmp_path)
        state = tmp_path / "state"
        state.mkdir()
        monkeypatch.setitem(sys.modules, "declib", None)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, [*argv, str(state), "--json"])
        assert result.exit_code == 2, result.output
        assert "declib is required" in json.loads(result.output)["error"]
        assert list(state.iterdir()) == []
