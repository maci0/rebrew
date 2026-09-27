"""Contract for tools/render_skills.py — the .agents/skills renderer.

``make gen-skills`` used to be a ``cp -r`` plus ``sed -i`` pipeline.  Those
depend on GNU-only sed, on find's traversal order, and on nothing failing
between the copy and the substitution, and a drifted render was only caught
later by tests/test_skills_sync.py.  These pin the renderer's own behavior so
the target regenerates the same bytes every time and names what drifted.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import tools.render_skills as rs
from tools.render_skills import PLACEHOLDER, RENDER_TARGET, render, rendered_tree

_SRC = Path("src/rebrew/agent-skills")


def _main(*args: str) -> int:
    """Run the CLI with *args* as argv, leaving the caller's argv untouched."""
    argv = sys.argv
    sys.argv = ["render_skills.py", *args]
    try:
        return rs.main()
    finally:
        sys.argv = argv


class TestRender:
    def test_placeholder_is_substituted(self) -> None:
        assert render(Path("a/SKILL.md"), f"target {PLACEHOLDER}\n".encode()) == (
            f"target {RENDER_TARGET}\n".encode()
        )

    def test_binary_assets_are_copied_verbatim(self) -> None:
        """Only prose carries the placeholder; a binary asset must not be decoded."""
        blob = b"\x00\xff<target>\x80"
        assert render(Path("a/logo.png"), blob) == blob

    def test_utf8_survives_the_round_trip(self) -> None:
        text = "café <target> — ✓\n"
        assert (
            render(Path("a/SKILL.md"), text.encode())
            == text.replace(PLACEHOLDER, RENDER_TARGET).encode()
        )

    def test_absent_placeholder_is_a_no_op(self) -> None:
        assert render(Path("a/SKILL.md"), b"nothing to do\n") == b"nothing to do\n"


class TestRenderedTree:
    def test_matches_the_checked_in_tree(self) -> None:
        """``--check`` on the real tree must pass, or the target is a no-op lie."""
        assert _main("--check") == 0

    def test_names_are_sorted(self) -> None:
        """Insertion order must not follow the filesystem's readdir order."""
        names = list(rendered_tree())
        assert names == sorted(names)


class TestCheckMode:
    def test_drift_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(rs, "DEST", tmp_path / "skills")
        assert _main() == 0
        (rs.DEST / "rebrew-workflow" / "SKILL.md").write_text("drifted\n", encoding="utf-8")
        assert _main("--check") == 1
        assert "stale or missing" in capsys.readouterr().err

    def test_leftover_file_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A renamed skill must not leave its old render behind unnoticed."""
        monkeypatch.setattr(rs, "DEST", tmp_path / "skills")
        assert _main() == 0
        (rs.DEST / "renamed-away").mkdir(parents=True)
        (rs.DEST / "renamed-away" / "SKILL.md").write_text("x\n", encoding="utf-8")
        assert _main("--check") == 1
        assert "not in the packaged tree" in capsys.readouterr().err

    def test_write_replaces_the_whole_tree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stale file must not survive a regeneration."""
        monkeypatch.setattr(rs, "DEST", tmp_path / "skills")
        stale = rs.DEST / "gone" / "SKILL.md"
        stale.parent.mkdir(parents=True)
        stale.write_text("old\n", encoding="utf-8")
        assert _main() == 0
        assert not stale.exists(), "gen-skills left a file the packaged tree no longer has"
        assert _main("--check") == 0


class TestMissingSource:
    def test_missing_packaged_tree_fails_loud(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(rs, "SRC", tmp_path / "absent")
        with pytest.raises(SystemExit):
            _main()
