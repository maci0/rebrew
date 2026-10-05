"""Tests for the `rebrew dev refactor` heuristic scanner.

Methodology: `_make_suggestions` and `_analyse_file` are pure functions over
text, so they are exercised directly against hand-built sources at each
threshold boundary (500 lines, 10 for-loops, 5 while-loops, one TODO). The
command is then driven through its Typer app to pin the `--min-lines` filter
and the JSON shape, which are the only parts a caller can observe.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner, Result

from rebrew import refactor
from rebrew.refactor import _analyse_file, _collect_python_files, _make_suggestions

# --- suggestion heuristics --------------------------------------------------

_TOO_LONG = "Consider splitting this module into smaller, focused files."
_TYPING = "Add `from __future__ import annotations` and complete type hints."
_CLEAN = "No obvious refactoring triggers detected by this simple heuristic."


def test_clean_source_gets_the_no_triggers_fallback() -> None:
    assert _make_suggestions(False, 0, False, 0, 0) == [_CLEAN]


def test_each_trigger_contributes_its_own_suggestion() -> None:
    suggestions = _make_suggestions(True, 2, True, 11, 6)
    assert _TOO_LONG in suggestions
    assert _TYPING in suggestions
    assert any("2 TODO" in s for s in suggestions)
    assert any("for-loops" in s for s in suggestions)
    assert any("while loops" in s for s in suggestions)


def test_suggestions_follow_their_own_thresholds() -> None:
    """A single for-loop is not "many"; the 11th is. The two loop counters
    must not share a bound."""
    assert not any("for-loops" in s for s in _make_suggestions(False, 0, False, 10, 0))
    assert any("for-loops" in s for s in _make_suggestions(False, 0, False, 11, 0))
    assert not any("while loops" in s for s in _make_suggestions(False, 0, False, 0, 5))
    assert any("while loops" in s for s in _make_suggestions(False, 0, False, 0, 6))


# --- per-file analysis ------------------------------------------------------


def _write(root: Path, body: str) -> Path:
    path = root / "mod.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_counts_are_reported_relative_to_root(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "from __future__ import annotations\n"
        "for a in x:\n    pass\n"
        "  for b in y:\n    pass\n"
        "while z:\n    pass\n"
        "# TODO: later\n",
    )
    info = _analyse_file(path, tmp_path)
    assert info["file"] == "mod.py"
    assert info["lines"] == 8
    assert info["for_loops"] == 2
    assert info["while_loops"] == 1
    assert info["todos"] == 1
    assert info["missing_typing"] is False
    assert info["too_long"] is False


def test_for_loop_counter_needs_the_stripped_prefix(tmp_path: Path) -> None:
    """`    for ...` is still a for-loop; a `for` inside a string is not."""
    path = _write(tmp_path, "text = 'for x in y:'\n    for a in z:\n    pass\n")
    assert _analyse_file(path, tmp_path)["for_loops"] == 1


def test_missing_typing_tracks_the_future_import(tmp_path: Path) -> None:
    """A module carrying the future import is never reported; a bare one is.
    The second escape hatch in the heuristic is a bare ``": ["`` substring,
    so it is deliberately not exercised as an annotation."""
    imported = _write(tmp_path, "from __future__ import annotations\ndef f():\n    return 1\n")
    assert _analyse_file(imported, tmp_path)["missing_typing"] is False
    bare = _write(tmp_path, "def f() -> int:\n    return 1\n")
    assert _analyse_file(bare, tmp_path)["missing_typing"] is True


def test_too_long_is_strictly_above_500_lines(tmp_path: Path) -> None:
    at_limit = _write(tmp_path, "x = 1\n" * 500)
    assert _analyse_file(at_limit, tmp_path)["too_long"] is False
    over = _write(tmp_path, "x = 1\n" * 501)
    assert _analyse_file(over, tmp_path)["too_long"] is True


def test_unreadable_file_is_reported_not_raised(tmp_path: Path) -> None:
    """A file that cannot be read yields an error entry; a missing one does
    not abort the whole scan.

    The read failure comes from a directory named `mod.py`, not from chmod
    0o000: root bypasses the permission bits, so the chmod version asserted
    nothing on the usual CI container.
    """
    path = tmp_path / "mod.py"
    path.mkdir()
    info = _analyse_file(path, tmp_path)
    assert "cannot read" in info["error"]
    assert "too_long" not in info


def test_a_readable_file_reports_no_error(tmp_path: Path) -> None:
    """The other side of the boundary: an error key appears only when the
    read actually failed."""
    path = _write(tmp_path, "x = 1\n")
    info = _analyse_file(path, tmp_path)
    assert "error" not in info
    assert info["file"] == "mod.py"


# --- file collection --------------------------------------------------------


def test_collect_is_sorted_and_spans_both_trees(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    for rel in ("src/b.py", "src/a.py", "src/nested/c.py", "tests/t.py", "src/notes.md"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
    found = _collect_python_files(tmp_path)
    assert [p.relative_to(tmp_path).as_posix() for p in found] == [
        "src/a.py",
        "src/b.py",
        "src/nested/c.py",
        "tests/t.py",
    ]


# --- command ----------------------------------------------------------------


class TestRefactorCommand:
    @staticmethod
    def _run(root: Path, *args: str) -> Result:
        return CliRunner().invoke(refactor.app, ["--repository", str(root), *args])

    def _tree(self, tmp_path: Path) -> Path:
        src = tmp_path / "src"
        src.mkdir()
        (src / "small.py").write_text("x = 1\n" * 10, encoding="utf-8")
        (src / "big.py").write_text("x = 1\n" * 300, encoding="utf-8")
        return tmp_path

    def test_min_lines_filter_drops_short_files(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        result = self._run(root, "--min-lines", "200", "--json")
        assert result.exit_code == 0
        files = json.loads(result.stdout)["files"]
        assert [f["file"] for f in files] == ["src/big.py"]
        assert files[0]["lines"] == 300

    def test_json_applies_the_default_min_lines(self, tmp_path: Path) -> None:
        """The default floor is 200 lines, so a 10-line module is not reported."""
        root = self._tree(tmp_path)
        result = self._run(root, "--json")
        assert result.exit_code == 0
        files = json.loads(result.stdout)["files"]
        assert [f["file"] for f in files] == ["src/big.py"]

    def test_min_lines_zero_reports_every_file(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        result = self._run(root, "--min-lines", "0", "--json")
        assert result.exit_code == 0
        files = json.loads(result.stdout)["files"]
        assert {f["file"] for f in files} == {"src/big.py", "src/small.py"}

    def test_table_output_names_the_files(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        result = self._run(root, "--min-lines", "200")
        assert result.exit_code == 0
        assert "big.py" in result.output
        assert "small.py" not in result.output


def test_missing_repository_is_reported(tmp_path: Path) -> None:
    """A missing Python checkout fails before scanning, without project config."""
    result = CliRunner().invoke(refactor.app, ["--repository", str(tmp_path / "missing"), "--json"])
    assert result.exit_code == 2
    assert "does not exist" in result.output
