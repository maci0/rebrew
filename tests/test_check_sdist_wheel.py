"""Contract for tools/check_sdist_wheel.py — the sdist-completeness gate.

The package job smoke-installs the wheel; nothing else proved the sdist
carried the same runtime files. These pin the comparator's behavior so the
gate cannot pass vacuously.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from tools.check_sdist_wheel import diff_members, main, wheel_members


def _wheel(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name in names:
            zf.writestr(name, b"x")
    return path


class TestCheckSdistWheel:
    def test_identical_member_sets_pass(self, tmp_path: Path, capsys: object) -> None:
        names = ["rebrew/__init__.py", "rebrew-1.0.dist-info/RECORD"]
        shipped = _wheel(tmp_path / "shipped.whl", names)
        from_sdist = _wheel(tmp_path / "from_sdist.whl", names)
        assert main(["check_sdist_wheel.py", str(shipped), str(from_sdist)]) == 0

    def test_directory_entries_are_ignored(self, tmp_path: Path) -> None:
        """Only payload files are part of the contract; setuptools emits
        directory entries on some build paths and not others."""
        shipped = _wheel(tmp_path / "a.whl", ["rebrew/__init__.py", "rebrew/"])
        from_sdist = _wheel(tmp_path / "b.whl", ["rebrew/__init__.py"])
        assert wheel_members(shipped) == wheel_members(from_sdist) == {"rebrew/__init__.py"}

    def test_file_dropped_by_the_sdist_fails(self, tmp_path: Path) -> None:
        shipped = _wheel(tmp_path / "a.whl", ["rebrew/__init__.py", "rebrew/AGENTS.md.template"])
        from_sdist = _wheel(tmp_path / "b.whl", ["rebrew/__init__.py"])
        assert main(["check_sdist_wheel.py", str(shipped), str(from_sdist)]) == 1
        problems = diff_members(wheel_members(shipped), wheel_members(from_sdist))
        assert problems == ["missing from the sdist-built wheel: rebrew/AGENTS.md.template"]

    def test_extra_sdist_member_fails(self, tmp_path: Path) -> None:
        shipped = _wheel(tmp_path / "a.whl", ["rebrew/__init__.py"])
        from_sdist = _wheel(tmp_path / "b.whl", ["rebrew/__init__.py", "rebrew/stale.py"])
        assert main(["check_sdist_wheel.py", str(shipped), str(from_sdist)]) == 1
        problems = diff_members(wheel_members(shipped), wheel_members(from_sdist))
        assert problems == ["only in the sdist-built wheel: rebrew/stale.py"]

    def test_missing_wheel_is_an_error_not_a_pass(self, tmp_path: Path) -> None:
        shipped = _wheel(tmp_path / "a.whl", ["rebrew/__init__.py"])
        try:
            wheel_members(tmp_path / "absent.whl")
        except FileNotFoundError as exc:
            assert "absent.whl" in str(exc)
        else:
            raise AssertionError("a missing wheel must not read as an empty, passing set")
        assert shipped.is_file()

    def test_wrong_argument_count_exits_2(self) -> None:
        assert main(["check_sdist_wheel.py", "only-one"]) == 2
