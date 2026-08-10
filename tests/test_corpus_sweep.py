"""Tests for tools/corpus_sweep.py — the corpus-wide smoke sweep."""

from __future__ import annotations

from pathlib import Path

from tools.corpus_sweep import check_project, discover_projects, is_skipped


def _make_project(root: Path, name: str, toml: bool = True) -> Path:
    p = root / name
    p.mkdir()
    if toml:
        (p / "rebrew-project.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    return p


class TestDiscover:
    def test_finds_only_toml_projects(self, tmp_path: Path) -> None:
        _make_project(tmp_path, "a-rebrew")
        _make_project(tmp_path, "b-rebrew", toml=False)
        _make_project(tmp_path, "not-a-project")
        assert discover_projects(tmp_path) == [tmp_path / "a-rebrew"]


class TestIsSkipped:
    def test_skipped_marker_detected(self, tmp_path: Path) -> None:
        p = _make_project(tmp_path, "s-rebrew")
        (p / "AGENTS.md").write_text(
            "# Status: SKIPPED (not a decomp target)\n\nInstallShield stub.\n",
            encoding="utf-8",
        )
        assert is_skipped(p)

    def test_normal_project_not_skipped(self, tmp_path: Path) -> None:
        p = _make_project(tmp_path, "n-rebrew")
        (p / "AGENTS.md").write_text("# Status: ACTIVE\n\nReal game binary.\n", encoding="utf-8")
        assert not is_skipped(p)

    def test_no_agents_not_skipped(self, tmp_path: Path) -> None:
        assert not is_skipped(_make_project(tmp_path, "m-rebrew"))


class TestCheckProject:
    def test_failing_command_reported(self, tmp_path: Path, monkeypatch) -> None:
        """A non-zero exit or non-JSON stdout marks the command failed."""
        import os

        import tools.corpus_sweep as sweep

        # Fake `rebrew` on PATH: doctor fails, everything else JSON.
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "rebrew").write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "  doctor) echo 'not json'; exit 1 ;;\n"
            "  *) echo '{\"ok\": true}'; exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        (bin_dir / "rebrew").chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")

        project = _make_project(tmp_path, "p-rebrew")
        results = check_project("rebrew", project)
        assert len(results) == len(sweep._COMMANDS)
        doctor = results[0]
        assert doctor[1] != 0  # exit 1 → failure
        # The rest pass with valid JSON.
        assert all(code == 0 for _, code, _ in results[1:])


class TestIsSkippedBlocked:
    def test_documented_toolchain_blocker_skipped(self, tmp_path: Path) -> None:
        p = _make_project(tmp_path, "d-rebrew")
        (p / "AGENTS.md").write_text(
            "# Status: BLOCKED (toolchain)\n\nBorland Delphi 2 binary — no profile can match.\n",
            encoding="utf-8",
        )
        assert is_skipped(p)

    def test_blocked_without_family_not_skipped(self, tmp_path: Path) -> None:
        p = _make_project(tmp_path, "e-rebrew")
        (p / "AGENTS.md").write_text(
            "# Status: BLOCKED (waiting on assets)\n\nNo family mentioned.\n",
            encoding="utf-8",
        )
        assert not is_skipped(p)
