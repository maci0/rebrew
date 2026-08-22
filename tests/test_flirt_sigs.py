"""Tests for the FLIRT signature resolution (project dir + rebrew-flirt-sigs repo)."""

from __future__ import annotations

from pathlib import Path

from rebrew.flirt import _flirt_sigs_repo, _sig_files


def test_sig_files_dedup_project_wins(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    repo = tmp_path / "repo"
    proj.mkdir()
    repo.mkdir()
    (proj / "a.sig").write_bytes(b"x")
    (proj / "shared.pat").write_bytes(b"project")
    (repo / "shared.pat").write_bytes(b"repo")
    (repo / "b.pat").write_bytes(b"y")
    files = _sig_files([proj, repo])
    names = [f.name for f in files]
    assert "shared.pat" in names
    # the project copy wins (first dir)
    assert (proj / "shared.pat") in files
    assert len(names) == 3


def test_flirt_sigs_repo_env(monkeypatch) -> None:
    monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", "/tmp/sigs")
    assert _flirt_sigs_repo() == Path("/tmp/sigs")
    monkeypatch.delenv("REBREW_FLIRT_SIGS_DIR")
    assert _flirt_sigs_repo().name == "rebrew-flirt-sigs"
