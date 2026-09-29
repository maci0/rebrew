"""Tests for the FLIRT signature resolution (project dir + rebrew-flirt-sigs repo)."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew import flirt
from rebrew.config import ConfigError
from rebrew.flirt import NO_SIGS_CHECKOUT, _flirt_sigs_repo, _sig_files


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


def test_flirt_sigs_repo_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sigs = tmp_path / "sigs"
    sigs.mkdir()
    monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", str(sigs))
    assert _flirt_sigs_repo() == sigs
    monkeypatch.delenv("REBREW_FLIRT_SIGS_DIR")
    assert _flirt_sigs_repo().name == "rebrew-flirt-sigs"


def test_flirt_sigs_repo_wheel_install(monkeypatch: pytest.MonkeyPatch) -> None:
    """A wheel install has no checkout beside it, and no sibling guess.

    The path used to come from ``parents[2]`` of this module, which in a wheel
    install is the interpreter's ``lib/python3.X``, so the sig dir pointed at
    a system ``lib`` that may or may not hold an unrelated directory of the
    same name.
    """
    monkeypatch.delenv("REBREW_FLIRT_SIGS_DIR", raising=False)
    monkeypatch.setattr(flirt, "SOURCE_CHECKOUT", None)
    assert _flirt_sigs_repo() == NO_SIGS_CHECKOUT
    assert not _flirt_sigs_repo().is_absolute()


def test_flirt_sigs_repo_checkout_sibling(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """From a source checkout the sigs come from the sibling directory."""
    monkeypatch.delenv("REBREW_FLIRT_SIGS_DIR", raising=False)
    monkeypatch.setattr(flirt, "SOURCE_CHECKOUT", tmp_path / "rebrew")
    assert _flirt_sigs_repo() == tmp_path / "rebrew-flirt-sigs"


def test_flirt_sigs_repo_env_typo_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A mistyped dir must be reported, not silently drop every stdlib sig."""
    monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", str(tmp_path / "typo"))
    with pytest.raises(ConfigError, match="REBREW_FLIRT_SIGS_DIR=.* is not a directory"):
        _flirt_sigs_repo()


def test_flirt_sigs_repo_env_expands_tilde(monkeypatch: pytest.MonkeyPatch) -> None:
    """A quoted ``~`` in a direnv-style export is expanded before the check."""
    monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", "~/sigs")
    monkeypatch.setenv("HOME", "/home/analyst")
    with pytest.raises(ConfigError, match="/home/analyst/sigs"):
        _flirt_sigs_repo()
