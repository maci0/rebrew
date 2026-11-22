"""Tests for the FLIRT signature resolution (project dir + recondb repo)."""

from __future__ import annotations

import os
lazy from pathlib import Path

import pytest

from rebrew import flirt
from rebrew.config import ConfigError
from rebrew.flirt import NO_SIGS_CHECKOUT, _flirt_sigs_repo, signature_files


def test_sig_files_dedup_project_wins(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    repo = tmp_path / "repo"
    proj.mkdir()
    repo.mkdir()
    (proj / "a.sig").write_bytes(b"x")
    (proj / "shared.pat").write_bytes(b"project")
    (repo / "shared.pat").write_bytes(b"repo")
    (repo / "b.pat").write_bytes(b"y")
    files = signature_files([proj, repo])
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
    assert _flirt_sigs_repo().name == "recondb"


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
    assert _flirt_sigs_repo() == tmp_path / "recondb"


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


# recondb 1.17.0's sigs/index.json keys each file by its path relative to sigs/, and
# a scan loads one file per stem in each directory, the .sig preferred.

_BOTH = {"gcc/x86/lib.pat": "x86", "gcc/arm/lib.pat": "arm"}


def _pat(path: Path, patterns: int) -> None:
    from rebrew.gen_flirt_pat import bytes_to_pat_line

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        bytes_to_pat_line(f"_f{i}", bytes((i + j) % 256 for j in range(40)), set())
        for i in range(patterns)
    ]
    path.write_text("\n".join([*lines, "---"]) + "\n", encoding="utf-8")


def _checkout(tmp_path: Path, files: dict[str, str]) -> Path:
    """A recondb-shaped checkout: one pattern in gcc/x86/lib.pat, two in gcc/arm/lib.pat."""
    import json

    repo = tmp_path / "recondb"
    _pat(repo / "sigs" / "gcc" / "x86" / "lib.pat", 1)
    _pat(repo / "sigs" / "gcc" / "arm" / "lib.pat", 2)
    index = {"files": {key: {"arch": arch} for key, arch in files.items()}}
    (repo / "sigs" / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return repo


@pytest.mark.parametrize(("arch", "loaded"), [("x86", 1), ("arm", 2), ("", 3)])
def test_two_files_of_one_name_each_load_for_their_own_architecture(
    tmp_path: Path, arch: str, loaded: int
) -> None:
    assert len(flirt.load_signatures_for([_checkout(tmp_path, _BOTH)], arch)) == loaded


def test_one_file_per_stem_per_directory_with_the_sig_preferred(tmp_path: Path) -> None:
    repo = _checkout(tmp_path, _BOTH)
    (repo / "sigs" / "gcc" / "x86" / "lib.sig").write_bytes(b"compiled")
    files = flirt.signature_files([repo])
    assert sorted(f.relative_to(repo / "sigs").as_posix() for f in files) == [
        "gcc/arm/lib.pat",
        "gcc/x86/lib.sig",
    ]


def test_an_index_keyed_by_file_name_is_refused_with_the_release_it_needs(
    tmp_path: Path,
) -> None:
    """recondb before 1.17.0 keyed by name, which cannot tell the two lib.pat apart."""
    repo = _checkout(tmp_path, {"lib.pat": "x86"})
    with pytest.raises(ConfigError, match=r"recondb 1\.17\.0 or later"):
        flirt.load_signatures_for([repo], "x86")


def test_a_file_its_checkouts_index_does_not_list_is_not_loaded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _checkout(tmp_path, {"gcc/x86/lib.pat": "x86"})
    assert flirt.load_signatures_for([repo], "arm") == []
    assert "not in its index.json and were not loaded (first: gcc/arm/lib.pat)" in " ".join(
        capsys.readouterr().err.split()
    )
    assert len(flirt.load_signatures_for([repo], "x86")) == 1


def test_a_directory_without_an_index_loads_every_file(tmp_path: Path) -> None:
    own = tmp_path / "flirt_sigs"
    _pat(own / "mine.pat", 1)
    _pat(own / "sub" / "mine.pat", 2)
    assert len(flirt.load_signatures_for([own], "x86")) == 3


def test_a_project_copy_takes_the_checkouts_index_by_its_key(tmp_path: Path) -> None:
    """init-signatures copies a file under its key, so the checkout's index filters the copy."""
    repo = _checkout(tmp_path, _BOTH)
    project = tmp_path / "flirt_sigs"
    _pat(project / "gcc" / "arm" / "lib.pat", 3)
    # The project's copy wins over the checkout's file and is skipped for x86 the same.
    assert len(flirt.load_signatures_for([project, repo], "x86")) == 1
    assert len(flirt.load_signatures_for([project, repo], "arm")) == 3


def test_init_signatures_copies_two_files_of_one_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    repo = _checkout(tmp_path, _BOTH)
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", str(repo))
    flirt._init_project_sigs(SimpleNamespace(root=project), json_output=True)
    copied = sorted(
        p.relative_to(project / "flirt_sigs").as_posix()
        for p in (project / "flirt_sigs").rglob("*.pat")
    )
    assert copied == ["gcc/arm/lib.pat", "gcc/x86/lib.pat"]


@pytest.mark.skipif(
    not os.environ.get("REBREW_FLIRT_SIGS_DIR"),
    reason="REBREW_FLIRT_SIGS_DIR names no recondb checkout",
)
def test_a_recondb_checkout_loads_for_an_architecture_what_its_index_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Against a real recondb 1.17.0 tree: every indexed file is found, and the files a
    scan selects for x86 are the ones the index lists as x86 or unknown."""
    import json

    repo = Path(os.environ["REBREW_FLIRT_SIGS_DIR"])
    index = json.loads((repo / "sigs" / "index.json").read_text(encoding="utf-8"))["files"]
    # The selection, not the parse: twelve million patterns do not belong in a test.
    monkeypatch.setattr(flirt, "_parse_sig_files", lambda files: files)
    selected = flirt.load_signatures_for([repo], "x86")
    assert len(flirt.signature_files([repo])) == len(index)
    assert len(selected) == sum(1 for meta in index.values() if meta["arch"] in ("", "x86"))
