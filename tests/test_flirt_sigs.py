"""Tests for the FLIRT signature resolution (project dir + recondb repo)."""

from __future__ import annotations

import json
import os
from typing import Any
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


# recondb 3.0.0's sigs/index.json (schema_version 3) keys each file by its path relative to sigs/, and
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


def _checkout(tmp_path: Path, files: dict[str, str], schema_version: int | str | None = 3) -> Path:
    """A recondb-shaped checkout: one pattern in gcc/x86/lib.pat, two in gcc/arm/lib.pat."""
    import json

    repo = tmp_path / "recondb"
    _pat(repo / "sigs" / "gcc" / "x86" / "lib.pat", 1)
    _pat(repo / "sigs" / "gcc" / "arm" / "lib.pat", 2)
    index: dict[str, object] = {"files": {key: {"arch": arch} for key, arch in files.items()}}
    if schema_version is not None:
        index["schema_version"] = schema_version
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


@pytest.mark.parametrize(
    ("files", "schema_version"),
    [
        ({"lib.pat": "x86"}, None),  # recondb 1.x: keyed by file name
        (_BOTH, None),  # recondb 2.0.0: keyed by path, no version member
        (_BOTH, 2),
        (_BOTH, 4),
        (_BOTH, "3"),
    ],
    ids=["names", "paths-2.0.0", "version-2", "version-4", "version-text"],
)
def test_an_index_of_another_format_is_refused_with_the_release_it_needs(
    tmp_path: Path, files: dict[str, str], schema_version: int | str | None
) -> None:
    """Only schema_version 3 is read; its absence or any other value is not guessed at."""
    repo = _checkout(tmp_path, files, schema_version)
    with pytest.raises(ConfigError, match=r"recondb 3\.0\.0 or later"):
        flirt.load_signatures_for([repo], "x86")


def test_a_file_its_checkouts_index_does_not_list_is_not_loaded(tmp_path: Path) -> None:
    repo = _checkout(tmp_path, {"gcc/x86/lib.pat": "x86"})
    assert flirt.load_signatures_for([repo], "arm") == []
    assert len(flirt.load_signatures_for([repo], "x86")) == 1


def test_a_file_the_index_lists_but_the_checkout_lacks_is_reported_unreadable(
    tmp_path: Path,
) -> None:
    repo = _checkout(tmp_path, {**_BOTH, "gcc/x86/gone.pat": "x86"})
    with pytest.warns(UserWarning, match="Error loading .*gone.pat"):
        assert len(flirt.load_signatures_for([repo], "x86")) == 1


#: Files the walk-guard checkout lists: a load answered from its index costs the same few stats at any count.
_LISTED = 40


def test_a_load_from_an_index_walks_no_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The index is the checkout's list of what it ships: a load reads it once and walks nothing."""
    import os

    repo = _checkout(tmp_path, _BOTH)
    listed = dict(_BOTH)
    for i in range(_LISTED):
        key = f"gcc/x86/extra{i}.pat"
        _pat(repo / "sigs" / key, 1)
        listed[key] = "x86"
    (repo / "sigs" / "index.json").write_text(
        json.dumps({"schema_version": 3, "files": {k: {"arch": a} for k, a in listed.items()}}),
        encoding="utf-8",
    )
    walks: list[str] = []
    stats: list[str] = []
    real_scandir, real_stat = os.scandir, os.stat

    def scandir(*args: Any) -> Any:
        walks.append(str(args))
        return real_scandir(*args)

    def stat(*args: Any, **kwargs: Any) -> os.stat_result:
        stats.append(str(args[0]))
        return real_stat(*args, **kwargs)

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(os, "stat", stat)
    assert len(flirt.load_signatures_for([repo], "x86")) == 1 + _LISTED
    assert walks == []
    assert len(stats) < _LISTED, stats


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
    """Against a real recondb 2.0.0 tree: every indexed file is found, and the files a
    scan selects for x86 are the ones the index lists as x86 or unknown."""
    import json

    repo = Path(os.environ["REBREW_FLIRT_SIGS_DIR"])
    index = json.loads((repo / "sigs" / "index.json").read_text(encoding="utf-8"))["files"]
    # The selection, not the parse: twelve million patterns do not belong in a test.
    monkeypatch.setattr(flirt, "_parse_sig_files", lambda files: files)
    selected = flirt.load_signatures_for([repo], "x86")
    assert len(flirt.signature_files([repo])) == len(index)
    assert len(selected) == sum(1 for meta in index.values() if meta["arch"] in ("", "x86"))


def test_init_signatures_moves_copies_the_checkout_renamed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project copy at a key recondb 3.0.0 renamed moves to the new key once."""
    from types import SimpleNamespace

    repo = _checkout(tmp_path, {"gcc/x86/lib-2.pat": "x86", "gcc/arm/lib.pat": "arm"})
    (repo / "sigs" / "gcc" / "x86" / "lib.pat").rename(repo / "sigs" / "gcc" / "x86" / "lib-2.pat")
    (repo / "docs").mkdir()
    (repo / "docs" / "renamed-3.0.0.tsv").write_text(
        "# old\tnew\ngcc/x86/lib.pat\tgcc/x86/lib-2.pat\n", encoding="utf-8"
    )
    project = tmp_path / "project"
    _pat(project / "flirt_sigs" / "gcc" / "x86" / "lib.pat", 1)
    monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", str(repo))
    flirt._init_project_sigs(SimpleNamespace(root=project), json_output=True)
    copies = sorted(
        p.relative_to(project / "flirt_sigs").as_posix()
        for p in (project / "flirt_sigs").rglob("*.pat")
    )
    assert copies == ["gcc/arm/lib.pat", "gcc/x86/lib-2.pat"]
