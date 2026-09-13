"""Tests for rebrew.workspace.config."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.workspace.config import (
    CONFIG_NAME,
    WorkspaceNotFound,
    db_dir,
    db_path,
    default_target,
    find_root,
    project_table,
    read_config,
    target_binary,
    target_marker,
    target_reversed_dir,
    targets_table,
    walk_up_to_root,
)

VALID_CONFIG = """
[project]
name = "demo"
default_target = "SERVER"

[targets.SERVER]
binary = "bin/server.exe"
marker = "SRV"

[targets.NP]
reversed_dir = "src/np"
"""


def write_config(root: Path, text: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / CONFIG_NAME
    path.write_text(text, encoding="utf-8")
    return path


def test_walk_up_to_root_finds_marker(tmp_path: Path) -> None:
    root = tmp_path / "project"
    write_config(root, VALID_CONFIG)
    nested = root / "src" / "deep"
    nested.mkdir(parents=True)
    assert walk_up_to_root(nested) == root.resolve()


def test_walk_up_to_root_includes_start(tmp_path: Path) -> None:
    root = tmp_path / "project"
    write_config(root, VALID_CONFIG)
    assert walk_up_to_root(root) == root.resolve()


def test_walk_up_to_root_without_marker(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    assert walk_up_to_root(tmp_path / "empty") is None


def test_find_root_explicit_start(tmp_path: Path) -> None:
    root = tmp_path / "project"
    write_config(root, VALID_CONFIG)
    assert find_root(root) == root.resolve()


def test_find_root_walks_up_from_start(tmp_path: Path) -> None:
    root = tmp_path / "project"
    write_config(root, VALID_CONFIG)
    nested = root / "src"
    nested.mkdir(parents=True)
    assert find_root(nested) == root.resolve()


def test_find_root_without_marker_raises(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(WorkspaceNotFound):
        find_root(tmp_path / "empty")


def test_workspace_not_found_is_file_not_found() -> None:
    assert issubclass(WorkspaceNotFound, FileNotFoundError)


def test_find_root_from_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "project"
    write_config(root, VALID_CONFIG)
    nested = root / "src"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert find_root() == root.resolve()


def test_read_config_valid(tmp_path: Path) -> None:
    write_config(tmp_path, VALID_CONFIG)
    assert project_table(read_config(tmp_path))["name"] == "demo"


def test_read_config_missing_file(tmp_path: Path) -> None:
    assert read_config(tmp_path) == {}


def test_read_config_invalid_toml(tmp_path: Path) -> None:
    write_config(tmp_path, "[project\nname = ")
    assert read_config(tmp_path) == {}


def test_read_config_invalid_utf8(tmp_path: Path) -> None:
    (tmp_path / CONFIG_NAME).write_bytes(b"[project]\nname = \xff\xfe\n")
    assert read_config(tmp_path) == {}


def test_read_config_directory_named_like_config(tmp_path: Path) -> None:
    (tmp_path / CONFIG_NAME).mkdir()
    assert read_config(tmp_path) == {}


def test_project_table_defaults(tmp_path: Path) -> None:
    assert project_table({}) == {}
    assert project_table({"project": "nope"}) == {}


def test_targets_table_drops_non_tables() -> None:
    config = {"targets": {"A": {"binary": "a"}, "B": "nope", 3: {"binary": "c"}}}
    assert targets_table(config) == {"A": {"binary": "a"}}
    assert targets_table({"targets": ["x"]}) == {}


def test_default_target_named() -> None:
    config = {"project": {"default_target": "B"}, "targets": {"A": {}, "B": {}}}
    assert default_target(config) == "B"


def test_default_target_unknown_name_falls_back_to_first() -> None:
    config = {"project": {"default_target": "Z"}, "targets": {"A": {}, "B": {}}}
    assert default_target(config) == "A"


def test_default_target_without_targets() -> None:
    assert default_target({}) is None
    assert default_target({"project": {"default_target": "A"}}) is None


def test_default_target_with_non_string_setting() -> None:
    config = {"project": {"default_target": 7}, "targets": {"A": {}}}
    assert default_target(config) == "A"


def test_target_marker_explicit() -> None:
    assert target_marker("SERVER", {"marker": "SRV"}) == "SRV"


def test_target_marker_derived() -> None:
    assert target_marker("server-1.0", {}) == "SERVER10"
    assert target_marker("NP", {"marker": "   "}) == "NP"
    assert target_marker("NP", {"marker": 5}) == "NP"


def test_target_reversed_dir_explicit(tmp_path: Path) -> None:
    entry = {"reversed_dir": "src/np"}
    assert target_reversed_dir(tmp_path, "NP", entry) == tmp_path / "src" / "np"


def test_target_reversed_dir_default(tmp_path: Path) -> None:
    assert target_reversed_dir(tmp_path, "NP", {}) == tmp_path / "src" / "NP"
    assert target_reversed_dir(tmp_path, "NP", {"reversed_dir": "  "}) == (tmp_path / "src" / "NP")


def test_target_binary_missing(tmp_path: Path) -> None:
    assert target_binary(tmp_path, {}) is None
    assert target_binary(tmp_path, {"binary": ""}) is None
    assert target_binary(tmp_path, {"binary": 7}) is None


def test_target_binary_relative_and_absolute(tmp_path: Path) -> None:
    assert target_binary(tmp_path, {"binary": "bin/server.exe"}) == (
        tmp_path / "bin" / "server.exe"
    )
    absolute = tmp_path / "elsewhere" / "server.exe"
    assert target_binary(tmp_path, {"binary": str(absolute)}) == absolute


def test_db_dir_default_and_override(tmp_path: Path) -> None:
    assert db_dir(tmp_path) == (tmp_path / "db").resolve()
    write_config(tmp_path, '[project]\ndb_dir = "artifacts/coverage"\n')
    assert db_dir(tmp_path) == (tmp_path / "artifacts" / "coverage").resolve()


def test_db_dir_empty_override_falls_back(tmp_path: Path) -> None:
    write_config(tmp_path, '[project]\ndb_dir = "  "\n')
    assert db_dir(tmp_path) == (tmp_path / "db").resolve()


def test_db_dir_invalid_config_falls_back(tmp_path: Path) -> None:
    write_config(tmp_path, "not toml =")
    assert db_dir(tmp_path) == (tmp_path / "db").resolve()


def test_db_path(tmp_path: Path) -> None:
    assert db_path(tmp_path) == (tmp_path / "db").resolve() / "coverage.db"
    write_config(tmp_path, '[project]\ndb_dir = "coverage"\n')
    assert db_path(tmp_path) == (tmp_path / "coverage").resolve() / "coverage.db"
