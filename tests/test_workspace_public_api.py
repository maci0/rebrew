"""The package's public surface is fully re-exported from the top level."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

import rebrew.workspace as workspace


def test_all_names_importable() -> None:
    assert workspace.__all__
    for name in workspace.__all__:
        assert getattr(workspace, name, None) is not None, name


def test_all_names_unique() -> None:
    assert len(workspace.__all__) == len(set(workspace.__all__))


def test_workspace_public_api_snapshot() -> None:
    """Gating: prevent accidental removal or breaking rename of workspace exports."""
    expected = {
        "CONFIG_NAME",
        "DEFAULT_DB_DIR",
        "DEFAULT_REVERSED_ROOT",
        "EARNED_STATUSES",
        "KNOWN_STATUSES",
        "MATCHED_STATUSES",
        "VA_MAX",
        "WorkspaceConfigError",
        "WorkspaceNotFound",
        "db_dir",
        "default_target",
        "find_root",
        "parse_va_candidates",
        "project_table",
        "read_config",
        "target_binary",
        "target_marker",
        "target_reversed_dir",
        "targets_table",
        "walk_up_to_root",
    }
    assert set(workspace.__all__) == expected


def test_workspace_without_compression_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in list(sys.modules):
        if name == "rebrew.workspace" or name.startswith("rebrew.workspace."):
            monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "zstandard", None)

    public = importlib.import_module("rebrew.workspace")
    for name in public.__all__:
        assert getattr(public, name, None) is not None, name
    (tmp_path / public.CONFIG_NAME).write_text("[project]\n", encoding="utf-8")
    assert public.find_root(tmp_path) == tmp_path
    assert public.read_config(tmp_path) == {"project": {}}


def test_submodules_import_without_rebrew_stack(monkeypatch: pytest.MonkeyPatch) -> None:
    # Drop any already-loaded rebrew modules so this asserts a cold import.
    for name in list(sys.modules):
        if name == "rebrew" or name.startswith("rebrew."):
            monkeypatch.delitem(sys.modules, name)

    before = set(sys.modules)
    for module in ("config", "status", "va"):
        mod = importlib.import_module(f"rebrew.workspace.{module}")
        assert mod.__name__ == f"rebrew.workspace.{module}"
    pulled = {
        name for name in set(sys.modules) - before if name == "rebrew" or name.startswith("rebrew.")
    }
    # workspace must stay free of the metadata / utils / registry stack.
    # rebrew.errors is allowed: a leaf module importing nothing, carrying the
    # RebrewError base WorkspaceNotFound inherits.
    assert pulled <= {
        "rebrew",
        "rebrew.errors",
        "rebrew.workspace",
        "rebrew.workspace.config",
        "rebrew.workspace.status",
        "rebrew.workspace.va",
    }, pulled
