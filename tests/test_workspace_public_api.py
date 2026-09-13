"""The package's public surface is fully re-exported from the top level."""

from __future__ import annotations

import importlib

import rebrew.workspace as workspace


def test_all_names_importable() -> None:
    assert workspace.__all__
    for name in workspace.__all__:
        assert getattr(workspace, name, None) is not None, name


def test_all_names_unique() -> None:
    assert len(workspace.__all__) == len(set(workspace.__all__))


def test_submodules_import_without_rebrew_stack() -> None:
    for module in ("config", "db", "status", "va"):
        importlib.import_module(f"rebrew.workspace.{module}")
