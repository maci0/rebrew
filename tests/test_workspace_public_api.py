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
    import sys

    # Drop any already-loaded rebrew modules so this asserts a cold import.
    for name in list(sys.modules):
        if name == "rebrew" or name.startswith("rebrew."):
            del sys.modules[name]

    before = set(sys.modules)
    for module in ("config", "db", "status", "va"):
        mod = importlib.import_module(f"rebrew.workspace.{module}")
        assert mod.__name__ == f"rebrew.workspace.{module}"
    pulled = {
        name for name in set(sys.modules) - before if name == "rebrew" or name.startswith("rebrew.")
    }
    # workspace must stay free of the metadata / utils / registry stack.
    assert pulled <= {
        "rebrew",
        "rebrew.workspace",
        "rebrew.workspace.config",
        "rebrew.workspace.db",
        "rebrew.workspace.status",
        "rebrew.workspace.va",
    }, pulled
