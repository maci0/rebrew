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


@pytest.mark.parametrize(
    "cells_json",
    [
        "[]",
        '[{"start":4096,"end":4112,"span":16,"state":"EXACT","label":"café"}]',
    ],
)
def test_section_cells_codec_round_trip(cells_json: str) -> None:
    blob = workspace.encode_section_cells(cells_json)
    assert isinstance(blob, bytes)
    assert workspace.decode_section_cells(blob) == cells_json


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
    assert public.db_path(tmp_path) == tmp_path / "db" / "coverage.db"
    assert public.read_db_version(public.db_path(tmp_path)) is None
    with pytest.raises(ModuleNotFoundError) as encode_error:
        public.encode_section_cells("[]")
    assert encode_error.value.name == "zstandard"
    with pytest.raises(ModuleNotFoundError) as decode_error:
        public.decode_section_cells(b"")
    assert decode_error.value.name == "zstandard"


def test_submodules_import_without_rebrew_stack(monkeypatch: pytest.MonkeyPatch) -> None:
    # Drop any already-loaded rebrew modules so this asserts a cold import.
    for name in list(sys.modules):
        if name == "rebrew" or name.startswith("rebrew."):
            monkeypatch.delitem(sys.modules, name)

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
