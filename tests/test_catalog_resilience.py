"""Error-handling tests for catalog loaders."""

from pathlib import Path

import pytest

from rebrew.catalog.loaders import load_ghidra_data_labels


class TestLoadGhidraDataLabelsResilience:
    def test_corrupt_json_warns_and_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "ghidra_data_labels.json").write_text("{not json", encoding="utf-8")

        with pytest.warns(UserWarning, match="Ignoring corrupt Ghidra data labels"):
            result = load_ghidra_data_labels(tmp_path)

        assert result == {}

    def test_wrong_json_shape_warns_and_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "ghidra_data_labels.json").write_text('{"labels": []}', encoding="utf-8")

        with pytest.warns(UserWarning, match="expected JSON array"):
            result = load_ghidra_data_labels(tmp_path)

        assert result == {}
