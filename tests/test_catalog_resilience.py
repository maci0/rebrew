"""Error-handling tests for catalog loaders."""

lazy from pathlib import Path

import pytest

from rebrew.catalog.loaders import load_ghidra_data_labels


class TestLoadGhidraDataLabelsResilience:
    @pytest.mark.parametrize("filename", ["ghidra_data_labels.json", "ghidra_switchdata.json"])
    def test_non_utf8_export_warns_and_returns_empty(self, tmp_path: Path, filename: str) -> None:
        (tmp_path / filename).write_bytes(b"\xff")
        with pytest.warns(UserWarning, match="Ignoring corrupt Ghidra data labels"):
            assert load_ghidra_data_labels(tmp_path) == {}

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
