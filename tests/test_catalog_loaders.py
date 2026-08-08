"""Tests for catalog/loaders.py — Ghidra JSON, function lists, data labels, bytes."""

import json
import warnings
from pathlib import Path

import pytest

from rebrew.catalog.loaders import (
    _classify_ghidra_label,
    load_function_structure,
    load_ghidra_data_labels,
    parse_function_list,
)


class TestLoadFunctionStructure:
    def test_missing_returns_empty(self, tmp_path: Path) -> None:
        assert load_function_structure(tmp_path / "nope.json") == []

    def test_valid(self, tmp_path: Path) -> None:
        p = tmp_path / "function_structure.json"
        p.write_text(json.dumps([{"va": "0x10001000", "size": 64, "name": "a"}]), encoding="utf-8")
        entries = load_function_structure(p)
        assert len(entries) == 1
        assert entries[0].va == 0x10001000
        assert entries[0].size == 64

    def test_non_list_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "function_structure.json"
        p.write_text(json.dumps({"va": 1}), encoding="utf-8")
        with pytest.raises(ValueError, match="Expected a JSON array"):
            load_function_structure(p)

    def test_corrupt_json_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "function_structure.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(ValueError, match="Corrupt structure JSON"):
            load_function_structure(p)


class TestClassifyGhidraLabel:
    def test_thunk(self) -> None:
        assert _classify_ghidra_label("thunk_FUN_1000") == "thunk"

    def test_data(self) -> None:
        assert _classify_ghidra_label("switchdataD_1000") == "data"
        assert _classify_ghidra_label("") == "data"


class TestLoadGhidraDataLabels:
    def test_missing_returns_empty(self, tmp_path: Path) -> None:
        assert load_ghidra_data_labels(tmp_path) == {}

    def test_none_src_dir(self) -> None:
        assert load_ghidra_data_labels(None) == {}

    def test_new_format_with_thunk_classification(self, tmp_path: Path) -> None:
        (tmp_path / "ghidra_data_labels.json").write_text(
            json.dumps(
                [
                    {"va": 0x10002000, "size": 4, "label": "g_thing"},
                    {"va": 0x10003000, "size": 6, "label": "thunk_FUN_3000"},
                ]
            ),
            encoding="utf-8",
        )
        labels = load_ghidra_data_labels(tmp_path)
        assert labels[0x10002000].state == "data"
        assert labels[0x10003000].state == "thunk"

    def test_legacy_fallback(self, tmp_path: Path) -> None:
        (tmp_path / "ghidra_switchdata.json").write_text(
            json.dumps([{"va": 0x10001000, "size": 8}]),
            encoding="utf-8",
        )
        labels = load_ghidra_data_labels(tmp_path)
        assert 0x10001000 in labels
        assert labels[0x10001000].size == 8

    def test_corrupt_warns_and_empty(self, tmp_path: Path) -> None:
        # Only the legacy file exists and it is corrupt → warn + empty.
        (tmp_path / "ghidra_switchdata.json").write_text("{oops", encoding="utf-8")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            out = load_ghidra_data_labels(tmp_path)
        assert out == {}
        assert any("corrupt" in str(x.message).lower() for x in w)

    def test_non_dict_entries_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "ghidra_data_labels.json").write_text(
            json.dumps([42, {"va": 0x10001000, "size": 4, "label": "x"}]),
            encoding="utf-8",
        )
        labels = load_ghidra_data_labels(tmp_path)
        assert list(labels) == [0x10001000]


class TestParseFunctionList:
    def test_size_first(self, tmp_path: Path) -> None:
        p = tmp_path / "functions.txt"
        p.write_text("0x10001000 64 _func_a\n", encoding="utf-8")
        funcs = parse_function_list(p)
        assert funcs == [{"va": 0x10001000, "size": 64, "name": "_func_a"}]

    def test_name_first(self, tmp_path: Path) -> None:
        p = tmp_path / "functions.txt"
        p.write_text("0x10002000 _func_b 128\n", encoding="utf-8")
        funcs = parse_function_list(p)
        assert funcs == [{"va": 0x10002000, "size": 128, "name": "_func_b"}]

    def test_comments_and_blanks_skipped(self, tmp_path: Path) -> None:
        p = tmp_path / "functions.txt"
        p.write_text("# comment\n\n0x10003000 32 _func_c\n", encoding="utf-8")
        assert len(parse_function_list(p)) == 1

    def test_unreadable_warns_and_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "missing.txt"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            out = parse_function_list(p)
        assert out == []
        assert any("Cannot read" in str(x.message) for x in w)


class TestLoadGhidraDataLabelsMore:
    def test_non_list_entries_warns(self, tmp_path: Path) -> None:
        import json

        from rebrew.catalog.loaders import load_ghidra_data_labels

        (tmp_path / "ghidra_data_labels.json").write_text(json.dumps({"va": 1}), encoding="utf-8")
        with pytest.warns(UserWarning, match="expected JSON array"):
            assert load_ghidra_data_labels(tmp_path) == {}

    def test_legacy_format_fallback(self, tmp_path: Path) -> None:
        import json

        from rebrew.catalog.loaders import load_ghidra_data_labels

        (tmp_path / "ghidra_switchdata.json").write_text(
            json.dumps([{"va": 0x1000, "size": 8}]), encoding="utf-8"
        )
        labels = load_ghidra_data_labels(tmp_path)
        assert 0x1000 in labels

    def test_corrupt_json_warns(self, tmp_path: Path) -> None:
        from rebrew.catalog.loaders import load_ghidra_data_labels

        (tmp_path / "ghidra_data_labels.json").write_text("{broken", encoding="utf-8")
        with pytest.warns(UserWarning, match="corrupt"):
            assert load_ghidra_data_labels(tmp_path) == {}


class TestScanReversedDirLibraryHeaders:
    def test_library_header_markers_included(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.catalog.loaders import scan_reversed_dir

        src = tmp_path / "src"
        src.mkdir()
        (src / "library_msvc.h").write_text(
            "// LIBRARY: SERVER 0x1000\n// _fflush\n", encoding="utf-8"
        )
        cfg = SimpleNamespace(metadata_dir=tmp_path, marker="SERVER", source_ext=".c")
        entries = scan_reversed_dir(src, cfg=cfg)
        assert any(e.va == 0x1000 and e.marker_type == "LIBRARY" for e in entries)
