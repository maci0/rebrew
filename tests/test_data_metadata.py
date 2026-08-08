"""test_data_metadata.py — Unit tests for rebrew.data_metadata.

Tests the per-directory rebrew-data.toml metadata for DATA/GLOBAL annotation metadata.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.data_metadata import (
    DATA_METADATA_FIELDS,
    DATA_METADATA_FILENAME,
    get_data_entry,
    load_data_metadata,
    merge_into_data_annotation,
    set_data_field,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_annotation(**kwargs: object) -> object:
    """Return a minimal Annotation-like object for merge tests."""
    defaults = {
        "va": 0x10025000,
        "module": "SERVER",
        "marker_type": "DATA",
        "size": 0,
        "section": "",
        "note": "",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------


class TestConstants:
    def test_filename(self) -> None:
        assert DATA_METADATA_FILENAME == "rebrew-data.toml"

    def test_fields_set(self) -> None:
        assert "SIZE" in DATA_METADATA_FIELDS
        assert "SECTION" in DATA_METADATA_FIELDS
        assert "NOTE" in DATA_METADATA_FIELDS
        # Status is NOT a data metadata field
        assert "STATUS" not in DATA_METADATA_FIELDS


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


class TestLoadSaveDataMetadata:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = load_data_metadata(tmp_path)
        assert result == {}

    def test_corrupted_file_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / DATA_METADATA_FILENAME).write_text("[[[[invalid toml", encoding="utf-8")
        result = load_data_metadata(tmp_path)
        assert result == {}


# ---------------------------------------------------------------------------
# get_data_entry
# ---------------------------------------------------------------------------


class TestGetDataEntry:
    def test_missing_returns_empty(self, tmp_path: Path) -> None:
        assert get_data_entry(tmp_path, 0x10025000, "SERVER") == {}


# ---------------------------------------------------------------------------
# set_data_field
# ---------------------------------------------------------------------------


class TestSetDataField:
    def test_creates_file_if_absent(self, tmp_path: Path) -> None:
        set_data_field(tmp_path, 0x10025000, "size", 256, "SERVER")
        entry = get_data_entry(tmp_path, 0x10025000, "SERVER")
        assert entry["size"] == 256

    def test_overwrites_field(self, tmp_path: Path) -> None:
        set_data_field(tmp_path, 0x10025000, "size", 128, "SERVER")
        set_data_field(tmp_path, 0x10025000, "size", 256, "SERVER")
        assert get_data_entry(tmp_path, 0x10025000, "SERVER")["size"] == 256

    def test_multiple_fields_same_entry(self, tmp_path: Path) -> None:
        set_data_field(tmp_path, 0x10025000, "size", 256, "SERVER")
        set_data_field(tmp_path, 0x10025000, "section", ".rdata", "SERVER")
        set_data_field(tmp_path, 0x10025000, "note", "sprite table", "SERVER")
        entry = get_data_entry(tmp_path, 0x10025000, "SERVER")
        assert entry["size"] == 256
        assert entry["section"] == ".rdata"
        assert entry["note"] == "sprite table"


# ---------------------------------------------------------------------------
# delete_data_field
# ---------------------------------------------------------------------------


class TestMergeIntoDataAnnotation:
    def test_no_entry_leaves_annotation_unchanged(self, tmp_path: Path) -> None:
        ann = _make_annotation(size=256, section=".rdata", note="test")
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.size == 256
        assert ann.section == ".rdata"
        assert ann.note == "test"


class TestDataMetadataEdgeCases:
    def test_load_corrupt_toml(self, tmp_path: Path) -> None:
        import rebrew.data_metadata as dm

        (tmp_path / "rebrew-data.toml").write_text("{broken", encoding="utf-8")
        assert dm.load_data_metadata(tmp_path) == {}

    def test_load_skips_non_dict_values(self, tmp_path: Path) -> None:
        import rebrew.data_metadata as dm

        (tmp_path / "rebrew-data.toml").write_text(
            '"SERVER.0x10001000" = "scalar"\n["SERVER.0x10002000"]\nsize = 8\n',
            encoding="utf-8",
        )
        result = dm.load_data_metadata(tmp_path)
        assert ("SERVER", 0x10002000) in result
        assert ("SERVER", 0x10001000) not in result


class TestCorruptTomlRecovery:
    def test_set_data_field_recovers(self, tmp_path: Path) -> None:
        from rebrew.data_metadata import DATA_METADATA_FILENAME, get_data_entry, set_data_field

        (tmp_path / DATA_METADATA_FILENAME).write_text("{broken", encoding="utf-8")
        set_data_field(tmp_path, 0x1000, "size", 16, "SERVER")
        entry = get_data_entry(tmp_path, 0x1000, "SERVER")
        assert entry.get("size") == 16

    def test_merge_into_data_annotation_no_crash(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation
        from rebrew.data_metadata import DATA_METADATA_FILENAME, merge_into_data_annotation

        (tmp_path / DATA_METADATA_FILENAME).write_text("{broken", encoding="utf-8")
        ann = Annotation(va=0x1000, module="SERVER", name="g_x", marker_type="DATA")
        result = merge_into_data_annotation(ann, tmp_path)
        assert result is ann


class TestDataMetadataCache:
    """load_data_metadata caches by mtime; writes invalidate the cache."""

    def test_repeated_load_served_from_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import data_metadata as dm

        dm._data_metadata_cache.clear()
        parse_calls: list[object] = []
        monkeypatch.setattr(
            dm,
            "parse_metadata_doc",
            lambda doc: parse_calls.append(doc) or {},
        )
        f = tmp_path / "rebrew-data.toml"
        f.write_text('["SERVER.0x1000"]\nsize = 4\n', encoding="utf-8")
        # First load parses; a second unchanged load must hit the cache.
        dm.load_data_metadata(tmp_path)
        dm.load_data_metadata(tmp_path)
        assert len(parse_calls) == 1
        # mtime change forces a re-parse.
        import os

        os.utime(f, (f.stat().st_atime + 2, f.stat().st_mtime + 2))
        dm.load_data_metadata(tmp_path)
        assert len(parse_calls) == 2
