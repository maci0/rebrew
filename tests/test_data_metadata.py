"""test_data_metadata.py — Unit tests for rebrew.data_metadata.

Tests the per-directory rebrew-data.toml metadata for DATA/GLOBAL annotation metadata.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rebrew.data_metadata import (
    DATA_METADATA_FIELDS,
    DATA_METADATA_FILENAME,
    data_metadata_path,
    delete_data_field,
    get_data_entry,
    is_data_metadata_key,
    load_data_metadata,
    merge_into_data_annotation,
    save_data_metadata,
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

    def test_is_data_metadata_key_known(self) -> None:
        assert is_data_metadata_key("SIZE") is True
        assert is_data_metadata_key("size") is True  # case-insensitive
        assert is_data_metadata_key("SECTION") is True
        assert is_data_metadata_key("NOTE") is True

    def test_is_data_metadata_key_unknown(self) -> None:
        assert is_data_metadata_key("STATUS") is False
        assert is_data_metadata_key("CFLAGS") is False
        assert is_data_metadata_key("BLOCKER") is False

    def test_metadata_path_from_dir(self, tmp_path: Path) -> None:
        assert data_metadata_path(tmp_path) == tmp_path / "rebrew-data.toml"

    def test_metadata_path_from_file(self, tmp_path: Path) -> None:
        # data_metadata_path now expects a directory (cfg.reversed_dir)
        assert data_metadata_path(tmp_path) == tmp_path / "rebrew-data.toml"


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


class TestLoadSaveDataMetadata:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = load_data_metadata(tmp_path)
        assert result == {}

    def test_round_trip_single_entry(self, tmp_path: Path) -> None:
        data = {("SERVER", 0x10025000): {"size": 256, "section": ".rdata", "note": "sprite lut"}}
        save_data_metadata(tmp_path, data)
        loaded = load_data_metadata(tmp_path)
        assert loaded == data

    def test_round_trip_multiple_entries(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x10025000): {"size": 256, "section": ".rdata"},
            ("SERVER", 0x10030000): {"size": 64, "section": ".bss", "note": "entity table"},
            ("CLIENT", 0x00408000): {"size": 4, "section": ".data"},
        }
        save_data_metadata(tmp_path, data)
        loaded = load_data_metadata(tmp_path)
        assert loaded == data

    def test_empty_entries_not_written(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x10025000): {},
            ("SERVER", 0x10030000): {"size": 64},
        }
        save_data_metadata(tmp_path, data)
        loaded = load_data_metadata(tmp_path)
        # Empty entry is not written
        assert ("SERVER", 0x10025000) not in loaded
        assert loaded[("SERVER", 0x10030000)] == {"size": 64}

    def test_canonical_key_order_in_file(self, tmp_path: Path) -> None:
        data = {("SERVER", 0x10025000): {"note": "test", "section": ".data", "size": 8}}
        save_data_metadata(tmp_path, data)
        text = (tmp_path / DATA_METADATA_FILENAME).read_text(encoding="utf-8")
        # size must come before section which must come before note
        assert text.index("size") < text.index("section") < text.index("note")

    def test_entries_sorted_by_module_then_va(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x10030000): {"size": 4},
            ("CLIENT", 0x00401000): {"size": 8},
            ("SERVER", 0x10020000): {"size": 16},
        }
        save_data_metadata(tmp_path, data)
        text = (tmp_path / DATA_METADATA_FILENAME).read_text(encoding="utf-8")
        # CLIENT < SERVER (alphabetical)
        assert text.index("CLIENT") < text.index("SERVER")
        # Within SERVER, lower VA first
        assert text.index("0x10020000") < text.index("0x10030000")

    def test_corrupted_file_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / DATA_METADATA_FILENAME).write_text("[[[[invalid toml", encoding="utf-8")
        result = load_data_metadata(tmp_path)
        assert result == {}


# ---------------------------------------------------------------------------
# get_data_entry
# ---------------------------------------------------------------------------


class TestGetDataEntry:
    def test_existing_entry(self, tmp_path: Path) -> None:
        data = {("SERVER", 0x10025000): {"size": 256, "section": ".rdata"}}
        save_data_metadata(tmp_path, data)
        entry = get_data_entry(tmp_path, 0x10025000, "SERVER")
        assert entry == {"size": 256, "section": ".rdata"}

    def test_missing_returns_empty(self, tmp_path: Path) -> None:
        assert get_data_entry(tmp_path, 0x10025000, "SERVER") == {}

    def test_wrong_module_returns_empty(self, tmp_path: Path) -> None:
        data = {("SERVER", 0x10025000): {"size": 256}}
        save_data_metadata(tmp_path, data)
        assert get_data_entry(tmp_path, 0x10025000, "CLIENT") == {}


# ---------------------------------------------------------------------------
# set_data_field
# ---------------------------------------------------------------------------


class TestSetDataField:
    def test_creates_file_if_absent(self, tmp_path: Path) -> None:
        set_data_field(tmp_path, 0x10025000, "size", 256, "SERVER")
        entry = get_data_entry(tmp_path, 0x10025000, "SERVER")
        assert entry["size"] == 256

    def test_creates_entry_if_absent(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10030000): {"size": 4}})
        set_data_field(tmp_path, 0x10025000, "section", ".rdata", "SERVER")
        entry = get_data_entry(tmp_path, 0x10025000, "SERVER")
        assert entry["section"] == ".rdata"
        # Existing entry preserved
        assert get_data_entry(tmp_path, 0x10030000, "SERVER")["size"] == 4

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


class TestDeleteDataField:
    def test_delete_existing_field(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"size": 256, "section": ".rdata"}})
        delete_data_field(tmp_path, 0x10025000, "section", "SERVER")
        entry = get_data_entry(tmp_path, 0x10025000, "SERVER")
        assert "section" not in entry
        assert entry["size"] == 256

    def test_delete_nonexistent_field_noop(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"size": 256}})
        delete_data_field(tmp_path, 0x10025000, "note", "SERVER")  # no-op
        assert get_data_entry(tmp_path, 0x10025000, "SERVER")["size"] == 256

    def test_delete_missing_file_noop(self, tmp_path: Path) -> None:
        delete_data_field(tmp_path, 0x10025000, "size", "SERVER")  # no-op, no crash

    def test_delete_missing_va_noop(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10030000): {"size": 4}})
        delete_data_field(tmp_path, 0x10025000, "size", "SERVER")  # no-op
        assert get_data_entry(tmp_path, 0x10030000, "SERVER")["size"] == 4


# ---------------------------------------------------------------------------
# merge_into_data_annotation
# ---------------------------------------------------------------------------


class TestMergeIntoDataAnnotation:
    def test_overlay_name_from_metadata(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"name": "g_sprite_lut"}})
        ann = _make_annotation(name="DAT_10025000")
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.name == "g_sprite_lut"

    def test_empty_name_not_applied(self, tmp_path: Path) -> None:
        """Empty name in metadata must not clobber an existing name."""
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"name": ""}})
        ann = _make_annotation(name="g_existing")
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.name == "g_existing"

    def test_overlay_size_from_metadata(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"size": 256}})
        ann = _make_annotation(size=0)
        merged = merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert merged.size == 256

    def test_overlay_section_from_metadata(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"section": ".rdata"}})
        ann = _make_annotation(section="")
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.section == ".rdata"

    def test_overlay_note_from_metadata(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"note": "sprite table"}})
        ann = _make_annotation(note="")
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.note == "sprite table"

    def test_metadata_wins_over_inline(self, tmp_path: Path) -> None:
        """Metadata values override inline .c annotation values."""
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"size": 512, "section": ".data"}})
        ann = _make_annotation(size=256, section=".rdata")
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.size == 512
        assert ann.section == ".data"

    def test_no_entry_leaves_annotation_unchanged(self, tmp_path: Path) -> None:
        ann = _make_annotation(size=256, section=".rdata", note="test")
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.size == 256
        assert ann.section == ".rdata"
        assert ann.note == "test"

    def test_no_module_returns_unchanged(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"size": 512}})
        ann = _make_annotation(module="", size=10)
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.size == 10  # unchanged

    def test_invalid_size_in_metadata_skipped(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"size": "not_a_number"}})
        ann = _make_annotation(size=99)
        merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.size == 99  # unchanged — bad value skipped

    def test_returns_same_object(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("SERVER", 0x10025000): {"size": 256}})
        ann = _make_annotation()
        result = merge_into_data_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert result is ann
