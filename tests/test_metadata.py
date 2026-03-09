"""Tests for rebrew.metadata — per-directory metadata store."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rebrew.metadata import (
    METADATA_FILENAME,
    _delete_field,
    _parse_key,
    _qualified_key,
    _set_field,
    get_entry,
    is_metadata_key,
    load_metadata,
    merge_into_annotation,
    metadata_path,
    remove_field,
    save_metadata,
    update_field,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_annotation(**kwargs: object) -> SimpleNamespace:
    """Make a minimal Annotation-like object for merge tests."""
    defaults: dict[str, object] = {
        "va": 0x01006364,
        "module": "SERVER",
        "size": 0,
        "cflags": "",
        "status": "",
        "blocker": "",
        "blocker_delta": None,
        "note": "",
        "ghidra": "",
        "globals_list": [],
        "section": "",
        "source": "",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# metadata_path
# ---------------------------------------------------------------------------


class TestMetadataPath:
    def test_from_file(self, tmp_path: Path) -> None:
        assert metadata_path(tmp_path) == tmp_path / METADATA_FILENAME

    def test_from_directory(self, tmp_path: Path) -> None:
        assert metadata_path(tmp_path) == tmp_path / METADATA_FILENAME


# ---------------------------------------------------------------------------
# is_metadata_key
# ---------------------------------------------------------------------------


class TestIsMetadataKey:
    def test_status(self) -> None:
        assert is_metadata_key("STATUS") is True

    def test_size(self) -> None:
        assert is_metadata_key("SIZE") is True

    def test_cflags(self) -> None:
        assert is_metadata_key("CFLAGS") is True

    def test_blocker(self) -> None:
        assert is_metadata_key("BLOCKER") is True

    def test_note(self) -> None:
        assert is_metadata_key("NOTE") is True

    def test_ghidra(self) -> None:
        assert is_metadata_key("GHIDRA") is True

    def test_origin_not_metadata(self) -> None:
        # ORIGIN stays in the .c file
        assert is_metadata_key("ORIGIN") is False

    def test_marker_not_metadata(self) -> None:
        assert is_metadata_key("FUNCTION") is False
        assert is_metadata_key("LIBRARY") is False

    def test_case_insensitive(self) -> None:
        assert is_metadata_key("status") is True
        assert is_metadata_key("CfLaGs") is True


# ---------------------------------------------------------------------------
# Key helpers: _qualified_key and _parse_key
# ---------------------------------------------------------------------------


class TestKeyHelpers:
    def test_qualified_key_with_module(self) -> None:
        assert _qualified_key("SERVER", 0x01006364) == "SERVER.0x01006364"

    def test_qualified_key_without_module(self) -> None:
        # No bare-key support — _qualified_key always requires a module string
        assert _qualified_key("SERVER", 0x01006364) == "SERVER.0x01006364"

    def test_parse_qualified_key(self) -> None:
        result = _parse_key("SERVER.0x01006364")
        assert result == ("SERVER", 0x01006364)

    def test_parse_unrecognised_key(self) -> None:
        assert _parse_key("not_a_key") is None
        assert _parse_key("SERVER") is None
        assert _parse_key("0x01006364") is None  # bare key no longer supported
        assert _parse_key("junk.junk") is None


# ---------------------------------------------------------------------------
# load_metadata / save_metadata round-trip
# ---------------------------------------------------------------------------


class TestLoadSaveMetadata:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = load_metadata(tmp_path)
        assert result == {}

    def test_round_trip_qualified_keys(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x01006364): {"size": 80, "cflags": "/O1 /Gd", "status": "NEAR_MATCHING"},
            ("SERVER", 0x01006400): {"size": 120, "cflags": "/O2 /Gd", "status": "EXACT"},
        }
        save_metadata(tmp_path, data)
        loaded = load_metadata(tmp_path)
        assert loaded[("SERVER", 0x01006364)]["size"] == 80
        assert loaded[("SERVER", 0x01006364)]["status"] == "NEAR_MATCHING"
        assert loaded[("SERVER", 0x01006400)]["cflags"] == "/O2 /Gd"

    def test_empty_entries_skipped(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x01006364): {"size": 80, "status": "EXACT"},
            ("SERVER", 0x0DEAD000): {},  # empty — should be skipped
        }
        save_metadata(tmp_path, data)
        loaded = load_metadata(tmp_path)
        assert ("SERVER", 0x01006364) in loaded
        assert ("SERVER", 0x0DEAD000) not in loaded

    def test_sorted_output(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x02000000): {"size": 10, "status": "EXACT"},
            ("SERVER", 0x01000000): {"size": 20, "status": "NEAR_MATCHING"},
        }
        save_metadata(tmp_path, data)
        text = (tmp_path / METADATA_FILENAME).read_text()
        idx_low = text.index("0x01000000")
        idx_high = text.index("0x02000000")
        assert idx_low < idx_high

    def test_corrupt_toml_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / METADATA_FILENAME).write_text("this is not [[valid toml", encoding="utf-8")
        result = load_metadata(tmp_path)
        assert result == {}

    def test_multi_target_no_collision(self, tmp_path: Path) -> None:
        """Two different modules at the same VA coexist in one metadata."""
        data = {
            ("SERVER", 0x10008880): {"size": 42, "status": "EXACT"},
            ("CLIENT", 0x10008880): {"size": 42, "status": "NEAR_MATCHING"},
        }
        save_metadata(tmp_path, data)
        loaded = load_metadata(tmp_path)
        assert loaded[("SERVER", 0x10008880)]["status"] == "EXACT"
        assert loaded[("CLIENT", 0x10008880)]["status"] == "NEAR_MATCHING"


# ---------------------------------------------------------------------------
# get_entry
# ---------------------------------------------------------------------------


class TestGetEntry:
    def test_missing_va(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "EXACT"}})
        assert get_entry(tmp_path, 0x99999999, module="SERVER") == {}

    def test_present_va_with_module(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "EXACT"}})
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["status"] == "EXACT"
        assert entry["size"] == 80

    def test_no_metadata(self, tmp_path: Path) -> None:
        assert get_entry(tmp_path, 0x01006364, module="SERVER") == {}


# ---------------------------------------------------------------------------
# set_field
# ---------------------------------------------------------------------------


class TestSetField:
    def test_creates_file_and_entry(self, tmp_path: Path) -> None:
        _set_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["status"] == "EXACT"

    def test_updates_existing_entry(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "NEAR_MATCHING"}})
        _set_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["status"] == "EXACT"
        assert entry["size"] == 80  # untouched

    def test_adds_new_field_to_existing_entry(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "NEAR_MATCHING"}})
        _set_field(tmp_path, 0x01006364, "blocker", "1B diff", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["blocker"] == "1B diff"
        assert entry["status"] == "NEAR_MATCHING"

    def test_adds_entry_to_existing_file(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01000000): {"size": 10, "status": "EXACT"}})
        _set_field(tmp_path, 0x02000000, "status", "NEAR_MATCHING", module="SERVER")
        loaded = load_metadata(tmp_path)
        assert ("SERVER", 0x01000000) in loaded
        assert ("SERVER", 0x02000000) in loaded

    def test_idempotent(self, tmp_path: Path) -> None:
        _set_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")
        _set_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["status"] == "EXACT"


# ---------------------------------------------------------------------------
# delete_field
# ---------------------------------------------------------------------------


class TestDeleteField:
    def test_removes_field(self, tmp_path: Path) -> None:
        save_metadata(
            tmp_path,
            {("SERVER", 0x01006364): {"size": 80, "status": "NEAR_MATCHING", "blocker": "1B diff"}},
        )
        _delete_field(tmp_path, 0x01006364, "blocker", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert "blocker" not in entry
        assert entry["status"] == "NEAR_MATCHING"

    def test_noop_on_missing_key(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "NEAR_MATCHING"}})
        # Should not raise
        _delete_field(tmp_path, 0x01006364, "blocker", module="SERVER")

    def test_noop_on_missing_va(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80}})
        _delete_field(tmp_path, 0x99999999, "status", module="SERVER")  # no-op

    def test_noop_when_no_file(self, tmp_path: Path) -> None:
        _delete_field(tmp_path, 0x01006364, "status", module="SERVER")  # no error


# ---------------------------------------------------------------------------
# update_field / remove_field (public API with STATUS blocking)
# ---------------------------------------------------------------------------


class TestUpdateField:
    def test_updates_non_status_field(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "NEAR_MATCHING"}})
        update_field(tmp_path, 0x01006364, "blocker", "1B diff", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["blocker"] == "1B diff"

    def test_status_blocked_via_update_field(self, tmp_path: Path) -> None:
        import pytest

        with pytest.raises(ValueError, match="update_source_status"):
            update_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")


class TestRemoveField:
    def test_removes_non_status_field(self, tmp_path: Path) -> None:
        save_metadata(
            tmp_path,
            {("SERVER", 0x01006364): {"size": 80, "status": "NEAR_MATCHING", "blocker": "old"}},
        )
        remove_field(tmp_path, 0x01006364, "blocker", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert "blocker" not in entry

    def test_status_blocked_via_remove_field(self, tmp_path: Path) -> None:
        import pytest

        with pytest.raises(ValueError, match="Cannot delete STATUS"):
            remove_field(tmp_path, 0x01006364, "status", module="SERVER")


# ---------------------------------------------------------------------------
# merge_into_annotation
# ---------------------------------------------------------------------------


class TestMergeIntoAnnotation:
    def test_merges_all_scalar_fields(self, tmp_path: Path) -> None:
        save_metadata(
            tmp_path,
            {
                ("SERVER", 0x01006364): {
                    "size": 80,
                    "cflags": "/O1 /Gd",
                    "status": "NEAR_MATCHING",
                    "blocker": "1B diff",
                    "blocker_delta": 1,
                    "note": "check xref",
                    "ghidra": "IsUtf8",
                    "source": "SBHEAP.C:100",
                }
            },
        )
        ann = _make_annotation(va=0x01006364, module="SERVER")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.size == 80
        assert ann.cflags == "/O1 /Gd"
        assert ann.status == "NEAR_MATCHING"
        assert ann.blocker == "1B diff"
        assert ann.blocker_delta == 1
        assert ann.note == "check xref"
        assert ann.ghidra == "IsUtf8"
        assert ann.source == "SBHEAP.C:100"

    def test_section_not_owned_by_function_metadata(self, tmp_path: Path) -> None:
        """SECTION is owned by data_metadata.py — function metadata must not merge it."""
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"section": ".text", "size": 80}})
        ann = _make_annotation(va=0x01006364, module="SERVER", section="")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.section == ""  # section NOT applied by function metadata
        assert ann.size == 80  # size still applied normally

    def test_metadata_wins_over_inline(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"status": "EXACT", "size": 90}})
        ann = _make_annotation(va=0x01006364, module="SERVER", status="NEAR_MATCHING", size=80)
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.status == "EXACT"
        assert ann.size == 90

    def test_no_metadata_leaves_annotation_unchanged(self, tmp_path: Path) -> None:
        ann = _make_annotation(va=0x01006364, module="SERVER", status="NEAR_MATCHING", size=80)
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.status == "NEAR_MATCHING"
        assert ann.size == 80

    def test_partial_entry_leaves_unset_fields_unchanged(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"status": "EXACT"}})
        ann = _make_annotation(
            va=0x01006364, module="SERVER", status="NEAR_MATCHING", size=80, cflags="/O2 /Gd"
        )
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.status == "EXACT"  # metadata wins
        assert ann.size == 80  # unchanged
        assert ann.cflags == "/O2 /Gd"  # unchanged

    def test_globals_from_list(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"globals": ["g_foo", "g_bar"]}})
        ann = _make_annotation(va=0x01006364, module="SERVER")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.globals_list == ["g_foo", "g_bar"]

    def test_globals_from_comma_string(self, tmp_path: Path) -> None:
        # Tolerate comma-string globals (inline annotation style)
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"globals": "g_foo, g_bar"}})
        ann = _make_annotation(va=0x01006364, module="SERVER")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.globals_list == ["g_foo", "g_bar"]

    def test_returns_same_object(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"status": "EXACT"}})
        ann = _make_annotation(va=0x01006364, module="SERVER")
        result = merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert result is ann

    def test_va_not_in_metadata_is_noop(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006000): {"status": "EXACT"}})
        ann = _make_annotation(va=0x01006364, module="SERVER", status="NEAR_MATCHING")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.status == "NEAR_MATCHING"  # not touched

    def test_multi_target_merge_isolated(self, tmp_path: Path) -> None:
        """Two different modules at same VA merge independently."""
        save_metadata(
            tmp_path,
            {
                ("SERVER", 0x10008880): {"status": "EXACT", "size": 42},
                ("CLIENT", 0x10008880): {"status": "NEAR_MATCHING", "size": 42, "blocker": "regs"},
            },
        )
        ann_server = _make_annotation(va=0x10008880, module="SERVER")
        ann_client = _make_annotation(va=0x10008880, module="CLIENT")
        merge_into_annotation(ann_server, tmp_path)  # type: ignore[arg-type]
        merge_into_annotation(ann_client, tmp_path)  # type: ignore[arg-type]
        assert ann_server.status == "EXACT"
        assert ann_server.blocker == ""  # CLIENT blocker not leaked into SERVER
        assert ann_client.status == "NEAR_MATCHING"
        assert ann_client.blocker == "regs"


# ---------------------------------------------------------------------------
# Idempotent status updates (moved from test_phase2.py)
# ---------------------------------------------------------------------------


class TestIdempotentStatusUpdate:
    """Verify update_source_status skips write when status matches."""

    def test_no_extra_bak_on_same_status(self, tmp_path: Path) -> None:
        p = tmp_path / "func.c"
        p.write_text(
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// ORIGIN: GAME\n"
            "// SIZE: 31\n// CFLAGS: /O2 /Gd\n\nint __cdecl bit_reverse(int x) { return x; }\n",
            encoding="utf-8",
        )
        bak = tmp_path / "func.c.bak"
        from rebrew.metadata import set_field, update_source_status

        set_field(tmp_path, 0x10008880, "status", "EXACT", module="SERVER")
        update_source_status(tmp_path, "EXACT", "SERVER", 0x10008880)
        assert not bak.exists(), "Should not create backup for no-op update"

    def test_writes_when_status_differs(self, tmp_path: Path) -> None:
        p = tmp_path / "func.c"
        p.write_text(
            "// FUNCTION: SERVER 0x10008880\n// STATUS: EXACT\n// ORIGIN: GAME\n"
            "// SIZE: 31\n// CFLAGS: /O2 /Gd\n\nint __cdecl bit_reverse(int x) { return x; }\n",
            encoding="utf-8",
        )
        from rebrew.metadata import get_entry, update_source_status

        update_source_status(tmp_path, "RELOC", "SERVER", 0x10008880)
        entry = get_entry(tmp_path, 0x10008880, module="SERVER")
        assert entry["status"] == "RELOC"
        assert "STATUS: EXACT" in p.read_text(encoding="utf-8")
