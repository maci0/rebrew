"""Tests for rebrew.metadata — per-directory metadata store."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.metadata import (
    METADATA_FILENAME,
    _delete_field,
    _set_field,
    delete_metadata_entry,
    get_entry,
    is_metadata_key,
    load_metadata,
    merge_into_annotation,
    metadata_path,
    remove_field,
    save_metadata,
    update_field,
)
from rebrew.utils import parse_metadata_key as _parse_key
from rebrew.utils import qualified_key as _qualified_key

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
    def test_returns_toml_in_directory(self, tmp_path: Path) -> None:
        result = metadata_path(tmp_path)
        assert result == tmp_path / METADATA_FILENAME
        assert result.name == METADATA_FILENAME


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
        assert (
            _parse_key("0x01006364") is None
        )  # bare VA keys require module prefix (e.g. "SERVER.0x01006364")
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
# delete_metadata_entry
# ---------------------------------------------------------------------------


class TestDeleteMetadataEntry:
    """delete_metadata_entry removes the whole (module, va) entry — used by
    intake's stale-stub pruning; a wrong deletion would silently drop status."""

    def test_removes_existing_entry(self, tmp_path: Path) -> None:
        save_metadata(
            tmp_path,
            {
                ("SERVER", 0x01006364): {"size": 80, "status": "EXACT"},
                ("SERVER", 0x01006400): {"size": 120, "status": "STUB"},
            },
        )
        assert delete_metadata_entry(tmp_path, 0x01006364, "SERVER") is True
        assert get_entry(tmp_path, 0x01006364, "SERVER") == {}
        # Sibling entries must survive.
        assert get_entry(tmp_path, 0x01006400, "SERVER")["status"] == "STUB"

    def test_missing_entry_returns_false(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80}})
        assert delete_metadata_entry(tmp_path, 0x99999999, "SERVER") is False
        assert get_entry(tmp_path, 0x01006364, "SERVER")["size"] == 80

    def test_missing_file_returns_false(self, tmp_path: Path) -> None:
        assert delete_metadata_entry(tmp_path, 0x01006364, "SERVER") is False
        assert not (tmp_path / METADATA_FILENAME).exists()

    def test_same_va_other_module_untouched(self, tmp_path: Path) -> None:
        save_metadata(
            tmp_path,
            {
                ("SERVER", 0x10008880): {"status": "EXACT"},
                ("CLIENT", 0x10008880): {"status": "STUB"},
            },
        )
        assert delete_metadata_entry(tmp_path, 0x10008880, "CLIENT") is True
        assert get_entry(tmp_path, 0x10008880, "SERVER")["status"] == "EXACT"


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
        _delete_field(tmp_path, 0x01006364, "blocker", module="SERVER")
        # Existing fields untouched.
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["size"] == 80
        assert entry["status"] == "NEAR_MATCHING"

    def test_noop_on_missing_va(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("SERVER", 0x01006364): {"size": 80}})
        _delete_field(tmp_path, 0x99999999, "status", module="SERVER")
        # Untouched key still has its original field.
        assert get_entry(tmp_path, 0x01006364, module="SERVER")["size"] == 80

    def test_noop_when_no_file(self, tmp_path: Path) -> None:
        _delete_field(tmp_path, 0x01006364, "status", module="SERVER")
        # No metadata file is created on a no-op delete.
        assert not (tmp_path / METADATA_FILENAME).exists()


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
# Idempotent status updates
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


class TestMetadataEdgeCases:
    def test_load_metadata_corrupt_toml(self, tmp_path: Path) -> None:
        import rebrew.metadata as md

        md.clear_metadata_cache()
        (tmp_path / "rebrew-functions.toml").write_text("{broken toml", encoding="utf-8")
        assert md.load_metadata(tmp_path) == {}

    def test_load_metadata_skips_non_dict_values(self, tmp_path: Path) -> None:
        import rebrew.metadata as md

        md.clear_metadata_cache()
        (tmp_path / "rebrew-functions.toml").write_text(
            '"SERVER.0x10001000" = "scalar"\n["SERVER.0x10002000"]\nstatus = "EXACT"\n',
            encoding="utf-8",
        )
        result = md.load_metadata(tmp_path)
        # Scalar value skipped; dict value kept.
        assert ("SERVER", 0x10002000) in result
        assert ("SERVER", 0x10001000) not in result

    def test_load_metadata_mtime_cache_invalidated(self, tmp_path: Path) -> None:
        import rebrew.metadata as md

        md.clear_metadata_cache()
        f = tmp_path / "rebrew-functions.toml"
        f.write_text('["SERVER.0x10001000"]\nstatus = "EXACT"\n', encoding="utf-8")
        first = md.load_metadata(tmp_path)
        assert ("SERVER", 0x10001000) in first
        # Rewrite with a new status; mtime change must invalidate the cache.
        import os

        os.utime(f, ns=(1_800_000_000_000_000_000, 1_800_000_000_000_000_000))
        f.write_text('["SERVER.0x10001000"]\nstatus = "STUB"\n', encoding="utf-8")
        second = md.load_metadata(tmp_path)
        assert second[("SERVER", 0x10001000)]["status"] == "STUB"

    def test_metadata_path(self, tmp_path: Path) -> None:
        import rebrew.metadata as md

        assert md.metadata_path(tmp_path) == tmp_path / "rebrew-functions.toml"


class TestWritePathsCorruptToml:
    def test_metadata_file_write_locked_readonly(self, tmp_path: Path) -> None:
        """rebrew-functions.toml is left 0444 after every tool write — hand
        edits fail with Permission denied; the sanctioned CLI path chmods
        writable, updates, re-locks (metadata-review F1)."""
        from rebrew.metadata import METADATA_FILENAME, get_entry, update_field, update_source_status

        update_field(tmp_path, 0x1000, "size", 42, "SERVER")
        path = tmp_path / METADATA_FILENAME
        assert path.exists()
        assert (path.stat().st_mode & 0o777) == 0o444
        # The sanctioned path keeps working through the lock.
        update_source_status(tmp_path, "EXACT", "SERVER", 0x1000)
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "EXACT"
        assert (path.stat().st_mode & 0o777) == 0o444

    def test_update_field_recovers_from_corrupt(self, tmp_path: Path) -> None:
        from rebrew.metadata import METADATA_FILENAME, get_entry, update_field

        (tmp_path / METADATA_FILENAME).write_text("{broken", encoding="utf-8")
        update_field(tmp_path, 0x1000, "size", 42, "SERVER")
        entry = get_entry(tmp_path, 0x1000, "SERVER")
        assert entry.get("size") == 42

    def test_update_source_status_recovers_from_corrupt(self, tmp_path: Path) -> None:
        from rebrew.metadata import METADATA_FILENAME, get_entry, update_source_status

        (tmp_path / METADATA_FILENAME).write_text("{broken", encoding="utf-8")
        update_source_status(tmp_path, "EXACT", "SERVER", 0x1000)
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "EXACT"

    def test_corrupt_file_is_preserved_not_clobbered(self, tmp_path: Path) -> None:
        from rebrew.metadata import METADATA_FILENAME, update_field

        original = '{broken\n[SERVER.0x2000]\nstatus = "EXACT"\n'
        (tmp_path / METADATA_FILENAME).write_text(original, encoding="utf-8")
        update_field(tmp_path, 0x1000, "size", 42, "SERVER")
        backup = tmp_path / (METADATA_FILENAME + ".corrupt")
        assert backup.read_text(encoding="utf-8") == original

    def test_remove_field_recovers_from_corrupt(self, tmp_path: Path) -> None:
        from rebrew.metadata import METADATA_FILENAME, remove_field

        (tmp_path / METADATA_FILENAME).write_text("{broken", encoding="utf-8")
        # Corrupt file → returns False without crashing.
        assert remove_field(tmp_path, 0x1000, "size", "SERVER") is False


class TestMergeAnnotationEdges:
    def test_blocker_delta_non_numeric_sets_none(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation
        from rebrew.metadata import merge_into_annotation, update_field

        update_field(tmp_path, 0x1000, "blocker_delta", "abc", "SERVER")
        ann = Annotation(va=0x1000, module="SERVER", name="f")
        merge_into_annotation(ann, tmp_path)
        assert ann.blocker_delta is None

    def test_analysis_fills_empty_note(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation
        from rebrew.metadata import merge_into_annotation, update_field

        update_field(tmp_path, 0x1000, "analysis", "structural note", "SERVER")
        ann = Annotation(va=0x1000, module="SERVER", name="f")
        merge_into_annotation(ann, tmp_path)
        assert ann.note == "structural note"

    def test_analysis_does_not_override_note(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation
        from rebrew.metadata import merge_into_annotation, update_field

        update_field(tmp_path, 0x1000, "analysis", "structural note", "SERVER")
        ann = Annotation(va=0x1000, module="SERVER", name="f", note="manual note")
        merge_into_annotation(ann, tmp_path)
        assert ann.note == "manual note"

    def test_globals_list_merged(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation
        from rebrew.metadata import merge_into_annotation, update_field

        update_field(tmp_path, 0x1000, "globals", ["g_a", "g_b"], "SERVER")
        ann = Annotation(va=0x1000, module="SERVER", name="f")
        merge_into_annotation(ann, tmp_path)
        assert ann.globals_list == ["g_a", "g_b"]


class TestConcurrentWrites:
    """Concurrent metadata writers must not lose updates — every thread's
    field survives (the read-modify-write is serialised by the module lock)."""

    def test_parallel_set_field_no_lost_updates(self, tmp_path: Path) -> None:
        import threading

        from rebrew.metadata import load_metadata, set_field

        threads = []
        for i in range(8):
            t = threading.Thread(
                target=set_field, args=(tmp_path, 0x1000 + i, "note", f"n{i}", "T")
            )
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        md = load_metadata(tmp_path)
        for i in range(8):
            assert md.get(("T", 0x1000 + i), {}).get("note") == f"n{i}", f"lost update {i}"

    def test_parallel_mixed_writers(self, tmp_path: Path) -> None:
        """set_field + remove_field + update_field racing on the same file."""
        import threading

        from rebrew.metadata import load_metadata, remove_field, set_field, update_field

        def _writer(i: int) -> None:
            if i % 3 == 0:
                set_field(tmp_path, 0x2000 + i, "note", f"w{i}", "T")
            elif i % 3 == 1:
                update_field(tmp_path, 0x3000 + i, "cflags", f"/O{i}", "T")
            else:
                set_field(tmp_path, 0x4000 + i, "note", f"x{i}", "T")
                remove_field(tmp_path, 0x4000 + i, "note", "T")

        threads = [threading.Thread(target=_writer, args=(i,)) for i in range(9)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        md = load_metadata(tmp_path)
        # The set-then-remove writers end with no note (deterministic per-key).
        for i in range(9):
            key = (
                "T",
                (0x2000 + i) if i % 3 == 0 else (0x3000 + i) if i % 3 == 1 else (0x4000 + i),
            )
            if i % 3 == 0:
                assert md.get(key, {}).get("note") == f"w{i}"
            elif i % 3 == 1:
                assert md.get(key, {}).get("cflags") == f"/O{i}"
            else:
                assert "note" not in md.get(key, {})


# ---------------------------------------------------------------------------
# Writer-layer promotion policy (update_statuses_batch)
# ---------------------------------------------------------------------------


class TestUpdateStatusesBatchPromotionPolicy:
    """The batch writer must enforce the same canonical promotion policy as
    should_promote_status — a direct writer-layer caller (prove, near-diag,
    future tools) gets STUB protection and PROVEN stickiness without having
    to pre-gate."""

    def _read_status(self, metadata_dir: Path, va: int) -> str:
        return load_metadata(metadata_dir).get(("T", va), {}).get("status", "")

    def test_stub_kept_against_size_mismatch(self, tmp_path: Path) -> None:
        from rebrew.metadata import update_statuses_batch

        update_statuses_batch(tmp_path, [{"module": "T", "va": 0x1000, "new_status": "STUB"}])
        changed = update_statuses_batch(
            tmp_path, [{"module": "T", "va": 0x1000, "new_status": "SIZE_MISMATCH"}]
        )
        assert changed == 0
        assert self._read_status(tmp_path, 0x1000) == "STUB"

    def test_force_overrides_stub_guard(self, tmp_path: Path) -> None:
        from rebrew.metadata import update_statuses_batch

        update_statuses_batch(tmp_path, [{"module": "T", "va": 0x1000, "new_status": "STUB"}])
        changed = update_statuses_batch(
            tmp_path,
            [{"module": "T", "va": 0x1000, "new_status": "SIZE_MISMATCH", "force": True}],
        )
        assert changed == 1
        assert self._read_status(tmp_path, 0x1000) == "SIZE_MISMATCH"

    def test_proven_never_silently_demoted(self, tmp_path: Path) -> None:
        from rebrew.metadata import update_statuses_batch

        update_statuses_batch(tmp_path, [{"module": "T", "va": 0x1000, "new_status": "PROVEN"}])
        changed = update_statuses_batch(
            tmp_path, [{"module": "T", "va": 0x1000, "new_status": "NEAR_MATCHING"}]
        )
        assert changed == 0
        assert self._read_status(tmp_path, 0x1000) == "PROVEN"

    def test_same_status_still_clears_stale_blocker(self, tmp_path: Path) -> None:
        """An already-classified entry with a stale blocker is cleaned up by
        the same-status clear_blockers write (the blocker-clearing path must
        not be swallowed by the unchanged-status refusal)."""
        from rebrew.metadata import set_field, update_statuses_batch

        update_statuses_batch(tmp_path, [{"module": "T", "va": 0x1000, "new_status": "EXACT"}])
        set_field(tmp_path, 0x1000, "blocker", "stale note", module="T")
        changed = update_statuses_batch(
            tmp_path,
            [{"module": "T", "va": 0x1000, "new_status": "EXACT", "clear_blockers": True}],
        )
        assert changed == 1
        entry = load_metadata(tmp_path).get(("T", 0x1000), {})
        assert entry.get("status") == "EXACT"
        assert "blocker" not in entry

    def test_same_status_still_clears_stale_blocker_delta(self, tmp_path: Path) -> None:
        """An entry carrying only a stale ``blocker_delta`` (no blocker text)
        is cleaned up too — the idempotency guard must not treat the delta as
        invisible state and leave it behind after clear_blockers."""
        from rebrew.metadata import set_field, update_statuses_batch

        update_statuses_batch(tmp_path, [{"module": "T", "va": 0x1000, "new_status": "EXACT"}])
        set_field(tmp_path, 0x1000, "blocker_delta", 12, module="T")
        changed = update_statuses_batch(
            tmp_path,
            [{"module": "T", "va": 0x1000, "new_status": "EXACT", "clear_blockers": True}],
        )
        assert changed == 1
        entry = load_metadata(tmp_path).get(("T", 0x1000), {})
        assert entry.get("status") == "EXACT"
        assert "blocker" not in entry
        assert "blocker_delta" not in entry

    def test_lowercase_new_status_normalized(self, tmp_path: Path) -> None:
        """A lower-case status from any caller is persisted in canonical
        upper-case so exact-case consumers never miss it."""
        from rebrew.metadata import update_statuses_batch

        changed = update_statuses_batch(
            tmp_path, [{"module": "T", "va": 0x1000, "new_status": "exact"}]
        )
        assert changed == 1
        assert self._read_status(tmp_path, 0x1000) == "EXACT"

    def test_hand_edited_lowercase_proven_stays_sticky(self, tmp_path: Path) -> None:
        """Validation accepts any STATUS case (metadata_model uses .upper()),
        so a hand-edited ``status = "proven"`` must keep its stickiness —
        case-sensitive comparison here would silently allow a demotion."""
        from rebrew.metadata import update_statuses_batch

        save_metadata(tmp_path, {("T", 0x1000): {"status": "proven"}})
        changed = update_statuses_batch(
            tmp_path, [{"module": "T", "va": 0x1000, "new_status": "NEAR_MATCHING"}]
        )
        assert changed == 0
        assert self._read_status(tmp_path, 0x1000) == "proven"


# ---------------------------------------------------------------------------
# Case-insensitive promotion policy + canonical merge (design-review)
# ---------------------------------------------------------------------------


class TestStatusCasePolicy:
    """The promotion policy and the metadata→annotation merge must be
    robust to non-canonical (lower-case) stored statuses."""

    def test_should_promote_is_case_insensitive(self) -> None:
        from rebrew.metadata import should_promote_status

        # PROVEN is sticky against demotion, but a byte match supersedes it:
        # EXACT/RELOC show what PROVEN could not, so they are recorded.
        assert should_promote_status("proven", "EXACT") is True
        assert should_promote_status("proven", "RELOC") is True
        assert should_promote_status("proven", "NEAR_MATCHING") is False
        assert should_promote_status("proven", "SIZE_MISMATCH") is False
        assert should_promote_status("stub", "SIZE_MISMATCH") is False
        assert should_promote_status("stub", "EXACT") is True
        assert should_promote_status("near_matching", "RELOC") is True
        # Same status differing only by case is a no-op.
        assert should_promote_status("exact", "EXACT") is False

    def test_merge_normalizes_metadata_status_case(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation
        from rebrew.metadata import merge_into_annotation, save_metadata

        save_metadata(tmp_path, {("T", 0x1000): {"status": "near_matching"}})
        ann = Annotation(va=0x1000, size=10, module="T")
        merge_into_annotation(ann, tmp_path)
        assert ann.status == "NEAR_MATCHING"


# ---------------------------------------------------------------------------
# Cross-process metadata write safety (concurrency-review; error-review F6)
# ---------------------------------------------------------------------------


def _write_statuses_child(metadata_dir: str, worker_id: int, count: int) -> None:
    """Child-process worker: promote *count* unique VAs for *worker_id*.

    Module-level so multiprocessing can import it under the spawn context.
    """
    from rebrew.metadata import update_statuses_batch

    updates = [
        {
            "module": "T",
            "va": 0x1000 + worker_id * count + i,
            "new_status": "EXACT",
        }
        for i in range(count)
    ]
    update_statuses_batch(Path(metadata_dir), updates)


class TestCrossProcessMetadataLock:
    """Concurrent *processes* must not lose STATUS promotions (error-review F6).

    The thread lock is per-process; without the flock sidecar an interleaved
    read-modify-write from two processes silently drops one side's updates.
    Regression: 4 processes x 20 unique VAs each — all 80 must survive.
    """

    def test_concurrent_processes_do_not_lose_updates(self, tmp_path: Path) -> None:
        import multiprocessing as mp

        ctx = mp.get_context("spawn")
        procs = [
            ctx.Process(target=_write_statuses_child, args=(str(tmp_path), w, 20)) for w in range(4)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=90)
            assert p.exitcode == 0, f"worker exited {p.exitcode}"

        md = load_metadata(tmp_path)
        for w in range(4):
            for i in range(20):
                key = ("T", 0x1000 + w * 20 + i)
                assert md.get(key, {}).get("status") == "EXACT", f"lost update for {key}"
