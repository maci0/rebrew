"""Tests for rebrew.sidecar — per-directory metadata store."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rebrew.sidecar import (
    SIDECAR_FILENAME,
    _parse_key,
    _qualified_key,
    delete_field,
    get_entry,
    is_sidecar_key,
    load_sidecar,
    merge_into_annotation,
    save_sidecar,
    set_field,
    sidecar_path,
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
# sidecar_path
# ---------------------------------------------------------------------------


class TestSidecarPath:
    def test_from_file(self, tmp_path: Path) -> None:
        src = tmp_path / "MyFunc.c"
        assert sidecar_path(src) == tmp_path / SIDECAR_FILENAME

    def test_from_directory(self, tmp_path: Path) -> None:
        assert sidecar_path(tmp_path) == tmp_path / SIDECAR_FILENAME


# ---------------------------------------------------------------------------
# is_sidecar_key
# ---------------------------------------------------------------------------


class TestIsSidecarKey:
    def test_status(self) -> None:
        assert is_sidecar_key("STATUS") is True

    def test_size(self) -> None:
        assert is_sidecar_key("SIZE") is True

    def test_cflags(self) -> None:
        assert is_sidecar_key("CFLAGS") is True

    def test_blocker(self) -> None:
        assert is_sidecar_key("BLOCKER") is True

    def test_note(self) -> None:
        assert is_sidecar_key("NOTE") is True

    def test_ghidra(self) -> None:
        assert is_sidecar_key("GHIDRA") is True

    def test_origin_not_sidecar(self) -> None:
        # ORIGIN stays in the .c file
        assert is_sidecar_key("ORIGIN") is False

    def test_marker_not_sidecar(self) -> None:
        assert is_sidecar_key("FUNCTION") is False
        assert is_sidecar_key("LIBRARY") is False

    def test_case_insensitive(self) -> None:
        assert is_sidecar_key("status") is True
        assert is_sidecar_key("CfLaGs") is True


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
# load_sidecar / save_sidecar round-trip
# ---------------------------------------------------------------------------


class TestLoadSaveSidecar:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = load_sidecar(tmp_path)
        assert result == {}

    def test_round_trip_qualified_keys(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x01006364): {"size": 80, "cflags": "/O1 /Gd", "status": "MATCHING"},
            ("SERVER", 0x01006400): {"size": 120, "cflags": "/O2 /Gd", "status": "EXACT"},
        }
        save_sidecar(tmp_path, data)
        loaded = load_sidecar(tmp_path)
        assert loaded[("SERVER", 0x01006364)]["size"] == 80
        assert loaded[("SERVER", 0x01006364)]["status"] == "MATCHING"
        assert loaded[("SERVER", 0x01006400)]["cflags"] == "/O2 /Gd"

    def test_empty_entries_skipped(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x01006364): {"size": 80, "status": "EXACT"},
            ("SERVER", 0x0DEAD000): {},  # empty — should be skipped
        }
        save_sidecar(tmp_path, data)
        loaded = load_sidecar(tmp_path)
        assert ("SERVER", 0x01006364) in loaded
        assert ("SERVER", 0x0DEAD000) not in loaded

    def test_sorted_output(self, tmp_path: Path) -> None:
        data = {
            ("SERVER", 0x02000000): {"size": 10, "status": "EXACT"},
            ("SERVER", 0x01000000): {"size": 20, "status": "MATCHING"},
        }
        save_sidecar(tmp_path, data)
        text = (tmp_path / SIDECAR_FILENAME).read_text()
        idx_low = text.index("0x01000000")
        idx_high = text.index("0x02000000")
        assert idx_low < idx_high

    def test_corrupt_toml_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / SIDECAR_FILENAME).write_text("this is not [[valid toml", encoding="utf-8")
        result = load_sidecar(tmp_path)
        assert result == {}

    def test_multi_target_no_collision(self, tmp_path: Path) -> None:
        """Two different modules at the same VA coexist in one sidecar."""
        data = {
            ("SERVER", 0x10008880): {"size": 42, "status": "EXACT"},
            ("CLIENT", 0x10008880): {"size": 42, "status": "MATCHING"},
        }
        save_sidecar(tmp_path, data)
        loaded = load_sidecar(tmp_path)
        assert loaded[("SERVER", 0x10008880)]["status"] == "EXACT"
        assert loaded[("CLIENT", 0x10008880)]["status"] == "MATCHING"


# ---------------------------------------------------------------------------
# get_entry
# ---------------------------------------------------------------------------


class TestGetEntry:
    def test_missing_va(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "EXACT"}})
        assert get_entry(tmp_path, 0x99999999, module="SERVER") == {}

    def test_present_va_with_module(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "EXACT"}})
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["status"] == "EXACT"
        assert entry["size"] == 80

    def test_no_sidecar(self, tmp_path: Path) -> None:
        assert get_entry(tmp_path, 0x01006364, module="SERVER") == {}


# ---------------------------------------------------------------------------
# set_field
# ---------------------------------------------------------------------------


class TestSetField:
    def test_creates_file_and_entry(self, tmp_path: Path) -> None:
        set_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["status"] == "EXACT"

    def test_updates_existing_entry(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "MATCHING"}})
        set_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["status"] == "EXACT"
        assert entry["size"] == 80  # untouched

    def test_adds_new_field_to_existing_entry(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "MATCHING"}})
        set_field(tmp_path, 0x01006364, "blocker", "1B diff", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["blocker"] == "1B diff"
        assert entry["status"] == "MATCHING"

    def test_adds_entry_to_existing_file(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01000000): {"size": 10, "status": "EXACT"}})
        set_field(tmp_path, 0x02000000, "status", "MATCHING", module="SERVER")
        loaded = load_sidecar(tmp_path)
        assert ("SERVER", 0x01000000) in loaded
        assert ("SERVER", 0x02000000) in loaded

    def test_idempotent(self, tmp_path: Path) -> None:
        set_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")
        set_field(tmp_path, 0x01006364, "status", "EXACT", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert entry["status"] == "EXACT"


# ---------------------------------------------------------------------------
# delete_field
# ---------------------------------------------------------------------------


class TestDeleteField:
    def test_removes_field(self, tmp_path: Path) -> None:
        save_sidecar(
            tmp_path,
            {("SERVER", 0x01006364): {"size": 80, "status": "MATCHING", "blocker": "1B diff"}},
        )
        delete_field(tmp_path, 0x01006364, "blocker", module="SERVER")
        entry = get_entry(tmp_path, 0x01006364, module="SERVER")
        assert "blocker" not in entry
        assert entry["status"] == "MATCHING"

    def test_noop_on_missing_key(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"size": 80, "status": "MATCHING"}})
        # Should not raise
        delete_field(tmp_path, 0x01006364, "blocker", module="SERVER")

    def test_noop_on_missing_va(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"size": 80}})
        delete_field(tmp_path, 0x99999999, "status", module="SERVER")  # no-op

    def test_noop_when_no_file(self, tmp_path: Path) -> None:
        delete_field(tmp_path, 0x01006364, "status", module="SERVER")  # no error


# ---------------------------------------------------------------------------
# merge_into_annotation
# ---------------------------------------------------------------------------


class TestMergeIntoAnnotation:
    def test_merges_all_scalar_fields(self, tmp_path: Path) -> None:
        save_sidecar(
            tmp_path,
            {
                ("SERVER", 0x01006364): {
                    "size": 80,
                    "cflags": "/O1 /Gd",
                    "status": "MATCHING",
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
        assert ann.status == "MATCHING"
        assert ann.blocker == "1B diff"
        assert ann.blocker_delta == 1
        assert ann.note == "check xref"
        assert ann.ghidra == "IsUtf8"
        assert ann.source == "SBHEAP.C:100"

    def test_section_not_owned_by_function_sidecar(self, tmp_path: Path) -> None:
        """SECTION is owned by data_sidecar.py — function sidecar must not merge it."""
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"section": ".text", "size": 80}})
        ann = _make_annotation(va=0x01006364, module="SERVER", section="")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.section == ""  # section NOT applied by function sidecar
        assert ann.size == 80  # size still applied normally

    def test_sidecar_wins_over_inline(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"status": "EXACT", "size": 90}})
        ann = _make_annotation(va=0x01006364, module="SERVER", status="MATCHING", size=80)
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.status == "EXACT"
        assert ann.size == 90

    def test_no_sidecar_leaves_annotation_unchanged(self, tmp_path: Path) -> None:
        ann = _make_annotation(va=0x01006364, module="SERVER", status="MATCHING", size=80)
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.status == "MATCHING"
        assert ann.size == 80

    def test_partial_entry_leaves_unset_fields_unchanged(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"status": "EXACT"}})
        ann = _make_annotation(
            va=0x01006364, module="SERVER", status="MATCHING", size=80, cflags="/O2 /Gd"
        )
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.status == "EXACT"  # sidecar wins
        assert ann.size == 80  # unchanged
        assert ann.cflags == "/O2 /Gd"  # unchanged

    def test_globals_from_list(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"globals": ["g_foo", "g_bar"]}})
        ann = _make_annotation(va=0x01006364, module="SERVER")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.globals_list == ["g_foo", "g_bar"]

    def test_globals_from_comma_string(self, tmp_path: Path) -> None:
        # Tolerate comma-string globals (inline annotation style)
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"globals": "g_foo, g_bar"}})
        ann = _make_annotation(va=0x01006364, module="SERVER")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.globals_list == ["g_foo", "g_bar"]

    def test_returns_same_object(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006364): {"status": "EXACT"}})
        ann = _make_annotation(va=0x01006364, module="SERVER")
        result = merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert result is ann

    def test_va_not_in_sidecar_is_noop(self, tmp_path: Path) -> None:
        save_sidecar(tmp_path, {("SERVER", 0x01006000): {"status": "EXACT"}})
        ann = _make_annotation(va=0x01006364, module="SERVER", status="MATCHING")
        merge_into_annotation(ann, tmp_path)  # type: ignore[arg-type]
        assert ann.status == "MATCHING"  # not touched

    def test_multi_target_merge_isolated(self, tmp_path: Path) -> None:
        """Two different modules at same VA merge independently."""
        save_sidecar(
            tmp_path,
            {
                ("SERVER", 0x10008880): {"status": "EXACT", "size": 42},
                ("CLIENT", 0x10008880): {"status": "MATCHING", "size": 42, "blocker": "regs"},
            },
        )
        ann_server = _make_annotation(va=0x10008880, module="SERVER")
        ann_client = _make_annotation(va=0x10008880, module="CLIENT")
        merge_into_annotation(ann_server, tmp_path)  # type: ignore[arg-type]
        merge_into_annotation(ann_client, tmp_path)  # type: ignore[arg-type]
        assert ann_server.status == "EXACT"
        assert ann_server.blocker == ""  # CLIENT blocker not leaked into SERVER
        assert ann_client.status == "MATCHING"
        assert ann_client.blocker == "regs"


# ---------------------------------------------------------------------------
# Walk-up resolution
# ---------------------------------------------------------------------------


class TestWalkUp:
    """load_sidecar / set_field / delete_field should climb parent dirs."""

    def test_load_finds_sidecar_in_parent(self, tmp_path: Path) -> None:
        """load_sidecar(child) returns entries from parent sidecar."""
        parent = tmp_path / "root"
        child = parent / "subdir"
        child.mkdir(parents=True)
        save_sidecar(parent, {("SERVER", 0x01000000): {"status": "EXACT", "size": 10}})
        loaded = load_sidecar(child)  # no sidecar in child — climbs to parent
        assert ("SERVER", 0x01000000) in loaded
        assert loaded[("SERVER", 0x01000000)]["status"] == "EXACT"

    def test_child_sidecar_takes_precedence_over_parent(self, tmp_path: Path) -> None:
        """A child-dir sidecar is found first and shadows the parent's."""
        parent = tmp_path / "root"
        child = parent / "subdir"
        child.mkdir(parents=True)
        save_sidecar(parent, {("SERVER", 0x01000000): {"status": "MATCHING", "size": 5}})
        save_sidecar(child, {("SERVER", 0x01000000): {"status": "EXACT", "size": 99}})
        loaded = load_sidecar(child)
        assert loaded[("SERVER", 0x01000000)]["status"] == "EXACT"  # child wins
        assert loaded[("SERVER", 0x01000000)]["size"] == 99

    def test_no_sidecar_anywhere_returns_empty(self, tmp_path: Path) -> None:
        child = tmp_path / "a" / "b" / "c"
        child.mkdir(parents=True)
        assert load_sidecar(child) == {}

    def test_set_field_writes_to_found_ancestor(self, tmp_path: Path) -> None:
        """set_field(child, ...) updates the ancestor sidecar, not creates a child file."""
        parent = tmp_path / "root"
        child = parent / "subdir"
        child.mkdir(parents=True)
        save_sidecar(parent, {("SERVER", 0x01000000): {"status": "MATCHING", "size": 10}})
        set_field(child, 0x01000000, "status", "EXACT", module="SERVER")
        # Parent file updated:
        loaded = load_sidecar(parent)
        assert loaded[("SERVER", 0x01000000)]["status"] == "EXACT"
        # No new child file created:
        assert not (child / SIDECAR_FILENAME).exists()

    def test_set_field_creates_in_place_when_no_ancestor(self, tmp_path: Path) -> None:
        """When no ancestor sidecar exists, set_field creates one in the given dir."""
        child = tmp_path / "orphan"
        child.mkdir()
        set_field(child, 0x01000000, "status", "STUB", module="SERVER")
        assert (child / SIDECAR_FILENAME).exists()
        assert get_entry(child, 0x01000000, module="SERVER")["status"] == "STUB"

    def test_delete_field_updates_ancestor(self, tmp_path: Path) -> None:
        parent = tmp_path / "root"
        child = parent / "sub"
        child.mkdir(parents=True)
        save_sidecar(parent, {("SERVER", 0x01000000): {"status": "EXACT", "blocker": "old"}})
        delete_field(child, 0x01000000, "blocker", module="SERVER")
        loaded = load_sidecar(parent)
        assert "blocker" not in loaded[("SERVER", 0x01000000)]

    def test_grandparent_sidecar_found(self, tmp_path: Path) -> None:
        """Walk-up skips multiple empty levels."""
        grandparent = tmp_path / "gp"
        child = grandparent / "a" / "b"
        child.mkdir(parents=True)
        save_sidecar(grandparent, {("SERVER", 0xDEAD): {"status": "STUB", "size": 1}})
        loaded = load_sidecar(child)
        assert ("SERVER", 0xDEAD) in loaded
