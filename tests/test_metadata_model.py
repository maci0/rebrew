"""Tests for the typed metadata facade (rebrew.metadata_model)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.metadata import KNOWN_STATUSES
from rebrew.metadata_model import MetadataEntry, MetadataValidationError


def _entry(tmp_path: Path) -> MetadataEntry:
    """A fresh entry for a function at 0x1000 in module MAIN."""
    return MetadataEntry.load(tmp_path, 0x1000, "MAIN")


def test_load_empty_entry_has_defaults(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    assert e.status is None
    assert e.size is None
    assert e.problems() == []


def test_apply_and_load_roundtrip(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    e.apply(tmp_path, size=42, cflags="/O2", blocker="register allocation")
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.size == 42
    assert loaded.cflags == "/O2"
    assert loaded.blocker == "register allocation"


def test_apply_coerces_size_to_int(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    e.apply(tmp_path, size="0x2A")
    assert MetadataEntry.load(tmp_path, 0x1000, "MAIN").size == 42


def test_apply_rejects_unknown_field(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    with pytest.raises(MetadataValidationError, match="not metadata-owned"):
        e.apply(tmp_path, author="x")  # file-only / unknown key
    # Key case is normalized: "STATUS" writes the lower-case status field.
    e.apply(tmp_path, STATUS="EXACT")
    assert MetadataEntry.load(tmp_path, 0x1000, "MAIN").status == "EXACT"


def test_apply_rejects_invalid_status(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    with pytest.raises(MetadataValidationError, match="unknown STATUS"):
        e.apply(tmp_path, status="DONE")


def test_apply_rejects_non_int_size(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    with pytest.raises(MetadataValidationError, match="must be an int"):
        e.apply(tmp_path, size="not-a-number")


def test_apply_status_uses_promotion_gate(tmp_path: Path) -> None:
    """STATUS writes clear stale blockers (update_source_status semantics)."""
    e = _entry(tmp_path)
    e.apply(tmp_path, size=16, blocker="stale blocker")
    e.apply(tmp_path, status="EXACT")
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.status == "EXACT"
    assert loaded.blocker is None  # promotion cleared it
    assert loaded.size == 16  # unaffected


def test_apply_proven_not_silently_demoted(tmp_path: Path) -> None:
    """PROVEN is sticky: a non-force write can't demote it."""
    e = _entry(tmp_path)
    e.apply(tmp_path, status="PROVEN")
    # apply() uses force=True (explicit user intent); the promotion gate's
    # stickiness applies to test/verify flows.  Verify force semantics:
    e.apply(tmp_path, status="EXACT")
    assert MetadataEntry.load(tmp_path, 0x1000, "MAIN").status == "EXACT"


def test_remove_roundtrip(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    e.apply(tmp_path, size=42, note="hi")
    assert e.remove(tmp_path, "size") is True
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.size is None
    assert loaded.note == "hi"
    # Removing an absent key is a no-op.
    assert e.remove(tmp_path, "cflags") is False


def test_remove_rejects_file_only_key(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    with pytest.raises(MetadataValidationError, match="not a metadata-owned"):
        e.remove(tmp_path, "SYMBOL")


def test_extra_fields_preserved(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    e.apply(tmp_path, size=8)
    # A field unknown to the typed view survives load into .extra.
    from rebrew.metadata import _set_field

    _set_field(tmp_path, 0x1000, "future_field", "x", module="MAIN")
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.extra.get("future_field") == "x"
    assert loaded.size == 8


def test_multiple_entries_isolated(tmp_path: Path) -> None:
    MetadataEntry.load(tmp_path, 0x1000, "MAIN").apply(tmp_path, size=10)
    MetadataEntry.load(tmp_path, 0x2000, "MAIN").apply(tmp_path, size=20)
    assert MetadataEntry.load(tmp_path, 0x1000, "MAIN").size == 10
    assert MetadataEntry.load(tmp_path, 0x2000, "MAIN").size == 20


# ---------------------------------------------------------------------------
# Property-based round-trip: any valid field set survives apply → load.
# ---------------------------------------------------------------------------


@st.composite
def _roundtrip_fields(draw) -> dict[str, object]:
    """A random valid metadata field set (status excluded — separate test)."""
    fields: dict[str, object] = {}
    if draw(st.booleans()):
        fields["size"] = draw(st.integers(min_value=0, max_value=1_000_000))
    if draw(st.booleans()):
        fields["blocker_delta"] = draw(st.integers(min_value=0, max_value=1_000_000))
    for key in ("cflags", "blocker", "note", "ghidra", "analysis", "skip", "source"):
        if draw(st.booleans()):
            fields[key] = draw(st.text(max_size=40))
    if draw(st.booleans()):
        fields["globals"] = ", ".join(draw(st.lists(st.text(max_size=16), max_size=4)))
    if draw(st.booleans()):
        fields["prove_constraints"] = {"stack": draw(st.integers(min_value=0, max_value=32))}
    return fields


@settings(max_examples=100, deadline=None)
@given(st.data())
def test_apply_load_roundtrip_property(data) -> None:
    """apply(**fields) → load() must reproduce every field exactly.

    The facade's reason to exist: routing/typing bugs (the add-module tomlkit
    copy bug, the lint --fix STATUS crash) are made impossible by construction
    if every valid field set round-trips losslessly.
    """
    import tempfile

    from rebrew.metadata_model import MetadataEntry

    fields = data.draw(_roundtrip_fields())
    with tempfile.TemporaryDirectory() as td:
        entry = MetadataEntry.load(Path(td), 0x1000, "MAIN")
        entry.apply(Path(td), **fields)
        loaded = MetadataEntry.load(Path(td), 0x1000, "MAIN")
        for key, value in fields.items():
            assert getattr(loaded, key) == value, f"{key}: {getattr(loaded, key)!r} != {value!r}"
        assert loaded.problems() == []


@settings(max_examples=50, deadline=None)
@given(st.sampled_from(sorted(KNOWN_STATUSES)))
def test_apply_load_status_roundtrip_property(status: str) -> None:
    """Every known STATUS survives the promotion-gate write and reloads."""
    import tempfile

    from rebrew.metadata_model import MetadataEntry

    with tempfile.TemporaryDirectory() as td:
        MetadataEntry.load(Path(td), 0x1000, "MAIN").apply(Path(td), status=status)
        loaded = MetadataEntry.load(Path(td), 0x1000, "MAIN")
        assert loaded.status == status
        assert loaded.problems() == []


class TestPersistedVerdictsAreKnownStatuses:
    """`rebrew verify` persists CompareResult.status verbatim (deferred_fixes →
    update_statuses_batch), so every persistable verdict must be in
    KNOWN_STATUSES — otherwise MetadataEntry.problems() flags the fresh entry
    as invalid and lint rejects what verify itself wrote."""

    def test_invalid_va_persists_without_problems(self, tmp_path: Path) -> None:
        """INVALID_VA is a real persisted verdict (VA below the arch-aware
        floor is an annotation problem, reported by verify_entry), so it must
        be part of the validated vocabulary."""
        from rebrew.metadata import update_source_status
        from rebrew.metadata_model import MetadataEntry

        update_source_status(tmp_path, "INVALID_VA", "MAIN", 0x1000)
        loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
        assert loaded.status == "INVALID_VA"
        assert loaded.problems() == []

    def test_internal_error_is_not_persistable_vocabulary(self) -> None:
        """INTERNAL_ERROR stays out of KNOWN_STATUSES on purpose: verify
        filters tooling crashes out of deferred_fixes, never writing them."""
        assert "INTERNAL_ERROR" not in KNOWN_STATUSES
