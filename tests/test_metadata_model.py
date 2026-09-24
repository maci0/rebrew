"""Tests for the typed metadata facade (rebrew.metadata_model)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.metadata_model import MetadataEntry, MetadataValidationError
from rebrew.workspace.status import KNOWN_STATUSES


def _entry(tmp_path: Path) -> MetadataEntry:
    """A fresh entry for a function at 0x1000 in module MAIN."""
    return MetadataEntry.load(tmp_path, 0x1000, "MAIN")


def test_load_corrupt_value_collects_problem(tmp_path: Path) -> None:
    from rebrew.metadata import _set_field
    from rebrew.metadata_model import MetadataEntry

    _set_field(tmp_path, 0x1000, "size", "abc", module="MAIN")
    _set_field(tmp_path, 0x1000, "note", "kept", module="MAIN")
    e = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert e.size is None
    assert e.note == "kept"
    assert any("size" in p for p in e.problems())
    with pytest.raises(MetadataValidationError):
        e.validate()


def test_load_problems_empty_when_clean(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    e.apply(tmp_path, size=8)
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.load_problems == []
    assert loaded.problems() == []


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


def test_apply_accepts_near_match_alias(tmp_path: Path) -> None:
    """Legacy NEAR_MATCH spelling normalizes to NEAR_MATCHING on write."""
    e = _entry(tmp_path)
    e.apply(tmp_path, status="NEAR_MATCH")
    assert MetadataEntry.load(tmp_path, 0x1000, "MAIN").status == "NEAR_MATCHING"


def test_problems_accept_near_match_alias(tmp_path: Path) -> None:
    from rebrew.metadata import _set_field

    _set_field(tmp_path, 0x1000, "status", "NEAR_MATCH", module="MAIN")
    e = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert e.status == "NEAR_MATCH"
    assert e.problems() == []


def test_apply_rejects_non_int_size(tmp_path: Path) -> None:
    e = _entry(tmp_path)
    with pytest.raises(MetadataValidationError, match="must be an int"):
        e.apply(tmp_path, size="not-a-number")


def test_apply_status_uses_promotion_gate(tmp_path: Path) -> None:
    """Matched STATUS writes clear stale blockers (update_source_status semantics)."""
    e = _entry(tmp_path)
    e.apply(tmp_path, size=16, blocker="stale blocker")
    e.apply(tmp_path, status="EXACT")
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.status == "EXACT"
    assert loaded.blocker is None  # matched promotion cleared it
    assert loaded.size == 16  # unaffected


def test_apply_near_matching_preserves_blocker(tmp_path: Path) -> None:
    """NEAR_MATCHING must not wipe blockers — same policy as rebrew test."""
    e = _entry(tmp_path)
    e.apply(tmp_path, blocker="1B register diff", blocker_delta=1)
    e.apply(tmp_path, status="NEAR_MATCHING")
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.status == "NEAR_MATCHING"
    assert loaded.blocker == "1B register diff"
    assert loaded.blocker_delta == 1


def test_apply_proven_preserves_blocker(tmp_path: Path) -> None:
    """PROVEN must keep blockers (rebrew prove clear_blockers=False)."""
    e = _entry(tmp_path)
    e.apply(tmp_path, blocker="GA_CEILING: register-only", blocker_delta=3)
    e.apply(tmp_path, status="PROVEN")
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.status == "PROVEN"
    assert loaded.blocker == "GA_CEILING: register-only"
    assert loaded.blocker_delta == 3


def test_apply_load_updated_by_roundtrip(tmp_path: Path) -> None:
    """updated_by/updated_at are typed fields, not opaque ``extra`` keys."""
    from rebrew.metadata import update_source_status

    update_source_status(tmp_path, "EXACT", "MAIN", 0x1000, updated_by="verify")
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.updated_by == "verify"
    assert loaded.updated_at
    assert "updated_by" not in loaded.extra
    assert "updated_at" not in loaded.extra


def test_load_globals_list_coerces_to_string(tmp_path: Path) -> None:
    """List-valued globals (store contract) normalize to a comma string."""
    from rebrew.metadata import save_metadata

    save_metadata(tmp_path, {("MAIN", 0x1000): {"globals": ["g_foo", "g_bar"]}})
    loaded = MetadataEntry.load(tmp_path, 0x1000, "MAIN")
    assert loaded.globals == "g_foo, g_bar"
    assert loaded.problems() == []


def test_apply_proven_demoted_by_plain_write(tmp_path: Path) -> None:
    """PROVEN is not sticky: a non-force write replaces it."""
    e = _entry(tmp_path)
    e.apply(tmp_path, status="PROVEN")
    e.apply(tmp_path, status="NEAR_MATCHING")
    assert MetadataEntry.load(tmp_path, 0x1000, "MAIN").status == "NEAR_MATCHING"


def test_apply_skip_needs_force(tmp_path: Path) -> None:
    """SKIP is parked: a plain apply is refused, force=True overrides."""
    e = _entry(tmp_path)
    e.apply(tmp_path, status="SKIP")
    e.apply(tmp_path, status="STUB")
    assert MetadataEntry.load(tmp_path, 0x1000, "MAIN").status == "SKIP"
    # force=True is the explicit user-intent override (lint --fix migration).
    e.apply(tmp_path, status="STUB", force=True)
    assert MetadataEntry.load(tmp_path, 0x1000, "MAIN").status == "STUB"


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
            # Control characters are sanitized on write (tomlkit>=0.15
            # emits them as invalid TOML), so roundtrip only promises
            # printable text + tab/newline.
            fields[key] = draw(
                st.text(
                    alphabet=st.characters(min_codepoint=0x20, blacklist_categories=("Cc", "Cs")),
                    max_size=40,
                )
            )
    if draw(st.booleans()):
        text = st.text(
            alphabet=st.characters(min_codepoint=0x20, blacklist_categories=("Cc", "Cs")),
            max_size=16,
        )
        fields["globals"] = ", ".join(draw(st.lists(text, max_size=4)))
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


class TestCoercionRejectsWrongTypes:
    def test_bool_is_not_an_int(self) -> None:
        """bool is an int subclass; `size = true` must not load as 1 (the
        sibling metadata.update_field rejects bools)."""
        import pytest

        from rebrew.metadata_model import MetadataValidationError, _coerce

        with pytest.raises(MetadataValidationError):
            _coerce("size", True)

    def test_non_integral_float_is_rejected(self) -> None:
        """``size = 12.9`` must not truncate to 12."""
        import pytest

        from rebrew.metadata_model import MetadataValidationError, _coerce

        with pytest.raises(MetadataValidationError):
            _coerce("size", 12.9)
        with pytest.raises(MetadataValidationError):
            _coerce("blocker_delta", -1.5)

    def test_non_finite_float_is_rejected(self) -> None:
        """``±inf`` used to raise OverflowError past load's catch."""
        import pytest

        from rebrew.metadata_model import MetadataValidationError, _coerce

        with pytest.raises(MetadataValidationError):
            _coerce("size", float("inf"))
        with pytest.raises(MetadataValidationError):
            _coerce("size", float("nan"))

    def test_integral_float_still_coerces(self) -> None:
        from rebrew.metadata_model import _coerce

        assert _coerce("size", 32.0) == 32

    def test_hex_string_still_coerces(self) -> None:
        from rebrew.metadata_model import _coerce

        assert _coerce("size", "0x20") == 32

    def test_non_string_status_is_a_load_problem(self, tmp_path: Path) -> None:
        """`status = 5` used to load uncoerced and then crash problems() on
        `.upper()`; it must surface as a load problem instead."""
        from rebrew.metadata_model import MetadataEntry

        (tmp_path / "rebrew-functions.toml").write_text(
            '["SERVER.0x1000"]\nstatus = 5\n', encoding="utf-8"
        )
        entry = MetadataEntry.load(tmp_path, 0x1000, "SERVER")
        assert entry.status is None
        problems = entry.problems()  # must not raise
        assert any("status" in p for p in problems)
