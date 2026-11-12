"""A stored data verdict stays current only while its extent and placement hold."""

from __future__ import annotations

from rebrew.metadata.data import data_definition_hash


def test_definition_hash_covers_placement_fields() -> None:
    """A stored verdict is stale once its placement changes, not only its extent."""
    base = {"size": 4, "type": "int", "section": ".data", "name": "g", "note": "kept"}
    measured = data_definition_hash("SERVER", 0x1000, base)
    # A label and a note are not what the verdict measured.
    assert data_definition_hash("SERVER", 0x1000, {**base, "name": "other"}) == measured
    assert data_definition_hash("SERVER", 0x1000, {**base, "note": "edited"}) == measured
    # The fields that decide where the bytes are placed move the hash, so a
    # reader comparing a stored definition_hash treats the old verdict as stale.
    for field, value in (
        ("storage_kind", "alias"),
        ("backing", "g_root"),
        ("link_symbol", "_g"),
    ):
        assert data_definition_hash("SERVER", 0x1000, {**base, field: value}) != measured


def test_definition_hash_ignores_absent_placement_fields() -> None:
    """A row that names no placement hashes the same as one with empty placement."""
    extent = {"size": 4, "type": "int", "section": ".data"}
    placed = {**extent, "storage_kind": "", "backing": "", "link_symbol": ""}
    assert data_definition_hash("S", 0x10, extent) == data_definition_hash("S", 0x10, placed)
