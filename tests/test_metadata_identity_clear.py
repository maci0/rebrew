"""Identity removal must preserve evidence and other targets at the same VA."""

from pathlib import Path
from typing import Any

import pytest

from rebrew.metadata import (
    METADATA_FILENAME,
    clear_identity_fields,
    get_entry,
    load_metadata,
    save_metadata,
)


def test_identity_removal_preserves_verdict_provenance_and_other_target(tmp_path: Path) -> None:
    entry: dict[str, Any] = {
        "file": "old.c",
        "name": "old",
        "symbol": "_old",
        "marker_type": "FUNCTION",
        "status": "RELOC",
        "size": 80,
        "note": "keep native evidence",
        "updated_by": "verify",
        "updated_at": "2026-10-04T00:00:00+00:00",
        "verification": {"status": "RELOC", "source_hash": "abc", "reference_hash": "def"},
    }
    other: dict[str, Any] = {"file": "other.c", "name": "other", "status": "EXACT"}
    save_metadata(tmp_path, {("SERVER", 0x1000): entry, ("GOLD", 0x1000): other})

    assert clear_identity_fields(tmp_path, 0x1000, "SERVER", "file", "name") is True

    assert get_entry(tmp_path, 0x1000, "SERVER") == {
        key: value for key, value in entry.items() if key not in {"file", "name"}
    }
    assert get_entry(tmp_path, 0x1000, "GOLD") == other
    path = tmp_path / METADATA_FILENAME
    contents, measured_at = path.read_bytes(), path.stat().st_mtime_ns
    assert clear_identity_fields(tmp_path, 0x1000, "SERVER", "file", "name") is False
    assert (path.read_bytes(), path.stat().st_mtime_ns) == (contents, measured_at)


@pytest.mark.parametrize("invalid", ["status", "verification", "updated_by", "unknown", "FILE"])
def test_invalid_identity_key_cannot_partially_clear_a_row(tmp_path: Path, invalid: str) -> None:
    save_metadata(tmp_path, {("SERVER", 0x1000): {"file": "old.c", "status": "EXACT"}})
    path = tmp_path / METADATA_FILENAME
    before = path.read_bytes()

    with pytest.raises(ValueError, match="unknown marker identity field"):
        clear_identity_fields(tmp_path, 0x1000, "SERVER", "file", invalid)

    assert path.read_bytes() == before


def test_last_identity_is_pruned_without_deleting_the_other_target(tmp_path: Path) -> None:
    save_metadata(
        tmp_path,
        {("SERVER", 0x1000): {"file": "old.c"}, ("GOLD", 0x1000): {"file": "other.c"}},
    )

    assert clear_identity_fields(tmp_path, 0x1000, "SERVER", "file") is True
    assert load_metadata(tmp_path) == {("GOLD", 0x1000): {"file": "other.c"}}
    assert clear_identity_fields(tmp_path, 0x1000, "SERVER", "file") is False


def test_empty_request_and_missing_store_do_not_create_metadata(tmp_path: Path) -> None:
    assert clear_identity_fields(tmp_path, 0x1000, "SERVER") is False
    assert clear_identity_fields(tmp_path, 0x1000, "SERVER", "file") is False
    assert not (tmp_path / METADATA_FILENAME).exists()
