"""A function an earned status describes stops being a stub in the registry (lint E017)."""

from typing import Any
lazy from pathlib import Path

import pytest

from rebrew.metadata.functions import (
    get_entry,
    save_metadata,
    update_source_status,
    update_statuses_batch,
)


def _row(kind: str, status: str = "STUB") -> dict[str, Any]:
    return {
        "file": "src/a.c",
        "name": "a",
        "symbol": "_a",
        "kind": kind,
        "status": status,
        "size": 8,
    }


@pytest.mark.parametrize("earned", ["EXACT", "RELOC", "PROVEN"])
def test_an_earned_status_turns_a_stub_into_a_function(tmp_path: Path, earned: str) -> None:
    save_metadata(tmp_path, {("SERVER", 0x1000): _row("STUB")})
    assert update_source_status(tmp_path, earned, "SERVER", 0x1000, updated_by="test") is True
    entry = get_entry(tmp_path, 0x1000, "SERVER")
    assert (entry["status"], entry["kind"]) == (earned, "FUNCTION")


def test_a_status_that_is_not_earned_keeps_the_stub(tmp_path: Path) -> None:
    save_metadata(tmp_path, {("SERVER", 0x1000): _row("STUB")})
    update_source_status(tmp_path, "NEAR_MATCHING", "SERVER", 0x1000, updated_by="test")
    assert get_entry(tmp_path, 0x1000, "SERVER")["kind"] == "STUB"


def test_other_kinds_and_other_rows_are_left_alone(tmp_path: Path) -> None:
    save_metadata(
        tmp_path,
        {
            ("SERVER", 0x1000): _row("LIBRARY"),
            ("SERVER", 0x2000): _row("STUB"),
            ("SERVER", 0x3000): _row("STUB"),
        },
    )
    update_statuses_batch(
        tmp_path,
        [
            {"module": "SERVER", "va": 0x1000, "new_status": "EXACT", "updated_by": "verify"},
            {"module": "SERVER", "va": 0x2000, "new_status": "EXACT", "updated_by": "verify"},
        ],
    )
    assert get_entry(tmp_path, 0x1000, "SERVER")["kind"] == "LIBRARY"
    assert get_entry(tmp_path, 0x2000, "SERVER")["kind"] == "FUNCTION"
    assert get_entry(tmp_path, 0x3000, "SERVER")["kind"] == "STUB"


def test_a_row_already_earned_with_a_stale_stub_kind_is_cleared_by_the_next_write(
    tmp_path: Path,
) -> None:
    save_metadata(tmp_path, {("SERVER", 0x1000): _row("STUB", status="EXACT")})
    assert update_source_status(tmp_path, "EXACT", "SERVER", 0x1000, updated_by="test") is True
    assert get_entry(tmp_path, 0x1000, "SERVER")["kind"] == "FUNCTION"


def test_a_kind_the_same_update_names_is_kept(tmp_path: Path) -> None:
    save_metadata(tmp_path, {("SERVER", 0x1000): _row("FUNCTION")})
    update_statuses_batch(
        tmp_path,
        [
            {
                "module": "SERVER",
                "va": 0x1000,
                "new_status": "EXACT",
                "identity": {"kind": "STUB"},
                "force": True,
            }
        ],
    )
    assert get_entry(tmp_path, 0x1000, "SERVER")["kind"] == "STUB"
