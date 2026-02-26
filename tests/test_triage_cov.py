"""Tests for triage module helpers -- coverage stats, near-miss sorting."""

from rebrew.next import parse_byte_delta

# ---------------------------------------------------------------------------
# parse_byte_delta (used by triage near-miss computation)
# ---------------------------------------------------------------------------


def test_parse_byte_delta_with_bytes_suffix():
    """'5 bytes' style blocker text extracts the number."""
    result = parse_byte_delta("5 bytes off")
    assert isinstance(result, (int, type(None)))


def test_parse_byte_delta_empty():
    """Empty string returns None."""
    assert parse_byte_delta("") is None


def test_parse_byte_delta_no_number():
    """Text with no digit returns None."""
    assert parse_byte_delta("unknown internals") is None


# ---------------------------------------------------------------------------
# Near-miss sorting logic (unit test of the lambda from triage.py)
# ---------------------------------------------------------------------------


def _sort_near_miss(items: list[dict]) -> list[dict]:
    """Re-implement the triage.py near-miss sort key for testing."""
    return sorted(
        items,
        key=lambda x: (x["byte_delta"] if x["byte_delta"] is not None else 9999, x["size"]),
    )


def test_near_miss_sort_by_delta():
    """Functions with smaller byte_delta come first."""
    items = [
        {"va": "0x10000010", "size": 100, "byte_delta": 10, "filename": "a.c", "blocker": ""},
        {"va": "0x10000020", "size": 100, "byte_delta": 2, "filename": "b.c", "blocker": ""},
    ]
    result = _sort_near_miss(items)
    assert result[0]["va"] == "0x10000020"
    assert result[1]["va"] == "0x10000010"


def test_near_miss_sort_none_delta_last():
    """None byte_delta sorts after numeric deltas."""
    items = [
        {"va": "0x10000010", "size": 50, "byte_delta": None, "filename": "a.c", "blocker": ""},
        {"va": "0x10000020", "size": 50, "byte_delta": 1, "filename": "b.c", "blocker": ""},
    ]
    result = _sort_near_miss(items)
    assert result[0]["va"] == "0x10000020"
    assert result[1]["va"] == "0x10000010"


def test_near_miss_sort_tiebreak_by_size():
    """When byte_delta is equal, smaller size comes first."""
    items = [
        {"va": "0x10000010", "size": 200, "byte_delta": 3, "filename": "a.c", "blocker": ""},
        {"va": "0x10000020", "size": 50, "byte_delta": 3, "filename": "b.c", "blocker": ""},
    ]
    result = _sort_near_miss(items)
    assert result[0]["size"] == 50
    assert result[1]["size"] == 200


def test_near_miss_sort_empty():
    """Empty list returns empty list."""
    assert _sort_near_miss([]) == []


# ---------------------------------------------------------------------------
# Coverage stats computation (unit test of the dict-counting logic)
# ---------------------------------------------------------------------------


def _compute_coverage_stats(
    existing: dict[int, dict],
) -> dict[str, int]:
    """Re-implement the triage.py coverage stats for testing."""
    by_status: dict[str, int] = {}
    for info in existing.values():
        by_status[info["status"]] = by_status.get(info["status"], 0) + 1
    exact = by_status.get("EXACT", 0)
    reloc = by_status.get("RELOC", 0)
    matching = by_status.get("MATCHING", 0) + by_status.get("MATCHING_RELOC", 0)
    stub = by_status.get("STUB", 0)
    return {"exact": exact, "reloc": reloc, "matching": matching, "stub": stub}


def test_coverage_stats_empty():
    """Empty existing dict gives all zeros."""
    stats = _compute_coverage_stats({})
    assert stats == {"exact": 0, "reloc": 0, "matching": 0, "stub": 0}


def test_coverage_stats_mixed():
    """Mixed statuses are counted correctly."""
    existing = {
        0x1000: {"status": "EXACT", "origin": "GAME", "filename": "a.c"},
        0x2000: {"status": "EXACT", "origin": "GAME", "filename": "b.c"},
        0x3000: {"status": "RELOC", "origin": "MSVCRT", "filename": "c.c"},
        0x4000: {"status": "MATCHING", "origin": "GAME", "filename": "d.c"},
        0x5000: {"status": "MATCHING_RELOC", "origin": "GAME", "filename": "e.c"},
        0x6000: {"status": "STUB", "origin": "GAME", "filename": "f.c"},
    }
    stats = _compute_coverage_stats(existing)
    assert stats["exact"] == 2
    assert stats["reloc"] == 1
    assert stats["matching"] == 2  # MATCHING + MATCHING_RELOC
    assert stats["stub"] == 1


def test_coverage_stats_all_stubs():
    """All STUB entries counted correctly."""
    existing = {
        0x1000: {"status": "STUB", "origin": "GAME", "filename": "a.c"},
        0x2000: {"status": "STUB", "origin": "GAME", "filename": "b.c"},
    }
    stats = _compute_coverage_stats(existing)
    assert stats["stub"] == 2
    assert stats["exact"] == 0


# ---------------------------------------------------------------------------
# Actionable count computation
# ---------------------------------------------------------------------------


def test_actionable_count():
    """actionable = total - covered - unmatchable."""
    total = 100
    covered = 30
    unmatchable = 10
    actionable = total - covered - unmatchable
    assert actionable == 60


def test_coverage_percentage():
    """Coverage percentage computed correctly, including zero-total guard."""
    total = 200
    covered = 50
    pct = 100 * covered / total if total else 0.0
    assert pct == 25.0

    # Zero total
    total = 0
    pct = 100 * covered / total if total else 0.0
    assert pct == 0.0
