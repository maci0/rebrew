"""Tests for the rebrew status command."""

from pathlib import Path

import rebrew.catalog.sections as sections_mod
from rebrew.catalog.sections import get_text_section_size
from rebrew.status import collect_target_stats

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_c(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


EXACT_GAME = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _bit_reverse

int __cdecl bit_reverse(int x)
{
    return x;
}
"""

STUB_GAME = """\
// STUB: SERVER 0x10009000
// STATUS: STUB
// ORIGIN: GAME
// SIZE: 50
// CFLAGS: /O2 /Gd
// SYMBOL: _some_stub
// BLOCKER: unknown internals

int stub(void) { return 0; }
"""

RELOC_MSVCRT = """\
// LIBRARY: SERVER 0x10023714
// STATUS: RELOC
// ORIGIN: MSVCRT
// SIZE: 103
// CFLAGS: /O1
// SYMBOL: __copy_environ
// SOURCE: ENVIRON.C

int foo(void) { return 0; }
"""


# ---------------------------------------------------------------------------
# collect_target_stats
# ---------------------------------------------------------------------------


class TestCollectTargetStats:
    def test_empty_dir(self, tmp_path: Path) -> None:
        stats = collect_target_stats("test", tmp_path)
        assert stats.file_count == 0
        assert stats.done_count == 0
        assert stats.stub_count == 0
        assert stats.status_counts == {}
        assert stats.origin_counts == {}
        assert stats.marker_counts == {}

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        stats = collect_target_stats("test", tmp_path / "nope")
        assert stats.file_count == 0

    def test_single_exact(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "bit_reverse.c", EXACT_GAME)
        stats = collect_target_stats("test", tmp_path)
        assert stats.file_count == 1
        assert stats.done_count == 1
        assert stats.stub_count == 0
        assert stats.status_counts == {"EXACT": 1}
        assert stats.origin_counts == {"GAME": 1}
        assert stats.marker_counts == {"FUNCTION": 1}
        assert stats.total_bytes_reversed == 31

    def test_mixed_files(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "bit_reverse.c", EXACT_GAME)
        _write_c(tmp_path, "some_stub.c", STUB_GAME)
        _write_c(tmp_path, "_copy_environ.c", RELOC_MSVCRT)
        stats = collect_target_stats("server.dll", tmp_path)

        assert stats.file_count == 3
        assert stats.done_count == 2  # EXACT + RELOC
        assert stats.stub_count == 1
        assert stats.status_counts["EXACT"] == 1
        assert stats.status_counts["RELOC"] == 1
        assert stats.status_counts["STUB"] == 1
        assert stats.origin_counts["GAME"] == 2
        assert stats.origin_counts["MSVCRT"] == 1
        assert stats.marker_counts["FUNCTION"] == 1
        assert stats.marker_counts["LIBRARY"] == 1
        assert stats.marker_counts["STUB"] == 1
        # STUBs are excluded from reversed byte count (only EXACT + RELOC)
        assert stats.total_bytes_reversed == 31 + 103

    def test_coverage_pct(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "bit_reverse.c", EXACT_GAME)
        stats = collect_target_stats("test", tmp_path)
        # Simulate text section size
        stats.text_section_size = 1000
        assert abs(stats.coverage_pct - 3.1) < 0.1

    def test_coverage_pct_zero_text(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "bit_reverse.c", EXACT_GAME)
        stats = collect_target_stats("test", tmp_path)
        assert stats.coverage_pct == 0.0  # no binary => text_section_size == 0


# ---------------------------------------------------------------------------
# TargetStats.to_dict
# ---------------------------------------------------------------------------


class TestTargetStatsToDict:
    def test_to_dict_schema(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "bit_reverse.c", EXACT_GAME)
        stats = collect_target_stats("test", tmp_path)
        d = stats.to_dict()

        assert d["target"] == "test"
        assert d["files"] == 1
        assert d["done"] == 1
        assert d["stubs"] == 0
        assert "by_status" in d
        assert "by_origin" in d
        assert "by_marker" in d
        assert d["by_status"]["EXACT"] == 1
        assert d["coverage_bytes"] == 31

    def test_to_dict_empty(self, tmp_path: Path) -> None:
        stats = collect_target_stats("empty", tmp_path)
        d = stats.to_dict()
        assert d["files"] == 0
        assert d["done"] == 0
        assert d["by_status"] == {}


def test_get_text_section_size_returns_zero_on_loader_error(monkeypatch) -> None:
    def _boom(_path: Path) -> int:
        raise RuntimeError("bad binary")

    monkeypatch.setattr(sections_mod, "load_binary", _boom)
    assert get_text_section_size(Path("dummy.exe")) == 0


# ---------------------------------------------------------------------------
# Overlapping function guard (Phase 1 fix)
# ---------------------------------------------------------------------------

# Two RELOC functions whose VA ranges overlap:
# func_a: VA 0x10001000, SIZE 200 → ends at 0x100010C8
# func_b: VA 0x10001064, SIZE 100 → starts inside func_a
OVERLAP_FUNC_A = """\
// FUNCTION: SERVER 0x10001000
// STATUS: RELOC
// ORIGIN: GAME
// SIZE: 200
// CFLAGS: /O2 /Gd
// SYMBOL: _func_a

int __cdecl func_a(void) { return 0; }
"""

OVERLAP_FUNC_B = """\
// FUNCTION: SERVER 0x10001064
// STATUS: RELOC
// ORIGIN: GAME
// SIZE: 100
// CFLAGS: /O2 /Gd
// SYMBOL: _func_b

int __cdecl func_b(void) { return 0; }
"""

# Two non-overlapping functions with a small gap (padding):
# func_c: VA 0x10002000, SIZE 50 → ends at 0x10002032
# func_d: VA 0x10002040, SIZE 60 → starts 14 bytes after func_c ends (padding)
GAP_FUNC_C = """\
// FUNCTION: SERVER 0x10002000
// STATUS: RELOC
// ORIGIN: GAME
// SIZE: 50
// CFLAGS: /O2 /Gd
// SYMBOL: _func_c

int __cdecl func_c(void) { return 0; }
"""

GAP_FUNC_D = """\
// FUNCTION: SERVER 0x10002040
// STATUS: RELOC
// ORIGIN: GAME
// SIZE: 60
// CFLAGS: /O2 /Gd
// SYMBOL: _func_d

int __cdecl func_d(void) { return 0; }
"""


class TestOverlappingFunctions:
    """Verify that overlapping functions do not double count coverage.

    Regression test: overlapping VA ranges should be merged before byte coverage
    is computed, while small positive gaps still count as alignment padding.
    """

    def test_overlapping_no_negative_padding(self, tmp_path: Path) -> None:
        """Overlapping functions should count only the merged byte extent."""
        _write_c(tmp_path, "func_a.c", OVERLAP_FUNC_A)
        _write_c(tmp_path, "func_b.c", OVERLAP_FUNC_B)
        stats = collect_target_stats("test", tmp_path)
        assert stats.total_bytes_reversed == 200

    def test_small_gap_adds_padding(self, tmp_path: Path) -> None:
        """Gaps of <=15 bytes between functions should count as padding."""
        _write_c(tmp_path, "func_c.c", GAP_FUNC_C)
        _write_c(tmp_path, "func_d.c", GAP_FUNC_D)
        stats = collect_target_stats("test", tmp_path)
        # func_c ends at 0x10002032, func_d starts at 0x10002040
        # gap = 0x10002040 - 0x10002032 = 14 bytes (<=15, so counted as padding)
        assert stats.total_bytes_reversed == 50 + 60 + 14
