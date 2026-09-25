"""Tests for catalog/grid.py — range merging and section/label lookup."""

from rebrew.catalog.grid import (
    _build_cells,
    _build_label_index,
    _build_section_index,
    _find_ghidra_data_label,
    _lookup_section,
)
from rebrew.catalog.models import GhidraDataLabel


class TestLookupSection:
    def _idx(self) -> object:
        return _build_section_index(
            {
                ".text": {"va": 0x1000, "size": 0x100, "fileOffset": 0},
                ".data": {"va": 0x2000, "size": 0x200, "fileOffset": 0x100},
            }
        )

    def test_in_range(self) -> None:
        starts, info = self._idx()
        result = _lookup_section(0x1050, starts, info)
        assert result is not None
        name, file_off, text_off = result
        assert name == ".text"
        assert file_off == 0x50
        assert text_off == 0x50

    def test_second_section(self) -> None:
        starts, info = self._idx()
        # Nonzero fileOffset separates the file offset from the in-section offset.
        assert _lookup_section(0x2100, starts, info) == (".data", 0x200, 0x100)

    def test_end_is_exclusive(self) -> None:
        starts, info = self._idx()
        assert _lookup_section(0x10FF, starts, info) == (".text", 0xFF, 0xFF)
        # 0x1100 falls in the gap between .text and .data.
        assert _lookup_section(0x1100, starts, info) is None

    def test_below_first(self) -> None:
        starts, info = _build_section_index(
            {".text": {"va": 0x1000, "size": 0x100, "fileOffset": 0}}
        )
        assert _lookup_section(0x500, starts, info) is None

    def test_outer_tail_past_a_nested_section(self) -> None:
        starts, info = _build_section_index(
            {
                ".text": {"va": 0x1000, "size": 0x300, "fileOffset": 0},
                ".inner": {"va": 0x1100, "size": 0x20, "fileOffset": 0x100},
            }
        )
        assert _lookup_section(0x1200, starts, info)[0] == ".text"
        assert _lookup_section(0x1110, starts, info)[0] == ".inner"

    def test_above_last(self) -> None:
        starts, info = _build_section_index(
            {".text": {"va": 0x1000, "size": 0x100, "fileOffset": 0}}
        )
        assert _lookup_section(0x1200, starts, info) is None


class TestFindGhidraDataLabel:
    def _label(self, va: int, size: int) -> GhidraDataLabel:
        return GhidraDataLabel(va=va, size=size, label="x")

    def test_inside_region(self) -> None:
        idx = _build_label_index({0x5000: self._label(0x5000, 20)})
        result = _find_ghidra_data_label(0x500A, idx)
        assert result is not None
        assert result[0] == 0x5000

    def test_outside_region(self) -> None:
        idx = _build_label_index({0x5000: self._label(0x5000, 20)})
        assert _find_ghidra_data_label(0x5020, idx) is None

    def test_none_index(self) -> None:
        assert _find_ghidra_data_label(0x5000, None) is None

    def test_outer_tail_past_a_nested_label(self) -> None:
        idx = _build_label_index(
            {
                0x5000: self._label(0x5000, 0x300),
                0x5100: self._label(0x5100, 0x20),
            }
        )
        assert _find_ghidra_data_label(0x5200, idx)[0] == 0x5000
        assert _find_ghidra_data_label(0x5110, idx)[0] == 0x5100

    def test_before_first(self) -> None:
        idx = _build_label_index({0x5000: self._label(0x5000, 20)})
        assert _find_ghidra_data_label(0x1000, idx) is None


class TestBuildCells:
    def test_zero_or_negative_unit_bytes_returns_empty(self) -> None:
        segs = [(0, 100, "exact", [], None, None)]
        assert _build_cells(segs, 0, 10) == []
        assert _build_cells(segs, -1, 10) == []

    def test_zero_or_negative_columns_returns_empty(self) -> None:
        segs = [(0, 100, "exact", [], None, None)]
        assert _build_cells(segs, 10, 0) == []
        assert _build_cells(segs, 10, -5) == []

    def test_empty_or_negative_segment_skipped(self) -> None:
        segs = [(100, 100, "exact", [], None, None), (50, 40, "exact", [], None, None)]
        assert _build_cells(segs, 10, 10) == []
