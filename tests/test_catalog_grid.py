"""Tests for catalog/grid.py — range merging and section/label lookup."""

from rebrew.catalog.grid import (
    _build_label_index,
    _build_section_index,
    _find_ghidra_data_label,
    _lookup_section,
    merge_ranges,
)
from rebrew.catalog.models import GhidraDataLabel


class TestMergeRanges:
    def test_empty(self) -> None:
        assert merge_ranges([]) == []

    def test_overlapping(self) -> None:
        assert merge_ranges([(0, 10), (5, 15)]) == [(0, 15)]

    def test_adjacent(self) -> None:
        assert merge_ranges([(0, 10), (10, 20)]) == [(0, 20)]

    def test_disjoint(self) -> None:
        assert merge_ranges([(0, 5), (10, 15)]) == [(0, 5), (10, 15)]

    def test_unsorted_input(self) -> None:
        assert merge_ranges([(10, 15), (0, 5)]) == [(0, 5), (10, 15)]


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
        result = _lookup_section(0x2100, starts, info)
        assert result is not None
        assert result[0] == ".data"

    def test_below_first(self) -> None:
        starts, info = _build_section_index(
            {".text": {"va": 0x1000, "size": 0x100, "fileOffset": 0}}
        )
        assert _lookup_section(0x500, starts, info) is None

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

    def test_before_first(self) -> None:
        idx = _build_label_index({0x5000: self._label(0x5000, 20)})
        assert _find_ghidra_data_label(0x1000, idx) is None
