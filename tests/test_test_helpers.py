"""Tests for test.py result-dict builders and reloc helpers."""

from rebrew.compile import CompareResult
from rebrew.test import (
    _expand_reloc_offsets,
    _select_annotation_for_va,
    build_result_dict_from_compare,
)


class TestExpandRelocOffsets:
    def test_expands_4byte_windows(self) -> None:
        assert _expand_reloc_offsets([0, 8], limit=20) == {0, 1, 2, 3, 8, 9, 10, 11}

    def test_clamps_to_limit(self) -> None:
        assert _expand_reloc_offsets([6], limit=8) == {6, 7}

    def test_empty(self) -> None:
        assert _expand_reloc_offsets([], limit=10) == set()


class TestSelectAnnotationForVa:
    """--va on a (possibly multi-function) file must select the annotation AT
    that VA — was lint_annos[0], silently testing the wrong function."""

    @staticmethod
    def _annos() -> list[object]:
        from types import SimpleNamespace as NS

        return [
            NS(va=0x1000, symbol="_f1", size=12, module="S"),
            NS(va=0x2000, symbol="_f2", size=16, module="S"),
        ]

    def test_selects_matching_annotation(self) -> None:
        ann = _select_annotation_for_va(self._annos(), "0x2000", False)
        assert ann is not None
        assert ann.va == 0x2000
        assert ann.symbol == "_f2"

    def test_first_annotation_not_chosen_for_second_va(self) -> None:
        # The regression: requesting the SECOND function's VA used to return
        # the FIRST annotation (its symbol tested against the wrong address).
        ann = _select_annotation_for_va(self._annos(), "0x2000", False)
        assert ann.symbol != "_f1"

    def test_returns_none_when_no_annotation_matches(self) -> None:
        assert _select_annotation_for_va(self._annos(), "0x9999", False) is None

    def test_empty_annotation_list(self) -> None:
        assert _select_annotation_for_va([], "0x1000", False) is None


class TestBuildResultDictFromCompare:
    def test_matched_exact(self) -> None:
        cmp = CompareResult(
            matched=True,
            status="EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x55",
            reloc_offsets=[],
            message="match",
        )
        d = build_result_dict_from_compare("f.c", "_f", "0x1000", 1, cmp, b"\x55")
        assert d["status"] == "EXACT"
        assert d["match_count"] == 1
        assert d["total"] == 1
        assert d["mismatches"] == []

    def test_reloc_status(self) -> None:
        cmp = CompareResult(
            matched=True,
            status="RELOC",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x55\x89",
            reloc_offsets=[0],
            message="reloc",
        )
        d = build_result_dict_from_compare("f.c", "_f", "0x1000", 2, cmp, b"\x55\x89")
        assert d["status"] == "RELOC"
        assert d["match_count"] == 2
        assert d["reloc_count"] == 1

    def test_partial_near_matching(self) -> None:
        cmp = CompareResult(
            matched=False,
            status="NEAR_MATCHING",
            match_percent=80.0,
            delta=1,
            obj_bytes=b"\x55\x89",
            reloc_offsets=[],
            message="diff",
        )
        d = build_result_dict_from_compare("f.c", "_f", "0x1000", 2, cmp, b"\x55\x90")
        assert d["status"] == "NEAR_MATCHING"
        assert d["match_count"] == 2  # round(0.8 * 2)
        assert len(d["mismatches"]) == 1  # offset 1 differs

    def test_error_status(self) -> None:
        cmp = CompareResult(
            matched=False,
            status="COMPILE_ERROR",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message="syntax",
        )
        d = build_result_dict_from_compare("f.c", "_f", "", 0, cmp, b"")
        assert d["status"] == "COMPILE_ERROR"
        assert d["obj_size"] == 0
        assert d["mismatches"] == []
