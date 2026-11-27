"""Shared shift-resistant instruction measurements."""

from difflib import Match, SequenceMatcher
from types import SimpleNamespace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from rapidfuzz.distance import LCSseq

from rebrew.alignment import (
    AlignedMatcher,
    WindowHashes,
    earliest_window,
    earliest_window_scalar,
    measure_alignment,
    record_alignment,
)
from rebrew.compiler.compile import CompareResult
from rebrew.test import build_result_dict_from_compare


class TestAlignment:
    @pytest.mark.parametrize("candidate", [b"\x90\x50\x58\xc3", b"\x50\x58\xc3\x90"])
    def test_insertions_keep_pairs_and_penalize_extra_instructions(self, candidate: bytes) -> None:
        metrics = measure_alignment(SimpleNamespace(), b"\x50\x58\xc3", candidate, 0x401000)
        assert metrics == {
            "aligned_pairs": 3,
            "target_instructions": 3,
            "candidate_instructions": 4,
            "hunks": 1,
            "similarity": 6 / 7,
        }

    def test_full_object_tail_and_json_preserve_byte_verdict(self) -> None:
        cmp = CompareResult(
            False,
            "SIZE_MISMATCH",
            0.0,
            3,
            b"\x90\x50\x58",
            [],
            full_obj_bytes=b"\x90\x50\x58\xc3",
            full_obj_size=4,
        )
        evidence = {"input_hash": "unchanged"}
        record_alignment(SimpleNamespace(), cmp, b"\x50\x58\xc3", 0x401000, evidence)
        result = build_result_dict_from_compare("a.c", "_f", "0x401000", 3, cmp, b"\x50\x58\xc3")
        assert CompareResult.from_dict(cmp.to_dict()).alignment == cmp.alignment
        assert result["aligned_pairs"] == 3
        assert result["candidate_instructions"] == 4
        assert result["similarity"] == 6 / 7
        assert result["status"] == "SIZE_MISMATCH"
        assert evidence["similarity"] == pytest.approx(600 / 7)
        assert evidence["input_hash"] == "unchanged"

    def test_empty_and_undecodable_are_not_perfect(self) -> None:
        assert measure_alignment(SimpleNamespace(), b"", b"", 0)["similarity"] == 0
        assert measure_alignment(SimpleNamespace(), b"\x0f", b"\x0f", 0)["similarity"] == 0


# Few distinct tokens, so windows repeat and the earliest-match tie-breaks decide.
_TOKENS = st.lists(st.integers(min_value=1, max_value=4), max_size=64)


class TestArrayWindowSearch:
    @settings(max_examples=400, deadline=None)
    @given(_TOKENS, _TOKENS, st.data())
    def test_the_array_search_answers_what_the_scalar_scan_answers(
        self, left: list[int], right: list[int], data: st.DataObject
    ) -> None:
        alo = data.draw(st.integers(0, len(left)))
        ahi = data.draw(st.integers(alo, len(left)))
        blo = data.draw(st.integers(0, len(right)))
        bhi = data.draw(st.integers(blo, len(right)))
        width = data.draw(st.integers(0, max(ahi - alo, bhi - blo) + 1))
        assert earliest_window(
            left, right, WindowHashes(left), WindowHashes(right), (alo, ahi, blo, bhi), width
        ) == earliest_window_scalar(left, right, alo, ahi, blo, bhi, width)

    @settings(max_examples=300, deadline=None)
    @given(_TOKENS, _TOKENS)
    def test_the_blocks_are_optimal_lcs(self, left: list[int], right: list[int]) -> None:
        a, b = [str(t) for t in left], [str(t) for t in right]
        matcher = AlignedMatcher(a=a, b=b, autojunk=False)
        blocks = matcher.get_matching_blocks()
        assert blocks[-1] == Match(len(a), len(b), 0)
        prev_i = prev_j = -1
        for blk in blocks[:-1]:
            assert blk.size > 0
            assert blk.a >= prev_i and blk.b >= prev_j
            assert not (blk.a == prev_i and blk.b == prev_j)
            assert a[blk.a : blk.a + blk.size] == b[blk.b : blk.b + blk.size]
            prev_i = blk.a + blk.size
            prev_j = blk.b + blk.size
        matched = sum(blk.size for blk in blocks)
        assert matched == LCSseq.similarity(a, b)
        difflib_matched = sum(
            blk.size for blk in SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks()
        )
        assert matched >= difflib_matched
        reconstructed: list[str] = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                assert a[i1:i2] == b[j1:j2]
                reconstructed.extend(a[i1:i2])
            elif tag in ("replace", "insert"):
                reconstructed.extend(b[j1:j2])
        assert reconstructed == b
