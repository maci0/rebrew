"""Shared shift-resistant instruction measurements."""

from types import SimpleNamespace

import pytest

from rebrew.alignment import measure_alignment, record_alignment
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
