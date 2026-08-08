"""Tests for compile.py classify_compare_result — the central classification."""

from rebrew.compile import classify_compare_result


class TestClassifyCompareResult:
    def test_matched_no_relocs_exact(self) -> None:
        r = classify_compare_result(True, "match", b"\x55", b"\x55", None)
        assert r.status == "EXACT"
        assert r.matched is True
        assert r.match_percent == 100.0

    def test_matched_with_relocs_reloc(self) -> None:
        r = classify_compare_result(True, "match", b"\x55", b"\x55", [4])
        assert r.status == "RELOC"
        assert r.reloc_offsets == [4]

    def test_compile_error_in_message(self) -> None:
        r = classify_compare_result(False, "COMPILE_ERROR: syntax", None, None, None)
        assert r.status == "COMPILE_ERROR"
        assert r.obj_bytes is None
        assert r.match_percent == 0.0

    def test_no_obj_bytes_compile_error(self) -> None:
        r = classify_compare_result(False, "something", b"\x55", None, None)
        assert r.status == "COMPILE_ERROR"

    def test_missing_size(self) -> None:
        r = classify_compare_result(False, "MISSING SIZE metadata", b"\x55", b"\x55", None)
        assert r.status == "MISSING_SIZE"

    def test_missing_file(self) -> None:
        r = classify_compare_result(False, "MISSING FILE: x.c", b"\x55", b"\x55", None)
        assert r.status == "MISSING_FILE"

    def test_size_mismatch_flag(self) -> None:
        r = classify_compare_result(
            False, "bytes differ", b"\x55\x89", b"\x55", None, size_mismatch=True
        )
        assert r.status == "SIZE_MISMATCH"
        assert r.match_percent > 0.0  # still reports over the common prefix

    def test_size_mismatch_in_message(self) -> None:
        r = classify_compare_result(False, "SIZE_MISMATCH", b"\x55", b"\x55", None)
        assert r.status == "SIZE_MISMATCH"

    def test_near_matching(self) -> None:
        # 4 of 5 bytes match (one mismatch) → 80% → NEAR_MATCHING.
        r = classify_compare_result(
            False, "diff", b"\x55\x89\xe5\x90\x90", b"\x55\x89\xe5\x91\x90", None
        )
        assert r.status == "NEAR_MATCHING"
        assert r.delta == 1

    def test_stub_below_threshold(self) -> None:
        # 1 of 5 bytes match → 20% → STUB.
        r = classify_compare_result(
            False, "diff", b"\x55\x89\xe5\x90\x90", b"\xaa\xbb\xcc\xdd\xee", None
        )
        assert r.status == "STUB"
        assert r.delta == 5

    def test_reloc_slots_masked_in_percent(self) -> None:
        # 2 mismatches, one at a reloc slot (offset 1) → masked → 1 real mismatch.
        r = classify_compare_result(
            False, "diff", b"\x55\xaa\xcc\xdd\xee", b"\x55\xbb\xcc\xdd\xee", [1]
        )
        assert r.status == "NEAR_MATCHING"  # 100% after masking the only mismatch
        assert r.delta == 0

    def test_short_obj_penalized(self) -> None:
        r = classify_compare_result(False, "diff", b"\x55\x89\xe5", b"\x55", None)
        assert r.match_percent < 60.0
        assert r.status == "STUB"
        # delta = abs(size diff) + mismatches — the 2 missing target bytes are
        # already counted by abs(3-1); adding `missing` again double-counted
        # short objects (regression fixed).
        assert r.delta == 2
