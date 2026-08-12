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

    def test_size_mismatch_delta_includes_truncated_length_diff(self) -> None:
        # The SIZE_MISMATCH caller truncates both sides before classifying and
        # passes the pre-truncation length difference — delta must include it
        # (10B vs 5B with 1 common-prefix diff → 6, not 1).
        r = classify_compare_result(
            False,
            "SIZE_MISMATCH",
            b"\x55\x89\xe5\x90\x90",  # truncated target (orig 10B)
            b"\x55\x89\xe5\x91\x90",  # truncated obj (orig 5B)
            None,
            size_mismatch=True,
            size_delta=5,
        )
        assert r.status == "SIZE_MISMATCH"
        assert r.delta == 6

    def test_size_mismatch_without_size_delta_unchanged(self) -> None:
        # Direct classify on untruncated bytes still counts the size diff via
        # abs(len diff) — size_delta defaults to 0.
        r = classify_compare_result(False, "SIZE_MISMATCH", b"\x55\x89\xe5", b"\x55", None)
        assert r.status == "SIZE_MISMATCH"
        assert r.delta == 2

    def test_full_obj_size_passthrough(self) -> None:
        """full_obj_size records the pre-truncation compiled size so
        rebrew test --fix-size can correct a stale SIZE annotation."""
        r = classify_compare_result(
            False,
            "SIZE_MISMATCH",
            b"\x55\x89\xe5",  # truncated target
            b"\x55\x89\xe5",  # truncated obj (orig 12B)
            None,
            size_mismatch=True,
            size_delta=9,
            full_obj_size=12,
        )
        assert r.status == "SIZE_MISMATCH"
        assert r.full_obj_size == 12

    def test_full_obj_size_none_by_default(self) -> None:
        r = classify_compare_result(True, "match", b"\x55", b"\x55", None)
        assert r.full_obj_size is None

    def test_matched_preserves_full_obj_size(self) -> None:
        # The --fix-size reclassification rebuilds a matched result from a
        # truncated SIZE_MISMATCH view; the full size must survive so JSON
        # reporting is not re-truncated.
        r = classify_compare_result(True, "match", b"\x55", b"\x55", None, full_obj_size=12)
        assert r.matched is True
        assert r.full_obj_size == 12

    def test_minimal_body_vs_large_target_is_stub(self) -> None:
        """A 3-byte `return 0` skeleton body against a 42-byte target must
        classify STUB (unimplemented skeleton), not a bare SIZE_MISMATCH —
        the caller truncates the longer side, so the original lengths arrive
        via full_obj_size / full_target_size."""
        r = classify_compare_result(
            False,
            "SIZE_MISMATCH: Size 3B vs 42B (0 byte diffs in common prefix)",
            b"\x33\xc0\xc3",  # target truncated to candidate length by caller
            b"\x33\xc0\xc3",
            None,
            size_mismatch=True,
            size_delta=39,
            full_obj_size=3,
            full_target_size=42,
        )
        assert r.status == "STUB"
        assert "stub body" in r.message
        assert "42B" in r.message

    def test_minimal_body_without_full_sizes_stays_size_mismatch(self) -> None:
        """Without the original lengths (other callers), the heuristic falls
        back to the truncated view — no false STUB."""
        r = classify_compare_result(
            False,
            "SIZE_MISMATCH",
            b"\x33\xc0\xc3",
            b"\x33\xc0\xc3",
            None,
            size_mismatch=True,
        )
        assert r.status == "SIZE_MISMATCH"

    def test_real_tiny_function_not_stub(self) -> None:
        """A genuinely tiny candidate (5B) against a small target (8B) is not
        a stub — target < _STUB_TARGET_MIN."""
        r = classify_compare_result(
            False,
            "SIZE_MISMATCH",
            b"\x33\xc0\xc3\x90\x90\x90\x90\x90",  # target truncated to 5
            b"\x33\xc0\xc3\x90\x90",
            None,
            size_mismatch=True,
            size_delta=3,
            full_obj_size=5,
            full_target_size=8,
        )
        assert r.status == "SIZE_MISMATCH"
