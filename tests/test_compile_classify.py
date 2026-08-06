"""Tests for classify_compare_result / SIZE_MISMATCH status."""

from rebrew.compile import classify_compare_result


class TestClassifyCompareResult:
    def test_size_mismatch_status(self) -> None:
        result = classify_compare_result(
            False,
            "SIZE_MISMATCH: Size 10B vs 8B (0 byte diffs in common prefix)",
            b"\x90" * 8,
            b"\x90" * 8,
            [],
            size_mismatch=True,
        )
        assert result.status == "SIZE_MISMATCH"
        assert result.matched is False
        assert result.match_percent == 100.0

    def test_exact_match(self) -> None:
        result = classify_compare_result(True, "EXACT MATCH", b"\x90", b"\x90", [])
        assert result.status == "EXACT"
        assert result.matched is True

    def test_reloc_match(self) -> None:
        result = classify_compare_result(True, "RELOC", b"\x90" * 8, b"\x90" * 8, [1])
        assert result.status == "RELOC"
