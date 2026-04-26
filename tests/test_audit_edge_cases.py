"""Edge-case tests added during the deep code audit.

Covers:
- smart_reloc_compare: empty inputs, single-byte, all-zero patterns
- parse_new_format_multi: orphaned KV warning
- annotation __all__: export completeness
"""

import pytest

from rebrew.annotation import __all__ as annotation_all
from rebrew.annotation import parse_new_format_multi
from rebrew.core import smart_reloc_compare

# ---------------------------------------------------------------------------
# smart_reloc_compare edge cases
# ---------------------------------------------------------------------------


class TestSmartRelocCompareEdgeCases:
    def test_both_empty(self) -> None:
        """Empty inputs are a vacuous match — zero length, zero mismatches."""
        matched, count, total, valid, invalid = smart_reloc_compare(b"", b"")
        assert matched is True
        assert count == 0
        assert total == 0
        assert valid == []
        assert invalid == []

    def test_single_byte_match(self) -> None:
        matched, count, total, valid, invalid = smart_reloc_compare(b"\x90", b"\x90")
        assert matched is True
        assert count == 1
        assert valid == []
        assert invalid == []

    def test_single_byte_mismatch(self) -> None:
        matched, count, total, valid, invalid = smart_reloc_compare(b"\x90", b"\x91")
        assert matched is False
        assert count == 0
        assert valid == []
        assert invalid == []

    def test_length_mismatch_shorter_obj(self) -> None:
        """When obj is shorter than target, non-matching bytes remain."""
        matched, count, total, valid, invalid = smart_reloc_compare(b"\x90", b"\x90\x91")
        assert matched is False  # length mismatch
        assert total == 2
        assert isinstance(valid, list)
        assert isinstance(invalid, list)

    def test_length_mismatch_longer_obj(self) -> None:
        """When obj is longer than target, non-matching bytes remain."""
        matched, count, total, valid, invalid = smart_reloc_compare(b"\x90\x91", b"\x90")
        assert matched is False
        assert total == 2
        assert isinstance(valid, list)
        assert isinstance(invalid, list)

    def test_reloc_masking_with_dict(self) -> None:
        """COFF relocation dict format: {offset: symbol_name}."""
        obj = b"\x90\x00\x00\x00\x00\x91"
        tgt = b"\x90\x01\x02\x03\x04\x91"
        matched, count, total, valid, invalid = smart_reloc_compare(
            obj, tgt, coff_relocs={1: "_some_func"}
        )
        assert matched is True
        assert len(valid) == 1
        assert valid[0] == 1

    def test_reloc_masking_with_list(self) -> None:
        """COFF relocation list format: [offset, ...]."""
        obj = b"\x90\x00\x00\x00\x00\x91"
        tgt = b"\x90\x01\x02\x03\x04\x91"
        matched, count, total, valid, invalid = smart_reloc_compare(obj, tgt, coff_relocs=[1])
        assert matched is True
        assert len(valid) == 1

    def test_zero_span_fallback(self) -> None:
        """Without COFF relocs, zero-span detection kicks in."""
        obj = b"\x90\x00\x00\x00\x00\x91"
        tgt = b"\x90\x01\x02\x03\x04\x91"
        matched, count, total, valid, invalid = smart_reloc_compare(obj, tgt)
        assert matched is True
        assert len(valid) == 1


# ---------------------------------------------------------------------------
# parse_new_format_multi: orphaned KV warning
# ---------------------------------------------------------------------------


class TestOrphanedKVWarning:
    def test_logs_on_orphaned_kv(self, caplog: pytest.LogCaptureFixture) -> None:
        """KV lines before any marker should emit a debug log."""
        lines = [
            "// STATUS: EXACT",
            "// SIZE: 100",
            "int main() { return 0; }",
        ]
        with caplog.at_level("DEBUG", logger="root"):
            result = parse_new_format_multi(lines)
        assert result == []
        orphan_msgs = [r for r in caplog.records if "orphaned" in r.message]
        assert len(orphan_msgs) == 1

    def test_no_log_for_kv_after_marker(self, caplog: pytest.LogCaptureFixture) -> None:
        """KV lines after a marker should NOT trigger orphan log."""
        lines = [
            "// FUNCTION: SERVER 0x10001000",
            "// STATUS: EXACT",
            "// SIZE: 100",
            "int func(void) { return 0; }",
        ]
        with caplog.at_level("DEBUG", logger="root"):
            result = parse_new_format_multi(lines)
        assert len(result) == 1
        orphan_msgs = [r for r in caplog.records if "orphaned" in r.message]
        assert len(orphan_msgs) == 0

    def test_no_log_for_clean_file(self, caplog: pytest.LogCaptureFixture) -> None:
        """File with no annotations at all should not log."""
        lines = [
            "int main() { return 0; }",
        ]
        with caplog.at_level("DEBUG", logger="root"):
            result = parse_new_format_multi(lines)
        assert result == []
        orphan_msgs = [r for r in caplog.records if "orphaned" in r.message]
        assert len(orphan_msgs) == 0


# ---------------------------------------------------------------------------
# annotation __all__ completeness
# ---------------------------------------------------------------------------


class TestAnnotationAllExports:
    def test_all_exports_are_importable(self) -> None:
        """Every name in __all__ must be importable from rebrew.annotation."""
        import rebrew.annotation as mod

        for name in annotation_all:
            assert hasattr(mod, name), f"{name} is in __all__ but does not exist"

    def test_all_contains_core_names(self) -> None:
        """Critical public names must appear in __all__."""
        required = {
            "Annotation",
            "parse_c_file_multi",
            "update_size_annotation",
        }
        missing = required - set(annotation_all)
        assert not missing, f"Missing from __all__: {missing}"
