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

    def test_dir32_addend_matches_symbol_plus_offset(self) -> None:
        """DIR32 with non-zero addend: actual must equal symbol_va + addend."""
        import struct

        g_var = 0x10020000
        addend = 4
        obj = b"\xa1" + struct.pack("<I", addend) + b"\xc3"
        tgt = b"\xa1" + struct.pack("<I", (g_var + addend) & 0xFFFFFFFF) + b"\xc3"
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj, tgt, coff_relocs={1: "_g_var"}, name_to_va={"g_var": g_var}
        )
        assert matched is True
        assert valid == [1]
        assert invalid == []

    def test_dir32_wrong_symbol_is_invalid(self) -> None:
        """DIR32 pointing at a different catalog VA is rejected."""
        import struct

        g_a, g_b = 0x10020000, 0x10020010
        obj = b"\xa1" + struct.pack("<I", 0) + b"\xc3"
        # PE has g_b's absolute address; obj reloc claims g_a.
        tgt = b"\xa1" + struct.pack("<I", g_b) + b"\xc3"
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj,
            tgt,
            coff_relocs={1: "_g_a"},
            name_to_va={"g_a": g_a, "g_b": g_b},
        )
        assert matched is False
        assert invalid == [1]
        assert valid == []

    def test_rel32_not_rejected_as_wrong_absolute(self) -> None:
        """REL32 displacements must not be compared as absolute VAs."""
        import struct

        callee = 0x10001000
        # Typical near-call displacement (small signed value as uint32).
        disp = 0xFFFFFFFC
        obj = b"\xe8" + struct.pack("<I", 0) + b"\xc3"
        tgt = b"\xe8" + struct.pack("<I", disp) + b"\xc3"
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj, tgt, coff_relocs={1: "_callee"}, name_to_va={"callee": callee}
        )
        assert matched is True
        assert valid == [1]
        assert invalid == []

    def test_typed_dir32_record(self) -> None:
        """CoffRelocRecord DIR32 validates symbol_va + addend."""
        import struct

        from rebrew.matcher.parsers import CoffRelocRecord

        g_var = 0x10020000
        addend = 4
        obj = b"\xa1" + struct.pack("<I", addend) + b"\xc3"
        tgt = b"\xa1" + struct.pack("<I", (g_var + addend) & 0xFFFFFFFF) + b"\xc3"
        rec = CoffRelocRecord(offset=1, type=0x0006, symbol="_g_var")
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj, tgt, coff_relocs=[rec], name_to_va={"g_var": g_var}
        )
        assert matched is True
        assert valid == [1]
        assert invalid == []

    def test_typed_rel32_with_section_va(self) -> None:
        """CoffRelocRecord REL32 validates against PC-relative expected value."""
        import struct

        from rebrew.matcher.parsers import CoffRelocRecord

        section_va = 0x10001000
        callee = 0x10002000
        offset = 1
        addend = 0
        pc = section_va + offset + 4
        expected = (callee + addend - pc) & 0xFFFFFFFF
        obj = b"\xe8" + struct.pack("<I", addend) + b"\xc3"
        tgt = b"\xe8" + struct.pack("<I", expected) + b"\xc3"
        rec = CoffRelocRecord(offset=offset, type=0x0014, symbol="_callee")
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj,
            tgt,
            coff_relocs=[rec],
            name_to_va={"callee": callee},
            section_va=section_va,
        )
        assert matched is True
        assert valid == [1]
        assert invalid == []

    def test_typed_rel32_wrong_target_invalid(self) -> None:
        import struct

        from rebrew.matcher.parsers import CoffRelocRecord

        section_va = 0x10001000
        callee = 0x10002000
        wrong = 0x10003000
        offset = 1
        pc = section_va + offset + 4
        pe_disp = (wrong - pc) & 0xFFFFFFFF
        obj = b"\xe8" + struct.pack("<I", 0) + b"\xc3"
        tgt = b"\xe8" + struct.pack("<I", pe_disp) + b"\xc3"
        rec = CoffRelocRecord(offset=offset, type=0x0014, symbol="_callee")
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj,
            tgt,
            coff_relocs=[rec],
            name_to_va={"callee": callee},
            section_va=section_va,
        )
        assert matched is False
        assert invalid == [1]
        assert valid == []


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
