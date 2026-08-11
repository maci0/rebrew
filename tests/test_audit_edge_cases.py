"""Edge-case tests added during the deep code audit.

Covers:
- smart_reloc_compare: empty inputs, single-byte, all-zero patterns
- parse_new_format_multi: orphaned KV warning
- annotation __all__: export completeness
"""

from pathlib import Path

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

    def test_dir32_iat_slot_masked_despite_wrong_catalog(self) -> None:
        """DIR32 whose target value lands in the IAT region is masked even
        when the catalog maps the symbol to a different VA (swapped ordinal
        import names — the guild-rebrew WS2_32 regression)."""
        import struct

        iat_slot = 0x10024178
        wrong_va = 0x1002417C  # catalog thinks the symbol lives here
        obj = b"\xff\x15" + struct.pack("<I", 0) + b"\xc3"  # call [0]
        tgt = b"\xff\x15" + struct.pack("<I", iat_slot) + b"\xc3"  # call [iat]
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj,
            tgt,
            coff_relocs={2: "__imp__WSAStartup@8"},
            name_to_va={"__imp__WSAStartup@8": wrong_va},
            iat_region={iat_slot},
        )
        assert matched is True
        assert valid == [2]
        assert invalid == []

    def test_dir32_iat_slot_still_rejected_outside_region(self) -> None:
        """The IAT masking must not leak: the same value without the region
        (or a different region) is still validated as a wrong symbol."""
        import struct

        g_a, g_b = 0x10020000, 0x10020010
        obj = b"\xa1" + struct.pack("<I", 0) + b"\xc3"
        tgt = b"\xa1" + struct.pack("<I", g_b) + b"\xc3"
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj,
            tgt,
            coff_relocs={1: "_g_a"},
            name_to_va={"g_a": g_a, "g_b": g_b},
            iat_region={0x99999999},  # g_b not in the IAT region
        )
        assert matched is False
        assert invalid == [1]

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

    def test_typed_dir32_record_iat_slot_masked(self) -> None:
        """The typed CoffRelocRecord branch (the preferred path) must also
        mask DIR32 values landing in the IAT region — same as the dict path."""
        import struct

        from rebrew.matcher.parsers import CoffRelocRecord

        iat_slot = 0x10024178
        obj = b"\xff\x15" + struct.pack("<I", 0) + b"\xc3"
        tgt = b"\xff\x15" + struct.pack("<I", iat_slot) + b"\xc3"
        rec = CoffRelocRecord(offset=2, type=0x0006, symbol="__imp__WSACleanup@0")
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj,
            tgt,
            coff_relocs=[rec],
            name_to_va={"__imp__WSACleanup@0": 0x1002417C},  # catalog swapped
            iat_region={iat_slot},
        )
        assert matched is True
        assert valid == [2]
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


class TestIatRegionBuild:
    """build_iat_region merges import-table slots AND configured jmp-stubs."""

    def test_configured_thunks_included(self, tmp_path: Path, monkeypatch) -> None:
        from types import SimpleNamespace

        from rebrew.core import build_iat_region

        cfg = SimpleNamespace(
            target_binary=tmp_path / "x.dll",
            iat_thunks=[0x1001A160, 0x1001A166, 0x10023840],
        )
        (tmp_path / "x.dll").write_bytes(b"MZ" + b"\x00" * 62)  # not a real PE
        region = build_iat_region(cfg)
        # configured stubs survive even though the PE parse fails/returns nothing
        assert 0x1001A160 in region
        assert 0x10023840 in region

    def test_empty_cfg_defaults(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.core import build_iat_region

        cfg = SimpleNamespace(target_binary=tmp_path / "nope.dll", iat_thunks=None)
        assert build_iat_region(cfg) == set()

    def test_real_pe_import_slots(self) -> None:
        """A real PE's import-address slots are included (LIEF path), not
        just the configured jmp-stubs."""
        from pathlib import Path
        from types import SimpleNamespace

        from rebrew.core import build_iat_region

        pe = Path(__file__).resolve().parent / "fixtures" / "mini_pe.exe"
        assert pe.exists()
        cfg = SimpleNamespace(target_binary=pe, iat_thunks=[])
        region = build_iat_region(cfg)
        # mini_pe.exe imports GetTickCount at IAT slot 0x104c (image base 0x400000)
        assert 0x40104C in region
        assert 0x104C not in region  # must be canonicalized to an absolute VA

    def test_dir32_jmp_stub_masked(self) -> None:
        """call [jmp_stub] vs recompiled call [__imp__] — masked by position."""
        import struct

        from rebrew.core import smart_reloc_compare

        stub = 0x1001A160
        obj = b"\xff\x15" + struct.pack("<I", 0) + b"\xc3"
        tgt = b"\xff\x15" + struct.pack("<I", stub) + b"\xc3"
        matched, _, _, valid, invalid = smart_reloc_compare(
            obj,
            tgt,
            coff_relocs={2: "__imp__CreateFileA@28"},
            name_to_va={"__imp__CreateFileA@28": 0x99999999},
            iat_region={stub},
        )
        assert matched is True
        assert valid == [2]
        assert invalid == []
