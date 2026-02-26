"""Tests for Ideas #14 (BSS layout verification) and #15 (DATA annotation marker)."""

import json

from rebrew.annotation import (
    VALID_MARKERS,
    Annotation,
    parse_new_format,
)
from rebrew.data import (
    BssEntry,
    BssGap,
    BssReport,
    GlobalEntry,
    ScanResult,
    _estimate_type_size,
    verify_bss_layout,
)

# ---------------------------------------------------------------------------
# Idea #15: DATA annotation marker
# ---------------------------------------------------------------------------


class TestDataAnnotationMarker:
    """Test that // DATA: marker is recognized by the annotation system."""

    def test_data_in_valid_markers(self) -> None:
        """DATA should be in the valid markers set."""
        assert "DATA" in VALID_MARKERS

    def test_parse_data_annotation(self) -> None:
        """Parse a // DATA: annotation from source lines."""
        lines = [
            "// DATA: SERVER 0x10025000",
            "// SIZE: 256",
            "// SECTION: .rdata",
            "// ORIGIN: GAME",
            "// NOTE: lookup table for sprite indices",
            "// SYMBOL: _g_sprite_lut",
        ]
        ann = parse_new_format(lines)
        assert ann is not None
        assert ann.marker_type == "DATA"
        assert ann.va == 0x10025000
        assert ann.size == 256
        assert ann.section == ".rdata"
        assert ann.origin == "GAME"
        assert ann.note == "lookup table for sprite indices"
        assert ann.symbol == "_g_sprite_lut"

    def test_parse_data_annotation_minimal(self) -> None:
        """Parse a minimal DATA annotation."""
        lines = [
            "// DATA: SERVER 0x10031000",
            "// SIZE: 4",
            "// SECTION: .bss",
        ]
        ann = parse_new_format(lines)
        assert ann is not None
        assert ann.marker_type == "DATA"
        assert ann.va == 0x10031000
        assert ann.section == ".bss"

    def test_data_annotation_to_dict(self) -> None:
        """DATA annotation should include section in dict output."""
        ann = Annotation(
            va=0x10025000,
            size=256,
            name="g_sprite_lut",
            marker_type="DATA",
            section=".rdata",
            origin="GAME",
        )
        d = ann.to_dict()
        assert d["section"] == ".rdata"
        assert d["marker_type"] == "DATA"

    def test_function_annotation_no_section(self) -> None:
        """FUNCTION annotations without section should NOT have section in dict."""
        ann = Annotation(
            va=0x10001000,
            size=100,
            name="func_a",
            marker_type="FUNCTION",
            origin="GAME",
        )
        d = ann.to_dict()
        assert "section" not in d

    def test_data_block_comment_format(self) -> None:
        """Parse // DATA: in block comment format."""
        lines = [
            "/* DATA: SERVER 0x10025000 */",
            "/* SIZE: 64 */",
            "/* SECTION: .data */",
        ]
        ann = parse_new_format(lines)
        assert ann is not None
        assert ann.marker_type == "DATA"
        assert ann.section == ".data"


# ---------------------------------------------------------------------------
# Idea #14: BSS layout verification
# ---------------------------------------------------------------------------


class TestEstimateTypeSize:
    """Test the C type size estimation helper."""

    def test_int(self) -> None:
        assert _estimate_type_size("int") == 4

    def test_char(self) -> None:
        assert _estimate_type_size("char") == 1

    def test_unsigned_short(self) -> None:
        assert _estimate_type_size("unsigned short") == 2

    def test_double(self) -> None:
        assert _estimate_type_size("double") == 8

    def test_pointer(self) -> None:
        assert _estimate_type_size("int *") == 4

    def test_dword(self) -> None:
        assert _estimate_type_size("DWORD") == 4

    def test_array(self) -> None:
        assert _estimate_type_size("char[256]") == 256

    def test_int_array(self) -> None:
        assert _estimate_type_size("int[10]") == 40


class TestBssVerification:
    """Test BSS layout verification logic."""

    def test_no_bss_section(self) -> None:
        """Should return empty report when no .bss found."""
        scan = ScanResult()
        report = verify_bss_layout(scan, {})
        assert report.bss_size == 0
        assert len(report.known_entries) == 0
        assert len(report.gaps) == 0

    def test_bss_with_no_globals(self) -> None:
        """BSS exists but no globals map to it."""
        scan = ScanResult()
        sections = {".bss": {"va": 0x10030000, "size": 0x1000}}
        report = verify_bss_layout(scan, sections)
        assert report.bss_size == 0x1000
        assert len(report.known_entries) == 0

    def test_bss_with_contiguous_globals(self) -> None:
        """Globals that fill BSS contiguously should have no gaps."""
        scan = ScanResult(
            globals={
                "g_a": GlobalEntry(
                    name="g_a", va=0x10030000, type_str="int", declared_in=["a.c"], annotated=True
                ),
                "g_b": GlobalEntry(
                    name="g_b", va=0x10030004, type_str="int", declared_in=["b.c"], annotated=True
                ),
                "g_c": GlobalEntry(
                    name="g_c", va=0x10030008, type_str="int", declared_in=["c.c"], annotated=True
                ),
            }
        )
        sections = {".bss": {"va": 0x10030000, "size": 12}}
        report = verify_bss_layout(scan, sections)
        assert len(report.known_entries) == 3
        assert len(report.gaps) == 0
        assert report.coverage_bytes == 12  # 3 ints

    def test_bss_with_gap(self) -> None:
        """Should detect gap between non-contiguous globals."""
        scan = ScanResult(
            globals={
                "g_a": GlobalEntry(
                    name="g_a", va=0x10030000, type_str="int", declared_in=["a.c"], annotated=True
                ),
                "g_b": GlobalEntry(
                    name="g_b", va=0x10030010, type_str="int", declared_in=["b.c"], annotated=True
                ),
            }
        )
        sections = {".bss": {"va": 0x10030000, "size": 0x20}}
        report = verify_bss_layout(scan, sections)
        assert len(report.known_entries) == 2
        assert len(report.gaps) == 1
        gap = report.gaps[0]
        assert gap.size == 12  # 0x10030004 to 0x10030010 = 12 bytes
        assert gap.before == "g_a"
        assert gap.after == "g_b"

    def test_bss_gap_at_start(self) -> None:
        """Should detect gap at the beginning of BSS."""
        scan = ScanResult(
            globals={
                "g_a": GlobalEntry(
                    name="g_a", va=0x10030010, type_str="int", declared_in=["a.c"], annotated=True
                ),
            }
        )
        sections = {".bss": {"va": 0x10030000, "size": 0x20}}
        report = verify_bss_layout(scan, sections)
        assert len(report.gaps) == 1
        gap = report.gaps[0]
        assert gap.offset == 0x10030000
        assert gap.size == 16
        assert gap.before == "<bss_start>"

    def test_bss_report_to_dict(self) -> None:
        """Test BssReport serialization."""
        report = BssReport(
            bss_va=0x10030000,
            bss_size=0x100,
            known_entries=[
                BssEntry(name="g_a", va=0x10030000, size_hint=4, source_file="a.c"),
            ],
            gaps=[
                BssGap(offset=0x10030004, size=8, before="g_a", after="g_b"),
            ],
            coverage_bytes=4,
        )
        d = report.to_dict()
        assert d["bss_va"] == "0x10030000"
        assert d["bss_size"] == 0x100
        assert len(d["known_entries"]) == 1
        assert len(d["gaps"]) == 1
        assert d["summary"]["total_globals"] == 1
        assert d["summary"]["gaps"] == 1

    def test_bss_report_json_serializable(self) -> None:
        """Test that BssReport can be serialized to JSON."""
        report = BssReport(
            bss_va=0x10030000,
            bss_size=256,
            known_entries=[BssEntry(name="g_x", va=0x10030000, size_hint=4)],
            coverage_bytes=4,
        )
        serialized = json.dumps(report.to_dict(), indent=2)
        loaded = json.loads(serialized)
        assert loaded["bss_va"] == "0x10030000"

    def test_globals_outside_bss_ignored(self) -> None:
        """Globals with VAs outside .bss range should be excluded."""
        scan = ScanResult(
            globals={
                "g_bss": GlobalEntry(
                    name="g_bss", va=0x10030000, type_str="int", declared_in=["a.c"], annotated=True
                ),
                "g_data": GlobalEntry(
                    name="g_data",
                    va=0x10020000,
                    type_str="int",
                    declared_in=["b.c"],
                    annotated=True,
                ),
            }
        )
        sections = {
            ".bss": {"va": 0x10030000, "size": 0x100},
            ".data": {"va": 0x10020000, "size": 0x100},
        }
        report = verify_bss_layout(scan, sections)
        assert len(report.known_entries) == 1
        assert report.known_entries[0].name == "g_bss"
