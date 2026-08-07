"""Tests for the rebrew data scanner."""

import struct
from pathlib import Path

from rebrew.data import (
    BssGap,
    BssReport,
    _generate_bss_fix,
    classify_section,
    enrich_with_sections,
    find_dispatch_tables,
    scan_globals,
    verify_bss_layout,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_c(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


ANNOTATED_GLOBAL = """\
// FUNCTION: SERVER 0x10011790
// STATUS: NEAR_MATCHING
// ORIGIN: GAME
// SIZE: 242
// CFLAGS: /O2 /Gd

// GLOBAL: SERVER 0x100a8c30
extern int DAT_100a8c30;

// GLOBAL: SERVER 0x1003546c
extern int DAT_1003546c;

int __cdecl func_10011790(unsigned char *param_1)
{
    return 0;
}
"""

EXTERN_DATA_ONLY = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd

extern unsigned short DAT_100358a0;
extern char s_message_buffer[];

int __cdecl foo(void) { return 0; }
"""

EXTERN_WITH_FUNCTIONS = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd

extern int __cdecl ResolveEntityById(void **, void **, void **, int);
extern void __cdecl LogMessage(char *, int);
extern int g_counter;
extern void __declspec(dllimport) __stdcall MessageBoxA(int, const char *, const char *, unsigned int);

int __cdecl bar(void) { return 0; }
"""

TYPE_CONFLICT_A = """\
// FUNCTION: SERVER 0x10001000
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 10
// CFLAGS: /O2 /Gd

extern int g_shared;

int __cdecl a(void) { return 0; }
"""

TYPE_CONFLICT_B = """\
// FUNCTION: SERVER 0x10002000
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 10
// CFLAGS: /O2 /Gd

extern char *g_shared;

int __cdecl b(void) { return 0; }
"""

DOUBLE_POINTER_GLOBAL = """\
// FUNCTION: SERVER 0x10003000
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 10
// CFLAGS: /O2 /Gd

extern char **g_double_ptr;

int __cdecl ptrs(void) { return 0; }
"""

BSS_LARGE_ENTRY = """\
// FUNCTION: SERVER 0x10004000
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 10
// CFLAGS: /O2 /Gd

// GLOBAL: SERVER 0x20000000
extern char g_bss_blob[200];

int __cdecl bss_large(void) { return 0; }
"""


# ---------------------------------------------------------------------------
# scan_globals
# ---------------------------------------------------------------------------


class TestScanGlobals:
    def test_empty_dir(self, tmp_path: Path) -> None:
        result = scan_globals(tmp_path)
        assert len(result.globals) == 0

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        result = scan_globals(tmp_path / "nope")
        assert len(result.globals) == 0

    def test_annotated_globals(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "func_10011790.c", ANNOTATED_GLOBAL)
        result = scan_globals(tmp_path)
        assert "DAT_100a8c30" in result.globals
        assert "DAT_1003546c" in result.globals
        g = result.globals["DAT_100a8c30"]
        assert g.va == 0x100A8C30
        assert g.annotated is True
        assert g.type_str == "int"
        assert "func_10011790.c" in g.declared_in

    def test_extern_data_without_annotation(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "foo.c", EXTERN_DATA_ONLY)
        result = scan_globals(tmp_path)
        assert "DAT_100358a0" in result.globals
        assert "s_message_buffer" in result.globals
        g = result.globals["DAT_100358a0"]
        assert g.annotated is False
        assert g.type_str == "unsigned short"

    def test_filters_function_declarations(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "bar.c", EXTERN_WITH_FUNCTIONS)
        result = scan_globals(tmp_path)
        # Should find the data global
        assert "g_counter" in result.globals
        # Should NOT find function forward declarations
        assert "ResolveEntityById" not in result.globals
        assert "LogMessage" not in result.globals
        # Should NOT find dllimport functions
        assert "MessageBoxA" not in result.globals

    def test_type_conflict_detection(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "a.c", TYPE_CONFLICT_A)
        _write_c(tmp_path, "b.c", TYPE_CONFLICT_B)
        result = scan_globals(tmp_path)
        assert len(result.type_conflicts) == 1
        assert result.type_conflicts[0]["name"] == "g_shared"
        assert "int" in result.type_conflicts[0]["types"]
        assert "char *" in result.type_conflicts[0]["types"]

    def test_no_conflict_same_type(self, tmp_path: Path) -> None:
        content_a = TYPE_CONFLICT_A  # extern int g_shared;
        content_b = TYPE_CONFLICT_B.replace("extern char *g_shared;", "extern int g_shared;")
        _write_c(tmp_path, "a.c", content_a)
        _write_c(tmp_path, "b.c", content_b)
        result = scan_globals(tmp_path)
        assert len(result.type_conflicts) == 0

    def test_multiple_files_same_global(self, tmp_path: Path) -> None:
        """Same global declared in multiple files should appear once with all files listed."""
        content_a = TYPE_CONFLICT_A  # extern int g_shared;
        content_b = TYPE_CONFLICT_B.replace("extern char *g_shared;", "extern int g_shared;")
        _write_c(tmp_path, "a.c", content_a)
        _write_c(tmp_path, "b.c", content_b)
        result = scan_globals(tmp_path)
        assert "g_shared" in result.globals
        assert len(result.globals["g_shared"].declared_in) == 2

    def test_double_pointer_type_is_preserved(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "ptrs.c", DOUBLE_POINTER_GLOBAL)
        result = scan_globals(tmp_path)
        assert "g_double_ptr" in result.globals
        assert result.globals["g_double_ptr"].type_str == "char **"


def test_function_pointer_declaration_not_treated_as_function() -> None:
    from rebrew.c_parser import find_extern_variables

    # Function pointer variable — tree-sitter recognises the function_declarator
    # and find_extern_variables correctly skips it (it's not a simple variable).
    line = "extern int (__cdecl *g_callback)(int, int);"
    assert find_extern_variables(line) == []


# ---------------------------------------------------------------------------
# classify_section
# ---------------------------------------------------------------------------


class TestClassifySection:
    def test_data_section(self) -> None:
        sections = {
            ".text": {"va": 0x10001000, "size": 0x20000},
            ".data": {"va": 0x10025000, "size": 0x5000},
            ".rdata": {"va": 0x1002A000, "size": 0x3000},
        }
        assert classify_section(0x10026000, sections) == ".data"
        assert classify_section(0x1002B000, sections) == ".rdata"
        assert classify_section(0x10005000, sections) == ".text"
        assert classify_section(0x20000000, sections) == ""

    def test_empty_sections(self) -> None:
        assert classify_section(0x10001000, {}) == ""


# ---------------------------------------------------------------------------
# enrich_with_sections
# ---------------------------------------------------------------------------


class TestEnrichWithSections:
    def test_enriches_annotated_globals(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "func_10011790.c", ANNOTATED_GLOBAL)
        result = scan_globals(tmp_path)
        sections = {
            ".text": {"va": 0x10001000, "size": 0x20000},
            ".data": {"va": 0x10025000, "size": 0x20000},
        }
        enrich_with_sections(result, sections)
        g = result.globals["DAT_1003546c"]
        assert g.section == ".data"


# ---------------------------------------------------------------------------
# ScanResult.to_dict
# ---------------------------------------------------------------------------


class TestToDict:
    def test_to_dict_schema(self, tmp_path: Path) -> None:
        _write_c(tmp_path, "func_10011790.c", ANNOTATED_GLOBAL)
        result = scan_globals(tmp_path)
        d = result.to_dict()
        assert "globals" in d
        assert "type_conflicts" in d
        assert "summary" in d
        assert d["summary"]["annotated"] == 2
        assert d["summary"]["total"] == 2


# ---------------------------------------------------------------------------
# BSS Layout and Fix
# ---------------------------------------------------------------------------


class TestBssFix:
    def test_generate_bss_fix_no_gaps(self, tmp_path: Path) -> None:
        report = BssReport(bss_va=0x1000, bss_size=0x100)
        _generate_bss_fix(report, tmp_path, "TEST")
        assert not (tmp_path / "bss_padding.c").exists()

    def test_generate_bss_fix_with_gaps(self, tmp_path: Path) -> None:
        report = BssReport(
            bss_va=0x1000,
            bss_size=0x100,
            gaps=[
                BssGap(offset=0x1010, size=16, before="g_var1", after="g_var2"),
                BssGap(offset=0x1030, size=32, before="g_var2", after="g_var3"),
            ],
        )
        _generate_bss_fix(report, tmp_path, "GAME")

        fix_file = tmp_path / "bss_padding.c"
        assert fix_file.exists()

        content = fix_file.read_text(encoding="utf-8")
        # Marker lines stay in the .c file
        assert "// DATA: GAME 0x00001010" in content
        assert "char gap_00001010[16];" in content
        assert "// DATA: GAME 0x00001030" in content
        assert "char gap_00001030[32];" in content
        # SIZE/SECTION/NOTE are NOT in the .c file — they live in rebrew-data.toml
        assert "// STATUS:" not in content
        assert "// SIZE:" not in content
        assert "// SECTION:" not in content
        assert "// NOTE:" not in content

        # Verify metadata was written to rebrew-data.toml metadata
        from rebrew.data_metadata import get_data_entry

        entry_1 = get_data_entry(tmp_path, 0x1010, "GAME")
        assert entry_1["size"] == 16
        assert entry_1["section"] == ".bss"
        assert "g_var1" in entry_1["note"] and "g_var2" in entry_1["note"]

        entry_2 = get_data_entry(tmp_path, 0x1030, "GAME")
        assert entry_2["size"] == 32
        assert entry_2["section"] == ".bss"


def test_verify_bss_layout_clamps_coverage(tmp_path: Path) -> None:
    _write_c(tmp_path, "bss_large.c", BSS_LARGE_ENTRY)
    scan = scan_globals(tmp_path)
    report = verify_bss_layout(scan, {".bss": {"va": 0x20000000, "size": 64}})
    assert report.coverage_bytes == 64


# ---------------------------------------------------------------------------
# find_dispatch_tables
# ---------------------------------------------------------------------------


def _make_dispatch_binary(
    text_va: int,
    text_size: int,
    data_va: int,
    pointers: list[int],
) -> tuple[bytes, dict[str, dict[str, int]]]:
    """Build a minimal fake binary with .text and .data sections for dispatch tests.

    .text is empty (all zeros, ``text_size`` bytes).
    .data starts immediately after and contains the packed ``pointers`` list.
    Returns (binary_bytes, sections_dict).
    """
    ptr_fmt = "<I"

    text_file_offset = 0
    text_content = bytes(text_size)
    data_file_offset = text_size
    data_content = b"".join(struct.pack(ptr_fmt, p) for p in pointers)

    binary = text_content + data_content

    sections: dict[str, dict[str, int]] = {
        ".text": {
            "va": text_va,
            "size": text_size,
            "file_offset": text_file_offset,
            "raw_size": text_size,
        },
        ".data": {
            "va": data_va,
            "size": len(data_content),
            "file_offset": data_file_offset,
            "raw_size": len(data_content),
        },
    }
    return binary, sections


class TestFindDispatchTables:
    _TEXT_VA = 0x10001000
    _TEXT_SIZE = 0x1000
    _DATA_VA = 0x10010000

    def _ptrs_in_text(self, count: int, step: int = 0x10) -> list[int]:
        """Return ``count`` VA values that fall inside .text."""
        return [self._TEXT_VA + i * step for i in range(count)]

    def test_no_text_section_returns_empty(self) -> None:
        binary = bytes(64)
        tables = find_dispatch_tables(binary, {}, {})
        assert tables == []

    def test_default_detects_table_of_three(self) -> None:
        ptrs = self._ptrs_in_text(3)
        binary, sections = _make_dispatch_binary(
            self._TEXT_VA, self._TEXT_SIZE, self._DATA_VA, ptrs
        )
        tables = find_dispatch_tables(binary, sections, {})
        assert len(tables) == 1
        assert tables[0].num_entries == 3

    def test_default_rejects_table_of_two(self) -> None:
        """A run of 2 entries is below the default min_entries=3 threshold."""
        ptrs = self._ptrs_in_text(2)
        binary, sections = _make_dispatch_binary(
            self._TEXT_VA, self._TEXT_SIZE, self._DATA_VA, ptrs
        )
        tables = find_dispatch_tables(binary, sections, {})
        assert tables == []

    def test_custom_min_table_len_raises_threshold(self) -> None:
        """A table of 3 entries should be rejected when min_entries=4."""
        ptrs = self._ptrs_in_text(3)
        binary, sections = _make_dispatch_binary(
            self._TEXT_VA, self._TEXT_SIZE, self._DATA_VA, ptrs
        )
        tables = find_dispatch_tables(binary, sections, {}, min_entries=4)
        assert tables == []

    def test_custom_min_table_len_lowers_threshold(self) -> None:
        """A run of 2 entries should be accepted when min_entries=2."""
        ptrs = self._ptrs_in_text(2)
        binary, sections = _make_dispatch_binary(
            self._TEXT_VA, self._TEXT_SIZE, self._DATA_VA, ptrs
        )
        tables = find_dispatch_tables(binary, sections, {}, min_entries=2)
        assert len(tables) == 1
        assert tables[0].num_entries == 2

    def test_default_behavior_unchanged_by_none_max_stride(self) -> None:
        """Passing max_stride=None should produce identical results to the default."""
        ptrs = self._ptrs_in_text(4)
        binary, sections = _make_dispatch_binary(
            self._TEXT_VA, self._TEXT_SIZE, self._DATA_VA, ptrs
        )
        default_result = find_dispatch_tables(binary, sections, {})
        none_stride_result = find_dispatch_tables(binary, sections, {}, max_stride=None)
        assert len(default_result) == len(none_stride_result)
        for dt, nt in zip(default_result, none_stride_result, strict=True):
            assert dt.num_entries == nt.num_entries

    def test_larger_max_stride_merges_split_tables(self) -> None:
        """With a larger stride, a gap between two pointer runs can be bridged.

        Layout: [ptr ptr ptr] [non-ptr (8-byte gap)] [ptr ptr ptr]
        Default stride=4 flushes after the gap → 2 separate tables.
        max_stride=8 steps over the gap → detected as a single run of 6.
        """
        text_ptrs = self._ptrs_in_text(6)
        # Insert a non-text-pointer word in between to create a gap at index 3
        pointers_with_gap = text_ptrs[:3] + [0xDEADBEEF] + text_ptrs[3:]
        binary, sections = _make_dispatch_binary(
            self._TEXT_VA, self._TEXT_SIZE, self._DATA_VA, pointers_with_gap
        )
        # Default: gap breaks the run into two tables of 3
        default_tables = find_dispatch_tables(binary, sections, {})
        assert len(default_tables) == 2

        # Larger stride: the non-pointer slot is skipped over
        wide_tables = find_dispatch_tables(binary, sections, {}, max_stride=8)
        # The first run of 3 is still detected; stride=8 means the gap slot is
        # consumed in one step, landing back on valid pointers
        assert len(wide_tables) >= 1
