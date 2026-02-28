"""Tests for the rebrew data scanner."""

from pathlib import Path

from rebrew.data import (
    BssGap,
    BssReport,
    _generate_bss_fix,
    _is_function_decl,
    classify_section,
    enrich_with_sections,
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
// STATUS: MATCHING
// ORIGIN: GAME
// SIZE: 242
// CFLAGS: /O2 /Gd
// SYMBOL: _func_10011790

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
// SYMBOL: _foo

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
// SYMBOL: _bar

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
// SYMBOL: _a

extern int g_shared;

int __cdecl a(void) { return 0; }
"""

TYPE_CONFLICT_B = """\
// FUNCTION: SERVER 0x10002000
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 10
// CFLAGS: /O2 /Gd
// SYMBOL: _b

extern char *g_shared;

int __cdecl b(void) { return 0; }
"""

DOUBLE_POINTER_GLOBAL = """\
// FUNCTION: SERVER 0x10003000
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 10
// CFLAGS: /O2 /Gd
// SYMBOL: _ptrs

extern char **g_double_ptr;

int __cdecl ptrs(void) { return 0; }
"""

BSS_LARGE_ENTRY = """\
// FUNCTION: SERVER 0x10004000
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 10
// CFLAGS: /O2 /Gd
// SYMBOL: _bss_large

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
    line = "extern int (__cdecl *g_callback)(int, int);"
    assert _is_function_decl("int __cdecl", line) is False


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
        assert d["summary"]["total"] >= 2


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
        assert "// DATA: GAME 0x00001010" in content
        assert "// STATUS: EXACT" in content
        assert "// ORIGIN: GAME" in content
        assert "// SECTION: .bss" in content
        assert "char gap_00001010[16];" in content
        assert "// NOTE: gap between g_var1 and g_var2" in content

        assert "// DATA: GAME 0x00001030" in content
        assert "char gap_00001030[32];" in content


def test_verify_bss_layout_clamps_coverage(tmp_path: Path) -> None:
    _write_c(tmp_path, "bss_large.c", BSS_LARGE_ENTRY)
    scan = scan_globals(tmp_path)
    report = verify_bss_layout(scan, {".bss": {"va": 0x20000000, "size": 64}})
    assert report.coverage_bytes == 64
