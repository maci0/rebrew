"""Tests for rebrew.annotation — Annotation dataclass and parsers."""

from pathlib import Path

import pytest

from rebrew.annotation import (
    Annotation,
    make_func_entry,
    normalize_cflags,
    normalize_status,
    parse_c_file,
    parse_library_header,
    parse_new_format,
    parse_old_format,
)

# ---------------------------------------------------------------------------
# Annotation dataclass basics
# ---------------------------------------------------------------------------


class TestAnnotationDataclass:
    """Verify Annotation dataclass behavior."""

    def test_defaults(self) -> None:
        ann = Annotation()
        assert ann.va == 0
        assert ann.size == 0
        assert ann.name == ""
        assert ann.globals_list == []

    def test_field_access(self) -> None:
        ann = Annotation(va=0x10001000, size=42, name="foo", status="EXACT")
        assert ann.va == 0x10001000
        assert ann.size == 42
        assert ann.name == "foo"
        assert ann.status == "EXACT"

    def test_dict_getitem(self) -> None:
        ann = Annotation(va=0x10001000, status="RELOC")
        assert ann["va"] == 0x10001000
        assert ann["status"] == "RELOC"

    def test_dict_setitem(self) -> None:
        ann = Annotation()
        ann["status"] = "EXACT"
        assert ann.status == "EXACT"
        assert ann["status"] == "EXACT"

    def test_dict_globals_alias(self) -> None:
        """The 'globals' key should map to globals_list field."""
        ann = Annotation(globals_list=["a", "b"])
        assert ann["globals"] == ["a", "b"]
        ann["globals"] = ["c"]
        assert ann.globals_list == ["c"]

    def test_dict_contains(self) -> None:
        ann = Annotation()
        assert "va" in ann
        assert "status" in ann
        assert "globals" in ann
        assert "nonexistent_field" not in ann

    def test_dict_get_existing(self) -> None:
        ann = Annotation(status="EXACT")
        assert ann.get("status") == "EXACT"

    def test_dict_get_missing(self) -> None:
        ann = Annotation()
        assert ann.get("nonexistent", "default") == "default"

    def test_dict_getitem_invalid_key(self) -> None:
        ann = Annotation()
        with pytest.raises(KeyError):
            _ = ann["nonexistent_key"]

    def test_dict_setitem_invalid_key(self) -> None:
        ann = Annotation()
        with pytest.raises(KeyError):
            ann["nonexistent_key"] = "value"

    def test_to_dict(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            name="foo",
            symbol="_foo",
            status="EXACT",
            module="SERVER",
            cflags="/O2",
            marker_type="FUNCTION",
            filepath="foo.c",
            source="",
            blocker="",
            note="",
            globals_list=["g1"],
        )
        d = ann.to_dict()
        assert d["va"] == 0x10001000
        assert d["name"] == "foo"
        assert d["globals"] == ["g1"]
        assert isinstance(d, dict)

    def test_make_func_entry_returns_annotation(self) -> None:
        ann = make_func_entry(
            va=0x10001000,
            size=42,
            name="foo",
            symbol="_foo",
            status="EXACT",
            module="SERVER",
            cflags="/O2",
            marker_type="FUNCTION",
            filepath="foo.c",
        )
        assert isinstance(ann, Annotation)
        assert ann.va == 0x10001000
        assert ann["va"] == 0x10001000


# ---------------------------------------------------------------------------
# Annotation.validate()
# ---------------------------------------------------------------------------


class TestAnnotationValidation:
    """Verify Annotation.validate() catches issues."""

    def test_valid_annotation_no_errors(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            name="foo",
            symbol="_foo",
            status="EXACT",
            cflags="/O2",
            marker_type="FUNCTION",
        )
        errors, warnings = ann.validate()
        assert errors == []

    def test_invalid_status(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            status="BOGUS",
            marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("STATUS" in e for e in errors)

    def test_invalid_module(self) -> None:
        """Annotation.validate() does not validate module values (open field)."""
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            status="EXACT",
            module="BOGUS",
            marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        # module is a free-form field, no ORIGIN error expected
        assert not any("ORIGIN" in e for e in errors)

    def test_invalid_size(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=0,
            cflags="/O2",
            status="EXACT",
            marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("SIZE" in e for e in errors)

    def test_missing_cflags_no_error(self) -> None:
        """CFLAGS is optional — missing cflags should not produce a validation error."""
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="",
            status="EXACT",
            marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert not any("CFLAGS" in e for e in errors)

    def test_no_symbol_warning_when_derived(self) -> None:
        """SYMBOL is now derived from C definition — no warning needed."""
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="",
            status="EXACT",
            marker_type="FUNCTION",
        )
        _, warnings = ann.validate()
        assert not any("SYMBOL" in w for w in warnings)

    def test_stub_without_blocker_warning(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="_foo",
            status="STUB",
            marker_type="STUB",
        )
        _, warnings = ann.validate()
        assert any("BLOCKER" in w for w in warnings)

    def test_msvcrt_without_source_warning(self) -> None:
        """Library module missing SOURCE should warn when that module is in library_modules."""
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="_foo",
            status="EXACT",
            module="MSVCRT",
            marker_type="LIBRARY",
        )
        _, warnings = ann.validate(library_modules={"MSVCRT"})
        assert any("SOURCE" in w for w in warnings)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestNormalizeHelpers:
    def test_normalize_status_exact(self) -> None:
        assert normalize_status("EXACT MATCH") == "EXACT"
        assert normalize_status("exact") == "EXACT"

    def test_normalize_status_reloc(self) -> None:
        assert normalize_status("RELOC MATCH") == "RELOC"

    def test_normalize_status_matching(self) -> None:
        assert normalize_status("MATCHING") == "MATCHING"

    def test_normalize_status_matching_reloc(self) -> None:
        # Regression: must NOT mangle RELOC → RELOC (substring order bug)
        assert normalize_status("RELOC") == "RELOC"

    def test_normalize_status_stub(self) -> None:
        assert normalize_status("STUB") == "STUB"

    def test_normalize_cflags(self) -> None:
        assert normalize_cflags("  /O2 /Gd , ") == "/O2 /Gd"


class TestParseOldFormat:
    def test_parse_valid(self) -> None:
        line = "/* bit_reverse @ 0x10008880 (31B) - /O2 /Gd - EXACT MATCH [GAME] */"
        result = parse_old_format(line)
        assert result is not None
        assert result["va"] == 0x10008880
        assert result["size"] == 31
        assert result["status"] == "EXACT"
        assert result["name"] == "bit_reverse"

    def test_parse_invalid_returns_none(self) -> None:
        assert parse_old_format("int main() {}") is None
        assert parse_old_format("") is None


class TestParseNewFormat:
    def test_parse_valid(self) -> None:
        lines = [
            "// FUNCTION: SERVER 0x10008880",
            "// STATUS: EXACT",
            "// SIZE: 31",
            "// CFLAGS: /O2 /Gd",
            "",
            "int bit_reverse(int x) { return x; }",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result["va"] == 0x10008880
        assert result["status"] == "EXACT"
        assert result["size"] == 31
        assert result["name"] == "bit_reverse"
        assert result["symbol"] == "_bit_reverse"

    def test_parse_no_marker_returns_none(self) -> None:
        lines = [
            "// STATUS: EXACT",
        ]
        assert parse_new_format(lines) is None

    def test_parse_with_globals(self) -> None:
        lines = [
            "// FUNCTION: SERVER 0x10001000",
            "// STATUS: EXACT",
            "// SIZE: 100",
            "// CFLAGS: /O2",
            "// GLOBALS: g_counter, g_flag",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result["va"] == 0x10001000
        assert result["status"] == "EXACT"
        assert result["size"] == 100
        assert result["cflags"] == "/O2"
        assert result["globals"] == ["g_counter", "g_flag"]


class TestParseCFile:
    def test_parse_new_format_file(self, tmp_path) -> None:
        content = """\
// FUNCTION: SERVER 0x10001234
// STATUS: EXACT
// SIZE: 42
// CFLAGS: /O2

int myfunc(void) { return 0; }
"""
        f = tmp_path / "myfunc.c"
        f.write_text(content, encoding="utf-8")
        result = parse_c_file(f)
        assert result is not None
        assert result["va"] == 0x10001234
        assert result["status"] == "EXACT"
        assert result["size"] == 42
        assert result["cflags"] == "/O2"
        assert result["symbol"] == "_myfunc"
        assert result["filepath"] == "myfunc.c"

    def test_parse_old_format_file(self, tmp_path) -> None:
        content = "/* myfunc @ 0x10001234 (42B) - /O2 - EXACT MATCH [GAME] */\nint myfunc(void) { return 0; }\n"
        f = tmp_path / "myfunc.c"
        f.write_text(content, encoding="utf-8")
        result = parse_c_file(f)
        assert result is not None
        assert result["va"] == 0x10001234
        assert result["size"] == 42
        assert result["status"] == "EXACT"
        assert result["name"] == "myfunc"

    def test_parse_nonexistent_file(self, tmp_path) -> None:
        f = tmp_path / "does_not_exist.c"
        assert parse_c_file(f) is None

    def test_parse_empty_file(self, tmp_path) -> None:
        f = tmp_path / "empty.c"
        f.write_text("", encoding="utf-8")
        assert parse_c_file(f) is None


# ---------------------------------------------------------------------------
# Multi-function parsing tests
# ---------------------------------------------------------------------------


class TestMultiFunctionParsing:
    """Verify parse_new_format_multi and parse_c_file_multi."""

    def test_parse_two_functions(self) -> None:
        from rebrew.annotation import parse_new_format_multi

        lines = [
            "// FUNCTION: SERVER 0x10001000",
            "// STATUS: EXACT",
            "// SIZE: 42",
            "// CFLAGS: /O2",
            "// SYMBOL: _func_a",
            "",
            "int func_a(void) { return 0; }",
            "",
            "// FUNCTION: SERVER 0x10002000",
            "// STATUS: MATCHING",
            "// SIZE: 100",
            "// CFLAGS: /O1",
            "// SYMBOL: _func_b",
            "",
            "int func_b(void) { return 1; }",
        ]
        results = parse_new_format_multi(lines)
        assert len(results) == 2
        assert results[0].va == 0x10001000
        assert results[0].symbol == "_func_a"
        assert results[0].status == "EXACT"
        assert results[1].va == 0x10002000
        assert results[1].symbol == "_func_b"
        assert results[1].status == "MATCHING"
        assert results[1].module == "SERVER"

    def test_parse_three_with_code_between(self) -> None:
        from rebrew.annotation import parse_new_format_multi

        lines = [
            "// FUNCTION: SERVER 0x10001000",
            "// STATUS: EXACT",
            "// SIZE: 10",
            "// CFLAGS: /O2",
            "// SYMBOL: _a",
            "void a(void) {}",
            "",
            "// FUNCTION: SERVER 0x10002000",
            "// STATUS: RELOC",
            "// SIZE: 20",
            "// CFLAGS: /O2",
            "// SYMBOL: _b",
            "void b(void) {}",
            "",
            "// FUNCTION: SERVER 0x10003000",
            "// STATUS: STUB",
            "// SIZE: 30",
            "// CFLAGS: /O1",
            "// SYMBOL: _c",
            "void c(void) {}",
        ]
        results = parse_new_format_multi(lines)
        assert len(results) == 3
        assert [r.va for r in results] == [0x10001000, 0x10002000, 0x10003000]
        assert [r.symbol for r in results] == ["_a", "_b", "_c"]
        assert [r.size for r in results] == [10, 20, 30]

    def test_single_function_returns_one(self) -> None:
        from rebrew.annotation import parse_new_format_multi

        lines = [
            "// FUNCTION: SERVER 0x10001000",
            "// STATUS: EXACT",
            "// SIZE: 42",
            "// CFLAGS: /O2",
            "// SYMBOL: _single",
            "int single(void) { return 0; }",
        ]
        results = parse_new_format_multi(lines)
        assert len(results) == 1
        assert results[0].va == 0x10001000

    def test_parse_c_file_multi_returns_all(self, tmp_path) -> None:
        from rebrew.annotation import parse_c_file_multi

        content = """\
// FUNCTION: SERVER 0x10001000
// STATUS: EXACT
// SIZE: 42
// CFLAGS: /O2

int func_a(void) { return 0; }

// FUNCTION: SERVER 0x10002000
// STATUS: MATCHING
// SIZE: 100
// CFLAGS: /O2

int func_b(void) { return 1; }
"""
        f = tmp_path / "multi.c"
        f.write_text(content, encoding="utf-8")
        results = parse_c_file_multi(f)
        assert len(results) == 2
        assert results[0].va == 0x10001000
        assert results[0].filepath == "multi.c"
        assert results[1].va == 0x10002000
        assert results[1].filepath == "multi.c"

    def test_parse_c_file_still_returns_first(self, tmp_path) -> None:
        """parse_c_file returns the first annotation; SIZE comes from sidecar via parse_c_file_multi."""
        content = """\
// FUNCTION: SERVER 0x10001000
// STATUS: EXACT
// CFLAGS: /O2

int func_a(void) { return 0; }

// FUNCTION: SERVER 0x10002000
// STATUS: MATCHING
// CFLAGS: /O2

int func_b(void) { return 1; }
"""
        f = tmp_path / "multi.c"
        f.write_text(content, encoding="utf-8")
        # SIZE lives in sidecar
        sidecar = tmp_path / "rebrew-function.toml"
        sidecar.write_text(
            '["SERVER.0x10001000"]\nsize = 42\n',
            encoding="utf-8",
        )
        # parse_c_file (no sidecar arg) returns first annotation; size=0 since sidecar not loaded
        result = parse_c_file(f)
        assert result is not None
        assert result.va == 0x10001000
        assert result.status == "EXACT"
        assert result.symbol == "_func_a"
        # parse_c_file_multi with sidecar_dir picks up SIZE from sidecar
        from rebrew.annotation import parse_c_file_multi

        results = parse_c_file_multi(f, sidecar_dir=f.parent)
        assert results[0].size == 42

    def test_shared_symbol_uses_func_name_hint(self) -> None:
        """Functions with shared SYMBOL should use the name hint comment instead.

        Regression test for the loadsave.c bug where all FUNCTION blocks had
        ``// SYMBOL: _ReadVfsDataChecked`` but were actually different functions.
        """
        from rebrew.annotation import parse_new_format_multi

        lines = [
            "// STATUS: MATCHING",
            "// SIZE: 728",
            "// SYMBOL: _ReadVfsDataChecked",
            "// FUNCTION: SERVER 0x10012000",
            "// LoadGraveyardData",
            "// PROTOTYPE: int __cdecl LoadGraveyardData(int, int)",
            "",
            "int __cdecl LoadGraveyardData(int a, int b) { return 0; }",
            "",
            "// STATUS: MATCHING",
            "// SIZE: 346",
            "// SYMBOL: _ReadVfsDataChecked",
            "// FUNCTION: SERVER 0x100122e0",
            "// InitNewDynastyEntity",
            "",
            "void InitNewDynastyEntity(int a, int b) {}",
            "",
            "// STATUS: RELOC",
            "// SIZE: 37",
            "// SYMBOL: _ReadVfsDataChecked",
            "// FUNCTION: SERVER 0x10012440",
            "// ReadVfsDataChecked",
            "",
            "int ReadVfsDataChecked(void* a, int b, int c, int d) { return 1; }",
        ]
        results = parse_new_format_multi(lines)
        assert len(results) == 3

        # First block: name hint overrides shared SYMBOL
        assert results[0].name == "LoadGraveyardData"
        assert results[0].symbol == "_LoadGraveyardData"
        assert results[0].va == 0x10012000
        assert results[0].size == 728

        # Second block: different name hint, different derived symbol
        assert results[1].name == "InitNewDynastyEntity"
        assert results[1].symbol == "_InitNewDynastyEntity"
        assert results[1].va == 0x100122E0
        assert results[1].size == 346

        # Third block: name hint matches SYMBOL, so SYMBOL is used directly
        assert results[2].name == "ReadVfsDataChecked"
        assert results[2].symbol == "_ReadVfsDataChecked"
        assert results[2].va == 0x10012440
        assert results[2].size == 37

    def test_func_name_hint_single_format(self) -> None:
        """Function name hint should also work in parse_new_format."""
        lines = [
            "// STATUS: EXACT",
            "// SIZE: 100",
            "// FUNCTION: SERVER 0x10001000",
            "// MyFunction",
            "",
            "int MyFunction(void) { return 0; }",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result.name == "MyFunction"
        assert result.symbol == "_MyFunction"

    def test_skip_forward_declaration_single(self) -> None:
        """Forward declarations (ending with ';') should be skipped in parse_new_format."""
        lines = [
            "// FUNCTION: SERVER 0x1000A8F0",
            "// QueueCommandForProcessing",
            "void* memcpy(void*, const void*, unsigned int);",
            "",
            "int __cdecl QueueCommandForProcessing(int player_slot, char* cmd_data)",
            "{",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result.name == "QueueCommandForProcessing"
        assert result.symbol == "_QueueCommandForProcessing"

    def test_skip_forward_declaration_multi(self) -> None:
        """Forward declarations should be skipped in parse_new_format_multi."""
        from rebrew.annotation import parse_new_format_multi

        lines = [
            "// STATUS: MATCHING",
            "// SIZE: 130",
            "// FUNCTION: SERVER 0x1000BD50",
            "// reset_entity_state",
            "void* memset(void*, int, unsigned int);",
            "",
            "void __cdecl reset_entity_state(char* param_1)",
            "{",
            "}",
            "",
            "// STATUS: MATCHING",
            "// SIZE: 109",
            "// FUNCTION: SERVER 0x1000C600",
            "// InitRandomEntity",
            "int __cdecl RandomBelow(unsigned short max);",
            "",
            "char* __cdecl InitRandomEntity(void)",
            "{",
            "}",
        ]
        results = parse_new_format_multi(lines)
        assert len(results) == 2
        assert results[0].name == "reset_entity_state"
        assert results[0].symbol == "_reset_entity_state"
        assert results[1].name == "InitRandomEntity"
        assert results[1].symbol == "_InitRandomEntity"

    def test_declspec_not_matched_as_name(self) -> None:
        """__declspec(noreturn) should not be matched as a function name."""
        lines = [
            "// FUNCTION: SERVER 0x10003520",
            "// ReportFatalError",
            "__declspec(noreturn) void __cdecl _exit(int);",
            "",
            "void __cdecl ReportFatalError(char* modulePath, unsigned int lineNumber, char* message)",
            "{",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result.name == "ReportFatalError"
        assert result.symbol == "_ReportFatalError"

    def test_stdcall_decorated_symbol(self) -> None:
        """__stdcall functions should get decorated symbol names (_func@N)."""
        lines = [
            "// FUNCTION: SERVER 0x10009310",
            "// STATUS: MATCHING",
            "// SIZE: 8",
            "",
            "int __stdcall exit_handler(int a, int b, int c)",
            "{",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result.name == "exit_handler"
        assert result.symbol == "_exit_handler@12"

    def test_winapi_decorated_symbol(self) -> None:
        """WINAPI functions should get decorated symbol names (_func@N)."""
        lines = [
            "// FUNCTION: SERVER 0x10002770",
            "// STATUS: MATCHING",
            "// SIZE: 1836",
            "",
            "int WINAPI CrashDumpUnhandledExceptionFilter(EXCEPTION_POINTERS* pExceptionPointers)",
            "{",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result.name == "CrashDumpUnhandledExceptionFilter"
        assert result.symbol == "_CrashDumpUnhandledExceptionFilter@4"

    def test_stdcall_void_params(self) -> None:
        """__stdcall with void params should produce @0 suffix."""
        lines = [
            "// FUNCTION: SERVER 0x10001000",
            "// STATUS: EXACT",
            "// SIZE: 10",
            "",
            "void __stdcall NoArgsFunc(void)",
            "{",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result.symbol == "_NoArgsFunc@0"

    def test_empty_file_returns_empty_list(self, tmp_path) -> None:
        from rebrew.annotation import parse_c_file_multi

        f = tmp_path / "empty.c"
        f.write_text("", encoding="utf-8")
        assert parse_c_file_multi(f) == []


# ---------------------------------------------------------------------------
# Shared helper tests
# ---------------------------------------------------------------------------


class TestHasSkipAnnotation:
    """Tests for has_skip_annotation()."""

    def test_skip_present(self, tmp_path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "skipped.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// SKIP: not matchable\nint x() {}\n", encoding="utf-8"
        )
        assert has_skip_annotation(f) is True

    def test_skip_block_comment(self, tmp_path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "skipped.c"
        f.write_text("/* SKIP: reason */\nint x() {}\n", encoding="utf-8")
        assert has_skip_annotation(f) is True

    def test_no_skip(self, tmp_path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "normal.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\nint x() {}\n", encoding="utf-8"
        )
        assert has_skip_annotation(f) is False

    def test_nonexistent_file(self, tmp_path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "does_not_exist.c"
        assert has_skip_annotation(f) is False

    def test_skip_beyond_line_20_ignored(self, tmp_path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "late_skip.c"
        lines = ["// line\n"] * 25 + ["// SKIP: too late\n"]
        f.write_text("".join(lines), encoding="utf-8")
        assert has_skip_annotation(f) is False


class TestResolveSymbol:
    """Tests for resolve_symbol()."""

    def test_symbol_present(self, tmp_path) -> None:
        from rebrew.annotation import Annotation, resolve_symbol

        ann = Annotation(symbol="_my_func")
        assert resolve_symbol(ann, tmp_path / "my_func.c") == "_my_func"

    def test_question_mark_fallback(self, tmp_path) -> None:
        from rebrew.annotation import Annotation, resolve_symbol

        ann = Annotation(symbol="?")
        assert resolve_symbol(ann, tmp_path / "my_func.c") == "_my_func"

    def test_empty_symbol_fallback(self, tmp_path) -> None:
        from rebrew.annotation import Annotation, resolve_symbol

        ann = Annotation(symbol="")
        assert resolve_symbol(ann, tmp_path / "game_pool_free.c") == "_game_pool_free"


# ---------------------------------------------------------------------------
# parse_library_header
# ---------------------------------------------------------------------------


class TestParseLibraryHeader:
    """Verify parse_library_header() for library_*.h files."""

    def test_parse_msvc_header(self, tmp_path) -> None:
        hfile = tmp_path / "library_msvc.h"
        hfile.write_text(
            "#ifdef 0\n"
            "// LIBRARY: SERVER 0x1001A18A\n"
            "// _fflush\n"
            "\n"
            "// LIBRARY: SERVER 0x1001A1BB\n"
            "// __fclose_lk\n"
            "#endif\n"
        )
        results = parse_library_header(hfile)
        assert len(results) == 2

        assert results[0].va == 0x1001A18A
        assert results[0].symbol == "_fflush"
        assert results[0].module == "SERVER"
        assert results[0].marker_type == "LIBRARY"
        assert results[0].status == "EXACT"

        assert results[1].va == 0x1001A1BB
        assert results[1].symbol == "__fclose_lk"
        assert results[1].module == "SERVER"

    def test_parse_zlib_header(self, tmp_path) -> None:
        hfile = tmp_path / "library_zlib.h"
        hfile.write_text("// LIBRARY: SERVER 0x10050000\n// _deflate\n")
        results = parse_library_header(hfile)
        assert len(results) == 1
        assert results[0].va == 0x10050000
        assert results[0].symbol == "_deflate"

    def test_target_filter(self, tmp_path) -> None:
        hfile = tmp_path / "library_msvc.h"
        hfile.write_text(
            "// LIBRARY: SERVER 0x1001A18A\n"
            "// _fflush\n"
            "// LIBRARY: OTHER 0x1001A1BB\n"
            "// __fclose_lk\n"
        )
        results = parse_library_header(hfile, target_name="SERVER")
        assert len(results) == 1
        assert results[0].va == 0x1001A18A

    def test_empty_file(self, tmp_path) -> None:
        hfile = tmp_path / "library_msvc.h"
        hfile.write_text("")
        results = parse_library_header(hfile)
        assert results == []

    def test_unknown_library_module(self, tmp_path) -> None:
        hfile = tmp_path / "library_openssl.h"
        hfile.write_text("// LIBRARY: SERVER 0x10060000\n// _SSL_init\n")
        results = parse_library_header(hfile)
        assert len(results) == 1
        assert results[0].module == "SERVER"

    def test_extended_kv_annotations(self, tmp_path) -> None:
        """KV lines after symbol are captured (rebrew extension, invisible to reccmp)."""
        hfile = tmp_path / "library_zlib.h"
        hfile.write_text(
            "// LIBRARY: SERVER 0x10050000\n"
            "// _deflate\n"
            "// STATUS: MATCHING\n"
            "// SIZE: 120\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SOURCE: deflate.c\n"
            "// BLOCKER: 2B diff\n"
            "\n"
            "// LIBRARY: SERVER 0x10050100\n"
            "// _inflate\n"
        )
        results = parse_library_header(hfile)
        assert len(results) == 2

        # Extended entry
        assert results[0].va == 0x10050000
        assert results[0].symbol == "_deflate"
        assert results[0].status == "MATCHING"
        assert results[0].size == 120
        assert results[0].cflags == "/O2 /Gd"
        assert results[0].source == "deflate.c"
        assert results[0].blocker == "2B diff"

        # Minimal entry — defaults still work
        assert results[1].va == 0x10050100
        assert results[1].symbol == "_inflate"
        assert results[1].status == "EXACT"
        assert results[1].size == 0
        assert results[1].cflags == ""

    def test_kv_module_preserved(self, tmp_path) -> None:
        """Module (target name) in LIBRARY marker is stored in annotation.module."""
        hfile = tmp_path / "library_msvc.h"
        hfile.write_text("// LIBRARY: MYTARGET 0x10060000\n// _custom_alloc\n")
        results = parse_library_header(hfile)
        assert len(results) == 1
        assert results[0].module == "MYTARGET"


# ---------------------------------------------------------------------------
# Audit-specific regression tests (Phase 3 hardening)
# ---------------------------------------------------------------------------


class TestAuditAnnotation:
    """Tests added during the formal Phase 1/2/3 code audit to cover
    branches that were not previously exercised."""

    # normalize_status: PROVEN branch (audit finding — was falling through to raw return)
    def test_normalize_status_proven(self) -> None:
        """'PROVEN' must map to the canonical status string, not pass through verbatim."""
        assert normalize_status("PROVEN") == "PROVEN"
        # Old-format variants containing the word should also normalise
        assert normalize_status("proven_match") == "PROVEN"
        assert normalize_status("PROVEN_OK") == "PROVEN"

    # update_size_annotation: target_va parameter (previously untested branch)
    def test_update_size_annotation_target_va_match(self, tmp_path: Path) -> None:
        """When target_va is provided, size is written to sidecar (not .c file)."""
        from rebrew.annotation import update_size_annotation
        from rebrew.sidecar import get_entry

        content = (
            "// FUNCTION: SERVER 0x10001000\n"
            "// SIZE: 10\n"
            "int func_a(void) {}\n\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// SIZE: 20\n"
            "int func_b(void) {}\n"
        )
        f = tmp_path / "dual.c"
        f.write_text(content, encoding="utf-8")

        # Update SIZE for 0x10002000 — goes to sidecar, NOT the .c file
        changed = update_size_annotation(f, 99, target_va=0x10002000)
        assert changed is True

        # .c file must be untouched
        original = f.read_text(encoding="utf-8")
        assert "// SIZE: 20" in original  # func_b still has old value in file

        # Sidecar must have new value for func_b only
        entry_b = get_entry(tmp_path, 0x10002000, module="SERVER")
        assert entry_b["size"] == 99
        # func_a not in sidecar (was not touched)
        entry_a = get_entry(tmp_path, 0x10001000, module="SERVER")
        assert "size" not in entry_a

    def test_update_size_annotation_target_va_no_match(self, tmp_path: Path) -> None:
        """update_size_annotation returns False when new_size <= existing sidecar size."""
        from rebrew.annotation import update_size_annotation
        from rebrew.sidecar import save_sidecar

        f = tmp_path / "single.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// SIZE: 10\nint f(void) {}\n", encoding="utf-8"
        )
        # Pre-populate sidecar with size=200 so new_size=99 is rejected (not an increase)
        save_sidecar(tmp_path, {("SERVER", 0x10001000): {"size": 200}})
        changed = update_size_annotation(f, 99, target_va=0x10001000)
        assert changed is False

    def test_update_size_annotation_no_shrink(self, tmp_path) -> None:
        """update_size_annotation never reduces size (safety invariant).

        The sidecar must be pre-populated with the existing size; the .c file's
        // SIZE: annotation is no longer read by update_size_annotation.
        """
        from rebrew.annotation import update_size_annotation
        from rebrew.sidecar import save_sidecar

        f = tmp_path / "big.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// SIZE: 100\nint f(void) {}\n", encoding="utf-8"
        )
        # Pre-populate sidecar with existing size — update_size_annotation now reads sidecar
        save_sidecar(tmp_path, {("SERVER", 0x10001000): {"size": 100}})
        changed = update_size_annotation(f, 50)  # 50 < 100 — must not shrink
        assert changed is False

    # _calc_stdcall_param_size: template param regression
    def test_stdcall_template_param_counted_correctly(self) -> None:
        """std::pair<int,int> is ONE parameter — must not be double-counted."""
        from rebrew.annotation import _calc_stdcall_param_size  # type: ignore[attr-defined]

        # pair<int,int> stripped to "pair", one 4-byte slot
        size = _calc_stdcall_param_size("void __stdcall foo(std::pair<int,int> p)")
        assert size == 4

    def test_stdcall_nested_template(self) -> None:
        """Nested templates should still count as single params each."""
        from rebrew.annotation import _calc_stdcall_param_size  # type: ignore[attr-defined]

        # Two params: pair<int,int> and int
        size = _calc_stdcall_param_size("void __stdcall bar(std::pair<int,int> a, int b)")
        assert size == 8

    # to_dict completeness: inline_error must be serialised
    def test_to_dict_contains_inline_error(self) -> None:
        """to_dict() must include inline_error for faithful round-tripping."""
        ann = Annotation(inline_error="// FUNCTION: SERVER 0x1000 // EXTRA")
        d = ann.to_dict()
        assert "inline_error" in d
        assert d["inline_error"] == "// FUNCTION: SERVER 0x1000 // EXTRA"

    def test_to_dict_inline_error_empty_by_default(self) -> None:
        """to_dict() inline_error is empty string when not set."""
        ann = Annotation()
        assert ann.to_dict()["inline_error"] == ""

    # --- P1-01 regression: update_annotation_key must not bleed into next block ---

    def test_update_annotation_key_no_bleed_into_next_block(self, tmp_path: Path) -> None:
        """STATUS is a sidecar key — update_annotation_key writes to rebrew-function.toml.

        The .c file must remain completely untouched. VA2 is never affected.
        """
        from rebrew.annotation import update_annotation_key
        from rebrew.sidecar import get_entry

        content = (
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: RELOC\n"
            "// SIZE: 42\n"
            "int func_a(void) {}\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: MATCHING\n"
            "// SIZE: 100\n"
            "int func_b(void) {}\n"
        )
        f = tmp_path / "dual.c"
        f.write_text(content, encoding="utf-8")

        changed = update_annotation_key(f, 0x10001000, "STATUS", "EXACT")
        assert changed is True

        # .c file must be completely untouched
        assert f.read_text(encoding="utf-8") == content

        # VA1 sidecar entry has new status
        entry1 = get_entry(tmp_path, 0x10001000, module="SERVER")
        assert entry1["status"] == "EXACT"
        # VA2 was not touched
        entry2 = get_entry(tmp_path, 0x10002000, module="SERVER")
        assert "status" not in entry2

    # --- P1-02 regression: remove_annotation_key must not bleed into next block ---

    def test_remove_annotation_key_no_bleed_into_next_block(self, tmp_path: Path) -> None:
        """BLOCKER is a sidecar key — remove_annotation_key deletes from rebrew-function.toml.

        The .c file must remain untouched. VA2's sidecar entry is not affected.
        """
        from rebrew.annotation import remove_annotation_key
        from rebrew.sidecar import get_entry, save_sidecar

        content = (
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// BLOCKER: needs investigation\n"
            "void func_a(void) {}\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: STUB\n"
            "// BLOCKER: different blocker\n"
            "void func_b(void) {}\n"
        )
        f = tmp_path / "dual_blockers.c"
        f.write_text(content, encoding="utf-8")

        # Pre-populate sidecar for both VAs
        save_sidecar(
            tmp_path,
            {
                ("SERVER", 0x10001000): {"blocker": "needs investigation"},
                ("SERVER", 0x10002000): {"blocker": "different blocker"},
            },
        )

        changed = remove_annotation_key(f, 0x10001000, "BLOCKER")
        assert changed is True

        # VA1's blocker must be gone from sidecar
        entry1 = get_entry(tmp_path, 0x10001000, module="SERVER")
        assert "blocker" not in entry1

        # VA2's blocker must survive
        entry2 = get_entry(tmp_path, 0x10002000, module="SERVER")
        assert entry2.get("blocker") == "different blocker"

        # .c file untouched
        assert f.read_text(encoding="utf-8") == content

    # --- P1-09 regression: nested templates in stdcall param sizing ---

    def test_stdcall_deeply_nested_template(self) -> None:
        """Bug P1-09: single-pass re.sub(<[^<>]*>) left stray '>' with templates
        nested more than one level deep (e.g. std::map<int, std::pair<A,B>>).

        Iterative stripping must handle arbitrary depth.
        """
        from rebrew.annotation import _calc_stdcall_param_size  # type: ignore[attr-defined]

        # std::map<int, std::pair<A,B>> is ONE parameter (a map).
        # Before fix: two-pass needed, single-pass left stray '>' giving TWO counted params.
        size = _calc_stdcall_param_size(
            "void __stdcall handler(std::map<int, std::pair<int,int>> m)"
        )
        # One pointer-sized parameter (map is passed by reference/pointer)
        assert size == 4, f"Expected 4 bytes for one param, got {size}"

        # Also: two parameters, one of which is a nested template
        size2 = _calc_stdcall_param_size(
            "void __stdcall handler(std::map<int, std::pair<int,int>> m, int n)"
        )
        assert size2 == 8, f"Expected 8 bytes for two params, got {size2}"
