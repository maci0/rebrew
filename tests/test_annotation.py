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
    split_annotation_sections,
    update_annotation_key,
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
        assert d["size"] == 42
        assert d["name"] == "foo"
        assert d["symbol"] == "_foo"
        assert d["status"] == "EXACT"
        assert d["module"] == "SERVER"
        assert d["cflags"] == "/O2"
        assert d["marker_type"] == "FUNCTION"
        assert d["filepath"] == "foo.c"
        assert d["globals"] == ["g1"]
        assert d["source"] == ""
        assert d["blocker"] == ""
        assert d["note"] == ""

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
        assert warnings == [], f"Expected no warnings, got: {warnings}"

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
        assert normalize_status("NEAR_MATCHING") == "NEAR_MATCHING"

    def test_normalize_status_matching_reloc(self) -> None:
        # Regression: must NOT mangle RELOC → RELOC (substring order bug)
        assert normalize_status("RELOC") == "RELOC"

    def test_normalize_status_stub(self) -> None:
        assert normalize_status("STUB") == "STUB"

    def test_normalize_cflags(self) -> None:
        assert normalize_cflags("  /O2 /Gd , ") == "/O2 /Gd"


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
    def test_parse_new_format_file(self, tmp_path: Path) -> None:
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

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        f = tmp_path / "does_not_exist.c"
        assert parse_c_file(f) is None

    def test_parse_empty_file(self, tmp_path: Path) -> None:
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
            "// STATUS: NEAR_MATCHING",
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
        assert results[1].status == "NEAR_MATCHING"
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

    def test_parse_c_file_multi_returns_all(self, tmp_path: Path) -> None:
        from rebrew.annotation import parse_c_file_multi

        content = """\
// FUNCTION: SERVER 0x10001000
// STATUS: EXACT
// SIZE: 42
// CFLAGS: /O2

int func_a(void) { return 0; }

// FUNCTION: SERVER 0x10002000
// STATUS: NEAR_MATCHING
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

    def test_parse_c_file_still_returns_first(self, tmp_path: Path) -> None:
        """parse_c_file returns the first annotation; SIZE comes from metadata via parse_c_file_multi."""
        content = """\
// FUNCTION: SERVER 0x10001000
// STATUS: EXACT
// CFLAGS: /O2

int func_a(void) { return 0; }

// FUNCTION: SERVER 0x10002000
// STATUS: NEAR_MATCHING
// CFLAGS: /O2

int func_b(void) { return 1; }
"""
        f = tmp_path / "multi.c"
        f.write_text(content, encoding="utf-8")
        # SIZE lives in metadata
        metadata_toml = tmp_path / "rebrew-function.toml"
        metadata_toml.write_text(
            '["SERVER.0x10001000"]\nsize = 42\n',
            encoding="utf-8",
        )
        # parse_c_file (no metadata arg) returns first annotation; size=0 since metadata not loaded
        result = parse_c_file(f)
        assert result is not None
        assert result.va == 0x10001000
        assert result.status == "EXACT"
        assert result.symbol == "_func_a"
        # parse_c_file_multi with metadata_dir picks up SIZE from metadata
        from rebrew.annotation import parse_c_file_multi

        results = parse_c_file_multi(f, metadata_dir=f.parent)
        assert results[0].size == 42

    def test_shared_symbol_uses_func_name_hint(self) -> None:
        """Functions with shared SYMBOL should use the name hint comment instead.

        Regression test for the loadsave.c bug where all FUNCTION blocks had
        ``// SYMBOL: _ReadVfsDataChecked`` but were actually different functions.
        """
        from rebrew.annotation import parse_new_format_multi

        lines = [
            "// STATUS: NEAR_MATCHING",
            "// SIZE: 728",
            "// SYMBOL: _ReadVfsDataChecked",
            "// FUNCTION: SERVER 0x10012000",
            "// LoadGraveyardData",
            "// PROTOTYPE: int __cdecl LoadGraveyardData(int, int)",
            "",
            "int __cdecl LoadGraveyardData(int a, int b) { return 0; }",
            "",
            "// STATUS: NEAR_MATCHING",
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
            "// STATUS: NEAR_MATCHING",
            "// SIZE: 130",
            "// FUNCTION: SERVER 0x1000BD50",
            "// reset_entity_state",
            "void* memset(void*, int, unsigned int);",
            "",
            "void __cdecl reset_entity_state(char* param_1)",
            "{",
            "}",
            "",
            "// STATUS: NEAR_MATCHING",
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
            "// STATUS: NEAR_MATCHING",
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
            "// STATUS: NEAR_MATCHING",
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

    def test_empty_file_returns_empty_list(self, tmp_path: Path) -> None:
        from rebrew.annotation import parse_c_file_multi

        f = tmp_path / "empty.c"
        f.write_text("", encoding="utf-8")
        assert parse_c_file_multi(f) == []

    def test_data_block_does_not_inherit_function_name(self, tmp_path: Path) -> None:
        """A DATA block followed by extern decls and then a function definition
        must NOT inherit the function's name via _C_FUNC_NAME extraction.

        Regression: guild-rebrew Error.c — the DATA entry at 0x10027084
        (g_log_format_table) got named 'DispatchLogOutput' from the following
        function definition, corrupting symbol→VA resolution and making
        REL32 validation fail (call DispatchLogOutput → NEAR_MATCHING instead
        of RELOC)."""
        from rebrew.annotation import parse_c_file_multi

        f = tmp_path / "mixed.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10002640\n"
            "// DispatchLogOutput\n"
            "\n"
            "// DATA: SERVER 0x10027084\n"
            "extern char g_log_format_table[];\n"
            "\n"
            "void __cdecl DispatchLogOutput(const char* msg, unsigned char flags, int level)\n"
            "{\n"
            "\treturn;\n"
            "}\n",
            encoding="utf-8",
        )
        anns = parse_c_file_multi(f)
        by_va = {a.va: a for a in anns}
        assert 0x10002640 in by_va
        assert by_va[0x10002640].name == "DispatchLogOutput"
        assert by_va[0x10002640].marker_type == "FUNCTION"
        # The DATA entry must keep its own identity, not the function's name.
        assert 0x10027084 in by_va
        data_ann = by_va[0x10027084]
        assert data_ann.marker_type == "DATA"
        assert data_ann.name == ""
        assert data_ann.symbol == ""

    def test_stub_block_extracts_stdcall_symbol(self, tmp_path: Path) -> None:
        """A STUB block with a __stdcall implementation must still derive the
        decorated symbol (_Name@N) — STUB is a FUNCTION marker and needs
        C-definition name extraction (regression: gate excluded STUB, so
        verify demoted implemented stubs to EXTRACT_ERROR because the
        undecorated symbol was never found in the .obj)."""
        from rebrew.annotation import parse_c_file_multi

        f = tmp_path / "stub.c"
        f.write_text(
            "// STUB: SERVER 0x10002770\n"
            "// CrashDumpUnhandledExceptionFilter\n"
            "\n"
            "int WINAPI CrashDumpUnhandledExceptionFilter(void* p)\n"
            "{\n"
            "\treturn 0;\n"
            "}\n",
            encoding="utf-8",
        )
        anns = parse_c_file_multi(f)
        assert len(anns) == 1
        a = anns[0]
        assert a.marker_type == "STUB"
        assert a.name == "CrashDumpUnhandledExceptionFilter"
        assert a.symbol == "_CrashDumpUnhandledExceptionFilter@4"


# ---------------------------------------------------------------------------
# Shared helper tests
# ---------------------------------------------------------------------------


class TestHasSkipAnnotation:
    """Tests for has_skip_annotation()."""

    def test_skip_present_in_metadata(self, tmp_path: Path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "skipped.c"
        f.write_text("// FUNCTION: SERVER 0x10001000\nint x() {}\n", encoding="utf-8")
        meta = tmp_path / "rebrew-function.toml"
        meta.write_text('["SERVER.0x10001000"]\nskip = "not matchable"\n', encoding="utf-8")
        assert has_skip_annotation(f, metadata_dir=tmp_path) is True

    def test_no_skip_in_metadata(self, tmp_path: Path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "normal.c"
        f.write_text("// FUNCTION: SERVER 0x10001000\nint x() {}\n", encoding="utf-8")
        meta = tmp_path / "rebrew-function.toml"
        meta.write_text('["SERVER.0x10001000"]\nstatus = "EXACT"\n', encoding="utf-8")
        assert has_skip_annotation(f, metadata_dir=tmp_path) is False

    def test_no_metadata_dir(self, tmp_path: Path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "skipped.c"
        f.write_text("// FUNCTION: SERVER 0x10001000\nint x() {}\n", encoding="utf-8")
        assert has_skip_annotation(f) is False

    def test_skip_false_values(self, tmp_path: Path) -> None:
        from rebrew.annotation import has_skip_annotation

        f = tmp_path / "skipped.c"
        f.write_text("// FUNCTION: SERVER 0x10001000\nint x() {}\n", encoding="utf-8")
        for val in ("0", "false", "no", ""):
            meta = tmp_path / "rebrew-function.toml"
            meta.write_text(f'["SERVER.0x10001000"]\nskip = "{val}"\n', encoding="utf-8")
            assert has_skip_annotation(f, metadata_dir=tmp_path) is False


class TestResolveSymbol:
    """Tests for resolve_symbol()."""

    def test_symbol_present(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation, resolve_symbol

        ann = Annotation(symbol="_my_func")
        assert resolve_symbol(ann, tmp_path / "my_func.c") == "_my_func"

    def test_question_mark_fallback(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation, resolve_symbol

        ann = Annotation(symbol="?")
        assert resolve_symbol(ann, tmp_path / "my_func.c") == "_my_func"

    def test_empty_symbol_fallback(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation, resolve_symbol

        ann = Annotation(symbol="")
        assert resolve_symbol(ann, tmp_path / "game_pool_free.c") == "_game_pool_free"


# ---------------------------------------------------------------------------
# parse_library_header
# ---------------------------------------------------------------------------


class TestParseLibraryHeader:
    """Verify parse_library_header() for library_*.h files."""

    def test_parse_msvc_header(self, tmp_path: Path) -> None:
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

    def test_parse_zlib_header(self, tmp_path: Path) -> None:
        hfile = tmp_path / "library_zlib.h"
        hfile.write_text("// LIBRARY: SERVER 0x10050000\n// _deflate\n")
        results = parse_library_header(hfile)
        assert len(results) == 1
        assert results[0].va == 0x10050000
        assert results[0].symbol == "_deflate"

    def test_target_filter(self, tmp_path: Path) -> None:
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

    def test_empty_file(self, tmp_path: Path) -> None:
        hfile = tmp_path / "library_msvc.h"
        hfile.write_text("")
        results = parse_library_header(hfile)
        assert results == []

    def test_unknown_library_module(self, tmp_path: Path) -> None:
        hfile = tmp_path / "library_openssl.h"
        hfile.write_text("// LIBRARY: SERVER 0x10060000\n// _SSL_init\n")
        results = parse_library_header(hfile)
        assert len(results) == 1
        assert results[0].module == "SERVER"

    def test_extended_kv_annotations(self, tmp_path: Path) -> None:
        """KV lines after symbol are captured (rebrew extension, invisible to reccmp)."""
        hfile = tmp_path / "library_zlib.h"
        hfile.write_text(
            "// LIBRARY: SERVER 0x10050000\n"
            "// _deflate\n"
            "// STATUS: NEAR_MATCHING\n"
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
        assert results[0].status == "NEAR_MATCHING"
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

    def test_kv_module_preserved(self, tmp_path: Path) -> None:
        """Module (target name) in LIBRARY marker is stored in annotation.module."""
        hfile = tmp_path / "library_msvc.h"
        hfile.write_text("// LIBRARY: MYTARGET 0x10060000\n// _custom_alloc\n")
        results = parse_library_header(hfile)
        assert len(results) == 1
        assert results[0].module == "MYTARGET"


# ---------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------


class TestAuditAnnotation:
    """Tests for annotation edge cases and regression coverage."""

    # normalize_status: PROVEN branch — old-format variants must normalise to "PROVEN"
    def test_normalize_status_proven(self) -> None:
        """'PROVEN' must map to the canonical status string, not pass through verbatim."""
        assert normalize_status("PROVEN") == "PROVEN"
        # Old-format variants containing the word should also normalise
        assert normalize_status("proven_match") == "PROVEN"
        assert normalize_status("PROVEN_OK") == "PROVEN"

    # update_size_annotation: target_va parameter routes size to metadata, not .c file
    def test_update_size_annotation_target_va_match(self, tmp_path: Path) -> None:
        """When target_va is provided, size is written to metadata (not .c file)."""
        from rebrew.annotation import update_size_annotation
        from rebrew.metadata import get_entry

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

        # Update SIZE for 0x10002000 — goes to metadata, NOT the .c file
        changed = update_size_annotation(f, 99, target_va=0x10002000)
        assert changed is True

        # .c file must be untouched
        original = f.read_text(encoding="utf-8")
        assert "// SIZE: 20" in original  # .c file must remain untouched; size goes to metadata

        # Metadata must have new value for func_b only
        entry_b = get_entry(tmp_path, 0x10002000, module="SERVER")
        assert entry_b["size"] == 99
        # func_a not in metadata (was not touched)
        entry_a = get_entry(tmp_path, 0x10001000, module="SERVER")
        assert "size" not in entry_a

    def test_update_size_annotation_target_va_no_match(self, tmp_path: Path) -> None:
        """update_size_annotation returns False when new_size <= existing metadata size."""
        from rebrew.annotation import update_size_annotation
        from rebrew.metadata import save_metadata

        f = tmp_path / "single.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// SIZE: 10\nint f(void) {}\n", encoding="utf-8"
        )
        # Pre-populate metadata with size=200 so new_size=99 is rejected (not an increase)
        save_metadata(tmp_path, {("SERVER", 0x10001000): {"size": 200}})
        changed = update_size_annotation(f, 99, target_va=0x10001000)
        assert changed is False

    def test_update_size_annotation_no_shrink(self, tmp_path: Path) -> None:
        """update_size_annotation never reduces size (safety invariant).

        The metadata must be pre-populated with the existing size; the .c file's
        // SIZE: annotation is no longer read by update_size_annotation.
        """
        from rebrew.annotation import update_size_annotation
        from rebrew.metadata import save_metadata

        f = tmp_path / "big.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// SIZE: 100\nint f(void) {}\n", encoding="utf-8"
        )
        # Pre-populate metadata with existing size — update_size_annotation now reads metadata
        save_metadata(tmp_path, {("SERVER", 0x10001000): {"size": 100}})
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
        """BLOCKER is a metadata key — update_annotation_key writes to rebrew-function.toml.

        The .c file must remain completely untouched. VA2 is never affected.
        """
        from rebrew.annotation import update_annotation_key
        from rebrew.metadata import get_entry

        content = (
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: RELOC\n"
            "// SIZE: 42\n"
            "int func_a(void) {}\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: NEAR_MATCHING\n"
            "// SIZE: 100\n"
            "int func_b(void) {}\n"
        )
        f = tmp_path / "dual.c"
        f.write_text(content, encoding="utf-8")

        changed = update_annotation_key(f, 0x10001000, "BLOCKER", "1B diff")
        assert changed is True

        # .c file must be completely untouched
        assert f.read_text(encoding="utf-8") == content

        # VA1 metadata entry has blocker
        entry1 = get_entry(tmp_path, 0x10001000, module="SERVER")
        assert entry1["blocker"] == "1B diff"
        # VA2 was not touched
        entry2 = get_entry(tmp_path, 0x10002000, module="SERVER")
        assert "blocker" not in entry2

    # --- P1-02 regression: remove_annotation_key must not bleed into next block ---

    def test_remove_annotation_key_no_bleed_into_next_block(self, tmp_path: Path) -> None:
        """BLOCKER is a metadata key — remove_annotation_key deletes from rebrew-function.toml.

        The .c file must remain untouched. VA2's metadata entry is not affected.
        """
        from rebrew.annotation import remove_annotation_key
        from rebrew.metadata import get_entry, save_metadata

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

        # Pre-populate metadata for both VAs
        save_metadata(
            tmp_path,
            {
                ("SERVER", 0x10001000): {"blocker": "needs investigation"},
                ("SERVER", 0x10002000): {"blocker": "different blocker"},
            },
        )

        changed = remove_annotation_key(f, 0x10001000, "BLOCKER")
        assert changed is True

        # VA1's blocker must be gone from metadata
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


# ---------------------------------------------------------------------------
# split_annotation_sections
# ---------------------------------------------------------------------------


class TestSplitAnnotationSections:
    def test_empty_text(self) -> None:
        preamble, blocks = split_annotation_sections("")
        assert preamble == ""
        assert blocks == []

    def test_no_markers(self) -> None:
        text = "#include <stdio.h>\nint main() { return 0; }\n"
        preamble, blocks = split_annotation_sections(text)
        assert preamble == text
        assert blocks == []

    def test_single_function_block(self) -> None:
        text = "#include <stdio.h>\n// FUNCTION: GAME 0x10001000\nint foo() { return 1; }\n"
        preamble, blocks = split_annotation_sections(text)
        assert preamble == "#include <stdio.h>\n"
        assert len(blocks) == 1
        assert "// FUNCTION: GAME 0x10001000" in blocks[0]
        assert "int foo()" in blocks[0]

    def test_multiple_function_blocks(self) -> None:
        text = (
            "#include <stdlib.h>\n"
            "// FUNCTION: GAME 0x10001000\n"
            "int foo() { return 1; }\n"
            "// FUNCTION: GAME 0x10002000\n"
            "int bar() { return 2; }\n"
            "// LIBRARY: MSVCRT 0x10003000\n"
            "int baz() { return 3; }\n"
        )
        preamble, blocks = split_annotation_sections(text)
        assert preamble == "#include <stdlib.h>\n"
        assert len(blocks) == 3

    def test_no_preamble(self) -> None:
        text = "// FUNCTION: GAME 0x10001000\nint foo() {}\n"
        preamble, blocks = split_annotation_sections(text)
        assert preamble == ""
        assert len(blocks) == 1

    def test_all_marker_types(self) -> None:
        text = (
            "// STUB: GAME 0x10001000\nvoid stub() {}\n"
            "// GLOBAL: GAME 0x10002000\nint g_val;\n"
            "// DATA: GAME 0x10003000\nchar data[];\n"
        )
        preamble, blocks = split_annotation_sections(text)
        assert preamble == ""
        assert len(blocks) == 3


def test_update_annotation_key_multiple_funcs(tmp_path: Path) -> None:
    cfile = tmp_path / "test.c"
    cfile.write_text(
        """// FUNCTION: GAME 0x1000
// STATUS: EXACT
// CFLAGS: /O2
// SIZE: 10
void func_1000() {}

// FUNCTION: GAME 0x2000
// SIZE: 10
void func_2000() {}
""",
        encoding="utf-8",
    )

    assert update_annotation_key(cfile, 0x1000, "SYMBOL", "ResetScore")
    assert update_annotation_key(cfile, 0x2000, "SYMBOL", "AddScore")

    text = cfile.read_text(encoding="utf-8")
    assert "// SYMBOL: ResetScore" in text
    assert "// SYMBOL: func_1000" not in text
    assert "// SYMBOL: AddScore" in text
    assert "// SYMBOL: func_2000" not in text


class TestValidateEdgeBranches:
    def test_inline_error_reported(self) -> None:
        ann = Annotation(va=0x10001000, inline_error="// FUNCTION: SERVER 0x1000 // EXTRA")
        errors, _warnings = ann.validate()
        assert any("Multiple annotations" in e for e in errors)

    def test_suspicious_va_reported(self) -> None:
        ann = Annotation(va=0x500)  # below MIN_VALID_VA
        errors, _warnings = ann.validate()
        assert any("suspicious" in e for e in errors)

    def test_invalid_marker_reported(self) -> None:
        ann = Annotation(va=0x10001000, marker_type="NOTAMARKER")
        errors, _warnings = ann.validate()
        assert any("Invalid marker type" in e for e in errors)


class TestSplitAnnotationSectionsRescue:
    def test_orphaned_kv_rescued_from_preamble(self) -> None:
        from rebrew.annotation import split_annotation_sections

        text = (
            "#include <stdio.h>\n"
            "// STATUS: EXACT\n"
            "int helper(void);\n"
            "// FUNCTION: SERVER 0x1000\n"
            "int f(void) { return helper(); }\n"
        )
        preamble, blocks = split_annotation_sections(text)
        # The orphaned STATUS KV moves into the function block.
        assert "STATUS" not in preamble
        assert "// STATUS: EXACT" in blocks[0]

    def test_no_rescue_when_no_orphans(self) -> None:
        from rebrew.annotation import split_annotation_sections

        text = "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n"
        preamble, blocks = split_annotation_sections(text)
        assert preamble == ""
        assert len(blocks) == 1


class TestNormalizeStatusProven:
    def test_proven_passthrough(self) -> None:
        from rebrew.annotation import normalize_status

        assert normalize_status("PROVEN") == "PROVEN"

    def test_exact_wins_over_proven_substring(self) -> None:
        from rebrew.annotation import normalize_status

        # "PROVEN" alone hits the PROVEN branch; a string containing EXACT
        # wins earlier.
        assert normalize_status("EXACT_MATCH_PROVEN") == "EXACT"


class TestAnnotationValidateBranches:
    def test_library_without_source_warns(self) -> None:
        from rebrew.annotation import Annotation

        ann = Annotation(
            va=0x1000, module="MSVCRT", name="f", marker_type="LIBRARY", status="EXACT"
        )
        errors, warnings = ann.validate(library_modules={"MSVCRT"})
        assert any("missing SOURCE" in w for w in warnings)

    def test_near_matching_stub_contradiction(self) -> None:
        from rebrew.annotation import Annotation

        ann = Annotation(
            va=0x1000, module="GAME", name="f", marker_type="STUB", status="NEAR_MATCHING"
        )
        errors, warnings = ann.validate()
        assert any("Contradictory" in w for w in warnings)


class TestRemoveAnnotationKeyFile:
    def test_removes_non_metadata_key(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_annotation_key

        f = tmp_path / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// SYMBOL: _f\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        assert remove_annotation_key(f, 0x1000, "SYMBOL") is True
        assert "// SYMBOL:" not in f.read_text(encoding="utf-8")

    def test_missing_key_noop(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_annotation_key

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert remove_annotation_key(f, 0x1000, "SYMBOL") is False


class TestUpdateAnnotationKeyFile:
    def test_same_value_noop(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_annotation_key

        f = tmp_path / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// NOTE: keep me\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        # NOTE is metadata-owned → writes to metadata, returns True.
        assert update_annotation_key(f, 0x1000, "NOTE", "keep me", metadata_dir=tmp_path) is True

    def test_unknown_key_inserted(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_annotation_key

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        # A non-metadata key (ANALYSIS is metadata; use a custom one) — the
        # function block gets a new KV line inserted.
        assert update_annotation_key(f, 0x1000, "TESTKEY", "abc") is True
        assert "// TESTKEY: abc" in f.read_text(encoding="utf-8")

    def test_va_not_in_file_noop(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_annotation_key

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert update_annotation_key(f, 0x9999, "TESTKEY", "abc") is False


class TestAnnotationKeyRoundTrips:
    """Round-trip invariants across update/remove for file vs metadata keys.

    update_annotation_key ↔ remove_annotation_key are inverses: a file key
    round-trips the ``.c`` back to its original bytes, and a metadata key
    round-trips the TOML without ever touching the source file.  The
    lint-style flow (inline STATUS in ``.c`` + metadata ownership) is covered
    by remove_inline_annotation_key, which must never delete metadata.
    """

    def test_file_key_update_remove_returns_to_original(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_annotation_key, update_annotation_key

        f = tmp_path / "f.c"
        original = "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n"
        f.write_text(original, encoding="utf-8")
        assert update_annotation_key(f, 0x1000, "TESTKEY", "abc") is True
        assert "// TESTKEY: abc" in f.read_text(encoding="utf-8")
        assert remove_annotation_key(f, 0x1000, "TESTKEY") is True
        assert f.read_text(encoding="utf-8") == original
        # Idempotent: nothing left to remove.
        assert remove_annotation_key(f, 0x1000, "TESTKEY") is False

    def test_metadata_key_round_trip_keeps_c_untouched(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_annotation_key, update_annotation_key
        from rebrew.metadata import get_entry

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        md = tmp_path / "md"
        md.mkdir()
        assert update_annotation_key(f, 0x1000, "CFLAGS", "/O2", metadata_dir=md) is True
        # File untouched; metadata owns the field.
        assert "CFLAGS" not in f.read_text(encoding="utf-8")
        assert get_entry(md, 0x1000, "SERVER").get("cflags") == "/O2"
        assert remove_annotation_key(f, 0x1000, "CFLAGS", metadata_dir=md) is True
        assert "cflags" not in get_entry(md, 0x1000, "SERVER")
        assert "CFLAGS" not in f.read_text(encoding="utf-8")

    def test_update_same_value_is_noop(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_annotation_key

        f = tmp_path / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// TESTKEY: old\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        assert update_annotation_key(f, 0x1000, "TESTKEY", "new") is True
        assert "// TESTKEY: new" in f.read_text(encoding="utf-8")
        # Same value again is a no-op (no rewrite).
        assert update_annotation_key(f, 0x1000, "TESTKEY", "new") is False

    def test_remove_inline_never_touches_metadata(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_inline_annotation_key
        from rebrew.metadata import get_entry, update_source_status

        f = tmp_path / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// STATUS: EXACT\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        update_source_status(tmp_path, "EXACT", "SERVER", 0x1000)
        assert remove_inline_annotation_key(f, 0x1000, "STATUS") is True
        assert "// STATUS:" not in f.read_text(encoding="utf-8")
        # Metadata untouched (routing through remove_annotation_key would
        # have deleted the field instead).
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "EXACT"


class TestModuleForVa:
    def test_unreadable_returns_empty(self, tmp_path: Path) -> None:
        from rebrew.annotation import module_for_va

        assert module_for_va(tmp_path / "nope.c", 0x1000) == ""

    def test_found_module(self, tmp_path: Path) -> None:
        from rebrew.annotation import module_for_va

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert module_for_va(f, 0x1000) == "SERVER"


class TestUpdateSizeAnnotation:
    def test_infers_va_from_marker(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_size_annotation
        from rebrew.metadata import get_entry

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert update_size_annotation(f, 128) is True
        assert get_entry(tmp_path, 0x1000, "SERVER").get("size") == 128

    def test_never_shrinks(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_size_annotation
        from rebrew.metadata import get_entry, update_field

        update_field(tmp_path, 0x1000, "size", 200, "SERVER")
        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert update_size_annotation(f, 128) is False
        assert get_entry(tmp_path, 0x1000, "SERVER").get("size") == 200

    def test_no_va_returns_false(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_size_annotation

        f = tmp_path / "f.c"
        f.write_text("int f(void) { return 0; }\n", encoding="utf-8")
        assert update_size_annotation(f, 128) is False


class TestParseLibraryHeaderKv:
    def test_kv_lines_collected(self, tmp_path: Path) -> None:
        from rebrew.annotation import parse_library_header

        h = tmp_path / "library_msvc.h"
        h.write_text(
            "// LIBRARY: SERVER 0x1000\n"
            "// _fflush\n"
            "// STATUS: NEAR_MATCHING\n"
            "// SIZE: 120\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SOURCE: deflate.c\n",
            encoding="utf-8",
        )
        results = parse_library_header(h, target_name="SERVER")
        assert len(results) == 1
        ann = results[0]
        assert ann.symbol == "_fflush"
        assert ann.status == "NEAR_MATCHING"
        assert ann.size == 120
        assert ann.cflags == "/O2 /Gd"
        assert ann.source == "deflate.c"

    def test_target_filter(self, tmp_path: Path) -> None:
        from rebrew.annotation import parse_library_header

        h = tmp_path / "library_msvc.h"
        h.write_text(
            "// LIBRARY: OTHER 0x1000\n// _fflush\n// LIBRARY: SERVER 0x2000\n// _malloc\n",
            encoding="utf-8",
        )
        results = parse_library_header(h, target_name="SERVER")
        assert [r.va for r in results] == [0x2000]

    def test_default_status_exact(self, tmp_path: Path) -> None:
        from rebrew.annotation import parse_library_header

        h = tmp_path / "library_msvc.h"
        h.write_text("// LIBRARY: SERVER 0x1000\n// _memcpy\n", encoding="utf-8")
        results = parse_library_header(h)
        assert results[0].status == "EXACT"

    def test_missing_file_empty(self, tmp_path: Path) -> None:
        from rebrew.annotation import parse_library_header

        assert parse_library_header(tmp_path / "nope.h") == []


class TestParseNewFormatEdges:
    def test_global_after_function_not_overwritten(self) -> None:
        from rebrew.annotation import parse_new_format_multi

        lines = [
            "// FUNCTION: GAME 0x1000",
            "int f(void) { return 0; }",
            "// GLOBAL: GAME 0x2000",
            "int g;",
        ]
        results = parse_new_format_multi(lines)
        types = [(a.marker_type, a.va) for a in results]
        # The GLOBAL marker becomes a separate entry (not merged into f).
        assert ("FUNCTION", 0x1000) in types
        assert ("GLOBAL", 0x2000) in types

    def test_inline_error_after_va_stashed(self) -> None:
        from rebrew.annotation import parse_new_format_multi

        lines = ["// FUNCTION: SERVER 0x1000 // trailing junk", "int f(void) { return 0; }"]
        results = parse_new_format_multi(lines)
        assert results[0].va == 0x1000
        assert "trailing junk" in results[0].inline_error

    def test_blocker_delta_non_numeric_none(self) -> None:
        from rebrew.annotation import parse_new_format_multi

        lines = [
            "// FUNCTION: SERVER 0x1000",
            "// BLOCKER_DELTA: abc",
            "int f(void) { return 0; }",
        ]
        results = parse_new_format_multi(lines)
        assert results[0].blocker_delta is None


class TestUpdateAnnotationKeySameValue:
    def test_same_value_noop_file_key(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_annotation_key

        f = tmp_path / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// TESTKEY: abc\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        assert update_annotation_key(f, 0x1000, "TESTKEY", "abc") is False

    def test_different_value_updates(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_annotation_key

        f = tmp_path / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// TESTKEY: abc\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        assert update_annotation_key(f, 0x1000, "TESTKEY", "xyz") is True
        assert "// TESTKEY: xyz" in f.read_text(encoding="utf-8")

    def test_end_of_file_insert(self, tmp_path: Path) -> None:
        from rebrew.annotation import update_annotation_key

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\n\nint f(void) { return 0; }\n", encoding="utf-8")
        # Annotation block ends at the blank line before the body.
        assert update_annotation_key(f, 0x1000, "TESTKEY", "tail") is True
        assert "// TESTKEY: tail" in f.read_text(encoding="utf-8")


class TestRemoveAnnotationKeyEdges:
    def test_removes_middle_key(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_annotation_key

        f = tmp_path / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// A: 1\n// B: 2\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        assert remove_annotation_key(f, 0x1000, "A") is True
        text = f.read_text(encoding="utf-8")
        assert "// A:" not in text
        assert "// B: 2" in text  # sibling key preserved

    def test_does_not_cross_into_next_block(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_annotation_key

        f = tmp_path / "f.c"
        f.write_text(
            "// FUNCTION: SERVER 0x1000\n// A: 1\nint f(void) { return 0; }\n"
            "// FUNCTION: SERVER 0x2000\n// A: 2\nint g(void) { return 0; }\n",
            encoding="utf-8",
        )
        assert remove_annotation_key(f, 0x1000, "A") is True
        text = f.read_text(encoding="utf-8")
        assert "// A: 2" in text  # second block's key untouched


class TestAnnotationKeyInvariants:
    """update ↔ remove symmetry for file and metadata keys."""

    def test_file_key_update_then_remove(self, tmp_path: Path) -> None:
        from rebrew.annotation import (
            remove_inline_annotation_key,
            update_annotation_key,
        )

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert update_annotation_key(f, 0x1000, "TESTKEY", "abc") is True
        assert "// TESTKEY: abc" in f.read_text(encoding="utf-8")
        assert remove_inline_annotation_key(f, 0x1000, "TESTKEY") is True
        assert f.read_text(encoding="utf-8") == (
            "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n"
        )

    def test_metadata_key_update_then_remove(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_annotation_key, update_annotation_key
        from rebrew.metadata import get_entry

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert update_annotation_key(f, 0x1000, "NOTE", "hello", metadata_dir=tmp_path) is True
        assert get_entry(tmp_path, 0x1000, "SERVER").get("note") == "hello"
        assert remove_annotation_key(f, 0x1000, "NOTE", metadata_dir=tmp_path) is True
        assert get_entry(tmp_path, 0x1000, "SERVER").get("note") is None

    def test_remove_then_remove_idempotent(self, tmp_path: Path) -> None:
        from rebrew.annotation import remove_inline_annotation_key

        f = tmp_path / "f.c"
        f.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert remove_inline_annotation_key(f, 0x1000, "TESTKEY") is False
        # Second call is still a no-op (idempotent).
        assert remove_inline_annotation_key(f, 0x1000, "TESTKEY") is False


class TestStdcallParamSizeDeclspec:
    """__declspec(...) groups contain parens — the param-list must not be
    confused with the declspec group (np-rebrew TOOLCHAIN_BUGS naked gap)."""

    def test_naked_void_is_zero(self) -> None:
        from rebrew.annotation import _calc_stdcall_param_size  # type: ignore[attr-defined]

        assert _calc_stdcall_param_size("void __declspec(naked) __stdcall foo(void)") == 0
        assert _calc_stdcall_param_size("void __declspec(naked) __stdcall foo()") == 0

    def test_naked_with_params(self) -> None:
        from rebrew.annotation import _calc_stdcall_param_size  # type: ignore[attr-defined]

        assert _calc_stdcall_param_size("void __declspec(naked) __stdcall foo(int a)") == 4
        assert _calc_stdcall_param_size("int __declspec(naked) __stdcall foo(int a, int b)") == 8

    def test_plain_unchanged(self) -> None:
        from rebrew.annotation import _calc_stdcall_param_size  # type: ignore[attr-defined]

        assert _calc_stdcall_param_size("void __stdcall foo(void)") == 0
        assert _calc_stdcall_param_size("int __stdcall foo(int a, int b, int c)") == 12
