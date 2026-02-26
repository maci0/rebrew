"""Tests for rebrew.annotation — Annotation dataclass and parsers."""

import pytest

from rebrew.annotation import (
    Annotation,
    make_func_entry,
    marker_for_origin,
    normalize_cflags,
    normalize_status,
    parse_c_file,
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
            origin="GAME",
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
            origin="GAME",
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
            origin="GAME",
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
            origin="GAME",
            marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("STATUS" in e for e in errors)

    def test_invalid_origin(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            status="EXACT",
            origin="BOGUS",
            marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("ORIGIN" in e for e in errors)

    def test_invalid_size(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=0,
            cflags="/O2",
            status="EXACT",
            origin="GAME",
            marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("SIZE" in e for e in errors)

    def test_missing_cflags(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="",
            status="EXACT",
            origin="GAME",
            marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("CFLAGS" in e for e in errors)

    def test_missing_symbol_warning(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="",
            status="EXACT",
            origin="GAME",
            marker_type="FUNCTION",
        )
        _, warnings = ann.validate()
        assert any("SYMBOL" in w for w in warnings)

    def test_stub_without_blocker_warning(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="_foo",
            status="STUB",
            origin="GAME",
            marker_type="STUB",
        )
        _, warnings = ann.validate()
        assert any("BLOCKER" in w for w in warnings)

    def test_msvcrt_without_source_warning(self) -> None:
        ann = Annotation(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="_foo",
            status="EXACT",
            origin="MSVCRT",
            marker_type="LIBRARY",
        )
        _, warnings = ann.validate()
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
        # Regression: must NOT mangle MATCHING_RELOC → RELOC (substring order bug)
        assert normalize_status("MATCHING_RELOC") == "MATCHING_RELOC"

    def test_normalize_status_stub(self) -> None:
        assert normalize_status("STUB") == "STUB"

    def test_normalize_cflags(self) -> None:
        assert normalize_cflags("  /O2 /Gd , ") == "/O2 /Gd"

    def test_marker_for_origin(self) -> None:
        assert marker_for_origin("GAME", "EXACT") == "FUNCTION"
        assert marker_for_origin("MSVCRT", "EXACT") == "LIBRARY"
        assert marker_for_origin("GAME", "STUB") == "STUB"

    def test_marker_for_origin_custom_library_origins(self) -> None:
        assert marker_for_origin("DIRECTX", "EXACT", library_origins={"DIRECTX"}) == "LIBRARY"
        assert marker_for_origin("GAME", "EXACT", library_origins={"DIRECTX"}) == "FUNCTION"

    def test_marker_for_origin_empty_library_origins(self) -> None:
        # Empty set: no origins are library origins
        assert marker_for_origin("MSVCRT", "EXACT", library_origins=set()) == "FUNCTION"


class TestOriginFromFilename:
    def test_default_prefixes(self) -> None:
        from rebrew.annotation import origin_from_filename

        # zlib_ prefix → ZLIB
        result = origin_from_filename("zlib_inflate")
        assert result == "ZLIB"

    def test_custom_prefixes(self) -> None:
        from rebrew.annotation import origin_from_filename

        result = origin_from_filename("dx_init_device", {"dx_": "DIRECTX", "game_": "GAME"})
        assert result == "DIRECTX"

    def test_no_match(self) -> None:
        from rebrew.annotation import origin_from_filename

        result = origin_from_filename("my_custom_func")
        assert result is None


class TestParseOldFormat:
    def test_parse_valid(self) -> None:
        line = "/* bit_reverse @ 0x10008880 (31B) - /O2 /Gd - EXACT MATCH [GAME] */"
        result = parse_old_format(line)
        assert result is not None
        assert result["va"] == 0x10008880
        assert result["size"] == 31
        assert result["status"] == "EXACT"
        assert result["origin"] == "GAME"
        assert result["name"] == "bit_reverse"

    def test_parse_invalid_returns_none(self) -> None:
        assert parse_old_format("int main() {}") is None
        assert parse_old_format("") is None


class TestParseNewFormat:
    def test_parse_valid(self) -> None:
        lines = [
            "// FUNCTION: SERVER 0x10008880",
            "// STATUS: EXACT",
            "// ORIGIN: GAME",
            "// SIZE: 31",
            "// CFLAGS: /O2 /Gd",
            "// SYMBOL: _bit_reverse",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result["va"] == 0x10008880
        assert result["status"] == "EXACT"
        assert result["origin"] == "GAME"
        assert result["size"] == 31
        assert result["symbol"] == "_bit_reverse"

    def test_parse_no_marker_returns_none(self) -> None:
        lines = [
            "// STATUS: EXACT",
            "// ORIGIN: GAME",
        ]
        assert parse_new_format(lines) is None

    def test_parse_with_globals(self) -> None:
        lines = [
            "// FUNCTION: SERVER 0x10001000",
            "// STATUS: EXACT",
            "// ORIGIN: GAME",
            "// SIZE: 100",
            "// CFLAGS: /O2",
            "// GLOBALS: g_counter, g_flag",
        ]
        result = parse_new_format(lines)
        assert result is not None
        assert result["va"] == 0x10001000
        assert result["status"] == "EXACT"
        assert result["origin"] == "GAME"
        assert result["size"] == 100
        assert result["cflags"] == "/O2"
        assert result["globals"] == ["g_counter", "g_flag"]


class TestParseCFile:
    def test_parse_new_format_file(self, tmp_path) -> None:
        content = """\
// FUNCTION: SERVER 0x10001234
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 42
// CFLAGS: /O2
// SYMBOL: _myfunc

int myfunc(void) { return 0; }
"""
        f = tmp_path / "myfunc.c"
        f.write_text(content, encoding="utf-8")
        result = parse_c_file(f)
        assert result is not None
        assert result["va"] == 0x10001234
        assert result["status"] == "EXACT"
        assert result["origin"] == "GAME"
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
        assert result["origin"] == "GAME"
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
            "// ORIGIN: GAME",
            "// SIZE: 42",
            "// CFLAGS: /O2",
            "// SYMBOL: _func_a",
            "",
            "int func_a(void) { return 0; }",
            "",
            "// FUNCTION: SERVER 0x10002000",
            "// STATUS: MATCHING",
            "// ORIGIN: MSVCRT",
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
        assert results[1].origin == "MSVCRT"

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
// ORIGIN: GAME
// SIZE: 42
// CFLAGS: /O2
// SYMBOL: _func_a

int func_a(void) { return 0; }

// FUNCTION: SERVER 0x10002000
// STATUS: MATCHING
// ORIGIN: GAME
// SIZE: 100
// CFLAGS: /O2
// SYMBOL: _func_b

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
        """parse_c_file backward compat: returns first annotation only."""
        content = """\
// FUNCTION: SERVER 0x10001000
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 42
// CFLAGS: /O2
// SYMBOL: _func_a

int func_a(void) { return 0; }

// FUNCTION: SERVER 0x10002000
// STATUS: MATCHING
// ORIGIN: GAME
// SIZE: 100
// CFLAGS: /O2
// SYMBOL: _func_b

int func_b(void) { return 1; }
"""
        f = tmp_path / "multi.c"
        f.write_text(content, encoding="utf-8")
        result = parse_c_file(f)
        assert result is not None
        assert result.va == 0x10001000
        assert result.status == "EXACT"
        assert result.size == 42
        assert result.symbol == "_func_a"

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
