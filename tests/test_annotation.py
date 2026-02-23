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

    def test_defaults(self):
        ann = Annotation()
        assert ann.va == 0
        assert ann.size == 0
        assert ann.name == ""
        assert ann.globals_list == []

    def test_field_access(self):
        ann = Annotation(va=0x10001000, size=42, name="foo", status="EXACT")
        assert ann.va == 0x10001000
        assert ann.size == 42
        assert ann.name == "foo"
        assert ann.status == "EXACT"

    def test_dict_getitem(self):
        ann = Annotation(va=0x10001000, status="RELOC")
        assert ann["va"] == 0x10001000
        assert ann["status"] == "RELOC"

    def test_dict_setitem(self):
        ann = Annotation()
        ann["status"] = "EXACT"
        assert ann.status == "EXACT"
        assert ann["status"] == "EXACT"

    def test_dict_globals_alias(self):
        """The 'globals' key should map to globals_list field."""
        ann = Annotation(globals_list=["a", "b"])
        assert ann["globals"] == ["a", "b"]
        ann["globals"] = ["c"]
        assert ann.globals_list == ["c"]

    def test_dict_contains(self):
        ann = Annotation()
        assert "va" in ann
        assert "status" in ann
        assert "globals" in ann
        assert "nonexistent_field" not in ann

    def test_dict_get_existing(self):
        ann = Annotation(status="EXACT")
        assert ann.get("status") == "EXACT"

    def test_dict_get_missing(self):
        ann = Annotation()
        assert ann.get("nonexistent", "default") == "default"

    def test_dict_getitem_invalid_key(self):
        ann = Annotation()
        with pytest.raises(KeyError):
            _ = ann["nonexistent_key"]

    def test_dict_setitem_invalid_key(self):
        ann = Annotation()
        with pytest.raises(KeyError):
            ann["nonexistent_key"] = "value"

    def test_to_dict(self):
        ann = Annotation(
            va=0x10001000, size=42, name="foo", symbol="_foo",
            status="EXACT", origin="GAME", cflags="/O2", marker_type="FUNCTION",
            filepath="foo.c", source="", blocker="", note="",
            globals_list=["g1"],
        )
        d = ann.to_dict()
        assert d["va"] == 0x10001000
        assert d["name"] == "foo"
        assert d["globals"] == ["g1"]
        assert isinstance(d, dict)

    def test_make_func_entry_returns_annotation(self):
        ann = make_func_entry(
            va=0x10001000, size=42, name="foo", symbol="_foo",
            status="EXACT", origin="GAME", cflags="/O2",
            marker_type="FUNCTION", filepath="foo.c",
        )
        assert isinstance(ann, Annotation)
        assert ann.va == 0x10001000
        assert ann["va"] == 0x10001000


# ---------------------------------------------------------------------------
# Annotation.validate()
# ---------------------------------------------------------------------------


class TestAnnotationValidation:
    """Verify Annotation.validate() catches issues."""

    def test_valid_annotation_no_errors(self):
        ann = Annotation(
            va=0x10001000, size=42, name="foo", symbol="_foo",
            status="EXACT", origin="GAME", cflags="/O2",
            marker_type="FUNCTION",
        )
        errors, warnings = ann.validate()
        assert errors == []

    def test_invalid_status(self):
        ann = Annotation(
            va=0x10001000, size=42, cflags="/O2",
            status="BOGUS", origin="GAME", marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("STATUS" in e for e in errors)

    def test_invalid_origin(self):
        ann = Annotation(
            va=0x10001000, size=42, cflags="/O2",
            status="EXACT", origin="BOGUS", marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("ORIGIN" in e for e in errors)

    def test_invalid_size(self):
        ann = Annotation(
            va=0x10001000, size=0, cflags="/O2",
            status="EXACT", origin="GAME", marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("SIZE" in e for e in errors)

    def test_missing_cflags(self):
        ann = Annotation(
            va=0x10001000, size=42, cflags="",
            status="EXACT", origin="GAME", marker_type="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("CFLAGS" in e for e in errors)

    def test_missing_symbol_warning(self):
        ann = Annotation(
            va=0x10001000, size=42, cflags="/O2", symbol="",
            status="EXACT", origin="GAME", marker_type="FUNCTION",
        )
        _, warnings = ann.validate()
        assert any("SYMBOL" in w for w in warnings)

    def test_stub_without_blocker_warning(self):
        ann = Annotation(
            va=0x10001000, size=42, cflags="/O2", symbol="_foo",
            status="STUB", origin="GAME", marker_type="STUB",
        )
        _, warnings = ann.validate()
        assert any("BLOCKER" in w for w in warnings)

    def test_msvcrt_without_source_warning(self):
        ann = Annotation(
            va=0x10001000, size=42, cflags="/O2", symbol="_foo",
            status="EXACT", origin="MSVCRT", marker_type="LIBRARY",
        )
        _, warnings = ann.validate()
        assert any("SOURCE" in w for w in warnings)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestNormalizeHelpers:
    def test_normalize_status_exact(self):
        assert normalize_status("EXACT MATCH") == "EXACT"
        assert normalize_status("exact") == "EXACT"

    def test_normalize_status_reloc(self):
        assert normalize_status("RELOC MATCH") == "RELOC"

    def test_normalize_status_stub(self):
        assert normalize_status("STUB") == "STUB"

    def test_normalize_cflags(self):
        assert normalize_cflags("  /O2 /Gd , ") == "/O2 /Gd"

    def test_marker_for_origin(self):
        assert marker_for_origin("GAME", "EXACT") == "FUNCTION"
        assert marker_for_origin("MSVCRT", "EXACT") == "LIBRARY"
        assert marker_for_origin("GAME", "STUB") == "STUB"


class TestParseOldFormat:
    def test_parse_valid(self):
        line = "/* bit_reverse @ 0x10008880 (31B) - /O2 /Gd - EXACT MATCH [GAME] */"
        result = parse_old_format(line)
        assert result is not None
        assert result["va"] == 0x10008880
        assert result["size"] == 31
        assert result["status"] == "EXACT"
        assert result["origin"] == "GAME"
        assert result["name"] == "bit_reverse"

    def test_parse_invalid_returns_none(self):
        assert parse_old_format("int main() {}") is None
        assert parse_old_format("") is None


class TestParseNewFormat:
    def test_parse_valid(self):
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

    def test_parse_no_marker_returns_none(self):
        lines = [
            "// STATUS: EXACT",
            "// ORIGIN: GAME",
        ]
        assert parse_new_format(lines) is None

    def test_parse_with_globals(self):
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
        assert result["globals"] == ["g_counter", "g_flag"]


class TestParseCFile:
    def test_parse_new_format_file(self, tmp_path):
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
        f.write_text(content)
        result = parse_c_file(f)
        assert result is not None
        assert result["va"] == 0x10001234
        assert result["filepath"] == "myfunc.c"

    def test_parse_old_format_file(self, tmp_path):
        content = "/* myfunc @ 0x10001234 (42B) - /O2 - EXACT MATCH [GAME] */\nint myfunc(void) { return 0; }\n"
        f = tmp_path / "myfunc.c"
        f.write_text(content)
        result = parse_c_file(f)
        assert result is not None
        assert result["va"] == 0x10001234

    def test_parse_nonexistent_file(self, tmp_path):
        f = tmp_path / "does_not_exist.c"
        assert parse_c_file(f) is None

    def test_parse_empty_file(self, tmp_path):
        f = tmp_path / "empty.c"
        f.write_text("")
        assert parse_c_file(f) is None
