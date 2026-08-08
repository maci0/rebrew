"""Tests for ghidra/commands.py struct helpers."""

from rebrew.ghidra.commands import _append_struct_def, _make_header_preamble


class TestMakeHeaderPreamble:
    def test_preamble(self) -> None:
        lines = _make_header_preamble(3, "TYPES_H")
        assert lines[0].startswith("/* Auto-generated")
        assert "3 structures" in lines[1]
        assert "#ifndef TYPES_H" in lines
        assert "#define TYPES_H" in lines
        assert "typedef unsigned char uint8_t;" in lines


class TestAppendStructDef:
    def test_c_definition_dict(self) -> None:
        lines: list[str] = []
        ok = _append_struct_def(
            lines, "NPSTATE", {"cDefinition": "typedef struct NPSTATE { int x; } NPSTATE;"}
        )
        assert ok is True
        assert "typedef struct NPSTATE" in "\n".join(lines)

    def test_fields_dict(self) -> None:
        lines: list[str] = []
        ok = _append_struct_def(
            lines,
            "Item",
            {"size": 8, "fields": [{"name": "id", "dataType": "int", "offset": 0}]},
        )
        assert ok is True
        assert "typedef struct Item {" in lines
        assert "int id;" in "\n".join(lines)
        assert "offset 0x0" in "\n".join(lines)

    def test_no_usable_info(self) -> None:
        lines: list[str] = []
        ok = _append_struct_def(lines, "Empty", {})
        assert ok is False
        assert lines == []

    def test_string_info_is_raw_definition(self) -> None:
        lines: list[str] = []
        ok = _append_struct_def(lines, "X", "typedef struct X { int y; } X;")
        assert ok is True
        assert "typedef struct X" in "\n".join(lines)
