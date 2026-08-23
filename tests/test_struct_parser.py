"""Tests for rebrew.struct_parser — struct/typedef extraction via tree-sitter."""

from pathlib import Path

import pytest

from rebrew.struct_parser import (
    extract_enums_from_file,
    extract_structs_from_file,
    extract_type_definitions,
)


def _tree_sitter_available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_c  # noqa: F401

        return True
    except ImportError:
        return False


_SKIP_NO_TS = pytest.mark.skipif(
    not _tree_sitter_available(),
    reason="tree-sitter-c not installed",
)


class TestExtractStructsFromFile:
    def test_nonexistent_file_yields_nothing(self, tmp_path: Path) -> None:
        result = list(extract_structs_from_file(tmp_path / "missing.c"))
        assert result == []

    def test_empty_file_yields_nothing(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.c"
        f.write_text("", encoding="utf-8")
        result = list(extract_structs_from_file(f))
        assert result == []

    @_SKIP_NO_TS
    def test_typedef_struct_extracted(self, tmp_path: Path) -> None:
        f = tmp_path / "types.c"
        f.write_text(
            "typedef struct { int x; int y; } Point;\n",
            encoding="utf-8",
        )
        result = list(extract_structs_from_file(f))
        assert len(result) == 1
        assert "Point" in result[0]
        assert "int x" in result[0]

    @_SKIP_NO_TS
    def test_standalone_struct_extracted(self, tmp_path: Path) -> None:
        f = tmp_path / "standalone.c"
        f.write_text(
            "struct Foo { int bar; };\n",
            encoding="utf-8",
        )
        result = list(extract_structs_from_file(f))
        assert len(result) == 1
        assert "Foo" in result[0]

    @_SKIP_NO_TS
    def test_no_struct_in_file(self, tmp_path: Path) -> None:
        f = tmp_path / "funcs.c"
        f.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        result = list(extract_structs_from_file(f))
        assert result == []


class TestExtractEnums:
    def _write(self, tmp_path: Path, content: str) -> Path:
        f = tmp_path / "types.c"
        f.write_text(content, encoding="utf-8")
        return f

    def test_standalone_enum(self, tmp_path: Path) -> None:
        f = self._write(tmp_path, "enum Color { RED, GREEN, BLUE };\nint x;\n")
        out = list(extract_enums_from_file(f))
        assert out == ["enum Color { RED, GREEN, BLUE };"]

    def test_typedef_enum(self, tmp_path: Path) -> None:
        f = self._write(tmp_path, "typedef enum { UP, DOWN } Direction;\n")
        out = list(extract_enums_from_file(f))
        assert out == ["typedef enum { UP, DOWN } Direction;"]

    def test_named_typedef_enum(self, tmp_path: Path) -> None:
        f = self._write(tmp_path, "typedef enum Dir { UP, DOWN } Direction;\n")
        out = list(extract_enums_from_file(f))
        assert out == ["typedef enum Dir { UP, DOWN } Direction;"]

    def test_enum_with_values_and_structs_ignored(self, tmp_path: Path) -> None:
        f = self._write(
            tmp_path,
            "typedef struct { int a; } S;\nenum Bits { A = 1, B = 2 };\n",
        )
        out = list(extract_enums_from_file(f))
        assert out == ["enum Bits { A = 1, B = 2 };"]

    def test_enum_forward_declaration_skipped(self, tmp_path: Path) -> None:
        """enum Color; (no body) is a forward decl, not a definition."""
        f = self._write(tmp_path, "enum Color;\nenum Color { RED };\n")
        out = list(extract_enums_from_file(f))
        assert out == ["enum Color { RED };"]

    def test_no_enums_yields_nothing(self, tmp_path: Path) -> None:
        f = self._write(tmp_path, "int main(void) { return 0; }\n")
        assert list(extract_enums_from_file(f)) == []


class TestExtractTypeDefinitions:
    """extract_type_definitions captures every typedef, including plain ones
    with no struct body — the behavior that distinguishes it from
    extract_structs_from_file."""

    def _write(self, tmp_path: Path, content: str) -> Path:
        f = tmp_path / "types.c"
        f.write_text(content, encoding="utf-8")
        return f

    @_SKIP_NO_TS
    def test_standalone_typedef_captured(self, tmp_path: Path) -> None:
        f = self._write(tmp_path, "typedef unsigned int uint32_t;\n")
        out = list(extract_type_definitions(f))
        assert len(out) == 1
        assert "uint32_t" in out[0]

    @_SKIP_NO_TS
    def test_struct_typedef_captured(self, tmp_path: Path) -> None:
        f = self._write(tmp_path, "typedef struct { int x; } Point;\n")
        out = list(extract_type_definitions(f))
        assert len(out) == 1
        assert "Point" in out[0]
        assert "int x" in out[0]

    @_SKIP_NO_TS
    def test_non_type_code_ignored(self, tmp_path: Path) -> None:
        src = "int counter;\nint add(int a, int b) { return a + b; }\n"
        f = self._write(tmp_path, src)
        assert list(extract_type_definitions(f)) == []

    def test_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        assert list(extract_type_definitions(tmp_path / "missing.c")) == []
