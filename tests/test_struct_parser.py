"""Tests for rebrew.struct_parser — struct/typedef extraction via tree-sitter."""

from pathlib import Path

import pytest

from rebrew.struct_parser import extract_structs_from_file


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
