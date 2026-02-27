"""Tests for rebrew.signature_parser — function signature extraction via tree-sitter."""

from pathlib import Path

import pytest

from rebrew.signature_parser import extract_function_signatures


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


class TestExtractFunctionSignatures:
    def test_nonexistent_file_yields_nothing(self, tmp_path: Path) -> None:
        result = list(extract_function_signatures(tmp_path / "missing.c"))
        assert result == []

    def test_empty_file_yields_nothing(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.c"
        f.write_text("", encoding="utf-8")
        result = list(extract_function_signatures(f))
        assert result == []

    @_SKIP_NO_TS
    def test_simple_function_extracted(self, tmp_path: Path) -> None:
        f = tmp_path / "func.c"
        f.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        result = list(extract_function_signatures(f))
        assert len(result) == 1
        name, sig = result[0]
        assert name == "add"
        assert "int" in sig
        assert sig.endswith(";")

    @_SKIP_NO_TS
    def test_void_function(self, tmp_path: Path) -> None:
        f = tmp_path / "void.c"
        f.write_text("void noop(void) { }\n", encoding="utf-8")
        result = list(extract_function_signatures(f))
        assert len(result) == 1
        name, sig = result[0]
        assert name == "noop"
        assert "void" in sig

    @_SKIP_NO_TS
    def test_multiple_functions(self, tmp_path: Path) -> None:
        f = tmp_path / "multi.c"
        f.write_text(
            "int foo(void) { return 0; }\nint bar(int x) { return x; }\n",
            encoding="utf-8",
        )
        result = list(extract_function_signatures(f))
        assert len(result) == 2
        names = {r[0] for r in result}
        assert names == {"foo", "bar"}

    @_SKIP_NO_TS
    def test_no_functions_in_file(self, tmp_path: Path) -> None:
        f = tmp_path / "types.c"
        f.write_text("typedef struct { int x; } Point;\n", encoding="utf-8")
        result = list(extract_function_signatures(f))
        assert result == []
