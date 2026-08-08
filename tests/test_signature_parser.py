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
        assert sig.endswith(")")  # no trailing semicolon (Ghidra CParser rejects them)

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


class TestNormalizeSignature:
    def test_strips_declspec(self) -> None:
        from rebrew.signature_parser import _normalize_signature

        assert _normalize_signature("__declspec(dllexport) int f(void);") == "int f(void)"

    def test_strips_calling_convention_and_const(self) -> None:
        from rebrew.signature_parser import _normalize_signature

        assert _normalize_signature("__stdcall const int g(int a);") == "int g(int a)"

    def test_function_pointer_param_to_void(self) -> None:
        from rebrew.signature_parser import _normalize_signature

        out = _normalize_signature("int h(void (*cb)(int));")
        assert "void *" in out
        assert "cb" in out

    def test_pointer_space_normalized(self) -> None:
        from rebrew.signature_parser import _normalize_signature

        # "char*s" (no space) gets a space inserted for CParser compatibility.
        assert _normalize_signature("char*s;") == "char *s"
        assert _normalize_signature("int *f(int *p);") == "int *f(int *p)"


class TestTsUnavailable:
    def test_parser_import_failure_returns_empty(self, tmp_path: Path, monkeypatch: object) -> None:
        import rebrew.c_parser
        import rebrew.signature_parser as sp

        def boom() -> object:
            raise ImportError("no tree-sitter")

        monkeypatch.setattr(rebrew.c_parser, "_get_parser", boom)
        f = tmp_path / "f.c"
        f.write_text("int f(void) { return 1; }", encoding="utf-8")
        assert list(sp.extract_function_signatures(f)) == []

    def test_pointer_declarator_signature(self, tmp_path: Path) -> None:
        from rebrew.signature_parser import extract_function_signatures

        f = tmp_path / "f.c"
        f.write_text("int *get_ptr(int a) { return 0; }\n", encoding="utf-8")
        result = dict(extract_function_signatures(f))
        assert "get_ptr" in result
        assert "int *get_ptr(int a)" in result["get_ptr"]


class TestSignatureParserBranches:
    def test_pointer_return_function(self, tmp_path: Path) -> None:
        from rebrew.signature_parser import extract_function_signatures

        f = tmp_path / "p.c"
        f.write_text("char *strdup2(const char *s) { return (char *)s; }\n", encoding="utf-8")
        results = list(extract_function_signatures(f))
        assert any(name == "strdup2" for name, _ in results)

    def test_no_body_function_definition(self, tmp_path: Path) -> None:
        from rebrew.signature_parser import extract_function_signatures

        f = tmp_path / "d.c"
        f.write_text("int decl_only(int x);\n", encoding="utf-8")
        # A bare declaration is not a function_definition → nothing extracted.
        assert list(extract_function_signatures(f)) == []
