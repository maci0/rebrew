"""Tests for c_parser.py — tree-sitter C parsing helpers."""

import pytest

from rebrew.c_parser import (
    extract_function_name_and_proto,
    extract_function_name_from_line,
    find_c_function_definitions,
    find_extern_function_names,
    find_extern_variables,
    type_from_declaration,
)


class TestExtractFunctionNameAndProto:
    def test_simple_function(self) -> None:
        name, proto = extract_function_name_and_proto("int foo(int a) { return a; }")
        assert name == "foo"
        assert "int foo(int a)" in proto

    def test_void_function(self) -> None:
        name, proto = extract_function_name_and_proto("void bar(void) {}")
        assert name == "bar"
        assert proto == "void bar(void)"

    def test_pointer_return(self) -> None:
        name, proto = extract_function_name_and_proto("int *get_ptr(void) { return 0; }")
        assert name == "get_ptr"
        assert "int *" in proto

    def test_stdcall_kept_in_proto(self) -> None:
        # The docstring says the prototype includes the calling convention.
        name, proto = extract_function_name_and_proto("int __stdcall f(int x) { return x; }")
        assert name == "f"
        assert "__stdcall" in proto

    def test_no_function_returns_none(self) -> None:
        assert extract_function_name_and_proto("int g_var = 3;") is None


class TestExtractFunctionNameFromLine:
    @pytest.mark.parametrize("line", ["(\ud800", "(\udd00"])
    def test_unencodable_line_returns_none(self, line: str) -> None:
        assert extract_function_name_from_line(line) is None

    def test_declaration_line(self) -> None:
        name, proto = extract_function_name_from_line("int foo(int a)")
        assert name == "foo"
        assert "int foo(int a)" in proto

    def test_definition_line(self) -> None:
        name, _proto = extract_function_name_from_line("int foo(int a) {")
        assert name == "foo"


class TestFindFunctionDefinitions:
    def test_multiple_functions(self) -> None:
        src = "int a(void) { return 1; }\n\nint b(void) { return 2; }\n"
        defs = find_c_function_definitions(src)
        names = [n for n, _line in defs]
        assert "a" in names
        assert "b" in names

    def test_no_definitions(self) -> None:
        assert find_c_function_definitions("int x = 0;\n") == []

    def test_macro_qualified_kr_definition(self) -> None:
        """An unknown macro between type and name is not the name (zlib ZEXPORT)."""
        src = (
            "int ZEXPORT deflate(strm, flush)\n    z_streamp strm;\n    int flush;\n{ return 0; }\n"
        )
        assert find_c_function_definitions(src) == [("deflate", 1)]


class TestFindExternFunctionNames:
    def test_simple_extern(self) -> None:
        names = find_extern_function_names("extern int printf(const char *fmt, ...);")
        assert "printf" in names

    def test_multiple_externs(self) -> None:
        src = "extern void foo(void);\nextern int bar(int x);\n"
        names = find_extern_function_names(src)
        assert "foo" in names
        assert "bar" in names

    def test_no_externs(self) -> None:
        assert find_extern_function_names("int local(void) { return 0; }") == []


class TestFindExternVariables:
    def test_scalar_global(self) -> None:
        vars_ = find_extern_variables("extern int g_counter;")
        assert len(vars_) == 1
        assert vars_[0].name == "g_counter"

    def test_array_global(self) -> None:
        vars_ = find_extern_variables("extern char g_name[32];")
        assert len(vars_) == 1
        assert vars_[0].name == "g_name"

    def test_no_variables(self) -> None:
        assert find_extern_variables("int local(void) { return 0; }") == []


class TestDeclaratorEdgeCases:
    def test_function_pointer_declarator_name(self) -> None:
        from rebrew.c_parser import extract_function_name_from_line

        name, proto = extract_function_name_from_line("int (*handler)(int a);")
        assert name == "handler"
        assert proto == "int (*handler)(int a)"

    def test_pointer_return_function(self) -> None:
        from rebrew.c_parser import extract_function_name_from_line

        name, proto = extract_function_name_from_line("char *strdup(const char *s);")
        assert name == "strdup"

    def test_array_global_declaration(self) -> None:
        from rebrew.c_parser import find_extern_variables

        vars_found = find_extern_variables("extern unsigned char g_buf[256];")
        assert vars_found and vars_found[0].name == "g_buf"

    def test_init_declarator_global(self) -> None:
        from rebrew.c_parser import find_extern_variables

        vars_found = find_extern_variables("extern int g_count = 0;")
        assert vars_found and vars_found[0].name == "g_count"

    def test_multiple_extern_variables_one_line(self) -> None:
        from rebrew.c_parser import find_extern_variables

        vars_found = find_extern_variables("extern int g_a, g_b;")
        names = {v.name for v in vars_found}
        assert "g_a" in names
        assert "g_b" in names

    def test_cc_prefixed_function(self) -> None:
        from rebrew.c_parser import extract_function_name_from_line

        name, _ = extract_function_name_from_line("void __cdecl my_func(int x)")
        assert name == "my_func"

    def test_parser_missing_raises_clear_error(self, monkeypatch) -> None:
        import builtins
        import threading

        from rebrew.c_parser import _get_parser, _language

        real_import = builtins.__import__

        def _fake_import(name, *a, **k):
            if name in ("tree_sitter_c", "tree_sitter"):
                raise ImportError("nope")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        monkeypatch.setattr("rebrew.c_parser._language", None)
        # Drop any thread-local parser so the language-init path is hit.
        monkeypatch.setattr("rebrew.c_parser._tls", threading.local())
        with pytest.raises(ImportError, match="tree-sitter and tree-sitter-c are required"):
            _get_parser()
        # Restore for other tests in the module.
        monkeypatch.setattr("rebrew.c_parser._language", _language)


class TestExternVariableDeclarators:
    def test_nested_array_dimensions(self) -> None:
        from rebrew.c_parser import find_extern_variables

        vars_found = find_extern_variables("extern int g_arr[10][5];")
        assert vars_found and vars_found[0].name == "g_arr"

    def test_array_of_pointers(self) -> None:
        from rebrew.c_parser import find_extern_variables

        vars_found = find_extern_variables("extern char *g_ptrs[4];")
        assert vars_found and vars_found[0].name == "g_ptrs"
        assert vars_found[0].type_str == "char *[4]"

    def test_function_pointer_not_treated_as_variable(self) -> None:
        from rebrew.c_parser import find_extern_variables

        # A function-pointer declaration is skipped (caller may want a prototype).
        assert find_extern_variables("extern int (*g_cb)(int);") == []

    def test_function_declaration_not_variable(self) -> None:
        from rebrew.c_parser import find_extern_variables

        assert find_extern_variables("extern int f(void);") == []


class TestPointerAndArrayTypes:
    @pytest.mark.parametrize(
        "declaration,expected_type,expected_suffix",
        [
            ("extern int * const *p;", "int **", ""),
            ("extern int * const * volatile *p;", "int ***", ""),
            ("extern int * const p[3];", "int *[3]", "[3]"),
            ("extern int * volatile * const p[3][5];", "int **[3][5]", "[3][5]"),
            ("int * const p[3] = {0};", "int *[3]", "[3]"),
        ],
    )
    def test_qualified_pointer_declarators(
        self, declaration: str, expected_type: str, expected_suffix: str
    ) -> None:
        variables = find_extern_variables(declaration, include_definitions=True)
        assert len(variables) == 1
        assert variables[0].name == "p"
        assert variables[0].type_str == expected_type
        assert variables[0].array_suffix == expected_suffix

    def test_pointer_depth_single(self) -> None:
        from rebrew.c_parser import find_extern_variables

        vars_found = find_extern_variables("extern int *g_p;")
        assert vars_found and vars_found[0].name == "g_p"
        assert vars_found[0].type_str == "int *"

    def test_double_pointer(self) -> None:
        from rebrew.c_parser import find_extern_variables

        vars_found = find_extern_variables("extern char **g_pp;")
        assert vars_found and vars_found[0].name == "g_pp"
        assert vars_found[0].type_str == "char **"

    def test_plain_array_suffix(self) -> None:
        from rebrew.c_parser import find_extern_variables

        vars_found = find_extern_variables("extern char g_s[16];")
        assert vars_found and vars_found[0].name == "g_s"
        assert "[16]" in vars_found[0].type_str


# ---------------------------------------------------------------------------
# MSVC declarator corpus — real tree-sitter parses of tricky declarations
# ---------------------------------------------------------------------------


class TestDeclaratorCorpus:
    """MSVC-era C declarator idioms must all resolve to the right function
    name (and a non-empty prototype).  Locks the walkers against tree-sitter
    or refactor regressions."""

    _CASES: list[tuple[str, str]] = [
        ("void __cdecl my_func(int x) { }", "my_func"),
        ("void __stdcall handler(unsigned char* p, int n) { }", "handler"),
        ("char *strdup_c(const char *s) { return 0; }", "strdup_c"),
        ("struct foo get_foo(void) { struct foo f; return f; }", "get_foo"),
        ("void (*get_handler(void))(int) { return 0; }", "get_handler"),
        ("char **split_path(const char *p, int *n) { return 0; }", "split_path"),
        (
            "static unsigned long crc32(const unsigned char *buf, size_t len) { return 0; }",
            "crc32",
        ),
        ("__forceinline int add(int a, int b) { return a + b; }", "add"),
        ("int (*table[10])(void); int use(void) { return 0; }", "use"),
        ("void *\nmy_alloc(\n    size_t size\n) { return 0; }", "my_alloc"),
        ("int apply(int (*fn)(int), int v) { return fn(v); }", "apply"),
        ("volatile unsigned char *read_reg(unsigned long addr) { return 0; }", "read_reg"),
        ("__declspec(naked) void stub(void) { }", "stub"),
        ("BOOL WINAPI set_handler(void) { return 0; }", "set_handler"),
        ("void (*(*get_trampoline(void))(int))(char) { return 0; }", "get_trampoline"),
        ("void fill(int buf[256], int n) { }", "fill"),
        ("unsigned long long rdtsc(void) { return 0; }", "rdtsc"),
        # A pure declaration is not a definition → None (and must not crash).
        ("int __cdecl (*cb)(void); int x;", None),
    ]

    @pytest.mark.parametrize("source,expected", _CASES)
    def test_corpus(self, source: str, expected: str | None) -> None:
        from rebrew.c_parser import extract_function_name_and_proto

        result = extract_function_name_and_proto(source)
        assert (result[0] if result else None) == expected
        if expected is not None:
            assert result is not None
            assert expected in result[1]  # proto carries the name


class TestCallingConventionDeclarators:
    """Borland 16-bit conventions: ``void far *pascal f(...)`` must extract
    ``f`` as the name — tree-sitter marks ``far``/``pascal`` (non-C89
    keywords) as ERROR nodes, which used to be picked up as the name."""

    @pytest.mark.parametrize(
        "proto,expected",
        [
            ("void far *pascal fcn_042e(int x, int y) { return 0; }", "fcn_042e"),
            ("void far * fcn_042e(int x, int y) { return 0; }", "fcn_042e"),
            ("int pascal fcn_042e(int x, int y) { return 0; }", "fcn_042e"),
            ("int __stdcall fcn_042e(int x, int y) { return 0; }", "fcn_042e"),
            ("int far *pascal fcn_042e(int x) { return 0; }", "fcn_042e"),
        ],
    )
    def test_convention_proto(self, proto: str, expected: str) -> None:
        result = extract_function_name_and_proto(proto)
        assert result is not None
        assert result[0] == expected
        assert expected in result[1]


class TestDefinitionsAndDllimport:
    """Definitions carry a global's real type; dllimport must never be reported."""

    def test_definitions_only_with_the_flag(self) -> None:
        from rebrew.c_parser import find_extern_variables

        src = "extern int g_decl;\nint g_def[4] = { 1, 2, 3, 4 };\n"
        assert [v.name for v in find_extern_variables(src)] == ["g_decl"]
        both = find_extern_variables(src, include_definitions=True)
        assert [v.name for v in both] == ["g_decl", "g_def"]
        assert next(v for v in both if v.name == "g_def").type_str == "int[4]"

    def test_function_locals_are_not_globals(self) -> None:
        from rebrew.c_parser import find_extern_variables

        src = "int f(void) {\n    int local = 3;\n    static int slocal = 4;\n    return local + slocal;\n}\n"
        assert find_extern_variables(src, include_definitions=True) == []

    def test_dllimport_variables_are_skipped(self) -> None:
        """`_strip_cc` deletes the declspec before tree-sitter sees it, so the
        in-tree check could never fire; `extern __declspec(dllimport) int g;`
        was reported despite the documented intent to skip it."""
        from rebrew.c_parser import find_extern_variables

        for src in (
            "__declspec(dllimport) int g_imp;\n",
            "extern __declspec(dllimport) int g_imp;\n",
            "__declspec(dllimport) int g_imp[4];\n",
        ):
            assert find_extern_variables(src) == [], src
            assert find_extern_variables(src, include_definitions=True) == [], src


class TestParsePreservesLegacyBytes:
    def test_cp1252_bytes_do_not_shift_string_spans(self) -> None:
        """Invalid-as-UTF-8 bytes must not be expanded to U+FFFD (3 bytes)
        before parsing — that shifted every later offset and made
        protected_spans miss the string literal after a CP1252 comment."""
        from rebrew.c_parser import protected_spans

        # 0xE9 is 'é' in cp1252; not a valid UTF-8 lead byte.
        raw = b'// Caf\xe9\nchar *s = "keep";\n'
        spans = protected_spans(raw)
        assert spans, "expected a protected string span"
        assert raw[spans[0][0] : spans[0][1]] == b'"keep"'

    def test_legacy_bytes_roundtrip_through_proto(self) -> None:
        from rebrew.c_parser import _node_text, _parse

        # Source with cp1252 byte decoded via surrogateescape
        src = b'char *s = "Caf\xe9";\n'.decode("utf-8", errors="surrogateescape")
        tree, src_bytes = _parse(src)

        def find_lit(n):
            if n.type == "string_literal":
                return n
            for c in n.children:
                res = find_lit(c)
                if res:
                    return res
            return None

        lit = find_lit(tree.root_node)
        assert lit is not None
        txt = _node_text(lit, src_bytes)
        assert txt == '"Caf\udce9"'
        # Must re-encode to the original raw bytes, not U+FFFD replacement
        assert txt.encode("utf-8", errors="surrogateescape") == b'"Caf\xe9"'


class TestTypeFromDeclaration:
    def test_simple_extern(self) -> None:
        assert type_from_declaration("extern int g_count;", "g_count") == "int"

    def test_array_suffix(self) -> None:
        assert type_from_declaration("char g_buf[64];", "g_buf") == "char[64]"

    def test_wrong_name_returns_none(self) -> None:
        assert type_from_declaration("int g_a;", "g_b") is None

    def test_empty_decl_returns_none(self) -> None:
        assert type_from_declaration("", "x") is None
