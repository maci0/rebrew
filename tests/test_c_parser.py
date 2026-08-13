"""Tests for c_parser.py — tree-sitter C parsing helpers."""

import pytest

from rebrew.c_parser import (
    extract_function_name_and_proto,
    extract_function_name_from_line,
    find_c_function_definitions,
    find_extern_function_names,
    find_extern_variables,
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
