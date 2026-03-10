import random
import re

from rebrew.matcher.mutator import (
    ALL_MUTATIONS,
    mut_add_volatile_intermediate,
    mut_commute_float_operands,
    mut_extract_args_to_temps,
    mut_extract_condition_to_var,
    mut_introduce_temp_for_call,
    mut_loop_condition_extraction,
    mut_loop_to_memcpy,
    mut_memcpy_to_loop,
    mut_merge_nested_ifs,
    mut_split_and_condition,
    mut_split_or_condition,
    mut_toggle_dllimport,
    mut_widen_local_type,
)

RNG = random.Random(42)


def _decl_before_first_stmt(result: str, decl_pattern: str) -> bool:
    """Check that a declaration matching *decl_pattern* appears inside the
    function body before the first non-declaration statement.

    This validates C89 compliance: all declarations must precede statements.
    """
    # Find function body opening brace
    brace_idx = result.find("{")
    if brace_idx == -1:
        return False
    body = result[brace_idx + 1 :]
    # The hoisted decl should be near the top of the body
    m = re.search(decl_pattern, body)
    if m is None:
        return False
    # Everything before the decl should be whitespace or other declarations
    before = body[: m.start()].strip()
    # Allow empty or other declarations before it
    return before == "" or all(
        line.strip() == "" or line.strip().startswith(("int ", "BOOL ", "volatile ", "char "))
        for line in before.split("\n")
    )


class TestSplitAndCondition:
    def test_basic(self) -> None:
        src = "if (a && b) {\n    x = 1;\n}"
        res = mut_split_and_condition(src, RNG)
        assert res is not None
        assert "if (a) {\n        if (b) {\n    x = 1;\n}" in res

    def test_no_match(self) -> None:
        src = "if (a || b) {\n    x = 1;\n}"
        assert mut_split_and_condition(src, RNG) is None


class TestSplitOrCondition:
    def test_basic(self) -> None:
        src = "if (a || b) {\n    x = 1;\n}"
        res = mut_split_or_condition(src, RNG)
        assert res is not None
        assert "if (a) {\n    x = 1;\n}\n    else if (b) {\n    x = 1;\n}" in res

    def test_no_match(self) -> None:
        src = "if (a && b) {\n    x = 1;\n}"
        assert mut_split_or_condition(src, RNG) is None


class TestMergeNestedIfs:
    def test_basic(self) -> None:
        src = "if (a) {\n    if (b) {\n        x = 1;\n    }\n}"
        res = mut_merge_nested_ifs(src, RNG)
        assert res is not None
        assert "if ((a) && (b))" in res


class TestExtractConditionToVar:
    def test_basic(self) -> None:
        src = "int f(int a, int b) {\n    if (a == b) {\n        x = 1;\n    }\n}"
        res = mut_extract_condition_to_var(src, RNG)
        assert res is not None
        assert "int _cond_" in res
        assert " = (a == b);" in res

    def test_c89_decl_hoisted(self) -> None:
        """Declaration must be at function body top, not inline before the if."""
        src = "int f(int a, int b) {\n    x = 0;\n    if (a == b) {\n        x = 1;\n    }\n}"
        res = mut_extract_condition_to_var(src, RNG)
        assert res is not None
        assert _decl_before_first_stmt(res, r"int _cond_\d+;")

    def test_c89_in_switch_body(self) -> None:
        """When the if is inside a switch case, decl must still be at function body top."""
        src = (
            "int f(int msg) {\n"
            "    switch (msg) {\n"
            "    case 1:\n"
            "        if (msg == 1) {\n"
            "            x = 1;\n"
            "        }\n"
            "        break;\n"
            "    }\n"
            "}"
        )
        res = mut_extract_condition_to_var(src, RNG)
        if res is not None:
            # The declaration should be hoisted to the function body, not inside switch
            assert _decl_before_first_stmt(res, r"int _cond_\d+;")


class TestLoopConditionExtraction:
    def test_basic(self) -> None:
        src = "while (a < b) {\n    x = 1;\n}"
        res = mut_loop_condition_extraction(src, RNG)
        assert res is not None
        assert "while (1) {" in res
        assert "if (!(a < b)) break;" in res


# -------------------------------------------------------------------------
# C89 compliance: declarations hoisted to function body top
# -------------------------------------------------------------------------


class TestC89ExtractArgsToTemps:
    def test_decl_hoisted(self) -> None:
        """int _tmp_X; must appear at function body top, not before the call."""
        src = "int f(int a, int b) {\n    x = 0;\n    foo(a + b);\n}"
        res = mut_extract_args_to_temps(src, RNG)
        assert res is not None
        assert "int _tmp_" in res
        assert _decl_before_first_stmt(res, r"int _tmp_\d+;")
        # The assignment should still be inline (before the call)
        assert re.search(r"_tmp_\d+ = a \+ b;", res)

    def test_no_match_on_literal(self) -> None:
        src = "int f() {\n    foo(42);\n}"
        assert mut_extract_args_to_temps(src, RNG) is None


class TestC89IntroduceTempForCall:
    def test_decl_hoisted(self) -> None:
        """BOOL tmp; must appear at function body top."""
        src = "int f() {\n    x = 0;\n    result = FuncA(a, b);\n    return result;\n}"
        res = mut_introduce_temp_for_call(src, RNG)
        if res is not None:
            if "BOOL tmp;" in res:
                assert _decl_before_first_stmt(res, r"BOOL tmp;")
            # The assignment should be inline
            assert "tmp = FuncA(a, b);" in res

    def test_existing_tmp_no_double_decl(self) -> None:
        """If 'tmp' already exists, no new declaration should be added."""
        src = "int f() {\n    int tmp;\n    result = FuncA(a, b);\n    return result;\n}"
        res = mut_introduce_temp_for_call(src, RNG)
        if res is not None:
            # Should NOT have a second declaration of tmp
            assert res.count("BOOL tmp;") == 0


class TestC89VolatileIntermediate:
    def test_decl_hoisted(self) -> None:
        """volatile int _t_N; must appear at function body top."""
        src = "int f(int a, int b) {\n    int x;\n    x = a + b;\n    return x;\n}"
        res = mut_add_volatile_intermediate(src, RNG)
        assert res is not None
        assert re.search(r"volatile int _t_\d+;", res)
        assert _decl_before_first_stmt(res, r"volatile int _t_\d+;")
        # The assignment should still be inline
        assert re.search(r"_t_\d+ = a \+ b;", res)


# -------------------------------------------------------------------------
# New mutators (2026-03 GA improvements batch)
# -------------------------------------------------------------------------


class TestWidenLocalType:
    def test_short_to_int(self) -> None:
        src = "void f() {\n    short x = 0;\n    x = 1;\n}"
        res = mut_widen_local_type(src, RNG)
        assert res is not None
        assert "int x = 0;" in res

    def test_byte_to_dword(self) -> None:
        src = "void f() {\n    BYTE val = 0;\n}"
        res = mut_widen_local_type(src, RNG)
        assert res is not None
        assert "DWORD val = 0;" in res

    def test_no_match(self) -> None:
        src = "void f() {\n    long x = 0;\n}"
        assert mut_widen_local_type(src, RNG) is None


class TestToggleDllimport:
    def test_remove_dllimport(self) -> None:
        src = "extern __declspec(dllimport) int GetFoo(int a);\nvoid f() {\n    GetFoo(1);\n}"
        res = mut_toggle_dllimport(src, RNG)
        assert res is not None
        assert "__declspec(dllimport)" not in res
        assert "extern" in res

    def test_add_dllimport(self) -> None:
        src = "extern int GetFoo(int a);\nvoid f() {\n    GetFoo(1);\n}"
        res = mut_toggle_dllimport(src, RNG)
        assert res is not None
        assert "__declspec(dllimport)" in res

    def test_no_match(self) -> None:
        src = "void f() {\n    int x = 1;\n}"
        assert mut_toggle_dllimport(src, RNG) is None


class TestMemcpyToLoop:
    def test_basic(self) -> None:
        src = "void f(char *dst, char *src) {\n    memcpy(dst, src, 16);\n}"
        res = mut_memcpy_to_loop(src, RNG)
        assert res is not None
        assert "memcpy" not in res
        assert "for (" in res
        assert "((char*)" in res

    def test_c89_decl_hoisted(self) -> None:
        """Loop counter declared at function body top."""
        src = "void f(char *dst, char *src) {\n    int x = 0;\n    memcpy(dst, src, 8);\n}"
        res = mut_memcpy_to_loop(src, RNG)
        assert res is not None
        assert re.search(r"int _ci_\d+;", res)
        assert _decl_before_first_stmt(res, r"int _ci_\d+;")

    def test_no_match(self) -> None:
        src = "void f() {\n    int x = 1;\n}"
        assert mut_memcpy_to_loop(src, RNG) is None


class TestLoopToMemcpy:
    def test_basic(self) -> None:
        src = "void f() {\n    for (_ci_0 = 0; _ci_0 < 16; _ci_0++) ((char*)dst)[_ci_0] = ((char*)src)[_ci_0];\n}"
        res = mut_loop_to_memcpy(src, RNG)
        assert res is not None
        assert "memcpy(dst, src, 16);" in res

    def test_no_match(self) -> None:
        src = "void f() {\n    for (i = 0; i < 10; i++) x[i] = 0;\n}"
        assert mut_loop_to_memcpy(src, RNG) is None


class TestCommuteFloatOperands:
    def test_swap_float_mul(self) -> None:
        src = "void f() {\n    float result = flt_a * flt_b;\n}"
        res = mut_commute_float_operands(src, RNG)
        assert res is not None
        assert "flt_b * flt_a" in res

    def test_no_match_integer(self) -> None:
        """Should not swap integer operations without float hints."""
        src = "void f() {\n    int x = a * b;\n}"
        assert mut_commute_float_operands(src, RNG) is None


class TestAllMutationsNoDuplicates:
    def test_no_duplicate_entries(self) -> None:
        """ALL_MUTATIONS should not have duplicate entries."""
        names = [m.__name__ for m in ALL_MUTATIONS]
        assert len(names) == len(set(names)), (
            f"Duplicates: {[n for n in names if names.count(n) > 1]}"
        )

    def test_new_mutators_registered(self) -> None:
        """All 5 new mutators should be in ALL_MUTATIONS."""
        names = {m.__name__ for m in ALL_MUTATIONS}
        expected = {
            "mut_widen_local_type",
            "mut_toggle_dllimport",
            "mut_memcpy_to_loop",
            "mut_loop_to_memcpy",
            "mut_commute_float_operands",
        }
        assert expected.issubset(names), f"Missing: {expected - names}"
