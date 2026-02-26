"""Tests for rebrew.matcher.mutator — mutation strategies for GA matching."""

import random

import pytest

from rebrew.matcher.mutator import (
    _find_matching_brace,
    _split_preamble_body,
    _sub_once,
    compute_population_diversity,
    crossover,
    mut_add_cast,
    mut_add_redundant_parens,
    mut_add_register_keyword,
    mut_bitand_to_if_false,
    mut_change_array_index_order,
    mut_change_return_type,
    mut_combine_ptr_arith,
    mut_commute_simple_add,
    mut_commute_simple_mul,
    mut_comparison_boundary,
    mut_duplicate_loop_body,
    mut_early_return_to_accum,
    mut_flip_eq_zero,
    mut_flip_lt_ge,
    mut_fold_constant_add,
    mut_goto_to_return,
    mut_if_false_to_bitand,
    mut_insert_noop_block,
    mut_int_to_pointer_param,
    mut_introduce_local_alias,
    mut_introduce_temp_for_call,
    mut_merge_cmp_chain,
    mut_merge_declaration_init,
    mut_pointer_to_int_param,
    mut_reassociate_add,
    mut_remove_cast,
    mut_remove_register_keyword,
    mut_remove_temp_var,
    mut_reorder_declarations,
    mut_reorder_elseif,
    mut_return_to_goto,
    mut_split_cmp_chain,
    mut_split_declaration_init,
    mut_split_ptr_arith,
    mut_struct_vs_ptr_access,
    mut_swap_adjacent_declarations,
    mut_swap_and_operands,
    mut_swap_eq_operands,
    mut_swap_if_else,
    mut_swap_ne_operands,
    mut_swap_or_operands,
    mut_toggle_bool_not,
    mut_toggle_calling_convention,
    mut_toggle_char_signedness,
    mut_toggle_signedness,
    mut_toggle_volatile,
    mut_unfold_constant_add,
    quick_validate,
)

try:
    from rebrew.matcher.mutator import mut_accum_to_early_return
except ImportError:
    mut_accum_to_early_return = None


RNG = random.Random(42)

SAMPLE_SOURCE = """\
#include <windows.h>

extern int g_value;

int __cdecl my_func(int a, int b) {
    int result = 0;
    int i;
    for (i = 0; i < a; i++) {
        result = result + b;
    }
    if (result == 0) {
        return 0;
    }
    return result;
}
"""


# -------------------------------------------------------------------------
# Utility functions
# -------------------------------------------------------------------------


class TestSplitPreambleBody:
    def test_splits_correctly(self) -> None:
        pre, body = _split_preamble_body(SAMPLE_SOURCE)
        assert "#include" in pre
        assert "extern" in pre
        assert "my_func" in body

    def test_empty_source(self) -> None:
        pre, body = _split_preamble_body("")
        assert pre == ""
        assert body == ""


class TestQuickValidate:
    def test_balanced(self) -> None:
        assert quick_validate("int f() { return 0; }") is True

    def test_unbalanced_brace(self) -> None:
        assert quick_validate("int f() { return 0; ") is False

    def test_unbalanced_paren(self) -> None:
        assert quick_validate("int f( { return 0; }") is False

    def test_switch_case_not_duplicate_label(self) -> None:
        """switch/case labels should not be treated as goto labels."""
        code = """\
int f(int x) {
    switch (x) {
        case 0: return 1;
        case 1: return 2;
        default: return 0;
    }
}
"""
        assert quick_validate(code) is True

    def test_duplicate_goto_label_rejected(self) -> None:
        code = """\
int f(int x) {
    goto done;
done:
    x = 1;
done:
    return x;
}
"""
        assert quick_validate(code) is False


class TestPopulationDiversity:
    def test_empty(self) -> None:
        assert compute_population_diversity([]) == 0.0

    def test_single(self) -> None:
        assert compute_population_diversity(["a"]) == 0.0

    def test_all_same(self) -> None:
        assert compute_population_diversity(["a", "a", "a"]) == pytest.approx(1 / 3)

    def test_all_different(self) -> None:
        assert compute_population_diversity(["a", "b", "c"]) == pytest.approx(1.0)


class TestSubOnce:
    def test_match_found(self) -> None:
        result = _sub_once(r"\d+", "X", "foo 123 bar", RNG)
        assert result == "foo X bar"

    def test_no_match(self) -> None:
        result = _sub_once(r"\d+", "X", "no numbers here", RNG)
        assert result is None


class TestCrossover:
    def test_basic(self) -> None:
        p1 = "int f(int a) {\n  a = 1;\n  return a;\n}"
        p2 = "int f(int a) {\n  a = 2;\n  return a;\n}"
        child = crossover(p1, p2, RNG)
        assert "int" in child
        assert "return" in child

    def test_empty_parent(self) -> None:
        result = crossover("", "int f() { return 1; }", RNG)
        assert result == ""

    def test_single_line_body_returns_parent(self) -> None:
        """Crossover with single-line body should not crash (regression test)."""
        p1 = "int f() { return 0; }"
        p2 = "int f() { return 1; }"
        result = crossover(p1, p2, RNG)
        # Should return parent1 since body is only 1 line
        assert result == p1


class TestFindMatchingBrace:
    def test_simple(self) -> None:
        s = "{ foo { bar } baz }"
        # Returns position AFTER the closing brace
        result = _find_matching_brace(s, 0)
        assert result == len(s)

    def test_nested(self) -> None:
        s = "{ { } }"
        result = _find_matching_brace(s, 0)
        assert result == 7

    def test_no_match(self) -> None:
        assert _find_matching_brace("{ foo", 0) is None

    def test_not_a_brace(self) -> None:
        assert _find_matching_brace("abc", 0) is None


# -------------------------------------------------------------------------
# Mutation tests — each tests for expected transformation or None
# -------------------------------------------------------------------------


class TestCommuteMutations:
    def test_commute_add(self) -> None:
        result = mut_commute_simple_add("x = a + b;", RNG)
        assert result is not None
        assert "b + a" in result

    def test_commute_mul(self) -> None:
        result = mut_commute_simple_mul("x = a * b;", RNG)
        assert result is not None
        assert "b * a" in result

    def test_no_match_add(self) -> None:
        assert mut_commute_simple_add("x = 1 + 2;", RNG) is None

    def test_no_match_mul(self) -> None:
        assert mut_commute_simple_mul("x = 1 * 2;", RNG) is None


class TestFlipMutations:
    def test_flip_eq_zero(self) -> None:
        result = mut_flip_eq_zero("if (x == 0)", RNG)
        assert result is not None
        assert "!x" in result

    def test_flip_ne_zero(self) -> None:
        result = mut_flip_eq_zero("if (x != 0)", RNG)
        assert result is not None
        assert "!!x" in result

    def test_flip_lt_ge(self) -> None:
        result = mut_flip_lt_ge("if (x < y)", RNG)
        assert result is not None
        assert ">=" in result

    def test_no_match(self) -> None:
        assert mut_flip_eq_zero("nothing to flip", RNG) is None


class TestParenAndReassociate:
    def test_add_parens(self) -> None:
        result = mut_add_redundant_parens("x = a + b;", RNG)
        assert result is not None
        assert "(" in result

    def test_reassociate(self) -> None:
        result = mut_reassociate_add("x = (a + b) + c;", RNG)
        assert result is not None
        assert "(b + c)" in result


class TestNoopBlock:
    def test_insert(self) -> None:
        src = "int f() {\n    int x = 0;\n    return x;\n}"
        result = mut_insert_noop_block(src, RNG)
        assert result is not None
        assert "if" in result or "0" in result


class TestBoolToggle:
    def test_toggle(self) -> None:
        result = mut_toggle_bool_not("if (!!condition)", RNG)
        assert result is not None
        assert "condition" in result
        assert "!!" not in result  # double-not should be removed


class TestSwapOperands:
    def test_swap_eq(self) -> None:
        result = mut_swap_eq_operands("if (a == b)", RNG)
        assert result is not None
        assert "b == a" in result

    def test_swap_ne(self) -> None:
        result = mut_swap_ne_operands("if (a != b)", RNG)
        assert result is not None
        assert "b != a" in result


class TestSwapLogical:
    def test_swap_or(self) -> None:
        result = mut_swap_or_operands("x = a || b;", RNG)
        assert result is not None
        assert "||" in result
        assert result != "x = a || b;"  # should be swapped

    def test_swap_and(self) -> None:
        result = mut_swap_and_operands("x = a && b;", RNG)
        assert result is not None
        assert "&&" in result
        assert result != "x = a && b;"  # should be swapped

    def test_no_or(self) -> None:
        assert mut_swap_or_operands("no logical ops", RNG) is None

    def test_no_and(self) -> None:
        assert mut_swap_and_operands("no logical ops", RNG) is None


class TestReturnGoto:
    def test_return_to_goto(self) -> None:
        src = "int f() {\n  if (err) return 0;\n  return 1;\n}"
        result = mut_return_to_goto(src, RNG)
        assert result is not None
        assert "goto" in result

    def test_goto_to_return(self) -> None:
        src = "int f() {\n  goto ret_false;\nret_false:\n  return FALSE;\n}"
        result = mut_goto_to_return(src, RNG)
        assert result is not None
        assert "return" in result


class TestLocalAlias:
    def test_introduce(self) -> None:
        src = "int f(int param1) {\n  return param1 + param1;\n}"
        result = mut_introduce_local_alias(src, RNG)
        assert result is not None
        assert "param1" in result


class TestReorderDeclarations:
    def test_reorder(self) -> None:
        src = "int f() {\n  int a;\n  int b;\n  a = 1;\n  b = 2;\n  return a + b;\n}"
        result = mut_reorder_declarations(src, RNG)
        assert result is not None
        assert "int a" in result and "int b" in result


class TestSwapIfElse:
    def test_basic(self) -> None:
        src = "if (x > 0) {\n  a = 1;\n} else {\n  a = 2;\n}"
        result = mut_swap_if_else(src, RNG)
        assert result is not None
        assert "if" in result
        assert result != src  # should be different from original


class TestReorderElseIf:
    def test_basic(self) -> None:
        src = "if (a) {\n  x = 1;\n} else if (b) {\n  x = 2;\n} else {\n  x = 3;\n}"
        result = mut_reorder_elseif(src, RNG)
        assert result is not None
        assert "if" in result


class TestCastMutations:
    def test_add_cast(self) -> None:
        result = mut_add_cast("if (result)", RNG)
        assert result is not None
        assert "int" in result or "BOOL" in result

    def test_remove_cast(self) -> None:
        result = mut_remove_cast("x = (int)y;", RNG)
        assert result is not None
        assert "(int)" not in result
        assert "y" in result


class TestVolatileRegister:
    def test_toggle_volatile(self) -> None:
        result = mut_toggle_volatile("int f() {\n    int x = 0;\n    return x;\n}", RNG)
        assert result is not None
        assert "volatile" in result

    def test_add_register(self) -> None:
        result = mut_add_register_keyword("int f() {\n    int x = 0;\n    return x;\n}", RNG)
        assert result is not None
        assert "register" in result

    def test_remove_register(self) -> None:
        result = mut_remove_register_keyword("    register int x = 0;", RNG)
        assert result is not None
        assert "register" not in result


class TestBitandIfFalse:
    def test_if_false_to_bitand(self) -> None:
        src = "if (!check()) var = FALSE;"
        result = mut_if_false_to_bitand(src, RNG)
        assert result is not None
        assert "&=" in result

    def test_bitand_to_if_false(self) -> None:
        src = "var &= check();"
        result = mut_bitand_to_if_false(src, RNG)
        assert result is not None
        assert "if" in result


class TestTempVar:
    def test_introduce_temp(self) -> None:
        src = "int f() {\n  result = FuncCall(a, b);\n  return result;\n}"
        result = mut_introduce_temp_for_call(src, RNG)
        assert result is not None
        assert "tmp" in result or "FuncCall" in result

    def test_remove_temp(self) -> None:
        src = "int f() {\n  tmp = expr;\n  var = tmp;\n}"
        result = mut_remove_temp_var(src, RNG)
        assert result is not None
        assert "var" in result


class TestSignedness:
    def test_toggle_remove(self) -> None:
        result = mut_toggle_signedness("unsigned int x;", RNG)
        assert result is not None
        assert "unsigned" not in result

    def test_no_match(self) -> None:
        assert mut_toggle_signedness("// nothing", RNG) is None


class TestDeclarationSplit:
    def test_swap_adjacent(self) -> None:
        src = "int f() {\n  int a;\n  int b;\n  return a + b;\n}"
        result = mut_swap_adjacent_declarations(src, RNG)
        if result is not None:
            # Declarations should be swapped — "int b" should come before "int a"
            assert result.index("int b") < result.index("int a")

    def test_split(self) -> None:
        src = "int f() {\n  int a = 5;\n  return a;\n}"
        result = mut_split_declaration_init(src, RNG)
        assert result is not None
        assert "int a" in result
        assert "a = 5" in result

    def test_merge(self) -> None:
        src = "int f() {\n  int a;\n  a = 5;\n  return a;\n}"
        result = mut_merge_declaration_init(src, RNG)
        if result is not None:
            assert "int a = 5" in result


class TestLoopMutations:
    def test_duplicate_body(self) -> None:
        src = "while (i < n) {\n  x = x + 1;\n}"
        result = mut_duplicate_loop_body(src, RNG)
        assert result is not None
        assert result.count("x + 1") >= 2  # body should be duplicated


class TestConstantFolding:
    def test_fold(self) -> None:
        src = "x = x + 1;\nx = x + 1;"
        result = mut_fold_constant_add(src, RNG)
        assert result is not None
        assert "2" in result

    def test_unfold(self) -> None:
        src = "x = x + 4;"
        result = mut_unfold_constant_add(src, RNG)
        assert result is not None
        assert "x =" in result


class TestArrayAndStruct:
    def test_array_index_order(self) -> None:
        src = "x = array[i];"
        result = mut_change_array_index_order(src, RNG)
        assert result is not None
        assert "i[array]" in result

    def test_struct_vs_ptr(self) -> None:
        src = "x = ptr->field;"
        result = mut_struct_vs_ptr_access(src, RNG)
        assert result is not None
        assert "(*ptr).field" in result


class TestCmpChain:
    def test_split(self) -> None:
        src = "if (foo && bar) {\n  x = 1;\n}"
        result = mut_split_cmp_chain(src, RNG)
        assert result is not None
        # Should produce nested ifs with balanced braces
        assert "if (foo)" in result
        assert "if (bar)" in result
        assert result.count("{") == result.count("}")

    def test_split_three_conditions(self) -> None:
        src = "if (a && b && c) {\n  x = 1;\n}"
        result = mut_split_cmp_chain(src, RNG)
        assert result is not None
        assert "if (a)" in result
        assert "if (b)" in result
        assert "if (c)" in result
        assert result.count("{") == result.count("}")

    def test_merge(self) -> None:
        src = "if (a == b) {}\nif (c == d) {}"
        result = mut_merge_cmp_chain(src, RNG)
        if result is not None:
            assert "&&" in result
            assert "a == b" in result
            assert "c == d" in result


class TestPtrArith:
    def test_combine(self) -> None:
        src = "p = p + 4;\np = p + 8;"
        result = mut_combine_ptr_arith(src, RNG)
        assert result is not None
        assert "12" in result

    def test_split(self) -> None:
        src = "p = p + 10;"
        result = mut_split_ptr_arith(src, RNG)
        assert result is not None
        assert "p =" in result


class TestReturnType:
    def test_change(self) -> None:
        src = "int my_func() {\n  return 0;\n}"
        result = mut_change_return_type(src, RNG)
        assert result is not None
        assert result != src  # type should change
        assert "my_func" in result  # function name preserved


class TestPointerParam:
    def test_pointer_to_int(self) -> None:
        src = "int f(char *ptr) {\n  return *ptr;\n}"
        result = mut_pointer_to_int_param(src, RNG)
        assert result is not None
        assert "*" not in result.split("{")[0] or "int" in result  # pointer removed or type changed

    def test_int_to_pointer(self) -> None:
        src = "int f(int param) {\n  return param;\n}"
        result = mut_int_to_pointer_param(src, RNG)
        assert result is not None
        assert "*" in result  # pointer added


class TestEarlyReturn:
    def test_to_accum(self) -> None:
        src = "int f() {\n  int ret = 1;\n  if (!check()) return 0;\n  return ret;\n}"
        result = mut_early_return_to_accum(src, RNG)
        assert result is not None
        assert "&=" in result

    @pytest.mark.skipif(mut_accum_to_early_return is None, reason="not exported")
    def test_to_early_return(self) -> None:
        src = "int f() {\n  ret &= check();\n  return ret;\n}"
        result = mut_accum_to_early_return(src, RNG)
        assert result is not None
        assert "if" in result


# -------------------------------------------------------------------------
# New mutation tests — calling convention, char signedness, comparison boundary
# -------------------------------------------------------------------------

try:
    from rebrew.matcher.mutator import (
        mut_comparison_boundary,
        mut_toggle_calling_convention,
        mut_toggle_char_signedness,
    )
except ImportError:
    mut_toggle_calling_convention = None
    mut_toggle_char_signedness = None
    mut_comparison_boundary = None


@pytest.mark.skipif(mut_toggle_calling_convention is None, reason="not exported")
class TestToggleCallingConvention:
    def test_cdecl_to_stdcall(self) -> None:
        src = "int __cdecl my_func(int a) {\n  return a;\n}"
        result = mut_toggle_calling_convention(src, RNG)
        assert result is not None
        assert "__stdcall" in result
        assert "__cdecl" not in result

    def test_stdcall_to_cdecl(self) -> None:
        src = "int __stdcall my_func(int a) {\n  return a;\n}"
        result = mut_toggle_calling_convention(src, RNG)
        assert result is not None
        assert "__cdecl" in result
        assert "__stdcall" not in result

    def test_no_convention_adds_one(self) -> None:
        src = "int my_func(int a) {\n  return a;\n}"
        result = mut_toggle_calling_convention(src, RNG)
        if result is not None:
            assert "__cdecl" in result or "__stdcall" in result

    def test_no_function_returns_none(self) -> None:
        assert mut_toggle_calling_convention("// just a comment", RNG) is None


@pytest.mark.skipif(mut_toggle_char_signedness is None, reason="not exported")
class TestToggleCharSignedness:
    def test_unsigned_to_signed(self) -> None:
        src = "unsigned char x = 0;"
        result = mut_toggle_char_signedness(src, RNG)
        assert result is not None
        assert "signed char" in result
        assert "unsigned" not in result

    def test_signed_to_bare(self) -> None:
        src = "signed char x = 0;"
        result = mut_toggle_char_signedness(src, RNG)
        assert result is not None
        assert "char x" in result
        assert "signed" not in result

    def test_bare_to_unsigned(self) -> None:
        src = "char x = 0;"
        result = mut_toggle_char_signedness(src, RNG)
        assert result is not None
        assert "unsigned char" in result

    def test_no_char_returns_none(self) -> None:
        assert mut_toggle_char_signedness("int x = 0;", RNG) is None


@pytest.mark.skipif(mut_comparison_boundary is None, reason="not exported")
class TestComparisonBoundary:
    def test_ge_one_to_gt_zero(self) -> None:
        result = mut_comparison_boundary("if (x >= 1)", RNG)
        assert result is not None
        assert "> 0" in result

    def test_gt_zero_to_ge_one(self) -> None:
        result = mut_comparison_boundary("if (x > 0)", RNG)
        assert result is not None
        assert ">= 1" in result

    def test_le_zero_to_lt_one(self) -> None:
        result = mut_comparison_boundary("if (x <= 0)", RNG)
        assert result is not None
        assert "< 1" in result

    def test_lt_one_to_le_zero(self) -> None:
        result = mut_comparison_boundary("if (x < 1)", RNG)
        assert result is not None
        assert "<= 0" in result

    def test_no_match_returns_none(self) -> None:
        assert mut_comparison_boundary("if (x == 0)", RNG) is None
