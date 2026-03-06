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
    mut_compound_assign_toggle,
    mut_demorgan,
    mut_duplicate_loop_body,
    mut_early_return_to_accum,
    mut_extract_else_body,
    mut_flatten_nested_if,
    mut_flip_eq_zero,
    mut_flip_lt_ge,
    mut_fold_constant_add,
    mut_for_to_while,
    mut_goto_to_return,
    mut_guard_clause,
    mut_hoist_return,
    mut_if_false_to_bitand,
    mut_if_to_ternary,
    mut_insert_noop_block,
    mut_int_to_pointer_param,
    mut_introduce_local_alias,
    mut_introduce_temp_for_call,
    mut_invert_loop_direction,
    mut_merge_cmp_chain,
    mut_merge_declaration_init,
    mut_negate_condition,
    mut_pointer_to_int_param,
    mut_postpre_increment,
    mut_reassociate_add,
    mut_remove_cast,
    mut_remove_register_keyword,
    mut_remove_temp_var,
    mut_reorder_declarations,
    mut_reorder_elseif,
    mut_return_to_goto,
    mut_sink_return,
    mut_split_cmp_chain,
    mut_split_declaration_init,
    mut_split_ptr_arith,
    mut_struct_vs_ptr_access,
    mut_swap_adjacent_declarations,
    mut_swap_adjacent_stmts,
    mut_swap_and_operands,
    mut_swap_eq_operands,
    mut_swap_if_else,
    mut_swap_ne_operands,
    mut_swap_or_operands,
    mut_ternary_to_if,
    mut_toggle_bool_not,
    mut_toggle_calling_convention,
    mut_toggle_char_signedness,
    mut_toggle_signedness,
    mut_toggle_volatile,
    mut_unfold_constant_add,
    mut_while_to_for,
    mut_xor_zero_toggle,
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


# -------------------------------------------------------------------------
# Code layout mutations
# -------------------------------------------------------------------------


class TestFlattenNestedIf:
    def test_basic(self) -> None:
        src = "if (a) {\n    if (b) {\n        x = 1;\n    }\n}"
        result = mut_flatten_nested_if(src, RNG)
        assert result is not None
        assert "&&" in result
        assert "if (a && b)" in result

    def test_trailing_code_prevents_flatten(self) -> None:
        src = "if (a) {\n    if (b) { x = 1; }\n    y = 2;\n}"
        # Cannot flatten because there's code after the inner if
        result = mut_flatten_nested_if(src, RNG)
        assert result is None or "&&" not in result

    def test_no_match(self) -> None:
        assert mut_flatten_nested_if("x = 1;", RNG) is None


class TestExtractElseBody:
    def test_basic(self) -> None:
        src = "if (cond) {\n    a = 1;\n} else {\n    b = 2;\n}"
        result = mut_extract_else_body(src, RNG)
        assert result is not None
        assert "!(cond)" in result or "!cond" in result
        assert "return 0;" in result

    def test_negated_cond_simplifies(self) -> None:
        src = "if (!flag) {\n    a = 1;\n} else {\n    b = 2;\n}"
        result = mut_extract_else_body(src, RNG)
        assert result is not None
        assert "flag" in result

    def test_no_else(self) -> None:
        # No else clause — should return None
        src = "if (x) { y = 1; }"
        assert mut_extract_else_body(src, RNG) is None

    def test_else_if_skipped(self) -> None:
        # else-if should not be extracted
        src = "if (a) { x = 1; } else if (b) { x = 2; }"
        assert mut_extract_else_body(src, RNG) is None


class TestForToWhile:
    def test_basic(self) -> None:
        src = "for (i = 0; i < n; i++) {\n    x = x + 1;\n}"
        result = mut_for_to_while(src, RNG)
        assert result is not None
        assert "while" in result
        assert "i = 0;" in result
        assert "i++;" in result
        assert "for" not in result

    def test_no_init(self) -> None:
        src = "for (; i < n; i++) {\n    x = x + 1;\n}"
        result = mut_for_to_while(src, RNG)
        assert result is not None
        assert "while (i < n)" in result

    def test_no_match(self) -> None:
        assert mut_for_to_while("while (1) { break; }", RNG) is None


class TestWhileToFor:
    def test_basic(self) -> None:
        src = "while (i < n) {\n    x = x + 1;\n}"
        result = mut_while_to_for(src, RNG)
        assert result is not None
        assert "for" in result
        assert "i < n" in result

    def test_no_match(self) -> None:
        assert mut_while_to_for("x = 1;", RNG) is None

    def test_dowhile_skipped(self) -> None:
        """do-while should not be converted to for."""
        src = "do {\n    x = x + 1;\n} while (x < 10);"
        result = mut_while_to_for(src, RNG)
        assert result is None


class TestIfToTernary:
    def test_basic(self) -> None:
        src = "if (flag)\n    x = 1;\nelse\n    x = 0;"
        result = mut_if_to_ternary(src, RNG)
        assert result is not None
        assert "?" in result
        assert ":" in result
        assert "x =" in result

    def test_no_match(self) -> None:
        # Different variables on each side — shouldn't match
        assert mut_if_to_ternary("if (flag) x = 1; else y = 0;", RNG) is None


class TestTernaryToIf:
    def test_basic(self) -> None:
        src = "x = (flag) ? 1 : 0;"
        result = mut_ternary_to_if(src, RNG)
        assert result is not None
        assert "if" in result
        assert "else" in result
        assert "x = 1;" in result
        assert "x = 0;" in result

    def test_no_match(self) -> None:
        assert mut_ternary_to_if("x = 42;", RNG) is None


class TestHoistReturn:
    def test_basic(self) -> None:
        src = "int f(int x) {\n    if (x) {\n        return 0;\n    }\n    return 1;\n}"
        result = mut_hoist_return(src, RNG)
        assert result is not None
        assert "goto end;" in result
        assert "end:" in result

    def test_existing_end_label_skips(self) -> None:
        src = "int f() {\n    goto end;\nend:\n    return 0;\n}"
        assert mut_hoist_return(src, RNG) is None

    def test_no_match(self) -> None:
        assert mut_hoist_return("x = 1;", RNG) is None


class TestSinkReturn:
    def test_basic(self) -> None:
        src = "int f() {\n    ret = 0;\n    goto end;\n    ret = 1;\nend:\n    return ret;\n}"
        result = mut_sink_return(src, RNG)
        assert result is not None
        assert "return 0;" in result

    def test_removes_end_label_when_unused(self) -> None:
        src = "int f() {\n    ret = 42;\n    goto end;\nend:\n    return ret;\n}"
        result = mut_sink_return(src, RNG)
        assert result is not None
        assert "return 42;" in result
        assert "end:" not in result  # label removed since no more gotos

    def test_no_match(self) -> None:
        assert mut_sink_return("x = 1;", RNG) is None


# -------------------------
# Structural codegen mutations (batch 2)
# -------------------------


class TestSwapAdjacentStmts:
    def test_basic(self) -> None:
        src = "void f() {\n    a = foo();\n    b = bar();\n}"
        result = mut_swap_adjacent_stmts(src, RNG)
        assert result is not None
        assert src.index("a = foo();") != result.index("a = foo();")
        assert "b = bar();" in result
        assert "a = foo();" in result

    def test_dependent_skipped(self) -> None:
        src = "void f() {\n    a = foo();\n    b = a + 1;\n}"
        # a is used in second stmt, so swap should be skipped
        assert mut_swap_adjacent_stmts(src, RNG) is None

    def test_no_match(self) -> None:
        assert mut_swap_adjacent_stmts("x = 1;", RNG) is None

    def test_compound_assignments(self) -> None:
        """Compound assignments like x += 1 should also be swappable."""
        src = "void f() {\n    x += 1;\n    y -= 2;\n}"
        result = mut_swap_adjacent_stmts(src, RNG)
        assert result is not None


class TestGuardClause:
    def test_basic(self) -> None:
        src = "int f() {\n    if (x) {\n        y = 1;\n        return 1;\n    }\n    return 0;\n}"
        result = mut_guard_clause(src, RNG)
        assert result is not None
        assert "!(x)" in result or "!x" in result
        assert "return 0;" in result
        assert "return 1;" in result

    def test_no_match(self) -> None:
        assert mut_guard_clause("x = 1;", RNG) is None


class TestInvertLoopDirection:
    def test_basic(self) -> None:
        src = "void f() { for (i = 0; i < n; i++) { body; } }"
        result = mut_invert_loop_direction(src, RNG)
        assert result is not None
        assert "i = n - 1" in result
        assert "i >= 0" in result
        assert "i--" in result

    def test_no_match(self) -> None:
        # while loop shouldn't match
        assert mut_invert_loop_direction("while (i < n) {}", RNG) is None


class TestCompoundAssignToggle:
    def test_shorten(self) -> None:
        src = "x = x + 5;"
        result = mut_compound_assign_toggle(src, RNG)
        assert result is not None
        assert "x += 5;" in result

    def test_expand(self) -> None:
        src = "x += 5;"
        result = mut_compound_assign_toggle(src, RNG)
        assert result is not None
        assert "x = x + 5;" in result

    def test_no_match(self) -> None:
        assert mut_compound_assign_toggle("x = 5;", RNG) is None

    def test_subtraction_multiterm_rejected(self) -> None:
        """x -= y - z != x = x - y - z — non-commutative operator with multi-term RHS."""
        assert mut_compound_assign_toggle("x -= y - z;", RNG) is None
        assert mut_compound_assign_toggle("x = x - y - z;", RNG) is None

    def test_simple_subtraction_allowed(self) -> None:
        """Single-term subtraction is always safe: x -= 5 == x = x - 5."""
        result = mut_compound_assign_toggle("x -= 5;", RNG)
        assert result is not None
        assert "x = x - 5;" in result


class TestDemorgan:
    def test_and_to_or(self) -> None:
        src = "if (!(a && b)) {}"
        result = mut_demorgan(src, RNG)
        assert result is not None
        assert "!a" in result
        assert "||" in result

    def test_or_to_and(self) -> None:
        src = "if (!(a || b)) {}"
        result = mut_demorgan(src, RNG)
        assert result is not None
        assert "!a" in result
        assert "&&" in result

    def test_no_match(self) -> None:
        assert mut_demorgan("if (a && b) {}", RNG) is None

    def test_chained_and_rejected(self) -> None:
        """Chained operators produce wrong precedence — must reject."""
        assert mut_demorgan("!(a && b && c)", RNG) is None

    def test_chained_or_rejected(self) -> None:
        assert mut_demorgan("!(x || y || z)", RNG) is None


class TestPostpreIncrement:
    def test_post_to_pre(self) -> None:
        src = "i++;"
        result = mut_postpre_increment(src, RNG)
        assert result is not None
        assert "++i" in result

    def test_pre_to_post(self) -> None:
        src = "++i;"
        result = mut_postpre_increment(src, RNG)
        assert result is not None
        assert "i++" in result

    def test_dec(self) -> None:
        src = "i--;"
        result = mut_postpre_increment(src, RNG)
        assert result is not None
        assert "--i" in result

    def test_no_match(self) -> None:
        assert mut_postpre_increment("x = 1;", RNG) is None


class TestXorZeroToggle:
    def test_to_xor(self) -> None:
        src = "x = 0;"
        result = mut_xor_zero_toggle(src, RNG)
        assert result is not None
        assert "x ^= x;" in result

    def test_to_zero(self) -> None:
        src = "x ^= x;"
        result = mut_xor_zero_toggle(src, RNG)
        assert result is not None
        assert "x = 0;" in result

    def test_no_match(self) -> None:
        assert mut_xor_zero_toggle("x = 5;", RNG) is None

    def test_struct_field_rejected(self) -> None:
        """p->len = 0 must NOT be transformed to len ^= len."""
        assert mut_xor_zero_toggle("p->len = 0;", RNG) is None

    def test_dot_field_rejected(self) -> None:
        assert mut_xor_zero_toggle("s.val = 0;", RNG) is None

    def test_for_loop_init_rejected(self) -> None:
        """CRITICAL: for (i = 0; ...) must NOT become for (i ^= i; ...)."""
        src = "for (i = 0; i < 10; i++) { x++; }"
        for seed in range(100):
            result = mut_xor_zero_toggle(src, random.Random(seed))
            assert result is None or "^=" not in result, (
                f"for-loop init corrupted with seed {seed}: {result!r}"
            )


class TestNegateCondition:
    def test_add_negation(self) -> None:
        src = "if (a > b) {}"
        result = mut_negate_condition(src, RNG)
        assert result is not None
        assert "!(a > b)" in result

    def test_remove_negation(self) -> None:
        src = "if (!(a > b)) {}"
        result = mut_negate_condition(src, RNG)
        assert result is not None
        assert "a > b" in result
        assert "!(" not in result

    def test_no_match(self) -> None:
        assert mut_negate_condition("x = 1;", RNG) is None

    def test_nested_parens(self) -> None:
        """Conditions with function calls must be handled correctly."""
        result = mut_negate_condition("if (foo(x)) {}", RNG)
        assert result is not None
        assert "!(foo(x))" in result

    def test_deep_nested_parens(self) -> None:
        result = mut_negate_condition("if (a && (b || c)) {}", RNG)
        assert result is not None
        assert "!(a && (b || c))" in result

    def test_not_equals_not_stripped(self) -> None:
        """x != 5 should NOT be treated as negation of '= 5'."""
        result = mut_negate_condition("if (x != 5) {}", RNG)
        assert result is not None
        assert "!(x != 5)" in result
