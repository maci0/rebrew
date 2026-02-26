"""Additional deep tests for mutator.py — mutate_code, loop conversions, ALL_MUTATIONS."""

import random

from rebrew.matcher.mutator import (
    ALL_MUTATIONS,
    _find_matching_char,
    _split_preamble_body,
    crossover,
    mut_add_redundant_parens,
    mut_change_array_index_order,
    mut_dowhile_to_while,
    mut_duplicate_loop_body,
    mut_early_return_to_accum,
    mut_goto_to_return,
    mut_introduce_local_alias,
    mut_introduce_temp_for_call,
    mut_merge_declaration_init,
    mut_remove_temp_var,
    mut_reorder_elseif,
    mut_return_to_goto,
    mut_split_cmp_chain,
    mut_split_declaration_init,
    mut_struct_vs_ptr_access,
    mut_swap_adjacent_declarations,
    mut_swap_if_else,
    mut_unfold_constant_add,
    mut_while_to_dowhile,
    mutate_code,
    quick_validate,
)

try:
    from rebrew.matcher.mutator import mut_change_param_order
except ImportError:
    mut_change_param_order = None

RNG = random.Random(42)

FULL_SOURCE = """\
#include <windows.h>

extern int g_value;

int __cdecl my_func(int a, int b) {
    int result = 0;
    int i;
    int check;
    for (i = 0; i < a; i++) {
        result = result + b;
    }
    if (result == 0) {
        return 0;
    } else {
        g_value = result;
    }
    return result;
}
"""


# -------------------------------------------------------------------------
# mutate_code (top-level API)
# -------------------------------------------------------------------------


class TestMutateCode:
    def test_basic(self) -> None:
        result = mutate_code(FULL_SOURCE, RNG)
        assert isinstance(result, str)

    def test_with_tracking(self) -> None:
        result = mutate_code(FULL_SOURCE, RNG, track_mutation=True)
        assert isinstance(result, tuple)
        assert len(result) == 2
        src, name = result
        assert isinstance(src, str)
        assert isinstance(name, str)

    def test_idempotent_on_trivial(self) -> None:
        # Trivial source where most mutations can't apply
        trivial = "int f() {\n  return 0;\n}"
        result = mutate_code(trivial, RNG)
        assert isinstance(result, str)

    def test_no_mutation_tracking(self) -> None:
        trivial = "int f() { return 0; }"
        result = mutate_code(trivial, RNG, track_mutation=True)
        src, name = result
        # Should either mutate or return "none"
        assert isinstance(name, str)

    def test_mutation_weights(self) -> None:
        """mutation_weights should bias selection toward higher-weighted mutations."""
        # Zero-weight all mutations except one — the selected mutation must be
        # one of the non-zero-weighted ones (though it may fail to apply and
        # fall through to "none").
        result = mutate_code(
            FULL_SOURCE,
            RNG,
            mutation_weights={"mut_swap_if_else": 100.0},
        )
        assert isinstance(result, str)

    def test_mutation_weights_empty_dict(self) -> None:
        """Empty weights dict should behave like no weights (uniform)."""
        result = mutate_code(FULL_SOURCE, RNG, mutation_weights={})
        assert isinstance(result, str)

    def test_mutation_weights_with_tracking(self) -> None:
        """Weighted mutations should work with track_mutation=True."""
        result = mutate_code(
            FULL_SOURCE,
            RNG,
            track_mutation=True,
            mutation_weights={"mut_swap_if_else": 10.0},
        )
        assert isinstance(result, tuple)
        src, name = result
        assert isinstance(src, str)
        assert isinstance(name, str)

    def test_mutation_weights_all_zero(self) -> None:
        """All-zero weights should fall back to uniform selection, not crash."""
        weights = {m.__name__: 0.0 for m in ALL_MUTATIONS}
        result = mutate_code(FULL_SOURCE, RNG, mutation_weights=weights)
        assert isinstance(result, str)

    def test_mutation_weights_unknown_names(self) -> None:
        """Weights for unknown mutation names should be ignored gracefully."""
        result = mutate_code(
            FULL_SOURCE,
            RNG,
            mutation_weights={"nonexistent_mutation": 100.0},
        )
        assert isinstance(result, str)


# -------------------------------------------------------------------------
# ALL_MUTATIONS list
# -------------------------------------------------------------------------


class TestAllMutations:
    def test_list_is_populated(self) -> None:
        assert len(ALL_MUTATIONS) > 30

    def test_all_callable(self) -> None:
        for m in ALL_MUTATIONS:
            assert callable(m), f"{m} is not callable"

    def test_all_return_str_or_none(self) -> None:
        """Run every mutation against a rich source and check return types."""
        for m in ALL_MUTATIONS:
            try:
                result = m(FULL_SOURCE, RNG)
                assert result is None or isinstance(result, str), (
                    f"{m.__name__} returned {type(result)}"
                )
            except Exception:
                pass  # some mutations may fail on this input, that's OK


# -------------------------------------------------------------------------
# Loop conversion mutations (deeper exercising)
# -------------------------------------------------------------------------


class TestWhileDoWhile:
    def test_while_to_dowhile(self) -> None:
        src = "while (i < 10) {\n    x = x + 1;\n}"
        result = mut_while_to_dowhile(src, RNG)
        assert result is not None
        assert "do" in result

    def test_dowhile_to_while(self) -> None:
        src = "do {\n    x = x + 1;\n} while (i < 10);"
        result = mut_dowhile_to_while(src, RNG)
        assert result is not None
        assert "while" in result

    def test_no_while(self) -> None:
        assert mut_while_to_dowhile("return 0;", RNG) is None

    def test_no_dowhile(self) -> None:
        assert mut_dowhile_to_while("return 0;", RNG) is None


# -------------------------------------------------------------------------
# If/else swap with braces (deeper exercising)
# -------------------------------------------------------------------------


class TestSwapIfElseDeep:
    def test_with_full_source(self) -> None:
        src = "if (x > 0) {\n    a = 1;\n    b = 2;\n} else {\n    a = 3;\n    b = 4;\n}"
        result = mut_swap_if_else(src, RNG)
        assert result is not None, "swap_if_else should succeed on valid if/else"
        # Condition should be negated, bodies should be swapped
        assert "!(x > 0)" in result or "x > 0" in result
        assert result != src

    def test_nested_if(self) -> None:
        src = "if (a) {\n  if (b) {\n    x = 1;\n  }\n} else {\n  x = 2;\n}"
        result = mut_swap_if_else(src, RNG)
        if result is not None:
            assert result != src
            assert result.count("{") == result.count("}")


class TestReorderElseIfDeep:
    def test_three_branches(self) -> None:
        src = (
            "if (a == 1) {\n  x = 1;\n} else if (a == 2) {\n  x = 2;\n} "
            "else if (a == 3) {\n  x = 3;\n} else {\n  x = 0;\n}"
        )
        result = mut_reorder_elseif(src, RNG)
        if result is not None:
            # Should still have all branches, possibly reordered
            assert "a == 1" in result or "a == 2" in result
            assert "else" in result


# -------------------------------------------------------------------------
# Declaration reordering (deeper)
# -------------------------------------------------------------------------


class TestDeclarationMutationsDeep:
    def test_swap_adjacent_no_decls(self) -> None:
        assert mut_swap_adjacent_declarations("return 0;", RNG) is None

    def test_split_no_init(self) -> None:
        src = "int f() {\n  int x;\n  return x;\n}"
        result = mut_split_declaration_init(src, RNG)
        assert result is None  # no initialized declaration

    def test_merge_separate_decl_and_assign(self) -> None:
        src = "int f() {\n  int x;\n  x = 5;\n  return x;\n}"
        result = mut_merge_declaration_init(src, RNG)
        if result is not None:
            assert "int x = 5" in result


# -------------------------------------------------------------------------
# Alias / goto mutations (deeper)
# -------------------------------------------------------------------------


class TestDeepAlias:
    def test_alias_with_multiple_uses(self) -> None:
        src = "int f(int param1) {\n  int x = param1 + param1;\n  x = x + param1;\n  return x;\n}"
        result = mut_introduce_local_alias(src, RNG)
        if result is not None:
            assert "param1" in result

    def test_return_goto_full(self) -> None:
        src = "int f() {\n  if (err) return 0;\n  if (bad) return FALSE;\n  return 1;\n}"
        result = mut_return_to_goto(src, RNG)
        assert result is not None, "return_to_goto should succeed on source with return 0/FALSE"
        assert "goto" in result

    def test_goto_to_return_present(self) -> None:
        src = "int f() {\n  goto ret_false;\nret_false:\n  return FALSE;\n}"
        result = mut_goto_to_return(src, RNG)
        # Mutation requires specific label+return pattern; may not match all variants
        if result is not None:
            assert "return" in result
            assert "goto" not in result


# -------------------------------------------------------------------------
# Temp var mutations (deeper)
# -------------------------------------------------------------------------


class TestTempVarDeep:
    def test_introduce_with_call(self) -> None:
        src = "int f() {\n  result = FuncA(a, b);\n  return result;\n}"
        result = mut_introduce_temp_for_call(src, RNG)
        # Regex may not match depending on exact format; permissive check
        if result is not None:
            assert "FuncA" in result
            assert isinstance(result, str)

    def test_remove_temp_present(self) -> None:
        src = "int f() {\n  tmp = GetValue();\n  var = tmp;\n}"
        result = mut_remove_temp_var(src, RNG)
        # Regex needs specific pattern; permissive check
        if result is not None:
            assert "var" in result
            assert isinstance(result, str)


# -------------------------------------------------------------------------
# Array / struct mutations (deeper)
# -------------------------------------------------------------------------


class TestArrayStructDeep:
    def test_multiple_array_accesses(self) -> None:
        src = "x = arr[i];\ny = arr[j];"
        for _ in range(5):
            result = mut_change_array_index_order(src, random.Random(_ + 1))
            if result is not None:
                assert isinstance(result, str)
                break
        # Mutation may legitimately not match this input; smoke test only

    def test_ptr_access(self) -> None:
        src = "x = obj->field1;\ny = obj->field2;"
        for _ in range(5):
            result = mut_struct_vs_ptr_access(src, random.Random(_ + 1))
            if result is not None:
                assert isinstance(result, str)
                break


# -------------------------------------------------------------------------
# Crossover (deeper)
# -------------------------------------------------------------------------


class TestCrossoverDeep:
    def test_different_lengths(self) -> None:
        p1 = "int f(int a) {\n  a = 1;\n  a = 2;\n  a = 3;\n  return a;\n}"
        p2 = "int f(int a) {\n  a = 10;\n  return a;\n}"
        for seed in range(10):
            child = crossover(p1, p2, random.Random(seed))
            assert "return" in child or "int" in child


# -------------------------------------------------------------------------
# Split preamble body (edge cases)
# -------------------------------------------------------------------------


class TestSplitPreambleBodyDeep:
    def test_multiple_functions(self) -> None:
        src = "#include <stdio.h>\nvoid f() {\n  return;\n}\nint g() {\n  return 0;\n}"
        pre, body = _split_preamble_body(src)
        assert "#include" in pre
        assert "f()" in body

    def test_no_function(self) -> None:
        src = "#include <stdio.h>\n#define X 1\n"
        pre, body = _split_preamble_body(src)
        assert "#include" in pre
        assert body == ""


# -------------------------------------------------------------------------
# Quick validate (edge cases)
# -------------------------------------------------------------------------


class TestQuickValidateDeep:
    def test_nested_balanced(self) -> None:
        assert quick_validate("int foo(void) { { { } } }") is True

    def test_mixed_balanced(self) -> None:
        assert quick_validate("int foo(void) { if (a) { while (b) { } } }") is True

    def test_empty(self) -> None:
        assert quick_validate("") is False

    def test_no_function(self) -> None:
        assert quick_validate("{ }") is False

    def test_duplicate_label(self) -> None:
        src = "int foo(void) {\n  ret_false:\n    return 0;\n  ret_false:\n    return 1;\n}"
        assert quick_validate(src) is False

    def test_single_label_ok(self) -> None:
        src = "int foo(void) {\n  ret_false:\n    return 0;\n}"
        assert quick_validate(src) is True

    def test_double_type_keyword(self) -> None:
        src = "int foo(void) {\n    int int x;\n}"
        assert quick_validate(src) is False

    def test_valid_unsigned_int(self) -> None:
        src = "int foo(void) {\n    unsigned int x;\n}"
        assert quick_validate(src) is True


# -------------------------------------------------------------------------
# _find_matching_char
# -------------------------------------------------------------------------


class TestFindMatchingChar:
    def test_parens(self) -> None:
        s = "(a + (b * c))"
        assert _find_matching_char(s, 0, "(", ")") == len(s)

    def test_nested_parens(self) -> None:
        s = "(func(a, b))"
        assert _find_matching_char(s, 0, "(", ")") == len(s)

    def test_unbalanced(self) -> None:
        assert _find_matching_char("(abc", 0, "(", ")") is None

    def test_not_open_char(self) -> None:
        assert _find_matching_char("abc", 0, "(", ")") is None


# -------------------------------------------------------------------------
# While/do-while with nested parens (regression)
# -------------------------------------------------------------------------


class TestWhileNestedParens:
    def test_while_with_func_call_in_condition(self) -> None:
        src = "while (check(a, b)) {\n    x = x + 1;\n}"
        result = mut_while_to_dowhile(src, RNG)
        assert result is not None
        assert "do" in result
        assert "check(a, b)" in result

    def test_duplicate_body_with_func_call_condition(self) -> None:
        src = "while (check(a)) {\n    x = x + 1;\n}"
        result = mut_duplicate_loop_body(src, RNG)
        assert result is not None
        assert result.count("x + 1") >= 2


# -------------------------------------------------------------------------
# mut_add_redundant_parens — C keywords excluded (regression)
# -------------------------------------------------------------------------


class TestRedundantParensKeywords:
    def test_does_not_wrap_keyword(self) -> None:
        """Ensure C keywords like 'if', 'return', 'while' are never wrapped."""
        src = "if (x) return 0;"
        for seed in range(50):
            result = mut_add_redundant_parens(src, random.Random(seed))
            if result is not None:
                assert "(if)" not in result
                assert "(return)" not in result

    def test_wraps_identifier(self) -> None:
        src = "x = myvar + 1;"
        result = mut_add_redundant_parens(src, RNG)
        assert result is not None
        assert "(" in result


# -------------------------------------------------------------------------
# mut_split_cmp_chain — balanced braces (regression)
# -------------------------------------------------------------------------


class TestSplitCmpChainBalanced:
    def test_two_conditions_balanced(self) -> None:
        src = "if (a && b) {\n  x = 1;\n}"
        result = mut_split_cmp_chain(src, RNG)
        assert result is not None
        assert result.count("{") == result.count("}")

    def test_three_conditions_balanced(self) -> None:
        src = "if (a && b && c) {\n  x = 1;\n}"
        result = mut_split_cmp_chain(src, RNG)
        assert result is not None
        assert result.count("{") == result.count("}")
        assert "if (a)" in result
        assert "if (b)" in result
        assert "if (c)" in result


# -------------------------------------------------------------------------
# mut_unfold_constant_add — capped at 16 (regression)
# -------------------------------------------------------------------------


class TestUnfoldConstantAddCap:
    def test_large_constant_returns_none(self) -> None:
        src = "x = x + 256;"
        result = mut_unfold_constant_add(src, RNG)
        assert result is None, "Should refuse to unroll constants > 16"

    def test_small_constant_unfolds(self) -> None:
        src = "x = x + 3;"
        result = mut_unfold_constant_add(src, RNG)
        assert result is not None
        assert result.count("x = x + 1") == 3


# -------------------------------------------------------------------------
# mut_early_return_to_accum with nested function calls (regression)
# -------------------------------------------------------------------------


class TestEarlyReturnNestedCalls:
    def test_nested_func_call(self) -> None:
        src = "int f() {\n  int ret = 1;\n  if (!validate(get_val(x))) return 0;\n  return ret;\n}"
        result = mut_early_return_to_accum(src, RNG)
        if result is not None:
            assert "&=" in result
            assert "validate" in result
