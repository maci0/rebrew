import random

from rebrew.matcher.mutator import (
    mut_accum_to_early_return,
    mut_add_cast,
    mut_add_redundant_parens,
    mut_add_register_keyword,
    mut_bitand_to_if_false,
    mut_change_array_index_order,
    mut_change_param_order,
    mut_change_return_type,
    mut_combine_ptr_arith,
    mut_commute_simple_add,
    mut_commute_simple_mul,
    mut_comparison_boundary,
    mut_dowhile_to_while,
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
    mut_while_to_dowhile,
)


def test_mut_ast_commute_simple_add():
    source = "int main() { return a + b; }"
    rng = random.Random(42)
    # The mutator selects a random match (only one here) and swaps left and right
    res = mut_commute_simple_add(source, rng)
    assert res == "int main() { return b + a; }"


def test_mut_ast_commute_simple_mul():
    source = "int main() { return a * b; }"
    rng = random.Random(42)
    res = mut_commute_simple_mul(source, rng)
    assert res == "int main() { return b * a; }"


def test_mut_ast_flip_eq_zero():
    source = "int main() { if (a == 0) return 0; if (b != 0) return 1; }"
    rng = random.Random(
        42
    )  # Try with a fixed seed to get the first one, or just check that one of them flipped

    # We loop to make sure we hit both eventually in a simple test
    results = set()
    for _ in range(10):
        res = mut_flip_eq_zero(source, rng)
        if res:
            results.add(res)

    assert "int main() { if (!a) return 0; if (b != 0) return 1; }" in results
    assert "int main() { if (a == 0) return 0; if (!!b) return 1; }" in results


def test_mut_ast_flip_lt_ge():
    source = "int main() { if (a < b) return 0; }"
    rng = random.Random(42)
    res = mut_flip_lt_ge(source, rng)
    assert res == "int main() { if (!(a >= b)) return 0; }"


def test_mut_ast_add_redundant_parens():
    source = "int main() { return a + b; }"
    rng = random.Random(42)
    # The identifier query will find 'main', 'a', 'b'.
    # random choice will pick one. Let's run a few times to see it wrap an identifier.
    results = set()
    for _ in range(10):
        res = mut_add_redundant_parens(source, rng)
        if res:
            results.add(res)
    assert (
        "int main() { return (a) + b; }" in results or "int main() { return a + (b); }" in results
    )


def test_mut_ast_swap_eq_operands():
    source = "int main() { if (a == b) return 0; }"
    rng = random.Random(42)
    res = mut_swap_eq_operands(source, rng)
    assert res == "int main() { if (b == a) return 0; }"


def test_mut_ast_swap_ne_operands():
    source = "int main() { if (a != b) return 0; }"
    rng = random.Random(42)
    res = mut_swap_ne_operands(source, rng)
    assert res == "int main() { if (b != a) return 0; }"


def test_mut_ast_reassociate_add():
    source = "int main() { return (a + b) + c; }"
    rng = random.Random(42)
    res = mut_reassociate_add(source, rng)
    assert res == "int main() { return a + (b + c); }"


def test_mut_ast_swap_or_operands():
    source = "int main() { if (a || b) return 0; }"
    rng = random.Random(42)
    res = mut_swap_or_operands(source, rng)
    assert res == "int main() { if (b || a) return 0; }"


def test_mut_ast_swap_and_operands():
    source = "int main() { if (a && b) return 0; }"
    rng = random.Random(42)
    res = mut_swap_and_operands(source, rng)
    assert res == "int main() { if (b && a) return 0; }"


def test_mut_ast_toggle_bool_not():
    source = "int main() { if (!!a) return 0; }"
    rng = random.Random(42)
    res = mut_toggle_bool_not(source, rng)
    assert res == "int main() { if (a) return 0; }"


def test_mut_ast_return_to_goto():
    source = "int foo() { if (a) { return 0; } return 1; }"
    rng = random.Random(42)
    res = mut_return_to_goto(source, rng)
    assert "goto ret_false;" in res
    assert "ret_false:" in res


def test_mut_ast_goto_to_return():
    source = "int main() {\n    goto ret_false;\nret_false:\n    return 0;\n}"
    rng = random.Random(42)
    res = mut_goto_to_return(source, rng)
    assert res == "int main() {\n    return 0;\n    return 0;\n}"


def test_mut_ast_swap_if_else():
    source = "int main() { if (a < b) { return 1; } else { return 0; } }"
    rng = random.Random(42)
    res = mut_swap_if_else(source, rng)
    assert res == "int main() { if (!(a < b)) { return 0; } else { return 1; } }"


def test_mut_ast_add_cast():
    source = "void foo() { int a = b; }"
    rng = random.Random(42)
    res = mut_add_cast(source, rng)
    assert "(int)b" in res or "(unsigned int)b" in res


def test_mut_ast_remove_cast():
    source = "void foo() { int a = (DWORD)b; }"
    rng = random.Random(42)
    res = mut_remove_cast(source, rng)
    assert res == "void foo() { int a = b; }"


def test_mut_ast_toggle_volatile():
    source1 = "int a;"
    rng = random.Random(42)
    res1 = mut_toggle_volatile(source1, rng)
    assert res1 == "volatile int a;"

    source2 = "volatile int a;"
    mut_toggle_volatile(source2, rng)
    # The RNG might choose to remove it. Let's just try running it until it flips
    results = set()
    for _ in range(10):
        res = mut_toggle_volatile(source2, rng)
        if res:
            results.add(res)
    assert "int a;" in results


def test_mut_ast_add_register_keyword():
    source = "int a;"
    rng = random.Random(42)
    res = mut_add_register_keyword(source, rng)
    assert res == "register int a;"


def test_mut_ast_remove_register_keyword():
    source = "register int a;"
    rng = random.Random(42)
    res = mut_remove_register_keyword(source, rng)
    assert res == "int a;"


def test_mut_ast_if_false_to_bitand():
    source = "int main() { if (!a) { b = 0; } }"
    rng = random.Random(42)
    res = mut_if_false_to_bitand(source, rng)
    assert res == "int main() { b &= a; }"


def test_mut_ast_reorder_elseif():
    source = "int main() { if (a) { return 0; } else if (b) { return 1; } }"
    rng = random.Random(42)
    res = mut_reorder_elseif(source, rng)
    assert "if (b)" in res and "else if (a)" in res


def test_mut_ast_bitand_to_if_false():
    source = "int main() { a &= foo(); }"
    rng = random.Random(42)
    res = mut_bitand_to_if_false(source, rng)
    assert res == "int main() { if (!(foo()))\n            a = 0; }"


def test_mut_ast_introduce_temp_for_call():
    source = "int main() { a = foo(); }"
    rng = random.Random(42)
    res = mut_introduce_temp_for_call(source, rng)
    assert res == "int main() { BOOL tmp = foo();\n    a = tmp; }"


def test_mut_ast_remove_temp_var():
    source = "int main() { tmp = foo(); a = tmp; }"
    rng = random.Random(42)
    res = mut_remove_temp_var(source, rng)
    assert res == "int main() { a = foo(); }"


def test_mut_ast_toggle_signedness():
    source = "int main() { unsigned int a; }"
    rng = random.Random(42)
    res = mut_toggle_signedness(source, rng)
    assert res == "int main() { int a; }"

    source2 = "int main() { int b; }"
    res2 = mut_toggle_signedness(source2, rng)
    assert res2 == "int main() { unsigned int b; }"


def test_mut_ast_swap_adjacent_declarations():
    source = "int main() { int a; int b; c = 0; }"
    rng = random.Random(42)
    res = mut_swap_adjacent_declarations(source, rng)
    assert res is not None
    assert "int b; int a;" in res


def test_mut_ast_split_declaration_init():
    source = "int main() { int a = 5; }"
    rng = random.Random(42)
    res = mut_split_declaration_init(source, rng)
    assert res is not None
    assert "int a;\n    a = 5;" in res


def test_mut_ast_merge_declaration_init():
    source = "int main() { int a;\n    a = 5; }"
    rng = random.Random(42)
    res = mut_merge_declaration_init(source, rng)
    assert res is not None
    assert "int a = 5;" in res


def test_mut_ast_while_to_dowhile():
    source = "int main() { while (a < 5) { a++; } }"
    rng = random.Random(42)
    res = mut_while_to_dowhile(source, rng)
    assert res is not None
    assert "if (a < 5) {\n    do { a++; } while (a < 5);\n    }" in res


def test_mut_ast_dowhile_to_while():
    source = "int main() { do { a++; } while (a < 5); }"
    rng = random.Random(42)
    res = mut_dowhile_to_while(source, rng)
    assert res is not None
    assert "while (a < 5) { a++; }" in res


def test_mut_ast_early_return_to_accum():
    source = "int main() { int ret; if (!foo()) return 0; return ret; }"
    rng = random.Random(42)
    res = mut_early_return_to_accum(source, rng)
    assert res is not None
    assert "ret &= foo();" in res


def test_mut_ast_accum_to_early_return():
    source = "int main() { int ret; ret &= foo(); }"
    rng = random.Random(42)
    res = mut_accum_to_early_return(source, rng)
    assert res is not None
    assert "if (!(foo()))\n        return 0;" in res


def test_mut_ast_pointer_to_int_param():
    source = "void foo(int *a) { }"
    rng = random.Random(42)
    res = mut_pointer_to_int_param(source, rng)
    assert res is not None
    assert "void foo(int a) { }" in res


def test_mut_ast_int_to_pointer_param():
    source = "void foo(int a) { }"
    rng = random.Random(42)
    res = mut_int_to_pointer_param(source, rng)
    assert res is not None
    assert "void foo(char *a) { }" in res


def test_mut_ast_duplicate_loop_body():
    source = "int main() { while (a < 5) { a++; } }"
    rng = random.Random(42)
    res = mut_duplicate_loop_body(source, rng)
    assert res is not None
    assert "{\n    a++;\n    a++;\n}" in res


def test_mut_ast_fold_constant_add():
    source = "int main() { x = x + 1; x = x + 2; }"
    rng = random.Random(42)
    res = mut_fold_constant_add(source, rng)
    assert "x = x + 3;" in res, res


def test_mut_ast_unfold_constant_add():
    source = "int main() { x = x + 3; }"
    rng = random.Random(42)
    res = mut_unfold_constant_add(source, rng)
    assert res == "int main() { x = x + 1; x = x + 1; x = x + 1; }"


def test_mut_ast_change_array_index_order():
    source = "int main() { arr[0] = 1; arr[idx] = 2; }"
    rng = random.Random(42)
    res = mut_change_array_index_order(source, rng)
    assert "0[arr]" in res or "idx[arr]" in res


def test_mut_ast_struct_vs_ptr_access():
    source = "int main() { ptr->field = 1; }"
    rng = random.Random(42)
    res = mut_struct_vs_ptr_access(source, rng)
    assert res == "int main() { (*ptr).field = 1; }"


def test_mut_ast_change_return_type():
    source = "int main() { return 0; }"
    rng = random.Random(42)
    res = mut_change_return_type(source, rng)
    assert "char main()" in res or "short main()" in res or "long main()" in res


def test_mut_ast_split_cmp_chain():
    source = "int main() { if (a && b) { return; } }"
    rng = random.Random(42)
    res = mut_split_cmp_chain(source, rng)
    assert res is not None
    assert "if (a) { if (b) { return; } }" in res


def test_mut_ast_merge_cmp_chain():
    source = "int main() { if (a) { if (b) { return; } } }"
    rng = random.Random(42)
    res = mut_merge_cmp_chain(source, rng)
    assert res is not None
    assert "if ((a) && (b))" in res


def test_mut_ast_combine_ptr_arith():
    source = "int main() { p = p + 2; p = p + 3; }"
    rng = random.Random(42)
    res = mut_combine_ptr_arith(source, rng)
    assert res is not None
    assert "p = p + 5;" in res


def test_mut_ast_split_ptr_arith():
    source = "int main() { p = p + 5; }"
    rng = random.Random(42)
    res = mut_split_ptr_arith(source, rng)
    assert res is not None
    assert "p = p + 2; p = p + 3;" in res


def test_mut_ast_change_param_order():
    source = "void foo(int a, int b) {}"
    rng = random.Random(42)
    res = mut_change_param_order(source, rng)
    assert res is not None
    assert "void foo(int b, int a)" in res


def test_mut_ast_toggle_calling_convention():
    source = "int __cdecl main() {}"
    rng = random.Random(42)
    res = mut_toggle_calling_convention(source, rng)
    assert res is not None
    assert "int __stdcall main() {}" in res


def test_mut_ast_toggle_char_signedness():
    source = "unsigned char x;"
    rng = random.Random(42)
    res = mut_toggle_char_signedness(source, rng)
    assert res is not None
    assert "signed char x;" in res


def test_mut_ast_comparison_boundary():
    source = "if (x > 0) {}"
    rng = random.Random(42)
    res = mut_comparison_boundary(source, rng)
    assert res is not None
    assert "if (x >= 1)" in res


def test_mut_ast_insert_noop_block():
    source = "int main() { x = 1; }"
    rng = random.Random(42)
    res = mut_insert_noop_block(source, rng)
    assert res is not None
    assert "if (0) {}" in res


def test_mut_ast_introduce_local_alias():
    source = "int main() { x = y; }"
    rng = random.Random(42)
    res = mut_introduce_local_alias(source, rng)
    assert res is not None
    assert "_alias_y" in res


def test_mut_ast_reorder_declarations():
    source = "int main() { int a; int b; }"
    rng = random.Random(42)
    res = mut_reorder_declarations(source, rng)
    assert res is not None
    assert "int b" in res[: res.index("int a")]


from rebrew.matcher.ast_engine import ASTMutator, parse_c_ast, quick_validate_ast  # noqa: E402


def test_parse_c_ast():
    source = b"int main() { return 0; }"
    tree = parse_c_ast(source)
    assert tree.root_node.type == "translation_unit"
    assert not tree.root_node.has_error


def test_quick_validate_ast_valid():
    assert quick_validate_ast(b"int main() { return 0; }")


def test_quick_validate_ast_invalid():
    # Missing closing brace
    assert not quick_validate_ast(b"int main() { return 0;")


def test_replace_node():
    source = b"int main() { return 0; }"
    tree = parse_c_ast(source)
    # The return statement is the child of the compound statement, which is the 2nd child of function_definition
    func_node = tree.root_node.children[0]
    compound_node = func_node.children[-1]
    return_node = compound_node.children[1]

    assert return_node.type == "return_statement"

    new_source = ASTMutator.replace_node(source, return_node, b"return 1;")
    assert new_source == b"int main() { return 1; }"
