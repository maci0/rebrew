from rebrew.matcher.ast_engine import ASTMutator, parse_c_ast, quick_validate_ast


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
