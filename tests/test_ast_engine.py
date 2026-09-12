"""Tests for matcher/ast_engine.py parsing."""

import pytest
from tree_sitter import Node, Tree

from rebrew.matcher.ast_engine import parse_c_ast, replace_node


def _func_defs(tree: Tree) -> list[Node]:
    return [n for n in tree.root_node.children if n.type == "function_definition"]


class TestParseAst:
    def test_parse_roundtrip(self) -> None:
        tree = parse_c_ast("int f(void) { return 1; }")
        assert tree is not None
        assert not tree.root_node.has_error
        assert len(_func_defs(tree)) == 1

    def test_parse_multi_function(self) -> None:
        tree = parse_c_ast("int f(void) { return 1; }\nint g(int x) { return x + 1; }")
        texts = []
        for n in _func_defs(tree):
            decl = n.child_by_field_name("declarator")
            assert decl is not None
            assert decl.text is not None
            texts.append(decl.text)
        assert texts == [b"f(void)", b"g(int x)"]

    def test_parse_accepts_bytes(self) -> None:
        tree = parse_c_ast(b"int f(void) { return 1; }")
        assert not tree.root_node.has_error
        assert len(_func_defs(tree)) == 1

    def test_malformed_input_has_error_node(self) -> None:
        tree = parse_c_ast("int f( { garbage !!!")
        assert tree.root_node.has_error

    def test_empty_source_parses_clean(self) -> None:
        tree = parse_c_ast("")
        assert not tree.root_node.has_error
        assert _func_defs(tree) == []

    def test_replace_node(self) -> None:
        src = b"int f(void) { return 1; }"
        tree = parse_c_ast(src)
        stack = [tree.root_node]
        ret = None
        while stack:
            node = stack.pop()
            if node.type == "number_literal":
                ret = node
                break
            stack.extend(node.children)
        assert ret is not None
        assert replace_node(src, ret, b"2") == b"int f(void) { return 2; }"


class TestParseAstErrors:
    @pytest.mark.parametrize("bad", ["int f( {", "void }", "struct { ;", "1 +* 2;"])
    def test_invalid_sources_flag_errors(self, bad: str) -> None:
        assert parse_c_ast(bad).root_node.has_error
