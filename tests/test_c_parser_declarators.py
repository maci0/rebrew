"""Unit tests for c_parser declarator walkers using synthetic AST nodes."""

from rebrew.c_parser import (
    _count_pointer_depth,
    _extract_array_suffix,
    _find_declarator_name,
    _find_function_name,
)


class Node:
    def __init__(self, type: str, children=None, start: int = 0, end: int = 0) -> None:
        self.type = type
        self.children = children or []
        self.start_byte = start
        self.end_byte = end

    def __repr__(self) -> str:
        return f"<{self.type}>"


def _ident(name: str, offset: int = 0) -> Node:
    return Node("identifier", start=offset, end=offset + len(name))


def _text(node: Node) -> str:
    # _node_text reads source_bytes[start_byte:end_byte]
    return node.type  # pragma: no cover — not used with real bytes here


class TestFindFunctionName:
    def test_identifier_direct(self) -> None:
        node = _ident("foo")
        assert _find_function_name(node, b"foo") == "foo"

    def test_pointer_declarator_walk(self) -> None:
        node = Node("pointer_declarator", children=[Node("*"), _ident("handler", offset=1)])
        assert _find_function_name(node, b"*handler") == "handler"

    def test_parenthesized_walk(self) -> None:
        node = Node(
            "parenthesized_declarator",
            children=[Node("("), _ident("cb", offset=1), Node(")", start=3)],
        )
        assert _find_function_name(node, b"(cb)") == "cb"

    def test_unknown_type_recursion(self) -> None:
        node = Node("weird", children=[_ident("inner")])
        assert _find_function_name(node, b"inner") == "inner"


class TestFindDeclaratorName:
    def test_init_declarator_skips_equals(self) -> None:
        node = Node(
            "init_declarator",
            children=[_ident("x"), Node("="), Node("number_literal")],
        )
        assert _find_declarator_name(node, b"x=5") == "x"

    def test_pointer_recursion(self) -> None:
        node = Node("pointer_declarator", children=[Node("*"), _ident("p", offset=1)])
        assert _find_declarator_name(node, b"*p") == "p"

    def test_function_declarator_returns_none(self) -> None:
        node = Node("function_declarator", children=[_ident("f")])
        assert _find_declarator_name(node, b"f") is None

    def test_fallthrough_recursion(self) -> None:
        node = Node("field_declaration", children=[_ident("field")])
        assert _find_declarator_name(node, b"field") == "field"


class TestPointerDepthAndArraySuffix:
    def test_pointer_depth_chain(self) -> None:
        ident = _ident("p")
        inner = Node("pointer_declarator", children=[Node("*"), ident])
        outer = Node("pointer_declarator", children=[Node("*"), inner])
        assert _count_pointer_depth(outer) == 2

    def test_array_suffix_non_array(self) -> None:
        assert _extract_array_suffix(_ident("x"), b"x") == ""

    def test_array_suffix_single(self) -> None:
        node = Node(
            "array_declarator",
            children=[_ident("a"), Node("[", start=1, end=2), Node("]", start=5, end=6)],
        )
        assert _extract_array_suffix(node, b"a[10]") == "[10]"
