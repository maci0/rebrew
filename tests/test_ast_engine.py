"""Tests for matcher/ast_engine.py parsing."""

import pytest
from tree_sitter import Node, Tree

from rebrew.matcher.ast_engine import (
    decode_source,
    encode_source,
    parse_c_ast,
    replace_node,
)


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


class TestLegacyEncodedSource:
    """A cp1252 / Shift-JIS seed must survive the GA str<->bytes boundary.

    ``read_compile_source`` decodes with ``surrogateescape`` so the compile
    round-trip stays byte-identical; encoding that text back with a plain
    ``utf-8`` encode raises UnicodeEncodeError on the lone surrogate, which
    killed every GA run on a legacy-encoded source before its first
    generation.
    """

    # cp1252 0xE9 ('é' in "Café") as read_compile_source hands it over.
    SRC = 'int f(int n) { char *s = "Caf\udce9"; return n + (int)s[0]; }'

    def test_parse_accepts_surrogate_escaped_source(self) -> None:
        assert not parse_c_ast(self.SRC).root_node.has_error

    def test_encode_source_restores_the_raw_byte(self) -> None:
        assert b'"Caf\xe9"' in encode_source(self.SRC)

    def test_encode_decode_roundtrip_is_lossless(self) -> None:
        assert decode_source(encode_source(self.SRC)) == self.SRC
