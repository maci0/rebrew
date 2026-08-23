"""Tests for matcher/ast_engine.py parsing."""

from rebrew.matcher.ast_engine import parse_c_ast


class TestParseAst:
    def test_parse_roundtrip(self) -> None:
        tree = parse_c_ast("int f(void) { return 1; }")
        assert tree is not None
