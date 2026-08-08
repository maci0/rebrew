"""Tests for matcher/ast_engine.py quick validation."""

from rebrew.matcher.ast_engine import parse_c_ast, quick_validate_ast


class TestQuickValidateAst:
    def test_valid_c(self) -> None:
        assert quick_validate_ast("int f(void) { return 1; }") is True

    def test_invalid_c(self) -> None:
        assert quick_validate_ast("int f( {") is False

    def test_parse_roundtrip(self) -> None:
        tree = parse_c_ast("int f(void) { return 1; }")
        assert tree is not None
