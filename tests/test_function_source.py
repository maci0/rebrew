"""Complete decompiler validation has no GA population size limit."""

from typing import Any

import pytest

from rebrew.c_parser import function_source_error
from rebrew.llm_seed import MAX_SEED_CHARS, valid_c_source


def _large_body() -> str:
    return "int f(void) { int n=0;" + "n += 1;\n" * 1500 + "return n; }"


class TestCompleteFunctionValidation:
    def test_large_body_is_complete_but_not_a_population_seed(self) -> None:
        body = _large_body()
        assert len(body) > MAX_SEED_CHARS
        assert function_source_error(body, expect_name="f") is None
        assert not valid_c_source(body)

    @pytest.mark.parametrize(
        ("prefix", "suffix", "name", "reason"),
        [
            ('#include "untrusted.h"\n', "", "f", "preprocessor"),
            ("", "\nint other(void) { return 1; }", "f", "exactly one"),
            ("", "", "different", "expected function"),
            ("int extra;\n", "", "f", "top-level"),
            ("", "\nnot C {{{", "f", "syntax"),
        ],
    )
    def test_large_body_retains_structural_and_identity_checks(
        self, prefix: str, suffix: str, name: str, reason: str
    ) -> None:
        error = function_source_error(prefix + _large_body() + suffix, expect_name=name)
        assert error is not None and reason in error

    def test_oversized_seed_is_rejected_before_the_parser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import c_parser

        def _unexpected(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("oversized population seed reached the parser")

        monkeypatch.setattr(c_parser, "function_source_error", _unexpected)
        assert not valid_c_source(_large_body())

    @pytest.mark.parametrize("literal", ["asm", "_Pragma(hi)", "__declspec(naked)", "//", "/*"])
    def test_literals_do_not_become_operators(self, literal: str) -> None:
        source = f'int f(void) {{ const char *s="{literal}"; return s != 0; }}'
        assert function_source_error(source, expect_name="f") is None

    @pytest.mark.parametrize(
        "source",
        [
            'int f(void) { const char *a="//"; __declspec(align(16)) int n=0; return n; }',
            'int f(void) { const char *a="/*"; __declspec(naked) int n; const char *b="*/"; return 0; }',
        ],
    )
    def test_string_comment_delimiters_cannot_hide_attributes(self, source: str) -> None:
        assert function_source_error(source) == "unexpected compiler attributes"

    @pytest.mark.parametrize(
        "declaration", ["int shadow;", "int shadow=7;", "extern int shadow=7;"]
    )
    def test_extra_storage_requires_ownership_review(self, declaration: str) -> None:
        error = function_source_error(
            declaration + "int f(void) { return 0; }", allow_declarations=True
        )
        assert error is not None and "storage definitions" in error
