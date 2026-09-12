"""Tests for the MSVC6 C-shape lever operators (structural.py).

Each lever comes from a measured finding in a real 2002 MSVC6 reconstruction:
the shape changes codegen without changing what the C computes.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterable

from rebrew.matcher.mutations.structural import (
    mut_call_prototype_view,
    mut_compare_negate_to_ternary,
    mut_home_byte_in_param_slot,
    mut_ternary_lift_constant,
    mut_walk_in_parameter,
)
from rebrew.matcher.mutator import quick_validate

_RNG_SEED = 42


def _rng() -> random.Random:
    """A fresh RNG with a fixed seed for deterministic, order-independent tests."""
    return random.Random(_RNG_SEED)


def _first(
    fn: Callable[[str, random.Random], str | None],
    src: str,
    seeds: Iterable[int] = range(60),
) -> str | None:
    """The first non-trivial mutation *fn* produces for *src*, or None."""
    for seed in seeds:
        out = fn(src, random.Random(seed))
        if out is not None and out != src:
            return out
    return None


class TestTernaryLiftConstant:
    """``p + (c ? K : K)`` folds the conditional away and kills the byte's
    liveness; ``(c) ? (p + K) : (p + K)`` keeps both live."""

    SRC = (
        "int f(char *p, char *c) {\n"
        "    c = p + (*p == 0x16 ? 0x15 : 0x15);\n"
        "    return (int)c;\n"
        "}\n"
    )

    def test_lifts_the_ternary_over_the_addition(self) -> None:
        out = _first(mut_ternary_lift_constant, self.SRC)
        assert out is not None
        assert "((*p == 0x16) ? (p + 0x15) : (p + 0x15))" in out
        assert quick_validate(out)

    def test_leaves_unequal_arms_alone(self) -> None:
        src = self.SRC.replace("? 0x15 : 0x15", "? 0x15 : 0x16")
        assert _first(mut_ternary_lift_constant, src) is None

    def test_leaves_a_bare_ternary_alone(self) -> None:
        """No enclosing binary expression, so there is nothing to lift over."""
        src = "int f(int x) {\n    return x ? 0x15 : 0x15;\n}\n"
        assert _first(mut_ternary_lift_constant, src) is None


class TestCompareNegateToTernary:
    """``-(a != b)`` compiles to the setne form; the ternary reaches the fused
    compare-and-negate the reference uses."""

    def test_rewrites_ne_to_fused_form(self) -> None:
        src = "int f(int x) {\n    return -(x != 0xe);\n}\n"
        out = _first(mut_compare_negate_to_ternary, src)
        assert out is not None
        assert "((x != 0xe) ? -1 : 0)" in out
        assert quick_validate(out)

    def test_rewrites_eq_to_the_mirror(self) -> None:
        src = "int f(int x) {\n    return -(x == 0xe);\n}\n"
        out = _first(mut_compare_negate_to_ternary, src)
        assert out is not None
        assert "((x == 0xe) ? 0 : -1)" in out
        assert quick_validate(out)

    def test_ignores_a_non_comparison_operand(self) -> None:
        src = "int f(int x) {\n    return -(x + 1);\n}\n"
        assert _first(mut_compare_negate_to_ternary, src) is None


class TestWalkInParameter:
    """A local copy of an advanced parameter adds a live range and rotates the
    callee-saved assignments; the walk belongs in the parameter."""

    SRC = (
        "int f(char *cursor) {\n"
        "    char *cur = cursor + 0x14;\n"
        "    cur = cur + 0x14;\n"
        "    return (int)cur;\n"
        "}\n"
    )

    def test_advances_the_parameter(self) -> None:
        out = _first(mut_walk_in_parameter, self.SRC)
        assert out is not None
        assert "char *cur =" not in out  # the local copy is gone
        assert out.count("cursor = cursor + 0x14;") == 2
        assert "(int)cursor" in out
        assert quick_validate(out)

    def test_skips_a_declaration_followed_by_another(self) -> None:
        """Turning the declaration into a statement would put it ahead of the
        next declaration, which C89 rejects."""
        src = (
            "int f(char *cursor) {\n"
            "    char *cur = cursor + 0x14;\n"
            "    int n;\n"
            "    n = (int)cur;\n"
            "    return n;\n"
            "}\n"
        )
        assert _first(mut_walk_in_parameter, src) is None

    def test_skips_when_the_initializer_names_no_parameter(self) -> None:
        src = (
            "char *g;\n"
            "int f(void) {\n"
            "    char *cur = g + 0x14;\n"
            "    cur = cur + 0x14;\n"
            "    return (int)cur;\n"
            "}\n"
        )
        assert _first(mut_walk_in_parameter, src) is None

    def test_skips_an_unused_local(self) -> None:
        src = "int f(char *cursor) {\n    char *cur = cursor + 0x14;\n    return (int)cursor;\n}\n"
        assert _first(mut_walk_in_parameter, src) is None


class TestHomeByteInParamSlot:
    """A byte that must survive a loop gets a spill dword; a dead parameter's
    slot already in the frame is a legal home."""

    SRC = (
        "int f(char *cmd, void *arg1, int i) {\n"
        "    unsigned char holder = cmd[6];\n"
        "    i = holder;\n"
        "    return i;\n"
        "}\n"
    )

    def test_homes_the_byte_in_a_dead_parameter(self) -> None:
        out = _first(mut_home_byte_in_param_slot, self.SRC)
        assert out is not None
        assert "unsigned char holder" not in out
        assert "((unsigned char*)&arg1)[" in out
        assert quick_validate(out)

    def test_skips_when_every_parameter_is_live(self) -> None:
        src = (
            "int f(char *cmd, void *arg1, int i) {\n"
            "    unsigned char holder = cmd[6];\n"
            "    i = holder + (int)(long)arg1;\n"
            "    return i;\n"
            "}\n"
        )
        assert _first(mut_home_byte_in_param_slot, src) is None

    def test_skips_a_non_byte_local(self) -> None:
        src = (
            "int f(char *cmd, void *arg1, int i) {\n"
            "    int holder = cmd[6];\n"
            "    i = holder;\n"
            "    return i;\n"
            "}\n"
        )
        assert _first(mut_home_byte_in_param_slot, src) is None


class TestCallPrototypeView:
    """The caller's view of the callee prototype decides how an argument is
    materialized, so the cast-call reproduces a prototype the callee no longer
    declares."""

    SRC = "int f(int a) {\n    return gm_QueryEntitySum(1, a);\n}\n"

    def test_casts_the_callee_with_a_varied_parameter(self) -> None:
        out = _first(mut_call_prototype_view, self.SRC)
        assert out is not None
        assert "gm_QueryEntitySum)(" in out
        assert any(t in out for t in ("unsigned char", "short", "char"))
        assert quick_validate(out)

    def test_skips_a_call_with_no_arguments(self) -> None:
        src = "int f(void) {\n    return g();\n}\n"
        assert _first(mut_call_prototype_view, src) is None
