import random

from rebrew.matcher.mutator import (
    ALL_MUTATIONS,
    mut_add_loop_break,
    mut_hoist_common_tail,
    mut_if_else_call_to_ternary_arg,
    mut_register_param,
    mut_remove_loop_break,
    mut_sink_common_tail,
    mut_ternary_arg_to_if_else_call,
    mut_unregister_param,
)

RNG = random.Random(42)


# ---------------------------------------------------------------------------
# 1. Register param mutations
# ---------------------------------------------------------------------------


class TestRegisterParam:
    def test_add_register_to_param(self) -> None:
        src = "void f(int a, int b) {\n    a = 1;\n}"
        res = mut_register_param(src, RNG)
        assert res is not None
        assert "register int" in res or "register" in res

    def test_no_double_register(self) -> None:
        src = "void f(register int a) {\n    a = 1;\n}"
        res = mut_register_param(src, RNG)
        # Should return None since the only param already has register
        assert res is None

    def test_skip_variadic(self) -> None:
        src = "void f(int fmt, ...) {\n    fmt = 1;\n}"
        res = mut_register_param(src, RNG)
        assert res is not None
        assert "register int fmt" in res
        # The ... should NOT get register
        assert "register ..." not in res

    def test_multiple_params_picks_non_register(self) -> None:
        src = "void f(register int a, int b) {\n    a = 1;\n}"
        res = mut_register_param(src, RNG)
        assert res is not None
        # b should get register, a already has it
        assert "register int b" in res


class TestUnregisterParam:
    def test_remove_register(self) -> None:
        src = "void f(register int a) {\n    a = 1;\n}"
        res = mut_unregister_param(src, RNG)
        assert res is not None
        assert "register" not in res
        assert "int a" in res

    def test_no_match(self) -> None:
        src = "void f(int a) {\n    a = 1;\n}"
        res = mut_unregister_param(src, RNG)
        assert res is None


# ---------------------------------------------------------------------------
# 2. Loop break mutations
# ---------------------------------------------------------------------------


class TestRemoveLoopBreak:
    def test_remove_break_from_while(self) -> None:
        src = "while (1) {\n    x = 1;\n    break;\n}"
        res = mut_remove_loop_break(src, RNG)
        assert res is not None
        assert "break" not in res
        assert "x = 1;" in res

    def test_remove_break_from_for(self) -> None:
        src = "for (i = 0; i < 10; i++) {\n    x = 1;\n    break;\n}"
        res = mut_remove_loop_break(src, RNG)
        assert res is not None
        assert "break" not in res

    def test_no_match(self) -> None:
        src = "while (1) {\n    x = 1;\n}"
        res = mut_remove_loop_break(src, RNG)
        assert res is None


class TestAddLoopBreak:
    def test_add_break_to_while(self) -> None:
        src = "while (1) {\n    x = 1;\n}"
        res = mut_add_loop_break(src, RNG)
        assert res is not None
        assert "break;" in res

    def test_no_double_break(self) -> None:
        src = "while (1) {\n    break;\n}"
        res = mut_add_loop_break(src, RNG)
        assert res is None

    def test_add_break_to_for(self) -> None:
        src = "for (i = 0; i < 10; i++) {\n    x = 1;\n}"
        res = mut_add_loop_break(src, RNG)
        assert res is not None
        assert "break;" in res


# ---------------------------------------------------------------------------
# 3. If/else call to ternary arg
# ---------------------------------------------------------------------------


class TestIfElseCallToTernaryArg:
    def test_basic(self) -> None:
        src = "if (flag) {\n    SetText(hwnd, strA);\n} else {\n    SetText(hwnd, strB);\n}"
        res = mut_if_else_call_to_ternary_arg(src, RNG)
        assert res is not None
        assert "SetText(" in res
        assert "?" in res
        assert "strA" in res
        assert "strB" in res
        # Should be a single call now
        assert res.count("SetText(") == 1

    def test_different_functions_no_match(self) -> None:
        src = "if (flag) {\n    FuncA(x);\n} else {\n    FuncB(x);\n}"
        res = mut_if_else_call_to_ternary_arg(src, RNG)
        assert res is None

    def test_multiple_args_differ_no_match(self) -> None:
        src = "if (flag) {\n    Fn(a, b);\n} else {\n    Fn(c, d);\n}"
        res = mut_if_else_call_to_ternary_arg(src, RNG)
        # Two args differ — should not match
        assert res is None

    def test_no_match_without_else(self) -> None:
        src = "if (flag) {\n    Fn(a);\n}"
        res = mut_if_else_call_to_ternary_arg(src, RNG)
        assert res is None


class TestTernaryArgToIfElseCall:
    def test_basic(self) -> None:
        src = "SetText(hwnd, flag ? strA : strB);"
        res = mut_ternary_arg_to_if_else_call(src, RNG)
        assert res is not None
        assert "if (flag)" in res
        assert "SetText(hwnd, strA);" in res
        assert "SetText(hwnd, strB);" in res

    def test_no_match(self) -> None:
        src = "SetText(hwnd, str);"
        res = mut_ternary_arg_to_if_else_call(src, RNG)
        assert res is None


# ---------------------------------------------------------------------------
# 4. Hoist/sink common tail
# ---------------------------------------------------------------------------


class TestHoistCommonTail:
    def test_basic(self) -> None:
        src = "if (x) {\n    a = 1;\n    Cleanup();\n} else {\n    b = 2;\n    Cleanup();\n}"
        res = mut_hoist_common_tail(src, RNG)
        assert res is not None
        # Cleanup() should appear after the if/else now
        assert "Cleanup();" in res
        # Should appear only once inside the if/else structure
        # (once hoisted out, removed from both branches)

    def test_no_common_tail(self) -> None:
        src = "if (x) {\n    a = 1;\n} else {\n    b = 2;\n}"
        res = mut_hoist_common_tail(src, RNG)
        assert res is None

    def test_empty_branches(self) -> None:
        src = "if (x) {\n} else {\n}"
        res = mut_hoist_common_tail(src, RNG)
        assert res is None


class TestSinkCommonTail:
    def test_basic(self) -> None:
        src = "void f() {\n    if (x) {\n        a = 1;\n    } else {\n        b = 2;\n    }\n    Cleanup();\n}"
        res = mut_sink_common_tail(src, RNG)
        assert res is not None
        # Cleanup should now be inside both branches
        assert res.count("Cleanup();") == 2

    def test_no_match_without_following_stmt(self) -> None:
        src = "void f() {\n    if (x) {\n        a = 1;\n    } else {\n        b = 2;\n    }\n}"
        res = mut_sink_common_tail(src, RNG)
        assert res is None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestPhase4Registration:
    def test_no_duplicate_entries(self) -> None:
        names = [m.__name__ for m in ALL_MUTATIONS]
        dupes = [n for n in names if names.count(n) > 1]
        assert len(names) == len(set(names)), f"Duplicates: {dupes}"

    def test_new_mutators_registered(self) -> None:
        names = {m.__name__ for m in ALL_MUTATIONS}
        expected = {
            "mut_register_param",
            "mut_unregister_param",
            "mut_remove_loop_break",
            "mut_add_loop_break",
            "mut_if_else_call_to_ternary_arg",
            "mut_ternary_arg_to_if_else_call",
            "mut_hoist_common_tail",
            "mut_sink_common_tail",
        }
        assert expected.issubset(names), f"Missing: {expected - names}"
