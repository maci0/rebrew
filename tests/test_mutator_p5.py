import random

from rebrew.matcher.mutator import (
    ALL_MUTATIONS,
    mut_commute_add_general,
    mut_commute_bit_and,
    mut_commute_bit_or,
    mut_commute_bit_xor,
    mut_commute_mul_general,
    mut_inject_block_register,
    mut_inject_dummy_registers,
    mut_retype_local_equiv,
    mut_zero_to_bitand,
)

RNG = random.Random(42)


# ---------------------------------------------------------------------------
# 1. Commutative bitwise operand swapping
# ---------------------------------------------------------------------------


class TestCommuteBitwiseOps:
    def test_swap_or(self) -> None:
        src = "void f() {\n    x = a | b;\n}"
        res = mut_commute_bit_or(src, RNG)
        assert res is not None
        assert "b | a" in res

    def test_swap_and(self) -> None:
        src = "void f() {\n    x = a & b;\n}"
        res = mut_commute_bit_and(src, RNG)
        assert res is not None
        assert "b & a" in res

    def test_swap_xor(self) -> None:
        src = "void f() {\n    x = a ^ b;\n}"
        res = mut_commute_bit_xor(src, RNG)
        assert res is not None
        assert "b ^ a" in res

    def test_no_swap_identical(self) -> None:
        src = "void f() {\n    x = a | a;\n}"
        res = mut_commute_bit_or(src, RNG)
        assert res is None  # identical operands → no change

    def test_complex_subexpressions(self) -> None:
        src = "void f() {\n    x = (w >> 8) | (w << 8);\n}"
        res = mut_commute_bit_or(src, RNG)
        assert res is not None
        assert "(w << 8)" in res
        assert "(w >> 8)" in res


# ---------------------------------------------------------------------------
# 2. Generalized arithmetic commutative swaps
# ---------------------------------------------------------------------------


class TestCommuteGeneralArith:
    def test_swap_complex_add(self) -> None:
        src = "void f() {\n    *lpDest = (WORD)((w >> 8) + (w << 8));\n}"
        res = mut_commute_add_general(src, RNG)
        assert res is not None
        # The swap should put (w << 8) before (w >> 8)
        assert "(w << 8)" in res

    def test_swap_complex_mul(self) -> None:
        src = "void f() {\n    x = (a + 1) * (b + 2);\n}"
        res = mut_commute_mul_general(src, RNG)
        assert res is not None
        assert "(b + 2)" in res

    def test_no_swap_identical_add(self) -> None:
        src = "void f() {\n    x = a + a;\n}"
        res = mut_commute_add_general(src, RNG)
        assert res is None


# ---------------------------------------------------------------------------
# 3. Block-scoped register injection
# ---------------------------------------------------------------------------


class TestInjectBlockRegister:
    def test_wrap_loop_body(self) -> None:
        src = "void f() {\n    while (x) {\n        a = 1;\n    }\n}"
        res = mut_inject_block_register(src, RNG)
        assert res is not None
        assert "register int _reg_" in res
        assert "a = 1;" in res

    def test_wrap_adjacent_stmts(self) -> None:
        src = "void f() {\n    a = 1;\n    b = 2;\n}"
        res = mut_inject_block_register(src, RNG)
        assert res is not None
        assert "register int _reg_" in res
        assert "a = 1;" in res
        assert "b = 2;" in res

    def test_no_duplicate_reg_name(self) -> None:
        # Force a specific RNG seed where _reg_N collides
        rng = random.Random(0)
        reg_id = rng.randint(0, 99)
        name = f"_reg_{reg_id}"
        src = f"void f() {{\n    int {name};\n    a = 1;\n    b = 2;\n}}"
        # Re-seed to get same _reg_N
        rng2 = random.Random(0)
        res = mut_inject_block_register(src, rng2)
        assert res is None  # should refuse to add duplicate


# ---------------------------------------------------------------------------
# 4. Equivalent-size local type retyping
# ---------------------------------------------------------------------------


class TestRetypeLocalEquiv:
    def test_int_to_dword(self) -> None:
        src = "void f() {\n    int count;\n    count = 0;\n}"
        res = mut_retype_local_equiv(src, RNG)
        assert res is not None
        assert "DWORD count" in res

    def test_dword_to_long(self) -> None:
        src = "void f() {\n    DWORD count;\n    count = 0;\n}"
        res = mut_retype_local_equiv(src, RNG)
        assert res is not None
        assert "long count" in res

    def test_preserves_register_qualifier(self) -> None:
        src = "void f() {\n    register int count;\n    count = 0;\n}"
        res = mut_retype_local_equiv(src, RNG)
        assert res is not None
        assert "register DWORD count" in res

    def test_unsupported_type_no_match(self) -> None:
        src = "void f() {\n    HANDLE h;\n    h = 0;\n}"
        res = mut_retype_local_equiv(src, RNG)
        assert res is None


# ---------------------------------------------------------------------------
# 5. Zero-to-bitand transform
# ---------------------------------------------------------------------------


class TestZeroToBitand:
    def test_forward(self) -> None:
        src = "void f() {\n    x = 0;\n}"
        res = mut_zero_to_bitand(src, RNG)
        assert res is not None
        assert "x &= 0;" in res

    def test_reverse(self) -> None:
        src = "void f() {\n    x &= 0;\n}"
        res = mut_zero_to_bitand(src, RNG)
        assert res is not None
        assert "x = 0;" in res

    def test_skips_for_init(self) -> None:
        src = "void f() {\n    for (i = 0; i < 10; i++) {\n        a = 1;\n    }\n}"
        res = mut_zero_to_bitand(src, RNG)
        # for-loop initializer should be skipped — no candidates
        assert res is None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestPhase5Registration:
    def test_no_duplicate_entries(self) -> None:
        names = [m.__name__ for m in ALL_MUTATIONS]
        dupes = [n for n in names if names.count(n) > 1]
        assert len(names) == len(set(names)), f"Duplicates: {dupes}"

    def test_new_mutators_registered(self) -> None:
        names = {m.__name__ for m in ALL_MUTATIONS}
        expected = {
            "mut_commute_bit_or",
            "mut_commute_bit_and",
            "mut_commute_bit_xor",
            "mut_commute_add_general",
            "mut_commute_mul_general",
            "mut_inject_block_register",
            "mut_inject_dummy_registers",
            "mut_retype_local_equiv",
            "mut_zero_to_bitand",
        }
        assert expected.issubset(names), f"Missing: {expected - names}"


# ---------------------------------------------------------------------------
# 6. Register pressure manipulation — mut_inject_dummy_registers
# ---------------------------------------------------------------------------


class TestInjectDummyRegisters:
    def test_injects_register_int(self) -> None:
        src = "int foo(int a, int b) {\n    return a + b;\n}"
        res = mut_inject_dummy_registers(src, random.Random(42))
        assert res is not None
        assert "register int _dummy_reg_" in res
        assert "= 0;" in res

    def test_injects_1_to_3_declarations(self) -> None:
        src = "int foo(int a) {\n    return a;\n}"
        # Run several seeds and check we get varying counts
        counts = set()
        for seed in range(100):
            res = mut_inject_dummy_registers(src, random.Random(seed))
            if res is not None:
                n = res.count("register int _dummy_reg_")
                assert 1 <= n <= 3
                counts.add(n)
        # With 100 seeds we should see at least 2 different counts
        assert len(counts) >= 2

    def test_no_duplicate_names(self) -> None:
        src = "int foo() {\n    return 0;\n}"
        for seed in range(50):
            res = mut_inject_dummy_registers(src, random.Random(seed))
            if res is not None:
                # Extract all _dummy_reg_NN names
                import re

                names = re.findall(r"_dummy_reg_\d+", res)
                assert len(names) == len(set(names)), f"Duplicate names in seed {seed}: {names}"

    def test_skips_if_name_collision(self) -> None:
        src = "int foo() {\n    register int _dummy_reg_42 = 0;\n    return 0;\n}"
        # Should still work — just picks different names
        res = mut_inject_dummy_registers(src, random.Random(42))
        # Either None (all names collided) or valid with different names
        if res is not None:
            assert res.count("_dummy_reg_") >= 2  # at least original + 1 new

    def test_no_function_returns_none(self) -> None:
        src = "int x = 5;"
        res = mut_inject_dummy_registers(src, random.Random(42))
        assert res is None
