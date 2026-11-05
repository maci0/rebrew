"""Target-sensitive structural fragments retain original byte coordinates."""

import pytest

from rebrew.binding_replacement_conditions import target_structural_view

SOURCE = """void old(void);\nvoid caller(int n) {\n#ifdef REBREW_GOLD\n if (n == 1) {\n#else\n if (n == 2) {\n#endif\n  old();\n }\n}\n"""


def test_selects_target_guard_at_unchanged_offsets():
    gold, names = target_structural_view(SOURCE, {"REBREW_GOLD": True})
    tl, _ = target_structural_view(SOURCE, {"REBREW_GOLD": False})
    assert names == ["REBREW_GOLD"]
    assert len(gold) == len(tl) == len(SOURCE.encode())
    assert b"n == 1" in gold and b"n == 2" not in gold
    assert b"n == 2" in tl and b"n == 1" not in tl
    assert gold.index(b"old();") == tl.index(b"old();") == SOURCE.encode().index(b"old();")


def test_unknown_macro_refuses():
    with pytest.raises(ValueError, match="unknown macro"):
        target_structural_view(SOURCE, {})


def test_unreviewed_branch_expression_refuses():
    with pytest.raises(ValueError, match="unsupported conditional guard"):
        target_structural_view(
            SOURCE.replace("#ifdef REBREW_GOLD", "#if OTHER + 1"), {"OTHER": True}
        )


def test_source_macro_mutation_refuses():
    with pytest.raises(ValueError, match="source changes macro state"):
        target_structural_view("#define REBREW_GOLD\n" + SOURCE, {"REBREW_GOLD": True})


def test_unrepresented_independent_branches_refuse():
    both = SOURCE + SOURCE.replace("REBREW_GOLD", "OTHER").replace("caller", "caller2")
    with pytest.raises(ValueError, match="combination"):
        target_structural_view(both, {"REBREW_GOLD": False, "OTHER": False})
