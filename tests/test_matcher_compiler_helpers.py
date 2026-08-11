"""Tests for matcher/compiler.py pure helpers."""

import re

from rebrew.matcher.compiler import _flags_to_axes, _map_symbol_re, generate_flag_combinations
from rebrew.matcher.flags import Checkbox, FlagSet


class TestFlagsToAxes:
    def test_flagset_and_checkbox(self) -> None:
        flags = [FlagSet(id="opt", flags=("/O1", "/O2")), Checkbox(id="gd", flag="/Gd")]
        axes = _flags_to_axes(flags)
        assert axes[0] == ["/O1", "/O2", ""]  # mutually exclusive + none
        assert axes[1] == ["/Gd", ""]  # on/off

    def test_tier_filter(self) -> None:
        flags = [FlagSet(id="opt", flags=("/O1", "/O2")), Checkbox(id="gd", flag="/Gd")]
        axes = _flags_to_axes(flags, tier_ids=["opt"])
        assert axes == [["/O1", "/O2", ""]]


class TestGenerateFlagCombinations:
    def test_quick_tier_nonempty(self) -> None:
        combos = generate_flag_combinations("quick", "msvc6")
        assert isinstance(combos, list)
        assert len(combos) > 0
        assert all(isinstance(c, str) for c in combos)

    def test_combinations_are_valid_flag_strings(self) -> None:
        combos = generate_flag_combinations("targeted", "msvc6")
        for c in combos[:20]:
            assert c.startswith("/") or c == ""

    def test_watcom_profile_uses_watcom_flags(self) -> None:
        combos = generate_flag_combinations("targeted", "watcom")
        assert len(combos) > 0
        # wcc386 flags are -style: -os/-ot/-ol/-ox x -3..-6 + none = 25
        assert len(combos) == 25
        for c in combos:
            assert c.startswith("-") or c == ""
        assert any("-ox" in c for c in combos)
        assert not any("/" in c for c in combos)  # no MSVC flags

    def test_watcom_quick_tier(self) -> None:
        combos = generate_flag_combinations("quick", "watcom")
        assert len(combos) == 5  # opt axis only


class TestMapSymbolRe:
    def test_escapes_special_chars(self) -> None:
        pat = _map_symbol_re("_func+[1]")
        assert re.escape("_func+[1]") in pat.pattern
