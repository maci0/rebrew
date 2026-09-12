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
        combos = generate_flag_combinations("quick", "msvc-6.0")
        assert isinstance(combos, list)
        assert len(combos) > 0
        assert all(isinstance(c, str) for c in combos)

    def test_combinations_are_valid_flag_strings(self) -> None:
        combos = generate_flag_combinations("targeted", "msvc-6.0")
        for c in combos[:20]:
            assert c.startswith("/") or c == ""

    def test_watcom_profile_uses_watcom_flags(self) -> None:
        combos = generate_flag_combinations("targeted", "watcom-2.0-win32")
        assert len(combos) > 0
        # wcc386 flags are -style: -os/-ot/-ol/-ox x -3..-6 + none = 25
        assert len(combos) == 25
        for c in combos:
            assert c.startswith("-") or c == ""
        assert any("-ox" in c for c in combos)
        assert not any("/" in c for c in combos)  # no MSVC flags

    def test_watcom_quick_tier(self) -> None:
        combos = generate_flag_combinations("quick", "watcom-2.0-win32")
        assert len(combos) == 5  # opt axis only

    def test_msvc152_profile_uses_16bit_flags(self) -> None:
        combos = generate_flag_combinations("targeted", "msvc-1.52")
        # 5 opt x 5 model (incl. none) x 3 codegen (+none each) = 75; flags
        # are /-style.  The memory-model axis (/AS /AM /AC /AL) is
        # essential: far-code models emit retf/lcall and are what 16-bit
        # Windows games use.
        assert len(combos) == 75
        for c in combos:
            assert c.startswith("/") or c == ""
        assert any("/G2" in c for c in combos)
        assert any("/AM" in c for c in combos)
        assert any("/AL" in c for c in combos)


class TestMapSymbolRe:
    def test_escapes_special_chars(self) -> None:
        pat = _map_symbol_re("_func+[1]")
        assert re.escape("_func+[1]") in pat.pattern


class TestFlagSweepsNewProfiles:
    """borland-3.1/borland-5.5 sweep the Borland flag dialect (-O1/-O2/-Od, no
    msvc-style / flags); watcom-2.0-win16 shares the wcc flag family."""

    def test_borland_3_1_uses_borland_flags(self) -> None:
        combos = generate_flag_combinations("targeted", "borland-3.1")
        assert len(combos) > 0
        for c in combos:
            assert c.startswith("-") or c == ""
            assert "/" not in c
        assert any("-O2" in c for c in combos)

    def test_borlandc55_uses_borland_flags(self) -> None:
        combos = generate_flag_combinations("quick", "borland-5.5")
        assert combos == ["", "-O1", "-O2", "-Od"]

    def test_watcom_2_0_win16_shares_watcom_flags(self) -> None:
        combos = generate_flag_combinations("targeted", "watcom-2.0-win16")
        assert len(combos) == 25  # same wcc axes as watcom
        for c in combos:
            assert c.startswith("-") or c == ""


class TestUnlistedProfileFlagFallback:
    """A profile with no packaged/plugin flag set sweeps axes for its
    registered ``flags_style`` — a posix compiler must not be handed MSVC's
    /Gd axes."""

    def test_posix_profile_gets_posix_axes(self) -> None:
        combos = generate_flag_combinations("targeted", "ido-5.3")
        assert combos
        for c in combos:
            assert c.startswith("-") or c == ""
            assert "/" not in c

    def test_unregistered_profile_keeps_msvc_axes(self) -> None:
        combos = generate_flag_combinations("targeted", "totally-made-up")
        assert combos
        for c in combos:
            assert c.startswith("/") or c == ""


class TestSweepScoringMode:
    def test_mode_matches_the_ga_path(self) -> None:
        """The sweep hardcoded 32-bit mode for everything but x86_16, so an
        x86_64 sweep scored with 32-bit decoding while the GA used 64-bit."""
        from types import SimpleNamespace

        import capstone

        from rebrew.matcher.compiler import _sweep_scoring_params

        assert _sweep_scoring_params(SimpleNamespace(arch="x86_64"))[0] == capstone.CS_MODE_64
        assert _sweep_scoring_params(SimpleNamespace(arch="x86_16"))[0] == capstone.CS_MODE_16
        assert _sweep_scoring_params(SimpleNamespace(arch="x86_32"))[0] == capstone.CS_MODE_32


class TestMalformedFlagSetProvider:
    def test_bad_entry_is_skipped(self, monkeypatch) -> None:
        """A provider value that is not (Flags, tiers) raised TypeError out of
        module import, defeating the documented skip."""
        from types import SimpleNamespace

        import rebrew.matcher.compiler as compiler_mod

        reg = SimpleNamespace(
            group="rebrew.flag_sets", name="bad", origin="test", module="m", attr="p"
        )
        monkeypatch.setattr("rebrew.registry.entry_point_registrations", lambda group: [reg])
        monkeypatch.setattr(
            "rebrew.registry.load_registration_optional",
            lambda r, log: lambda: {"msvc-6.0": None},
        )
        flags, _tiers = compiler_mod._merged_flag_sets()
        assert flags["msvc-6.0"] is compiler_mod._FLAGS_MAP["msvc-6.0"]
