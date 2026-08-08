"""Tests for tools/sync_decomp_flags.py — flag formatting and combo counting."""

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import sync_decomp_flags as sdf  # noqa: E402

from rebrew.matcher.flags import Checkbox, FlagSet  # noqa: E402


class LanguageFlagSet:
    """Stand-in matching the decomp.me LanguageFlagSet shape."""

    def __init__(self, id: str, flags: dict) -> None:
        self.id = id
        self.flags = flags


class TestFormatFlagsList:
    def test_short_flagset_inline(self) -> None:
        out = sdf.format_flags_list("COMMON_MSVC_FLAGS", [FlagSet(id="o", flags=("/O1", "/O2"))])
        assert "COMMON_MSVC_FLAGS: Flags = [" in out
        assert "FlagSet(id='o', flags=('/O1', '/O2'))," in out

    def test_long_flagset_multiline(self) -> None:
        flags = tuple(f"/flag{i}" for i in range(6))
        out = sdf.format_flags_list("X", [FlagSet(id="big", flags=flags)])
        assert "FlagSet(" in out
        assert "id='big'," in out
        assert repr(flags) in out

    def test_checkbox(self) -> None:
        out = sdf.format_flags_list("X", [Checkbox(id="opt", flag="/O2")])
        assert "Checkbox(id='opt', flag='/O2')," in out

    def test_language_flagset_converted(self) -> None:
        lfs = LanguageFlagSet(id="lang", flags={"C": "/TC", "C++": "/TP"})
        out = sdf.format_flags_list("X", [lfs])
        # FlagSet.flags is typed tuple[str, ...] — lists are normalized to tuples.
        assert "FlagSet(id='lang', flags=('C', 'C++'))," in out


class TestCountCombos:
    def test_all(self) -> None:
        items = [
            FlagSet(id="o", flags=("/O1", "/O2")),  # 3
            Checkbox(id="zi", flag="/ZI"),  # 2
            LanguageFlagSet(id="lang", flags={"C": "/TC"}),  # 2
        ]
        assert sdf.count_combos(items) == 3 * 2 * 2

    def test_tier_filter(self) -> None:
        items = [FlagSet(id="o", flags=("/O1", "/O2")), Checkbox(id="zi", flag="/ZI")]
        assert sdf.count_combos(items, tier_ids={"zi"}) == 2  # only the checkbox
        assert sdf.count_combos(items, tier_ids={"o"}) == 3

    def test_empty(self) -> None:
        assert sdf.count_combos([]) == 1


class TestGenerateFlagDataPy:
    def test_header_and_lists(self) -> None:
        msvc = [FlagSet(id="o", flags=("/O1", "/O2"))]
        msvc6 = [Checkbox(id="zi", flag="/ZI")]
        out = sdf.generate_flag_data_py(msvc, msvc6, "2026-08-07")
        assert "Auto-generated compiler flag axes from decomp.me" in out
        assert "Synced: 2026-08-07" in out
        assert "COMMON_MSVC_FLAGS: Flags = [" in out
        assert "MSVC6_FLAGS: Flags = [" in out
        assert "MSVC_SWEEP_TIERS = {" in out
