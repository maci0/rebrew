"""Tests for tools/sync_decomp_flags.py — flag formatting, combo counting, sync inputs."""

from typing import Any

from rebrew.flags import Checkbox, FlagSet
from tools import sync_decomp_flags as sdf


class LanguageFlagSet:
    """Stand-in matching the decomp.me LanguageFlagSet shape."""

    # `id` is the real attribute name on declib's flag set, and the format
    # assertions below pin its repr: a renamed parameter would stop this
    # stand-in from standing in.
    def __init__(self, id: str, flags: dict) -> None:  # noqa: A002
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
        msvc6_flags = [Checkbox(id="zi", flag="/ZI")]
        out = sdf.generate_flag_data_py(msvc, msvc6_flags, "2026-08-07")
        assert "Auto-generated compiler flag axes from decomp.me" in out
        assert "Synced: 2026-08-07" in out
        assert "COMMON_MSVC_FLAGS: Flags = [" in out
        assert "MSVC6_FLAGS: Flags = [" in out
        assert "MSVC_SWEEP_TIERS: dict[str, list[str] | None] = {" in out


class TestSyncDate:
    """SOURCE_DATE_EPOCH makes a re-sync of one upstream commit byte-identical."""

    def test_honors_source_date_epoch(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790635867")
        assert sdf.sync_date() == "2026-09-28"

    def test_epoch_is_read_as_utc(self, monkeypatch: Any) -> None:
        # One second before the same instant in UTC: a local-time reading would
        # land on the previous day west of Greenwich.
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        assert sdf.sync_date() == "1970-01-01"

    def test_falls_back_to_the_clock(self, monkeypatch: Any) -> None:
        monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
        assert len(sdf.sync_date()) == len("2026-08-07")

    def test_non_numeric_epoch_falls_back(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
        assert len(sdf.sync_date()) == len("2026-08-07")


class TestDriftedLines:
    def test_unchanged_upstream_is_current_on_another_day(self) -> None:
        committed = '"""doc."""\nSynced: 2026-08-07\n\nFLAG = 1\n'
        regenerated = '"""doc."""\nSynced: 2026-09-29\n\nFLAG = 1\n'
        assert sdf.drifted_lines(committed, regenerated) == []

    def test_real_difference_is_reported(self) -> None:
        committed = '"""doc."""\nSynced: 2026-08-07\n\nFLAG = 1\n'
        regenerated = '"""doc."""\nSynced: 2026-08-07\n\nFLAG = 2\n'
        diff = sdf.drifted_lines(committed, regenerated)
        assert [line for line in diff if line.startswith("-") and not line.startswith("---")] == [
            "-FLAG = 1"
        ]
        assert [line for line in diff if line.startswith("+") and not line.startswith("+++")] == [
            "+FLAG = 2"
        ]


class TestCloneRef:
    def test_ref_is_passed_to_git(self, monkeypatch: Any, tmp_path: Any) -> None:
        commands: list[list[str]] = []

        def fake_run(command: list[str], **kwargs: Any) -> Any:
            commands.append(command)
            return None

        monkeypatch.setattr(sdf.subprocess, "run", fake_run)
        sdf.clone_decomp_me(str(tmp_path), "v1.2.3")
        assert commands[0][commands[0].index("--branch") + 1] == "v1.2.3"

    def test_default_branch_is_left_unpinned(self, monkeypatch: Any, tmp_path: Any) -> None:
        commands: list[list[str]] = []

        def fake_run(command: list[str], **kwargs: Any) -> Any:
            commands.append(command)
            return None

        monkeypatch.setattr(sdf.subprocess, "run", fake_run)
        sdf.clone_decomp_me(str(tmp_path))
        assert "--branch" not in commands[0]
