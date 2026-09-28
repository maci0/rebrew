"""Tests for rebrew.matcher.core: Score, BuildResult."""

import pytest

from rebrew.matcher.core import (
    WEIGHT_BYTE,
    WEIGHT_LEN_DIFF,
    WEIGHT_MNEMONIC,
    WEIGHT_RELOC,
    BuildResult,
    Score,
)

# -------------------------------------------------------------------------
# Score dataclass
# -------------------------------------------------------------------------


class TestScore:
    def test_creation(self) -> None:
        s = Score(
            length_diff=0,
            byte_score=0.0,
            reloc_score=0.0,
            mnemonic_score=0.0,
            prologue_bonus=0.0,
        )
        assert s.total == 0.0
        assert s.length_diff == 0

    def test_total_is_derived_from_components(self) -> None:
        """``total`` is the weighted sum, not an independently settable field.

        A stored total could disagree with the five components it summarizes,
        and ``EXACT_SCORE_THRESHOLD`` reads it, so it is computed.
        """
        s = Score(
            length_diff=2,
            byte_score=1.0,
            reloc_score=0.5,
            mnemonic_score=4.0,
            prologue_bonus=-100.0,
        )
        expected = (
            2 * WEIGHT_LEN_DIFF
            + 1.0 * WEIGHT_BYTE
            + 0.5 * WEIGHT_RELOC
            + 4.0 * WEIGHT_MNEMONIC
            + -100.0
        )
        assert s.total == pytest.approx(expected)

    def test_total_tracks_a_mutated_component(self) -> None:
        s = Score(0, 0.0, 0.0, 0.0, 0.0)
        before = s.total
        s.byte_score = 1.0
        assert s.total == pytest.approx(before + WEIGHT_BYTE)


# -------------------------------------------------------------------------
# BuildResult dataclass
# -------------------------------------------------------------------------


class TestBuildResult:
    def test_ok(self) -> None:
        r = BuildResult(ok=True, obj_bytes=b"\x55\x8b")
        assert r.ok is True
        assert r.error_msg == ""

    def test_failed(self) -> None:
        r = BuildResult(ok=False, error_msg="compilation failed")
        assert r.ok is False
        assert r.score is None
