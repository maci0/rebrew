"""Tests for rebrew.matcher.core: Score, BuildResult."""

from rebrew.matcher.core import (
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
            total=0.0,
        )
        assert s.total == 0.0
        assert s.length_diff == 0


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
