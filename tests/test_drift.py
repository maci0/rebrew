"""Unit tests for rebrew.drift -- byte-drift localisation from branch targets.

The arithmetic here was got wrong twice in real use before it was pinned down,
so both failure modes are covered explicitly:

* backward jumps measure ``[target, jump)`` with an inverted sign -- getting it
  wrong yields a negative-width window, which is the tell;
* nested windows subtract, and the remainder can carry the opposite sign to the
  window it came from, which is the only way a region with no branch pair of its
  own becomes visible.

Machine code is assembled by hand so the expected drift is known exactly rather
than inferred from a compiler's output.
"""

from __future__ import annotations

import pytest

from rebrew.drift import branch_targets, derive_regions, drift_windows

capstone = pytest.importorskip("capstone")


@pytest.fixture
def md():
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def _jmp_rel8(delta: int) -> bytes:
    """``jmp rel8`` -- 2 bytes, displacement relative to the next instruction."""
    return bytes([0xEB, delta & 0xFF])


def _nops(n: int) -> bytes:
    return b"\x90" * n


class TestBranchTargets:
    def test_finds_forward_jump(self, md):
        # rel8 is relative to the next instruction: 0 + 2 + 3 = 5
        code = _jmp_rel8(3) + _nops(3) + b"\xc3"
        assert branch_targets(code, md) == {0: (2, 5)}

    def test_excludes_call(self, md):
        # e8 rel32: in an unlinked object this displacement is an unresolved
        # relocation, so its "target" is noise rather than a layout signal.
        code = b"\xe8\x00\x00\x00\x00" + b"\xc3"
        assert branch_targets(code, md) == {}

    def test_excludes_target_outside_body(self, md):
        # A jump past the end of the function is a tail call, not a measurement
        # of this function's layout.
        code = _jmp_rel8(0x40) + b"\xc3"
        assert branch_targets(code, md) == {}

    def test_excludes_indirect_branch(self, md):
        code = b"\xff\xe0" + b"\xc3"  # jmp eax
        assert branch_targets(code, md) == {}


class TestDriftWindows:
    def test_identical_code_has_no_windows(self, md):
        code = _jmp_rel8(3) + _nops(3) + b"\xc3"
        assert drift_windows(code, code, md) == []

    def test_forward_jump_positive_drift(self, md):
        """Ours reaches the same landmark two bytes later => +2 across the span."""
        ref = _jmp_rel8(4) + _nops(4) + b"\xc3"
        our = _jmp_rel8(6) + _nops(6) + b"\xc3"
        (w,) = drift_windows(ref, our, md)
        assert (w.lo, w.hi, w.drift) == (0, 6, 2)  # ref target 0+2+4
        assert w.backward is False
        assert w.width == 6

    def test_forward_jump_negative_drift(self, md):
        ref = _jmp_rel8(6) + _nops(6) + b"\xc3"
        our = _jmp_rel8(4) + _nops(4) + b"\xc3"
        (w,) = drift_windows(ref, our, md)
        assert w.drift == -2

    def test_backward_jump_inverts_sign_and_span(self, md):
        """The regression this exists to prevent.

        Both streams put a backward ``jmp`` at offset 6.  The reference jumps to
        2; ours jumps to 0, i.e. *earlier*.  An earlier backward target means the
        code between target and jump is LONGER on our side, so the drift is +2 --
        not the raw target delta of -2 -- and the span is [target, jump), never
        [jump, target).
        """
        ref = _nops(6) + _jmp_rel8(-6)  # jmp at 6 -> 2
        our = _nops(6) + _jmp_rel8(-8)  # jmp at 6 -> 0
        (w,) = drift_windows(ref, our, md)
        assert w.backward is True
        # The span is anchored on the REFERENCE target: [2, 6), never [6, 2).
        assert (w.lo, w.hi) == (2, 6)
        assert w.width > 0, "a negative-width window means lo/hi were swapped"
        assert w.drift == 2, "backward drift must be negated relative to the target delta"

    def test_differing_encoding_size_is_not_a_window(self, md):
        """Equal encoding is what makes the target delta attributable to the span."""
        ref = _jmp_rel8(4) + _nops(4) + b"\xc3"
        our = b"\xe9" + (4).to_bytes(4, "little") + _nops(4) + b"\xc3"  # jmp rel32
        assert drift_windows(ref, our, md) == []


def _w(lo, hi, drift):
    from rebrew.drift import DriftWindow

    return DriftWindow(lo=lo, hi=hi, drift=drift, jump=lo, ref_target=hi, our_target=hi + drift)


class TestDeriveRegions:
    def test_opposite_sign_remainder_is_exposed(self):
        """The CrashDump case: every window negative, yet a surplus hides inside.

        Outer [0xda,0x6b9) drifts -10 while inner [0x490,0x4d0) drifts -19, so
        the region the inner does not cover carries +9 -- a surplus no direct
        measurement reports.
        """
        windows = [_w(0xDA, 0x6B9, -10), _w(0x490, 0x4D0, -19)]
        (d,) = derive_regions(windows)
        assert d.drift == 9
        assert (d.outer.lo, d.inner.lo) == (0xDA, 0x490)

    def test_widest_inner_wins_over_a_narrower_one(self):
        """Regression: a narrow late window must not displace the informative pair.

        Taken from the real CrashDump measurement, where a 33-byte window at
        [0x5d2,0x5f3) sits inside the same outer window as the 64-byte
        [0x490,0x4d0).  Choosing the narrow one yields -8, which is true but
        localises nothing; the wide one yields the +9 surplus that matters.
        """
        windows = [
            _w(0xDA, 0x6B9, -10),
            _w(0x490, 0x4D0, -19),
            _w(0x5D2, 0x5F3, -2),
        ]
        outer_da = [d for d in derive_regions(windows) if d.outer.lo == 0xDA]
        assert len(outer_da) == 1
        assert (outer_da[0].inner.lo, outer_da[0].inner.hi) == (0x490, 0x4D0)
        assert outer_da[0].drift == 9

    def test_reports_the_widest_inner_window(self):
        """One region per outer window, and the one that localises best.

        Every containment yields an arithmetically true remainder, but about a
        different region.  The widest inner leaves the narrowest remainder, so
        that is the useful statement; picking the narrowest inner reports a
        correct number about a region nobody asked about.
        """
        windows = [_w(0, 0x100, 5), _w(0x10, 0x90, 2), _w(0x20, 0x40, 1)]
        derived = derive_regions(windows)
        outer_zero = [d for d in derived if d.outer.lo == 0]
        assert len(outer_zero) == 1
        assert (outer_zero[0].inner.lo, outer_zero[0].inner.hi) == (0x10, 0x90)
        assert outer_zero[0].drift == 3

    def test_zero_remainder_is_dropped(self):
        """Inner accounting for all of outer's drift is a consistency check, not a finding."""
        windows = [_w(0, 0x100, 5), _w(0x10, 0x20, 5)]
        assert derive_regions(windows) == []

    def test_non_nested_windows_do_not_subtract(self):
        windows = [_w(0, 0x10, 3), _w(0x20, 0x30, -4)]
        assert derive_regions(windows) == []

    def test_no_windows_yields_no_derivations(self):
        """The inference must not invent a region where nothing was measured."""
        assert derive_regions([]) == []
