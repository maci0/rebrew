"""Localise byte drift between compiled and reference code from branch targets.

A jump whose *encoding* matches the reference but whose *target* differs is not
a defect -- it is a measurement.  The difference between the two targets is
exactly the byte drift accumulated between the jump and its target, so every
such pair yields a window ``[lo, hi)`` carrying a signed byte count, obtained
without disassembling the window's contents at all.

Two refinements make this worth having as a command rather than a one-off
script, both learned from real misreadings:

* **Backward jumps invert.**  For ``target < jump`` the measured span is
  ``[target, jump)`` and the sign flips: our backward target sitting two bytes
  *earlier* than the reference's means the code between them *grew* by two.
  Getting this wrong reports a negative-width window, which is the tell.

* **Nested windows subtract.**  A window strictly inside another accounts for
  part of the outer window's drift, so the remainder belongs to the region the
  inner one does not cover -- and that remainder can have the opposite sign.
  This is the only way to see a region with no branch pair of its own: on one
  function every measured window was negative while the object was size-exact,
  and subtracting a -19 inner window from its -10 outer one exposed a +9
  surplus that no direct measurement reported.

A negative window is evidence, not a defect: it says the compiled code is
*shorter* there than the reference, which constrains what any change to an
opposing window can achieve.  Read both signs before attributing a cause.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "DriftWindow",
    "DerivedRegion",
    "branch_targets",
    "drift_windows",
    "derive_regions",
]


@dataclass(frozen=True)
class DriftWindow:
    """A span whose byte drift is known from a single branch pair.

    Attributes:
        lo: Inclusive start of the measured span.
        hi: Exclusive end of the measured span.
        drift: Signed byte count; positive means the compiled code is *longer*
            than the reference across ``[lo, hi)``.
        jump: Offset of the branch instruction the window was measured from.
        ref_target: The reference's branch target.
        our_target: The compiled code's branch target.
        backward: ``True`` when the branch jumps backwards, in which case the
            span runs from the target to the jump and the raw target delta was
            negated.
    """

    lo: int
    hi: int
    drift: int
    jump: int
    ref_target: int
    our_target: int
    backward: bool = False

    @property
    def width(self) -> int:
        """Byte width of the measured span."""
        return self.hi - self.lo


@dataclass(frozen=True)
class DerivedRegion:
    """Drift attributed to the part of a window an inner window does not cover.

    Carries the pair it was derived from so a reader can check the arithmetic
    rather than trusting the result.
    """

    outer: DriftWindow
    inner: DriftWindow
    drift: int = field(compare=True)


def branch_targets(code: bytes, md) -> dict[int, tuple[int, int]]:
    """Map branch offset to ``(instruction_size, target_offset)``.

    Only intra-function jumps are collected.  ``call`` is excluded because in an
    unlinked object its displacement is an unresolved relocation, so its
    "target" is noise rather than a layout signal; a jump leaving the function
    body is excluded for the same reason -- it is a tail call, not a measurement
    of this function's layout.

    Args:
        code: The function's bytes, starting at offset 0.
        md: A capstone disassembler, from :func:`rebrew.asm.make_disassembler`.
    """
    out: dict[int, tuple[int, int]] = {}
    for insn in md.disasm(code, 0):
        if not insn.mnemonic.startswith("j"):
            continue
        # capstone renders a branch target as bare decimal when it is small
        # (``jmp 5``) and as hex otherwise (``jmp 0x4fa``), so parse both rather
        # than filtering on a ``0x`` prefix -- that filter silently drops every
        # window in a function under 0x10 bytes and skews the ones just above it.
        op = insn.op_str.strip()
        try:
            target = int(op, 16) if op.startswith("0x") else int(op, 10)
        except ValueError:
            continue  # indirect (register/memory) branch: no static target
        if not 0 <= target < len(code):
            continue  # leaves the function body
        out[insn.address] = (insn.size, target)
    return out


def drift_windows(ref_code: bytes, our_code: bytes, md) -> list[DriftWindow]:
    """Measure drift windows between reference and compiled code.

    A branch contributes a window only when it appears at the same offset in
    both streams *with the same encoded size* and a differing target.  Equal
    encoding is what makes the target difference attributable to the span
    rather than to the branch itself.

    Returns windows sorted by start offset, then by width.
    """
    ref_br = branch_targets(ref_code, md)
    our_br = branch_targets(our_code, md)

    windows: list[DriftWindow] = []
    for addr in sorted(ref_br.keys() & our_br.keys()):
        ref_size, ref_target = ref_br[addr]
        our_size, our_target = our_br[addr]
        if ref_size != our_size or ref_target == our_target:
            continue
        delta = our_target - ref_target
        if ref_target >= addr:
            lo, hi, drift, backward = addr, ref_target, delta, False
        else:
            # Backward branch: the span runs target -> jump and the sign flips.
            lo, hi, drift, backward = ref_target, addr, -delta, True
        windows.append(
            DriftWindow(
                lo=lo,
                hi=hi,
                drift=drift,
                jump=addr,
                ref_target=ref_target,
                our_target=our_target,
                backward=backward,
            )
        )
    windows.sort(key=lambda w: (w.lo, w.width))
    return windows


def derive_regions(windows: list[DriftWindow]) -> list[DerivedRegion]:
    """Subtract nested windows to expose regions with no branch pair of their own.

    For each outer window one strictly-contained inner window is reported, so a
    single region is not claimed several times over.  The one chosen is the
    *widest* qualifying inner window, because the remainder describes the part
    of the outer window the inner does not cover: a wider inner leaves a
    narrower, better-localised remainder, which is the useful statement.

    Selecting the *narrowest* inner instead is a subtle trap -- every choice
    yields an arithmetically true remainder, but about a different region, so
    the wrong rule silently reports a correct number answering a question
    nobody asked.  On one real function the narrowest inner gave "-8 outside a
    33-byte window" while the widest gave "+9 outside a 64-byte window": both
    true, only the second localising the surplus that mattered.

    Pairs whose remainder is zero are dropped: they say the inner window
    accounts for all of the outer one's drift, which is a consistency check
    rather than a finding.
    """
    best: dict[tuple[int, int], tuple[DriftWindow, DriftWindow]] = {}
    for outer in windows:
        for inner in windows:
            if (inner.lo, inner.hi) == (outer.lo, outer.hi):
                continue
            if not (outer.lo <= inner.lo and inner.hi <= outer.hi):
                continue
            if inner.width >= outer.width:
                continue
            if outer.drift - inner.drift == 0:
                continue
            key = (outer.lo, outer.hi)
            prev = best.get(key)
            if prev is None or inner.width > prev[1].width:
                best[key] = (outer, inner)

    return [
        DerivedRegion(outer=outer, inner=inner, drift=outer.drift - inner.drift)
        for outer, inner in (best[k] for k in sorted(best))
    ]
